use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    pin::pin,
    sync::{Arc, MutexGuard, OnceLock, PoisonError},
    time::Duration,
};

use http::{Method, Response};
use phantom_net::{
    http1::{
        Http1Connection,
        validate_request_body_source_with_trailers as validate_http1_request_body_source_with_trailers,
    },
    http1_or_2::{Http1Or2Connection, Http1Or2TlsConnector, Http1Or2TlsError},
    http2::{
        Http2Connection, Http2Error, Http2ProtocolErrorKind,
        validate_request_body_source_with_trailers as validate_http2_request_body_source_with_trailers,
    },
    proxy::HttpsProxyConnector,
    request::{OriginForm, RequestBody, RequestHeader},
};
use phantom_profile::Http2Priority;
use tokio::sync::{Mutex, Notify};
use tracing::{Span, debug};

use super::{
    admission::{Admission, AdmissionPermit, AdmissionRegistry},
    client_hints::ClientHintContext,
    http2_connections::{Choice, Http2Spread},
    http2_pool::{is_graceful_goaway, send_on},
    stream_count::{OpenStream, StreamCount},
};
use crate::{
    HttpProtocol, RequestError, ResponseBody, Route, Socks5DnsMode,
    authority::Endpoint,
    error::is_unprocessed_http2,
    retry::ConnectionSetupRetryState,
    timeout::{PhaseTimeout, TimeoutBudget, TimeoutPhase, within},
};

/// Negotiated HTTP/1.1-or-HTTP/2 connections, grouped by origin and route.
///
/// Each pool key keeps up to `max_http2_connections` reusable H2
/// connections, one by default, which carry all of the key's H2 requests,
/// and up to `max_http1_active` connections that are H1 or still in setup.
/// A request reuses an H2 connection when one has room (see
/// [`Http2Spread`]), then the most recently used idle H1 connection, and
/// otherwise opens a connection whose protocol ALPN chooses.
///
/// Concurrent requests to a key that has never selected H2 open connections
/// in parallel, up to the H1 bound, as Chromium and Firefox do before they
/// know the server speaks H2. Once a connection to the key has selected H2,
/// a request that finds another connection to the key in setup waits for
/// that setup to finish instead of opening one of its own.
pub(crate) struct Http1Or2Pool {
    capacity: NonZeroUsize,
    max_http1_active: NonZeroUsize,
    max_http1_pending: NonZeroUsize,
    max_http2_active: NonZeroUsize,
    max_http2_pending: NonZeroUsize,
    max_http2_connections: NonZeroUsize,
    /// Longest wait for a setup in flight to a key that selected H2 before.
    setup_wait_limit: Option<Duration>,
    state: Mutex<PoolState>,
    http2_keys: Arc<Http2Keys>,
    #[cfg(feature = "https-records")]
    https_records: Option<super::alt_svc::HttpsRecordDiscovery>,
}

impl Http1Or2Pool {
    pub(super) fn new(
        http1_capacity: NonZeroUsize,
        max_http1_active: NonZeroUsize,
        max_http1_pending: NonZeroUsize,
        http2_capacity: NonZeroUsize,
        max_http2_active: NonZeroUsize,
        max_http2_pending: NonZeroUsize,
    ) -> Self {
        Self {
            capacity: http1_capacity.min(http2_capacity),
            max_http1_active,
            max_http1_pending,
            max_http2_active,
            max_http2_pending,
            max_http2_connections: NonZeroUsize::MIN,
            setup_wait_limit: None,
            state: Mutex::new(PoolState::default()),
            http2_keys: Arc::new(Http2Keys::default()),
            #[cfg(feature = "https-records")]
            https_records: None,
        }
    }

    /// Lets each pool key keep up to `maximum` H2 connections.
    pub(super) const fn with_max_http2_connections(mut self, maximum: NonZeroUsize) -> Self {
        self.max_http2_connections = maximum;
        self
    }

    /// Bounds how long a request waits for another request's setup to a key
    /// that selected H2 before; `None` waits until it finishes.
    pub(super) const fn with_setup_wait_limit(mut self, limit: Option<Duration>) -> Self {
        self.setup_wait_limit = limit;
        self
    }

    /// Gives direct connections the client's HTTPS record lookups, for
    /// profiles that offer ECH from HTTPS records.
    #[cfg(feature = "https-records")]
    pub(super) fn set_https_records(
        &mut self,
        discovery: Option<super::alt_svc::HttpsRecordDiscovery>,
    ) {
        self.https_records = discovery;
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn send_request(
        &self,
        connector: &Http1Or2TlsConnector,
        https_proxy: Option<&HttpsProxyConnector>,
        endpoint: &Endpoint,
        route: &Route,
        request_span: &Span,
        method: Method,
        target: OriginForm,
        http1_headers: Vec<RequestHeader>,
        http2_headers: Vec<RequestHeader>,
        trailers: Vec<RequestHeader>,
        client_hints: Option<ClientHintContext<'_>>,
        body: Option<RequestBody>,
        http2_priority: Option<Http2Priority>,
        fresh_http1_connection: bool,
        leased: Option<NegotiatedLease>,
        timeout_budget: TimeoutBudget,
        retries: &mut ConnectionSetupRetryState,
    ) -> Result<NegotiatedResponse, RequestError> {
        let http1_wire_headers = validate_request(
            endpoint,
            &method,
            &target,
            http1_headers,
            &http2_headers,
            &trailers,
            client_hints,
            body.as_ref(),
        )?;

        // A raced connection was admitted by this pool for this endpoint.
        let mut leased = leased;
        let entry = match &leased {
            Some(leased) => Arc::clone(&leased.entry),
            None => self.entry(PoolKey::new(endpoint, route)).await,
        };
        // Same eligibility as the exact HTTP/2 pool: only a bodyless GET
        // without trailers may repeat after GOAWAY(NO_ERROR).
        let graceful_goaway_replayable =
            method == Method::GET && body.is_none() && trailers.is_empty();
        let request = NegotiatedRequest {
            method,
            authority: endpoint.authority().as_str(),
            target,
            http2_priority,
            trailers,
            client_hints,
        };
        let fields = NegotiatedFields {
            http1_wire_headers,
            http2_headers,
        };
        let retire_unprocessed = retries.replays_unprocessed_requests();
        let mut retried_graceful_goaway = false;
        let mut fresh_http1_connection = fresh_http1_connection;

        loop {
            let (lease, permit) = match leased.take() {
                Some(leased) => (leased.lease, leased.permit),
                None => {
                    let selection = timeout_budget
                        .run(
                            TimeoutPhase::PoolAdmission,
                            None,
                            entry.admit_before_selection(),
                        )
                        .await?;
                    entry
                        .acquire_selected(
                            connector,
                            https_proxy,
                            endpoint,
                            route,
                            request_span,
                            selection,
                            std::mem::take(&mut fresh_http1_connection),
                            timeout_budget,
                            retries,
                        )
                        .await?
                }
            };
            // Only an HTTP/2 stream can be refused by a graceful GOAWAY.
            let replays_graceful_goaway = graceful_goaway_replayable
                && !retried_graceful_goaway
                && matches!(lease, ConnectionLease::Http2(_));
            if !replays_graceful_goaway {
                return entry
                    .dispatch_on_lease(
                        lease,
                        permit,
                        request,
                        fields,
                        body,
                        retire_unprocessed,
                        timeout_budget,
                    )
                    .await
                    .map_err(RequestError::from);
            }
            // The replacement may negotiate either protocol, so both lists
            // stay; this stream needs a copy of the HTTP/2 list only.
            let attempt_fields = NegotiatedFields {
                http1_wire_headers: Vec::new(),
                http2_headers: fields.http2_headers.clone(),
            };
            match entry
                .dispatch_on_lease(
                    lease,
                    permit,
                    request.clone(),
                    attempt_fields,
                    None,
                    retire_unprocessed,
                    timeout_budget,
                )
                .await
            {
                Ok(response) => return Ok(response),
                Err(DispatchFailure::Request(error)) => return Err(error),
                Err(DispatchFailure::GracefulGoaway(_)) => {
                    // The protocol admission was released with the refused
                    // stream; the replacement is admitted and negotiated anew.
                    retried_graceful_goaway = true;
                    debug!(
                        retry = 1,
                        reason = "graceful_goaway",
                        "retrying negotiated request on a replacement connection"
                    );
                }
            }
        }
    }

    /// Admits one request and acquires its ALPN-selected connection without
    /// dispatching; the lease holds the selected protocol's admission.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn acquire_lease(
        &self,
        connector: &Http1Or2TlsConnector,
        https_proxy: Option<&HttpsProxyConnector>,
        endpoint: &Endpoint,
        route: &Route,
        request_span: &Span,
        timeout_budget: TimeoutBudget,
        retries: &mut ConnectionSetupRetryState,
    ) -> Result<NegotiatedLease, RequestError> {
        let entry = self.entry(PoolKey::new(endpoint, route)).await;
        let selection = timeout_budget
            .run(
                TimeoutPhase::PoolAdmission,
                None,
                entry.admit_before_selection(),
            )
            .await?;
        let (lease, permit) = entry
            .acquire_selected(
                connector,
                https_proxy,
                endpoint,
                route,
                request_span,
                selection,
                false,
                timeout_budget,
                retries,
            )
            .await?;
        Ok(NegotiatedLease {
            entry,
            lease,
            permit,
        })
    }

    /// Bounds requests that hold no protocol-specific admission yet.
    ///
    /// ALPN has not chosen H1 or H2 at this point, so the bound takes the
    /// larger active and waiting limit of the two protocols. Every request
    /// that the selected protocol could run or queue is therefore admitted,
    /// while requests waiting for another connection's setup, and setup
    /// retry delays, remain bounded by configured limits.
    fn selection_limits(&self) -> (NonZeroUsize, NonZeroUsize) {
        (
            self.max_http1_active.max(self.max_http2_active),
            self.max_http1_pending.max(self.max_http2_pending),
        )
    }

    /// Admits one stream on the current reusable HTTP/2 generation for this
    /// origin.
    ///
    /// This neither opens a connection nor creates a pool entry, and it does
    /// not change eviction order. An HTTP/1.1 generation yields `None`. When
    /// an HTTP/2 generation exists, the returned permit is the HTTP/2
    /// admission a negotiated request holds once ALPN selected HTTP/2: it
    /// waits at the active bound and fails with a typed capacity error when
    /// the waiting bound is full. The generation is checked again after
    /// admission because it may have been retired while the caller waited.
    #[cfg(feature = "websocket")]
    pub(crate) async fn admit_current_http2_connection(
        &self,
        endpoint: &Endpoint,
        route: &Route,
    ) -> Result<Option<(Http2Connection, AdmissionPermit)>, RequestError> {
        let key = PoolKey::new(endpoint, route);
        let entry = {
            let state = self.state.lock().await;
            state
                .entries
                .iter()
                .find(|(candidate, _)| candidate == &key)
                .map(|(_, entry)| Arc::clone(entry))
        };
        let Some(entry) = entry else {
            return Ok(None);
        };
        if entry.connections.current_http2().is_none() {
            return Ok(None);
        }
        let permit = entry.admit(HttpProtocol::Http2).await?;
        Ok(entry
            .connections
            .current_http2()
            .map(|connection| (connection, permit)))
    }

    /// Returns whether the origin has a reusable HTTP/2 connection, even one
    /// with no room for another stream.
    ///
    /// This neither opens a connection, creates a pool entry, admits a
    /// request, nor changes eviction order. An entry whose only connections
    /// are being set up, or are H1, counts as unavailable.
    pub(crate) async fn has_available_http2(&self, endpoint: &Endpoint, route: &Route) -> bool {
        let key = PoolKey::new(endpoint, route);
        let entry = {
            let state = self.state.lock().await;
            state
                .entries
                .iter()
                .find(|(candidate, _)| candidate == &key)
                .map(|(_, entry)| Arc::clone(entry))
        };
        entry.is_some_and(|entry| entry.connections.current_http2().is_some())
    }

    async fn entry(&self, key: PoolKey) -> Arc<PoolEntry> {
        let mut state = self.state.lock().await;
        if let Some(position) = state
            .entries
            .iter()
            .position(|(candidate, _)| candidate == &key)
            && let Some((stored_key, entry)) = state.entries.remove(position)
        {
            state.entries.push_back((stored_key, Arc::clone(&entry)));
            return entry;
        }

        if state.entries.len() == self.capacity.get() {
            state.entries.pop_front();
            debug!(outcome = "evicted", "negotiated HTTP pool entry evicted");
        }
        let http1_admission =
            state
                .http1_admissions
                .get(&key, self.max_http1_active, self.max_http1_pending);
        let http2_admission =
            state
                .http2_admissions
                .get(&key, self.max_http2_active, self.max_http2_pending);
        let (selection_active, selection_pending) = self.selection_limits();
        let selection_admission =
            state
                .selection_admissions
                .get(&key, selection_active, selection_pending);
        let connections = EntryConnections::new(
            self.max_http1_active,
            Arc::clone(&self.http2_keys),
            key.clone(),
        )
        .with_http2_spread(Http2Spread::new(
            self.max_http2_connections,
            self.max_http2_active,
        ));
        #[cfg_attr(not(feature = "https-records"), allow(unused_mut))]
        let mut entry = PoolEntry::new(
            selection_admission,
            http1_admission,
            http2_admission,
            connections,
        )
        .with_setup_wait_limit(self.setup_wait_limit);
        // HTTPS records are looked up on the direct route only: Chromium sends
        // no HTTPS query for a proxied request.
        #[cfg(feature = "https-records")]
        if key.route == Route::Direct {
            entry.https_records = self.https_records.clone();
        }
        let entry = Arc::new(entry);
        state.entries.push_back((key, Arc::clone(&entry)));
        entry
    }
}

#[derive(Default)]
struct PoolState {
    entries: VecDeque<(PoolKey, Arc<PoolEntry>)>,
    selection_admissions: AdmissionRegistry<PoolKey>,
    http1_admissions: AdmissionRegistry<PoolKey>,
    http2_admissions: AdmissionRegistry<PoolKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PoolKey {
    host: Box<str>,
    port: u16,
    route: Route,
}

impl PoolKey {
    fn new(endpoint: &Endpoint, route: &Route) -> Self {
        Self {
            host: endpoint.host().to_ascii_lowercase().into(),
            port: endpoint.port(),
            route: route.clone(),
        }
    }
}

/// The most pool keys a client remembers as having selected H2: Chromium's
/// `HttpServerProperties::kMaxServerInfoEntries`
/// (`net/http/http_server_properties.h:97`).
const MAX_HTTP2_KEYS: usize = 500;

/// Pool keys whose connections have selected H2, least recently used first.
///
/// The memory outlives pool entries, as Chromium's `HttpServerProperties`
/// outlives its sockets, so an evicted entry does not start over as a first
/// contact. It is keyed by origin and route, as Firefox keys the
/// `ConnectionEntry` that holds `mUsingSpdy`
/// (`netwerk/protocol/http/nsHttpConnectionInfo.cpp:212-232`) and as Phantom
/// keys its other learned state; Chromium keys it by origin alone.
#[derive(Default)]
struct Http2Keys {
    keys: std::sync::Mutex<VecDeque<PoolKey>>,
}

impl Http2Keys {
    fn lock(&self) -> MutexGuard<'_, VecDeque<PoolKey>> {
        self.keys.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns whether `key` selected H2 before, marking it recently used.
    fn contains(&self, key: &PoolKey) -> bool {
        let mut keys = self.lock();
        let Some(position) = keys.iter().position(|candidate| candidate == key) else {
            return false;
        };
        if let Some(found) = keys.remove(position) {
            keys.push_back(found);
        }
        true
    }

    fn insert(&self, key: &PoolKey) {
        let mut keys = self.lock();
        if let Some(position) = keys.iter().position(|candidate| candidate == key) {
            keys.remove(position);
        } else if keys.len() == MAX_HTTP2_KEYS {
            keys.pop_front();
        }
        keys.push_back(key.clone());
    }
}

struct PoolEntry {
    connections: Arc<EntryConnections>,
    selection_admission: Arc<Admission>,
    http1_admission: Arc<Admission>,
    http2_admission: Arc<Admission>,
    connector: OnceLock<Http1Or2TlsConnector>,
    https_proxy: OnceLock<HttpsProxyConnector>,
    setup_wait_limit: Option<Duration>,
    #[cfg(feature = "https-records")]
    https_records: Option<super::alt_svc::HttpsRecordDiscovery>,
}

impl PoolEntry {
    fn new(
        selection_admission: Arc<Admission>,
        http1_admission: Arc<Admission>,
        http2_admission: Arc<Admission>,
        connections: EntryConnections,
    ) -> Self {
        Self {
            connections: Arc::new(connections),
            selection_admission,
            http1_admission,
            http2_admission,
            connector: OnceLock::new(),
            https_proxy: OnceLock::new(),
            setup_wait_limit: None,
            #[cfg(feature = "https-records")]
            https_records: None,
        }
    }

    const fn with_setup_wait_limit(mut self, limit: Option<Duration>) -> Self {
        self.setup_wait_limit = limit;
        self
    }

    /// Opens a direct connection, offering the `ech` value of the origin's
    /// HTTPS record when the profile does, as Chrome 154 does.
    async fn connect_direct(
        &self,
        connector: &Http1Or2TlsConnector,
        endpoint: &Endpoint,
    ) -> Result<Http1Or2Connection, Http1Or2TlsError> {
        #[cfg(feature = "https-records")]
        if connector.ech_from_https_records()
            && let Some(discovery) = &self.https_records
        {
            let ech = discovery.tcp_ech(endpoint, connector.alpn_protocols());
            return connector
                .connect_direct_with_ech(endpoint.host(), endpoint.port(), endpoint.host(), ech)
                .await;
        }
        connector
            .connect_direct(endpoint.host(), endpoint.port(), endpoint.host())
            .await
    }

    /// Phase one: bounded admission before ALPN selects a protocol.
    async fn admit_before_selection(&self) -> Result<AdmissionPermit, RequestError> {
        Arc::clone(&self.selection_admission)
            .admit_unselected()
            .await
    }

    async fn admit(&self, protocol: HttpProtocol) -> Result<AdmissionPermit, RequestError> {
        match protocol {
            HttpProtocol::Http1 => Arc::clone(&self.http1_admission).admit(protocol).await,
            HttpProtocol::Http2 => Arc::clone(&self.http2_admission).admit(protocol).await,
            HttpProtocol::Http3 => Err(RequestError::unsupported_protocol(protocol)),
        }
    }

    /// Admits one request to an H1 connection slot, waiting in arrival order.
    ///
    /// Only a request to a key with an H1 connection waits here, so the
    /// capacity error names H1. `protocol` is `None` only when every slot was
    /// taken with no setup in flight, which lasts until a slot holder
    /// reserves its setup.
    async fn admit_connection_slot(
        &self,
        protocol: Option<HttpProtocol>,
    ) -> Result<AdmissionPermit, RequestError> {
        match protocol {
            Some(protocol) => Arc::clone(&self.http1_admission).admit(protocol).await,
            None => Arc::clone(&self.http1_admission).admit_unselected().await,
        }
    }

    /// Phase two: acquires a selected-protocol lease and converts admission.
    ///
    /// `selection` stays held across setup retry delays and until the selected
    /// protocol admits the request, so the request is always counted by one
    /// bounded admission; its connection slot is released during the delay.
    /// No lock is held across an await. `fresh_http1` makes the request skip
    /// idle H1 connections until it acquires a connection.
    ///
    /// While ALPN has not chosen a protocol for the key, a request that finds
    /// every slot held by a setup in flight waits for a setup to finish
    /// instead of queueing for a slot: the setup may select H2, which serves
    /// the request without a slot. Only a key with an H1 connection queues
    /// requests at the H1 waiting bound.
    ///
    /// A request to a key that selected H2 before waits for a setup in
    /// flight for at most the entry's setup wait limit, when one is set, and
    /// then opens a connection of its own.
    #[allow(clippy::too_many_arguments)]
    async fn acquire_selected(
        &self,
        connector: &Http1Or2TlsConnector,
        https_proxy: Option<&HttpsProxyConnector>,
        endpoint: &Endpoint,
        route: &Route,
        request_span: &Span,
        selection: AdmissionPermit,
        fresh_http1: bool,
        timeout_budget: TimeoutBudget,
        retries: &mut ConnectionSetupRetryState,
    ) -> Result<(ConnectionLease, AdmissionPermit), RequestError> {
        let mut force_new_connection = fresh_http1;
        // One connect deadline covers each setup attempt: waiting for another
        // request's setup and this request's own. A setup retry starts anew.
        let mut connect: Option<PhaseTimeout> = None;
        // Set once the setup wait limit passed; the request then opens its
        // own connection instead of waiting again.
        let mut setup_wait_expired = false;
        loop {
            let slot = match self.connections.before_admission(setup_wait_expired) {
                BeforeAdmission::Http2 => {
                    if let Some(admitted) =
                        self.try_admit_http2(request_span, timeout_budget).await?
                    {
                        drop(selection);
                        return Ok(admitted);
                    }
                    continue;
                }
                BeforeAdmission::AwaitSetup => {
                    if !self.await_http2_setup(&mut connect, timeout_budget).await? {
                        setup_wait_expired = true;
                    }
                    continue;
                }
                BeforeAdmission::Admit(Some(protocol)) => {
                    timeout_budget
                        .run(
                            TimeoutPhase::PoolAdmission,
                            Some(protocol),
                            self.admit_connection_slot(Some(protocol)),
                        )
                        .await?
                }
                BeforeAdmission::Admit(None) => {
                    match Arc::clone(&self.http1_admission).try_admit() {
                        Some(slot) => slot,
                        None if self.await_setup(&mut connect, timeout_budget).await? => continue,
                        // Every slot is taken and no setup is in flight.
                        None => {
                            timeout_budget
                                .run(
                                    TimeoutPhase::PoolAdmission,
                                    None,
                                    self.admit_connection_slot(None),
                                )
                                .await?
                        }
                    }
                }
            };
            // Connector futures include bounded proxy-authentication state
            // machines; keep them off this future's stack.
            let attempt = Box::pin(self.acquire(
                connector,
                https_proxy,
                endpoint,
                route,
                force_new_connection,
                setup_wait_expired,
            ));
            let acquired = match connect_phase(&mut connect, timeout_budget)?
                .run(attempt)
                .await
            {
                Ok(acquired) => acquired,
                Err(error) => {
                    // A request in a retry delay has no connection, so its
                    // slot goes back before the delay.
                    drop(slot);
                    connect = None;
                    if retries.retry_after(&error, None, timeout_budget).await? {
                        continue;
                    }
                    return Err(error);
                }
            };
            match acquired {
                // The slot goes back before waiting, so the setup being
                // awaited never waits for this request.
                Acquired::AwaitSetup => {}
                Acquired::Http1(lease) => {
                    request_span.record("selected_protocol", HttpProtocol::Http1.trace_name());
                    drop(selection);
                    return Ok((ConnectionLease::Http1(lease), slot));
                }
                // An H2 request holds H2 admission, not a slot.
                Acquired::Http2 => {
                    drop(slot);
                    force_new_connection = false;
                    if let Some(admitted) =
                        self.try_admit_http2(request_span, timeout_budget).await?
                    {
                        drop(selection);
                        return Ok(admitted);
                    }
                }
            }
        }
    }

    /// Waits under the attempt's connect deadline, and at most the setup
    /// wait limit, for a setup in flight to a key that selected H2 before.
    ///
    /// Returns `false` when the limit passed first. Chromium 154 bounds this
    /// wait by 300 ms; Firefox 156 does not bound it (see
    /// [`ConnectionState::awaits_setup`]).
    async fn await_http2_setup(
        &self,
        connect: &mut Option<PhaseTimeout>,
        timeout_budget: TimeoutBudget,
    ) -> Result<bool, RequestError> {
        let limit = self.setup_wait_limit;
        connect_phase(connect, timeout_budget)?
            .run(async {
                match limit {
                    Some(limit) => Ok(within(limit, self.connections.setup_finished())
                        .await?
                        .is_some()),
                    None => {
                        self.connections.setup_finished().await;
                        Ok(true)
                    }
                }
            })
            .await
    }

    /// Waits under the attempt's connect deadline for a setup in flight;
    /// returns `false` at once when none is.
    async fn await_setup(
        &self,
        connect: &mut Option<PhaseTimeout>,
        timeout_budget: TimeoutBudget,
    ) -> Result<bool, RequestError> {
        connect_phase(connect, timeout_budget)?
            .run(async { Ok(self.connections.setup_finished().await) })
            .await
    }

    /// Admits a request to one of the key's H2 connections.
    ///
    /// The connection is chosen after admission, when the streams in flight
    /// are known. Returns `None` when no connection is reusable any more, or
    /// none has room and the key may open another.
    async fn try_admit_http2(
        &self,
        request_span: &Span,
        timeout_budget: TimeoutBudget,
    ) -> Result<Option<(ConnectionLease, AdmissionPermit)>, RequestError> {
        request_span.record("selected_protocol", HttpProtocol::Http2.trace_name());
        let permit = timeout_budget
            .run(
                TimeoutPhase::PoolAdmission,
                Some(HttpProtocol::Http2),
                self.admit(HttpProtocol::Http2),
            )
            .await?;
        Ok(self
            .connections
            .open_http2_stream()
            .map(|stream| (ConnectionLease::Http2(stream), permit)))
    }

    /// Phase three: dispatches the request on its admitted lease.
    ///
    /// `retire_unprocessed` retires an H2 connection that refused the stream,
    /// so an unprocessed replay uses another connection.
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_on_lease(
        &self,
        lease: ConnectionLease,
        permit: AdmissionPermit,
        request: NegotiatedRequest<'_>,
        fields: NegotiatedFields,
        body: Option<RequestBody>,
        retire_unprocessed: bool,
        timeout_budget: TimeoutBudget,
    ) -> Result<NegotiatedResponse, DispatchFailure> {
        let NegotiatedRequest {
            method,
            authority,
            target,
            http2_priority,
            trailers,
            client_hints,
        } = request;
        let NegotiatedFields {
            http1_wire_headers,
            http2_headers,
        } = fields;

        match lease {
            ConnectionLease::Http1(mut lease) => {
                // The fields as sent follow the `Host` field `validate_request`
                // put first.
                let http1_sent_headers: Vec<_> =
                    http1_wire_headers.iter().skip(1).cloned().collect();
                let result = timeout_budget
                    .run(
                        TimeoutPhase::ResponseHead,
                        Some(HttpProtocol::Http1),
                        async {
                            Ok::<_, RequestError>(
                                lease
                                    .connection
                                    .send_request_body_with_trailers(
                                        method,
                                        target,
                                        http1_wire_headers,
                                        body,
                                        trailers,
                                    )
                                    .await,
                            )
                        },
                    )
                    .await;
                match result {
                    Ok(Ok(response)) => {
                        let (parts, body) = response.into_parts();
                        Ok((
                            Response::from_parts(
                                parts,
                                ResponseBody::http1_with_guard(
                                    body,
                                    Http1RequestGuard {
                                        _lease: lease,
                                        _permit: permit,
                                    },
                                ),
                            ),
                            HttpProtocol::Http1,
                            http1_sent_headers,
                        ))
                    }
                    Ok(Err(error)) => {
                        // The lease drops before the permit, so the next
                        // admitted request finds a reusable connection idle.
                        drop(lease);
                        drop(permit);
                        Err(RequestError::http1(error.into()).into())
                    }
                    Err(error) => {
                        lease.retire();
                        drop(lease);
                        drop(permit);
                        Err(error.into())
                    }
                }
            }
            ConnectionLease::Http2(lease) => {
                let Http2Stream {
                    connection,
                    token,
                    stream,
                } = lease;
                let sent_headers = prepare_headers(
                    client_hints,
                    http2_headers,
                    client_hints
                        .and_then(|context| connection.accept_ch_for_origin(context.origin())),
                )?;
                let result = timeout_budget
                    .run(
                        TimeoutPhase::ResponseHead,
                        Some(HttpProtocol::Http2),
                        async {
                            Ok::<_, RequestError>(
                                send_on(
                                    &connection,
                                    method,
                                    authority,
                                    target,
                                    sent_headers.clone(),
                                    body,
                                    trailers,
                                    http2_priority,
                                )
                                .await,
                            )
                        },
                    )
                    .await;
                match result {
                    Ok(Ok(response)) => {
                        let (parts, body) = response.into_parts();
                        Ok((
                            Response::from_parts(
                                parts,
                                // The stream count drops first, so the
                                // request the permit admits next sees it.
                                ResponseBody::http2_with_guard(body, (stream, permit)),
                            ),
                            HttpProtocol::Http2,
                            sent_headers,
                        ))
                    }
                    Ok(Err(error)) => {
                        drop(stream);
                        drop(permit);
                        if invalidates_http2_connection(&error)
                            || (retire_unprocessed && is_unprocessed_http2(&error))
                        {
                            self.connections.invalidate_http2(&token);
                        }
                        if is_graceful_goaway(&error) {
                            return Err(DispatchFailure::GracefulGoaway(error));
                        }
                        Err(RequestError::http2_stream(error).into())
                    }
                    Err(error) => {
                        drop(stream);
                        drop(permit);
                        Err(error.into())
                    }
                }
            }
        }
    }

    /// Leases a pooled connection for a request that holds a connection
    /// slot, or opens one when none can serve it.
    async fn acquire(
        &self,
        connector: &Http1Or2TlsConnector,
        https_proxy: Option<&HttpsProxyConnector>,
        endpoint: &Endpoint,
        route: &Route,
        force_new_connection: bool,
        setup_wait_expired: bool,
    ) -> Result<Acquired, RequestError> {
        let reservation = match self
            .connections
            .checkout(force_new_connection, setup_wait_expired)
        {
            Checkout::Found(acquired) => return Ok(acquired),
            Checkout::Reserved(reservation) => reservation,
        };

        debug!(
            outcome = "connect",
            "negotiated HTTP pool opening connection"
        );
        // Boxed: opening a connection awaits the largest connector futures,
        // which would otherwise enlarge the future of every request, including
        // one that reuses a pooled connection.
        let connection = Box::pin(self.open(connector, https_proxy, endpoint, route)).await?;
        Ok(reservation.finish(connection.into()))
    }

    /// Opens a connection for [`Self::acquire`] over `route`.
    async fn open(
        &self,
        connector: &Http1Or2TlsConnector,
        https_proxy: Option<&HttpsProxyConnector>,
        endpoint: &Endpoint,
        route: &Route,
    ) -> Result<Http1Or2Connection, RequestError> {
        let connector = self
            .connector
            .get_or_init(|| connector.with_isolated_session_cache());
        let connection = match route {
            Route::Direct => self
                .connect_direct(connector, endpoint)
                .await
                .map_err(RequestError::http1_or_2_connection_setup)?,
            // The origin keeps its own TLS identity: the proxy carries the
            // stream, and `endpoint.host()` remains the verified name and SNI.
            Route::Socks5(proxy) => match proxy.dns_mode() {
                Socks5DnsMode::Local => connector
                    .connect_socks5_local_with_auth(
                        proxy.host(),
                        proxy.port(),
                        proxy.auth(),
                        endpoint.host(),
                        endpoint.port(),
                        endpoint.host(),
                    )
                    .await
                    .map_err(RequestError::http1_or_2_connection_setup)?,
                Socks5DnsMode::Remote => connector
                    .connect_socks5_remote_with_auth(
                        proxy.host(),
                        proxy.port(),
                        proxy.auth(),
                        endpoint.host(),
                        endpoint.port(),
                        endpoint.host(),
                    )
                    .await
                    .map_err(RequestError::http1_or_2_connection_setup)?,
            },
            // One CONNECT tunnel carries one origin TLS handshake, as the
            // exact H1 and H2 pools do; ALPN inside it selects the protocol.
            Route::HttpProxy(proxy) => {
                let connect_authority = endpoint.tunnel_authority();
                if proxy.uses_tls() {
                    let base =
                        https_proxy.ok_or_else(RequestError::unsupported_negotiated_route)?;
                    let proxy_connector = self
                        .https_proxy
                        .get_or_init(|| proxy.https_connector(&base.with_isolated_session_cache()));
                    if let Some(credentials) = proxy.basic_credentials() {
                        // The retry state machine is large; one allocation per
                        // authenticated proxy connection bounds this future.
                        Box::pin(connector.connect_https_connect_with_basic_auth(
                            proxy_connector,
                            proxy.host(),
                            proxy.port(),
                            proxy.host(),
                            &connect_authority,
                            proxy.ordered_connect_headers(),
                            credentials,
                            endpoint.host(),
                        ))
                        .await
                        .map_err(RequestError::http1_or_2_connection_setup)?
                    } else {
                        connector
                            .connect_https_connect(
                                proxy_connector,
                                proxy.host(),
                                proxy.port(),
                                proxy.host(),
                                &connect_authority,
                                proxy.ordered_connect_headers(),
                                endpoint.host(),
                            )
                            .await
                            .map_err(RequestError::http1_or_2_connection_setup)?
                    }
                } else if let Some(credentials) = proxy.basic_credentials() {
                    // See the TLS-proxy branch above.
                    Box::pin(connector.connect_http_connect_with_basic_auth(
                        proxy.host(),
                        proxy.port(),
                        &connect_authority,
                        proxy.ordered_connect_headers(),
                        credentials,
                        endpoint.host(),
                    ))
                    .await
                    .map_err(RequestError::http1_or_2_connection_setup)?
                } else {
                    connector
                        .connect_http_connect(
                            proxy.host(),
                            proxy.port(),
                            &connect_authority,
                            proxy.ordered_connect_headers(),
                            endpoint.host(),
                        )
                        .await
                        .map_err(RequestError::http1_or_2_connection_setup)?
                }
            }
            // Refused before admission by `ensure_request_supported`; the route
            // is never reinterpreted as another transport here.
            Route::ConnectUdp(_) => {
                return Err(RequestError::unsupported_negotiated_route());
            }
        };
        Ok(connection)
    }
}

/// Returns the attempt's connect deadline, starting it on first use.
fn connect_phase(
    connect: &mut Option<PhaseTimeout>,
    timeout_budget: TimeoutBudget,
) -> Result<PhaseTimeout, RequestError> {
    if let Some(phase) = *connect {
        return Ok(phase);
    }
    let phase = timeout_budget.phase(TimeoutPhase::Connect, None)?;
    *connect = Some(phase);
    Ok(phase)
}

/// The connections of one negotiated pool key.
///
/// Up to the spread's connection limit of reusable H2 connections, one by
/// default, serve the key. H1 connections, idle
/// or leased, and connections whose setup has not finished, so whose protocol
/// ALPN has not chosen yet, number at most `max_http1` together. A request
/// holds a connection slot from the key's H1 admission, which lets at most
/// `max_http1` requests through, before it leases an H1 connection or opens
/// one, and each such request holds at most one. A request that finds no
/// idle connection therefore always has room to open one.
struct EntryConnections {
    max_http1: NonZeroUsize,
    state: std::sync::Mutex<ConnectionState>,
    /// Woken whenever a connection setup finishes, fails, or is cancelled,
    /// and whenever a stream on one of the key's H2 connections ends.
    setup_done: Arc<Notify>,
    /// The client's memory of keys that selected H2, and this entry's key.
    http2_keys: Arc<Http2Keys>,
    key: PoolKey,
}

struct ConnectionState {
    /// Reusable H2 connections, oldest first.
    http2: Vec<Http2Slot>,
    /// How H2 streams spread across `http2`.
    spread: Http2Spread,
    /// H1 connections with no request, least recently used first.
    http1_idle: Vec<Http1Connection>,
    /// H1 connections leased to a request.
    http1_leased: usize,
    /// Connections being set up.
    connecting: usize,
    /// A connection to this key has selected H2 before, in this entry or in
    /// the client's [`Http2Keys`]. Chromium's `SetSupportsSpdy` and Firefox's
    /// `mUsingSpdy` record the same fact, and neither clears it when a later
    /// connection selects H1: every writer sets it to true
    /// (`net/http/http_stream_factory_job.cc:1304-1306`,
    /// `net/http/http_stream_pool_attempt_manager.cc:823-825`;
    /// `netwerk/protocol/http/nsHttpConnectionMgr.cpp:1023`, `:3920`).
    selected_http2: bool,
}

impl ConnectionState {
    fn open_http1_or_connecting(&self) -> usize {
        self.http1_idle.len() + self.http1_leased + self.connecting
    }

    /// Chooses among the reusable H2 connections, forgetting closed ones.
    fn choose_http2(&mut self) -> Choice {
        self.http2.retain(|slot| slot.connection.is_reusable());
        self.spread.choose(
            self.http2
                .iter()
                .map(|slot| (&slot.connection, &slot.streams)),
        )
    }

    /// Returns the H2 connection a new stream would use, if one has room or
    /// the key is at its connection limit.
    fn current_http2(&mut self) -> Option<&Http2Slot> {
        match self.choose_http2() {
            Choice::Use(index) => self.http2.get(index),
            Choice::Open => None,
        }
    }

    /// Whether a request should wait for a setup in flight rather than open
    /// a connection of its own.
    ///
    /// Once the key has selected H2, the setup in flight will most likely
    /// select it again and then carry every request. Chromium 154 holds new
    /// connection attempts to such a server until the first one finishes, for
    /// at most 300 ms (`net/http/http_stream_factory_job.cc:749-775`,
    /// `:1417-1429`), and Firefox 156 holds them until the attempt reports
    /// its protocol (`netwerk/protocol/http/ConnectionEntry.cpp:225-248`,
    /// `nsHttpConnectionMgr.cpp:1399-1409`). Phantom waits as Firefox does,
    /// unless the caller sets a limit
    /// (`ClientBuilder::negotiated_setup_wait_limit`).
    /// A key whose protocol is unknown waits only when every slot is taken
    /// (see [`PoolEntry::acquire_selected`]).
    fn awaits_setup(&self) -> bool {
        self.selected_http2 && self.connecting > 0
    }
}

/// What a request can do before it takes a connection slot.
enum BeforeAdmission {
    /// An H2 connection can take the request once H2 admits it.
    Http2,
    AwaitSetup,
    /// Take a connection slot; the protocol names the capacity error.
    Admit(Option<HttpProtocol>),
}

/// What a request holding a connection slot found.
enum Checkout {
    Found(Acquired),
    /// No connection can serve the request, so it opens one.
    Reserved(Reservation),
}

/// A connection for a request holding a connection slot, or the need to
/// wait for another request's setup.
enum Acquired {
    Http1(Http1Lease),
    /// An H2 connection can take the request once H2 admits it.
    Http2,
    AwaitSetup,
}

impl EntryConnections {
    /// Starts with the browser default of one H2 connection per key.
    fn new(max_http1: NonZeroUsize, http2_keys: Arc<Http2Keys>, key: PoolKey) -> Self {
        let state = ConnectionState {
            http2: Vec::new(),
            spread: Http2Spread::new(NonZeroUsize::MIN, NonZeroUsize::MAX),
            http1_idle: Vec::new(),
            http1_leased: 0,
            connecting: 0,
            selected_http2: http2_keys.contains(&key),
        };
        Self {
            max_http1,
            state: std::sync::Mutex::new(state),
            setup_done: Arc::new(Notify::new()),
            http2_keys,
            key,
        }
    }

    fn with_http2_spread(self, spread: Http2Spread) -> Self {
        self.lock().spread = spread;
        self
    }

    fn lock(&self) -> MutexGuard<'_, ConnectionState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns a reusable H2 connection of the key, whether or not it has
    /// room for another stream: the one a new stream would use, or else the
    /// oldest. WebSocket reuse and the Alt-Svc race treat the key as
    /// speaking H2 whenever one exists, as the exact H2 pool does.
    fn current_http2(&self) -> Option<Http2Connection> {
        let mut state = self.lock();
        let index = match state.choose_http2() {
            Choice::Use(index) => index,
            Choice::Open => 0,
        };
        state.http2.get(index).map(|slot| slot.connection.clone())
    }

    #[cfg(test)]
    fn current_http2_token(&self) -> Option<Arc<()>> {
        let mut state = self.lock();
        let index = match state.choose_http2() {
            Choice::Use(index) => index,
            Choice::Open => 0,
        };
        state.http2.get(index).map(|slot| Arc::clone(&slot.token))
    }

    /// Opens a counted stream on the H2 connection chosen now, or returns
    /// `None` when no connection is reusable or the key should open another.
    fn open_http2_stream(&self) -> Option<Http2Stream> {
        let mut state = self.lock();
        match state.choose_http2() {
            Choice::Use(index) => state.http2.get(index).map(Http2Slot::stream),
            Choice::Open => None,
        }
    }

    /// `setup_wait_expired` skips the wait for a setup in flight to a key
    /// that selected H2.
    fn before_admission(&self, setup_wait_expired: bool) -> BeforeAdmission {
        let mut state = self.lock();
        if matches!(state.choose_http2(), Choice::Use(_)) {
            return BeforeAdmission::Http2;
        }
        if !setup_wait_expired && state.awaits_setup() {
            return BeforeAdmission::AwaitSetup;
        }
        let has_http1 = !state.http1_idle.is_empty() || state.http1_leased > 0;
        BeforeAdmission::Admit(has_http1.then_some(HttpProtocol::Http1))
    }

    /// Waits until a setup in flight finishes, fails, or is cancelled, or an
    /// H2 stream of the key ends; callers choose again either way.
    ///
    /// Returns `false` at once when no setup is in flight.
    async fn setup_finished(&self) -> bool {
        let mut notified = pin!(self.setup_done.notified());
        // Registered before the check, so a setup finishing in between still
        // wakes this waiter.
        notified.as_mut().enable();
        if self.lock().connecting == 0 {
            return false;
        }
        notified.await;
        true
    }

    /// Leases the H2 connection or the most recently used idle H1
    /// connection, or reserves a slot for a new connection.
    ///
    /// `force_new_connection` skips idle H1 connections, closing the least
    /// recently used one when the key is at its bound. `setup_wait_expired`
    /// skips the wait for a setup in flight to a key that selected H2.
    fn checkout(
        self: &Arc<Self>,
        force_new_connection: bool,
        setup_wait_expired: bool,
    ) -> Checkout {
        let mut state = self.lock();
        if state.current_http2().is_some() {
            return Checkout::Found(Acquired::Http2);
        }
        if !setup_wait_expired && state.awaits_setup() {
            return Checkout::Found(Acquired::AwaitSetup);
        }
        state.http1_idle.retain(Http1Connection::is_reusable);
        let idle = if force_new_connection {
            if state.open_http1_or_connecting() >= self.max_http1.get()
                && !state.http1_idle.is_empty()
            {
                // A reused-connection replay needs a connection that has
                // carried no earlier request. Close the least recently used
                // idle one to stay within the bound.
                state.http1_idle.remove(0);
                debug!(
                    outcome = "retired",
                    "negotiated HTTP/1 connection retired before a fresh-connection attempt"
                );
            }
            None
        } else {
            state.http1_idle.pop()
        };
        match idle {
            Some(connection) => {
                state.http1_leased += 1;
                debug!(
                    outcome = "hit",
                    "negotiated HTTP/1 connection acquired from client pool"
                );
                Checkout::Found(Acquired::Http1(Http1Lease {
                    connections: Arc::clone(self),
                    connection,
                    retired: false,
                }))
            }
            None => {
                state.connecting += 1;
                Checkout::Reserved(Reservation {
                    connections: Arc::clone(self),
                    finished: false,
                })
            }
        }
    }

    fn invalidate_http2(&self, token: &Arc<()>) {
        let mut state = self.lock();
        if let Some(position) = state
            .http2
            .iter()
            .position(|slot| Arc::ptr_eq(&slot.token, token))
        {
            state.http2.remove(position);
            debug!(
                outcome = "invalidated",
                "negotiated HTTP/2 connection invalidated"
            );
        }
    }

    /// Frees one leased H1 connection, keeping it idle when it is reusable.
    fn release_http1(&self, connection: Option<Http1Connection>) {
        let mut state = self.lock();
        state.http1_leased = state.http1_leased.saturating_sub(1);
        match connection {
            Some(connection) if connection.is_reusable() => state.http1_idle.push(connection),
            _ => debug!(
                outcome = "invalidated",
                "negotiated HTTP/1 pooled connection invalidated"
            ),
        }
    }

    #[cfg(test)]
    fn http2_connections(&self) -> usize {
        self.lock().http2.len()
    }

    #[cfg(test)]
    fn counts(&self) -> (usize, usize, usize) {
        let state = self.lock();
        (state.http1_idle.len(), state.http1_leased, state.connecting)
    }
}

/// A connection slot counted against the key's bound while its setup runs.
///
/// Dropping it unfinished, when setup fails or the request is cancelled,
/// frees the slot and wakes requests waiting for the setup.
struct Reservation {
    connections: Arc<EntryConnections>,
    finished: bool,
}

impl Reservation {
    /// Records the protocol ALPN selected and leases the connection.
    ///
    /// A second H2 connection is closed and its request joins the current
    /// one, as Chromium does when an H2 session to the key appeared while its
    /// own socket connected (`net/http/http_stream_factory_job.cc:1245-1280`).
    /// Only a key allowed more than one H2 connection, whose connections are
    /// all full, keeps it. The key's first H2 connection closes its idle H1
    /// connections, as Chromium closes the group's idle sockets
    /// (`:1283-1287`).
    fn finish(mut self, connection: PooledConnection) -> Acquired {
        self.finished = true;
        let mut remember_http2 = false;
        let mut state = self.connections.lock();
        state.connecting = state.connecting.saturating_sub(1);
        let (lease, closed_http2, closed_http1) = match connection {
            PooledConnection::Http1(connection) => {
                state.http1_leased += 1;
                let lease = Acquired::Http1(Http1Lease {
                    connections: Arc::clone(&self.connections),
                    connection,
                    retired: false,
                });
                (lease, None, Vec::new())
            }
            PooledConnection::Http2(connection) => {
                state.selected_http2 = true;
                remember_http2 = true;
                match state.current_http2() {
                    Some(_) => {
                        debug!(
                            outcome = "redundant",
                            "negotiated HTTP/2 connection closed in favor of the current one"
                        );
                        (Acquired::Http2, Some(connection), Vec::new())
                    }
                    None => {
                        let first = state.http2.is_empty();
                        let slot = Http2Slot {
                            connection,
                            token: Arc::new(()),
                            streams: StreamCount::notifying(Arc::clone(
                                &self.connections.setup_done,
                            )),
                        };
                        state.http2.push(slot);
                        let idle = if first {
                            std::mem::take(&mut state.http1_idle)
                        } else {
                            Vec::new()
                        };
                        (Acquired::Http2, None, idle)
                    }
                }
            }
        };
        drop(state);
        // Dropping the last handle shuts a connection down; that happens
        // outside the state lock.
        drop(closed_http2);
        drop(closed_http1);
        if remember_http2 {
            self.connections.http2_keys.insert(&self.connections.key);
        }
        self.connections.setup_done.notify_waiters();
        lease
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.finished {
            let mut state = self.connections.lock();
            state.connecting = state.connecting.saturating_sub(1);
            drop(state);
            self.connections.setup_done.notify_waiters();
        }
    }
}

/// A negotiated connection admitted for one request and not yet dispatched.
pub(crate) struct NegotiatedLease {
    entry: Arc<PoolEntry>,
    lease: ConnectionLease,
    permit: AdmissionPermit,
}

/// Checks one negotiated request's H1 and H2 representations before any I/O
/// and returns the H1 wire fields: `Host`, then the H1 fields as sent.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_request(
    endpoint: &Endpoint,
    method: &Method,
    target: &OriginForm,
    http1_headers: Vec<RequestHeader>,
    http2_headers: &[RequestHeader],
    trailers: &[RequestHeader],
    client_hints: Option<ClientHintContext<'_>>,
    body: Option<&RequestBody>,
) -> Result<Vec<RequestHeader>, RequestError> {
    let http1_sent_headers = prepare_headers(client_hints, http1_headers, None)?;
    // Without client hints the H2 fields are sent as they are, so they are
    // checked in place; with hints, the hints known before the connection is
    // chosen are placed in a copy.
    let http2_prepared;
    let http2_validation_headers = match client_hints {
        Some(context) => {
            http2_prepared = context.prepare(http2_headers.to_vec(), None)?;
            &http2_prepared[..]
        }
        None => http2_headers,
    };
    let mut http1_wire_headers = Vec::with_capacity(http1_sent_headers.len() + 1);
    http1_wire_headers.push(RequestHeader::new(
        "Host",
        endpoint.authority().as_str().as_bytes(),
    ));
    http1_wire_headers.extend(http1_sent_headers);
    validate_http1_request_body_source_with_trailers(
        method,
        target,
        &http1_wire_headers,
        body,
        trailers,
    )
    .map_err(RequestError::negotiated_http1_validation)?;
    validate_http2_request_body_source_with_trailers(
        method,
        endpoint.authority().as_str(),
        target,
        http2_validation_headers,
        body,
        trailers,
    )
    .map_err(RequestError::negotiated_http2_validation)?;
    Ok(http1_wire_headers)
}

/// One negotiated request, without its body or fields, for either protocol.
#[derive(Clone)]
struct NegotiatedRequest<'a> {
    method: Method,
    authority: &'a str,
    target: OriginForm,
    http2_priority: Option<Http2Priority>,
    trailers: Vec<RequestHeader>,
    client_hints: Option<ClientHintContext<'a>>,
}

/// The field lists of one negotiated request. A dispatch consumes only the
/// list of the protocol its connection selected.
struct NegotiatedFields {
    /// `Host`, then the H1 fields with client hints placed.
    http1_wire_headers: Vec<RequestHeader>,
    /// The H2 fields before client hints are placed for the connection.
    http2_headers: Vec<RequestHeader>,
}

type NegotiatedResponse = (Response<ResponseBody>, HttpProtocol, Vec<RequestHeader>);

enum DispatchFailure {
    /// The peer refused the stream with `GOAWAY(NO_ERROR)` before processing it.
    GracefulGoaway(Http2Error),
    Request(RequestError),
}

impl From<RequestError> for DispatchFailure {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

impl From<DispatchFailure> for RequestError {
    fn from(failure: DispatchFailure) -> Self {
        match failure {
            DispatchFailure::GracefulGoaway(error) => Self::http2_stream(error),
            DispatchFailure::Request(error) => error,
        }
    }
}

enum PooledConnection {
    Http1(Http1Connection),
    Http2(Http2Connection),
}

impl From<Http1Or2Connection> for PooledConnection {
    fn from(connection: Http1Or2Connection) -> Self {
        match connection {
            Http1Or2Connection::Http1(connection) => Self::Http1(connection),
            Http1Or2Connection::Http2(connection) => Self::Http2(connection),
        }
    }
}

enum ConnectionLease {
    Http1(Http1Lease),
    Http2(Http2Stream),
}

/// One of the key's reusable H2 connections, which requests share.
///
/// The token identifies the connection, so a failure retires it only while
/// the key still holds it.
struct Http2Slot {
    connection: Http2Connection,
    token: Arc<()>,
    streams: StreamCount,
}

impl Http2Slot {
    fn stream(&self) -> Http2Stream {
        Http2Stream {
            connection: self.connection.clone(),
            token: Arc::clone(&self.token),
            stream: self.streams.open(),
        }
    }
}

/// One admitted request's stream on an H2 connection, counted against the
/// connection until the response body ends.
struct Http2Stream {
    connection: Http2Connection,
    token: Arc<()>,
    stream: OpenStream,
}

/// One request's hold on an H1 connection of the key.
///
/// Dropping it returns a still-reusable connection to the idle list unless
/// it was retired.
struct Http1Lease {
    connections: Arc<EntryConnections>,
    connection: Http1Connection,
    retired: bool,
}

impl Http1Lease {
    /// Keeps this connection from serving another request.
    fn retire(&mut self) {
        self.retired = true;
    }
}

impl Drop for Http1Lease {
    fn drop(&mut self) {
        let connection = (!self.retired).then(|| self.connection.clone());
        self.connections.release_http1(connection);
    }
}

/// Held by an H1 response body until it completes or is dropped.
///
/// Fields drop in declaration order, so the connection returns to the idle
/// list before the connection slot lets the next request in.
struct Http1RequestGuard {
    _lease: Http1Lease,
    _permit: AdmissionPermit,
}

fn prepare_headers(
    client_hints: Option<ClientHintContext<'_>>,
    headers: Vec<RequestHeader>,
    connection_accept_ch: Option<&[u8]>,
) -> Result<Vec<RequestHeader>, RequestError> {
    match client_hints {
        Some(context) => context.prepare(headers, connection_accept_ch),
        None => Ok(headers),
    }
}

fn invalidates_http2_connection(error: &Http2Error) -> bool {
    matches!(
        error,
        Http2Error::Protocol(error)
            if error.kind() != Http2ProtocolErrorKind::StreamReset
    )
}

#[cfg(test)]
mod tests;
