use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    pin::pin,
    sync::{Arc, MutexGuard, OnceLock, PoisonError},
};

use http::{Method, Response};
use phantom_net::{
    http1::{
        Http1Connection,
        validate_request_body_source_with_trailers as validate_http1_request_body_source_with_trailers,
    },
    http1_or_2::{Http1Or2Connection, Http1Or2TlsConnector},
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
    http2_pool::{is_graceful_goaway, send_on},
};
use crate::{
    HttpProtocol, RequestError, ResponseBody, Route, Socks5DnsMode,
    authority::Endpoint,
    error::is_unprocessed_http2,
    retry::ConnectionSetupRetryState,
    timeout::{PhaseTimeout, TimeoutBudget, TimeoutPhase},
};

/// Negotiated HTTP/1.1-or-HTTP/2 connections, grouped by origin and route.
///
/// Each pool key keeps at most one reusable H2 connection, which carries all
/// of the key's H2 requests, and up to `max_http1_active` connections that
/// are H1 or still in setup. A request reuses the H2 connection when there
/// is one, then the most recently used idle H1 connection, and otherwise
/// opens a connection whose protocol ALPN chooses.
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
    state: Mutex<PoolState>,
    http2_keys: Arc<Http2Keys>,
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
            state: Mutex::new(PoolState::default()),
            http2_keys: Arc::new(Http2Keys::default()),
        }
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
        let (http1_wire_headers, http1_sent_headers) = validate_request(
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
            http1_wire_headers,
            http1_sent_headers,
            http2_headers,
            http2_priority,
            trailers,
            client_hints,
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
            if !graceful_goaway_replayable || retried_graceful_goaway {
                return entry
                    .dispatch_on_lease(
                        lease,
                        permit,
                        request,
                        body,
                        retire_unprocessed,
                        timeout_budget,
                    )
                    .await
                    .map_err(RequestError::from);
            }
            match entry
                .dispatch_on_lease(
                    lease,
                    permit,
                    request.clone(),
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
            .map(|lease| (lease.connection, permit)))
    }

    /// Returns whether the origin's current generation is a reusable HTTP/2
    /// connection.
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
        );
        let entry = Arc::new(PoolEntry::new(
            selection_admission,
            http1_admission,
            http2_admission,
            connections,
        ));
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
        }
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
        loop {
            let slot = match self.connections.before_admission() {
                BeforeAdmission::Http2(lease) => {
                    if let Some(admitted) = self
                        .try_admit_http2(lease, request_span, timeout_budget)
                        .await?
                    {
                        drop(selection);
                        return Ok(admitted);
                    }
                    continue;
                }
                BeforeAdmission::AwaitSetup => {
                    self.await_setup(&mut connect, timeout_budget).await?;
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
                Acquired::Http2(lease) => {
                    drop(slot);
                    force_new_connection = false;
                    if let Some(admitted) = self
                        .try_admit_http2(lease, request_span, timeout_budget)
                        .await?
                    {
                        drop(selection);
                        return Ok(admitted);
                    }
                }
            }
        }
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

    /// Admits a request to the key's H2 connection.
    ///
    /// Returns `None`, with the connection retired, when the connection
    /// stopped being the key's reusable H2 connection while the request
    /// waited for admission.
    async fn try_admit_http2(
        &self,
        lease: Http2Lease,
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
        if self.connections.is_current_http2(&lease) {
            return Ok(Some((ConnectionLease::Http2(lease), permit)));
        }
        drop(permit);
        self.connections.invalidate_http2(&lease.token);
        Ok(None)
    }

    /// Phase three: dispatches the request on its admitted lease.
    ///
    /// `retire_unprocessed` retires an H2 connection that refused the stream,
    /// so an unprocessed replay uses another connection.
    async fn dispatch_on_lease(
        &self,
        lease: ConnectionLease,
        permit: AdmissionPermit,
        request: NegotiatedRequest<'_>,
        body: Option<RequestBody>,
        retire_unprocessed: bool,
        timeout_budget: TimeoutBudget,
    ) -> Result<NegotiatedResponse, DispatchFailure> {
        let NegotiatedRequest {
            method,
            authority,
            target,
            http1_wire_headers,
            http1_sent_headers,
            http2_headers,
            http2_priority,
            trailers,
            client_hints,
        } = request;

        match lease {
            ConnectionLease::Http1(mut lease) => {
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
                let Http2Lease { connection, token } = lease;
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
                                ResponseBody::http2_with_guard(body, permit),
                            ),
                            HttpProtocol::Http2,
                            sent_headers,
                        ))
                    }
                    Ok(Err(error)) => {
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
    ) -> Result<Acquired, RequestError> {
        let reservation = match self.connections.checkout(force_new_connection) {
            Checkout::Found(acquired) => return Ok(acquired),
            Checkout::Reserved(reservation) => reservation,
        };

        debug!(
            outcome = "connect",
            "negotiated HTTP pool opening connection"
        );
        let connector = self
            .connector
            .get_or_init(|| connector.with_isolated_session_cache());
        let connection = match route {
            Route::Direct => connector
                .connect_direct(endpoint.host(), endpoint.port(), endpoint.host())
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
        Ok(reservation.finish(connection.into()))
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
/// At most one reusable H2 connection serves the key. H1 connections, idle
/// or leased, and connections whose setup has not finished, so whose protocol
/// ALPN has not chosen yet, number at most `max_http1` together. A request
/// holds a connection slot from the key's H1 admission, which lets at most
/// `max_http1` requests through, before it leases an H1 connection or opens
/// one, and each such request holds at most one. A request that finds no
/// idle connection therefore always has room to open one.
struct EntryConnections {
    max_http1: NonZeroUsize,
    state: std::sync::Mutex<ConnectionState>,
    /// Woken whenever a connection setup finishes, fails, or is cancelled.
    setup_done: Notify,
    /// The client's memory of keys that selected H2, and this entry's key.
    http2_keys: Arc<Http2Keys>,
    key: PoolKey,
}

#[derive(Default)]
struct ConnectionState {
    http2: Option<Http2Lease>,
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

    /// Returns the reusable H2 connection, forgetting one that has closed.
    fn current_http2(&mut self) -> Option<Http2Lease> {
        if self
            .http2
            .as_ref()
            .is_some_and(|lease| !lease.connection.is_reusable())
        {
            self.http2 = None;
        }
        self.http2.as_ref().map(Http2Lease::clone_lease)
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
    /// `nsHttpConnectionMgr.cpp:1399-1409`). Phantom waits as Firefox does.
    /// A key whose protocol is unknown waits only when every slot is taken
    /// (see [`PoolEntry::acquire_selected`]).
    fn awaits_setup(&self) -> bool {
        self.selected_http2 && self.connecting > 0
    }
}

/// What a request can do before it takes a connection slot.
enum BeforeAdmission {
    Http2(Http2Lease),
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
    Http2(Http2Lease),
    AwaitSetup,
}

impl EntryConnections {
    fn new(max_http1: NonZeroUsize, http2_keys: Arc<Http2Keys>, key: PoolKey) -> Self {
        let state = ConnectionState {
            selected_http2: http2_keys.contains(&key),
            ..ConnectionState::default()
        };
        Self {
            max_http1,
            state: std::sync::Mutex::new(state),
            setup_done: Notify::new(),
            http2_keys,
            key,
        }
    }

    fn lock(&self) -> MutexGuard<'_, ConnectionState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn current_http2(&self) -> Option<Http2Lease> {
        self.lock().current_http2()
    }

    fn before_admission(&self) -> BeforeAdmission {
        let mut state = self.lock();
        if let Some(lease) = state.current_http2() {
            return BeforeAdmission::Http2(lease);
        }
        if state.awaits_setup() {
            return BeforeAdmission::AwaitSetup;
        }
        let has_http1 = !state.http1_idle.is_empty() || state.http1_leased > 0;
        BeforeAdmission::Admit(has_http1.then_some(HttpProtocol::Http1))
    }

    /// Waits until a setup in flight finishes, fails, or is cancelled.
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
    /// recently used one when the key is at its bound.
    fn checkout(self: &Arc<Self>, force_new_connection: bool) -> Checkout {
        let mut state = self.lock();
        if let Some(lease) = state.current_http2() {
            return Checkout::Found(Acquired::Http2(lease));
        }
        if state.awaits_setup() {
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

    fn is_current_http2(&self, lease: &Http2Lease) -> bool {
        self.lock().http2.as_ref().is_some_and(|current| {
            Arc::ptr_eq(&current.token, &lease.token) && current.connection.is_reusable()
        })
    }

    fn invalidate_http2(&self, token: &Arc<()>) {
        let mut state = self.lock();
        if state
            .http2
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(&current.token, token))
        {
            state.http2 = None;
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
    /// A new H2 connection closes idle H1 connections to the key, as Chromium
    /// closes the group's idle sockets (`:1283-1287`).
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
                    Some(current) => {
                        debug!(
                            outcome = "redundant",
                            "negotiated HTTP/2 connection closed in favor of the current one"
                        );
                        (Acquired::Http2(current), Some(connection), Vec::new())
                    }
                    None => {
                        let lease = Http2Lease {
                            connection,
                            token: Arc::new(()),
                        };
                        state.http2 = Some(lease.clone_lease());
                        let idle = std::mem::take(&mut state.http1_idle);
                        (Acquired::Http2(lease), None, idle)
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
/// and returns the H1 wire fields (with `Host`) and the H1 fields as sent.
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
) -> Result<(Vec<RequestHeader>, Vec<RequestHeader>), RequestError> {
    let http1_sent_headers = prepare_headers(client_hints, http1_headers, None)?;
    let http2_validation_headers = prepare_headers(client_hints, http2_headers.to_vec(), None)?;
    let mut http1_wire_headers = Vec::with_capacity(http1_sent_headers.len() + 1);
    http1_wire_headers.push(RequestHeader::new(
        "Host",
        endpoint.authority().as_str().as_bytes(),
    ));
    http1_wire_headers.extend(http1_sent_headers.clone());
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
        &http2_validation_headers,
        body,
        trailers,
    )
    .map_err(RequestError::negotiated_http2_validation)?;
    Ok((http1_wire_headers, http1_sent_headers))
}

/// One negotiated request, without its body, prepared for either protocol.
#[derive(Clone)]
struct NegotiatedRequest<'a> {
    method: Method,
    authority: &'a str,
    target: OriginForm,
    http1_wire_headers: Vec<RequestHeader>,
    http1_sent_headers: Vec<RequestHeader>,
    http2_headers: Vec<RequestHeader>,
    http2_priority: Option<Http2Priority>,
    trailers: Vec<RequestHeader>,
    client_hints: Option<ClientHintContext<'a>>,
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
    Http2(Http2Lease),
}

/// One request's hold on the key's H2 connection, which requests share.
///
/// The token identifies the connection, so a failure retires it only while
/// it is still the key's current H2 connection.
struct Http2Lease {
    connection: Http2Connection,
    token: Arc<()>,
}

impl Http2Lease {
    fn clone_lease(&self) -> Self {
        Self {
            connection: self.connection.clone(),
            token: Arc::clone(&self.token),
        }
    }
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
