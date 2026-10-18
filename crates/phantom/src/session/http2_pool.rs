use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    pin::pin,
    sync::{Arc, MutexGuard, OnceLock, PoisonError, Weak},
    time::Duration,
};

use http::Method;
use phantom_net::proxy::HttpsProxyConnector;
use phantom_net::request::RequestBody;
use phantom_net::{
    http2::{
        Http2Body, Http2Connection, Http2Error, Http2ProtocolErrorKind, Http2ProxyOpening,
        Http2TlsConnector, Http2TlsError, validate_request_body_source_with_trailers,
    },
    request::{OriginForm, RequestHeader},
    tcp::{AddressFamilyMemory, SlowerConnection},
};
use phantom_profile::Http2Priority;
use tokio::{
    sync::{Mutex, Notify},
    task::AbortHandle,
    time::Instant,
};
use tracing::debug;

use super::tickets::{
    TicketCacheBinding,
    binding::{TicketCacheLeg, TicketCacheProtocol},
};
use super::{
    address_families::AddressFamilies,
    admission::{Admission, AdmissionPermit, AdmissionRegistry},
    client_hints::{AcceptChRestart, ClientHintContext, Dispatched},
    http2_connections::{Choice, Http2Spread},
    prune_timer::{PruneTimer, Pruned, PrunedEntry},
    stream_count::{OpenStream, StreamCount},
};
use crate::timeout::{TimeoutBudget, TimeoutPhase};
use crate::{
    HttpProtocol, RequestError, ResponseBody, Route,
    authority::Endpoint,
    error::is_unprocessed_http2,
    retry::{ConnectionSetupRetryState, acquire_with_retries},
};

/// Sends one request, with the request's own HEADERS priority when it has
/// one and the connection's otherwise.
#[allow(clippy::too_many_arguments)]
pub(super) async fn send_on(
    connection: &Http2Connection,
    method: Method,
    authority: &str,
    target: OriginForm,
    headers: Vec<RequestHeader>,
    body: Option<RequestBody>,
    trailers: Vec<RequestHeader>,
    priority: Option<Http2Priority>,
) -> Result<http::Response<Http2Body>, Http2Error> {
    match priority {
        Some(priority) => {
            connection
                .send_request_body_with_trailers_and_priority(
                    method, authority, target, headers, body, trailers, priority,
                )
                .await
        }
        None => {
            connection
                .send_request_body_with_trailers(method, authority, target, headers, body, trailers)
                .await
        }
    }
}

/// How an HTTP/2 pool connection reaches its origin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Http2ConnectionMode {
    /// TLS to the origin, directly or through a tunnel.
    TlsOrigin,
    /// A connection to an HTTP/2 proxy that forwards `http://` requests
    /// with `:scheme` `http`.
    Forward,
}

pub(crate) struct Http2Pool {
    tickets: Arc<super::tickets::TicketOwner>,
    capacity: NonZeroUsize,
    max_active: NonZeroUsize,
    max_pending: NonZeroUsize,
    max_connections: NonZeroUsize,
    /// Reuse limit of a quiet HTTP/1 CONNECT proxy socket.
    http1_used_idle_timeout: Option<Duration>,
    /// The client's prune timer, when the profile closes idle connections on
    /// one.
    prune_timer: Option<Arc<PruneTimer>>,
    state: Mutex<PoolState>,
    retired: Arc<super::retired_connections::RetiredConnections>,
    #[cfg(feature = "https-records")]
    https_records: Option<super::alt_svc::HttpsRecordDiscovery>,
}

impl Http2Pool {
    pub(super) async fn refresh_connections(&self) {
        let mut previous = Vec::new();
        {
            let mut state = self.state.lock().await;
            for (_, entry) in &mut state.entries {
                let fresh =
                    Arc::new(entry.fresh(Http2Spread::new(self.max_connections, self.max_active)));
                if let Some(timer) = &self.prune_timer {
                    let pruned: Arc<dyn PrunedEntry> = fresh.clone();
                    timer.register(Arc::downgrade(&pruned));
                }
                entry.begin_retirement(&self.retired);
                previous.push(std::mem::replace(entry, fresh));
            }
        }
        drop(previous);
    }

    pub(super) async fn close_idle_connections(&self) {
        let mut retired_connections = Vec::new();
        let mut retired_spares = Vec::new();
        {
            let state = self.state.lock().await;
            for (_, entry) in &state.entries {
                let mut connections = entry.lock();
                let mut index = 0;
                while index < connections.slots.len() {
                    let connection = &connections.slots[index].connection;
                    if connection.is_exclusively_owned() && !connection.early_data_pending() {
                        retired_connections.push(connections.slots.remove(index));
                    } else {
                        index += 1;
                    }
                }
                let mut index = 0;
                while index < connections.spares.len() {
                    let spare = &connections.spares[index];
                    if spare.ready.is_some() && spare.task.is_none() {
                        retired_spares.push(connections.spares.remove(index));
                    } else {
                        index += 1;
                    }
                }
            }
        }
        drop(retired_connections);
        drop(retired_spares);
    }

    pub(super) fn new(
        capacity: NonZeroUsize,
        max_active: NonZeroUsize,
        max_pending: NonZeroUsize,
    ) -> Self {
        Self {
            tickets: Arc::default(),
            capacity,
            max_active,
            max_pending,
            max_connections: NonZeroUsize::MIN,
            http1_used_idle_timeout: None,
            prune_timer: None,
            state: Mutex::new(PoolState::default()),
            retired: Arc::default(),
            #[cfg(feature = "https-records")]
            https_records: None,
        }
    }

    pub(super) fn with_ticket_owner(mut self, tickets: Arc<super::tickets::TicketOwner>) -> Self {
        self.tickets = tickets;
        self
    }

    /// Applies the profile's idle reuse limit to quiet CONNECT proxy sockets.
    pub(super) const fn with_http1_used_idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.http1_used_idle_timeout = timeout;
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

    /// Lets each pool key open up to `maximum` connections; see
    /// [`Http2Spread`].
    pub(super) const fn with_max_connections(mut self, maximum: NonZeroUsize) -> Self {
        self.max_connections = maximum;
        self
    }

    /// Lets the client's prune timer close connections past their idle
    /// limit ([`phantom_profile::Http2Settings::idle_timeout`]) between
    /// requests.
    pub(super) fn with_prune_timer(mut self, timer: Option<Arc<PruneTimer>>) -> Self {
        self.prune_timer = timer;
        self
    }

    #[cfg(test)]
    pub(super) const fn prune_timer(&self) -> Option<&Arc<PruneTimer>> {
        self.prune_timer.as_ref()
    }

    pub(super) const fn max_connections(&self) -> NonZeroUsize {
        self.max_connections
    }

    pub(super) const fn capacity(&self) -> NonZeroUsize {
        self.capacity
    }

    pub(super) const fn max_active(&self) -> NonZeroUsize {
        self.max_active
    }

    pub(super) const fn max_pending(&self) -> NonZeroUsize {
        self.max_pending
    }

    /// Sends one request whose `headers` already carry its client hints.
    ///
    /// On a connection whose ALPS `ACCEPT_CH` names a hint the fields lack,
    /// nothing is sent and [`Dispatched::Restart`] returns the body for a
    /// request built again with the hint.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn send_request(
        &self,
        connector: &Http2TlsConnector,
        https_proxy: Option<&HttpsProxyConnector>,
        endpoint: &Endpoint,
        route: &Route,
        mode: Http2ConnectionMode,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        trailers: Vec<RequestHeader>,
        client_hints: Option<ClientHintContext<'_>>,
        body: Option<RequestBody>,
        priority: Option<Http2Priority>,
        timeout_budget: TimeoutBudget,
        retries: &mut ConnectionSetupRetryState,
    ) -> Result<Dispatched<(http::Response<ResponseBody>, Vec<RequestHeader>)>, RequestError> {
        validate_request_body_source_with_trailers(
            &method,
            authority,
            &target,
            &headers,
            body.as_ref(),
            &trailers,
        )
        .map_err(Http2TlsError::from)
        .map_err(RequestError::http2)?;
        if route.as_http_proxy().is_some_and(|proxy| proxy.uses_tls()) && https_proxy.is_none() {
            return Err(RequestError::unsupported_route(HttpProtocol::Http2));
        }
        if mode == Http2ConnectionMode::Forward && !route.forwards_plaintext_over_http2() {
            return Err(RequestError::unsupported_route(HttpProtocol::Http2));
        }
        let key = PoolKey::new(endpoint, route, mode);
        let entry = self.entry(key).await;
        let permit = timeout_budget
            .run(
                TimeoutPhase::PoolAdmission,
                Some(HttpProtocol::Http2),
                entry.admit(),
            )
            .await?;
        let retryable_request = method == Method::GET && body.is_none() && trailers.is_empty();
        let mut body = body;
        let mut retried_graceful_goaway = false;

        loop {
            retries.admit_http_attempt(Some(HttpProtocol::Http2))?;
            let lease =
                acquire_with_retries(HttpProtocol::Http2, timeout_budget, retries, || async {
                    entry
                        .acquire(connector, https_proxy, endpoint, route, mode)
                        .await
                })
                .await?;
            // Nothing is written on a connection whose ACCEPT_CH asks for a
            // hint the request lacks; the request restarts with it.
            if let Some(hints) = client_hints.and_then(|context| {
                context.connection_restart(
                    &headers,
                    lease.connection.accept_ch_for_origin(context.origin()),
                )
            }) {
                drop(lease);
                drop(permit);
                return Ok(Dispatched::Restart(AcceptChRestart { hints, body }));
            }
            if phantom_net::request::is_replay_safe(&method, body.is_some(), !trailers.is_empty()) {
                lease
                    .connection
                    .register_early_data_attempt_optional(retries.attempt_budget());
            }
            let response_timeout =
                timeout_budget.phase(TimeoutPhase::ResponseHead, Some(HttpProtocol::Http2))?;
            let sent_headers = headers.clone();
            let mut diagnostic_head = phantom_net::request_diagnostics::PhaseObservation::begin(
                crate::RequestTimingPhase::SendResponseHead,
                Some(HttpProtocol::Http2.version()),
            );
            let result = response_timeout
                .run(async {
                    Ok::<_, RequestError>(match mode {
                        Http2ConnectionMode::TlsOrigin => {
                            send_on(
                                &lease.connection,
                                method.clone(),
                                authority,
                                target.clone(),
                                sent_headers.clone(),
                                body.take(),
                                trailers.clone(),
                                priority,
                            )
                            .await
                        }
                        Http2ConnectionMode::Forward => {
                            lease
                                .connection
                                .send_forward_request_body_with_trailers(
                                    method.clone(),
                                    authority,
                                    target.clone(),
                                    sent_headers.clone(),
                                    body.take(),
                                    trailers.clone(),
                                    priority,
                                )
                                .await
                        }
                    })
                })
                .await;
            diagnostic_head.nested_result(&result);
            match result {
                Ok(Ok(response)) => {
                    let (parts, body) = response.into_parts();
                    return Ok(Dispatched::Sent((
                        http::Response::from_parts(
                            parts,
                            // The stream count drops first, so the request the
                            // permit admits next sees this stream ended.
                            ResponseBody::http2_with_guard(body, (lease.stream, permit)),
                        ),
                        sent_headers,
                    )));
                }
                Ok(Err(error)) => {
                    // An unprocessed replay must use another connection, so
                    // one that refused a stream is retired when it is enabled.
                    if invalidates_connection(&error)
                        || (retries.replays_unprocessed_requests() && is_unprocessed_http2(&error))
                    {
                        entry.invalidate(&lease.token).await;
                    }
                    if retryable_request && !retried_graceful_goaway && is_graceful_goaway(&error) {
                        retried_graceful_goaway = true;
                        debug!(
                            retry = 1,
                            reason = "graceful_goaway",
                            "retrying HTTP/2 request on a replacement connection"
                        );
                        continue;
                    }
                    // A handshake that failed after early data reports what a
                    // fresh connection's handshake would.
                    let early_data_failure = lease.connection.early_data_failure();
                    // The stream count drops before the permit, as on success.
                    drop(lease);
                    drop(permit);
                    return Err(match early_data_failure {
                        Some(failure) => RequestError::http2_connection_setup(failure),
                        None => RequestError::http2_stream(error),
                    });
                }
                Err(error) => {
                    drop(lease);
                    drop(permit);
                    return Err(error);
                }
            }
        }
    }

    /// Admits one stream on the current reusable connection for this origin
    /// and route.
    ///
    /// This neither opens a connection nor creates a pool entry, and it does
    /// not change eviction order. When a connection exists, the returned
    /// permit is the same per-origin admission an ordinary request takes: it
    /// waits while the origin is at its active bound and fails with a typed
    /// capacity error when the waiting bound is full. The connection is
    /// checked again after admission because it may have been retired while
    /// the caller waited.
    #[cfg(feature = "websocket")]
    pub(crate) async fn admit_current_connection(
        &self,
        endpoint: &Endpoint,
        route: &Route,
    ) -> Result<Option<(Http2Connection, AdmissionPermit)>, RequestError> {
        let key = PoolKey::new(endpoint, route, Http2ConnectionMode::TlsOrigin);
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
        if entry.current_reusable().await.is_none() {
            return Ok(None);
        }
        let permit = entry.admit().await?;
        Ok(entry
            .current_reusable()
            .await
            .map(|connection| (connection, permit)))
    }

    /// The TLS connector of the TLS origin key of `endpoint` and `route` on
    /// the current runtime, which holds the key's TLS session tickets,
    /// creating the key as a request would.
    ///
    /// A WebSocket opening connects with it, so it resumes the tickets the
    /// key's requests were issued and leaves its own for them, as browsers
    /// keep one session cache for an origin's requests and WebSocket
    /// connections.
    #[cfg(feature = "websocket")]
    pub(crate) async fn tls_origin_connector(
        &self,
        base: &Http2TlsConnector,
        endpoint: &Endpoint,
        route: &Route,
    ) -> Result<Http2TlsConnector, RequestError> {
        let entry = self
            .entry(PoolKey::new(
                endpoint,
                route,
                Http2ConnectionMode::TlsOrigin,
            ))
            .await;
        entry.origin_connector(base, endpoint, route)
    }

    /// Owns a dedicated direct H2 opening in its ordinary origin entry.
    #[cfg(feature = "websocket")]
    pub(crate) async fn origin_http2_opening(&self, endpoint: &Endpoint) -> OriginHttp2Opening {
        let entry = self
            .entry(PoolKey::new(
                endpoint,
                &Route::Direct,
                Http2ConnectionMode::TlsOrigin,
            ))
            .await;
        entry.begin_http2_opening()
    }

    #[cfg(feature = "websocket")]
    pub(crate) async fn proxy_http2_opening(
        &self,
        endpoint: &Endpoint,
        route: &Route,
    ) -> OriginHttp2Opening {
        let entry = self
            .entry(PoolKey::new(
                endpoint,
                route,
                Http2ConnectionMode::TlsOrigin,
            ))
            .await;
        entry.begin_http2_opening()
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
            debug!(outcome = "evicted", "HTTP/2 pool entry evicted");
        }
        let admission = state
            .admissions
            .get(&key.origin(), self.max_active, self.max_pending);
        #[cfg_attr(not(feature = "https-records"), allow(unused_mut))]
        let mut entry = PoolEntry::new(
            admission,
            Http2Spread::new(self.max_connections, self.max_active),
        );
        entry.prune.clone_from(&self.prune_timer);
        entry.http1_used_idle_timeout = self.http1_used_idle_timeout;
        entry.family = state.families.get(&key.origin());
        // HTTPS records are looked up on the direct route only: Chromium sends
        // no HTTPS query for a proxied request.
        #[cfg(feature = "https-records")]
        if key.route == Route::Direct {
            entry.https_records = self.https_records.clone();
        }
        entry.tickets = Arc::clone(&self.tickets);
        let entry = Arc::new(entry);
        if let Some(timer) = &self.prune_timer {
            let pruned: Arc<dyn PrunedEntry> = entry.clone();
            timer.register(Arc::downgrade(&pruned));
        }
        state.entries.push_back((key, Arc::clone(&entry)));
        entry
    }
}

#[derive(Default)]
struct PoolState {
    entries: VecDeque<(PoolKey, Arc<PoolEntry>)>,
    admissions: AdmissionRegistry<PoolKey>,
    families: AddressFamilies<PoolKey>,
}

fn invalidates_connection(error: &Http2Error) -> bool {
    match error {
        Http2Error::Protocol(error) => error.kind() != Http2ProtocolErrorKind::StreamReset,
        // The connection closed itself, as Chromium's SpdySession leaves the
        // pool on ERR_HTTP2_PING_FAILED.
        Http2Error::PingTimeout | Http2Error::ReusedConnectionClosed => true,
        _ => false,
    }
}

pub(super) fn is_graceful_goaway(error: &Http2Error) -> bool {
    matches!(
        error,
        Http2Error::Protocol(error)
            if error.kind() == Http2ProtocolErrorKind::ConnectionError
                && error.reason_code() == Some(0)
    )
}

/// The client certificate depends only on host and port
/// ([`ClientBuilder::client_certificate_for`](crate::ClientBuilder::client_certificate_for)),
/// so the connections and TLS session tickets of one key share a certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
struct PoolKey {
    host: Box<str>,
    port: u16,
    route: Route,
    mode: Http2ConnectionMode,
    runtime: Option<tokio::runtime::Id>,
}

impl PoolKey {
    fn new(endpoint: &Endpoint, route: &Route, mode: Http2ConnectionMode) -> Self {
        Self {
            host: endpoint.host().to_ascii_lowercase().into(),
            port: endpoint.port(),
            route: route.clone(),
            mode,
            runtime: super::current_runtime(),
        }
    }
    /// This key without its runtime: the origin and route that per-origin
    /// admission and learned protocol state belong to across runtimes.
    fn origin(&self) -> Self {
        Self {
            runtime: None,
            ..self.clone()
        }
    }
}

struct PoolEntry {
    retirement: OnceLock<Weak<super::retired_connections::RetiredConnections>>,
    tickets: Arc<super::tickets::TicketOwner>,
    /// The key's connections, oldest first. The lock is never held across an
    /// await; a setup in flight is counted in it instead.
    connections: std::sync::Mutex<Connections>,
    /// Woken whenever a connection setup finishes, fails, or is cancelled,
    /// and whenever a stream on one of the key's connections ends.
    setup_done: Arc<Notify>,
    admission: Arc<Admission>,
    family: Arc<AddressFamilyMemory>,
    connector: Arc<OnceLock<Http2TlsConnector>>,
    https_proxy: Arc<OnceLock<HttpsProxyConnector>>,
    /// The client's prune timer, when the profile closes idle connections on
    /// one.
    prune: Option<Arc<PruneTimer>>,
    http1_used_idle_timeout: Option<Duration>,
    #[cfg(feature = "https-records")]
    https_records: Option<super::alt_svc::HttpsRecordDiscovery>,
}

impl PoolEntry {
    fn fresh(&self, spread: Http2Spread) -> Self {
        let mut entry = Self::new(Arc::clone(&self.admission), spread);
        entry.tickets = Arc::clone(&self.tickets);
        entry.family = Arc::clone(&self.family);
        entry.connector = Arc::clone(&self.connector);
        entry.https_proxy = Arc::clone(&self.https_proxy);
        entry.prune.clone_from(&self.prune);
        entry.http1_used_idle_timeout = self.http1_used_idle_timeout;
        #[cfg(feature = "https-records")]
        {
            entry.https_records.clone_from(&self.https_records);
        }
        entry
    }

    fn begin_retirement(
        self: &Arc<Self>,
        registry: &Arc<super::retired_connections::RetiredConnections>,
    ) {
        let state = self.lock();
        self.retirement.get_or_init(|| Arc::downgrade(registry));
        if state.spares.iter().any(|spare| spare.ready.is_none()) {
            registry.retain(self);
        }
    }

    fn retain_pending(self: &Arc<Self>) {
        let _state = self.lock();
        if let Some(registry) = self.retirement.get().and_then(Weak::upgrade) {
            registry.retain(self);
        }
    }

    fn release_retired(self: &Arc<Self>) {
        let removed = {
            let state = self.lock();
            if state.spares.iter().any(|spare| spare.ready.is_none()) {
                return;
            }
            self.retirement
                .get()
                .and_then(Weak::upgrade)
                .and_then(|registry| registry.take(self))
        };
        drop(removed);
    }

    fn new(admission: Arc<Admission>, spread: Http2Spread) -> Self {
        Self {
            retirement: OnceLock::new(),
            tickets: Arc::default(),
            connections: std::sync::Mutex::new(Connections {
                slots: Vec::new(),
                connecting: false,
                spread,
                spares: Vec::new(),
                next_spare: 0,
                openings: 0,
                dedicated: Vec::new(),
            }),
            setup_done: Arc::new(Notify::new()),
            admission,
            family: Arc::default(),
            connector: Arc::default(),
            https_proxy: Arc::default(),
            prune: None,
            http1_used_idle_timeout: None,
            #[cfg(feature = "https-records")]
            https_records: None,
        }
    }

    #[cfg(feature = "websocket")]
    fn origin_connector(
        &self,
        base: &Http2TlsConnector,
        endpoint: &Endpoint,
        route: &Route,
    ) -> Result<Http2TlsConnector, RequestError> {
        let connector = self
            .connector
            .get_or_init(|| base.with_isolated_session_cache());
        self.tickets
            .register_before_use(
                connector.session_ticket_cache(),
                TicketCacheBinding {
                    origin: endpoint,
                    server_name: endpoint.host(),
                    leg: TicketCacheLeg::Origin,
                    protocol: Ok(TicketCacheProtocol::Http2),
                    route,
                },
            )
            .map_err(RequestError::session_tickets)?;
        Ok(connector.clone())
    }
    async fn admit(&self) -> Result<AdmissionPermit, RequestError> {
        Arc::clone(&self.admission).admit(HttpProtocol::Http2).await
    }

    /// Opens a direct TLS connection, offering the `ech` value of the
    /// origin's HTTPS record when the profile does, as Chrome 154 does.
    async fn connect_direct(
        &self,
        connector: &Http2TlsConnector,
        endpoint: &Endpoint,
    ) -> Result<(Http2Connection, Option<SlowerConnection<Http2Connection>>), Http2TlsError> {
        // Bound the connector's `Send` proof separately from pool setup;
        // see `box_send`.
        #[cfg(feature = "https-records")]
        if connector.ech_from_https_records()
            && let Some(discovery) = &self.https_records
        {
            let ech = discovery.tcp_ech(endpoint, connector.alpn_protocols());
            let mut ech = pin!(ech);
            return super::box_send(connector.connect(phantom_net::route::Http2Route::Origin(
                phantom_net::route::OriginRoute::Tls {
                    tcp: phantom_net::route::TcpRoute::Direct(phantom_net::route::Endpoint {
                        host: endpoint.host(),
                        port: endpoint.port(),
                    }),
                    server_name: endpoint.host(),
                    setup: phantom_net::route::DirectTlsSetup::EchKeepingSlower {
                        lookup: ech.as_mut(),
                        family: &self.family,
                    },
                },
            )))
            .await;
        }
        super::box_send(connector.connect(phantom_net::route::Http2Route::Origin(
            phantom_net::route::OriginRoute::Tls {
                tcp: phantom_net::route::TcpRoute::Direct(phantom_net::route::Endpoint {
                    host: endpoint.host(),
                    port: endpoint.port(),
                }),
                server_name: endpoint.host(),
                setup: phantom_net::route::DirectTlsSetup::KeepSlower(&self.family),
            },
        )))
        .await
    }

    fn lock(&self) -> MutexGuard<'_, Connections> {
        self.connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns the connection a new stream would use, without counting one.
    ///
    /// When the key has no connection but one is being set up, this waits
    /// for that setup and returns its connection, so a WebSocket joins it as
    /// with the single-connection pool instead of opening its own. The wait
    /// ends with the setup, whether it succeeds or fails. A WebSocket holds
    /// admission rather than a counted stream, so it does not steer later
    /// requests to another connection.
    #[cfg(feature = "websocket")]
    async fn current_reusable(&self) -> Option<Http2Connection> {
        loop {
            let mut setup_done = pin!(self.setup_done.notified());
            // Registered before the check; see `acquire`.
            setup_done.as_mut().enable();
            {
                let mut connections = self.lock();
                connections.retain_reusable();
                if connections.slots.is_empty() {
                    // A quiet proxy opening cannot publish H2 until an
                    // ordinary request claims it and owns `connecting`.
                    if !connections.connecting
                        && !connections.spares.iter().any(|spare| !spare.proxy)
                    {
                        return None;
                    }
                } else {
                    let index = match connections.choose() {
                        Choice::Use(index) => index,
                        Choice::Open => 0,
                    };
                    return connections
                        .slots
                        .get(index)
                        .map(|slot| slot.connection.clone());
                }
            }
            setup_done.await;
        }
    }

    async fn acquire(
        self: &Arc<Self>,
        connector: &Http2TlsConnector,
        https_proxy: Option<&HttpsProxyConnector>,
        endpoint: &Endpoint,
        route: &Route,
        mode: Http2ConnectionMode,
    ) -> Result<ConnectionLease, RequestError> {
        // One setup runs at a time per key. Requests that a connection with
        // room can serve never wait for it; the rest wait until it finishes
        // or a stream ends, as the single-connection pool did, and choose
        // again. Waiters are woken together, not in arrival order: after a
        // failed setup, whichever runs first makes the next attempt.
        let (reservation, proxy_opening) = loop {
            let expired = self
                .lock()
                .take_expired_proxy_spares(Instant::now(), self.http1_used_idle_timeout);
            let removed = !expired.is_empty();
            close_proxy_spares(expired);
            if removed {
                self.setup_done.notify_waiters();
            }
            let mut setup_done = pin!(self.setup_done.notified());
            // Registered before the check, so a setup finishing in between
            // still wakes this request.
            setup_done.as_mut().enable();
            {
                let mut connections = self.lock();
                connections.retain_reusable();
                if let Choice::Use(index) = connections.choose()
                    && let Some(slot) = connections.slots.get(index)
                {
                    debug!(
                        outcome = "hit",
                        "HTTP/2 connection acquired from client pool"
                    );
                    return Ok(slot.lease());
                }
                if !connections.connecting {
                    if let Some(index) = connections
                        .spares
                        .iter()
                        .position(|spare| spare.ready.is_some())
                    {
                        let mut spare = connections.spares.swap_remove(index);
                        let opening = spare.ready.take();
                        connections.connecting = true;
                        break (
                            SetupReservation {
                                entry: self,
                                finished: false,
                            },
                            opening.map(|opening| {
                                (opening, spare.idle_since.unwrap_or_else(Instant::now))
                            }),
                        );
                    }
                    if connections.spares.is_empty() {
                        self.family.mark_active();
                        connections.connecting = true;
                        break (
                            SetupReservation {
                                entry: self,
                                finished: false,
                            },
                            None,
                        );
                    }
                }
            }
            setup_done.await;
        };

        if let Some((opening, since)) = proxy_opening {
            let claim = ProxyClaim {
                reservation: Some(reservation),
                opening: Some(opening),
                since,
            };
            // A proxy claim is connection setup too; keep its CONNECT/TLS
            // future out of acquire, including when a request reuses H2.
            return super::box_send(self.finish_proxy_claim(claim, endpoint, route)).await;
        }

        debug!(outcome = "connect", "HTTP/2 client pool opening connection");
        // Boxed: opening a connection awaits the largest connector futures,
        // which would otherwise enlarge the future of every request, including
        // one that reuses a pooled connection.
        let (connection, slower) =
            super::box_send(self.open(connector, https_proxy, endpoint, route, mode)).await?;
        Ok(reservation.finish(connection, slower))
    }

    async fn finish_proxy_claim(
        &self,
        claim: ProxyClaim<'_>,
        endpoint: &Endpoint,
        route: &Route,
    ) -> Result<ConnectionLease, RequestError> {
        #[cfg(feature = "websocket")]
        if matches!(route, Route::Socks4(_) | Route::Socks5(_)) {
            return claim.finish_socks().await;
        }
        let Some(proxy) = route.as_http_proxy() else {
            return Err(RequestError::unsupported_route(HttpProtocol::Http2));
        };
        let authority = endpoint.tunnel_authority();
        let endpoint = phantom_net::route::Endpoint {
            host: proxy.host(),
            port: proxy.port(),
        };
        let transport = if proxy.uses_tls() {
            let connector = self
                .https_proxy
                .get()
                .ok_or_else(|| RequestError::unsupported_route(HttpProtocol::Http2))?;
            phantom_net::route::ProxyTransport::Tls {
                endpoint,
                server_name: proxy.host(),
                connector,
            }
        } else {
            phantom_net::route::ProxyTransport::Tcp(endpoint)
        };
        claim
            .finish(phantom_net::route::HttpConnectRoute {
                speculative_tls: proxy.speculative_tls(),
                proxy: transport,
                authority: &authority,
                headers: proxy.ordered_connect_headers(),
                credentials: proxy.authentication(),
            })
            .await
    }

    fn adopt_proxy(self: &Arc<Self>, slower: SlowerConnection<Http2ProxyOpening>) {
        self.adopt_quiet(SlowerConnection::new(slower.progress(), async move {
            slower.finish().await.map(QuietOpening::Http)
        }));
    }

    #[cfg(feature = "websocket")]
    fn adopt_socks(
        self: &Arc<Self>,
        slower: SlowerConnection<phantom_net::http2::Http2SocksOpening>,
    ) {
        self.adopt_quiet(SlowerConnection::new(slower.progress(), async move {
            slower.finish().await.map(QuietOpening::Socks)
        }));
    }

    fn adopt_quiet(self: &Arc<Self>, slower: SlowerConnection<QuietOpening>) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let id = {
            let mut state = self.lock();
            self.family.mark_active();
            let id = state.register_spare();
            if let Some(spare) = state.spares.iter_mut().find(|spare| spare.id == id) {
                spare.proxy = true;
            }
            id
        };
        let report = ProxySpareReport {
            entry: Some(Arc::downgrade(self)),
            id,
        };
        self.retain_pending();
        let task = runtime.spawn(async move {
            report.finish(slower.finish().await);
        });
        let installed = {
            let mut state = self.lock();
            if let Some(spare) = state.spares.iter_mut().find(|spare| spare.id == id) {
                spare.task = Some(task.abort_handle());
                true
            } else {
                false
            }
        };
        if !installed {
            task.abort();
        }
    }

    fn proxy_spare_finished(&self, id: u64, opening: Option<QuietOpening>) {
        let mut state = self.lock();
        let retired = if let Some(opening) = opening {
            if let Some(spare) = state.spares.iter_mut().find(|spare| spare.id == id) {
                spare.ready = Some(opening);
                spare.idle_since = Some(Instant::now());
                spare.task = None;
                None
            } else {
                Some(opening)
            }
        } else {
            let removed = state
                .spares
                .iter()
                .position(|spare| spare.id == id)
                .map(|index| state.spares.swap_remove(index));
            drop(state);
            drop(removed);
            self.prune_empty_family();
            self.setup_done.notify_waiters();
            return;
        };
        drop(state);
        drop(retired);
        if let Some(timer) = &self.prune {
            timer.http1_idle_added();
        }
        self.setup_done.notify_waiters();
    }

    /// Opens a connection for [`Self::acquire`] in `mode` over `route`.
    async fn open(
        self: &Arc<Self>,
        connector: &Http2TlsConnector,
        https_proxy: Option<&HttpsProxyConnector>,
        endpoint: &Endpoint,
        route: &Route,
        mode: Http2ConnectionMode,
    ) -> Result<(Http2Connection, Option<SlowerConnection<Http2Connection>>), RequestError> {
        let connector = self
            .connector
            .get_or_init(|| connector.with_isolated_session_cache());
        self.tickets
            .register_before_use(
                connector.session_ticket_cache(),
                TicketCacheBinding {
                    origin: endpoint,
                    server_name: endpoint.host(),
                    leg: TicketCacheLeg::Origin,
                    protocol: Ok(TicketCacheProtocol::Http2),
                    route,
                },
            )
            .map_err(RequestError::session_tickets)?;
        let connection = match route {
            // The forwarding connector's pool decides whether this proxy
            // connection also carries other origins' forwarded requests and
            // CONNECT tunnels, as the profile says.
            Route::HttpProxy(proxy) if mode == Http2ConnectionMode::Forward => {
                let base = https_proxy
                    .ok_or_else(|| RequestError::unsupported_route(HttpProtocol::Http2))?;
                let proxy_connector = self
                    .https_proxy
                    .get_or_init(|| proxy.https_connector(&base.with_isolated_session_cache()));
                self.tickets
                    .register_before_use(
                        proxy_connector.session_ticket_cache(),
                        TicketCacheBinding {
                            origin: endpoint,
                            server_name: proxy.host(),
                            leg: TicketCacheLeg::HttpProxy,
                            protocol: TicketCacheBinding::proxy_protocol(
                                proxy_connector.protocol(),
                            ),
                            route,
                        },
                    )
                    .map_err(RequestError::session_tickets)?;
                super::box_send(connector.connect(phantom_net::route::Http2Route::Forward {
                    proxy: phantom_net::route::ProxyTransport::Tls {
                        endpoint: phantom_net::route::Endpoint {
                            host: proxy.host(),
                            port: proxy.port(),
                        },
                        server_name: proxy.host(),
                        connector: proxy_connector,
                    },
                    credentials: proxy.authentication(),
                }))
                .await
                .map_err(RequestError::http2_connection_setup)?
            }
            // Checked before admission; forwarding needs an HTTP proxy.
            _ if mode == Http2ConnectionMode::Forward => {
                return Err(RequestError::unsupported_route(HttpProtocol::Http2));
            }
            // Rejected before admission; never reinterpreted as TCP.
            Route::ConnectUdp(_) => {
                return Err(RequestError::unsupported_route(HttpProtocol::Http2));
            }
            Route::Direct => {
                return self
                    .connect_direct(connector, endpoint)
                    .await
                    .map_err(RequestError::http2_connection_setup);
            }
            Route::HttpProxy(proxy) => {
                let connect_authority = endpoint.tunnel_authority();
                let proxy_endpoint = phantom_net::route::Endpoint {
                    host: proxy.host(),
                    port: proxy.port(),
                };
                let transport = if proxy.uses_tls() {
                    let base = https_proxy
                        .ok_or_else(|| RequestError::unsupported_route(HttpProtocol::Http2))?;
                    let proxy_connector = self
                        .https_proxy
                        .get_or_init(|| proxy.https_connector(&base.with_isolated_session_cache()));
                    self.tickets
                        .register_before_use(
                            proxy_connector.session_ticket_cache(),
                            TicketCacheBinding {
                                origin: endpoint,
                                server_name: proxy.host(),
                                leg: TicketCacheLeg::HttpProxy,
                                protocol: TicketCacheBinding::proxy_protocol(
                                    proxy_connector.protocol(),
                                ),
                                route,
                            },
                        )
                        .map_err(RequestError::session_tickets)?;
                    phantom_net::route::ProxyTransport::Tls {
                        endpoint: proxy_endpoint,
                        server_name: proxy.host(),
                        connector: proxy_connector,
                    }
                } else {
                    phantom_net::route::ProxyTransport::Tcp(proxy_endpoint)
                };
                let connect = phantom_net::route::HttpConnectRoute {
                    speculative_tls: proxy.speculative_tls(),
                    proxy: transport,
                    authority: &connect_authority,
                    headers: proxy.ordered_connect_headers(),
                    credentials: proxy.authentication(),
                };
                if match transport {
                    phantom_net::route::ProxyTransport::Tcp(_) => connector.tcp_settings(),
                    phantom_net::route::ProxyTransport::Tls { connector, .. }
                        if connector.protocol()
                            == phantom_net::proxy::HttpsProxyProtocol::Http1 =>
                    {
                        connector.tcp_settings()
                    }
                    _ => None,
                }
                .is_some_and(|settings| {
                    matches!(
                        settings.address_selection,
                        phantom_profile::TcpAddressSelection::Backup(_)
                    )
                }) {
                    let (opening, slower) = connector
                        .open_http_connect_retaining(connect, endpoint.host(), &self.family)
                        .await
                        .map_err(RequestError::http2_connection_setup)?;
                    if let Some(slower) = slower {
                        self.adopt_proxy(slower);
                    }
                    return Ok((
                        opening
                            .finish(connect)
                            .await
                            .map_err(RequestError::http2_connection_setup)?,
                        None,
                    ));
                }
                super::box_send(connector.connect(phantom_net::route::Http2Route::Origin(
                    phantom_net::route::OriginRoute::Tls {
                        tcp: phantom_net::route::TcpRoute::HttpConnect(connect),
                        server_name: endpoint.host(),
                        setup: phantom_net::route::DirectTlsSetup::Default,
                    },
                )))
                .await
                .map_err(RequestError::http2_connection_setup)?
            }
            Route::Socks4(proxy) => super::box_send(
                connector.connect_socks_retaining(
                    phantom_net::route::OriginRoute::Tls {
                        tcp: proxy
                            .tcp_route(phantom_net::route::Endpoint {
                                host: endpoint.host(),
                                port: endpoint.port(),
                            })
                            .map_err(|source| {
                                RequestError::http2_connection_setup(source.into())
                            })?,
                        server_name: endpoint.host(),
                        setup: phantom_net::route::DirectTlsSetup::Default,
                    },
                    &self.family,
                ),
            )
            .await
            .map_err(RequestError::http2_connection_setup)?,
            Route::Socks5(proxy) => match proxy.dns_mode() {
                crate::Socks5DnsMode::Local => super::box_send(connector.connect_socks_retaining(
                    phantom_net::route::OriginRoute::Tls {
                        tcp: phantom_net::route::TcpRoute::Socks5 {
                            proxy: phantom_net::route::Endpoint {
                                host: proxy.host(),
                                port: proxy.port(),
                            },
                            target: phantom_net::route::Socks5Target::LocalDns(
                                phantom_net::route::Endpoint {
                                    host: endpoint.host(),
                                    port: endpoint.port(),
                                },
                            ),
                            auth: proxy.auth(),
                        },
                        server_name: endpoint.host(),
                        setup: phantom_net::route::DirectTlsSetup::Default,
                    },
                    &self.family,
                ))
                .await
                .map_err(RequestError::http2_connection_setup)?,
                crate::Socks5DnsMode::Remote => super::box_send(connector.connect_socks_retaining(
                    phantom_net::route::OriginRoute::Tls {
                        tcp: phantom_net::route::TcpRoute::Socks5 {
                            proxy: phantom_net::route::Endpoint {
                                host: proxy.host(),
                                port: proxy.port(),
                            },
                            target: phantom_net::route::Socks5Target::RemoteDns(
                                phantom_net::route::Endpoint {
                                    host: endpoint.host(),
                                    port: endpoint.port(),
                                },
                            ),
                            auth: proxy.auth(),
                        },
                        server_name: endpoint.host(),
                        setup: phantom_net::route::DirectTlsSetup::Default,
                    },
                    &self.family,
                ))
                .await
                .map_err(RequestError::http2_connection_setup)?,
            },
        };
        Ok(connection)
    }

    /// Starts a backup whose slot is already registered under the entry lock.
    fn spawn_spare(
        self: &Arc<Self>,
        runtime: tokio::runtime::Handle,
        id: u64,
        slower: SlowerConnection<Http2Connection>,
    ) {
        self.retain_pending();
        let report = SpareReport {
            entry: Some(Arc::downgrade(self)),
            id,
        };
        // A shutting-down runtime can drop the report immediately; do not spawn
        // under the entry lock that its completion takes.
        let task = runtime.spawn(async move {
            report.finish(slower.finish().await);
        });
        if let Some(spare) = self.lock().spares.iter_mut().find(|spare| spare.id == id) {
            spare.task = Some(task.abort_handle());
        }
    }

    fn spare_finished(&self, id: u64, connection: Option<Http2Connection>) {
        let mut state = self.lock();
        state.dedicated.retain(|owner| owner.strong_count() != 0);
        let dedicated: Vec<_> = state.dedicated.iter().filter_map(Weak::upgrade).collect();
        let registered = state
            .spares
            .iter()
            .position(|spare| spare.id == id)
            .map(|position| state.spares.swap_remove(position))
            .is_some();
        let mut expired = Vec::new();
        for index in (0..state.slots.len()).rev() {
            if !state.slots[index].connection.is_reusable() {
                expired.push(state.slots.remove(index));
            }
        }
        let left = connection
            .as_ref()
            .and_then(Http2Connection::idle_time_left);
        let mut retired = connection;
        let mut kept = false;
        if registered
            && !state.connecting
            && !dedicated.iter().any(|owner| owner.is_reusable())
            && retired.as_ref().is_some_and(Http2Connection::is_reusable)
            && matches!(state.choose(), Choice::Open)
            && let Some(connection) = retired.take()
        {
            state.slots.push(ConnectionSlot {
                connection,
                token: Arc::new(()),
                streams: StreamCount::notifying(Arc::clone(&self.setup_done)),
            });
            kept = true;
        }
        drop(state);
        drop(dedicated);
        // A redundant H2 session closes after its preface/SETTINGS, with no
        // request. As in the negotiated pool, drop it outside the entry lock.
        drop(retired);
        drop(expired);
        if kept && let (Some(timer), Some(left)) = (&self.prune, left) {
            timer.idle_added(left);
        }
        self.prune_empty_family();
        self.setup_done.notify_waiters();
    }

    fn prune_empty_family(&self) {
        if let Some(timer) = &self.prune
            && self.lock().is_empty()
            && self.family.family().is_some()
        {
            timer.idle_added(Duration::from_secs(1));
        }
    }

    async fn invalidate(&self, token: &Arc<()>) {
        let mut connections = self.lock();
        if let Some(position) = connections
            .slots
            .iter()
            .position(|slot| Arc::ptr_eq(&slot.token, token))
        {
            connections.slots.remove(position);
            debug!(
                outcome = "invalidated",
                "HTTP/2 client pool connection invalidated"
            );
        }
        drop(connections);
        self.prune_empty_family();
    }
}

/// A dedicated H2 setup that still owns its route entry and family.
#[cfg(feature = "websocket")]
pub(crate) struct OriginHttp2Opening {
    entry: Arc<PoolEntry>,
    pending: bool,
}

#[cfg(feature = "websocket")]
impl PoolEntry {
    fn begin_http2_opening(self: &Arc<Self>) -> OriginHttp2Opening {
        {
            let mut state = self.lock();
            self.family.mark_active();
            state.openings += 1;
        }
        OriginHttp2Opening {
            entry: Arc::clone(self),
            pending: true,
        }
    }
}

#[cfg(feature = "websocket")]
impl OriginHttp2Opening {
    pub(crate) fn family(&self) -> &Arc<AddressFamilyMemory> {
        &self.entry.family
    }

    pub(crate) fn connector(
        &self,
        base: &Http2TlsConnector,
        endpoint: &Endpoint,
    ) -> Result<Http2TlsConnector, RequestError> {
        self.entry.origin_connector(base, endpoint, &Route::Direct)
    }

    pub(crate) fn proxy_origin_connector(
        &self,
        base: &Http2TlsConnector,
        endpoint: &Endpoint,
        route: &Route,
    ) -> Result<Http2TlsConnector, RequestError> {
        self.entry.origin_connector(base, endpoint, route)
    }

    pub(crate) fn proxy_connector(
        &self,
        base: &HttpsProxyConnector,
        endpoint: &Endpoint,
        route: &Route,
    ) -> Result<HttpsProxyConnector, RequestError> {
        let proxy = route
            .as_http_proxy()
            .ok_or_else(|| RequestError::unsupported_route(HttpProtocol::Http2))?;
        let connector = self
            .entry
            .https_proxy
            .get_or_init(|| proxy.https_connector(&base.with_isolated_session_cache()));
        self.entry
            .tickets
            .register_before_use(
                connector.session_ticket_cache(),
                TicketCacheBinding {
                    origin: endpoint,
                    server_name: proxy.host(),
                    leg: TicketCacheLeg::HttpProxy,
                    protocol: TicketCacheBinding::proxy_protocol(connector.protocol()),
                    route,
                },
            )
            .map_err(RequestError::session_tickets)?;
        Ok(connector.clone())
    }

    pub(crate) async fn open_proxy_extended_connect(
        &self,
        connector: &Http2TlsConnector,
        route: phantom_net::route::HttpConnectRoute<'_>,
        endpoint: &Endpoint,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<phantom_net::http2::Http2ExtendedConnectOpening, RequestError> {
        let opening = self.take_proxy_opening().await;
        let opening = match opening {
            Some(opening) => opening,
            None => {
                let (opening, slower) = connector
                    .open_http_connect_retaining(route, endpoint.host(), &self.entry.family)
                    .await
                    .map_err(RequestError::http2_connection_setup)?;
                // The pool owns the quiet physical backup before CONNECT or origin TLS.
                if let Some(slower) = slower {
                    self.entry.adopt_proxy(slower);
                }
                QuietOpening::Http(opening)
            }
        };
        opening
            .finish_extended_connect(route, endpoint.authority().as_str(), target, headers)
            .await
            .map_err(RequestError::http2_connection_setup)
    }

    pub(crate) async fn open_socks_extended_connect(
        &self,
        connector: &Http2TlsConnector,
        origin: phantom_net::route::OriginRoute<'_>,
        endpoint: &Endpoint,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<phantom_net::http2::Http2ExtendedConnectOpening, RequestError> {
        let opening = match self.take_proxy_opening().await {
            Some(opening) => opening,
            None => {
                let (opening, slower) = connector
                    .open_socks_retaining(origin, &self.entry.family)
                    .await
                    .map_err(RequestError::http2_connection_setup)?;
                if let Some(slower) = slower {
                    self.entry.adopt_socks(slower);
                }
                QuietOpening::Socks(opening)
            }
        };
        opening
            .finish_socks_extended_connect(endpoint.authority().as_str(), target, headers)
            .await
            .map_err(RequestError::http2_connection_setup)
    }

    async fn take_proxy_opening(&self) -> Option<QuietOpening> {
        loop {
            let mut notified = pin!(self.entry.setup_done.notified());
            notified.as_mut().enable();
            let (opening, pending, expired) = {
                let mut state = self.entry.lock();
                let expired = state
                    .take_expired_proxy_spares(Instant::now(), self.entry.http1_used_idle_timeout);
                let opening = state
                    .spares
                    .iter()
                    .position(|spare| spare.ready.is_some())
                    .and_then(|index| state.spares.swap_remove(index).ready);
                let pending = state
                    .spares
                    .iter()
                    .any(|spare| spare.proxy && spare.task.is_some());
                (opening, pending, expired)
            };
            close_proxy_spares(expired);
            if opening.is_some() || !pending {
                return opening;
            }
            notified.await;
        }
    }

    /// Publishes the actual winner and spare before either can notify waiters.
    pub(crate) fn connected(
        mut self,
        winner: &Http2Connection,
        slower: Option<SlowerConnection<Http2Connection>>,
    ) -> DedicatedHttp2Owner {
        let owner = DedicatedHttp2Owner {
            connection: Some(Arc::new(winner.clone())),
            entry: Arc::clone(&self.entry),
        };
        let spare = slower.and_then(|slower| {
            tokio::runtime::Handle::try_current()
                .ok()
                .map(|runtime| (runtime, slower))
        });
        let (spare, retired_proxy) = {
            let mut state = self.entry.lock();
            state.openings -= 1;
            state.dedicated.retain(|owner| owner.strong_count() != 0);
            if let Some(connection) = &owner.connection {
                state.dedicated.push(Arc::downgrade(connection));
            }
            let spare = spare.map(|(runtime, slower)| (runtime, state.register_spare(), slower));
            self.pending = false;
            (spare, state.take_proxy_spares())
        };
        close_proxy_spares(retired_proxy);
        if let Some((runtime, id, slower)) = spare {
            self.entry.spawn_spare(runtime, id, slower);
        }
        self.entry.setup_done.notify_waiters();
        owner
    }
}

#[cfg(feature = "websocket")]
impl Drop for OriginHttp2Opening {
    fn drop(&mut self) {
        if self.pending {
            self.entry.lock().openings -= 1;
            self.entry.prune_empty_family();
            self.entry.setup_done.notify_waiters();
        }
    }
}

#[cfg(feature = "websocket")]
pub(crate) struct DedicatedHttp2Owner {
    connection: Option<Arc<Http2Connection>>,
    entry: Arc<PoolEntry>,
}

#[cfg(feature = "websocket")]
impl Drop for DedicatedHttp2Owner {
    fn drop(&mut self) {
        // Release the last wrapped handle outside the entry lock before prune.
        drop(self.connection.take());
        self.entry.prune_empty_family();
        self.entry.setup_done.notify_waiters();
    }
}

impl Drop for PoolEntry {
    fn drop(&mut self) {
        for spare in &self
            .connections
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .spares
        {
            if let Some(task) = &spare.task {
                task.abort();
            }
        }
    }
}

struct Spare {
    id: u64,
    task: Option<AbortHandle>,
    proxy: bool,
    ready: Option<QuietOpening>,
    idle_since: Option<Instant>,
}

struct ProxySpareReport {
    entry: Option<Weak<PoolEntry>>,
    id: u64,
}

impl ProxySpareReport {
    fn finish(mut self, opening: Option<QuietOpening>) {
        if let Some(entry) = self.entry.take().and_then(|entry| entry.upgrade()) {
            entry.proxy_spare_finished(self.id, opening);
            entry.release_retired();
        }
    }
}

impl Drop for ProxySpareReport {
    fn drop(&mut self) {
        if let Some(entry) = self.entry.take().and_then(|entry| entry.upgrade()) {
            entry.proxy_spare_finished(self.id, None);
            entry.release_retired();
        }
    }
}

enum QuietOpening {
    Http(Http2ProxyOpening),
    #[cfg(feature = "websocket")]
    Socks(phantom_net::http2::Http2SocksOpening),
}
impl QuietOpening {
    async fn finish(
        self,
        route: phantom_net::route::HttpConnectRoute<'_>,
    ) -> Result<Http2Connection, Http2TlsError> {
        match self {
            Self::Http(opening) => opening.finish(route).await,
            #[cfg(feature = "websocket")]
            Self::Socks(_) => Err(quiet_route_error()),
        }
    }
    #[cfg(feature = "websocket")]
    async fn finish_socks(self) -> Result<Http2Connection, Http2TlsError> {
        match self {
            Self::Socks(opening) => opening.finish().await,
            Self::Http(_) => Err(quiet_route_error()),
        }
    }
    #[cfg(feature = "websocket")]
    async fn finish_extended_connect(
        self,
        route: phantom_net::route::HttpConnectRoute<'_>,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<phantom_net::http2::Http2ExtendedConnectOpening, phantom_net::http2::Http2TlsError>
    {
        match self {
            Self::Http(opening) => {
                super::box_send(opening.finish_extended_connect(route, authority, target, headers))
                    .await
            }
            #[cfg(feature = "websocket")]
            Self::Socks(_) => Err(phantom_net::http2::Http2TlsError::Connect(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "quiet opening route does not match",
                ),
            )),
        }
    }
    #[cfg(feature = "websocket")]
    async fn finish_socks_extended_connect(
        self,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<phantom_net::http2::Http2ExtendedConnectOpening, phantom_net::http2::Http2TlsError>
    {
        match self {
            Self::Socks(opening) => {
                opening
                    .finish_extended_connect(authority, target, headers)
                    .await
            }
            Self::Http(_) => Err(phantom_net::http2::Http2TlsError::Connect(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "quiet opening route does not match",
                ),
            )),
        }
    }
}
#[cfg(feature = "websocket")]
fn quiet_route_error() -> Http2TlsError {
    Http2TlsError::Connect(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "quiet opening route does not match",
    ))
}

struct ProxyClaim<'a> {
    reservation: Option<SetupReservation<'a>>,
    opening: Option<QuietOpening>,
    since: Instant,
}

impl ProxyClaim<'_> {
    async fn finish(
        mut self,
        route: phantom_net::route::HttpConnectRoute<'_>,
    ) -> Result<ConnectionLease, RequestError> {
        let opening = self
            .opening
            .take()
            .ok_or_else(|| RequestError::unsupported_route(HttpProtocol::Http2))?;
        let connection = opening
            .finish(route)
            .await
            .map_err(RequestError::http2_connection_setup)?;
        let reservation = self
            .reservation
            .take()
            .ok_or_else(|| RequestError::unsupported_route(HttpProtocol::Http2))?;
        Ok(reservation.finish(connection, None))
    }

    #[cfg(feature = "websocket")]
    async fn finish_socks(mut self) -> Result<ConnectionLease, RequestError> {
        let opening = self
            .opening
            .take()
            .ok_or_else(|| RequestError::unsupported_route(HttpProtocol::Http2))?;
        let connection = opening
            .finish_socks()
            .await
            .map_err(RequestError::http2_connection_setup)?;
        let reservation = self
            .reservation
            .take()
            .ok_or_else(|| RequestError::unsupported_route(HttpProtocol::Http2))?;
        Ok(reservation.finish(connection, None))
    }
}

impl Drop for ProxyClaim<'_> {
    fn drop(&mut self) {
        if let (Some(opening), Some(reservation)) = (self.opening.take(), self.reservation.as_ref())
        {
            let mut state = reservation.entry.lock();
            let id = state.register_spare();
            if let Some(spare) = state.spares.iter_mut().find(|spare| spare.id == id) {
                spare.proxy = true;
                spare.ready = Some(opening);
                spare.idle_since = Some(self.since);
            }
            drop(state);
            if let Some(timer) = &reservation.entry.prune {
                timer.http1_idle_added();
            }
        }
    }
}

fn close_proxy_spares(spares: Vec<Spare>) {
    for spare in spares {
        if let Some(task) = &spare.task {
            task.abort();
        }
        drop(spare);
    }
}

struct SpareReport {
    entry: Option<Weak<PoolEntry>>,
    id: u64,
}

impl SpareReport {
    fn finish(mut self, connection: Option<Http2Connection>) {
        if let Some(entry) = self.entry.take().and_then(|entry| entry.upgrade()) {
            entry.spare_finished(self.id, connection);
            entry.release_retired();
        }
    }
}

impl Drop for SpareReport {
    fn drop(&mut self) {
        if let Some(entry) = self.entry.take().and_then(|entry| entry.upgrade()) {
            entry.spare_finished(self.id, None);
            entry.release_retired();
        }
    }
}

impl PrunedEntry for PoolEntry {
    /// Gives up the key's connections past their idle limit, which close
    /// once no stream is open, and those the server closed.
    fn prune(&self, now: Instant, http1_limit: Option<Duration>) -> Pruned {
        let mut connections = self.lock();
        connections.retain_reusable();
        let expired = connections.take_expired_proxy_spares(now, http1_limit);
        let removed = !expired.is_empty();
        let proxy_next = http1_limit.and_then(|limit| {
            connections
                .spares
                .iter()
                .filter_map(|spare| {
                    spare
                        .idle_since
                        .map(|since| limit.saturating_sub(now.saturating_duration_since(since)))
                })
                .min()
        });
        let result = Pruned {
            next: connections
                .slots
                .iter()
                .filter_map(|slot| slot.connection.idle_time_left())
                .chain(proxy_next)
                .min(),
            empty: connections.is_empty(),
        };
        drop(connections);
        close_proxy_spares(expired);
        if removed {
            self.setup_done.notify_waiters();
        }
        result
    }

    fn address_family(&self) -> Option<&Arc<AddressFamilyMemory>> {
        Some(&self.family)
    }
}

/// One pool key's HTTP/2 connections and how streams spread across them.
struct Connections {
    slots: Vec<ConnectionSlot>,
    /// Whether the key's one connection setup is in flight.
    connecting: bool,
    spread: Http2Spread,
    spares: Vec<Spare>,
    next_spare: u64,
    openings: usize,
    dedicated: Vec<Weak<Http2Connection>>,
}

/// The key's one connection setup in flight.
///
/// Dropping it unfinished, when setup fails or the request is cancelled,
/// frees the setup and wakes every request waiting for it. They are not
/// served in arrival order: the first to run takes the next setup.
struct SetupReservation<'a> {
    entry: &'a Arc<PoolEntry>,
    finished: bool,
}

impl SetupReservation<'_> {
    /// Pools the new connection and leases it for this request's stream.
    fn finish(
        mut self,
        connection: Http2Connection,
        slower: Option<SlowerConnection<Http2Connection>>,
    ) -> ConnectionLease {
        let spare = slower.and_then(|slower| {
            tokio::runtime::Handle::try_current()
                .ok()
                .map(|runtime| (runtime, slower))
        });
        let left = connection.idle_time_left();
        let slot = ConnectionSlot {
            connection,
            token: Arc::new(()),
            streams: StreamCount::notifying(Arc::clone(&self.entry.setup_done)),
        };
        let lease = slot.lease();
        let mut connections = self.entry.lock();
        connections.slots.push(slot);
        let retired_proxy = connections.take_proxy_spares();
        let spare = spare.map(|(runtime, slower)| {
            self.entry.family.mark_active();
            (runtime, connections.register_spare(), slower)
        });
        // Waiters must see the winner and its backup before setup is released.
        connections.connecting = false;
        self.finished = true;
        drop(connections);
        close_proxy_spares(retired_proxy);
        if let Some((runtime, id, slower)) = spare {
            self.entry.spawn_spare(runtime, id, slower);
        }
        // Reported after the push, so a prune that runs from here on finds
        // the connection.
        if let (Some(timer), Some(left)) = (&self.entry.prune, left) {
            timer.idle_added(left);
        }
        self.entry.setup_done.notify_waiters();
        lease
    }
}

impl Drop for SetupReservation<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.entry.lock().connecting = false;
            self.entry.prune_empty_family();
            self.entry.setup_done.notify_waiters();
        }
    }
}

impl Connections {
    fn register_spare(&mut self) -> u64 {
        let id = self.next_spare;
        self.next_spare = self.next_spare.wrapping_add(1);
        self.spares.push(Spare {
            id,
            task: None,
            proxy: false,
            ready: None,
            idle_since: None,
        });
        id
    }

    fn take_expired_proxy_spares(&mut self, now: Instant, limit: Option<Duration>) -> Vec<Spare> {
        let mut removed = Vec::new();
        for index in (0..self.spares.len()).rev() {
            let spare = &self.spares[index];
            if spare.ready.is_some()
                && spare.idle_since.is_some_and(|since| {
                    limit.is_some_and(|limit| now.saturating_duration_since(since) >= limit)
                })
            {
                removed.push(self.spares.swap_remove(index));
            }
        }
        removed
    }

    fn take_proxy_spares(&mut self) -> Vec<Spare> {
        let mut removed = Vec::new();
        for index in (0..self.spares.len()).rev() {
            if self.spares[index].proxy {
                removed.push(self.spares.swap_remove(index));
            }
        }
        removed
    }

    fn is_empty(&self) -> bool {
        self.slots.is_empty()
            && !self.connecting
            && self.spares.is_empty()
            && self.openings == 0
            && !self.dedicated.iter().any(|owner| owner.strong_count() != 0)
    }

    fn retain_reusable(&mut self) {
        self.slots.retain(|slot| slot.connection.is_reusable());
    }

    fn choose(&mut self) -> Choice {
        self.spread.choose(
            self.slots
                .iter()
                .map(|slot| (&slot.connection, &slot.streams)),
        )
    }
}

struct ConnectionSlot {
    connection: Http2Connection,
    token: Arc<()>,
    streams: StreamCount,
}

impl ConnectionSlot {
    /// Leases the connection for one stream, counted until the lease's
    /// stream guard drops.
    fn lease(&self) -> ConnectionLease {
        ConnectionLease {
            connection: self.connection.clone(),
            token: Arc::clone(&self.token),
            stream: self.streams.open(),
        }
    }
}

struct ConnectionLease {
    connection: Http2Connection,
    token: Arc<()>,
    stream: OpenStream,
}

#[cfg(test)]
mod tests {
    mod proxy_retention;
    mod retention;
    #[cfg(feature = "websocket")]
    mod websocket_retention;
    use std::{num::NonZeroUsize, sync::Arc};

    use super::{Http2Pool, PoolEntry, PoolKey, SetupReservation};
    use crate::{Route, authority::Endpoint};

    #[tokio::test]
    async fn refresh_isolates_stale_setup_and_keeps_aggregate_admission()
    -> Result<(), Box<dyn std::error::Error>> {
        let one = NonZeroUsize::MIN;
        let pool = Http2Pool::new(one, one, one);
        let endpoint = Endpoint::new("refresh.test:443".parse()?, 443)?;
        let key = PoolKey::new(
            &endpoint,
            &Route::Direct,
            super::Http2ConnectionMode::TlsOrigin,
        );
        let old = pool.entry(key.clone()).await;
        let permit = old.admit().await?;
        let old_setup = reserve(&old);
        pool.refresh_connections().await;
        let fresh = pool.entry(key).await;
        let fresh_setup = reserve(&fresh);
        drop(old_setup);
        assert!(
            fresh.lock().connecting,
            "stale cancellation cleared fresh setup"
        );
        let mut admitting = std::pin::pin!(fresh.admit());
        assert!(
            poll_once(admitting.as_mut()).is_none(),
            "refresh reset admission"
        );
        drop(permit);
        let _permit = admitting.await?;
        drop(fresh_setup);
        Ok(())
    }

    fn poll_once<F: std::future::Future>(future: std::pin::Pin<&mut F>) -> Option<F::Output> {
        match future.poll(&mut std::task::Context::from_waker(std::task::Waker::noop())) {
            std::task::Poll::Ready(output) => Some(output),
            std::task::Poll::Pending => None,
        }
    }

    async fn cold_entry() -> Result<Arc<PoolEntry>, Box<dyn std::error::Error>> {
        let one = NonZeroUsize::MIN;
        let pool = Http2Pool::new(one, one, one);
        let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
        Ok(pool
            .entry(PoolKey::new(
                &endpoint,
                &Route::Direct,
                super::Http2ConnectionMode::TlsOrigin,
            ))
            .await)
    }

    /// Reserves the key's one setup, as `PoolEntry::acquire` does.
    fn reserve(entry: &Arc<PoolEntry>) -> SetupReservation<'_> {
        entry.lock().connecting = true;
        SetupReservation {
            entry,
            finished: false,
        }
    }

    #[tokio::test]
    async fn dropping_an_unfinished_setup_frees_it_and_wakes_waiters()
    -> Result<(), Box<dyn std::error::Error>> {
        let entry = cold_entry().await?;
        let reservation = reserve(&entry);
        let mut waiter = std::pin::pin!(entry.setup_done.notified());
        waiter.as_mut().enable();
        assert!(poll_once(waiter.as_mut()).is_none());

        drop(reservation);
        assert!(!entry.lock().connecting);
        assert!(poll_once(waiter).is_some());
        Ok(())
    }

    #[cfg(feature = "websocket")]
    #[tokio::test]
    async fn websocket_reuse_waits_for_the_setup_in_flight()
    -> Result<(), Box<dyn std::error::Error>> {
        let entry = cold_entry().await?;
        // With no connection and no setup, there is nothing to reuse.
        assert!(entry.current_reusable().await.is_none());

        let reservation = reserve(&entry);
        let mut reuse = std::pin::pin!(entry.current_reusable());
        assert!(poll_once(reuse.as_mut()).is_none());
        let (client, _server) = tokio::io::duplex(64 * 1024);
        let connection = phantom_net::http2::Http2Connection::connect(
            client,
            &phantom_profile::browser::chrome::v154_http2(),
        )
        .await?;
        drop(reservation.finish(connection, None));
        assert!(
            reuse.await.is_some(),
            "the WebSocket did not join the new connection"
        );

        // A setup that fails ends the wait with nothing to reuse.
        entry.lock().slots.clear();
        let reservation = reserve(&entry);
        let mut reuse = std::pin::pin!(entry.current_reusable());
        assert!(poll_once(reuse.as_mut()).is_none());
        drop(reservation);
        assert!(reuse.await.is_none());
        Ok(())
    }

    /// A connection past its idle limit leaves the key when the prune timer
    /// fires; one within it sets the timer for the whole seconds it has
    /// left.
    #[tokio::test(start_paused = true)]
    async fn the_prune_timer_gives_up_a_connection_past_its_idle_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::time::Duration;

        use phantom_profile::{Http2IdleTimeout, browser::firefox};
        use tokio::time::{Instant, advance};

        use super::super::prune_timer::PruneTimer;

        let one = NonZeroUsize::MIN;
        let timer = PruneTimer::unscheduled(Duration::from_secs(115));
        let pool = Http2Pool::new(one, one, one).with_prune_timer(Some(Arc::clone(&timer)));
        let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
        let entry = pool
            .entry(PoolKey::new(
                &endpoint,
                &Route::Direct,
                super::Http2ConnectionMode::TlsOrigin,
            ))
            .await;
        let mut settings = firefox::v157_http2();
        settings.idle_timeout = Http2IdleTimeout::ClosedOnTimer(Duration::from_secs(2));
        let (client, _server) = tokio::io::duplex(64 * 1024);
        let connection = phantom_net::http2::Http2Connection::connect(client, &settings).await?;
        let start = Instant::now();
        drop(reserve(&entry).finish(connection, None));
        assert_eq!(timer.wake_at(), Some(start + Duration::from_secs(2)));

        advance(Duration::from_millis(1_500)).await;
        timer.fire();
        assert_eq!(entry.lock().slots.len(), 1);
        // Half a second left still waits one second.
        assert_eq!(timer.wake_at(), Some(start + Duration::from_millis(2_500)));

        advance(Duration::from_secs(1)).await;
        timer.fire();
        assert!(entry.lock().slots.is_empty());
        assert_eq!(timer.wake_at(), None);
        Ok(())
    }

    #[tokio::test]
    async fn per_origin_admission_survives_lru_eviction() -> Result<(), Box<dyn std::error::Error>>
    {
        let one = NonZeroUsize::MIN;
        let pool = Http2Pool::new(one, one, one);
        let first = Endpoint::new("first.test:443".parse()?, 443)?;
        let second = Endpoint::new("second.test:443".parse()?, 443)?;

        let mode = super::Http2ConnectionMode::TlsOrigin;
        let first_entry = pool.entry(PoolKey::new(&first, &Route::Direct, mode)).await;
        let permit = first_entry.admit().await?;
        pool.entry(PoolKey::new(&second, &Route::Direct, mode))
            .await;
        drop(first_entry);
        let replacement = pool.entry(PoolKey::new(&first, &Route::Direct, mode)).await;

        assert!(Arc::ptr_eq(permit.admission(), &replacement.admission));
        assert_eq!(replacement.admission.available_active(), 0);
        drop(permit);
        assert_eq!(replacement.admission.available_active(), 1);
        Ok(())
    }

    /// A request awaits `acquire` whether it reuses a connection or opens one,
    /// so only `open`, which a new connection boxes, may hold the connectors'
    /// futures.
    #[cfg(debug_assertions)]
    #[test]
    fn acquire_leaves_connection_setup_off_the_request_future() {
        // A reuse holds only the arguments and the boxed setup.
        let size = phantom_testkit::future_size::future_size(&super::PoolEntry::acquire);
        assert!(size <= 1024, "PoolEntry::acquire is {size} bytes");
    }

    /// `open` holds the connectors' futures for a new connection; see
    /// `phantom_testkit::future_size`.
    #[cfg(debug_assertions)]
    #[test]
    fn opening_a_connection_stays_within_the_setup_budget() {
        use phantom_testkit::future_size::{SETUP_FUTURE_BUDGET, assert_within, future_size};

        assert_within(
            SETUP_FUTURE_BUDGET,
            &[("PoolEntry::open", future_size(&super::PoolEntry::open))],
        );
    }
}
