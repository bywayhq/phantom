use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use http::Method;
use phantom_net::http3::{
    ConnectUdpError, ConnectUdpErrorKind, Http3Connection, Http3Connector, Http3ConnectorError,
    Http3ConnectorErrorKind, OriginForm, RequestHeader,
};
use phantom_net::proxy::HttpsProxyConnector;
use phantom_net::request::RequestBody;
use tokio::sync::{Mutex, OwnedMutexGuard};
use tracing::debug;

use super::{
    admission::{Admission, AdmissionPermit, AdmissionRegistry},
    client_hints::ClientHintContext,
};
use crate::timeout::{TimeoutBudget, TimeoutPhase};
use crate::{
    ConnectUdpProxy, HttpProtocol, RequestError, ResponseBody, Route, Socks5DnsMode,
    authority::Endpoint,
    retry::{ConnectionSetupRetryState, acquire_with_retries},
};

/// Borrowed network location used to reach an HTTP/3 origin.
///
/// The origin endpoint still owns TLS authentication, request authority, pool
/// identity, and route policy. This value changes only where QUIC is sent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Http3TransportTarget<'a> {
    host: &'a str,
    port: u16,
}

impl<'a> Http3TransportTarget<'a> {
    pub(crate) const fn new(host: &'a str, port: u16) -> Self {
        Self { host, port }
    }

    fn for_origin(endpoint: &'a Endpoint) -> Self {
        Self::new(endpoint.host(), endpoint.port())
    }
}

/// Proxy-leg connectors for CONNECT-UDP routes, all using proxy trust.
#[derive(Debug)]
pub(crate) struct ConnectUdpConnectors {
    /// Outer HTTP/3 connector for the default HTTP/3 leg.
    pub(crate) http3: Option<Http3Connector>,
    /// TLS connector for HTTP/1.1 Upgrade and HTTP/2 extended CONNECT legs.
    pub(crate) tcp: Option<HttpsProxyConnector>,
}

pub(crate) struct Http3Pool {
    capacity: NonZeroUsize,
    max_active: NonZeroUsize,
    max_pending: NonZeroUsize,
    state: Mutex<PoolState>,
}

impl Http3Pool {
    pub(super) fn new(
        capacity: NonZeroUsize,
        max_active: NonZeroUsize,
        max_pending: NonZeroUsize,
    ) -> Self {
        Self {
            capacity,
            max_active,
            max_pending,
            state: Mutex::new(PoolState::default()),
        }
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn send_request(
        &self,
        connector: &Http3Connector,
        connect_udp_proxy: Option<&ConnectUdpConnectors>,
        endpoint: &Endpoint,
        route: &Route,
        alternative: Option<Http3TransportTarget<'_>>,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        trailers: Vec<RequestHeader>,
        client_hints: Option<ClientHintContext<'_>>,
        body: Option<RequestBody>,
        timeout_budget: TimeoutBudget,
        retries: &mut ConnectionSetupRetryState,
    ) -> Result<(http::Response<ResponseBody>, Vec<RequestHeader>), RequestError> {
        let transport = alternative.unwrap_or_else(|| Http3TransportTarget::for_origin(endpoint));
        validate_request(
            connector,
            connect_udp_proxy,
            route,
            transport,
            &method,
            authority,
            &target,
            &headers,
            &trailers,
            client_hints,
            body.as_ref(),
        )?;
        let leased = self
            .admit(endpoint, route, timeout_budget)
            .await?
            .connect(
                connector,
                connect_udp_proxy,
                endpoint,
                route,
                transport,
                timeout_budget,
                retries,
                Http3SetupControl {
                    early_data: connector.sends_early_data(),
                    ..Http3SetupControl::default()
                },
            )
            .await?;
        if sends_before_handshake(
            is_replay_safe(&method, body.as_ref(), &trailers),
            leased.lease.connection.early_data_pending(),
            connector.requests_wait_for_peer_settings()
                && !leased.lease.connection.started_from_remembered_settings(),
        ) {
            // A replay-safe request on a connection whose early data is still
            // unanswered goes out as early data, with the client hints known
            // before the handshake.
            let result = dispatch(
                leased,
                connector,
                method.clone(),
                authority,
                target.clone(),
                headers.clone(),
                trailers.clone(),
                client_hints,
                None,
                timeout_budget,
                retries,
            )
            .await;
            match result {
                Err(error) if error.is_http3_early_data_rejected() => {}
                result => return result,
            }
        } else {
            // Any other request is sent once the early data is answered, with
            // the client hints the completed handshake delivered, and keeps
            // its body until then.
            match leased
                .wait_for_early_data(connector, timeout_budget)
                .await?
            {
                EarlyDataWait::Ready(leased) => {
                    return dispatch(
                        leased,
                        connector,
                        method,
                        authority,
                        target,
                        headers,
                        trailers,
                        client_hints,
                        body,
                        timeout_budget,
                        retries,
                    )
                    .await;
                }
                EarlyDataWait::Rejected(_) => {}
            }
        }
        // Rejected early data was not processed (RFC 9001, section 4.6.2). The
        // request is sent again after a handshake, over the same route and
        // protocol, on a connection that offers no early data.
        debug!(
            outcome = "early_data_rejected",
            "HTTP/3 early data rejected; sending after a handshake"
        );
        let leased = self
            .acquire_lease(
                connector,
                connect_udp_proxy,
                endpoint,
                route,
                transport,
                timeout_budget,
                retries,
            )
            .await?;
        self.send_request_on_lease(
            leased,
            connector,
            method,
            authority,
            target,
            headers,
            trailers,
            client_hints,
            body,
            timeout_budget,
            retries,
        )
        .await
    }

    /// Admits one request and acquires its connection without dispatching.
    ///
    /// The lease holds the request's admission permit until it is dispatched
    /// or dropped; dropping it leaves an established connection pooled.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn acquire_lease(
        &self,
        connector: &Http3Connector,
        connect_udp_proxy: Option<&ConnectUdpConnectors>,
        endpoint: &Endpoint,
        route: &Route,
        transport: Http3TransportTarget<'_>,
        timeout_budget: TimeoutBudget,
        retries: &mut ConnectionSetupRetryState,
    ) -> Result<Http3Lease, RequestError> {
        self.admit(endpoint, route, timeout_budget)
            .await?
            .connect(
                connector,
                connect_udp_proxy,
                endpoint,
                route,
                transport,
                timeout_budget,
                retries,
                Http3SetupControl::default(),
            )
            .await
    }

    /// Admits one request to its origin-and-route entry without connecting.
    pub(crate) async fn admit(
        &self,
        endpoint: &Endpoint,
        route: &Route,
        timeout_budget: TimeoutBudget,
    ) -> Result<Http3Admission, RequestError> {
        let entry = self.entry(PoolKey::new(endpoint, route)).await;
        let permit = timeout_budget
            .run(
                TimeoutPhase::PoolAdmission,
                Some(HttpProtocol::Http3),
                entry.admit(),
            )
            .await?;
        Ok(Http3Admission { entry, permit })
    }

    /// Validates, then dispatches one request on a lease from [`Self::acquire_lease`].
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn send_request_on_lease(
        &self,
        leased: Http3Lease,
        connector: &Http3Connector,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        trailers: Vec<RequestHeader>,
        client_hints: Option<ClientHintContext<'_>>,
        body: Option<RequestBody>,
        timeout_budget: TimeoutBudget,
        retries: &mut ConnectionSetupRetryState,
    ) -> Result<(http::Response<ResponseBody>, Vec<RequestHeader>), RequestError> {
        validate_wire(
            connector,
            &method,
            authority,
            &target,
            &headers,
            &trailers,
            client_hints,
            body.as_ref(),
        )?;
        let leased = match leased
            .wait_for_early_data(connector, timeout_budget)
            .await?
        {
            EarlyDataWait::Ready(leased) => leased,
            EarlyDataWait::Rejected(error) => return Err(error),
        };
        dispatch(
            leased,
            connector,
            method,
            authority,
            target,
            headers,
            trailers,
            client_hints,
            body,
            timeout_budget,
            retries,
        )
        .await
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
            debug!(outcome = "evicted", "HTTP/3 pool entry evicted");
        }
        let admission = state.admission(&key, self.max_active, self.max_pending);
        let entry = Arc::new(PoolEntry::new(admission));
        state.entries.push_back((key, Arc::clone(&entry)));
        entry
    }
}

#[derive(Default)]
struct PoolState {
    entries: VecDeque<(PoolKey, Arc<PoolEntry>)>,
    admissions: AdmissionRegistry<PoolKey>,
}

impl PoolState {
    fn admission(
        &mut self,
        key: &PoolKey,
        max_active: NonZeroUsize,
        max_pending: NonZeroUsize,
    ) -> Arc<Admission> {
        self.admissions.get(key, max_active, max_pending)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TransportLocation {
    host: Box<str>,
    port: u16,
}

impl TransportLocation {
    fn new(target: Http3TransportTarget<'_>) -> Self {
        Self {
            host: target.host.to_ascii_lowercase().into(),
            port: target.port,
        }
    }
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

/// Transport locations that keep a connection within one origin-and-route entry.
///
/// Exact H3 dials the origin location while an Alt-Svc attempt dials the
/// alternative; separate slots stop each switch from replacing the other's
/// connection. The least recently used location is closed beyond this bound.
const MAX_TRANSPORT_LOCATIONS_PER_ENTRY: usize = 4;

struct PoolEntry {
    /// Connections keyed by transport location, least recently used first.
    /// Held for lookup and insertion only, never across connection setup.
    slots: Mutex<VecDeque<ConnectionSlot>>,
    /// Connect turns keyed by transport location; see [`ConnectTurn`].
    turns: ConnectTurns,
    admission: Arc<Admission>,
    /// Origin connector with this entry's own QUIC ticket cache, so a ticket
    /// is presented only on the origin and route that learned it. It never
    /// sends early data; it opens the connection that replaces one whose
    /// early data was rejected.
    origin: OnceLock<Http3Connector>,
    /// The origin connector's early-data twin, sharing its ticket cache, when
    /// the client enables HTTP/3 early data.
    origin_early: OnceLock<Option<Http3Connector>>,
    /// Outer HTTP/3 CONNECT-UDP proxy connector, with its own ticket cache.
    http3_proxy: OnceLock<Http3Connector>,
    /// Proxy TLS connector for a TCP CONNECT-UDP leg, with its own session cache.
    tcp_proxy: OnceLock<HttpsProxyConnector>,
}

impl PoolEntry {
    fn new(admission: Arc<Admission>) -> Self {
        Self {
            slots: Mutex::new(VecDeque::new()),
            turns: std::sync::Mutex::new(Vec::new()),
            admission,
            origin: OnceLock::new(),
            origin_early: OnceLock::new(),
            http3_proxy: OnceLock::new(),
            tcp_proxy: OnceLock::new(),
        }
    }

    async fn admit(&self) -> Result<AdmissionPermit, RequestError> {
        Arc::clone(&self.admission).admit(HttpProtocol::Http3).await
    }

    /// Waits until no other setup of this entry is connecting to `location`.
    async fn connect_turn(self: &Arc<Self>, location: TransportLocation) -> ConnectTurn {
        let gate = {
            let mut turns = lock_turns(&self.turns);
            // A gate only the table refers to was left by a cancelled waiter.
            turns.retain(|(_, gate)| Arc::strong_count(gate) > 1);
            if let Some((_, gate)) = turns.iter().find(|(candidate, _)| candidate == &location) {
                Arc::clone(gate)
            } else {
                let gate = Arc::new(Mutex::new(()));
                turns.push((location, Arc::clone(&gate)));
                gate
            }
        };
        let guard = Arc::clone(&gate).lock_owned().await;
        ConnectTurn {
            entry: Arc::clone(self),
            gate,
            guard: Some(guard),
        }
    }

    async fn acquire(
        self: &Arc<Self>,
        connector: &Http3Connector,
        connect_udp_proxy: Option<&ConnectUdpConnectors>,
        endpoint: &Endpoint,
        route: &Route,
        transport: Http3TransportTarget<'_>,
        control: Http3SetupControl<'_>,
    ) -> Result<ConnectionLease, RequestError> {
        let location = TransportLocation::new(transport);
        let turn = self.connect_turn(location.clone()).await;
        if let Some(connecting) = control.connecting {
            connecting.store(true, Ordering::Release);
        }
        {
            let mut slots = self.slots.lock().await;
            if let Some(position) = slots.iter().position(|slot| slot.location == location)
                && let Some(slot) = slots.remove(position)
                && connector.can_reuse(&slot.connection).await
            {
                debug!(
                    outcome = "hit",
                    "HTTP/3 connection acquired from client pool"
                );
                let lease = slot.lease();
                slots.push_back(slot);
                return Ok(lease);
            }
        }

        let connect = self.connect(
            connector,
            connect_udp_proxy,
            endpoint,
            route,
            transport,
            control.early_data,
        );
        let connection = match control.attempt_limit {
            Some(limit) => tokio::time::timeout(limit, connect).await.map_err(|_| {
                debug!(
                    timeout_phase = TimeoutPhase::Connect.trace_name(),
                    protocol = HttpProtocol::Http3.trace_name(),
                    "HTTP/3 connection attempt reached its limit"
                );
                RequestError::timeout(TimeoutPhase::Connect, Some(HttpProtocol::Http3))
            })??,
            None => connect.await?,
        };
        let slot = ConnectionSlot {
            connection,
            token: Arc::new(()),
            location,
        };
        // A connection whose early data is unanswered is pooled at once, so
        // later requests to this location share it instead of opening their
        // own; each waits for the answer unless it may go out early. A
        // rejected or failed connection is invalidated by the first request
        // that sees it.
        let lease = slot.lease();
        let mut slots = self.slots.lock().await;
        if slots.len() == MAX_TRANSPORT_LOCATIONS_PER_ENTRY {
            slots.pop_front();
            debug!(outcome = "evicted", "HTTP/3 transport location evicted");
        }
        slots.push_back(slot);
        drop(slots);
        drop(turn);
        Ok(lease)
    }

    /// Opens one connection to `transport` on `route`.
    ///
    /// Connections use this entry's isolated connectors, so QUIC tickets stay
    /// within one origin and route. When an attempt that presented a ticket
    /// fails its TLS handshake, the attempt is repeated once with a full
    /// handshake over the same route; nothing else about it changes.
    async fn connect(
        &self,
        connector: &Http3Connector,
        connect_udp_proxy: Option<&ConnectUdpConnectors>,
        endpoint: &Endpoint,
        route: &Route,
        transport: Http3TransportTarget<'_>,
        early_data: bool,
    ) -> Result<Http3Connection, RequestError> {
        debug!(outcome = "connect", "HTTP/3 client pool opening connection");
        let origin = self
            .origin
            .get_or_init(|| connector.without_early_data().with_isolated_session_cache());
        let early_origin = self
            .origin_early
            .get_or_init(|| {
                connector
                    .sends_early_data()
                    .then(|| origin.with_early_data())
            })
            .as_ref()
            .filter(|_| early_data);
        let http3_proxy = match route {
            Route::ConnectUdp(proxy) if proxy.tcp_protocol().is_none() => {
                let base = connect_udp_http3(connect_udp_proxy)?;
                Some((
                    self.http3_proxy
                        .get_or_init(|| base.with_isolated_session_cache()),
                    proxy.host(),
                ))
            }
            _ => None,
        };
        let presented_ticket = origin.has_ticket_for(endpoint.host())
            || http3_proxy.is_some_and(|(proxy, host)| proxy.has_ticket_for(host));
        let first = self
            .connect_with(
                early_origin.unwrap_or(origin),
                http3_proxy.map(|(proxy, _)| proxy),
                endpoint,
                route,
                transport,
                connect_udp_proxy,
            )
            .await;
        match first {
            Err(failure) if presented_ticket && failure.is_handshake() => {
                debug!(
                    outcome = "full_handshake_retry",
                    "HTTP/3 handshake that presented a session ticket failed"
                );
                let origin = origin.without_ticket_offers();
                let http3_proxy = http3_proxy.map(|(proxy, _)| proxy.without_ticket_offers());
                self.connect_with(
                    &origin,
                    http3_proxy.as_ref(),
                    endpoint,
                    route,
                    transport,
                    connect_udp_proxy,
                )
                .await
                .map_err(SetupFailure::into_request_error)
            }
            result => result.map_err(SetupFailure::into_request_error),
        }
    }

    /// Opens one connection with the given connectors, without retrying.
    async fn connect_with(
        &self,
        connector: &Http3Connector,
        http3_proxy: Option<&Http3Connector>,
        endpoint: &Endpoint,
        route: &Route,
        transport: Http3TransportTarget<'_>,
        connect_udp_proxy: Option<&ConnectUdpConnectors>,
    ) -> Result<Http3Connection, SetupFailure> {
        Ok(match route {
            Route::Direct => connector
                .connect_direct(transport.host, transport.port, endpoint.host())
                .await
                .map_err(SetupFailure::Origin)?,
            Route::Socks5(proxy) if proxy.dns_mode() == Socks5DnsMode::Local => connector
                .connect_socks5_local_with_auth(
                    proxy.host(),
                    proxy.port(),
                    proxy.auth(),
                    transport.host,
                    transport.port,
                    endpoint.host(),
                )
                .await
                .map_err(SetupFailure::Origin)?,
            Route::Socks5(proxy) => connector
                .connect_socks5_remote_with_auth(
                    proxy.host(),
                    proxy.port(),
                    proxy.auth(),
                    transport.host,
                    transport.port,
                    endpoint.host(),
                )
                .await
                .map_err(SetupFailure::Origin)?,
            // One fresh outer connection and CONNECT-UDP request per inner
            // connection, including every retry on this route.
            Route::ConnectUdp(proxy) => match proxy.tcp_protocol() {
                None => connector
                    .connect_connect_udp_with_basic_auth(
                        http3_proxy.ok_or_else(|| {
                            SetupFailure::Other(RequestError::unsupported_route(
                                HttpProtocol::Http3,
                            ))
                        })?,
                        proxy.host(),
                        proxy.port(),
                        proxy.authority(),
                        connect_udp_path(proxy, transport).map_err(SetupFailure::Other)?,
                        proxy.headers().to_vec(),
                        proxy.credentials(),
                        endpoint.host(),
                    )
                    .await
                    .map_err(SetupFailure::ConnectUdp)?,
                Some(protocol) => {
                    let base = connect_udp_tcp(connect_udp_proxy).map_err(SetupFailure::Other)?;
                    // Proxy TLS sessions stay within this origin-and-route
                    // entry, like the HTTP proxy pools.
                    let proxy_connector = self
                        .tcp_proxy
                        .get_or_init(|| base.with_isolated_session_cache());
                    connector
                        .connect_connect_udp_over_tcp(
                            proxy_connector,
                            protocol,
                            proxy.host(),
                            proxy.port(),
                            proxy.authority(),
                            connect_udp_path(proxy, transport).map_err(SetupFailure::Other)?,
                            proxy.headers().to_vec(),
                            proxy.credentials(),
                            endpoint.host(),
                        )
                        .await
                        .map_err(SetupFailure::ConnectUdp)?
                }
            },
            Route::HttpProxy(_) => {
                return Err(SetupFailure::Other(RequestError::unsupported_route(
                    HttpProtocol::Http3,
                )));
            }
        })
    }

    async fn invalidate(&self, token: &Arc<()>) {
        let mut slots = self.slots.lock().await;
        if let Some(position) = slots
            .iter()
            .position(|slot| Arc::ptr_eq(&slot.token, token))
        {
            slots.remove(position);
            debug!(
                outcome = "invalidated",
                "HTTP/3 pool connection invalidated"
            );
        }
    }
}

/// One failed connection setup, kept typed until the ticket retry decision.
enum SetupFailure {
    Origin(Http3ConnectorError),
    ConnectUdp(Http3ConnectorError),
    Other(RequestError),
}

impl SetupFailure {
    /// Returns whether the origin or outer-proxy TLS handshake failed.
    fn is_handshake(&self) -> bool {
        let error = match self {
            Self::Origin(error) | Self::ConnectUdp(error) => error,
            Self::Other(_) => return false,
        };
        match error.kind() {
            Http3ConnectorErrorKind::Handshake => true,
            Http3ConnectorErrorKind::Proxy => std::error::Error::source(error)
                .and_then(|source| source.downcast_ref::<ConnectUdpError>())
                .is_some_and(|source| source.kind() == ConnectUdpErrorKind::Handshake),
            _ => false,
        }
    }

    fn into_request_error(self) -> RequestError {
        match self {
            Self::Origin(error) => RequestError::http3_connection_setup(error),
            Self::ConnectUdp(error) => RequestError::http3_connect_udp_setup(error),
            Self::Other(error) => error,
        }
    }
}

/// The right to set up a connection to one transport location of an entry.
///
/// A request for the same location waits for the turn and then reuses the
/// connection it pooled, while setup to another location of the entry, such
/// as exact H3 beside an Alt-Svc alternative, proceeds independently.
struct ConnectTurn {
    entry: Arc<PoolEntry>,
    gate: Arc<Mutex<()>>,
    guard: Option<OwnedMutexGuard<()>>,
}

impl Drop for ConnectTurn {
    fn drop(&mut self) {
        drop(self.guard.take());
        let mut turns = lock_turns(&self.entry.turns);
        // Only the table and this turn still refer to the gate: nobody waits.
        if Arc::strong_count(&self.gate) == 2 {
            turns.retain(|(_, gate)| !Arc::ptr_eq(gate, &self.gate));
        }
    }
}

/// One connect gate per transport location with a setup in progress or queued.
type ConnectTurns = std::sync::Mutex<Vec<(TransportLocation, Arc<Mutex<()>>)>>;

fn lock_turns(
    turns: &ConnectTurns,
) -> std::sync::MutexGuard<'_, Vec<(TransportLocation, Arc<Mutex<()>>)>> {
    match turns.lock() {
        Ok(turns) => turns,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// How one admitted setup reports and bounds its connection attempts.
#[derive(Clone, Copy, Default)]
pub(crate) struct Http3SetupControl<'a> {
    /// Set once the setup holds its location's connect turn, the point after
    /// which it may perform network I/O.
    pub(crate) connecting: Option<&'a AtomicBool>,
    /// Limit on one connection attempt once the turn is held, reported as a
    /// connect-phase timeout.
    pub(crate) attempt_limit: Option<Duration>,
    /// Whether a new connection offers early data. Set on a client that
    /// enables HTTP/3 early data; only a replay-safe request is then sent
    /// before the handshake completes.
    pub(crate) early_data: bool,
}

/// One admitted request that has not acquired a connection yet.
pub(crate) struct Http3Admission {
    entry: Arc<PoolEntry>,
    permit: AdmissionPermit,
}

impl Http3Admission {
    /// Acquires this admission's connection, with setup retries.
    ///
    /// Waiting for the location's connect turn counts toward each attempt's
    /// connect phase, as does the attempt itself.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn connect(
        self,
        connector: &Http3Connector,
        connect_udp_proxy: Option<&ConnectUdpConnectors>,
        endpoint: &Endpoint,
        route: &Route,
        transport: Http3TransportTarget<'_>,
        timeout_budget: TimeoutBudget,
        retries: &mut ConnectionSetupRetryState,
        control: Http3SetupControl<'_>,
    ) -> Result<Http3Lease, RequestError> {
        let Self { entry, permit } = self;
        let lease = acquire_with_retries(HttpProtocol::Http3, timeout_budget, retries, || async {
            entry
                .acquire(
                    connector,
                    connect_udp_proxy,
                    endpoint,
                    route,
                    transport,
                    control,
                )
                .await
        })
        .await?;
        Ok(Http3Lease {
            entry,
            lease,
            permit,
        })
    }
}

/// A pooled H3 connection admitted for one request and not yet dispatched.
pub(crate) struct Http3Lease {
    entry: Arc<PoolEntry>,
    lease: ConnectionLease,
    permit: AdmissionPermit,
}

/// Whether a request may use its lease, after waiting for the early data.
enum EarlyDataWait {
    /// The connection sent no early data, or the server accepted it.
    Ready(Http3Lease),
    /// The server rejected the early data, so it processed none of it. The
    /// error is the one to report when the request is not sent again.
    Rejected(RequestError),
}

impl Http3Lease {
    /// Waits, within the connect phase, until the server answers the leased
    /// connection's early data.
    ///
    /// A connection that sent none, or whose early data was accepted, is
    /// ready at once. A rejection, a failed handshake, and invalid handshake
    /// metadata each invalidate the pooled connection, and only a rejection
    /// lets the request be sent elsewhere; the others are request errors.
    /// A connect timeout leaves the connection pooled for the requests still
    /// waiting on it. Dropping the lease releases its admission.
    async fn wait_for_early_data(
        self,
        connector: &Http3Connector,
        timeout_budget: TimeoutBudget,
    ) -> Result<EarlyDataWait, RequestError> {
        if !self.lease.connection.sent_early_data() {
            return Ok(EarlyDataWait::Ready(self));
        }
        let settled = timeout_budget
            .run(TimeoutPhase::Connect, Some(HttpProtocol::Http3), async {
                Ok(connector
                    .early_data_settled_on(&self.lease.connection)
                    .await)
            })
            .await?;
        let Err(error) = settled else {
            return Ok(EarlyDataWait::Ready(self));
        };
        self.entry.invalidate(&self.lease.token).await;
        let error = RequestError::http3_stream(error);
        if error.is_http3_early_data_rejected() {
            Ok(EarlyDataWait::Rejected(error))
        } else {
            Err(error)
        }
    }
}

/// Returns whether a request goes out before its connection's handshake
/// completes: a replay-safe request on a connection whose early data is
/// unanswered, unless the QPACK policy holds every request until the peer's
/// SETTINGS and the connection has neither those nor remembered ones. The
/// server's SETTINGS arrive only with the completed handshake. Such a request
/// uses the client hints known before the handshake; every other request
/// waits for the answer and uses the hints the handshake delivered.
const fn sends_before_handshake(
    replay_safe: bool,
    early_data_pending: bool,
    requests_wait_for_peer_settings: bool,
) -> bool {
    replay_safe && early_data_pending && !requests_wait_for_peer_settings
}

/// Checks one request's H3 and route representation before any I/O.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_request(
    connector: &Http3Connector,
    connect_udp_proxy: Option<&ConnectUdpConnectors>,
    route: &Route,
    transport: Http3TransportTarget<'_>,
    method: &Method,
    authority: &str,
    target: &OriginForm,
    headers: &[RequestHeader],
    trailers: &[RequestHeader],
    client_hints: Option<ClientHintContext<'_>>,
    body: Option<&RequestBody>,
) -> Result<(), RequestError> {
    validate_wire(
        connector,
        method,
        authority,
        target,
        headers,
        trailers,
        client_hints,
        body,
    )?;
    if let Route::ConnectUdp(proxy) = route {
        let path = connect_udp_path(proxy, transport)?;
        match proxy.tcp_protocol() {
            None => connect_udp_http3(connect_udp_proxy)?.validate_connect_udp_with_basic_auth(
                proxy.host(),
                proxy.authority(),
                &path,
                proxy.headers(),
                proxy.credentials(),
            ),
            Some(protocol) => Http3Connector::validate_connect_udp_over_tcp(
                connect_udp_tcp(connect_udp_proxy)?,
                protocol,
                proxy.authority(),
                &path,
                proxy.headers(),
                proxy.credentials(),
            ),
        }
        .map_err(RequestError::http3)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_wire(
    connector: &Http3Connector,
    method: &Method,
    authority: &str,
    target: &OriginForm,
    headers: &[RequestHeader],
    trailers: &[RequestHeader],
    client_hints: Option<ClientHintContext<'_>>,
    body: Option<&RequestBody>,
) -> Result<(), RequestError> {
    let prepared_validation_headers = client_hints
        .map(|context| context.prepare(headers.to_vec(), None))
        .transpose()?;
    let validation_headers = prepared_validation_headers.as_deref().unwrap_or(headers);
    connector
        .validate_request_body_source_with_trailers(
            method.clone(),
            authority,
            target,
            validation_headers,
            body,
            trailers,
        )
        .map_err(RequestError::http3)
}

#[allow(clippy::too_many_arguments)]
async fn dispatch(
    leased: Http3Lease,
    connector: &Http3Connector,
    method: Method,
    authority: &str,
    target: OriginForm,
    headers: Vec<RequestHeader>,
    trailers: Vec<RequestHeader>,
    client_hints: Option<ClientHintContext<'_>>,
    body: Option<RequestBody>,
    timeout_budget: TimeoutBudget,
    retries: &ConnectionSetupRetryState,
) -> Result<(http::Response<ResponseBody>, Vec<RequestHeader>), RequestError> {
    let Http3Lease {
        entry,
        lease,
        permit,
    } = leased;
    let sent_headers = match client_hints {
        Some(context) => context.prepare(
            headers,
            lease.connection.accept_ch_for_origin(context.origin()),
        )?,
        None => headers,
    };
    let result = timeout_budget
        .run(
            TimeoutPhase::ResponseHead,
            Some(HttpProtocol::Http3),
            async {
                Ok::<_, RequestError>(
                    connector
                        .send_request_body_with_trailers_on(
                            &lease.connection,
                            method,
                            authority,
                            target,
                            sent_headers.clone(),
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
                http::Response::from_parts(parts, ResponseBody::http3_with_guard(body, permit)),
                sent_headers,
            ))
        }
        Ok(Err(error)) => {
            drop(permit);
            let error = RequestError::http3_stream(error);
            // An unprocessed replay must use another connection, so one
            // that rejected a request is retired when it is enabled.
            if !connector.can_reuse(&lease.connection).await
                || (retries.replays_unprocessed_requests() && error.is_unprocessed_request())
            {
                entry.invalidate(&lease.token).await;
            }
            Err(error)
        }
        Err(error) => {
            drop(permit);
            Err(error)
        }
    }
}

/// Returns whether sending `method` twice is harmless: a safe method (RFC
/// 9110, section 9.2.1) with no body and no trailers. This is the method rule
/// Phantom applies to critical client-hint replays, and the rule Chromium
/// applies to early data for a request of default idempotency.
fn is_replay_safe(method: &Method, body: Option<&RequestBody>, trailers: &[RequestHeader]) -> bool {
    method.is_safe() && body.is_none() && trailers.is_empty()
}

/// Expands the CONNECT-UDP path for the transport target before I/O.
fn connect_udp_path(
    proxy: &ConnectUdpProxy,
    transport: Http3TransportTarget<'_>,
) -> Result<OriginForm, RequestError> {
    proxy
        .expand(transport.host, transport.port)
        .map_err(RequestError::invalid_target)
}

/// Returns the outer HTTP/3 connector, absent when proxy verification is
/// disabled or the profile has no HTTP/3.
fn connect_udp_http3(
    connectors: Option<&ConnectUdpConnectors>,
) -> Result<&Http3Connector, RequestError> {
    connectors
        .and_then(|connectors| connectors.http3.as_ref())
        .ok_or_else(|| RequestError::unsupported_route(HttpProtocol::Http3))
}

/// Returns the proxy TLS connector for HTTP/1.1 and HTTP/2 legs, absent
/// when proxy verification is disabled or TLS cannot offer `http/1.1`.
fn connect_udp_tcp(
    connectors: Option<&ConnectUdpConnectors>,
) -> Result<&HttpsProxyConnector, RequestError> {
    connectors
        .and_then(|connectors| connectors.tcp.as_ref())
        .ok_or_else(|| RequestError::unsupported_route(HttpProtocol::Http3))
}

struct ConnectionSlot {
    connection: Http3Connection,
    token: Arc<()>,
    location: TransportLocation,
}

impl ConnectionSlot {
    fn lease(&self) -> ConnectionLease {
        ConnectionLease {
            connection: self.connection.clone(),
            token: Arc::clone(&self.token),
        }
    }
}

struct ConnectionLease {
    connection: Http3Connection,
    token: Arc<()>,
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroUsize, sync::Arc};

    use super::{Http3Pool, Http3TransportTarget, PoolKey, TransportLocation};
    use crate::{Route, Socks5Proxy, authority::Endpoint};

    #[tokio::test]
    async fn per_origin_admission_survives_lru_eviction() -> Result<(), Box<dyn std::error::Error>>
    {
        let one = NonZeroUsize::MIN;
        let pool = Http3Pool::new(one, one, one);
        let first = Endpoint::new("first.test:443".parse()?, 443)?;
        let second = Endpoint::new("second.test:443".parse()?, 443)?;

        let first_entry = pool.entry(PoolKey::new(&first, &Route::Direct)).await;
        let permit = first_entry.admit().await?;
        pool.entry(PoolKey::new(&second, &Route::Direct)).await;
        drop(first_entry);
        let replacement = pool.entry(PoolKey::new(&first, &Route::Direct)).await;

        assert!(Arc::ptr_eq(permit.admission(), &replacement.admission));
        assert_eq!(replacement.admission.available_active(), 0);
        drop(permit);
        assert_eq!(replacement.admission.available_active(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn connect_turn_serializes_one_transport_location_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let one = NonZeroUsize::MIN;
        let pool = Http3Pool::new(one, one, one);
        let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
        let entry = pool.entry(PoolKey::new(&endpoint, &Route::Direct)).await;
        let alternative = TransportLocation::new(Http3TransportTarget::new("alt.test", 8443));
        let origin = TransportLocation::new(Http3TransportTarget::for_origin(&endpoint));

        let setup = entry.connect_turn(alternative.clone()).await;
        // Exact H3 to the origin location does not wait for the alternative.
        let exact = std::pin::pin!(entry.connect_turn(origin));
        let exact = poll_once(exact).ok_or("exact H3 waited for another location")?;
        // A second setup to the same location waits until the turn ends.
        let mut same = std::pin::pin!(entry.connect_turn(alternative));
        assert!(poll_once(same.as_mut()).is_none());
        drop(setup);
        let same = poll_once(same).ok_or("the released turn was not handed over")?;

        drop((exact, same));
        assert!(super::lock_turns(&entry.turns).is_empty());
        Ok(())
    }

    fn poll_once<F: std::future::Future>(future: std::pin::Pin<&mut F>) -> Option<F::Output> {
        match future.poll(&mut std::task::Context::from_waker(std::task::Waker::noop())) {
            std::task::Poll::Ready(output) => Some(output),
            std::task::Poll::Pending => None,
        }
    }

    /// Only a replay-safe request on a connection whose early data is
    /// unanswered, where the QPACK policy does not wait for the peer's
    /// SETTINGS or remembered SETTINGS stand in for them, goes out before the
    /// handshake with the pre-handshake client hints; every other request
    /// waits and uses the handshake's hints.
    #[test]
    fn only_an_unheld_replay_safe_request_goes_out_before_the_handshake() {
        use super::sends_before_handshake;

        assert!(sends_before_handshake(true, true, false));
        for (replay_safe, pending, waits) in [
            (true, true, true),
            (false, true, false),
            (true, false, false),
            (false, false, true),
        ] {
            assert!(!sends_before_handshake(replay_safe, pending, waits));
        }
    }

    #[test]
    fn only_bodiless_safe_requests_without_trailers_are_replay_safe() {
        use http::Method;
        use phantom_net::http3::RequestHeader;
        use phantom_net::request::RequestBody;

        use super::is_replay_safe;

        for method in [Method::GET, Method::HEAD, Method::OPTIONS, Method::TRACE] {
            assert!(is_replay_safe(&method, None, &[]), "{method}");
        }
        for method in [Method::POST, Method::PUT, Method::DELETE, Method::CONNECT] {
            assert!(!is_replay_safe(&method, None, &[]), "{method}");
        }
        let body = RequestBody::from_bytes(bytes::Bytes::from_static(b"body"));
        assert!(!is_replay_safe(&Method::GET, Some(&body), &[]));
        let trailer = RequestHeader::new("x-trailer", "1");
        assert!(!is_replay_safe(&Method::GET, None, &[trailer]));
    }

    #[test]
    fn transport_location_is_separate_from_origin_pool_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
        let key = PoolKey::new(&endpoint, &Route::Direct);
        let alternative = TransportLocation::new(Http3TransportTarget::new("Alt.Test", 8443));
        let matching = TransportLocation::new(Http3TransportTarget::new("alt.test", 8443));
        let origin = TransportLocation::new(Http3TransportTarget::for_origin(&endpoint));

        assert_eq!(key, PoolKey::new(&endpoint, &Route::Direct));
        assert_eq!(alternative, matching);
        assert_ne!(alternative, origin);
        Ok(())
    }

    #[test]
    fn an_alternative_learned_on_one_route_uses_that_route_s_entry()
    -> Result<(), Box<dyn std::error::Error>> {
        let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
        let proxied = Route::socks5(Socks5Proxy::new("socks5h://proxy.test:1080")?);
        let other = Route::socks5(Socks5Proxy::new("socks5h://other.test:1080")?);

        // The same alternative location on another route is another entry, so
        // a proxied alternative never reuses a direct connection or another
        // proxy's.
        assert_ne!(
            PoolKey::new(&endpoint, &proxied),
            PoolKey::new(&endpoint, &Route::Direct)
        );
        assert_ne!(
            PoolKey::new(&endpoint, &proxied),
            PoolKey::new(&endpoint, &other)
        );
        assert_eq!(
            PoolKey::new(&endpoint, &proxied),
            PoolKey::new(&endpoint, &proxied)
        );
        Ok(())
    }
}
