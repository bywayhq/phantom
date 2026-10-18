use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    pin::pin,
    sync::{
        Arc, MutexGuard, OnceLock, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use http::Method;
#[cfg(feature = "websocket")]
use phantom_net::http3::{
    Http3ExtendedConnectOutcome, Http3ExtendedConnectStream, Http3ExtendedProtocol,
};
use phantom_net::proxy::HttpsProxyConnector;
use phantom_net::request::RequestBody;
use phantom_net::{
    http3::{Http3Connection, Http3Connector, Http3ConnectorError, Http3ConnectorErrorKind},
    request::{OriginForm, RequestHeader},
};
use tokio::sync::{Mutex, Notify, OwnedMutexGuard};
use tracing::debug;

use super::tickets::{
    TicketCacheBinding,
    binding::{TicketCacheLeg, TicketCacheProtocol},
};
use super::{
    admission::{Admission, AdmissionPermit, AdmissionRegistry},
    alt_svc::{
        AltSvcValidationPublication, DEFAULT_ALTERNATIVE_SETUP_LIMIT,
        rtt_history::{Publication, RttHistory},
    },
    client_hints::{AcceptChRestart, ClientHintContext, Dispatched},
    http3_connections::{Candidate, Choice, Http3Spread},
    stream_count::{OpenStream, StreamCount},
};
use crate::timeout::{TimeoutBudget, TimeoutPhase, within};
use crate::{
    ConnectUdpProxy, HttpProtocol, RequestError, ResponseBody, Route, Socks5DnsMode,
    authority::Endpoint,
    retry::{ConnectionSetupRetryState, acquire_with_retries},
};

/// Borrowed network location used to reach an HTTP/3 origin.
///
/// The origin endpoint still owns TLS authentication, request authority, pool
/// identity, and route policy. This value changes only where QUIC is sent.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Http3TransportTarget<'a> {
    host: &'a str,
    port: u16,
    validation: Option<&'a AltSvcValidationPublication>,
    #[cfg(feature = "https-records")]
    alt_svc: bool,
}

impl<'a> Http3TransportTarget<'a> {
    pub(crate) const fn new(host: &'a str, port: u16) -> Self {
        Self {
            host,
            port,
            validation: None,
            #[cfg(feature = "https-records")]
            alt_svc: false,
        }
    }

    pub(crate) fn for_origin(endpoint: &'a Endpoint) -> Self {
        Self::new(endpoint.host(), endpoint.port())
    }

    pub(crate) fn for_alternative(alternative: &'a super::alt_svc::AlternativeTarget) -> Self {
        Self {
            host: alternative.host(),
            port: alternative.port(),
            validation: alternative.validation_publication(),
            #[cfg(feature = "https-records")]
            alt_svc: alternative.is_alt_svc(),
        }
    }

    #[cfg(feature = "https-records")]
    fn destination_lookup_timeout(
        self,
        route: &Route,
        policy: crate::AltSvcHttpsPolicy,
    ) -> Option<Duration> {
        match policy {
            crate::AltSvcHttpsPolicy::Destination { lookup_timeout }
                if self.alt_svc && matches!(route, Route::Direct) =>
            {
                Some(lookup_timeout)
            }
            _ => None,
        }
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
    tickets: Arc<super::tickets::TicketOwner>,
    capacity: NonZeroUsize,
    max_active: NonZeroUsize,
    max_pending: NonZeroUsize,
    max_connections: NonZeroUsize,
    state: Mutex<PoolState>,
    rtt_history: Option<Arc<RttHistory>>,
    #[cfg(feature = "https-records")]
    https_records: Option<super::alt_svc::HttpsRecordDiscovery>,
    #[cfg(feature = "https-records")]
    alt_svc_https_policy: crate::AltSvcHttpsPolicy,
}

impl Http3Pool {
    pub(super) async fn close_idle_connections(
        &self,
    ) -> Vec<phantom_net::proxy::ConnectUdpProxyPool> {
        let mut retired = Vec::new();
        let mut proxy_pools = Vec::new();
        {
            let state = self.state.lock().await;
            for (key, entry) in &state.entries {
                if let Route::ConnectUdp(proxy) = &key.route {
                    proxy_pools.push(proxy.pool().clone());
                }
                let mut slots = entry.lock_slots();
                let mut index = 0;
                while index < slots.connections.len() {
                    let connection = &slots.connections[index].connection;
                    if connection.is_exclusively_owned() && !connection.early_data_pending() {
                        if let Some(connection) = slots.connections.remove(index) {
                            retired.push(connection);
                        }
                    } else {
                        index += 1;
                    }
                }
            }
        }
        drop(retired);
        proxy_pools
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
            state: Mutex::new(PoolState::default()),
            rtt_history: None,
            #[cfg(feature = "https-records")]
            https_records: None,
            #[cfg(feature = "https-records")]
            alt_svc_https_policy: crate::AltSvcHttpsPolicy::OriginOnly,
        }
    }

    pub(super) fn with_ticket_owner(mut self, tickets: Arc<super::tickets::TicketOwner>) -> Self {
        self.tickets = tickets;
        self
    }

    /// Lets each transport location of a pool entry keep up to `maximum`
    /// connections; see [`Http3Spread`].
    pub(super) const fn with_max_connections(mut self, maximum: NonZeroUsize) -> Self {
        self.max_connections = maximum;
        self
    }

    pub(super) const fn max_connections(&self) -> NonZeroUsize {
        self.max_connections
    }

    /// Gives direct connections to an origin's own location the client's
    /// HTTPS-record lookups, for profiles that offer ECH from HTTPS records.
    #[cfg(feature = "https-records")]
    pub(super) fn set_https_records(
        &mut self,
        discovery: Option<super::alt_svc::HttpsRecordDiscovery>,
    ) {
        self.https_records = discovery;
    }

    #[cfg(feature = "https-records")]
    pub(super) const fn set_alt_svc_https_policy(&mut self, policy: crate::AltSvcHttpsPolicy) {
        self.alt_svc_https_policy = policy;
    }

    pub(super) fn set_rtt_history(&mut self, history: Option<Arc<RttHistory>>) {
        self.rtt_history = history;
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

    /// Connects to `transport` and sends one request with the `fields` that
    /// [`validate_request`] returned for the same route, transport, method,
    /// authority, target, trailers, and body.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn send_request(
        &self,
        connector: &Http3Connector,
        connect_udp_proxy: Option<&ConnectUdpConnectors>,
        endpoint: &Endpoint,
        route: &Route,
        transport: Http3TransportTarget<'_>,
        method: Method,
        authority: &str,
        target: OriginForm,
        fields: Http3Fields,
        trailers: Vec<RequestHeader>,
        client_hints: Option<ClientHintContext<'_>>,
        body: Option<RequestBody>,
        timeout_budget: TimeoutBudget,
        retries: &mut ConnectionSetupRetryState,
        may_fall_back: bool,
    ) -> Result<Dispatched<Http3Response>, RequestError> {
        // A request that would fall back to HTTP/2 bounds each QUIC attempt
        // as a raced alternative's is bounded, with the same caveat: a
        // responsive but slow handshake fails here and not in Chromium.
        let attempt_limit = may_fall_back.then_some(DEFAULT_ALTERNATIVE_SETUP_LIMIT);
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
                    attempt_limit,
                    ..Http3SetupControl::default()
                },
            )
            .await?;
        self.send_on_lease(
            leased,
            connector,
            method,
            authority,
            target,
            fields.0,
            trailers,
            client_hints,
            body,
            timeout_budget,
            retries,
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

    /// Dispatches one request on a lease from [`Http3Admission::connect`],
    /// with the `fields` that [`validate_request`] returned for the lease's
    /// route and transport and for the same method, authority, target,
    /// trailers, and body.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn send_request_on_lease(
        &self,
        leased: Http3Lease,
        connector: &Http3Connector,
        method: Method,
        authority: &str,
        target: OriginForm,
        fields: Http3Fields,
        trailers: Vec<RequestHeader>,
        client_hints: Option<ClientHintContext<'_>>,
        body: Option<RequestBody>,
        timeout_budget: TimeoutBudget,
        retries: &mut ConnectionSetupRetryState,
    ) -> Result<Dispatched<Http3Response>, RequestError> {
        self.send_on_lease(
            leased,
            connector,
            method,
            authority,
            target,
            fields.0,
            trailers,
            client_hints,
            body,
            timeout_budget,
            retries,
        )
        .await
    }

    /// Dispatches one validated request on `leased`, under the early-data
    /// rule of [`sends_before_handshake`].
    ///
    /// A replay-safe request on a connection whose early data is unanswered
    /// goes out as early data; the connection knows no ALPS `ACCEPT_CH` yet.
    /// If the server rejects the early data, it processed none of it (RFC
    /// 9001, section 4.6.2); the connection starts HTTP/3 again after the
    /// handshake, and the request is sent again on it as built, as Chromium
    /// does. Any other request waits for the answer, keeps its body until
    /// then, and restarts when the completed handshake's `ACCEPT_CH` asks for
    /// a hint it lacks.
    #[allow(clippy::too_many_arguments)]
    async fn send_on_lease(
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
    ) -> Result<Dispatched<Http3Response>, RequestError> {
        let mut leased = leased;
        // The connection's ACCEPT_CH check, which a request sent as early
        // data never gets.
        let mut accept_ch_check = client_hints;
        if sends_before_handshake(
            is_replay_safe(&method, body.as_ref(), &trailers),
            leased.lease.connection.early_data_pending(),
            connector.requests_wait_for_peer_settings()
                && !leased.lease.connection.started_from_remembered_settings(),
        ) {
            let entry = Arc::clone(&leased.entry);
            let lease = leased.lease.clone();
            // Early data goes out before the handshake delivers ALPS. If the
            // server rejects it, Chromium's QUIC session retransmits the same
            // stream data under 1-RTT keys (`QuicSession::OnZeroRttRejected`,
            // `quiche/quic/core/quic_session.cc` lines 2038-2049 at the quiche
            // revision Chromium 154.0.8037.58 pins), so the request is not
            // built or checked again; the resend below sends it as built.
            accept_ch_check = None;
            let result = dispatch(
                leased,
                connector,
                method.clone(),
                authority,
                target.clone(),
                headers.clone(),
                trailers.clone(),
                None,
                None,
                timeout_budget,
                retries,
            )
            .await;
            match result {
                Err(error) if error.is_http3_early_data_rejected() => {
                    debug!(
                        outcome = "early_data_rejected",
                        "HTTP/3 early data rejected; sending again on the connection"
                    );
                    leased = Http3Lease::readmit(entry, lease, timeout_budget).await?;
                }
                result => return result,
            }
        }
        let leased = leased
            .wait_for_early_data(connector, timeout_budget)
            .await?;
        dispatch(
            leased,
            connector,
            method,
            authority,
            target,
            headers,
            trailers,
            accept_ch_check,
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
        let mut entry = PoolEntry::new(
            admission,
            Http3Spread::new(self.max_connections, self.max_active),
            self.rtt_history.clone(),
            #[cfg(feature = "https-records")]
            self.https_records.clone(),
            #[cfg(feature = "https-records")]
            self.alt_svc_https_policy,
        );
        entry.tickets = Arc::clone(&self.tickets);
        let entry = Arc::new(entry);
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
        self.admissions.get(&key.origin(), max_active, max_pending)
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

/// The client certificate depends only on host and port
/// ([`ClientBuilder::client_certificate_for`](crate::ClientBuilder::client_certificate_for)),
/// so the connections and TLS session tickets of one key share a certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
struct PoolKey {
    host: Box<str>,
    port: u16,
    route: Route,
    runtime: Option<tokio::runtime::Id>,
}

impl PoolKey {
    fn new(endpoint: &Endpoint, route: &Route) -> Self {
        Self {
            host: endpoint.host().to_ascii_lowercase().into(),
            port: endpoint.port(),
            route: route.clone(),
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

/// Transport locations that keep connections within one origin-and-route entry.
///
/// Exact H3 dials the origin location while an Alt-Svc attempt dials the
/// alternative; separate slots stop each switch from replacing the other's
/// connections. Each location keeps up to the pool's connection limit, and
/// beyond this many locations' worth the least recently used connection is
/// closed.
const MAX_TRANSPORT_LOCATIONS_PER_ENTRY: usize = 4;

// A race's alternatives and exact H3 to the origin's own location all keep
// their connections without evicting one another.
const _: () =
    assert!(super::alt_svc::MAX_RACED_ALTERNATIVES == MAX_TRANSPORT_LOCATIONS_PER_ENTRY - 1);

struct PoolEntry {
    tickets: Arc<super::tickets::TicketOwner>,
    /// The entry's connections and how streams spread across them. The lock
    /// is held for lookup and insertion only, never across an await.
    slots: std::sync::Mutex<Slots>,
    /// Woken whenever a stream on one of the entry's connections ends, so a
    /// request waiting to open a connection can take the freed room instead.
    stream_ended: Arc<Notify>,
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
    /// Dedicated HTTP/1.1 CONNECT-UDP outer cache, scoped to this origin and route.
    tcp_proxy: OnceLock<HttpsProxyConnector>,
    rtt_history: Option<Arc<RttHistory>>,
    /// The client's HTTPS-record lookups, when it makes them.
    #[cfg(feature = "https-records")]
    https_records: Option<super::alt_svc::HttpsRecordDiscovery>,
    #[cfg(feature = "https-records")]
    alt_svc_https_policy: crate::AltSvcHttpsPolicy,
}

impl PoolEntry {
    fn new(
        admission: Arc<Admission>,
        spread: Http3Spread,
        rtt_history: Option<Arc<RttHistory>>,
        #[cfg(feature = "https-records")] https_records: Option<
            super::alt_svc::HttpsRecordDiscovery,
        >,
        #[cfg(feature = "https-records")] alt_svc_https_policy: crate::AltSvcHttpsPolicy,
    ) -> Self {
        Self {
            tickets: Arc::default(),
            slots: std::sync::Mutex::new(Slots {
                connections: VecDeque::new(),
                spread,
            }),
            stream_ended: Arc::new(Notify::new()),
            turns: std::sync::Mutex::new(Vec::new()),
            admission,
            origin: OnceLock::new(),
            origin_early: OnceLock::new(),
            tcp_proxy: OnceLock::new(),
            rtt_history,
            #[cfg(feature = "https-records")]
            https_records,
            #[cfg(feature = "https-records")]
            alt_svc_https_policy,
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

    fn lock_slots(&self) -> MutexGuard<'_, Slots> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Leases a connection to `transport` for one stream, opening one when
    /// the location has none with room and is below its connection limit.
    ///
    /// Setup to one location is single-flight: the request that must open a
    /// connection takes the location's connect turn, and the others wait for
    /// the turn and then choose again, so they share the new connection
    /// while it has room. With more than one connection allowed, a waiting
    /// request also chooses again whenever a stream on the entry ends, and
    /// keeps its place in the turn's queue meanwhile.
    async fn acquire(
        self: &Arc<Self>,
        connector: &Http3Connector,
        connect_udp_proxy: Option<&ConnectUdpConnectors>,
        endpoint: &Endpoint,
        route: &Route,
        transport: Http3TransportTarget<'_>,
        control: Http3SetupControl<'_>,
    ) -> Result<(ConnectionLease, OpenStream), RequestError> {
        let location = TransportLocation::new(transport);
        let spreads = self.lock_slots().spread.max_connections().get() > 1;
        let turn = if spreads {
            let mut waiting_turn = pin!(self.connect_turn(location.clone()));
            loop {
                let mut stream_ended = pin!(self.stream_ended.notified());
                // Registered before the choice, so a stream ending in between
                // still wakes this request.
                stream_ended.as_mut().enable();
                if let Some(leased) = self.choose(connector, &location) {
                    return Ok(leased);
                }
                tokio::select! {
                    turn = waiting_turn.as_mut() => break turn,
                    () = stream_ended => {}
                }
            }
        } else {
            if let Some(leased) = self.choose(connector, &location) {
                return Ok(leased);
            }
            self.connect_turn(location.clone()).await
        };
        if let Some(connecting) = control.connecting {
            connecting.store(true, Ordering::Release);
        }
        // The setup that held the turn before may have pooled a connection
        // with room.
        if let Some(leased) = self.choose(connector, &location) {
            return Ok(leased);
        }

        // Captured before I/O. Clears or target invalidation cannot admit a
        // delayed handshake into a newer history generation.
        let publication = self.rtt_history.as_ref().and_then(|history| {
            history.publication(
                endpoint,
                route,
                transport.host,
                transport.port,
                connector.server_authentication().verifies(),
            )
        });
        // Boxed: opening a connection awaits the largest connector futures,
        // which would otherwise enlarge the future of every request, including
        // one that reuses a pooled connection.
        let connection = super::box_send(self.open(
            connector,
            connect_udp_proxy,
            endpoint,
            route,
            transport,
            control,
        ))
        .await?;
        if !connection.sent_early_data()
            && let Some(publication) = &publication
        {
            publication.record(connection.completed_handshake_rtt());
        }
        let slot = ConnectionSlot {
            publication,
            connection,
            token: Arc::new(()),
            location,
            // Only a pool that spreads streams wakes requests when one ends.
            streams: if spreads {
                StreamCount::notifying(Arc::clone(&self.stream_ended))
            } else {
                StreamCount::default()
            },
            peer_limit: None,
        };
        // A connection whose early data is unanswered is pooled at once, so
        // later requests to this location share it instead of opening their
        // own; each waits for the answer unless it may go out early. A
        // rejected or failed connection is invalidated by the first request
        // that sees it.
        let leased = slot.lease();
        let mut slots = self.lock_slots();
        let retained = MAX_TRANSPORT_LOCATIONS_PER_ENTRY * slots.spread.max_connections().get();
        if slots.connections.len() >= retained {
            slots.connections.pop_front();
            debug!(outcome = "evicted", "HTTP/3 pooled connection evicted");
        }
        slots.connections.push_back(slot);
        drop(slots);
        drop(turn);
        Ok(leased)
    }

    /// Opens one connection for [`Self::acquire`], within the setup's
    /// attempt limit when it has one.
    async fn open(
        &self,
        connector: &Http3Connector,
        connect_udp_proxy: Option<&ConnectUdpConnectors>,
        endpoint: &Endpoint,
        route: &Route,
        transport: Http3TransportTarget<'_>,
        control: Http3SetupControl<'_>,
    ) -> Result<Http3Connection, RequestError> {
        // Pinned in place: `within` would otherwise hold a second copy. The
        // block drops the attempt before a timeout is reported, as when
        // `within` owned it.
        let attempt = {
            let connect = pin!(self.connect(
                connector,
                connect_udp_proxy,
                endpoint,
                route,
                transport,
                control.early_data,
            ));
            match control.attempt_limit {
                // A runtime without a time driver fails the attempt instead of
                // panicking.
                Some(limit) => within(limit, connect).await?,
                None => return connect.await,
            }
        };
        attempt.ok_or_else(|| {
            debug!(
                timeout_phase = TimeoutPhase::Connect.trace_name(),
                protocol = HttpProtocol::Http3.trace_name(),
                "HTTP/3 connection attempt reached its limit"
            );
            RequestError::timeout(TimeoutPhase::Connect, Some(HttpProtocol::Http3))
        })?
    }

    /// Leases a reusable pooled connection to `location` for one stream, or
    /// returns `None` when the location should open another.
    ///
    /// Connections that can no longer carry a request, such as one draining
    /// after the server's GOAWAY, leave the pool first; they do not count
    /// toward the location's connection limit.
    fn choose(
        &self,
        connector: &Http3Connector,
        location: &TransportLocation,
    ) -> Option<(ConnectionLease, OpenStream)> {
        let mut slots = self.lock_slots();
        let Slots {
            connections,
            spread,
        } = &mut *slots;
        connections
            .retain(|slot| &slot.location != location || connector.can_reuse_now(&slot.connection));
        if spread.max_connections().get() > 1 {
            for slot in connections
                .iter_mut()
                .filter(|slot| &slot.location == location)
            {
                slot.read_peer_limit();
            }
        }
        let candidates = connections
            .iter()
            .enumerate()
            .filter(|(_, slot)| &slot.location == location)
            .map(|(position, slot)| (position, slot.candidate()));
        let Choice::Use(position) = spread.choose(candidates) else {
            return None;
        };
        let slot = connections.remove(position)?;
        let leased = slot.lease();
        connections.push_back(slot);
        drop(slots);
        debug!(
            outcome = "hit",
            "HTTP/3 connection acquired from client pool"
        );
        Some(leased)
    }

    /// Opens one connection to `transport` on `route`.
    ///
    /// Inner connections use this entry's isolated connector. A shared
    /// CONNECT-UDP route owns a separate outer session and ticket scope.
    /// When an attempt that presented a ticket
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
        let early_origin = self.origin_early.get_or_init(|| {
            connector
                .sends_early_data()
                .then(|| connector.with_isolated_session_cache())
        });
        let origin = self.origin.get_or_init(|| {
            // Derive suppression from the enabled owner so both offers share
            // one cache without enabling early data on an already bound alias.
            early_origin.as_ref().map_or_else(
                || connector.without_early_data().with_isolated_session_cache(),
                Http3Connector::without_early_data,
            )
        });
        self.tickets
            .register_before_use(
                origin.session_ticket_cache(),
                TicketCacheBinding {
                    origin: endpoint,
                    server_name: endpoint.host(),
                    leg: TicketCacheLeg::Origin,
                    protocol: Ok(TicketCacheProtocol::Http3),
                    route,
                },
            )
            .map_err(RequestError::session_tickets)?;
        // Fix destination metadata after cold installation, before any
        // ClientHello or ticket retry. `open` bounds the whole setup budget.
        #[cfg(feature = "https-records")]
        let destination = self.destination_plan(connector, route, transport).await?;
        let early_origin = early_origin.as_ref().filter(|_| early_data);
        let http3_proxy = match route {
            Route::ConnectUdp(proxy) if proxy.tcp_protocol().is_none() => {
                let base = connect_udp_http3(connect_udp_proxy)?;
                Some(base)
            }
            _ => None,
        };
        let presented_ticket = origin.has_ticket_for(endpoint.host());
        // Boxed apart from `open`, which nests this future in its attempt
        // limit: together the two carry the compiler's `Send` proof past the
        // default recursion limit; see `box_send`.
        let first = super::box_send(self.connect_with(
            early_origin.unwrap_or(origin),
            http3_proxy,
            endpoint,
            route,
            transport,
            connect_udp_proxy,
            #[cfg(feature = "https-records")]
            destination.as_ref(),
        ))
        .await;
        match first {
            Err(failure) if presented_ticket && failure.is_origin_handshake() => {
                debug!(
                    outcome = "full_handshake_retry",
                    "HTTP/3 handshake that presented a session ticket failed"
                );
                let origin = origin.without_ticket_offers();
                super::box_send(self.connect_with(
                    &origin,
                    http3_proxy,
                    endpoint,
                    route,
                    transport,
                    connect_udp_proxy,
                    #[cfg(feature = "https-records")]
                    destination.as_ref(),
                ))
                .await
                .map_err(SetupFailure::into_request_error)
            }
            result => result.map_err(SetupFailure::into_request_error),
        }
    }

    #[cfg(feature = "https-records")]
    async fn destination_plan(
        &self,
        connector: &Http3Connector,
        route: &Route,
        transport: Http3TransportTarget<'_>,
    ) -> Result<Option<super::alt_svc::https_policy::DestinationPlan>, RequestError> {
        use super::alt_svc::https_policy::DestinationError;
        let Some(limit) = transport.destination_lookup_timeout(route, self.alt_svc_https_policy)
        else {
            return Ok(None);
        };
        let discovery = self
            .https_records
            .as_ref()
            .filter(|_| connector.ech_from_https_records())
            .ok_or_else(|| RequestError::alt_svc_https(DestinationError::DiscoveryUnavailable))?;
        // Starting the shared lookup on the first poll keeps timer setup
        // failure from starting work that cannot be awaited within its limit.
        let plan = within(limit, async {
            discovery
                .destination_plan(transport.host, transport.port)
                .await
        })
        .await
        .map_err(RequestError::alt_svc_https)?
        .ok_or_else(|| {
            RequestError::alt_svc_https(RequestError::timeout(
                TimeoutPhase::Connect,
                Some(HttpProtocol::Http3),
            ))
        })?
        .map_err(RequestError::alt_svc_https)?;
        Ok(Some(plan))
    }

    /// Builds one datagram route, retaining logical-origin authentication.
    #[allow(clippy::too_many_arguments)]
    async fn connect_with(
        &self,
        connector: &Http3Connector,
        http3_proxy: Option<&Http3Connector>,
        endpoint: &Endpoint,
        route: &Route,
        transport: Http3TransportTarget<'_>,
        connect_udp_proxy: Option<&ConnectUdpConnectors>,
        #[cfg(feature = "https-records")] destination: Option<
            &super::alt_svc::https_policy::DestinationPlan,
        >,
    ) -> Result<Http3Connection, SetupFailure> {
        use phantom_net::route::{
            ConnectUdpRoute, ConnectUdpTransport, DatagramRoute, Endpoint as DialEndpoint,
            Socks5Target,
        };
        let dial = DialEndpoint {
            host: transport.host,
            port: transport.port,
        };
        #[cfg(feature = "https-records")]
        let lookup = if destination.is_none()
            && matches!(route, Route::Direct)
            && connector.ech_from_https_records()
            && transport.port == endpoint.port()
            && transport.host.eq_ignore_ascii_case(endpoint.host())
        {
            self.https_records
                .as_ref()
                .map(|discovery| discovery.quic_ech(endpoint))
        } else {
            None
        };
        #[cfg(feature = "https-records")]
        let prepared = destination.map(|plan| plan.ech.clone());
        #[cfg(feature = "https-records")]
        let mut ech = pin!(if prepared.is_some() || lookup.is_some() {
            Some(async move {
                match prepared {
                    Some(ech) => ech,
                    None => match lookup {
                        Some(lookup) => lookup.await,
                        None => None,
                    },
                }
            })
        } else {
            None
        });
        let mut prepared_outer = None;
        let mut shared_tcp = None;
        let datagrams = match route {
            Route::Direct => {
                #[cfg(feature = "https-records")]
                let direct = match ech.as_mut().as_pin_mut() {
                    Some(lookup) => DatagramRoute::DirectEch {
                        endpoint: dial,
                        lookup,
                    },
                    None => DatagramRoute::Direct(dial),
                };
                #[cfg(not(feature = "https-records"))]
                let direct = DatagramRoute::Direct(dial);
                direct
            }
            Route::Socks5(proxy) => DatagramRoute::Socks5 {
                proxy: DialEndpoint {
                    host: proxy.host(),
                    port: proxy.port(),
                },
                target: match proxy.dns_mode() {
                    Socks5DnsMode::Local => Socks5Target::LocalDns(dial),
                    Socks5DnsMode::Remote => Socks5Target::RemoteDns(dial),
                },
                auth: proxy.auth(),
            },
            // Route clones share outer sessions through their isolated pool.
            Route::ConnectUdp(proxy) => {
                let outer = match proxy.tcp_protocol() {
                    None => {
                        let base = http3_proxy.ok_or_else(|| {
                            SetupFailure::Other(RequestError::unsupported_route(
                                HttpProtocol::Http3,
                            ))
                        })?;
                        prepared_outer = Some(
                            connector
                                .prepare_connect_udp_outer(
                                    base,
                                    proxy.pool(),
                                    proxy.host(),
                                    proxy.port(),
                                    proxy.authority(),
                                    proxy.headers(),
                                    proxy.credentials(),
                                )
                                .map_err(|error| {
                                    SetupFailure::Other(
                                        RequestError::http3_connect_udp_preparation(error),
                                    )
                                })?,
                        );
                        ConnectUdpTransport::Http3(base)
                    }
                    Some(protocol) => {
                        let base =
                            connect_udp_tcp(connect_udp_proxy).map_err(SetupFailure::Other)?;
                        // H2 shares the route-owned cache. H1 Upgrade keeps its
                        // dedicated origin-and-route-scoped cache.
                        let connector = if protocol == phantom_net::proxy::HttpsProxyProtocol::Http1
                        {
                            self.tcp_proxy
                                .get_or_init(|| base.with_isolated_session_cache())
                        } else {
                            // The client base also serves H1 proxies. Select the
                            // route's H2 policy before preparing its shared cache.
                            let shared: &HttpsProxyConnector =
                                shared_tcp.insert(base.clone().with_protocol(protocol));
                            prepared_outer = Some(
                                shared
                                    .prepare_connect_udp_outer(
                                        proxy.pool(),
                                        proxy.host(),
                                        proxy.port(),
                                        proxy.authority(),
                                        proxy.headers(),
                                        proxy.credentials(),
                                    )
                                    .map_err(|error| {
                                        SetupFailure::Other(
                                            RequestError::http3_connect_udp_preparation(error),
                                        )
                                    })?,
                            );
                            shared
                        };
                        if protocol == phantom_net::proxy::HttpsProxyProtocol::Http1 {
                            self.tickets
                                .register_before_use(
                                    connector.session_ticket_cache(),
                                    TicketCacheBinding {
                                        origin: endpoint,
                                        server_name: proxy.host(),
                                        leg: TicketCacheLeg::ConnectUdp,
                                        protocol: TicketCacheBinding::proxy_protocol(protocol),
                                        route,
                                    },
                                )
                                .map_err(|error| {
                                    SetupFailure::Other(RequestError::session_tickets(error))
                                })?;
                        }
                        ConnectUdpTransport::Tls {
                            connector,
                            protocol,
                        }
                    }
                };
                if let Some(prepared) = &prepared_outer {
                    // Preparation releases both net pool locks before registration.
                    // The token pins this exact cache through the awaited TLS setup.
                    let proxy_endpoint = Endpoint::new(
                        proxy.authority().parse().map_err(|_| {
                            SetupFailure::Other(RequestError::invalid_authority(
                                "invalid CONNECT-UDP proxy authority",
                            ))
                        })?,
                        proxy.port(),
                    )
                    .map_err(|error| {
                        SetupFailure::Other(RequestError::invalid_authority(error.message()))
                    })?;
                    self.tickets
                        .register_shared_outer_before_use(
                            prepared.session_ticket_cache(),
                            TicketCacheBinding {
                                origin: &proxy_endpoint,
                                server_name: proxy.host(),
                                leg: TicketCacheLeg::ConnectUdp,
                                protocol: match proxy.tcp_protocol() {
                                    Some(protocol) => TicketCacheBinding::proxy_protocol(protocol),
                                    None => Ok(TicketCacheProtocol::Http3),
                                },
                                route,
                            },
                        )
                        .map_err(|error| {
                            SetupFailure::Other(RequestError::session_tickets(error))
                        })?;
                }
                DatagramRoute::ConnectUdp(ConnectUdpRoute {
                    proxy: DialEndpoint {
                        host: proxy.host(),
                        port: proxy.port(),
                    },
                    transport: outer,
                    authority: proxy.authority(),
                    path: connect_udp_path(proxy, transport).map_err(SetupFailure::Other)?,
                    headers: proxy.headers().to_vec(),
                    credentials: proxy.credentials(),
                    pool: Some(proxy.pool()),
                    prepared_outer: prepared_outer.as_ref(),
                })
            }
            Route::HttpProxy(_) | Route::Socks4(_) => {
                return Err(SetupFailure::Other(RequestError::unsupported_route(
                    HttpProtocol::Http3,
                )));
            }
        };
        // End the connector's nested I/O `Send` proof before pool setup adds
        // its attempt-limit and ticket-retry futures; see `box_send`.
        super::box_send(connector.connect(datagrams, endpoint.host()))
            .await
            .map_err(|error| {
                if matches!(route, Route::ConnectUdp(_)) {
                    SetupFailure::ConnectUdp(error)
                } else {
                    SetupFailure::Origin(error)
                }
            })
    }

    fn invalidate(&self, token: &Arc<()>) {
        let mut slots = self.lock_slots();
        if let Some(position) = slots
            .connections
            .iter()
            .position(|slot| Arc::ptr_eq(&slot.token, token))
        {
            slots.connections.remove(position);
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
    /// Returns whether the inner origin TLS handshake failed.
    fn is_origin_handshake(&self) -> bool {
        let error = match self {
            Self::Origin(error) | Self::ConnectUdp(error) => error,
            Self::Other(_) => return false,
        };
        // A rejected Encrypted Client Hello is not a ticket problem, and
        // Chrome 154 does not repeat a QUIC connection after it.
        if error.ech_failure().is_some() {
            return false;
        }
        matches!(error.kind(), Http3ConnectorErrorKind::Handshake)
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
        let (lease, stream) =
            acquire_with_retries(HttpProtocol::Http3, timeout_budget, retries, || async {
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
        // Acquisition has released every pool lock. Registration holds only the
        // mapping's entries lock across net's synchronous checked-state update.
        if let Some(validation) = transport.validation {
            validation.register(connector, &lease.connection);
        }
        Ok(Http3Lease {
            entry,
            lease,
            stream,
            permit,
        })
    }
}

/// A pooled H3 connection admitted for one request and not yet dispatched.
pub(crate) struct Http3Lease {
    entry: Arc<PoolEntry>,
    lease: ConnectionLease,
    /// Counts the request's stream against the connection until the
    /// response ends; it drops before the permit.
    stream: OpenStream,
    permit: AdmissionPermit,
}

impl Http3Lease {
    /// Returns the leased connection.
    pub(crate) fn connection(&self) -> &Http3Connection {
        &self.lease.connection
    }

    /// Admits another request to a connection whose rejected early data
    /// carried the previous one, within the pool-admission phase.
    async fn readmit(
        entry: Arc<PoolEntry>,
        lease: ConnectionLease,
        timeout_budget: TimeoutBudget,
    ) -> Result<Self, RequestError> {
        let permit = timeout_budget
            .run(
                TimeoutPhase::PoolAdmission,
                Some(HttpProtocol::Http3),
                entry.admit(),
            )
            .await?;
        Ok(Self {
            stream: lease.streams.open(),
            entry,
            lease,
            permit,
        })
    }

    /// Waits, within the connect phase, until the server answers the leased
    /// connection's early data.
    ///
    /// A connection that sent none is ready at once. One whose early data was
    /// accepted, or rejected and then restarted on the same connection, is
    /// ready once the answer settles. A failed handshake or invalid handshake
    /// metadata invalidates the pooled connection and is a request error. A
    /// connect timeout leaves the connection pooled for the requests still
    /// waiting on it. Dropping the lease releases its admission.
    async fn wait_for_early_data(
        self,
        connector: &Http3Connector,
        timeout_budget: TimeoutBudget,
    ) -> Result<Self, RequestError> {
        if !self.lease.connection.sent_early_data() {
            return Ok(self);
        }
        let settled = timeout_budget
            .run(TimeoutPhase::Connect, Some(HttpProtocol::Http3), async {
                Ok(connector
                    .early_data_settled_on(&self.lease.connection)
                    .await)
            })
            .await?;
        match settled {
            Ok(()) => Ok(self),
            Err(error) => {
                self.entry.invalidate(&self.lease.token);
                Err(RequestError::http3_early_data_setup(error))
            }
        }
    }
}

#[cfg(feature = "websocket")]
impl Http3Lease {
    /// Opens one RFC 9220 extended CONNECT stream for `protocol` on the
    /// leased connection.
    ///
    /// The request waits until the server has answered the connection's
    /// early data, so it never goes out as early data, and it is sent only
    /// after the peer's SETTINGS enable extended CONNECT. An accepted stream
    /// keeps the lease's stream count and admission permit until it
    /// completes or is dropped; a rejecting response's body keeps them until
    /// it is read or dropped. A stream failure retires the connection when it
    /// can no longer be reused, as an ordinary request's does. Nothing is
    /// replayed.
    pub(crate) async fn send_extended_connect(
        self,
        connector: &Http3Connector,
        protocol: Http3ExtendedProtocol,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        timeout_budget: TimeoutBudget,
    ) -> Result<Http3ExtendedConnect, RequestError> {
        let Self {
            entry,
            lease,
            stream,
            permit,
        } = self.wait_for_early_data(connector, timeout_budget).await?;
        let mut diagnostic_head = phantom_net::request_diagnostics::PhaseObservation::begin(
            crate::RequestTimingPhase::SendResponseHead,
            Some(HttpProtocol::Http3.version()),
        );
        let result = timeout_budget
            .run(
                TimeoutPhase::ResponseHead,
                Some(HttpProtocol::Http3),
                async {
                    Ok::<_, RequestError>(
                        connector
                            .send_extended_connect_on(
                                &lease.connection,
                                protocol,
                                authority,
                                target,
                                headers,
                            )
                            .await,
                    )
                },
            )
            .await;
        diagnostic_head.nested_result(&result);
        match result {
            Ok(Ok(Http3ExtendedConnectOutcome::Accepted {
                response,
                stream: mut tunnel,
            })) => {
                if let Some(publication) = &lease.publication {
                    publication.record(lease.connection.completed_handshake_rtt());
                }
                // The stream count drops first, so the request the permit
                // admits next sees this stream ended.
                tunnel.retain_until_stream_complete((stream, permit));
                Ok(Http3ExtendedConnect::Accepted {
                    response: Box::new(response),
                    stream: tunnel,
                })
            }
            Ok(Ok(Http3ExtendedConnectOutcome::Rejected(response))) => {
                if let Some(publication) = &lease.publication {
                    publication.record(lease.connection.completed_handshake_rtt());
                }
                let (parts, body) = response.into_parts();
                Ok(Http3ExtendedConnect::Rejected(Box::new(
                    http::Response::from_parts(
                        parts,
                        ResponseBody::http3_with_guard(body, (stream, permit)),
                    ),
                )))
            }
            Ok(Err(error)) => {
                drop(stream);
                drop(permit);
                if !connector.can_reuse_now(&lease.connection) {
                    entry.invalidate(&lease.token);
                }
                Err(RequestError::http3_stream(error))
            }
            Err(error) => {
                drop(stream);
                drop(permit);
                Err(error)
            }
            Ok(Ok(_)) => {
                drop(stream);
                drop(permit);
                entry.invalidate(&lease.token);
                Err(RequestError::unsupported_transport_outcome())
            }
        }
    }
}

/// The answer to an extended CONNECT from [`Http3Lease::send_extended_connect`].
#[cfg(feature = "websocket")]
pub(crate) enum Http3ExtendedConnect {
    /// A 2xx response head and the stream it opened.
    Accepted {
        response: Box<http::Response<()>>,
        stream: Http3ExtendedConnectStream,
    },
    /// Any other final response, with its body.
    Rejected(Box<http::Response<ResponseBody>>),
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

/// One request's HTTP/3 field list, which [`validate_request`] checked, with
/// its client hints.
#[derive(Clone)]
pub(crate) struct Http3Fields(Vec<RequestHeader>);

/// A response and the fields its request carried.
pub(crate) type Http3Response = (http::Response<ResponseBody>, Vec<RequestHeader>);

/// Checks one request's H3 and route representation before any I/O and
/// returns its field list, with its client hints placed, for
/// [`Http3Pool::send_request`] or [`Http3Pool::send_request_on_lease`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_request(
    connector: &Http3Connector,
    connect_udp_proxy: Option<&ConnectUdpConnectors>,
    route: &Route,
    transport: Http3TransportTarget<'_>,
    method: &Method,
    authority: &str,
    target: &OriginForm,
    headers: Vec<RequestHeader>,
    trailers: &[RequestHeader],
    client_hints: Option<ClientHintContext<'_>>,
    body: Option<&RequestBody>,
) -> Result<Http3Fields, RequestError> {
    let headers = match client_hints {
        Some(context) => context.prepare(headers)?,
        None => headers,
    };
    validate_wire(
        connector, method, authority, target, &headers, trailers, body,
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
    Ok(Http3Fields(headers))
}

#[allow(clippy::too_many_arguments)]
fn validate_wire(
    connector: &Http3Connector,
    method: &Method,
    authority: &str,
    target: &OriginForm,
    headers: &[RequestHeader],
    trailers: &[RequestHeader],
    body: Option<&RequestBody>,
) -> Result<(), RequestError> {
    connector
        .validate_request_body_source_with_trailers(
            method.clone(),
            authority,
            target,
            headers,
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
) -> Result<Dispatched<Http3Response>, RequestError> {
    retries.admit_http_attempt(Some(HttpProtocol::Http3))?;
    let Http3Lease {
        entry,
        lease,
        stream,
        permit,
    } = leased;
    // Nothing is written on a connection whose ACCEPT_CH asks for a hint the
    // request lacks; the request restarts with it. A connection whose early
    // data is unanswered knows no ACCEPT_CH yet.
    if let Some(hints) = client_hints.and_then(|context| {
        context.connection_restart(
            &headers,
            lease.connection.accept_ch_for_origin(context.origin()),
        )
    }) {
        drop((stream, permit));
        return Ok(Dispatched::Restart(AcceptChRestart { hints, body }));
    }
    let sent_headers = headers;
    let mut diagnostic_head = phantom_net::request_diagnostics::PhaseObservation::begin(
        crate::RequestTimingPhase::SendResponseHead,
        Some(HttpProtocol::Http3.version()),
    );
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
    diagnostic_head.nested_result(&result);
    match result {
        Ok(Ok(response)) => {
            // Early setup publishes conservatively at its first successful
            // response, after its handshake and metadata checks have settled.
            if let Some(publication) = &lease.publication {
                publication.record(lease.connection.completed_handshake_rtt());
            }
            let (parts, body) = response.into_parts();
            Ok(Dispatched::Sent((
                // The stream count drops first, so the request the permit
                // admits next sees this stream ended.
                http::Response::from_parts(
                    parts,
                    ResponseBody::http3_with_guard(body, (stream, permit)),
                ),
                sent_headers,
            )))
        }
        Ok(Err(error)) => {
            drop(stream);
            drop(permit);
            let error = RequestError::http3_stream(error);
            // An unprocessed replay must use another connection, so one
            // that rejected a request is retired when it is enabled. Rejected
            // early data is the exception: the pool sends it again on the
            // same connection, which started HTTP/3 again.
            if !connector.can_reuse_now(&lease.connection)
                || (retries.replays_unprocessed_requests()
                    && error.is_unprocessed_request()
                    && !error.is_http3_early_data_rejected())
            {
                entry.invalidate(&lease.token);
            }
            Err(error)
        }
        Err(error) => {
            drop(stream);
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
    phantom_net::request::is_replay_safe(method, body.is_some(), !trailers.is_empty())
}

/// Expands the CONNECT-UDP path for the transport target before I/O.
fn connect_udp_path(
    proxy: &ConnectUdpProxy,
    transport: Http3TransportTarget<'_>,
) -> Result<OriginForm, RequestError> {
    proxy
        .expand(transport.host, transport.port)
        .map_err(RequestError::invalid_connect_udp_target)
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

/// One pool entry's connections, least recently used first, and how
/// streams spread across those of one location.
struct Slots {
    connections: VecDeque<ConnectionSlot>,
    spread: Http3Spread,
}

struct ConnectionSlot {
    connection: Http3Connection,
    publication: Option<Arc<Publication>>,
    token: Arc<()>,
    location: TransportLocation,
    streams: StreamCount,
    /// The server's stream limit, read once the handshake completed.
    peer_limit: Option<u64>,
}

impl ConnectionSlot {
    /// Leases the connection for one stream, counted until the returned
    /// guard drops.
    fn lease(&self) -> (ConnectionLease, OpenStream) {
        (
            ConnectionLease {
                connection: self.connection.clone(),
                publication: self.publication.clone(),
                token: Arc::clone(&self.token),
                streams: self.streams.clone(),
            },
            self.streams.open(),
        )
    }

    /// Reads the server's stream limit once the handshake has completed.
    fn read_peer_limit(&mut self) {
        if self.peer_limit.is_none() {
            self.peer_limit = self.connection.peer_initial_max_streams_bidi();
        }
    }

    fn candidate(&self) -> Candidate {
        Candidate {
            peer_limit: self.peer_limit,
            streams: self.streams.get(),
        }
    }
}

#[derive(Clone)]
struct ConnectionLease {
    connection: Http3Connection,
    publication: Option<Arc<Publication>>,
    token: Arc<()>,
    streams: StreamCount,
}

#[cfg(test)]
mod tests;
