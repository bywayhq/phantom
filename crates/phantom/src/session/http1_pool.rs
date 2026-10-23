use std::{
    collections::VecDeque,
    future::poll_fn,
    num::NonZeroUsize,
    pin::Pin,
    sync::{Arc, MutexGuard, OnceLock, PoisonError, Weak},
    time::Duration,
};

use http::{
    HeaderMap, Method,
    header::{CONNECTION, HeaderName},
};
use http_body::Body as _;
use phantom_net::proxy::{HttpsProxyConnector, MAX_CHALLENGE_BODY_BYTES};
use phantom_net::request::RequestBody;
use phantom_net::route::{
    DirectTlsSetup, Http1Route, HttpConnectRoute, OriginRoute, ProxyTransport, Socks5Target,
    TcpRoute,
};
use phantom_net::tcp::{AddressFamilyMemory, SlowerConnection, SlowerProgress};
use phantom_net::{
    http1::{
        Http1Body, Http1Connection, Http1ProxyOpening, Http1TlsConnector, Http1TlsError,
        validate_forward_request_body_source_with_trailers,
        validate_request_body_source_with_trailers,
    },
    request::{AbsoluteForm, OriginForm, RequestHeader},
};
use tokio::{
    sync::{Mutex, oneshot},
    task::AbortHandle,
    time::Instant,
};
use tracing::debug;

use super::address_families::AddressFamilies;
use super::admission::{Admission, AdmissionPermit, AdmissionRegistry};
use super::alt_svc::OriginEchConfigured;
use super::prune_timer::{PruneTimer, Pruned, PrunedEntry};
use super::tickets::{
    TicketCacheBinding,
    binding::{TicketCacheLeg, TicketCacheProtocol},
};
use crate::timeout::{TimeoutBudget, TimeoutPhase};
use crate::{
    HttpProtocol, RequestError, ResponseBody, Route,
    authority::Endpoint,
    retry::{ConnectionSetupRetryState, acquire_with_retries},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Http1ConnectionMode {
    TlsOrigin,
    PlaintextOrigin,
    Forward,
}

/// Exact HTTP/1.1 connections, grouped by origin and route.
///
/// Each pool key keeps up to `max_active` connections, idle ones included.
/// A request first passes the key's admission, which lets at most
/// `max_active` requests through and queues the rest in arrival order. It
/// then takes the most recently used idle connection, claims the slower
/// connection of a backup connection that has not finished its setup, or
/// opens one. An idle connection past `used_idle_timeout` is closed instead,
/// and the client's prune timer, when it has one, closes it between
/// requests.
pub(crate) struct Http1Pool {
    tickets: Arc<super::tickets::TicketOwner>,
    capacity: NonZeroUsize,
    max_active: NonZeroUsize,
    max_pending: NonZeroUsize,
    used_idle_timeout: Option<Duration>,
    prune_timer: Option<Arc<PruneTimer>>,
    state: Mutex<PoolState>,
    retired: Arc<super::retired_connections::RetiredConnections>,
    #[cfg(feature = "https-records")]
    https_records: Option<super::alt_svc::HttpsRecordDiscovery>,
}

impl Http1Pool {
    pub(super) async fn refresh_connections(&self) {
        let mut previous = Vec::new();
        {
            let mut state = self.state.lock().await;
            for (_, entry) in &mut state.entries {
                let fresh = Arc::new(entry.fresh());
                entry.connections.begin_retirement(&self.retired);
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
                let mut set = entry.connections.lock();
                let mut index = 0;
                while index < set.idle.len() {
                    let connection = &set.idle[index].connection;
                    if connection.is_exclusively_owned() && !connection.early_data_pending() {
                        retired_connections.push(set.idle.remove(index));
                    } else {
                        index += 1;
                    }
                }
                let mut index = 0;
                while index < set.spares.len() {
                    let spare = &set.spares[index];
                    if spare.ready.is_some() && spare.task.is_none() && !spare.is_claimed() {
                        retired_spares.push(set.spares.remove(index));
                    } else {
                        index += 1;
                    }
                }
            }
        }
        // Opening destructors may report back to these entries.
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
            used_idle_timeout: None,
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

    /// Closes an idle connection instead of reusing it once it has been idle
    /// `timeout` or longer; `None` reuses it until the server closes it.
    pub(super) const fn with_used_idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.used_idle_timeout = timeout;
        self
    }

    /// Lets the client's prune timer close idle connections between
    /// requests and forget an origin's address family once none of its keys
    /// has a connection.
    pub(super) fn with_prune_timer(mut self, timer: Option<Arc<PruneTimer>>) -> Self {
        self.prune_timer = timer;
        self
    }

    #[cfg(test)]
    pub(super) const fn used_idle_timeout(&self) -> Option<Duration> {
        self.used_idle_timeout
    }

    #[cfg(test)]
    pub(super) const fn prune_timer(&self) -> Option<&Arc<PruneTimer>> {
        self.prune_timer.as_ref()
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
        connector: &Http1TlsConnector,
        https_proxy: Option<&HttpsProxyConnector>,
        endpoint: &Endpoint,
        route: &Route,
        mode: Http1ConnectionMode,
        method: Method,
        target: OriginForm,
        absolute_target: AbsoluteForm,
        headers: Vec<RequestHeader>,
        trailers: Vec<RequestHeader>,
        body: Option<RequestBody>,
        forward_authorization: bool,
        fresh_connection: bool,
        mut challenged: Option<&mut ChallengedConnection>,
        timeout_budget: TimeoutBudget,
        retries: &mut ConnectionSetupRetryState,
    ) -> Result<http::Response<ResponseBody>, RequestError> {
        let validation: Result<(), phantom_net::http1::Http1Error> = (|| {
            if mode != Http1ConnectionMode::Forward {
                return validate_request_body_source_with_trailers(
                    &method,
                    &target,
                    &headers,
                    body.as_ref(),
                    &trailers,
                );
            }
            validate_forward_request_body_source_with_trailers(
                &method,
                &absolute_target,
                &headers,
                body.as_ref(),
                &trailers,
            )?;
            // An anonymous attempt may be replayed with the route's
            // credentials after a challenge; that request is checked now,
            // before any proxy I/O. The field's position does not change
            // the outcome.
            if !forward_authorization
                && let Some(phantom_net::proxy::HttpProxyCredentials::Basic(credentials)) = route
                    .as_http_proxy()
                    .and_then(crate::HttpProxy::credentials)
            {
                let mut candidate = headers.clone();
                candidate.push(credentials.proxy_authorization_header());
                validate_forward_request_body_source_with_trailers(
                    &method,
                    &absolute_target,
                    &candidate,
                    body.as_ref(),
                    &trailers,
                )?;
            }
            Ok(())
        })();
        validation
            .map_err(Http1TlsError::from)
            .map_err(RequestError::http1)?;
        if route.as_http_proxy().is_some_and(|proxy| proxy.uses_tls()) && https_proxy.is_none() {
            return Err(RequestError::unsupported_route(HttpProtocol::Http1));
        }
        retries.admit_http_attempt(Some(HttpProtocol::Http1))?;
        let held = challenged
            .as_mut()
            .and_then(|slot| slot.held.take())
            .filter(|_| !fresh_connection);
        let (mut lease, permit) = if let Some(held) = held {
            debug!(
                outcome = "authentication_retry",
                "HTTP/1 challenged proxy connection reused"
            );
            (held.lease, held.permit)
        } else {
            let key = PoolKey::new(endpoint, route, mode);
            let entry = self.entry(key).await;
            let permit = timeout_budget
                .run(
                    TimeoutPhase::PoolAdmission,
                    Some(HttpProtocol::Http1),
                    entry.admit(),
                )
                .await?;
            let lease =
                acquire_with_retries(HttpProtocol::Http1, timeout_budget, retries, || async {
                    entry
                        .acquire(
                            connector,
                            https_proxy,
                            endpoint,
                            route,
                            mode,
                            fresh_connection,
                        )
                        .await
                })
                .await?;
            (lease, permit)
        };
        if phantom_net::request::is_replay_safe(&method, body.is_some(), !trailers.is_empty()) {
            lease
                .connection
                .register_early_data_attempt_optional(retries.attempt_budget());
        }
        let mut diagnostic_head = phantom_net::request_diagnostics::PhaseObservation::begin(
            crate::RequestTimingPhase::SendResponseHead,
            Some(HttpProtocol::Http1.version()),
        );
        let result = timeout_budget
            .run(
                TimeoutPhase::ResponseHead,
                Some(HttpProtocol::Http1),
                async {
                    Ok(if mode == Http1ConnectionMode::Forward {
                        lease
                            .connection
                            .send_forward_request_body_with_trailers(
                                method,
                                absolute_target,
                                headers,
                                body,
                                trailers,
                            )
                            .await
                    } else {
                        lease
                            .connection
                            .send_request_body_with_trailers(
                                method, target, headers, body, trailers,
                            )
                            .await
                    })
                },
            )
            .await;
        diagnostic_head.nested_result(&result);
        match result {
            Ok(Ok(response)) => {
                if mode == Http1ConnectionMode::Forward
                    && route
                        .as_http_proxy()
                        .and_then(crate::HttpProxy::credentials)
                        .is_some()
                    && response.status() == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
                {
                    let (parts, mut body) = response.into_parts();
                    if let Some(slot) = challenged.filter(|slot| {
                        !slot.replayed
                            || matches!(
                                route
                                    .as_http_proxy()
                                    .and_then(crate::HttpProxy::credentials),
                                Some(phantom_net::proxy::HttpProxyCredentials::Digest(_))
                            )
                    }) {
                        // The drain belongs to the response-head phase, and
                        // each body frame to the read-idle timeout. Without
                        // configured timeouts only the size bounds it.
                        let drained = timeout_budget
                            .run(
                                TimeoutPhase::ResponseHead,
                                Some(HttpProtocol::Http1),
                                drain_challenge(&mut body, timeout_budget.read_idle()),
                            )
                            .await;
                        let drained = match drained {
                            Ok(drained) => drained,
                            Err(error) => {
                                lease.retire();
                                return Err(error);
                            }
                        };
                        if drained
                            && !has_close_token(&parts.headers)
                            && connection_is_idle(&lease.connection).await
                        {
                            // The replay takes this connection and admission, so
                            // no other request can use the connection in between.
                            slot.held = Some(HeldConnection { lease, permit });
                            return Ok(http::Response::from_parts(
                                parts,
                                ResponseBody::http1(body),
                            ));
                        }
                    }
                    // A zero-length 407 may already have released its transport
                    // lease as reusable. Retire the generation before exposing
                    // the response so an authentication retry must reconnect.
                    lease.retire();
                    return Ok(http::Response::from_parts(
                        parts,
                        ResponseBody::http1_with_guard(
                            body,
                            RequestGuard {
                                _lease: lease,
                                _permit: permit,
                            },
                        ),
                    ));
                }
                let (mut parts, body) = response.into_parts();
                parts.extensions.insert(OriginEchConfigured(
                    lease.connection.origin_ech_configured(),
                ));
                Ok(http::Response::from_parts(
                    parts,
                    ResponseBody::http1_with_guard(
                        body,
                        RequestGuard {
                            _lease: lease,
                            _permit: permit,
                        },
                    ),
                ))
            }
            Ok(Err(error)) => {
                // A handshake that failed after early data reports what a
                // fresh connection's handshake would.
                let early_data_failure = lease.connection.early_data_failure();
                // The lease drops before the permit, so the next admitted
                // request finds a reusable connection idle.
                drop(lease);
                drop(permit);
                Err(match early_data_failure {
                    Some(failure) => RequestError::http1_connection_setup(failure),
                    None => RequestError::http1(error.into()),
                })
            }
            Err(error) => {
                lease.retire();
                drop(lease);
                drop(permit);
                Err(error)
            }
        }
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
        base: &Http1TlsConnector,
        endpoint: &Endpoint,
        route: &Route,
    ) -> Result<Http1TlsConnector, RequestError> {
        let entry = self
            .entry(PoolKey::new(
                endpoint,
                route,
                Http1ConnectionMode::TlsOrigin,
            ))
            .await;
        entry.origin_connector(base, endpoint, route)
    }

    /// Holds a direct WebSocket opening in its request entry until transport handoff.
    #[cfg(feature = "websocket")]
    pub(crate) async fn origin_opening(
        &self,
        endpoint: &Endpoint,
        plaintext: bool,
    ) -> OriginOpening {
        let mode = if plaintext {
            Http1ConnectionMode::PlaintextOrigin
        } else {
            Http1ConnectionMode::TlsOrigin
        };
        let entry = self
            .entry(PoolKey::new(endpoint, &Route::Direct, mode))
            .await;
        {
            let mut state = entry.connections.lock();
            entry.connections.family.mark_active();
            state.openings += 1;
        }
        OriginOpening { entry }
    }

    #[cfg(feature = "websocket")]
    pub(crate) async fn proxy_upgrade_opening(
        &self,
        endpoint: &Endpoint,
        route: &Route,
    ) -> OriginOpening {
        let entry = self
            .entry(PoolKey::new(
                endpoint,
                route,
                Http1ConnectionMode::TlsOrigin,
            ))
            .await;
        {
            let mut state = entry.connections.lock();
            entry.connections.family.mark_active();
            state.openings += 1;
        }
        OriginOpening { entry }
    }

    #[cfg(feature = "websocket")]
    pub(crate) async fn socks_upgrade_opening(
        &self,
        endpoint: &Endpoint,
        route: &Route,
        plaintext: bool,
    ) -> OriginOpening {
        let mode = if plaintext {
            Http1ConnectionMode::PlaintextOrigin
        } else {
            Http1ConnectionMode::TlsOrigin
        };
        let entry = self.entry(PoolKey::new(endpoint, route, mode)).await;
        {
            let mut state = entry.connections.lock();
            entry.connections.family.mark_active();
            state.openings += 1;
        }
        OriginOpening { entry }
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
            debug!(outcome = "evicted", "HTTP/1 pool entry evicted");
        }
        let admission = state
            .admissions
            .get(&key.origin(), self.max_active, self.max_pending);
        let family = state.families.get(&key.origin());
        #[cfg_attr(not(feature = "https-records"), allow(unused_mut))]
        let mut entry = PoolEntry::new(
            admission,
            EntryConnections::new(
                self.max_active,
                self.used_idle_timeout,
                self.prune_timer.clone(),
                family,
            ),
        );
        // HTTPS records are looked up on the direct route only: Chromium sends
        // no HTTPS query for a proxied request.
        #[cfg(feature = "https-records")]
        if key.route == Route::Direct {
            entry.https_records = self.https_records.clone();
        }
        entry.tickets = Arc::clone(&self.tickets);
        let entry = Arc::new(entry);
        state.entries.push_back((key, Arc::clone(&entry)));
        entry
    }
}

/// A forward-proxy connection kept after a `407`, for the credentialed replay
/// of the same request.
///
/// The connection keeps its admission permit while it waits, so the replay
/// neither queues again nor finds the connection taken by another request.
/// Dropping the slot returns a reusable connection to the idle list.
#[derive(Default)]
pub(crate) struct ChallengedConnection {
    held: Option<HeldConnection>,
    replayed: bool,
}

impl ChallengedConnection {
    /// Whether a challenged connection waits for the replay.
    pub(crate) const fn is_held(&self) -> bool {
        self.held.is_some()
    }

    /// Marks the next attempt as authenticated. Basic has one replay; Digest
    /// may retain this connection for its separately bounded stale retry.
    pub(crate) fn begin_replay(&mut self) {
        self.replayed = true;
    }
}

/// Fields drop in declaration order, so the connection returns to the idle
/// list before the admission permit lets the next request in.
struct HeldConnection {
    lease: ConnectionLease,
    permit: AdmissionPermit,
}

/// Reads a `407` body to its end, up to [`MAX_CHALLENGE_BODY_BYTES`], and
/// reports whether it ended.
///
/// A body that ends leaves its connection at the start of the next response,
/// as Chromium's `HttpNetworkTransaction::PrepareForAuthRestart` requires
/// before it reuses the connection for the replay. A frame that takes longer
/// than `read_idle` fails the request with a read-idle timeout.
async fn drain_challenge(
    body: &mut Http1Body,
    read_idle: Option<Duration>,
) -> Result<bool, RequestError> {
    let mut received = 0_usize;
    loop {
        let frame = poll_fn(|context| Pin::new(&mut *body).poll_frame(context));
        let frame = match read_idle {
            Some(read_idle) => {
                crate::timeout::within(read_idle, frame)
                    .await?
                    .ok_or_else(|| {
                        RequestError::timeout(TimeoutPhase::ReadIdle, Some(HttpProtocol::Http1))
                    })?
            }
            None => frame.await,
        };
        match frame {
            None => return Ok(true),
            Some(Err(_)) => return Ok(false),
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    received = received.saturating_add(data.len());
                    if received > MAX_CHALLENGE_BODY_BYTES {
                        return Ok(false);
                    }
                }
            }
        }
    }
}

/// Reports whether `connection` can carry the replay after its `407`.
///
/// The connection driver runs as its own task and closes the connection when
/// it reads the proxy's end of stream. Yielding once lets it act on an end of
/// stream that arrived with the `407`, the check Chromium makes with
/// `IsConnectedAndIdle` before it reuses the socket. A close that arrives
/// later fails the replay before any response byte, and the replay moves to
/// a new connection then.
async fn connection_is_idle(connection: &Http1Connection) -> bool {
    tokio::task::yield_now().await;
    connection.is_reusable()
}

/// Reports a `close` token in `Connection` or `Proxy-Connection`.
///
/// Both browsers close a connection whose response names `close` in either
/// field; the transport checks only `Connection`.
fn has_close_token(headers: &HeaderMap) -> bool {
    [CONNECTION, HeaderName::from_static("proxy-connection")]
        .iter()
        .flat_map(|name| headers.get_all(name))
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("close"))
}

/// An HTTP opening still owns a direct origin transport or rejection body.
#[cfg(feature = "websocket")]
pub(crate) struct OriginOpening {
    entry: Arc<PoolEntry>,
}

#[cfg(feature = "websocket")]
impl OriginOpening {
    pub(crate) fn family(&self) -> &Arc<AddressFamilyMemory> {
        &self.entry.connections.family
    }

    pub(crate) fn connector(
        &self,
        base: &Http1TlsConnector,
        endpoint: &Endpoint,
    ) -> Result<Http1TlsConnector, RequestError> {
        self.entry.origin_connector(base, endpoint, &Route::Direct)
    }

    pub(crate) fn adopt(&self, slower: SlowerConnection<phantom_net::http1::Http1Connection>) {
        self.entry.connections.adopt(slower);
    }

    pub(crate) fn proxy_origin_connector(
        &self,
        base: &Http1TlsConnector,
        endpoint: &Endpoint,
        route: &Route,
    ) -> Result<Http1TlsConnector, RequestError> {
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
            .ok_or_else(|| RequestError::unsupported_route(HttpProtocol::Http1))?;
        let connector = self
            .entry
            .https_proxy
            .get_or_init(|| proxy.https_connector(&base.with_isolated_session_cache()));
        let ticket_binding = TicketCacheBinding {
            origin: endpoint,
            server_name: proxy.host(),
            leg: TicketCacheLeg::HttpProxy,
            protocol: TicketCacheBinding::proxy_protocol(connector.protocol()),
            route,
        };
        let connector = self
            .entry
            .https_proxy
            .prepare(&self.entry.tickets, connector, ticket_binding)
            .map_err(RequestError::session_tickets)?;
        self.entry
            .tickets
            .register_before_use(connector.session_ticket_cache(), ticket_binding)
            .map_err(RequestError::session_tickets)?;
        Ok(connector.clone())
    }

    pub(crate) async fn open_proxy_upgrade(
        &self,
        connector: &Http1TlsConnector,
        route: HttpConnectRoute<'_>,
        protocols: &[Box<[u8]>],
        endpoint: &Endpoint,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<phantom_net::http1::Http1UpgradeOpening, RequestError> {
        let claim = match self.entry.connections.checkout(false) {
            Checkout::Proxy(claim) => Some(claim),
            Checkout::Spare(claim) => match claim.wait_delivery().await {
                Some(SpareDelivery::Proxy(claim)) => Some(claim),
                _ => None,
            },
            _ => None,
        };
        if let Some(mut claim) = claim
            && let Some(opening) = claim.opening.take()
        {
            // Taking the quiet socket commits this claim; later cancellation
            // closes it rather than returning a partial CONNECT to the pool.
            drop(claim);
            return opening
                .finish_upgrade(route, protocols, target, headers)
                .await
                .map_err(RequestError::http1_connection_setup);
        }
        let (opening, slower) = connector
            .open_http_connect_retaining(route, endpoint.host(), self.family())
            .await
            .map_err(RequestError::http1_connection_setup)?;
        if let Some(slower) = slower {
            self.entry.connections.adopt_proxy(slower);
        }
        opening
            .finish_upgrade(route, protocols, target, headers)
            .await
            .map_err(RequestError::http1_connection_setup)
    }
    pub(crate) async fn open_socks_upgrade(
        &self,
        connector: &Http1TlsConnector,
        origin: OriginRoute<'_>,
        protocols: &[Box<[u8]>],
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<phantom_net::http1::Http1UpgradeOpening, RequestError> {
        let claim = match self.entry.connections.checkout(false) {
            Checkout::Proxy(claim) => Some(claim),
            Checkout::Spare(claim) => match claim.wait_delivery().await {
                Some(SpareDelivery::Proxy(claim)) => Some(claim),
                _ => None,
            },
            _ => None,
        };
        if let Some(mut claim) = claim
            && let Some(opening) = claim.opening.take()
        {
            drop(claim);
            return opening
                .finish_socks_upgrade(protocols, target, headers)
                .await
                .map_err(RequestError::http1_connection_setup);
        }
        let (opening, slower) = connector
            .open_socks_retaining(origin, self.family())
            .await
            .map_err(RequestError::http1_connection_setup)?;
        if let Some(slower) = slower {
            self.entry.connections.adopt_socks(slower);
        }
        opening
            .finish_upgrade(protocols, target, headers)
            .await
            .map_err(RequestError::http1_connection_setup)
    }
}

#[cfg(feature = "websocket")]
impl Drop for OriginOpening {
    fn drop(&mut self) {
        {
            let mut state = self.entry.connections.lock();
            state.openings = state.openings.saturating_sub(1);
        }
        self.entry.connections.prune_empty_family();
    }
}

#[derive(Default)]
struct PoolState {
    entries: VecDeque<(PoolKey, Arc<PoolEntry>)>,
    admissions: AdmissionRegistry<PoolKey>,
    families: AddressFamilies<PoolKey>,
}

/// The client certificate depends only on host and port
/// ([`ClientBuilder::client_certificate_for`](crate::ClientBuilder::client_certificate_for)),
/// so the connections and TLS session tickets of one key share a certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
struct PoolKey {
    host: Box<str>,
    port: u16,
    route: Route,
    mode: Http1ConnectionMode,
    runtime: Option<tokio::runtime::Id>,
}

impl PoolKey {
    fn new(endpoint: &Endpoint, route: &Route, mode: Http1ConnectionMode) -> Self {
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
    tickets: Arc<super::tickets::TicketOwner>,
    connections: Arc<EntryConnections>,
    admission: Arc<Admission>,
    connector: Arc<super::tickets::TicketConnector<Http1TlsConnector>>,
    https_proxy: Arc<super::tickets::TicketConnector<HttpsProxyConnector>>,
    #[cfg(feature = "https-records")]
    https_records: Option<super::alt_svc::HttpsRecordDiscovery>,
}

impl PoolEntry {
    fn fresh(&self) -> Self {
        Self {
            tickets: Arc::clone(&self.tickets),
            connections: EntryConnections::new(
                self.connections.max,
                self.connections.used_idle_timeout,
                self.connections.prune.clone(),
                Arc::clone(&self.connections.family),
            ),
            admission: Arc::clone(&self.admission),
            connector: Arc::clone(&self.connector),
            https_proxy: Arc::clone(&self.https_proxy),
            #[cfg(feature = "https-records")]
            https_records: self.https_records.clone(),
        }
    }

    #[cfg(feature = "websocket")]
    fn origin_connector(
        &self,
        base: &Http1TlsConnector,
        endpoint: &Endpoint,
        route: &Route,
    ) -> Result<Http1TlsConnector, RequestError> {
        let connector = self
            .connector
            .get_or_init(|| base.with_isolated_session_cache());
        let ticket_binding = TicketCacheBinding {
            origin: endpoint,
            server_name: endpoint.host(),
            leg: TicketCacheLeg::Origin,
            protocol: Ok(TicketCacheProtocol::Http1),
            route,
        };
        let connector = self
            .connector
            .prepare(&self.tickets, connector, ticket_binding)
            .map_err(RequestError::session_tickets)?;
        self.tickets
            .register_before_use(connector.session_ticket_cache(), ticket_binding)
            .map_err(RequestError::session_tickets)?;
        Ok(connector.clone())
    }

    fn new(admission: Arc<Admission>, connections: Arc<EntryConnections>) -> Self {
        Self {
            tickets: Arc::default(),
            connections,
            admission,
            connector: Arc::default(),
            https_proxy: Arc::default(),
            #[cfg(feature = "https-records")]
            https_records: None,
        }
    }

    async fn admit(&self) -> Result<AdmissionPermit, RequestError> {
        Arc::clone(&self.admission).admit(HttpProtocol::Http1).await
    }

    /// Opens a direct TLS connection, offering the `ech` value of the
    /// origin's HTTPS record when the profile does, as Chrome 154 does.
    ///
    /// The slower attempt of a backup connection comes back for the key to
    /// keep, including when the handshake offers ECH.
    async fn connect_direct(
        &self,
        connector: &Http1TlsConnector,
        endpoint: &Endpoint,
    ) -> Result<Opened, Http1TlsError> {
        let tcp = || {
            TcpRoute::Direct(phantom_net::route::Endpoint {
                host: endpoint.host(),
                port: endpoint.port(),
            })
        };
        // Bound the connector's `Send` proof separately from pool setup;
        // see `box_send`.
        #[cfg(feature = "https-records")]
        if connector.ech_from_https_records()
            && let Some(discovery) = &self.https_records
        {
            let mut ech = std::pin::pin!(discovery.tcp_ech(endpoint, connector.alpn_protocols()));
            return super::box_send(connector.connect(Http1Route::Origin(OriginRoute::Tls {
                tcp: tcp(),
                server_name: endpoint.host(),
                setup: DirectTlsSetup::EchKeepingSlower {
                    lookup: ech.as_mut(),
                    family: &self.connections.family,
                },
            })))
            .await;
        }
        super::box_send(connector.connect(Http1Route::Origin(OriginRoute::Tls {
            tcp: tcp(),
            server_name: endpoint.host(),
            setup: DirectTlsSetup::KeepSlower(&self.connections.family),
        })))
        .await
    }

    async fn acquire(
        &self,
        connector: &Http1TlsConnector,
        https_proxy: Option<&HttpsProxyConnector>,
        endpoint: &Endpoint,
        route: &Route,
        mode: Http1ConnectionMode,
        force_new_connection: bool,
    ) -> Result<ConnectionLease, RequestError> {
        let reservation = loop {
            match self.connections.checkout(force_new_connection) {
                Checkout::Idle(lease) => {
                    debug!(
                        outcome = "hit",
                        "HTTP/1 connection acquired from client pool"
                    );
                    return Ok(lease);
                }
                Checkout::Spare(claim) => {
                    // A slower attempt that fails drops the claim, and the
                    // request chooses again.
                    if let Some(delivery) = claim.wait_delivery().await {
                        let lease = self.finish_spare(delivery, endpoint, route, mode).await?;
                        debug!(
                            outcome = "claimed",
                            "HTTP/1 slower backup connection acquired"
                        );
                        return Ok(lease);
                    }
                }
                Checkout::Proxy(claim) => {
                    // A claimed proxy still needs its purpose-specific setup.
                    return super::box_send(self.finish_proxy_claim(claim, endpoint, route, mode))
                        .await;
                }
                Checkout::Reserved(reservation) => break reservation,
            }
        };

        debug!(outcome = "connect", "HTTP/1 client pool opening connection");
        // Boxed: opening a connection awaits the largest connector futures,
        // which would otherwise enlarge the future of every request, including
        // one that reuses a pooled connection.
        let (connection, slower) =
            super::box_send(self.open(connector, https_proxy, endpoint, route, mode)).await?;
        if let Some(slower) = slower {
            self.connections.adopt(slower);
        }
        Ok(reservation.into_lease(connection))
    }

    async fn finish_proxy_opening(
        &self,
        opening: Http1ProxyOpening,
        slower: Option<SlowerConnection<Http1ProxyOpening>>,
        route: HttpConnectRoute<'_>,
    ) -> Result<Http1Connection, RequestError> {
        // Adoption precedes the primary's proxy TLS, CONNECT and origin TLS.
        if let Some(slower) = slower {
            self.connections.adopt_proxy(slower);
        }
        opening
            .finish(route)
            .await
            .map_err(RequestError::http1_connection_setup)
    }

    async fn finish_forward_opening(
        &self,
        opening: Http1ProxyOpening,
        slower: Option<SlowerConnection<Http1ProxyOpening>>,
        transport: ProxyTransport<'_>,
    ) -> Result<Http1Connection, RequestError> {
        if let Some(slower) = slower {
            self.connections.adopt_proxy(slower);
        }
        opening
            .finish_forward(transport)
            .await
            .map_err(RequestError::http1_connection_setup)
    }

    async fn finish_spare(
        &self,
        delivery: SpareDelivery,
        endpoint: &Endpoint,
        route: &Route,
        mode: Http1ConnectionMode,
    ) -> Result<ConnectionLease, RequestError> {
        match delivery {
            SpareDelivery::Ready(lease) => Ok(lease),
            SpareDelivery::Proxy(claim) => {
                super::box_send(self.finish_proxy_claim(claim, endpoint, route, mode)).await
            }
        }
    }

    async fn finish_proxy_claim(
        &self,
        claim: ProxyClaim,
        endpoint: &Endpoint,
        route: &Route,
        mode: Http1ConnectionMode,
    ) -> Result<ConnectionLease, RequestError> {
        #[cfg(feature = "websocket")]
        if matches!(route, Route::Socks4(_) | Route::Socks5(_)) {
            return claim
                .finish_socks()
                .await
                .map_err(RequestError::http1_connection_setup);
        }
        let Some(proxy) = route.as_http_proxy() else {
            return Err(RequestError::unsupported_route(HttpProtocol::Http1));
        };
        let authority = endpoint.tunnel_authority();
        let proxy_endpoint = phantom_net::route::Endpoint {
            host: proxy.host(),
            port: proxy.port(),
        };
        let transport = if proxy.uses_tls() {
            let connector = self
                .https_proxy
                .get()
                .ok_or_else(|| RequestError::unsupported_route(HttpProtocol::Http1))?;
            ProxyTransport::Tls {
                endpoint: proxy_endpoint,
                server_name: proxy.host(),
                connector,
            }
        } else {
            ProxyTransport::Tcp(proxy_endpoint)
        };
        if mode == Http1ConnectionMode::Forward {
            return claim
                .finish_forward(transport)
                .await
                .map_err(RequestError::http1_connection_setup);
        }
        if mode != Http1ConnectionMode::TlsOrigin {
            return Err(RequestError::unsupported_route(HttpProtocol::Http1));
        }
        claim
            .finish(HttpConnectRoute {
                speculative_tls: proxy.speculative_tls(),
                proxy: transport,
                authority: &authority,
                headers: proxy.ordered_connect_headers(),
                credentials: proxy.authentication(),
            })
            .await
            .map_err(RequestError::http1_connection_setup)
    }

    /// Opens a connection for [`Self::acquire`] in `mode` over `route`, with
    /// the slower attempt of a backup connection on the direct route.
    async fn open(
        &self,
        connector: &Http1TlsConnector,
        https_proxy: Option<&HttpsProxyConnector>,
        endpoint: &Endpoint,
        route: &Route,
        mode: Http1ConnectionMode,
    ) -> Result<Opened, RequestError> {
        let mut connector = if mode == Http1ConnectionMode::TlsOrigin {
            self.connector
                .get_or_init(|| connector.with_isolated_session_cache())
        } else {
            connector
        };
        if mode == Http1ConnectionMode::TlsOrigin {
            let ticket_binding = TicketCacheBinding {
                origin: endpoint,
                server_name: endpoint.host(),
                leg: TicketCacheLeg::Origin,
                protocol: Ok(TicketCacheProtocol::Http1),
                route,
            };
            connector = self
                .connector
                .prepare(&self.tickets, connector, ticket_binding)
                .map_err(RequestError::session_tickets)?;
            self.tickets
                .register_before_use(connector.session_ticket_cache(), ticket_binding)
                .map_err(RequestError::session_tickets)?;
        }
        if mode == Http1ConnectionMode::TlsOrigin && matches!(route, Route::Direct) {
            return self
                .connect_direct(connector, endpoint)
                .await
                .map_err(RequestError::http1_connection_setup);
        }
        let authority = endpoint.tunnel_authority();
        let endpoint_route = phantom_net::route::Endpoint {
            host: endpoint.host(),
            port: endpoint.port(),
        };
        let tcp = match route {
            Route::Direct => TcpRoute::Direct(endpoint_route),
            Route::Socks4(proxy) => proxy
                .tcp_route(endpoint_route)
                .map_err(|source| RequestError::http1_connection_setup(source.into()))?,
            Route::Socks5(proxy) => TcpRoute::Socks5 {
                proxy: phantom_net::route::Endpoint {
                    host: proxy.host(),
                    port: proxy.port(),
                },
                target: match proxy.dns_mode() {
                    crate::Socks5DnsMode::Local => Socks5Target::LocalDns(endpoint_route),
                    crate::Socks5DnsMode::Remote => Socks5Target::RemoteDns(endpoint_route),
                },
                auth: proxy.auth(),
            },
            Route::HttpProxy(proxy) => {
                if mode == Http1ConnectionMode::PlaintextOrigin {
                    return Err(RequestError::unsupported_route(HttpProtocol::Http1));
                }
                let origin_endpoint = endpoint;
                let endpoint = phantom_net::route::Endpoint {
                    host: proxy.host(),
                    port: proxy.port(),
                };
                let transport = if proxy.uses_tls() {
                    let base = https_proxy
                        .ok_or_else(|| RequestError::unsupported_route(HttpProtocol::Http1))?;
                    let proxy_connector = self
                        .https_proxy
                        .get_or_init(|| proxy.https_connector(&base.with_isolated_session_cache()));
                    let ticket_binding = TicketCacheBinding {
                        origin: origin_endpoint,
                        server_name: proxy.host(),
                        leg: TicketCacheLeg::HttpProxy,
                        protocol: TicketCacheBinding::proxy_protocol(proxy_connector.protocol()),
                        route,
                    };
                    let proxy_connector = self
                        .https_proxy
                        .prepare(&self.tickets, proxy_connector, ticket_binding)
                        .map_err(RequestError::session_tickets)?;
                    self.tickets
                        .register_before_use(proxy_connector.session_ticket_cache(), ticket_binding)
                        .map_err(RequestError::session_tickets)?;
                    ProxyTransport::Tls {
                        endpoint,
                        server_name: proxy.host(),
                        connector: proxy_connector,
                    }
                } else {
                    ProxyTransport::Tcp(endpoint)
                };
                if mode == Http1ConnectionMode::Forward {
                    if !proxy.uses_tls() {
                        return super::box_send(
                            connector.connect_forward_retaining(endpoint, &self.connections.family),
                        )
                        .await
                        .map_err(RequestError::http1_connection_setup);
                    }
                    let (opening, slower) = super::box_send(
                        connector.open_https_forward_retaining(transport, &self.connections.family),
                    )
                    .await
                    .map_err(RequestError::http1_connection_setup)?;
                    let connection =
                        super::box_send(self.finish_forward_opening(opening, slower, transport))
                            .await?;
                    return Ok((connection, None));
                }
                if mode == Http1ConnectionMode::TlsOrigin
                    && (!proxy.uses_tls()
                        || matches!(transport, ProxyTransport::Tls { connector, .. }
                        if connector.protocol() == phantom_net::proxy::HttpsProxyProtocol::Http1))
                {
                    let connect_route = HttpConnectRoute {
                        speculative_tls: proxy.speculative_tls(),
                        proxy: transport,
                        authority: &authority,
                        headers: proxy.ordered_connect_headers(),
                        credentials: proxy.authentication(),
                    };
                    let (opening, slower) = super::box_send(connector.open_http_connect_retaining(
                        connect_route,
                        origin_endpoint.host(),
                        &self.connections.family,
                    ))
                    .await
                    .map_err(RequestError::http1_connection_setup)?;
                    let connection =
                        super::box_send(self.finish_proxy_opening(opening, slower, connect_route))
                            .await?;
                    return Ok((connection, None));
                }
                TcpRoute::HttpConnect(HttpConnectRoute {
                    speculative_tls: proxy.speculative_tls()
                        && mode == Http1ConnectionMode::TlsOrigin,
                    proxy: transport,
                    authority: &authority,
                    headers: proxy.ordered_connect_headers(),
                    credentials: proxy.authentication(),
                })
            }
            Route::ConnectUdp(_) => {
                return Err(RequestError::unsupported_route(HttpProtocol::Http1));
            }
        };
        let origin = match mode {
            Http1ConnectionMode::TlsOrigin => OriginRoute::Tls {
                tcp,
                server_name: endpoint.host(),
                setup: DirectTlsSetup::Default,
            },
            Http1ConnectionMode::PlaintextOrigin => OriginRoute::Plaintext {
                tcp,
                family: matches!(route, Route::Direct).then_some(&self.connections.family),
            },
            Http1ConnectionMode::Forward => {
                return Err(RequestError::unsupported_route(HttpProtocol::Http1));
            }
        };
        if matches!(route, Route::Socks4(_) | Route::Socks5(_)) {
            return super::box_send(
                connector.connect_socks_retaining(origin, &self.connections.family),
            )
            .await
            .map_err(RequestError::http1_connection_setup);
        }
        let operation = connector.connect(Http1Route::Origin(origin));
        super::box_send(operation)
            .await
            .map_err(RequestError::http1_connection_setup)
    }
}

/// A new connection, and the slower attempt of its backup connection when
/// one is still connecting.
type Opened = (Http1Connection, Option<SlowerConnection<Http1Connection>>);

/// The connections of one pool key.
///
/// Admission lets at most `max` requests past it, and each holds at most one
/// lease, so a request that finds no idle connection always has room to open
/// one. A lease returns its connection before the request's admission permit
/// is released.
///
/// The slower attempt of a backup connection counts toward `max` of the key
/// of the runtime that opened it once it has connected, as Firefox counts
/// the connections of an origin
/// (`netwerk/protocol/http/ConnectionEntry.cpp:289-297` at tag
/// `FIREFOX_157_0_RELEASE`), but is adopted whatever the count, as Firefox
/// pools it at its limit too. Each request that opened its connection with
/// a backup can leave one such connection, so the key holds up to one
/// extra connection per backup connection whose slower attempt is in
/// flight, at most `max` extra, until they are used or expire idle.
struct EntryConnections {
    retirement: OnceLock<Weak<super::retired_connections::RetiredConnections>>,
    max: NonZeroUsize,
    /// How long an idle connection stays reusable; see
    /// [`phantom_profile::Http1Settings::idle_timeout`].
    used_idle_timeout: Option<Duration>,
    /// The client's prune timer, when the profile closes idle connections
    /// on one.
    prune: Option<Arc<PruneTimer>>,
    /// The address family a backup connection to the origin tries first,
    /// shared with the origin's keys on other runtimes.
    family: Arc<AddressFamilyMemory>,
    set: std::sync::Mutex<ConnectionSet>,
}

#[derive(Default)]
struct ConnectionSet {
    /// Direct Upgrade openings that have not handed off their transport.
    openings: usize,
    /// Connections with no request, least recently used first.
    idle: Vec<IdleConnection>,
    /// Connections leased to a request, and connections being opened.
    leased: usize,
    /// Slower attempts of backup connections that have not finished.
    spares: Vec<Spare>,
    next_spare: u64,
}

impl ConnectionSet {
    fn open(&self) -> usize {
        let connected_spares = self
            .spares
            .iter()
            .filter(|spare| spare.progress.has_connected())
            .count();
        self.idle.len() + self.leased + connected_spares
    }

    fn is_empty(&self) -> bool {
        self.idle.is_empty() && self.leased == 0 && self.spares.is_empty() && self.openings == 0
    }

    fn take_spare(&mut self, id: u64) -> Option<Spare> {
        let position = self.spares.iter().position(|spare| spare.id == id)?;
        Some(self.spares.swap_remove(position))
    }
}

/// The slower attempt of a backup connection, kept by its pool key until it
/// has connected and finished its handshake.
///
/// One request that finds no idle connection may claim it and wait for it
/// instead of opening a connection, as Firefox lets a request claim the
/// connection attempt whose own request went to the faster connection, and
/// the connection while its handshake runs
/// (`netwerk/protocol/http/ConnectionAttemptPool.cpp:141-163`,
/// `netwerk/protocol/http/PendingTransactionInfo.cpp:20-44`, `:113-128`,
/// `netwerk/protocol/http/ConnectionEntry.cpp:652-676` at tag
/// `FIREFOX_157_0_RELEASE`).
struct Spare {
    id: u64,
    progress: SlowerProgress,
    claim: Option<oneshot::Sender<SpareDelivery>>,
    ready: Option<QuietOpening>,
    idle_since: Option<Instant>,
    /// The task finishing the attempt, once it is spawned.
    task: Option<AbortHandle>,
}

impl Spare {
    fn is_claimed(&self) -> bool {
        self.claim.as_ref().is_some_and(|claim| !claim.is_closed())
    }
}

/// Reports the end of a slower attempt's task to its pool key.
///
/// The task owns it, so a task dropped before the attempt finishes, aborted
/// or with the runtime it runs on, reports the attempt as failed and the key
/// does not keep a spare that never ends.
struct SpareReport {
    entry: Option<Weak<EntryConnections>>,
    id: u64,
}

impl SpareReport {
    fn finished(mut self, connection: Option<SpareConnection>) {
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

/// A connection returned to its pool key, and when it was returned.
pub(super) struct IdleConnection {
    pub(super) connection: Http1Connection,
    since: Instant,
}

impl IdleConnection {
    pub(super) fn new(connection: Http1Connection) -> Self {
        Self {
            connection,
            since: Instant::now(),
        }
    }

    /// Whether the connection may carry another request: the server has not
    /// closed it, and it has been idle less than `used_idle_timeout`.
    ///
    /// Chromium checks the timeout as each request reaches its socket pool
    /// and closes every idle socket idle at least that long
    /// (`net/socket/transport_client_socket_pool.cc:263`, `:969-1000` at
    /// tag `154.0.8037.58`).
    pub(super) fn is_reusable(&self, used_idle_timeout: Option<Duration>) -> bool {
        self.connection.is_reusable()
            && used_idle_timeout.is_none_or(|timeout| self.since.elapsed() < timeout)
    }

    /// How long the connection has been idle at `now`.
    pub(super) fn idle_for(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.since)
    }
}

enum Checkout {
    /// An idle connection.
    Idle(ConnectionLease),
    /// The slower connection of a backup connection, once it is ready.
    Spare(SpareClaim),
    /// A connected quiet proxy socket whose claimant must establish its tunnel.
    Proxy(ProxyClaim),
    /// A slot for a connection the caller opens.
    Reserved(Reservation),
}

/// A request's claim on a slower connection still in its setup.
struct SpareClaim {
    receiver: oneshot::Receiver<SpareDelivery>,
}

impl SpareClaim {
    /// The connection, leased to the request, or `None` when its setup
    /// failed.
    #[cfg(test)]
    async fn wait(self) -> Option<ConnectionLease> {
        match self.wait_delivery().await? {
            SpareDelivery::Ready(lease) => Some(lease),
            SpareDelivery::Proxy(_) => None,
        }
    }

    async fn wait_delivery(self) -> Option<SpareDelivery> {
        self.receiver.await.ok()
    }
}

enum SpareConnection {
    Ready(Http1Connection),
    Proxy(QuietOpening),
}

enum SpareDelivery {
    Ready(ConnectionLease),
    Proxy(ProxyClaim),
}

/// A quiet HTTP proxy socket or a complete SOCKS tunnel, before origin setup.
enum QuietOpening {
    Http(Http1ProxyOpening),
    #[cfg(feature = "websocket")]
    Socks(phantom_net::http1::Http1SocksOpening),
}
impl QuietOpening {
    async fn finish(
        self,
        route: phantom_net::route::HttpConnectRoute<'_>,
    ) -> Result<Http1Connection, Http1TlsError> {
        match self {
            Self::Http(opening) => opening.finish(route).await,
            #[cfg(feature = "websocket")]
            Self::Socks(_) => Err(quiet_route_error()),
        }
    }
    #[cfg(feature = "websocket")]
    async fn finish_socks(self) -> Result<Http1Connection, Http1TlsError> {
        match self {
            Self::Socks(opening) => opening.finish().await,
            Self::Http(_) => Err(quiet_route_error()),
        }
    }
    #[cfg(feature = "websocket")]
    async fn finish_upgrade(
        self,
        route: HttpConnectRoute<'_>,
        protocols: &[Box<[u8]>],
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<phantom_net::http1::Http1UpgradeOpening, phantom_net::http1::Http1TlsError> {
        match self {
            Self::Http(opening) => {
                opening
                    .finish_upgrade(route, protocols, target, headers)
                    .await
            }
            #[cfg(feature = "websocket")]
            Self::Socks(_) => Err(phantom_net::http1::Http1TlsError::Connect(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "quiet opening route does not match",
                ),
            )),
        }
    }
    #[cfg(feature = "websocket")]
    async fn finish_socks_upgrade(
        self,
        protocols: &[Box<[u8]>],
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<phantom_net::http1::Http1UpgradeOpening, phantom_net::http1::Http1TlsError> {
        match self {
            Self::Socks(opening) => opening.finish_upgrade(protocols, target, headers).await,
            Self::Http(_) => Err(phantom_net::http1::Http1TlsError::Connect(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "quiet opening route does not match",
                ),
            )),
        }
    }
    async fn finish_forward(
        self,
        transport: ProxyTransport<'_>,
    ) -> Result<Http1Connection, Http1TlsError> {
        match self {
            Self::Http(opening) => opening.finish_forward(transport).await,
            #[cfg(feature = "websocket")]
            Self::Socks(_) => Err(quiet_route_error()),
        }
    }
}
#[cfg(feature = "websocket")]
fn quiet_route_error() -> Http1TlsError {
    Http1TlsError::Connect(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "quiet opening route does not match",
    ))
}

struct ProxyClaim {
    reservation: Reservation,
    opening: Option<QuietOpening>,
    progress: SlowerProgress,
    since: Instant,
}

impl ProxyClaim {
    async fn finish_forward(
        mut self,
        transport: ProxyTransport<'_>,
    ) -> Result<ConnectionLease, Http1TlsError> {
        let Some(opening) = self.opening.take() else {
            return Err(Http1TlsError::Connect(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "proxy opening was already consumed",
            )));
        };
        let connection = opening.finish_forward(transport).await?;
        self.reservation.released = true;
        Ok(Reservation {
            connections: Arc::clone(&self.reservation.connections),
            released: false,
        }
        .into_lease(connection))
    }

    async fn finish(
        mut self,
        route: HttpConnectRoute<'_>,
    ) -> Result<ConnectionLease, Http1TlsError> {
        let Some(opening) = self.opening.take() else {
            return Err(Http1TlsError::Connect(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "proxy opening was already consumed",
            )));
        };
        // Taking the opening commits this claim: cancellation closes the socket.
        let connection = opening.finish(route).await?;
        self.reservation.released = true;
        Ok(Reservation {
            connections: Arc::clone(&self.reservation.connections),
            released: false,
        }
        .into_lease(connection))
    }

    #[cfg(feature = "websocket")]
    async fn finish_socks(mut self) -> Result<ConnectionLease, Http1TlsError> {
        let Some(opening) = self.opening.take() else {
            return Err(Http1TlsError::Connect(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "proxy opening was already consumed",
            )));
        };
        // Taking the opening commits this claim: cancellation closes the socket.
        let connection = opening.finish_socks().await?;
        self.reservation.released = true;
        Ok(Reservation {
            connections: Arc::clone(&self.reservation.connections),
            released: false,
        }
        .into_lease(connection))
    }
}

impl Drop for ProxyClaim {
    fn drop(&mut self) {
        if let Some(opening) = self.opening.take() {
            self.reservation.connections.keep_proxy_ready(
                opening,
                self.progress.clone(),
                self.since,
            );
        }
    }
}

impl EntryConnections {
    fn begin_retirement(
        self: &Arc<Self>,
        registry: &Arc<super::retired_connections::RetiredConnections>,
    ) {
        let set = self.lock();
        self.retirement.get_or_init(|| Arc::downgrade(registry));
        if set.spares.iter().any(|spare| spare.ready.is_none()) {
            registry.retain(self);
        }
    }

    fn retain_pending(self: &Arc<Self>) {
        let _set = self.lock();
        if let Some(registry) = self.retirement.get().and_then(Weak::upgrade) {
            registry.retain(self);
        }
    }

    fn release_retired(self: &Arc<Self>) {
        let removed = {
            let set = self.lock();
            if set.spares.iter().any(|spare| spare.ready.is_none()) {
                return;
            }
            self.retirement
                .get()
                .and_then(Weak::upgrade)
                .and_then(|registry| registry.take(self))
        };
        drop(removed);
    }

    fn new(
        max: NonZeroUsize,
        used_idle_timeout: Option<Duration>,
        prune: Option<Arc<PruneTimer>>,
        family: Arc<AddressFamilyMemory>,
    ) -> Arc<Self> {
        let connections = Arc::new(Self {
            retirement: OnceLock::new(),
            max,
            used_idle_timeout,
            prune,
            family,
            set: std::sync::Mutex::new(ConnectionSet::default()),
        });
        if let Some(timer) = &connections.prune {
            let entry: Arc<dyn PrunedEntry> = connections.clone();
            timer.register(Arc::downgrade(&entry));
        }
        connections
    }

    fn lock(&self) -> MutexGuard<'_, ConnectionSet> {
        self.set.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Tells the prune timer that a connection became idle.
    fn idle_added(&self) {
        if let Some(timer) = &self.prune {
            timer.http1_idle_added();
        }
    }

    /// Rechecks a learned family when the last active owner leaves no socket.
    fn prune_empty_family(&self) {
        let Some(timer) = &self.prune else {
            return;
        };
        let empty = self.lock().is_empty();

        if empty && self.family.family().is_some() {
            timer.idle_added(Duration::from_secs(1));
        }
    }

    /// Keeps the slower attempt of a backup connection, which finishes its
    /// setup on its own task and then joins the idle list or the request
    /// that claimed it.
    ///
    /// Outside a Tokio runtime the attempt is closed instead.
    fn adopt(self: &Arc<Self>, slower: SlowerConnection<Http1Connection>) {
        self.adopt_spare(SlowerConnection::new(slower.progress(), async move {
            slower.finish().await.map(SpareConnection::Ready)
        }));
    }

    fn adopt_proxy(self: &Arc<Self>, slower: SlowerConnection<Http1ProxyOpening>) {
        self.adopt_quiet(SlowerConnection::new(slower.progress(), async move {
            slower.finish().await.map(QuietOpening::Http)
        }));
    }

    #[cfg(feature = "websocket")]
    fn adopt_socks(
        self: &Arc<Self>,
        slower: SlowerConnection<phantom_net::http1::Http1SocksOpening>,
    ) {
        self.adopt_quiet(SlowerConnection::new(slower.progress(), async move {
            slower.finish().await.map(QuietOpening::Socks)
        }));
    }

    fn adopt_quiet(self: &Arc<Self>, slower: SlowerConnection<QuietOpening>) {
        self.adopt_spare(SlowerConnection::new(slower.progress(), async move {
            slower.finish().await.map(SpareConnection::Proxy)
        }));
    }

    fn adopt_spare(self: &Arc<Self>, slower: SlowerConnection<SpareConnection>) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let progress = slower.progress();
        let id = {
            let mut set = self.lock();
            let id = set.next_spare;
            set.next_spare = set.next_spare.wrapping_add(1);

            self.family.mark_active();
            set.spares.push(Spare {
                id,
                progress,
                claim: None,
                ready: None,
                idle_since: None,
                task: None,
            });
            id
        };
        let report = SpareReport {
            entry: Some(Arc::downgrade(self)),
            id,
        };
        self.retain_pending();
        // Spawned outside the lock: a runtime that is shutting down drops
        // the task at once, and its report takes the lock.
        let task = runtime.spawn(async move {
            let connection = slower.finish().await;
            report.finished(connection);
        });
        if let Some(spare) = self.lock().spares.iter_mut().find(|spare| spare.id == id) {
            spare.task = Some(task.abort_handle());
        }
    }

    /// Gives a finished slower connection to the request that claimed it,
    /// or to the idle list.
    fn spare_finished(self: &Arc<Self>, id: u64, connection: Option<SpareConnection>) {
        let mut set = self.lock();
        let spare = set.take_spare(id);
        let Some(mut spare) = spare else {
            drop(set);
            drop(connection);
            return;
        };
        let claim = spare.claim.take().filter(|claim| !claim.is_closed());
        match connection {
            Some(SpareConnection::Proxy(opening)) => {
                let since = Instant::now();
                if let Some(claim) = claim {
                    set.leased += 1;
                    drop(set);
                    let delivery = SpareDelivery::Proxy(ProxyClaim {
                        reservation: Reservation {
                            connections: Arc::clone(self),
                            released: false,
                        },
                        opening: Some(opening),
                        progress: spare.progress,
                        since,
                    });
                    // A lost receiver returns the untouched opening outside the lock.
                    drop(claim.send(delivery));
                } else {
                    spare.ready = Some(opening);
                    spare.idle_since = Some(since);
                    spare.task = None;
                    set.spares.push(spare);
                    drop(set);
                    self.idle_added();
                }
            }
            Some(SpareConnection::Ready(connection)) if connection.is_reusable() => match claim {
                Some(claim) => {
                    set.leased += 1;
                    drop(set);
                    let lease = Reservation {
                        connections: Arc::clone(self),
                        released: false,
                    }
                    .into_lease(connection);
                    drop(claim.send(SpareDelivery::Ready(lease)));
                }
                None => {
                    set.idle.push(IdleConnection::new(connection));
                    drop(set);
                    debug!(outcome = "kept", "HTTP/1 slower backup connection idle");
                    self.idle_added();
                }
            },
            connection => {
                drop(set);
                drop(connection);
                debug!(outcome = "failed", "HTTP/1 slower backup connection failed");
                self.prune_empty_family();
            }
        }
    }

    fn keep_proxy_ready(&self, opening: QuietOpening, progress: SlowerProgress, since: Instant) {
        let mut set = self.lock();
        let id = set.next_spare;
        set.next_spare = set.next_spare.wrapping_add(1);
        set.spares.push(Spare {
            id,
            progress,
            ready: Some(opening),
            idle_since: Some(since),
            claim: None,
            task: None,
        });
        drop(set);
        self.idle_added();
    }

    /// Leases the most recently used idle connection, or reserves a slot for a
    /// new connection when none is idle or `force_new_connection` is set.
    fn checkout(self: &Arc<Self>, force_new_connection: bool) -> Checkout {
        let mut set = self.lock();
        let timeout = self.used_idle_timeout;
        set.idle.retain(|idle| idle.is_reusable(timeout));
        // Move expired raw sockets out before dropping them: stream/TLS owner
        // destruction must not run while the pool lock is held.
        let expired = take_expired_proxy_openings(&mut set, Instant::now(), timeout);
        if !force_new_connection
            && set.idle.is_empty()
            && let Some(spare) = set.spares.iter_mut().find(|spare| !spare.is_claimed())
        {
            if spare.ready.is_some() {
                let id = spare.id;
                if let Some(mut spare) = set.take_spare(id)
                    && let Some(opening) = spare.ready.take()
                {
                    set.leased += 1;
                    drop(set);
                    drop(expired);
                    return Checkout::Proxy(ProxyClaim {
                        reservation: Reservation {
                            connections: Arc::clone(self),
                            released: false,
                        },
                        opening: Some(opening),
                        progress: spare.progress,
                        since: spare.idle_since.unwrap_or_else(Instant::now),
                    });
                }
            } else {
                let (sender, receiver) = oneshot::channel();
                spare.claim = Some(sender);
                drop(set);
                drop(expired);
                return Checkout::Spare(SpareClaim { receiver });
            }
        }
        let idle = if force_new_connection {
            if set.open() >= self.max.get() && !set.idle.is_empty() {
                // Proxy-authentication and reused-connection replays both need
                // a connection that has carried no earlier request. Close the
                // least recently used idle one to stay within the bound.
                set.idle.remove(0);
                debug!(
                    outcome = "authentication_retry",
                    "HTTP/1 pooled connection retired before a fresh-connection attempt"
                );
            }
            None
        } else {
            set.idle.pop().map(|idle| idle.connection)
        };

        if idle.is_none() {
            self.family.mark_active();
        }

        set.leased += 1;
        let reservation = Reservation {
            connections: Arc::clone(self),
            released: false,
        };
        drop(set);
        drop(expired);
        match idle {
            Some(connection) => Checkout::Idle(reservation.into_lease(connection)),
            None => Checkout::Reserved(reservation),
        }
    }

    /// Frees one leased slot, keeping `connection` idle when it is reusable.
    fn release(&self, connection: Option<Http1Connection>) {
        let mut set = self.lock();
        set.leased = set.leased.saturating_sub(1);
        match connection {
            Some(connection) if connection.is_reusable() => {
                set.idle.push(IdleConnection::new(connection));
                drop(set);
                self.idle_added();
            }
            _ => {
                drop(set);
                debug!(
                    outcome = "invalidated",
                    "HTTP/1 pooled connection invalidated"
                );
                self.prune_empty_family();
            }
        }
    }

    #[cfg(test)]
    fn open(&self) -> usize {
        self.lock().open()
    }
}

/// Returns retired raw sockets to the caller, which drops them after unlocking.
fn take_expired_proxy_openings(
    set: &mut ConnectionSet,
    now: Instant,
    limit: Option<Duration>,
) -> Vec<Spare> {
    let mut expired = Vec::new();
    if let Some(limit) = limit {
        let mut index = 0;
        while index < set.spares.len() {
            if set.spares[index]
                .idle_since
                .is_some_and(|since| now.saturating_duration_since(since) >= limit)
            {
                expired.push(set.spares.swap_remove(index));
            } else {
                index += 1;
            }
        }
    }
    expired
}

impl PrunedEntry for EntryConnections {
    fn prune(&self, now: Instant, http1_limit: Option<Duration>) -> Pruned {
        let mut set = self.lock();
        set.idle.retain(|idle| {
            idle.connection.is_reusable()
                && http1_limit.is_none_or(|limit| idle.idle_for(now) < limit)
        });
        let expired = take_expired_proxy_openings(&mut set, now, http1_limit);
        let next = http1_limit.and_then(|limit| {
            set.idle
                .iter()
                .map(|idle| limit.saturating_sub(idle.idle_for(now)))
                .chain(
                    set.spares
                        .iter()
                        .filter_map(|spare| spare.idle_since)
                        .map(|since| limit.saturating_sub(now.saturating_duration_since(since))),
                )
                .min()
        });
        let empty = set.is_empty();
        drop(set);
        drop(expired);
        Pruned { next, empty }
    }

    fn address_family(&self) -> Option<&Arc<AddressFamilyMemory>> {
        Some(&self.family)
    }
}

impl Drop for EntryConnections {
    fn drop(&mut self) {
        for spare in &self.lock().spares {
            if let Some(task) = &spare.task {
                task.abort();
            }
        }
    }
}

/// A slot counted against the pool key's bound before its connection exists.
///
/// Dropping it, for example when connection setup fails or the request is
/// cancelled, frees the slot.
struct Reservation {
    connections: Arc<EntryConnections>,
    released: bool,
}

impl Reservation {
    fn into_lease(self, connection: Http1Connection) -> ConnectionLease {
        ConnectionLease {
            reservation: self,
            connection,
            retired: false,
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.released {
            self.connections.release(None);
        }
    }
}

/// One request's hold on a pool-key connection.
///
/// Dropping it returns a still-reusable connection to the idle list unless it
/// was retired.
struct ConnectionLease {
    reservation: Reservation,
    connection: Http1Connection,
    retired: bool,
}

impl ConnectionLease {
    /// Keeps this connection from serving another request.
    fn retire(&mut self) {
        self.retired = true;
    }
}

impl Drop for ConnectionLease {
    fn drop(&mut self) {
        let connection = (!self.retired).then(|| self.connection.clone());
        self.reservation.connections.release(connection);
        self.reservation.released = true;
    }
}

/// Held by a response body until it completes or is dropped.
///
/// Fields drop in declaration order, so the connection returns to the idle
/// list before the admission permit lets the next request in.
struct RequestGuard {
    _lease: ConnectionLease,
    _permit: AdmissionPermit,
}

#[cfg(test)]
mod tests;
