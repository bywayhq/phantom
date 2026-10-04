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
use phantom_net::http1::{
    AbsoluteForm, Http1Body, Http1Connection, Http1TlsConnector, Http1TlsError, OriginForm,
    RequestHeader, validate_forward_request_body_source_with_trailers,
    validate_request_body_source_with_trailers,
};
use phantom_net::proxy::{HttpsProxyConnector, MAX_CHALLENGE_BODY_BYTES};
use phantom_net::request::RequestBody;
use phantom_net::tcp::{AddressFamilyMemory, SlowerConnection, SlowerProgress};
use tokio::{
    sync::{Mutex, oneshot},
    task::AbortHandle,
    time::Instant,
};
use tracing::debug;

use super::address_families::AddressFamilies;
use super::admission::{Admission, AdmissionPermit, AdmissionRegistry};
use super::prune_timer::{PruneTimer, Pruned, PrunedEntry};
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
    capacity: NonZeroUsize,
    max_active: NonZeroUsize,
    max_pending: NonZeroUsize,
    used_idle_timeout: Option<Duration>,
    prune_timer: Option<Arc<PruneTimer>>,
    state: Mutex<PoolState>,
    #[cfg(feature = "https-records")]
    https_records: Option<super::alt_svc::HttpsRecordDiscovery>,
}

impl Http1Pool {
    pub(super) fn new(
        capacity: NonZeroUsize,
        max_active: NonZeroUsize,
        max_pending: NonZeroUsize,
    ) -> Self {
        Self {
            capacity,
            max_active,
            max_pending,
            used_idle_timeout: None,
            prune_timer: None,
            state: Mutex::new(PoolState::default()),
            #[cfg(feature = "https-records")]
            https_records: None,
        }
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
                && let Some(credentials) = route
                    .as_http_proxy()
                    .and_then(crate::HttpProxy::basic_credentials)
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
        match result {
            Ok(Ok(response)) => {
                if mode == Http1ConnectionMode::Forward
                    && route
                        .as_http_proxy()
                        .and_then(crate::HttpProxy::basic_credentials)
                        .is_some()
                    && response.status() == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
                {
                    let (parts, mut body) = response.into_parts();
                    if let Some(slot) = challenged.filter(|slot| !slot.replayed) {
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
                let (parts, body) = response.into_parts();
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
    ) -> Http1TlsConnector {
        self.entry(PoolKey::new(
            endpoint,
            route,
            Http1ConnectionMode::TlsOrigin,
        ))
        .await
        .connector
        .get_or_init(|| base.with_isolated_session_cache())
        .clone()
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

    /// Marks the next attempt as the proxy-authentication replay, whose `407`
    /// is final, so the pool keeps no connection for it.
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
    connections: Arc<EntryConnections>,
    admission: Arc<Admission>,
    connector: OnceLock<Http1TlsConnector>,
    https_proxy: OnceLock<HttpsProxyConnector>,
    #[cfg(feature = "https-records")]
    https_records: Option<super::alt_svc::HttpsRecordDiscovery>,
}

impl PoolEntry {
    fn new(admission: Arc<Admission>, connections: Arc<EntryConnections>) -> Self {
        Self {
            connections,
            admission,
            connector: OnceLock::new(),
            https_proxy: OnceLock::new(),
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
    /// keep; the ECH path closes it.
    async fn connect_direct(
        &self,
        connector: &Http1TlsConnector,
        endpoint: &Endpoint,
    ) -> Result<Opened, Http1TlsError> {
        #[cfg(feature = "https-records")]
        if connector.ech_from_https_records()
            && let Some(discovery) = &self.https_records
        {
            let ech = discovery.tcp_ech(endpoint, connector.alpn_protocols());
            return connector
                .connect_direct_with_ech(endpoint.host(), endpoint.port(), endpoint.host(), ech)
                .await
                .map(|connection| (connection, None));
        }
        connector
            .connect_direct_keeping_slower(
                endpoint.host(),
                endpoint.port(),
                endpoint.host(),
                &self.connections.family,
            )
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
                    if let Some(lease) = claim.wait().await {
                        debug!(
                            outcome = "claimed",
                            "HTTP/1 slower backup connection acquired"
                        );
                        return Ok(lease);
                    }
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
        let connection = match mode {
            Http1ConnectionMode::Forward => {
                let Route::HttpProxy(proxy) = route else {
                    return Err(RequestError::unsupported_route(HttpProtocol::Http1));
                };
                if proxy.uses_tls() {
                    let base = https_proxy
                        .ok_or_else(|| RequestError::unsupported_route(HttpProtocol::Http1))?;
                    let proxy_connector = self
                        .https_proxy
                        .get_or_init(|| proxy.https_connector(&base.with_isolated_session_cache()));
                    connector
                        .connect_https_forward_proxy(
                            proxy_connector,
                            proxy.host(),
                            proxy.port(),
                            proxy.host(),
                        )
                        .await
                        .map_err(RequestError::http1_connection_setup)?
                } else {
                    connector
                        .connect_forward_proxy(proxy.host(), proxy.port())
                        .await
                        .map_err(RequestError::http1_connection_setup)?
                }
            }
            Http1ConnectionMode::PlaintextOrigin => match route {
                Route::Direct => {
                    return connector
                        .connect_plaintext_direct_keeping_slower(
                            endpoint.host(),
                            endpoint.port(),
                            &self.connections.family,
                        )
                        .await
                        .map_err(RequestError::http1_connection_setup);
                }
                Route::Socks5(proxy) => match proxy.dns_mode() {
                    crate::Socks5DnsMode::Local => connector
                        .connect_plaintext_socks5_local_with_auth(
                            proxy.host(),
                            proxy.port(),
                            proxy.auth(),
                            endpoint.host(),
                            endpoint.port(),
                        )
                        .await
                        .map_err(RequestError::http1_connection_setup)?,
                    crate::Socks5DnsMode::Remote => connector
                        .connect_plaintext_socks5_remote_with_auth(
                            proxy.host(),
                            proxy.port(),
                            proxy.auth(),
                            endpoint.host(),
                            endpoint.port(),
                        )
                        .await
                        .map_err(RequestError::http1_connection_setup)?,
                },
                // Forwarding owns HTTP proxies; CONNECT-UDP carries only QUIC.
                Route::HttpProxy(_) | Route::ConnectUdp(_) => {
                    return Err(RequestError::unsupported_route(HttpProtocol::Http1));
                }
            },
            Http1ConnectionMode::TlsOrigin => {
                let connector = self
                    .connector
                    .get_or_init(|| connector.with_isolated_session_cache());
                match route {
                    // Rejected before admission; never reinterpreted as TCP.
                    Route::ConnectUdp(_) => {
                        return Err(RequestError::unsupported_route(HttpProtocol::Http1));
                    }
                    Route::Direct => {
                        return self
                            .connect_direct(connector, endpoint)
                            .await
                            .map_err(RequestError::http1_connection_setup);
                    }
                    Route::HttpProxy(proxy) => {
                        let connect_authority = endpoint.tunnel_authority();
                        if proxy.uses_tls() {
                            let base = https_proxy.ok_or_else(|| {
                                RequestError::unsupported_route(HttpProtocol::Http1)
                            })?;
                            let proxy_connector = self.https_proxy.get_or_init(|| {
                                proxy.https_connector(&base.with_isolated_session_cache())
                            });
                            if let Some(credentials) = proxy.basic_credentials() {
                                // Bound the challenge/retry state machine without
                                // adding allocation to unauthenticated connections.
                                super::box_send(connector.connect_https_connect_with_basic_auth(
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
                                .map_err(RequestError::http1_connection_setup)?
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
                                    .map_err(RequestError::http1_connection_setup)?
                            }
                        } else {
                            if let Some(credentials) = proxy.basic_credentials() {
                                super::box_send(connector.connect_http_connect_with_basic_auth(
                                    proxy.host(),
                                    proxy.port(),
                                    &connect_authority,
                                    proxy.ordered_connect_headers(),
                                    credentials,
                                    endpoint.host(),
                                ))
                                .await
                                .map_err(RequestError::http1_connection_setup)?
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
                                    .map_err(RequestError::http1_connection_setup)?
                            }
                        }
                    }
                    Route::Socks5(proxy) => match proxy.dns_mode() {
                        crate::Socks5DnsMode::Local => connector
                            .connect_socks5_local_with_auth(
                                proxy.host(),
                                proxy.port(),
                                proxy.auth(),
                                endpoint.host(),
                                endpoint.port(),
                                endpoint.host(),
                            )
                            .await
                            .map_err(RequestError::http1_connection_setup)?,
                        crate::Socks5DnsMode::Remote => connector
                            .connect_socks5_remote_with_auth(
                                proxy.host(),
                                proxy.port(),
                                proxy.auth(),
                                endpoint.host(),
                                endpoint.port(),
                                endpoint.host(),
                            )
                            .await
                            .map_err(RequestError::http1_connection_setup)?,
                    },
                }
            }
        };
        Ok((connection, None))
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
        self.idle.is_empty() && self.leased == 0 && self.spares.is_empty()
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
    claim: Option<oneshot::Sender<ConnectionLease>>,
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
    fn finished(mut self, connection: Option<Http1Connection>) {
        if let Some(entry) = self.entry.take().and_then(|entry| entry.upgrade()) {
            entry.spare_finished(self.id, connection);
        }
    }
}

impl Drop for SpareReport {
    fn drop(&mut self) {
        if let Some(entry) = self.entry.take().and_then(|entry| entry.upgrade()) {
            entry.spare_finished(self.id, None);
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
    /// A slot for a connection the caller opens.
    Reserved(Reservation),
}

/// A request's claim on a slower connection still in its setup.
struct SpareClaim {
    receiver: oneshot::Receiver<ConnectionLease>,
}

impl SpareClaim {
    /// The connection, leased to the request, or `None` when its setup
    /// failed.
    async fn wait(self) -> Option<ConnectionLease> {
        self.receiver.await.ok()
    }
}

impl EntryConnections {
    fn new(
        max: NonZeroUsize,
        used_idle_timeout: Option<Duration>,
        prune: Option<Arc<PruneTimer>>,
        family: Arc<AddressFamilyMemory>,
    ) -> Arc<Self> {
        let connections = Arc::new(Self {
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
            timer.idle_added(timer.limit());
        }
    }

    /// Keeps the slower attempt of a backup connection, which finishes its
    /// setup on its own task and then joins the idle list or the request
    /// that claimed it.
    ///
    /// Outside a Tokio runtime the attempt is closed instead.
    fn adopt(self: &Arc<Self>, slower: SlowerConnection<Http1Connection>) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let progress = slower.progress();
        let id = {
            let mut set = self.lock();
            let id = set.next_spare;
            set.next_spare = set.next_spare.wrapping_add(1);
            set.spares.push(Spare {
                id,
                progress,
                claim: None,
                task: None,
            });
            id
        };
        let report = SpareReport {
            entry: Some(Arc::downgrade(self)),
            id,
        };
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
    fn spare_finished(self: &Arc<Self>, id: u64, connection: Option<Http1Connection>) {
        let mut set = self.lock();
        let claim = set.take_spare(id).and_then(|spare| spare.claim);
        let Some(connection) = connection.filter(Http1Connection::is_reusable) else {
            debug!(outcome = "failed", "HTTP/1 slower backup connection failed");
            // A claimant finds its claim dropped and chooses again.
            return;
        };
        match claim.filter(|claim| !claim.is_closed()) {
            Some(claim) => {
                set.leased += 1;
                drop(set);
                let lease = Reservation {
                    connections: Arc::clone(self),
                    released: false,
                }
                .into_lease(connection);
                // A claimant that just left drops the lease, which returns
                // the connection to the idle list.
                drop(claim.send(lease));
            }
            None => {
                set.idle.push(IdleConnection::new(connection));
                drop(set);
                debug!(outcome = "kept", "HTTP/1 slower backup connection idle");
                self.idle_added();
            }
        }
    }

    /// Leases the most recently used idle connection, or reserves a slot for a
    /// new connection when none is idle or `force_new_connection` is set.
    fn checkout(self: &Arc<Self>, force_new_connection: bool) -> Checkout {
        let mut set = self.lock();
        let timeout = self.used_idle_timeout;
        set.idle.retain(|idle| idle.is_reusable(timeout));
        if !force_new_connection
            && set.idle.is_empty()
            && let Some(spare) = set.spares.iter_mut().find(|spare| !spare.is_claimed())
        {
            let (sender, receiver) = oneshot::channel();
            spare.claim = Some(sender);
            return Checkout::Spare(SpareClaim { receiver });
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
        set.leased += 1;
        let reservation = Reservation {
            connections: Arc::clone(self),
            released: false,
        };
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
            _ => debug!(
                outcome = "invalidated",
                "HTTP/1 pooled connection invalidated"
            ),
        }
    }

    #[cfg(test)]
    fn open(&self) -> usize {
        self.lock().open()
    }
}

impl PrunedEntry for EntryConnections {
    fn prune(&self, now: Instant, limit: Duration) -> Pruned {
        let mut set = self.lock();
        set.idle
            .retain(|idle| idle.connection.is_reusable() && idle.idle_for(now) < limit);
        let next = set
            .idle
            .iter()
            .map(|idle| limit.saturating_sub(idle.idle_for(now)))
            .min();
        Pruned {
            next,
            empty: set.is_empty(),
        }
    }

    fn address_family(&self) -> &Arc<AddressFamilyMemory> {
        &self.family
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
