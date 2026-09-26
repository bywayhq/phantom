use std::{
    collections::VecDeque,
    future::poll_fn,
    num::NonZeroUsize,
    pin::Pin,
    sync::{Arc, MutexGuard, OnceLock, PoisonError},
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
use tokio::sync::Mutex;
use tracing::debug;

use super::admission::{Admission, AdmissionPermit, AdmissionRegistry};
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
/// then takes the most recently used idle connection, or opens one when none
/// is idle.
pub(crate) struct Http1Pool {
    capacity: NonZeroUsize,
    max_active: NonZeroUsize,
    max_pending: NonZeroUsize,
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
            state: Mutex::new(PoolState::default()),
            #[cfg(feature = "https-records")]
            https_records: None,
        }
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
                // The lease drops before the permit, so the next admitted
                // request finds a reusable connection idle.
                drop(lease);
                drop(permit);
                Err(RequestError::http1(error.into()))
            }
            Err(error) => {
                lease.retire();
                drop(lease);
                drop(permit);
                Err(error)
            }
        }
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
            .get(&key, self.max_active, self.max_pending);
        #[cfg_attr(not(feature = "https-records"), allow(unused_mut))]
        let mut entry = PoolEntry::new(admission, self.max_active);
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
            Some(read_idle) => tokio::time::timeout(read_idle, frame).await.map_err(|_| {
                RequestError::timeout(TimeoutPhase::ReadIdle, Some(HttpProtocol::Http1))
            })?,
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PoolKey {
    host: Box<str>,
    port: u16,
    route: Route,
    mode: Http1ConnectionMode,
}

impl PoolKey {
    fn new(endpoint: &Endpoint, route: &Route, mode: Http1ConnectionMode) -> Self {
        Self {
            host: endpoint.host().to_ascii_lowercase().into(),
            port: endpoint.port(),
            route: route.clone(),
            mode,
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
    fn new(admission: Arc<Admission>, max_connections: NonZeroUsize) -> Self {
        Self {
            connections: Arc::new(EntryConnections {
                max: max_connections,
                set: std::sync::Mutex::new(ConnectionSet::default()),
            }),
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
    async fn connect_direct(
        &self,
        connector: &Http1TlsConnector,
        endpoint: &Endpoint,
    ) -> Result<Http1Connection, Http1TlsError> {
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

    async fn acquire(
        &self,
        connector: &Http1TlsConnector,
        https_proxy: Option<&HttpsProxyConnector>,
        endpoint: &Endpoint,
        route: &Route,
        mode: Http1ConnectionMode,
        force_new_connection: bool,
    ) -> Result<ConnectionLease, RequestError> {
        let reservation = match self.connections.checkout(force_new_connection) {
            Checkout::Idle(lease) => {
                debug!(
                    outcome = "hit",
                    "HTTP/1 connection acquired from client pool"
                );
                return Ok(lease);
            }
            Checkout::Reserved(reservation) => reservation,
        };

        debug!(outcome = "connect", "HTTP/1 client pool opening connection");
        // Boxed: opening a connection awaits the largest connector futures,
        // which would otherwise enlarge the future of every request, including
        // one that reuses a pooled connection.
        let connection = Box::pin(self.open(connector, https_proxy, endpoint, route, mode)).await?;
        Ok(reservation.into_lease(connection))
    }

    /// Opens a connection for [`Self::acquire`] in `mode` over `route`.
    async fn open(
        &self,
        connector: &Http1TlsConnector,
        https_proxy: Option<&HttpsProxyConnector>,
        endpoint: &Endpoint,
        route: &Route,
        mode: Http1ConnectionMode,
    ) -> Result<Http1Connection, RequestError> {
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
                Route::Direct => connector
                    .connect_plaintext_direct(endpoint.host(), endpoint.port())
                    .await
                    .map_err(RequestError::http1_connection_setup)?,
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
                    Route::Direct => self
                        .connect_direct(connector, endpoint)
                        .await
                        .map_err(RequestError::http1_connection_setup)?,
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
                                Box::pin(connector.connect_http_connect_with_basic_auth(
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
        Ok(connection)
    }
}

/// The connections of one pool key.
///
/// Admission lets at most `max` requests past it, and each holds at most one
/// lease, so a request that finds no idle connection always has room to open
/// one. A lease returns its connection before the request's admission permit
/// is released.
struct EntryConnections {
    max: NonZeroUsize,
    set: std::sync::Mutex<ConnectionSet>,
}

#[derive(Default)]
struct ConnectionSet {
    /// Connections with no request, least recently used first.
    idle: Vec<Http1Connection>,
    /// Connections leased to a request, and connections being opened.
    leased: usize,
}

impl ConnectionSet {
    fn open(&self) -> usize {
        self.idle.len() + self.leased
    }
}

enum Checkout {
    /// An idle connection that has carried an earlier request.
    Idle(ConnectionLease),
    /// A slot for a connection the caller opens.
    Reserved(Reservation),
}

impl EntryConnections {
    fn lock(&self) -> MutexGuard<'_, ConnectionSet> {
        self.set.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Leases the most recently used idle connection, or reserves a slot for a
    /// new connection when none is idle or `force_new_connection` is set.
    fn checkout(self: &Arc<Self>, force_new_connection: bool) -> Checkout {
        let mut set = self.lock();
        set.idle.retain(Http1Connection::is_reusable);
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
            set.idle.pop()
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
            Some(connection) if connection.is_reusable() => set.idle.push(connection),
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
