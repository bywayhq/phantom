use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    pin::pin,
    sync::{Arc, MutexGuard, OnceLock, PoisonError},
    time::Duration,
};

use http::Method;
use phantom_net::http2::{
    Http2Body, Http2Connection, Http2Error, Http2ProtocolErrorKind, Http2TlsConnector,
    Http2TlsError, OriginForm, RequestHeader, validate_request_body_source_with_trailers,
};
use phantom_net::proxy::HttpsProxyConnector;
use phantom_net::request::RequestBody;
use phantom_profile::Http2Priority;
use tokio::{
    sync::{Mutex, Notify},
    time::Instant,
};
use tracing::debug;

use super::{
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
    capacity: NonZeroUsize,
    max_active: NonZeroUsize,
    max_pending: NonZeroUsize,
    max_connections: NonZeroUsize,
    /// The client's prune timer, when the profile closes idle connections on
    /// one.
    prune_timer: Option<Arc<PruneTimer>>,
    state: Mutex<PoolState>,
    #[cfg(feature = "https-records")]
    https_records: Option<super::alt_svc::HttpsRecordDiscovery>,
}

impl Http2Pool {
    pub(super) fn new(
        capacity: NonZeroUsize,
        max_active: NonZeroUsize,
        max_pending: NonZeroUsize,
    ) -> Self {
        Self {
            capacity,
            max_active,
            max_pending,
            max_connections: NonZeroUsize::MIN,
            prune_timer: None,
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
            let response_timeout =
                timeout_budget.phase(TimeoutPhase::ResponseHead, Some(HttpProtocol::Http2))?;
            let sent_headers = headers.clone();
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
    ) -> Http2TlsConnector {
        self.entry(PoolKey::new(
            endpoint,
            route,
            Http2ConnectionMode::TlsOrigin,
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
        // HTTPS records are looked up on the direct route only: Chromium sends
        // no HTTPS query for a proxied request.
        #[cfg(feature = "https-records")]
        if key.route == Route::Direct {
            entry.https_records = self.https_records.clone();
        }
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
    /// The key's connections, oldest first. The lock is never held across an
    /// await; a setup in flight is counted in it instead.
    connections: std::sync::Mutex<Connections>,
    /// Woken whenever a connection setup finishes, fails, or is cancelled,
    /// and whenever a stream on one of the key's connections ends.
    setup_done: Arc<Notify>,
    admission: Arc<Admission>,
    connector: OnceLock<Http2TlsConnector>,
    https_proxy: OnceLock<HttpsProxyConnector>,
    /// The client's prune timer, when the profile closes idle connections on
    /// one.
    prune: Option<Arc<PruneTimer>>,
    #[cfg(feature = "https-records")]
    https_records: Option<super::alt_svc::HttpsRecordDiscovery>,
}

impl PoolEntry {
    fn new(admission: Arc<Admission>, spread: Http2Spread) -> Self {
        Self {
            connections: std::sync::Mutex::new(Connections {
                slots: Vec::new(),
                connecting: false,
                spread,
            }),
            setup_done: Arc::new(Notify::new()),
            admission,
            connector: OnceLock::new(),
            https_proxy: OnceLock::new(),
            prune: None,
            #[cfg(feature = "https-records")]
            https_records: None,
        }
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
    ) -> Result<Http2Connection, Http2TlsError> {
        #[cfg(feature = "https-records")]
        if connector.ech_from_https_records()
            && let Some(discovery) = &self.https_records
        {
            let ech = discovery.tcp_ech(endpoint, connector.alpn_protocols());
            let mut ech = pin!(ech);
            return connector
                .connect(phantom_net::route::Http2Route::Origin(
                    phantom_net::route::OriginRoute::Tls {
                        tcp: phantom_net::route::TcpRoute::Direct(phantom_net::route::Endpoint {
                            host: endpoint.host(),
                            port: endpoint.port(),
                        }),
                        server_name: endpoint.host(),
                        setup: phantom_net::route::DirectTlsSetup::Ech(ech.as_mut()),
                    },
                ))
                .await;
        }
        connector
            .connect(phantom_net::route::Http2Route::Origin(
                phantom_net::route::OriginRoute::Tls {
                    tcp: phantom_net::route::TcpRoute::Direct(phantom_net::route::Endpoint {
                        host: endpoint.host(),
                        port: endpoint.port(),
                    }),
                    server_name: endpoint.host(),
                    setup: phantom_net::route::DirectTlsSetup::Default,
                },
            ))
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
                    if !connections.connecting {
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
        &self,
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
        let reservation = loop {
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
                    connections.connecting = true;
                    break SetupReservation {
                        entry: self,
                        finished: false,
                    };
                }
            }
            setup_done.await;
        };

        debug!(outcome = "connect", "HTTP/2 client pool opening connection");
        // Boxed: opening a connection awaits the largest connector futures,
        // which would otherwise enlarge the future of every request, including
        // one that reuses a pooled connection.
        let connection =
            super::box_send(self.open(connector, https_proxy, endpoint, route, mode)).await?;
        Ok(reservation.finish(connection))
    }

    /// Opens a connection for [`Self::acquire`] in `mode` over `route`.
    async fn open(
        &self,
        connector: &Http2TlsConnector,
        https_proxy: Option<&HttpsProxyConnector>,
        endpoint: &Endpoint,
        route: &Route,
        mode: Http2ConnectionMode,
    ) -> Result<Http2Connection, RequestError> {
        let connector = self
            .connector
            .get_or_init(|| connector.with_isolated_session_cache());
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
                connector
                    .connect(phantom_net::route::Http2Route::Forward {
                        proxy: phantom_net::route::ProxyTransport::Tls {
                            endpoint: phantom_net::route::Endpoint {
                                host: proxy.host(),
                                port: proxy.port(),
                            },
                            server_name: proxy.host(),
                            connector: proxy_connector,
                        },
                        credentials: proxy.basic_credentials(),
                    })
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
            Route::Direct => self
                .connect_direct(connector, endpoint)
                .await
                .map_err(RequestError::http2_connection_setup)?,
            Route::HttpProxy(proxy) => {
                let connect_authority = endpoint.tunnel_authority();
                if proxy.uses_tls() {
                    let base = https_proxy
                        .ok_or_else(|| RequestError::unsupported_route(HttpProtocol::Http2))?;
                    let proxy_connector = self
                        .https_proxy
                        .get_or_init(|| proxy.https_connector(&base.with_isolated_session_cache()));
                    if let Some(credentials) = proxy.basic_credentials() {
                        // The retry state machine is large; one allocation per
                        // authenticated proxy connection bounds this future.
                        super::box_send(connector.connect(phantom_net::route::Http2Route::Origin(
                            phantom_net::route::OriginRoute::Tls {
                                tcp: phantom_net::route::TcpRoute::HttpConnect(
                                    phantom_net::route::HttpConnectRoute {
                                        proxy: phantom_net::route::ProxyTransport::Tls {
                                            endpoint: phantom_net::route::Endpoint {
                                                host: proxy.host(),
                                                port: proxy.port(),
                                            },
                                            server_name: proxy.host(),
                                            connector: proxy_connector,
                                        },
                                        authority: &connect_authority,
                                        headers: proxy.ordered_connect_headers(),
                                        credentials: Some(credentials),
                                    },
                                ),
                                server_name: endpoint.host(),
                                setup: phantom_net::route::DirectTlsSetup::Default,
                            },
                        )))
                        .await
                        .map_err(RequestError::http2_connection_setup)?
                    } else {
                        connector
                            .connect(phantom_net::route::Http2Route::Origin(
                                phantom_net::route::OriginRoute::Tls {
                                    tcp: phantom_net::route::TcpRoute::HttpConnect(
                                        phantom_net::route::HttpConnectRoute {
                                            proxy: phantom_net::route::ProxyTransport::Tls {
                                                endpoint: phantom_net::route::Endpoint {
                                                    host: proxy.host(),
                                                    port: proxy.port(),
                                                },
                                                server_name: proxy.host(),
                                                connector: proxy_connector,
                                            },
                                            authority: &connect_authority,
                                            headers: proxy.ordered_connect_headers(),
                                            credentials: None,
                                        },
                                    ),
                                    server_name: endpoint.host(),
                                    setup: phantom_net::route::DirectTlsSetup::Default,
                                },
                            ))
                            .await
                            .map_err(RequestError::http2_connection_setup)?
                    }
                } else {
                    if let Some(credentials) = proxy.basic_credentials() {
                        // See the TLS-proxy branch above.
                        super::box_send(connector.connect(phantom_net::route::Http2Route::Origin(
                            phantom_net::route::OriginRoute::Tls {
                                tcp: phantom_net::route::TcpRoute::HttpConnect(
                                    phantom_net::route::HttpConnectRoute {
                                        proxy: phantom_net::route::ProxyTransport::Tcp(
                                            phantom_net::route::Endpoint {
                                                host: proxy.host(),
                                                port: proxy.port(),
                                            },
                                        ),
                                        authority: &connect_authority,
                                        headers: proxy.ordered_connect_headers(),
                                        credentials: Some(credentials),
                                    },
                                ),
                                server_name: endpoint.host(),
                                setup: phantom_net::route::DirectTlsSetup::Default,
                            },
                        )))
                        .await
                        .map_err(RequestError::http2_connection_setup)?
                    } else {
                        connector
                            .connect(phantom_net::route::Http2Route::Origin(
                                phantom_net::route::OriginRoute::Tls {
                                    tcp: phantom_net::route::TcpRoute::HttpConnect(
                                        phantom_net::route::HttpConnectRoute {
                                            proxy: phantom_net::route::ProxyTransport::Tcp(
                                                phantom_net::route::Endpoint {
                                                    host: proxy.host(),
                                                    port: proxy.port(),
                                                },
                                            ),
                                            authority: &connect_authority,
                                            headers: proxy.ordered_connect_headers(),
                                            credentials: None,
                                        },
                                    ),
                                    server_name: endpoint.host(),
                                    setup: phantom_net::route::DirectTlsSetup::Default,
                                },
                            ))
                            .await
                            .map_err(RequestError::http2_connection_setup)?
                    }
                }
            }
            Route::Socks5(proxy) => match proxy.dns_mode() {
                crate::Socks5DnsMode::Local => connector
                    .connect(phantom_net::route::Http2Route::Origin(
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
                    ))
                    .await
                    .map_err(RequestError::http2_connection_setup)?,
                crate::Socks5DnsMode::Remote => connector
                    .connect(phantom_net::route::Http2Route::Origin(
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
                    ))
                    .await
                    .map_err(RequestError::http2_connection_setup)?,
            },
        };
        Ok(connection)
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
    }
}

impl PrunedEntry for PoolEntry {
    /// Gives up the key's connections past their idle limit, which close
    /// once no stream is open, and those the server closed.
    fn prune(&self, _now: Instant, _http1_limit: Option<Duration>) -> Pruned {
        let mut connections = self.lock();
        connections.retain_reusable();
        Pruned {
            next: connections
                .slots
                .iter()
                .filter_map(|slot| slot.connection.idle_time_left())
                .min(),
            empty: connections.slots.is_empty() && !connections.connecting,
        }
    }

    /// The exact H2 pool remembers no address family.
    fn address_family(&self) -> Option<&Arc<phantom_net::tcp::AddressFamilyMemory>> {
        None
    }
}

/// One pool key's HTTP/2 connections and how streams spread across them.
struct Connections {
    slots: Vec<ConnectionSlot>,
    /// Whether the key's one connection setup is in flight.
    connecting: bool,
    spread: Http2Spread,
}

/// The key's one connection setup in flight.
///
/// Dropping it unfinished, when setup fails or the request is cancelled,
/// frees the setup and wakes every request waiting for it. They are not
/// served in arrival order: the first to run takes the next setup.
struct SetupReservation<'a> {
    entry: &'a PoolEntry,
    finished: bool,
}

impl SetupReservation<'_> {
    /// Pools the new connection and leases it for this request's stream.
    fn finish(mut self, connection: Http2Connection) -> ConnectionLease {
        self.finished = true;
        let left = connection.idle_time_left();
        let slot = ConnectionSlot {
            connection,
            token: Arc::new(()),
            streams: StreamCount::notifying(Arc::clone(&self.entry.setup_done)),
        };
        let lease = slot.lease();
        let mut connections = self.entry.lock();
        connections.connecting = false;
        connections.slots.push(slot);
        drop(connections);
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
            self.entry.setup_done.notify_waiters();
        }
    }
}

impl Connections {
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
    use std::{num::NonZeroUsize, sync::Arc};

    use super::{Http2Pool, PoolEntry, PoolKey, SetupReservation};
    use crate::{Route, authority::Endpoint};

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
    fn reserve(entry: &PoolEntry) -> SetupReservation<'_> {
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
            &phantom_profile::chromium::v154_http2(),
        )
        .await?;
        drop(reservation.finish(connection));
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

        use phantom_profile::{Http2IdleTimeout, firefox};
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
        drop(reserve(&entry).finish(connection));
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
