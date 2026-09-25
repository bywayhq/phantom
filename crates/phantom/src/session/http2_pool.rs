use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    pin::pin,
    sync::{Arc, MutexGuard, OnceLock, PoisonError},
};

use http::Method;
use phantom_net::http2::{
    Http2Body, Http2Connection, Http2Error, Http2ProtocolErrorKind, Http2TlsConnector,
    Http2TlsError, OriginForm, RequestHeader, validate_request_body_source_with_trailers,
};
use phantom_net::proxy::HttpsProxyConnector;
use phantom_net::request::RequestBody;
use phantom_profile::Http2Priority;
use tokio::sync::{Mutex, Notify};
use tracing::debug;

use super::{
    admission::{Admission, AdmissionPermit, AdmissionRegistry},
    client_hints::ClientHintContext,
    http2_connections::{Choice, Http2Spread, OpenStream, StreamCount},
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
    ) -> Result<(http::Response<ResponseBody>, Vec<RequestHeader>), RequestError> {
        let prepared_validation_headers = client_hints
            .map(|context| context.prepare(headers.clone(), None))
            .transpose()?;
        let validation_headers = prepared_validation_headers.as_deref().unwrap_or(&headers);
        validate_request_body_source_with_trailers(
            &method,
            authority,
            &target,
            validation_headers,
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
            let response_timeout =
                timeout_budget.phase(TimeoutPhase::ResponseHead, Some(HttpProtocol::Http2))?;
            let sent_headers = match client_hints {
                Some(context) => context.prepare(
                    headers.clone(),
                    lease.connection.accept_ch_for_origin(context.origin()),
                )?,
                None => headers.clone(),
            };
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
                    return Ok((
                        http::Response::from_parts(
                            parts,
                            // The stream count drops first, so the request the
                            // permit admits next sees this stream ended.
                            ResponseBody::http2_with_guard(body, (lease.stream, permit)),
                        ),
                        sent_headers,
                    ));
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
                    // The stream count drops before the permit, as on success.
                    drop(lease);
                    drop(permit);
                    return Err(RequestError::http2_stream(error));
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
            .get(&key, self.max_active, self.max_pending);
        #[cfg_attr(not(feature = "https-records"), allow(unused_mut))]
        let mut entry = PoolEntry::new(
            admission,
            Http2Spread::new(self.max_connections, self.max_active),
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

#[derive(Default)]
struct PoolState {
    entries: VecDeque<(PoolKey, Arc<PoolEntry>)>,
    admissions: AdmissionRegistry<PoolKey>,
}

fn invalidates_connection(error: &Http2Error) -> bool {
    matches!(
        error,
        Http2Error::Protocol(error)
            if error.kind() != Http2ProtocolErrorKind::StreamReset
    )
}

pub(super) fn is_graceful_goaway(error: &Http2Error) -> bool {
    matches!(
        error,
        Http2Error::Protocol(error)
            if error.kind() == Http2ProtocolErrorKind::ConnectionError
                && error.reason_code() == Some(0)
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PoolKey {
    host: Box<str>,
    port: u16,
    route: Route,
    mode: Http2ConnectionMode,
}

impl PoolKey {
    fn new(endpoint: &Endpoint, route: &Route, mode: Http2ConnectionMode) -> Self {
        Self {
            host: endpoint.host().to_ascii_lowercase().into(),
            port: endpoint.port(),
            route: route.clone(),
            mode,
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
            return connector
                .connect_direct_with_ech(endpoint.host(), endpoint.port(), endpoint.host(), ech)
                .await;
        }
        connector
            .connect_direct(endpoint.host(), endpoint.port(), endpoint.host())
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
        let connector = self
            .connector
            .get_or_init(|| connector.with_isolated_session_cache());
        let connection = match route {
            // One proxy connection per origin carries its forwarded requests;
            // the pool key keeps it apart from CONNECT tunnels.
            Route::HttpProxy(proxy) if mode == Http2ConnectionMode::Forward => {
                let base = https_proxy
                    .ok_or_else(|| RequestError::unsupported_route(HttpProtocol::Http2))?;
                let proxy_connector = self
                    .https_proxy
                    .get_or_init(|| proxy.https_connector(&base.with_isolated_session_cache()));
                proxy_connector
                    .connect_forward_http2(proxy.host(), proxy.port(), proxy.host())
                    .await
                    .map_err(|error| {
                        RequestError::http2_connection_setup(Http2TlsError::from(error))
                    })?
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
                        .map_err(RequestError::http2_connection_setup)?
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
                            .map_err(RequestError::http2_connection_setup)?
                    }
                } else {
                    if let Some(credentials) = proxy.basic_credentials() {
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
                        .map_err(RequestError::http2_connection_setup)?
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
                            .map_err(RequestError::http2_connection_setup)?
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
                    .map_err(RequestError::http2_connection_setup)?,
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
                    .map_err(RequestError::http2_connection_setup)?,
            },
        };
        Ok(reservation.finish(connection))
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
}
