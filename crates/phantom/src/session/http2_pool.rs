use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    sync::{Arc, OnceLock},
};

use http::Method;
use phantom_net::http2::{
    Http2Body, Http2Connection, Http2Error, Http2ProtocolErrorKind, Http2TlsConnector,
    Http2TlsError, OriginForm, RequestHeader, validate_request_body_source_with_trailers,
};
use phantom_net::proxy::HttpsProxyConnector;
use phantom_net::request::RequestBody;
use phantom_profile::Http2Priority;
use tokio::sync::Mutex;
use tracing::debug;

use super::{
    admission::{Admission, AdmissionPermit, AdmissionRegistry},
    client_hints::ClientHintContext,
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
    state: Mutex<PoolState>,
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
                            ResponseBody::http2_with_guard(body, permit),
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
                    drop(permit);
                    return Err(RequestError::http2_stream(error));
                }
                Err(error) => {
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
    current: Mutex<Option<ConnectionSlot>>,
    admission: Arc<Admission>,
    connector: OnceLock<Http2TlsConnector>,
    https_proxy: OnceLock<HttpsProxyConnector>,
}

impl PoolEntry {
    fn new(admission: Arc<Admission>) -> Self {
        Self {
            current: Mutex::new(None),
            admission,
            connector: OnceLock::new(),
            https_proxy: OnceLock::new(),
        }
    }

    async fn admit(&self) -> Result<AdmissionPermit, RequestError> {
        Arc::clone(&self.admission).admit(HttpProtocol::Http2).await
    }

    #[cfg(feature = "websocket")]
    async fn current_reusable(&self) -> Option<Http2Connection> {
        let current = self.current.lock().await;
        current
            .as_ref()
            .filter(|slot| slot.connection.is_reusable())
            .map(|slot| slot.connection.clone())
    }

    async fn acquire(
        &self,
        connector: &Http2TlsConnector,
        https_proxy: Option<&HttpsProxyConnector>,
        endpoint: &Endpoint,
        route: &Route,
        mode: Http2ConnectionMode,
    ) -> Result<ConnectionLease, RequestError> {
        let mut current = self.current.lock().await;
        if let Some(slot) = current.as_ref()
            && slot.connection.is_reusable()
        {
            debug!(
                outcome = "hit",
                "HTTP/2 connection acquired from client pool"
            );
            return Ok(slot.lease());
        }

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
            Route::Direct => connector
                .connect_direct(endpoint.host(), endpoint.port(), endpoint.host())
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
        let slot = ConnectionSlot {
            connection,
            token: Arc::new(()),
        };
        let lease = slot.lease();
        *current = Some(slot);
        Ok(lease)
    }

    async fn invalidate(&self, token: &Arc<()>) {
        let mut current = self.current.lock().await;
        if current
            .as_ref()
            .is_some_and(|slot| Arc::ptr_eq(&slot.token, token))
        {
            current.take();
            debug!(
                outcome = "invalidated",
                "HTTP/2 client pool connection invalidated"
            );
        }
    }
}

struct ConnectionSlot {
    connection: Http2Connection,
    token: Arc<()>,
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
    connection: Http2Connection,
    token: Arc<()>,
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroUsize, sync::Arc};

    use super::{Http2Pool, PoolKey};
    use crate::{Route, authority::Endpoint};

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
