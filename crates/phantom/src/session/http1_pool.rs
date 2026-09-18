use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    sync::{Arc, OnceLock},
};

use http::Method;
use phantom_net::http1::{
    AbsoluteForm, Http1Connection, Http1TlsConnector, Http1TlsError, OriginForm, RequestHeader,
    validate_forward_request_body_source_with_trailers, validate_request_body_source_with_trailers,
};
use phantom_net::proxy::HttpsProxyConnector;
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

pub(crate) struct Http1Pool {
    capacity: NonZeroUsize,
    max_pending: NonZeroUsize,
    state: Mutex<PoolState>,
}

impl Http1Pool {
    pub(super) fn new(capacity: NonZeroUsize, max_pending: NonZeroUsize) -> Self {
        Self {
            capacity,
            max_pending,
            state: Mutex::new(PoolState::default()),
        }
    }

    pub(super) const fn capacity(&self) -> NonZeroUsize {
        self.capacity
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
        timeout_budget: TimeoutBudget,
        retries: &mut ConnectionSetupRetryState,
    ) -> Result<http::Response<ResponseBody>, RequestError> {
        let mut authenticated_headers = None;
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
            if let Some(credentials) = route
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
                authenticated_headers = Some(candidate);
            }
            Ok(())
        })();
        validation
            .map_err(Http1TlsError::from)
            .map_err(RequestError::http1)?;
        let headers = if forward_authorization {
            authenticated_headers
                .ok_or_else(|| RequestError::unsupported_route(HttpProtocol::Http1))?
        } else {
            headers
        };
        if route.as_http_proxy().is_some_and(|proxy| proxy.uses_tls()) && https_proxy.is_none() {
            return Err(RequestError::unsupported_route(HttpProtocol::Http1));
        }
        let key = PoolKey::new(endpoint, route, mode);
        let entry = self.entry(key).await;
        let permit = timeout_budget
            .run(
                TimeoutPhase::PoolAdmission,
                Some(HttpProtocol::Http1),
                entry.admit(),
            )
            .await?;
        let lease = acquire_with_retries(HttpProtocol::Http1, timeout_budget, retries, || async {
            entry
                .acquire(
                    connector,
                    https_proxy,
                    endpoint,
                    route,
                    mode,
                    forward_authorization,
                )
                .await
        })
        .await?;
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
                    // A zero-length 407 may already have released its transport
                    // lease as reusable. Retire the generation before exposing
                    // the response so an authentication retry must reconnect.
                    entry.invalidate(&lease.token).await;
                }
                let (parts, body) = response.into_parts();
                Ok(http::Response::from_parts(
                    parts,
                    ResponseBody::http1_with_guard(body, permit),
                ))
            }
            Ok(Err(error)) => {
                drop(permit);
                if !lease.connection.is_reusable() {
                    entry.invalidate(&lease.token).await;
                }
                Err(RequestError::http1(error.into()))
            }
            Err(error) => {
                drop(permit);
                entry.invalidate(&lease.token).await;
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
        {
            if let Some((stored_key, entry)) = state.entries.remove(position) {
                state.entries.push_back((stored_key, Arc::clone(&entry)));
                return entry;
            }
        }

        if state.entries.len() == self.capacity.get() {
            state.entries.pop_front();
            debug!(outcome = "evicted", "HTTP/1 pool entry evicted");
        }
        let admission = state
            .admissions
            .get(&key, NonZeroUsize::MIN, self.max_pending);
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
    current: Mutex<Option<ConnectionSlot>>,
    admission: Arc<Admission>,
    connector: OnceLock<Http1TlsConnector>,
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
        Arc::clone(&self.admission).admit(HttpProtocol::Http1).await
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
        let mut current = self.current.lock().await;
        if !force_new_connection {
            if let Some(slot) = current.as_ref() {
                if slot.connection.is_reusable() {
                    debug!(
                        outcome = "hit",
                        "HTTP/1 connection acquired from client pool"
                    );
                    return Ok(slot.lease());
                }
            }
        } else if current.take().is_some() {
            debug!(
                outcome = "authentication_retry",
                "HTTP/1 pooled connection retired before authenticated retry"
            );
        }

        debug!(outcome = "connect", "HTTP/1 client pool opening connection");
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
                        .get_or_init(|| base.with_isolated_session_cache());
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
            Http1ConnectionMode::PlaintextOrigin => {
                if !matches!(route, Route::Direct) {
                    return Err(RequestError::unsupported_route(HttpProtocol::Http1));
                }
                connector
                    .connect_plaintext_direct(endpoint.host(), endpoint.port())
                    .await
                    .map_err(RequestError::http1_connection_setup)?
            }
            Http1ConnectionMode::TlsOrigin => {
                let connector = self
                    .connector
                    .get_or_init(|| connector.with_isolated_session_cache());
                match route {
                    Route::Direct => connector
                        .connect_direct(endpoint.host(), endpoint.port(), endpoint.host())
                        .await
                        .map_err(RequestError::http1_connection_setup)?,
                    Route::HttpProxy(proxy) => {
                        let connect_authority = endpoint.tunnel_authority();
                        if proxy.uses_tls() {
                            let base = https_proxy.ok_or_else(|| {
                                RequestError::unsupported_route(HttpProtocol::Http1)
                            })?;
                            let proxy_connector = self
                                .https_proxy
                                .get_or_init(|| base.with_isolated_session_cache());
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
                "HTTP/1 pooled connection invalidated"
            );
        }
    }
}

struct ConnectionSlot {
    connection: Http1Connection,
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
    connection: Http1Connection,
    token: Arc<()>,
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroUsize, sync::Arc};

    use super::{Http1ConnectionMode, Http1Pool, PoolKey};
    use crate::{Route, authority::Endpoint};

    #[tokio::test]
    async fn per_origin_admission_survives_lru_eviction() -> Result<(), Box<dyn std::error::Error>>
    {
        let one = NonZeroUsize::MIN;
        let pool = Http1Pool::new(one, one);
        let first = Endpoint::new("first.test:443".parse()?, 443)?;
        let second = Endpoint::new("second.test:443".parse()?, 443)?;

        let first_entry = pool
            .entry(PoolKey::new(
                &first,
                &Route::Direct,
                Http1ConnectionMode::TlsOrigin,
            ))
            .await;
        let permit = first_entry.admit().await?;
        pool.entry(PoolKey::new(
            &second,
            &Route::Direct,
            Http1ConnectionMode::TlsOrigin,
        ))
        .await;
        drop(first_entry);
        let replacement = pool
            .entry(PoolKey::new(
                &first,
                &Route::Direct,
                Http1ConnectionMode::TlsOrigin,
            ))
            .await;

        assert!(Arc::ptr_eq(permit.admission(), &replacement.admission));
        assert_eq!(replacement.admission.available_active(), 0);
        drop(permit);
        assert_eq!(replacement.admission.available_active(), 1);
        Ok(())
    }
}
