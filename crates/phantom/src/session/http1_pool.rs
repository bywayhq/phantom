use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    sync::{Arc, OnceLock},
};

use bytes::Bytes;
use http::Method;
use phantom_net::http1::{
    Http1Connection, Http1TlsConnector, Http1TlsError, OriginForm, RequestHeader, validate_request,
};
use phantom_net::proxy::HttpsProxyConnector;
use tokio::sync::Mutex;
use tracing::debug;

use super::admission::{Admission, AdmissionPermit, AdmissionRegistry};
use crate::{HttpProtocol, RequestError, ResponseBody, Route, authority::Endpoint};

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
        method: Method,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<http::Response<ResponseBody>, RequestError> {
        validate_request(&method, &target, &headers, body.as_ref())
            .map_err(Http1TlsError::from)
            .map_err(RequestError::http1)?;
        if route.as_http_proxy().is_some_and(|proxy| proxy.uses_tls()) && https_proxy.is_none() {
            return Err(RequestError::unsupported_route(HttpProtocol::Http1));
        }
        let key = PoolKey::new(endpoint, route);
        let entry = self.entry(key).await;
        let permit = entry.admit().await?;
        let lease = entry
            .acquire(connector, https_proxy, endpoint, route)
            .await?;
        let result = lease
            .connection
            .send_request(method, target, headers, body)
            .await;
        match result {
            Ok(response) => {
                let (parts, body) = response.into_parts();
                Ok(http::Response::from_parts(
                    parts,
                    ResponseBody::http1_with_guard(body, permit),
                ))
            }
            Err(error) => {
                drop(permit);
                if !lease.connection.is_reusable() {
                    entry.invalidate(&lease.token).await;
                }
                Err(RequestError::http1(error.into()))
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
    ) -> Result<ConnectionLease, RequestError> {
        let mut current = self.current.lock().await;
        if let Some(slot) = current.as_ref() {
            if slot.connection.is_reusable() {
                debug!(
                    outcome = "hit",
                    "HTTP/1 connection acquired from session pool"
                );
                return Ok(slot.lease());
            }
        }

        debug!(
            outcome = "connect",
            "HTTP/1 session pool opening connection"
        );
        let connector = self
            .connector
            .get_or_init(|| connector.with_isolated_session_cache());
        let connection = match route {
            Route::Direct => connector
                .connect_direct(endpoint.host(), endpoint.port(), endpoint.host())
                .await
                .map_err(RequestError::http1)?,
            Route::HttpConnect(proxy) => {
                let connect_authority = endpoint.tunnel_authority();
                if proxy.uses_tls() {
                    let base = https_proxy
                        .ok_or_else(|| RequestError::unsupported_route(HttpProtocol::Http1))?;
                    let proxy_connector = self
                        .https_proxy
                        .get_or_init(|| base.with_isolated_session_cache());
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
                        .map_err(RequestError::http1)?
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
                        .map_err(RequestError::http1)?
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
                    .map_err(RequestError::http1)?,
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
                    .map_err(RequestError::http1)?,
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
                "HTTP/1 session connection invalidated"
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

    use super::{Http1Pool, PoolKey};
    use crate::{Route, authority::Endpoint};

    #[tokio::test]
    async fn per_origin_admission_survives_lru_eviction() -> Result<(), Box<dyn std::error::Error>>
    {
        let one = NonZeroUsize::MIN;
        let pool = Http1Pool::new(one, one);
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
}
