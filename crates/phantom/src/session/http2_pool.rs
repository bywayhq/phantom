use std::{collections::VecDeque, num::NonZeroUsize, sync::Arc};

use bytes::Bytes;
use http::Method;
use phantom_net::http2::{
    Http2Connection, Http2Error, Http2ProtocolErrorKind, Http2TlsConnector, Http2TlsError,
    OriginForm, RequestHeader, validate_request,
};
use tokio::sync::Mutex;
use tracing::debug;

use super::admission::{Admission, AdmissionPermit, AdmissionRegistry};
use crate::{HttpProtocol, RequestError, ResponseBody, Route, authority::Endpoint};

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
        endpoint: &Endpoint,
        route: &Route,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<http::Response<ResponseBody>, RequestError> {
        validate_request(&method, authority, &target, &headers, body.as_ref())
            .map_err(Http2TlsError::from)
            .map_err(RequestError::http2)?;
        let key = PoolKey::new(endpoint, route);
        let entry = self.entry(key).await;
        let permit = entry.admit().await?;
        let lease = entry
            .acquire(connector, endpoint, route)
            .await
            .map_err(RequestError::http2)?;
        let result = lease
            .connection
            .send_request(method, authority, target, headers, body)
            .await;
        match result {
            Ok(response) => {
                let (parts, body) = response.into_parts();
                Ok(http::Response::from_parts(
                    parts,
                    ResponseBody::http2_with_guard(body, permit),
                ))
            }
            Err(error) => {
                drop(permit);
                if invalidates_connection(&error) {
                    entry.invalidate(&lease.token).await;
                }
                Err(RequestError::http2(error.into()))
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
}

impl PoolEntry {
    fn new(admission: Arc<Admission>) -> Self {
        Self {
            current: Mutex::new(None),
            admission,
        }
    }

    async fn admit(&self) -> Result<AdmissionPermit, RequestError> {
        Arc::clone(&self.admission).admit(HttpProtocol::Http2).await
    }

    async fn acquire(
        &self,
        connector: &Http2TlsConnector,
        endpoint: &Endpoint,
        route: &Route,
    ) -> Result<ConnectionLease, Http2TlsError> {
        let mut current = self.current.lock().await;
        if let Some(slot) = current.as_ref() {
            if slot.connection.is_reusable() {
                debug!(
                    outcome = "hit",
                    "HTTP/2 connection acquired from session pool"
                );
                return Ok(slot.lease());
            }
        }

        debug!(
            outcome = "connect",
            "HTTP/2 session pool opening connection"
        );
        let connection = match route {
            Route::Direct => {
                connector
                    .connect_direct(endpoint.host(), endpoint.port(), endpoint.host())
                    .await?
            }
            Route::HttpConnect(proxy) => {
                let connect_authority = endpoint.tunnel_authority();
                connector
                    .connect_http_connect(
                        proxy.host(),
                        proxy.port(),
                        &connect_authority,
                        proxy.ordered_connect_headers(),
                        endpoint.host(),
                    )
                    .await?
            }
            Route::Socks5(proxy) => match proxy.dns_mode() {
                crate::Socks5DnsMode::Local => {
                    connector
                        .connect_socks5_local(
                            proxy.host(),
                            proxy.port(),
                            endpoint.host(),
                            endpoint.port(),
                            endpoint.host(),
                        )
                        .await?
                }
                crate::Socks5DnsMode::Remote => {
                    connector
                        .connect_socks5_remote(
                            proxy.host(),
                            proxy.port(),
                            endpoint.host(),
                            endpoint.port(),
                            endpoint.host(),
                        )
                        .await?
                }
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
                "HTTP/2 session pool connection invalidated"
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
