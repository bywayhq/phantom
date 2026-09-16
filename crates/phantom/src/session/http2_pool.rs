use std::{collections::VecDeque, num::NonZeroUsize, sync::Arc};

use phantom_net::http2::{
    Http2Connection, Http2Error, Http2ProtocolErrorKind, Http2TlsConnector, Http2TlsError,
    OriginForm, RequestHeader, validate_get,
};
use tokio::sync::Mutex;
use tracing::debug;

use crate::{ResponseBody, Route, authority::Endpoint};

pub(crate) struct Http2Pool {
    capacity: NonZeroUsize,
    entries: Mutex<VecDeque<(PoolKey, Arc<PoolEntry>)>>,
}

impl Http2Pool {
    pub(super) fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(VecDeque::new()),
        }
    }

    pub(super) const fn capacity(&self) -> NonZeroUsize {
        self.capacity
    }

    pub(crate) async fn send_get(
        &self,
        connector: &Http2TlsConnector,
        endpoint: &Endpoint,
        route: &Route,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<http::Response<ResponseBody>, Http2TlsError> {
        validate_get(authority, &target, &headers)?;
        let key = PoolKey::new(endpoint, route);
        let entry = self.entry(key).await;
        let lease = entry.acquire(connector, endpoint, route).await?;
        let result = lease.connection.send_get(authority, target, headers).await;
        match result {
            Ok(response) => {
                let (parts, body) = response.into_parts();
                Ok(http::Response::from_parts(parts, ResponseBody::http2(body)))
            }
            Err(error) => {
                if invalidates_connection(&error) {
                    entry.invalidate(&lease.token).await;
                }
                Err(error.into())
            }
        }
    }

    async fn entry(&self, key: PoolKey) -> Arc<PoolEntry> {
        let mut entries = self.entries.lock().await;
        if let Some(position) = entries.iter().position(|(candidate, _)| candidate == &key) {
            if let Some((stored_key, entry)) = entries.remove(position) {
                entries.push_back((stored_key, Arc::clone(&entry)));
                return entry;
            }
        }

        if entries.len() == self.capacity.get() {
            entries.pop_front();
            debug!(outcome = "evicted", "HTTP/2 pool entry evicted");
        }
        let entry = Arc::new(PoolEntry::default());
        entries.push_back((key, Arc::clone(&entry)));
        entry
    }
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

#[derive(Default)]
struct PoolEntry {
    current: Mutex<Option<ConnectionSlot>>,
}

impl PoolEntry {
    async fn acquire(
        &self,
        connector: &Http2TlsConnector,
        endpoint: &Endpoint,
        route: &Route,
    ) -> Result<ConnectionLease, Http2TlsError> {
        let mut current = self.current.lock().await;
        if let Some(slot) = current.as_ref() {
            if !slot.connection.is_closed() {
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
            Route::Socks5(proxy) => {
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
