use std::{collections::VecDeque, num::NonZeroUsize, sync::Arc};

use bytes::Bytes;
use http::Method;
use phantom_net::http3::{Http3Connection, Http3Connector, OriginForm, RequestHeader};
use tokio::sync::Mutex;
use tracing::debug;

use super::{
    admission::{Admission, AdmissionPermit, AdmissionRegistry},
    client_hints::ClientHintContext,
};
use crate::{HttpProtocol, RequestError, ResponseBody, Route, authority::Endpoint};

pub(crate) struct Http3Pool {
    capacity: NonZeroUsize,
    max_active: NonZeroUsize,
    max_pending: NonZeroUsize,
    state: Mutex<PoolState>,
}

impl Http3Pool {
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
        connector: &Http3Connector,
        endpoint: &Endpoint,
        route: &Route,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        client_hints: Option<ClientHintContext<'_>>,
        body: Option<Bytes>,
    ) -> Result<(http::Response<ResponseBody>, Vec<RequestHeader>), RequestError> {
        let prepared_validation_headers =
            client_hints.map(|context| context.prepare(headers.clone(), None));
        let validation_headers = prepared_validation_headers.as_deref().unwrap_or(&headers);
        connector
            .validate_request(
                method.clone(),
                authority,
                &target,
                validation_headers,
                body.as_ref(),
            )
            .map_err(RequestError::http3)?;
        if !matches!(route, Route::Direct) {
            return Err(RequestError::unsupported_route(HttpProtocol::Http3));
        }

        let key = PoolKey::new(endpoint, route);
        let entry = self.entry(key).await;
        let permit = entry.admit().await?;
        let lease = entry.acquire(connector, endpoint).await?;
        let sent_headers = match client_hints {
            Some(context) => context.prepare(
                headers,
                lease.connection.accept_ch_for_origin(context.origin()),
            ),
            None => headers,
        };
        let result = connector
            .send_request_on(
                &lease.connection,
                method,
                authority,
                target,
                sent_headers.clone(),
                body,
            )
            .await;
        match result {
            Ok(response) => {
                let (parts, body) = response.into_parts();
                Ok((
                    http::Response::from_parts(parts, ResponseBody::http3_with_guard(body, permit)),
                    sent_headers,
                ))
            }
            Err(error) => {
                drop(permit);
                if !connector.can_reuse(&lease.connection).await {
                    entry.invalidate(&lease.token).await;
                }
                Err(RequestError::http3(error))
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
            debug!(outcome = "evicted", "HTTP/3 pool entry evicted");
        }
        let admission = state.admission(&key, self.max_active, self.max_pending);
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

impl PoolState {
    fn admission(
        &mut self,
        key: &PoolKey,
        max_active: NonZeroUsize,
        max_pending: NonZeroUsize,
    ) -> Arc<Admission> {
        self.admissions.get(key, max_active, max_pending)
    }
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
        Arc::clone(&self.admission).admit(HttpProtocol::Http3).await
    }

    async fn acquire(
        &self,
        connector: &Http3Connector,
        endpoint: &Endpoint,
    ) -> Result<ConnectionLease, RequestError> {
        let mut current = self.current.lock().await;
        if let Some(slot) = current.as_ref() {
            if connector.can_reuse(&slot.connection).await {
                debug!(
                    outcome = "hit",
                    "HTTP/3 connection acquired from client pool"
                );
                return Ok(slot.lease());
            }
        }

        debug!(outcome = "connect", "HTTP/3 client pool opening connection");
        let connection = connector
            .connect_direct(endpoint.host(), endpoint.port(), endpoint.host())
            .await
            .map_err(RequestError::http3)?;
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
                "HTTP/3 pool connection invalidated"
            );
        }
    }
}

struct ConnectionSlot {
    connection: Http3Connection,
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
    connection: Http3Connection,
    token: Arc<()>,
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroUsize, sync::Arc};

    use super::{Http3Pool, PoolKey};
    use crate::{Route, authority::Endpoint};

    #[tokio::test]
    async fn per_origin_admission_survives_lru_eviction() -> Result<(), Box<dyn std::error::Error>>
    {
        let one = NonZeroUsize::MIN;
        let pool = Http3Pool::new(one, one, one);
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
