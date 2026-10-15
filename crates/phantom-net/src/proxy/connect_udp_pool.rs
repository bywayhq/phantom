//! Bounded ownership of outer CONNECT-UDP sessions and tunnel admission.

use std::{
    fmt,
    num::NonZeroUsize,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};

use super::{HttpBasicCredentials, HttpsProxyConnector, http2_pool::ConnectionSettingsId};
use crate::{
    http2::Http2Connection,
    http3::{ConnectUdpError, ConnectUdpErrorKind, Http3Connection, Http3Connector},
    request::RequestHeader,
};

pub(crate) mod http3;

/// Most independently scoped outer sessions retained by a CONNECT-UDP pool.
///
/// Live keys are never evicted to admit another key. Idle keys may be forgotten.
pub const MAX_CONNECT_UDP_POOL_KEYS: usize = 32;

/// Outer proxy connections shared by CONNECT-UDP tunnels.
///
/// Clones share admission and connections. Each key retains one healthy H2 or
/// H3 session. Authentication, ordered fields, connector policies and runtime
/// isolate sessions. HTTP/1.1 Upgrade continues to use dedicated connections.
/// Resource limits apply to this pool, across its keys and protocols.
#[derive(Clone)]
pub struct ConnectUdpProxyPool {
    inner: Arc<dyn PoolState>,
}

impl Default for ConnectUdpProxyPool {
    fn default() -> Self {
        let limit = NonZeroUsize::new(100).unwrap_or(NonZeroUsize::MIN);
        Self::from_limits(limit, limit)
    }
}

impl ConnectUdpProxyPool {
    /// Creates a pool with at most 100 active tunnels and 100 queued opens.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a pool with explicit active and pending tunnel limits.
    ///
    /// Setup and peer stream-capacity waits count as active work. Overflow of
    /// the pending limit returns [`ConnectUdpErrorKind::Capacity`] immediately.
    ///
    /// # Errors
    ///
    /// Returns a configuration error if a limit exceeds Tokio's semaphore bound.
    pub fn with_limits(
        active: NonZeroUsize,
        pending: NonZeroUsize,
    ) -> Result<Self, ConnectUdpError> {
        if active.get() > Semaphore::MAX_PERMITS || pending.get() > Semaphore::MAX_PERMITS {
            return Err(ConnectUdpError::new(
                ConnectUdpErrorKind::Configuration,
                "CONNECT-UDP tunnel limits exceed the semaphore bound",
            ));
        }
        Ok(Self::from_limits(active, pending))
    }

    fn from_limits(active: NonZeroUsize, pending: NonZeroUsize) -> Self {
        Self {
            inner: Arc::new(Pool {
                active: Arc::new(Semaphore::new(active.get())),
                pending: Arc::new(Semaphore::new(pending.get())),
                maximum_active: active,
                maximum_pending: pending,
                entries: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Returns whether two handles own the same immutable route scope.
    #[doc(hidden)]
    #[must_use]
    pub fn shares_scope(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// Creates an empty independently scoped pool with the same limits.
    #[must_use]
    pub fn fresh(&self) -> Self {
        Self::from_limits(self.max_active(), self.max_pending())
    }

    /// Returns the active tunnel and setup limit.
    #[must_use]
    pub fn max_active(&self) -> NonZeroUsize {
        self.inner.state().maximum_active
    }

    /// Returns the queued tunnel-open limit.
    #[must_use]
    pub fn max_pending(&self) -> NonZeroUsize {
        self.inner.state().maximum_pending
    }

    /// Retires retained sessions while allowing existing tunnels to finish.
    ///
    /// Active keys and their admission counts remain registered. Pending setup
    /// owners cannot publish into the cleared generation.
    pub fn clear(&self) {
        for entry in lock(&self.inner.state().entries).iter() {
            let mut state = lock(&entry.state);
            state.generation = state.generation.wrapping_add(1);
            state.session = None;
            state.authenticated = false;
            state.http3_connector = None;
            state.http2_connector = None;
        }
    }

    pub(crate) async fn acquire(&self, key: PoolKey) -> Result<Acquisition, ConnectUdpError> {
        let permit = self.admit().await?;
        let entry = {
            let mut entries = lock(&self.inner.state().entries);
            if let Some(entry) = entries.iter().find(|entry| entry.key == key) {
                Arc::clone(entry)
            } else {
                if entries.len() == MAX_CONNECT_UDP_POOL_KEYS {
                    // A lease or setup owner holds an additional Arc. Never
                    // forget such a key and open a duplicate live connection.
                    if let Some(index) = entries
                        .iter()
                        .position(|entry| Arc::strong_count(entry) == 1)
                    {
                        entries.remove(index);
                    } else {
                        return Err(capacity());
                    }
                }
                let entry = Arc::new(Entry {
                    key,
                    state: Mutex::new(SessionState::default()),
                });
                entries.push(Arc::clone(&entry));
                entry
            }
        };
        let lease = TunnelLease {
            entry,
            generation: 0,
            _permit: permit,
            _pool: Arc::clone(&self.inner),
        };
        Self::acquire_entry(lease).await
    }

    async fn admit(&self) -> Result<OwnedSemaphorePermit, ConnectUdpError> {
        if let Ok(permit) = Arc::clone(&self.inner.state().active).try_acquire_owned() {
            return Ok(permit);
        }
        let pending = Arc::clone(&self.inner.state().pending)
            .try_acquire_owned()
            .map_err(|_| capacity())?;
        let active = Arc::clone(&self.inner.state().active)
            .acquire_owned()
            .await
            .map_err(|_| capacity())?;
        drop(pending);
        Ok(active)
    }

    async fn acquire_entry(mut lease: TunnelLease) -> Result<Acquisition, ConnectUdpError> {
        loop {
            let waiting = {
                let mut state = lock(&lease.entry.state);
                if let Some(session) = state
                    .session
                    .as_ref()
                    .filter(|session| state.can_reuse(session))
                {
                    let session = session.clone();
                    let authenticated = state.authenticated;
                    lease.generation = state.generation;
                    drop(state);
                    return Ok(Acquisition::Reuse {
                        session,
                        authenticated,
                        lease,
                    });
                }
                state.session = None;
                if let Some(waiting) = &state.connecting {
                    waiting.clone()
                } else {
                    let (finished, waiting) = watch::channel(None);
                    state.connecting = Some(waiting);
                    let generation = state.generation;
                    drop(state);
                    return Ok(Acquisition::Setup(SetupLease {
                        lease: Some(lease),
                        generation,
                        finished,
                    }));
                }
            };
            wait_for_setup(waiting).await?;
        }
    }
}

impl fmt::Debug for ConnectUdpProxyPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectUdpProxyPool")
            .field("max_active", &self.max_active())
            .field("max_pending", &self.max_pending())
            .field("retained_keys", &lock(&self.inner.state().entries).len())
            .finish()
    }
}

// Keep the retained transport types out of callers' Send and Sync proofs.
trait PoolState: Send + Sync + std::panic::RefUnwindSafe + std::panic::UnwindSafe {
    fn state(&self) -> &Pool;
}

struct Pool {
    active: Arc<Semaphore>,
    pending: Arc<Semaphore>,
    maximum_active: NonZeroUsize,
    maximum_pending: NonZeroUsize,
    entries: Mutex<Vec<Arc<Entry>>>,
}

impl PoolState for Pool {
    fn state(&self) -> &Pool {
        self
    }
}

#[derive(Clone, Eq)]
pub(crate) struct ProxySettingsId(Arc<()>);

impl Default for ProxySettingsId {
    fn default() -> Self {
        Self(Arc::new(()))
    }
}

impl PartialEq for ProxySettingsId {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl fmt::Debug for ProxySettingsId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProxySettingsId")
    }
}

#[derive(Clone, Eq, PartialEq)]
enum Settings {
    Http2(ConnectionSettingsId),
    Http3 {
        outer: ProxySettingsId,
        dial: ProxySettingsId,
    },
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PoolKey {
    settings: Settings,
    host: Box<str>,
    port: u16,
    authority: Box<str>,
    fields: Vec<RequestHeader>,
    credentials: Option<HttpBasicCredentials>,
    runtime: tokio::runtime::Id,
}

impl PoolKey {
    pub(crate) fn http2(
        connector: &HttpsProxyConnector,
        host: &str,
        port: u16,
        authority: &str,
        fields: &[RequestHeader],
        credentials: Option<&HttpBasicCredentials>,
    ) -> Result<Self, ConnectUdpError> {
        Self::new(
            Settings::Http2(connector.connect_udp_settings().clone()),
            host,
            port,
            authority,
            fields,
            credentials,
        )
    }

    pub(crate) fn http3(
        outer: &ProxySettingsId,
        dial: &ProxySettingsId,
        host: &str,
        port: u16,
        authority: &str,
        fields: &[RequestHeader],
        credentials: Option<&HttpBasicCredentials>,
    ) -> Result<Self, ConnectUdpError> {
        Self::new(
            Settings::Http3 {
                outer: outer.clone(),
                dial: dial.clone(),
            },
            host,
            port,
            authority,
            fields,
            credentials,
        )
    }

    fn new(
        settings: Settings,
        host: &str,
        port: u16,
        authority: &str,
        fields: &[RequestHeader],
        credentials: Option<&HttpBasicCredentials>,
    ) -> Result<Self, ConnectUdpError> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| {
                ConnectUdpError::new(
                    ConnectUdpErrorKind::RuntimeUnavailable,
                    "CONNECT-UDP pooling requires a Tokio runtime",
                )
            })?
            .id();
        Ok(Self {
            settings,
            host: host.to_ascii_lowercase().into(),
            port,
            authority: authority.into(),
            fields: fields.to_vec(),
            credentials: credentials.cloned(),
            runtime,
        })
    }
}

struct Entry {
    key: PoolKey,
    state: Mutex<SessionState>,
}

#[derive(Default)]
struct SessionState {
    session: Option<OuterSession>,
    authenticated: bool,
    generation: u64,
    http3_connector: Option<Arc<Http3Connector>>,
    http2_connector: Option<Arc<HttpsProxyConnector>>,
    connecting: Option<watch::Receiver<Option<SetupResult>>>,
}

#[derive(Clone)]
pub(crate) enum OuterSession {
    Http2(Http2Connection),
    Http3(Http3Connection),
}

impl SessionState {
    fn can_reuse(&self, session: &OuterSession) -> bool {
        match session {
            OuterSession::Http2(connection) => connection.can_wait_for_connect_udp(),
            OuterSession::Http3(connection) => self
                .http3_connector
                .as_ref()
                .is_some_and(|connector| connector.can_reuse_now(connection)),
        }
    }
}

pub(crate) enum Acquisition {
    Setup(SetupLease),
    Reuse {
        session: OuterSession,
        authenticated: bool,
        lease: TunnelLease,
    },
}

pub(crate) struct TunnelLease {
    entry: Arc<Entry>,
    generation: u64,
    _permit: OwnedSemaphorePermit,
    _pool: Arc<dyn PoolState>,
}

impl TunnelLease {
    pub(crate) fn http3_connector(&self, base: &Http3Connector) -> Arc<Http3Connector> {
        let mut state = lock(&self.entry.state);
        Arc::clone(
            state
                .http3_connector
                .get_or_insert_with(|| Arc::new(base.with_isolated_session_cache())),
        )
    }

    pub(crate) fn http2_connector(&self, base: &HttpsProxyConnector) -> Arc<HttpsProxyConnector> {
        let mut state = lock(&self.entry.state);
        Arc::clone(
            state
                .http2_connector
                .get_or_insert_with(|| Arc::new(base.with_isolated_session_cache())),
        )
    }

    /// Retires only the session that rejected this stream, not a newer one.
    pub(crate) async fn retry(self) -> Result<Acquisition, ConnectUdpError> {
        {
            let mut state = lock(&self.entry.state);
            if state.generation == self.generation && !state.authenticated {
                state.session = None;
                state.generation = state.generation.wrapping_add(1);
            }
        }
        ConnectUdpProxyPool::acquire_entry(self).await
    }
}

#[derive(Clone, Copy)]
enum SetupResult {
    Ready,
    Failed(ConnectUdpErrorKind),
    Canceled,
}

pub(crate) struct SetupLease {
    lease: Option<TunnelLease>,
    generation: u64,
    finished: watch::Sender<Option<SetupResult>>,
}

impl SetupLease {
    pub(crate) fn http3_connector(
        &self,
        base: &Http3Connector,
    ) -> Result<Arc<Http3Connector>, ConnectUdpError> {
        self.lease
            .as_ref()
            .map(|lease| lease.http3_connector(base))
            .ok_or_else(setup_stopped)
    }

    pub(crate) fn http2_connector(
        &self,
        base: &HttpsProxyConnector,
    ) -> Result<Arc<HttpsProxyConnector>, ConnectUdpError> {
        self.lease
            .as_ref()
            .map(|lease| lease.http2_connector(base))
            .ok_or_else(setup_stopped)
    }

    pub(crate) fn publish(
        mut self,
        session: OuterSession,
        authenticated: bool,
    ) -> Result<TunnelLease, ConnectUdpError> {
        let mut lease = self.lease.take().ok_or_else(setup_stopped)?;
        {
            let mut state = lock(&lease.entry.state);
            if state.generation == self.generation {
                state.generation = state.generation.wrapping_add(1);
                lease.generation = state.generation;
                state.session = Some(session);
                state.authenticated = authenticated;
            }
            state.connecting = None;
        }
        self.finished.send_replace(Some(SetupResult::Ready));
        Ok(lease)
    }

    pub(crate) fn fail(mut self, kind: ConnectUdpErrorKind) {
        if let Some(lease) = self.lease.take() {
            lock(&lease.entry.state).connecting = None;
            self.finished.send_replace(Some(SetupResult::Failed(kind)));
        }
    }
}

impl Drop for SetupLease {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            lock(&lease.entry.state).connecting = None;
            self.finished.send_replace(Some(SetupResult::Canceled));
        }
    }
}

async fn wait_for_setup(
    mut waiting: watch::Receiver<Option<SetupResult>>,
) -> Result<(), ConnectUdpError> {
    loop {
        match *waiting.borrow_and_update() {
            Some(SetupResult::Ready) => return Ok(()),
            Some(SetupResult::Failed(kind)) => {
                return Err(ConnectUdpError::new(
                    kind,
                    "shared CONNECT-UDP proxy setup failed",
                ));
            }
            Some(SetupResult::Canceled) => {
                return Err(ConnectUdpError::new(
                    ConnectUdpErrorKind::Protocol,
                    "shared CONNECT-UDP proxy setup was canceled",
                ));
            }
            None => {}
        }
        waiting.changed().await.map_err(|_| {
            ConnectUdpError::new(
                ConnectUdpErrorKind::Protocol,
                "shared CONNECT-UDP proxy setup stopped",
            )
        })?;
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn setup_stopped() -> ConnectUdpError {
    ConnectUdpError::new(
        ConnectUdpErrorKind::Protocol,
        "CONNECT-UDP setup ownership ended",
    )
}

fn capacity() -> ConnectUdpError {
    ConnectUdpError::new(
        ConnectUdpErrorKind::Capacity,
        "CONNECT-UDP pool admission or key capacity exceeded",
    )
}

#[cfg(test)]
mod tests;
