//! HTTP/2 connections to HTTPS proxies that carry many CONNECT tunnels.
//!
//! Shares one connection per proxy route by default. The HTTP/2 layer queues
//! CONNECTs at the proxy's stream limit until another stream ends. A caller
//! may allow more connections per route.
//!
//! The pool never holds its lock across an `.await`. One connection setup
//! runs at a time per route; other tunnels wait for it rather than open
//! their own. Waiters receive that setup attempt's failure.

use std::{
    fmt,
    future::Future,
    num::NonZeroUsize,
    pin::pin,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
};

use tokio::sync::{Notify, watch};
use tracing::debug;

use super::{
    HttpConnectError, HttpConnectErrorKind, HttpProxyAuthentication, HttpProxyCredentials,
};
use crate::{http2::Http2Connection, tcp::AddressFamilyMemory};

mod idle;

/// Tunnels one HTTP/2 proxy connection carries before a pool that allows
/// more than one connection per route opens another.
///
/// This is Phantom's choice, not a browser value, and applies only after
/// [`Http2ProxyPool::with_max_connections_per_route`]. A connection is also
/// full at the proxy's `SETTINGS_MAX_CONCURRENT_STREAMS`, when that is
/// lower. The default pool keeps one connection per route and runtime and
/// never applies it.
pub const MAX_TUNNELS_PER_HTTP2_PROXY_CONNECTION: usize = 100;

/// Most HTTP/2 connections
/// [`Http2ProxyPool::with_max_connections_per_route`] allows per proxy
/// route; a larger request is lowered to it.
pub const HTTP2_PROXY_CONNECTIONS_PER_ROUTE_CEILING: usize = 8;

/// Most proxy routes a pool keeps connections for.
///
/// A new route beyond this forgets the least recently used one. Tunnels
/// already open on its connections are unaffected.
pub const MAX_HTTP2_PROXY_POOL_ROUTES: usize = 32;

/// HTTP/2 connections to HTTPS proxies, shared by the CONNECT tunnels of
/// one route.
///
/// Attach a pool with [`HttpsProxyConnector::with_http2_proxy_pool`]. A
/// tunnel then becomes the next stream of a pooled connection to the same
/// proxy host, port, and TLS server name, opened by a connector with the
/// same TLS, TCP, HTTP/2, and name-resolution settings, for a route with the
/// same credential scheme, values and policy, or none. Without a pool, every
/// tunnel opens its own connection.
///
/// A route keeps one connection, as browsers do. Every tunnel goes on it;
/// past the proxy's `SETTINGS_MAX_CONCURRENT_STREAMS`, the HTTP/2 layer
/// holds the CONNECT until another stream on the connection ends. Once the
/// proxy sends `GOAWAY` or the connection closes, the next tunnel opens a new
/// one. [`Self::with_max_connections_per_route`] lets a route open more.
/// Each open tunnel keeps its connection alive, whether or not the pool
/// still holds it. Closing or resetting a tunnel ends only its own stream.
///
/// A connection's driver runs on the Tokio runtime that opened it, so a
/// route keeps its connections per runtime: a tunnel on another runtime
/// opens a connection of its own.
///
/// When a connection setup fails, every tunnel that was waiting for it fails
/// with an [`HttpConnectError::PooledSetupFailed`] of the same kind, rather
/// than each trying again in turn.
///
/// Clones share one pool. It holds at most
/// [`MAX_HTTP2_PROXY_POOL_ROUTES`] routes. A timer stops reusing a connection
/// past its read-idle limit ([`Http2Settings::idle_timeout`]), even without
/// another tunnel opening. Existing streams and caller-owned connection
/// handles keep it alive until they end. Without an idle limit, the pool
/// keeps it until the proxy closes it or its route is forgotten.
///
/// [`Http2Settings::idle_timeout`]: phantom_profile::Http2Settings::idle_timeout
/// [`HttpsProxyConnector::with_http2_proxy_pool`]: super::HttpsProxyConnector::with_http2_proxy_pool
#[derive(Clone)]
pub struct Http2ProxyPool {
    routes: Arc<Mutex<Routes>>,
    max_connections: NonZeroUsize,
}

impl Default for Http2ProxyPool {
    fn default() -> Self {
        Self {
            routes: Arc::default(),
            max_connections: NonZeroUsize::MIN,
        }
    }
}

impl Http2ProxyPool {
    /// Replaces retained proxy connections while existing owners finish.
    ///
    /// Later acquisitions use new connections. Pending setup, forwarding
    /// handles and tunnels keep their previous route owner. Clones share this
    /// operation. Driver shutdown remains asynchronous.
    pub fn refresh_connections(&self) {
        let mut previous = Vec::new();
        {
            let mut routes = self.lock();
            for entry in &mut routes.entries {
                let fresh = Arc::new(RouteConnections {
                    family: entry.connections.family.clone(),
                    ..RouteConnections::default()
                });
                previous.push(std::mem::replace(&mut entry.connections, fresh));
            }
        }
        drop(previous);
    }

    /// Releases retained connections with no request or tunnel owners.
    ///
    /// Clones share this operation. Pending setup and active streams keep
    /// working. Route configuration and session-ticket caches are retained.
    /// Physical driver shutdown completes asynchronously.
    pub fn close_idle_connections(&self) {
        let mut retired = Vec::new();
        {
            let routes = self.lock();
            for route in &routes.entries {
                let mut state = route.connections.lock();
                let mut index = 0;
                while index < state.slots.len() {
                    let connection = &state.slots[index].connection;
                    if connection.is_exclusively_owned() && !connection.early_data_pending() {
                        retired.push(state.slots.remove(index));
                    } else {
                        index += 1;
                    }
                }
            }
        }
        drop(retired);
    }

    /// Creates an empty pool that keeps one connection per route and runtime.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty pool that opens up to `maximum` connections per
    /// route, at most [`HTTP2_PROXY_CONNECTIONS_PER_ROUTE_CEILING`].
    ///
    /// A route opens another connection only when each one it has carries
    /// [`MAX_TUNNELS_PER_HTTP2_PROXY_CONNECTION`] tunnels, or the proxy's
    /// `SETTINGS_MAX_CONCURRENT_STREAMS` when that is lower; at `maximum`, a
    /// new tunnel takes the least loaded connection and waits there. A
    /// tunnel then does not wait behind long-lived tunnels while another
    /// connection could open, but a proxy can see more connections than a
    /// browser opens: Chromium and Firefox keep one per proxy and queue
    /// streams on it.
    #[must_use]
    pub fn with_max_connections_per_route(maximum: NonZeroUsize) -> Self {
        let ceiling = NonZeroUsize::new(HTTP2_PROXY_CONNECTIONS_PER_ROUTE_CEILING)
            .unwrap_or(NonZeroUsize::MIN);
        Self {
            routes: Arc::default(),
            max_connections: maximum.min(ceiling),
        }
    }

    /// Returns how many connections a route may open.
    #[must_use]
    pub fn max_connections_per_route(&self) -> NonZeroUsize {
        self.max_connections
    }

    fn lock(&self) -> MutexGuard<'_, Routes> {
        self.routes.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn route(&self, key: RouteKey) -> Arc<RouteConnections> {
        let mut routes = self.lock();
        routes.clock += 1;
        let now = routes.clock;
        if let Some(entry) = routes.entries.iter_mut().find(|entry| entry.key == key) {
            entry.last_used = now;
            return Arc::clone(&entry.connections);
        }
        if routes.entries.len() == MAX_HTTP2_PROXY_POOL_ROUTES
            && let Some(oldest) = routes
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(index, _)| index)
        {
            routes.entries.swap_remove(oldest);
            debug!(outcome = "evicted", "HTTP/2 proxy pool route evicted");
        }
        let connections = Arc::new(RouteConnections::default());
        routes.entries.push(RouteEntry {
            key,
            last_used: now,
            connections: Arc::clone(&connections),
        });
        connections
    }

    /// Returns a pooled connection with room for one more tunnel, or opens
    /// one with `open`.
    pub(super) async fn acquire<F, Fut>(
        &self,
        key: RouteKey,
        open: F,
    ) -> Result<PooledConnection, HttpConnectError>
    where
        F: FnOnce(AddressFamilyMemory) -> Fut,
        Fut: Future<Output = Result<Http2Connection, HttpConnectError>>,
    {
        let route = self.route(key);
        // The setup attempt this tunnel last waited for.
        let mut waited_for: Option<watch::Receiver<Option<HttpConnectErrorKind>>> = None;
        let reservation = loop {
            let mut changed = pin!(route.changed.notified());
            // Registered before the check, so a setup that finishes in
            // between still wakes this tunnel.
            changed.as_mut().enable();
            {
                let mut state = route.lock();
                if let Some(kind) = waited_for.as_ref().and_then(|attempt| *attempt.borrow()) {
                    return Err(HttpConnectError::PooledSetupFailed { kind });
                }

                if state.idle_failed {
                    // Surface a failed background rearm before a caller can
                    // explicitly retry and establish a newly timed connection.
                    state.idle_failed = false;
                    return Err(HttpConnectError::RuntimeUnavailable);
                }

                let retired = state.prune();
                if let Choice::Use(index) = state.choose(self.max_connections.get())
                    && let Some(slot) = state.slots.get(index)
                {
                    let lease = slot.lease(&route, true);
                    drop(state);
                    drop(retired);
                    debug!(outcome = "hit", "HTTP/2 proxy connection reused");
                    return Ok(lease);
                }
                if state.connecting.is_none() {
                    let (failed, attempt) = watch::channel(None);
                    state.connecting = Some(attempt);
                    drop(state);
                    drop(retired);
                    break SetupReservation {
                        route: &route,
                        failed,
                        finished: false,
                    };
                }
                waited_for = state.connecting.clone();
                drop(state);
                drop(retired);
            }
            changed.await;
        };
        debug!(outcome = "connect", "HTTP/2 proxy pool opening connection");
        match open(route.family.clone()).await {
            Ok(connection) => reservation.finish(connection),
            Err(error) => {
                reservation.fail(error.kind());
                Err(error)
            }
        }
    }
}

impl fmt::Debug for Http2ProxyPool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http2ProxyPool")
            .field("routes", &self.lock().entries.len())
            .finish()
    }
}

#[derive(Default)]
struct Routes {
    entries: Vec<RouteEntry>,
    clock: u64,
}

struct RouteEntry {
    key: RouteKey,
    last_used: u64,
    connections: Arc<RouteConnections>,
}

/// What must match for two tunnels to share a proxy connection.
///
/// `settings` identifies the connector settings a connection was opened
/// with; see [`ConnectionSettingsId`]. `authorization` is the route's
/// credential scheme, values and policy, so routes with other credentials,
/// or none, never share a connection. `runtime` is the runtime the tunnel's
/// task runs on: a connection's driver runs on the runtime that opened it and stops
/// being polled once that runtime is dropped or no longer driven.
#[derive(Clone, Eq, PartialEq)]
pub(super) struct RouteKey {
    settings: ConnectionSettingsId,
    host: Box<str>,
    port: u16,
    server_name: Box<str>,
    authorization: Option<HttpProxyCredentials>,
    runtime: Option<tokio::runtime::Id>,
}

impl RouteKey {
    pub(super) fn new(
        settings: &ConnectionSettingsId,
        host: &str,
        port: u16,
        server_name: &str,
        credentials: Option<HttpProxyAuthentication<'_>>,
    ) -> Self {
        Self {
            settings: settings.clone(),
            host: host.to_ascii_lowercase().into(),
            port,
            server_name: server_name.to_ascii_lowercase().into(),
            authorization: credentials.map(HttpProxyAuthentication::to_owned),
            runtime: tokio::runtime::Handle::try_current()
                .ok()
                .map(|runtime| runtime.id()),
        }
    }
}

/// Identifies one set of connector settings that shape a proxy connection.
///
/// A connector gets a new identity whenever a builder method changes how it
/// opens a proxy connection, and clones keep it, so a pool never hands one
/// connector a connection another connector opened differently.
#[derive(Clone, Default)]
pub(super) struct ConnectionSettingsId(Arc<()>);

impl PartialEq for ConnectionSettingsId {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for ConnectionSettingsId {}

impl fmt::Debug for ConnectionSettingsId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectionSettingsId")
    }
}

/// One route's connections, oldest first.
#[derive(Default)]
struct RouteConnections {
    state: Mutex<RouteState>,
    /// The physical proxy's family, shared by this keyed route's setups.
    /// Keep it through slot retirement: forwarding handles can outlive slots.
    /// A route recreated after bounded LRU eviction starts with fresh memory.
    family: AddressFamilyMemory,
    /// Woken when a setup finishes, fails, or is cancelled, and when a
    /// tunnel ends.
    changed: Notify,
    #[cfg(test)]
    fail_next_deadline: std::sync::atomic::AtomicBool,
}

impl RouteConnections {
    fn lock(&self) -> MutexGuard<'_, RouteState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[derive(Default)]
struct RouteState {
    slots: Vec<Slot>,
    /// The route's current setup, whose failure remains owned by its waiters
    /// after a later setup replaces it. Success and cancellation close the
    /// channel without a failure; waiters then reuse or open a connection.
    connecting: Option<watch::Receiver<Option<HttpConnectErrorKind>>>,
    idle: Option<idle::Deadline>,
    /// A background rearm failed. The next acquisition observes the failure
    /// before an explicit subsequent call can attempt a new setup.
    idle_failed: bool,
}

enum Choice {
    Use(usize),
    Open,
}

impl RouteState {
    /// Chooses the oldest connection with room for another tunnel.
    ///
    /// A connection's room is the lower of
    /// [`MAX_TUNNELS_PER_HTTP2_PROXY_CONNECTION`] and the proxy's
    /// `SETTINGS_MAX_CONCURRENT_STREAMS`; its load is the tunnels the pool
    /// handed it that have not ended. Forwarded requests are short and are
    /// not counted. When none has room, the route opens another connection
    /// below `max_connections`, or else uses the least loaded, where the
    /// HTTP/2 layer holds the CONNECT until another stream ends. With one
    /// connection allowed, the route's connection always takes the tunnel.
    fn choose(&self, max_connections: usize) -> Choice {
        let mut least_loaded: Option<(usize, usize)> = None;
        for (index, slot) in self.slots.iter().enumerate() {
            let room = slot
                .connection
                .peer_max_concurrent_streams()
                .map_or(MAX_TUNNELS_PER_HTTP2_PROXY_CONNECTION, |peer| {
                    peer.min(MAX_TUNNELS_PER_HTTP2_PROXY_CONNECTION)
                });
            let load = slot.load();
            if load < room {
                return Choice::Use(index);
            }
            if least_loaded.is_none_or(|(_, fewest)| load < fewest) {
                least_loaded = Some((index, load));
            }
        }
        match least_loaded {
            Some((index, _)) if self.slots.len() >= max_connections => Choice::Use(index),
            _ => Choice::Open,
        }
    }
}

struct Slot {
    connection: Http2Connection,
    tunnels: Arc<AtomicUsize>,
}

impl Slot {
    fn load(&self) -> usize {
        self.tunnels.load(Ordering::Acquire)
    }

    fn lease(&self, route: &Arc<RouteConnections>, reused: bool) -> PooledConnection {
        self.tunnels.fetch_add(1, Ordering::AcqRel);
        PooledConnection {
            connection: self.connection.clone(),
            tunnel: TunnelCount {
                tunnels: Arc::clone(&self.tunnels),
                route: Arc::clone(route),
            },
            reused,
        }
    }
}

/// The route's one connection setup in flight.
///
/// A failed setup fails every tunnel that waited for it. Dropping it
/// unfinished, when the tunnel is cancelled, frees the setup and wakes
/// every tunnel waiting for it; whichever runs first makes the next attempt.
struct SetupReservation<'a> {
    route: &'a Arc<RouteConnections>,
    failed: watch::Sender<Option<HttpConnectErrorKind>>,
    finished: bool,
}

impl SetupReservation<'_> {
    fn finish(mut self, connection: Http2Connection) -> Result<PooledConnection, HttpConnectError> {
        let mut state = self.route.lock();
        if state.idle_failed {
            state.idle_failed = false;
            drop(state);
            self.fail(HttpConnectErrorKind::RuntimeUnavailable);
            return Err(HttpConnectError::RuntimeUnavailable);
        }

        let slot = Slot {
            connection,
            tunnels: Arc::default(),
        };
        // Arm before publishing the lease or successful setup. A route with
        // a required idle limit cannot succeed without its timer.
        let lease = slot.lease(self.route, false);
        state.slots.push(slot);
        if self.route.arm_idle(&mut state).is_err() {
            let retired = state.remove_timed();
            drop(state);
            drop(retired);
            drop(lease);
            self.fail(HttpConnectErrorKind::RuntimeUnavailable);
            return Err(HttpConnectError::RuntimeUnavailable);
        }

        self.finished = true;
        state.connecting = None;
        drop(state);
        self.route.changed.notify_waiters();
        Ok(lease)
    }

    /// Records that this attempt failed with `kind`, for the tunnels that
    /// waited for it.
    fn fail(mut self, kind: HttpConnectErrorKind) {
        self.finished = true;
        let mut state = self.route.lock();
        self.failed.send_replace(Some(kind));
        state.connecting = None;
        drop(state);
        self.route.changed.notify_waiters();
    }
}

impl Drop for SetupReservation<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.route.lock().connecting = None;
            self.route.changed.notify_waiters();
        }
    }
}

/// A pooled connection handed to one tunnel.
pub(super) struct PooledConnection {
    pub(super) connection: Http2Connection,
    tunnel: TunnelCount,
    /// Whether the connection carried a stream before this tunnel.
    pub(super) reused: bool,
}

impl PooledConnection {
    /// Stops the pool from handing this connection to later tunnels.
    ///
    /// Tunnels already open on it keep it.
    pub(super) fn retire(&self) {
        let mut state = self.tunnel.route.lock();
        let retired = state.remove_matching(&self.tunnel.tunnels);
        drop(state);
        drop(retired);
        debug!(outcome = "retired", "HTTP/2 proxy connection retired");
    }

    /// Returns the count this tunnel holds on its connection, to keep until
    /// the tunnel ends.
    pub(super) fn into_tunnel(self) -> (Http2Connection, TunnelCount) {
        (self.connection, self.tunnel)
    }
}

/// One tunnel counted against its pooled connection until it drops.
pub(super) struct TunnelCount {
    tunnels: Arc<AtomicUsize>,
    route: Arc<RouteConnections>,
}

impl Drop for TunnelCount {
    fn drop(&mut self) {
        self.tunnels.fetch_sub(1, Ordering::AcqRel);
        self.route.changed.notify_waiters();
    }
}

#[cfg(test)]
mod tests;
