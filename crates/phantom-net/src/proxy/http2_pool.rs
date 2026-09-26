//! HTTP/2 connections to HTTPS proxies that carry many CONNECT tunnels.
//!
//! Browsers open a page's CONNECT tunnels as streams of one HTTP/2 proxy
//! connection (the `https-proxy-*` captures under `fixtures/proxy/`). A pool
//! keeps each proxy route's connections, hands a tunnel the oldest one with
//! room, and opens another only when every connection is full.
//!
//! The pool never holds its lock across an `.await`. One connection setup
//! runs at a time per route; other tunnels wait for it rather than open
//! their own, as a browser waits for its proxy session.

use std::{
    fmt,
    future::Future,
    pin::pin,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
};

use tokio::sync::Notify;
use tracing::debug;

use super::{HttpBasicCredentials, HttpConnectError};
use crate::http2::Http2Connection;

/// Most tunnels one pooled HTTP/2 proxy connection carries at once.
///
/// A connection also stops taking tunnels at the proxy's
/// `SETTINGS_MAX_CONCURRENT_STREAMS`, when that is lower. Until the proxy's
/// SETTINGS arrive, this is the only bound.
pub const MAX_TUNNELS_PER_HTTP2_PROXY_CONNECTION: usize = 100;

/// Most HTTP/2 connections a pool keeps for one proxy route.
///
/// When every connection of a route is full and the route has this many, a
/// new tunnel takes the least loaded one, and the HTTP/2 layer holds its
/// CONNECT until the proxy allows another stream.
pub const MAX_HTTP2_PROXY_CONNECTIONS_PER_ROUTE: usize = 8;

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
/// same Basic credentials or none. Without a pool, every tunnel opens its
/// own connection.
///
/// A connection takes tunnels until it carries
/// [`MAX_TUNNELS_PER_HTTP2_PROXY_CONNECTION`] or the proxy's
/// `SETTINGS_MAX_CONCURRENT_STREAMS` of them, and stops taking them once the
/// proxy sends `GOAWAY` or the connection closes. Each open tunnel keeps its
/// connection alive, whether or not the pool still holds it. Closing or
/// resetting a tunnel ends only its own stream.
///
/// Clones share one pool. It holds at most
/// [`MAX_HTTP2_PROXY_POOL_ROUTES`] routes of at most
/// [`MAX_HTTP2_PROXY_CONNECTIONS_PER_ROUTE`] connections each, and keeps an
/// idle connection until the proxy closes it or its route is forgotten.
///
/// [`HttpsProxyConnector::with_http2_proxy_pool`]: super::HttpsProxyConnector::with_http2_proxy_pool
#[derive(Clone, Default)]
pub struct Http2ProxyPool {
    routes: Arc<Mutex<Routes>>,
}

impl Http2ProxyPool {
    /// Creates an empty pool.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Http2Connection, HttpConnectError>>,
    {
        let route = self.route(key);
        let reservation = loop {
            let mut changed = pin!(route.changed.notified());
            // Registered before the check, so a setup that finishes in
            // between still wakes this tunnel.
            changed.as_mut().enable();
            {
                let mut state = route.lock();
                state.slots.retain(|slot| slot.connection.is_reusable());
                if let Choice::Use(index) = state.choose()
                    && let Some(slot) = state.slots.get(index)
                {
                    debug!(outcome = "hit", "HTTP/2 proxy connection reused");
                    return Ok(slot.lease(&route, true));
                }
                if !state.connecting {
                    state.connecting = true;
                    break SetupReservation {
                        route: &route,
                        finished: false,
                    };
                }
            }
            changed.await;
        };
        debug!(outcome = "connect", "HTTP/2 proxy pool opening connection");
        let connection = open().await?;
        Ok(reservation.finish(connection))
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
/// encoded Basic credential, so routes with other credentials, or none,
/// never share a connection.
#[derive(Clone, Eq, PartialEq)]
pub(super) struct RouteKey {
    settings: ConnectionSettingsId,
    host: Box<str>,
    port: u16,
    server_name: Box<str>,
    authorization: Option<Box<[u8]>>,
}

impl RouteKey {
    pub(super) fn new(
        settings: &ConnectionSettingsId,
        host: &str,
        port: u16,
        server_name: &str,
        credentials: Option<&HttpBasicCredentials>,
    ) -> Self {
        Self {
            settings: settings.clone(),
            host: host.to_ascii_lowercase().into(),
            port,
            server_name: server_name.to_ascii_lowercase().into(),
            authorization: credentials.map(|credentials| credentials.authorization().into()),
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
    /// Woken when a setup finishes, fails, or is cancelled, and when a
    /// tunnel ends.
    changed: Notify,
}

impl RouteConnections {
    fn lock(&self) -> MutexGuard<'_, RouteState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[derive(Default)]
struct RouteState {
    slots: Vec<Slot>,
    /// Whether the route's one connection setup is in flight.
    connecting: bool,
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
    /// not counted; the HTTP/2 layer holds a stream past the proxy's limit
    /// until another ends. When none has room, the route opens another
    /// connection, or, at [`MAX_HTTP2_PROXY_CONNECTIONS_PER_ROUTE`], uses the
    /// least loaded.
    fn choose(&self) -> Choice {
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
            Some((index, _)) if self.slots.len() >= MAX_HTTP2_PROXY_CONNECTIONS_PER_ROUTE => {
                Choice::Use(index)
            }
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
/// Dropping it unfinished, when the setup fails or the tunnel is cancelled,
/// frees the setup and wakes every tunnel waiting for it; whichever runs
/// first makes the next attempt.
struct SetupReservation<'a> {
    route: &'a Arc<RouteConnections>,
    finished: bool,
}

impl SetupReservation<'_> {
    fn finish(mut self, connection: Http2Connection) -> PooledConnection {
        self.finished = true;
        let slot = Slot {
            connection,
            tunnels: Arc::default(),
        };
        let lease = slot.lease(self.route, false);
        let mut state = self.route.lock();
        state.connecting = false;
        state.slots.push(slot);
        drop(state);
        self.route.changed.notify_waiters();
        lease
    }
}

impl Drop for SetupReservation<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.route.lock().connecting = false;
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
        state
            .slots
            .retain(|slot| !Arc::ptr_eq(&slot.tunnels, &self.tunnel.tunnels));
        drop(state);
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
