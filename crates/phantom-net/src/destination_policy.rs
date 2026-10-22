//! Admission of direct-origin socket destinations.

use std::{
    error::Error,
    fmt, io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// Restricts the socket addresses used for new direct-origin connections.
///
/// The callback runs before a TCP socket is prepared or a QUIC connection is
/// started, including for literals, overrides, cached answers and discovered
/// alternatives. Denied candidates are skipped. Existing connections remain
/// reusable. This does not restrict DNS service sockets or work done by caller
/// callbacks, and it cannot inspect destinations reached through proxies or
/// caller-owned streams. Those routes are unsupported while configured.
///
/// Clones share the callback, which can run concurrently outside internal locks.
/// Keep it short, nonblocking and stable for the lifetime of the client. This
/// is connection admission, not live revocation of established connections.
#[derive(Clone)]
pub struct DestinationPolicy(Arc<dyn Fn(SocketAddr) -> bool + Send + Sync>);

impl DestinationPolicy {
    /// Builds a policy that permits an address when `permits` returns `true`.
    ///
    /// No connection is opened by this constructor. The address includes the
    /// actual destination port and any IPv6 scope ID.
    ///
    /// ```
    /// use phantom_net::DestinationPolicy;
    /// let policy = DestinationPolicy::from_fn(|address| address.ip().is_loopback());
    /// # drop(policy);
    /// ```
    #[must_use]
    pub fn from_fn(permits: impl Fn(SocketAddr) -> bool + Send + Sync + 'static) -> Self {
        Self(Arc::new(permits))
    }

    pub(crate) fn permits(&self, address: SocketAddr) -> bool {
        (self.0)(address)
    }
}

impl fmt::Debug for DestinationPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DestinationPolicy(..)")
    }
}

/// No candidate socket address was permitted by the destination policy.
///
/// Display and Debug omit addresses and callback state. This is a local
/// admission decision, not a network failure or DNS reachability signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DestinationDenied;

impl fmt::Display for DestinationDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("destination policy denied every candidate address")
    }
}

impl Error for DestinationDenied {}

impl DestinationDenied {
    pub(crate) fn io() -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, Self)
    }
}

/// One TCP traversal shares only its denial observation across family cursors.
/// It never changes DNS history or persists into the shared address cache.
pub(crate) struct DestinationAdmission {
    policy: DestinationPolicy,
    denied: AtomicBool,
}

impl DestinationAdmission {
    pub(crate) fn new(policy: DestinationPolicy) -> Self {
        Self {
            policy,
            denied: AtomicBool::new(false),
        }
    }

    pub(crate) fn permits(&self, address: SocketAddr) -> bool {
        let permits = self.policy.permits(address);
        if !permits {
            self.denied.store(true, Ordering::Relaxed);
        }
        permits
    }

    pub(crate) fn denied(&self) -> bool {
        self.denied.load(Ordering::Relaxed)
    }
}

pub(crate) fn check_route(
    resolver: Option<&crate::host_resolver::HostResolver>,
    direct: bool,
) -> io::Result<()> {
    if !direct && resolver.and_then(|r| r.destination_policy()).is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "destination policies require a direct origin route without caller-owned streams",
        ));
    }
    Ok(())
}

pub(crate) fn check_origin(
    resolver: Option<&crate::host_resolver::HostResolver>,
    origin: &crate::route::OriginRoute<'_>,
) -> io::Result<()> {
    use crate::route::{OriginRoute, TcpRoute};
    check_route(
        resolver,
        matches!(
            origin,
            OriginRoute::Plaintext {
                tcp: TcpRoute::Direct(_),
                ..
            } | OriginRoute::Tls {
                tcp: TcpRoute::Direct(_),
                ..
            }
        ),
    )
}
