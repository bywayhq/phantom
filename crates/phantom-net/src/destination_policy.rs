//! Admission of direct-origin socket destinations.

use std::{
    error::Error,
    fmt, io,
    net::{Ipv4Addr, SocketAddr},
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
    /// Permits ordinary public IPv4 and IPv6 unicast destinations.
    ///
    /// Denies private, loopback, link-local, multicast, documentation, reserved
    /// and special-purpose ranges. IPv6 is limited to `2000::/3`, excluding
    /// special-purpose and transition prefixes. IPv4-mapped IPv6 addresses use
    /// the IPv4 rules; IPv6 addresses with a scope ID are denied.
    ///
    /// This deliberately excludes some globally reachable special-purpose
    /// addresses. It classifies IP addresses, not local routing or custom
    /// translation prefixes. The direct-route and connection-reuse limits of
    /// [`DestinationPolicy`] still apply. No policy is enabled by default.
    ///
    /// ```
    /// use phantom_net::DestinationPolicy;
    /// let policy = DestinationPolicy::public_only();
    /// # drop(policy);
    /// ```
    #[must_use]
    pub fn public_only() -> Self {
        Self::from_fn(|address| match address {
            SocketAddr::V4(address) => public_ipv4(*address.ip()),
            SocketAddr::V6(address) => {
                if address.scope_id() != 0 {
                    return false;
                }

                let ip = address.ip();
                if let Some(mapped) = ip.to_ipv4_mapped() {
                    return public_ipv4(mapped);
                }

                let [first, second, third, ..] = ip.segments();
                first & 0xe000 == 0x2000
                    && !(first == 0x2001 && second < 0x0200)
                    && !(first == 0x2001 && second == 0x0db8)
                    && first != 0x2002
                    && !(first == 0x2620 && second == 0x004f && third == 0x8000)
                    && !(first == 0x3fff && second < 0x1000)
            }
        })
    }

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

// IANA IPv4/IPv6 Special-Purpose Address Registries, updated 2025-10-09:
// https://www.iana.org/assignments/iana-ipv4-special-registry/
// https://www.iana.org/assignments/iana-ipv6-special-registry/
// Exclude whole special-purpose blocks, including their public exceptions.
fn public_ipv4(address: Ipv4Addr) -> bool {
    !matches!(
        address.octets(),
        [0 | 10 | 127 | 224..=255, ..]
            | [100, 64..=127, ..]
            | [169, 254, ..]
            | [172, 16..=31, ..]
            | [192, 0, 0 | 2, _]
            | [192, 31, 196, _]
            | [192, 52, 193, _]
            | [192, 88, 99, _]
            | [192, 168, ..]
            | [192, 175, 48, _]
            | [198, 18 | 19, ..]
            | [198, 51, 100, _]
            | [203, 0, 113, _]
    )
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

#[cfg(test)]
mod tests;
