//! Caching of the host addresses a client resolves for its own connections.

use std::{num::NonZeroUsize, time::Duration};

/// How a client reuses the addresses it resolves for its own connections.
///
/// A client that caches addresses resolves a host name once and reuses the
/// answer for later TCP and QUIC connections, as browsers do, so repeated
/// requests to one host do not each send a DNS query. The cache covers every
/// name the client resolves itself: origin hosts on a direct route, proxy
/// hosts, and the target of a local-DNS `socks5://` route. A target that a
/// proxy resolves, through `socks5h://`, an HTTP proxy, or CONNECT-UDP, is
/// never resolved or cached locally.
///
/// Phantom resolves names through the operating system, which reports no
/// record TTL, so every successful answer is kept for the same [`Self::ttl`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsCacheSettings {
    /// Most host names kept at once.
    ///
    /// When the cache is full, a new answer first replaces an expired one,
    /// then the one that would expire soonest.
    pub max_entries: NonZeroUsize,
    /// How long a successful answer is reused.
    ///
    /// A zero duration keeps nothing, though concurrent lookups of one name
    /// still share one resolution.
    pub ttl: Duration,
    /// How long a failed lookup is remembered, or `None` to resolve again on
    /// the next connection.
    pub negative_ttl: Option<Duration>,
}

#[cfg(test)]
mod tests;
