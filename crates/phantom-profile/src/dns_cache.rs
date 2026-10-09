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
/// An answer from the operating system's resolver, or from a caller's
/// resolver built with `AddressResolver::from_fn`, carries no record TTL and
/// is kept for [`Self::ttl`]. An answer from a resolver that sends its own
/// DNS queries carries the smallest TTL of its records and is kept for that
/// TTL or [`Self::min_record_ttl`], whichever is longer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsCacheSettings {
    /// Most host names kept at once.
    ///
    /// When the cache is full, a new answer first replaces an expired one,
    /// then the one that would expire soonest.
    pub max_entries: NonZeroUsize,
    /// How long a successful answer without a record TTL is reused.
    ///
    /// A zero duration keeps nothing, though concurrent lookups of one name
    /// still share one resolution.
    pub ttl: Duration,
    /// The shortest time a successful answer with a record TTL is reused.
    ///
    /// Such an answer is kept for its record TTL or this, whichever is
    /// longer, and [`Self::ttl`] does not apply to it. A zero duration keeps
    /// the record TTL as it is, and a record TTL of zero then keeps nothing.
    pub min_record_ttl: Duration,
    /// How long a failed lookup is remembered, or `None` to resolve again on
    /// the next connection.
    pub negative_ttl: Option<Duration>,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{browser::chrome, browser::firefox};

    #[test]
    fn chromium_154_keeps_1000_answers_for_60_seconds_and_no_failures() {
        // `kDefaultCacheSize`, `net/dns/resolve_context.cc:110`, the system
        // resolver TTLs, `net/dns/host_resolver_manager_job.cc:55-58`, and the
        // built-in client's `kMinimumTTLSeconds`, `:61`, at `154.0.8037.58`.
        let settings = chrome::v154_dns_cache();

        assert_eq!(settings.max_entries.get(), 1000);
        assert_eq!(settings.ttl, Duration::from_secs(60));
        assert_eq!(settings.min_record_ttl, Duration::from_secs(60));
        assert_eq!(settings.negative_ttl, None);
    }

    #[test]
    fn firefox_157_keeps_1600_answers_and_failures_for_60_seconds() {
        // `network.dnsCacheEntries` and `network.dnsCacheExpiration`,
        // `modules/libpref/init/StaticPrefList.yaml:15648-15661`, and
        // `NEGATIVE_RECORD_LIFETIME`, `netwerk/dns/nsHostResolver.cpp:68`, at
        // `FIREFOX_157_0_RELEASE`.
        // A record TTL from `DnsQuery_A` replaces the lifetime without a bound,
        // `netwerk/dns/nsHostResolver.cpp:1314-1315`.
        let settings = firefox::v157_dns_cache();

        assert_eq!(settings.max_entries.get(), 1600);
        assert_eq!(settings.ttl, Duration::from_secs(60));
        assert_eq!(settings.min_record_ttl, Duration::ZERO);
        assert_eq!(settings.negative_ttl, Some(Duration::from_secs(60)));
    }
}
