//! Caching of the host addresses a client resolves for its own connections.

use std::{num::NonZeroUsize, time::Duration};

/// Whether system address lookups also obtain native DNS lifetime information.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemDnsTtlPolicy {
    /// Use the configured fallback lifetime without additional native queries.
    Ignore,
    /// On Windows, request a canonical system name and query its A/AAAA TTLs.
    ///
    /// Uses Firefox's native DNS query options, which permit network queries.
    /// Other platforms keep the configured fallback lifetime. Custom resolvers
    /// are unaffected. TTLs are obtained before returning the first answer.
    FirefoxWindows,
}

/// Whether locally resolved DNS records remember failed connection addresses.
///
/// This policy is independent of TCP family selection and native DNS TTLs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsAddressFailurePolicy {
    /// Leave the resolver's address order unchanged after a connection failure.
    Ignore,
    /// Skip failed IP addresses retained by the same DNS record.
    ///
    /// Refreshing an answer preserves its history. A fresh traversal of an
    /// entirely blocked answer clears history and selects its first eligible
    /// address. A traversal with no eligible address leaves history intact.
    /// Clear, eviction and configuration invalidation retire that
    /// record; stale connection reports cannot modify its replacement.
    Record {
        /// Most distinct failed IP addresses retained by one record.
        ///
        /// Phantom's per-record resource limit, separate from the cache-entry
        /// limit. Reaching it returns a resource error without dropping history
        /// or authorizing a retry. The Firefox recipe uses 1600; Firefox itself
        /// has no per-record limit.
        max_unusable_addresses: NonZeroUsize,
    },
}

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
/// [`Self::system_ttl`] can obtain a native remaining lifetime on Windows.
/// Without one, a system answer is kept for
/// [`Self::ttl`], as is a caller's `AddressResolver::from_fn` answer.
/// An answer from a resolver that sends its own
/// DNS queries through `AddressResolver::system_nameservers` carries the
/// smallest record TTL and is kept for that TTL or [`Self::min_record_ttl`],
/// whichever is longer. [`Self::stale_grace`] allows those positive answers
/// to be used while they are refreshed. A caller using
/// `AddressResolver::from_answer_fn` supplies a hard remaining lifetime,
/// which the cache never extends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsCacheSettings {
    /// Failed-address history for locally resolved, cached DNS records.
    ///
    /// Overrides and IP literals do not create history. Without an address
    /// cache, this setting creates no cross-request DNS record.
    pub address_failure_policy: DnsAddressFailurePolicy,
    /// Native TTL handling for successful system-resolver address lookups.
    pub system_ttl: SystemDnsTtlPolicy,
    /// Most host names kept at once.
    ///
    /// When the cache is full, a new answer first replaces an expired one,
    /// then the one that would expire soonest.
    pub max_entries: NonZeroUsize,
    /// How long a successful answer without a record TTL is reused.
    ///
    /// A zero duration enters [`Self::stale_grace`] immediately. If both are
    /// zero, concurrent lookups still share one resolution but keep no answer.
    pub ttl: Duration,
    /// The shortest time a successful answer with a record TTL is reused.
    ///
    /// Such an answer is kept for its record TTL or this, whichever is
    /// longer, and [`Self::ttl`] does not apply to it. A zero duration keeps
    /// the record TTL as it is, including immediate entry into the grace period.
    /// This floor does not apply to native remaining lifetimes or to
    /// `AddressResolver::from_answer_fn`.
    pub min_record_ttl: Duration,
    /// How long a positive answer can be reused after its fresh lifetime ends.
    ///
    /// A lookup during this period returns the old answer and starts a bounded
    /// background refresh. Concurrent lookups share that refresh. After this
    /// period, lookups wait for resolution. Zero disables stale reuse.
    /// Failed lookups and hard lifetimes from `AddressResolver::from_answer_fn`
    /// never receive grace.
    pub stale_grace: Duration,
    /// How long a failed lookup is remembered, or `None` to resolve again on
    /// the next connection.
    ///
    /// For `AddressResolver::from_answer_fn`, this caps a negative DNS answer's
    /// remaining lifetime. Callback errors are never stored.
    pub negative_ttl: Option<Duration>,
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroUsize, time::Duration};

    use super::DnsAddressFailurePolicy;
    use crate::{SystemDnsTtlPolicy, browser::chrome, browser::firefox};

    #[test]
    fn chromium_154_keeps_1000_answers_for_60_seconds_and_no_failures() {
        // `kDefaultCacheSize`, `net/dns/resolve_context.cc:110`, the system
        // resolver TTLs, `net/dns/host_resolver_manager_job.cc:55-58`, and the
        // built-in client's `kMinimumTTLSeconds`, `:61`, at `154.0.8037.58`.
        let settings = chrome::v154_dns_cache();

        assert_eq!(settings.system_ttl, SystemDnsTtlPolicy::Ignore);
        assert_eq!(
            settings.address_failure_policy,
            DnsAddressFailurePolicy::Ignore
        );

        assert_eq!(settings.max_entries.get(), 1000);
        assert_eq!(settings.ttl, Duration::from_secs(60));
        assert_eq!(settings.min_record_ttl, Duration::from_secs(60));
        assert_eq!(settings.stale_grace, Duration::ZERO);
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

        assert_eq!(settings.system_ttl, SystemDnsTtlPolicy::FirefoxWindows);
        assert!(matches!(
            settings.address_failure_policy,
            DnsAddressFailurePolicy::Record { max_unusable_addresses }
                if max_unusable_addresses.get() == 1600
        ));

        assert_eq!(settings.max_entries.get(), 1600);
        assert_eq!(settings.ttl, Duration::from_secs(60));
        assert_eq!(settings.min_record_ttl, Duration::ZERO);
        assert_eq!(settings.stale_grace, Duration::from_secs(600));
        assert_eq!(settings.negative_ttl, Some(Duration::from_secs(60)));
    }

    #[test]
    fn changing_cache_entry_limit_does_not_change_the_record_history_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut settings = firefox::v157_dns_cache();
        let original_history = settings.address_failure_policy;
        settings.max_entries = NonZeroUsize::new(3).ok_or("nonzero test cache limit")?;
        assert_eq!(settings.address_failure_policy, original_history);
        settings.address_failure_policy = DnsAddressFailurePolicy::Record {
            max_unusable_addresses: NonZeroUsize::new(7).ok_or("nonzero test history limit")?,
        };
        assert_eq!(settings.max_entries.get(), 3);
        assert!(matches!(
            settings.address_failure_policy,
            DnsAddressFailurePolicy::Record { max_unusable_addresses }
                if max_unusable_addresses.get() == 7
        ));
        Ok(())
    }
}
