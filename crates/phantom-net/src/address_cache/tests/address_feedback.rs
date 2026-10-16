use super::{AddressCache, AddressResolver, TestResult, V4, V4_OTHER, long_lived};
use phantom_profile::DnsAddressFailurePolicy;
use std::{
    net::SocketAddr,
    num::NonZeroUsize,
    time::{Duration, Instant},
};

fn cache(capacity: NonZeroUsize) -> AddressCache {
    let mut settings = long_lived();
    settings.address_failure_policy = DnsAddressFailurePolicy::Record {
        max_unusable_addresses: capacity,
    };
    AddressCache::with_resolver(
        settings,
        AddressResolver::from_fn(|_| async { Ok(vec![V4, V4_OTHER]) }),
    )
}
async fn first(
    cache: &AddressCache,
) -> TestResult<crate::host_resolver::tcp_addresses::TcpCandidate> {
    cache
        .lookup_tcp_noting_cache("origin.test", 443)
        .await?
        .0
        .cursor()
        .next()
        .ok_or_else(|| "no candidate".into())
}

#[tokio::test]
async fn initial_waiter_and_cache_hit_share_the_actual_retained_record() -> TestResult {
    let cache = cache(NonZeroUsize::MIN);
    first(&cache).await?.failed_connect()?;
    let (addresses, hit) = cache.lookup_tcp_noting_cache("origin.test", 8443).await?;
    assert!(hit);
    assert_eq!(
        addresses.cursor().next().ok_or("no candidate")?.address(),
        SocketAddr::new(V4_OTHER, 8443)
    );
    // Non-TCP consumers retain the exact DNS answer.
    assert_eq!(
        cache.lookup("origin.test", 443).await?,
        [SocketAddr::new(V4, 443), SocketAddr::new(V4_OTHER, 443)]
    );
    Ok(())
}

#[tokio::test]
async fn refresh_keeps_history_and_retires_previous_answer_witnesses() -> TestResult {
    let cache = cache(NonZeroUsize::MIN);
    let held = first(&cache).await?;
    held.failed_connect()?;
    let old = first(&cache).await?;
    cache
        .lock()
        .entries
        .get_mut("origin.test")
        .ok_or("missing entry")?
        .expires_at = Some(
        Instant::now()
            .checked_sub(Duration::from_secs(1))
            .ok_or("clock")?,
    );
    assert_eq!(first(&cache).await?.address().ip(), V4_OTHER);
    // The old generation's second-address failure cannot consume capacity.
    old.failed_connect()?;
    assert_eq!(first(&cache).await?.address().ip(), V4_OTHER);
    Ok(())
}

#[tokio::test]
async fn clear_replaces_record_identity_and_old_connect_cannot_poison_new_answer() -> TestResult {
    let cache = cache(NonZeroUsize::MIN);
    let held = first(&cache).await?;
    cache.clear();
    assert_eq!(first(&cache).await?.address().ip(), V4);
    held.failed_connect()?;
    assert_eq!(first(&cache).await?.address().ip(), V4);
    Ok(())
}

#[tokio::test]
async fn eviction_replaces_record_identity_without_a_side_history_map() -> TestResult {
    let mut settings = long_lived();
    settings.max_entries = NonZeroUsize::MIN;
    settings.address_failure_policy = DnsAddressFailurePolicy::Record {
        max_unusable_addresses: NonZeroUsize::MIN,
    };
    let cache = AddressCache::with_resolver(
        settings,
        AddressResolver::from_fn(|_| async { Ok(vec![V4, V4_OTHER]) }),
    );
    let held = first(&cache).await?;
    cache.lookup("other.test", 443).await?;
    assert_eq!(cache.len(), 1);
    assert_eq!(first(&cache).await?.address().ip(), V4);
    held.failed_connect()?;
    assert_eq!(first(&cache).await?.address().ip(), V4);
    Ok(())
}

#[tokio::test]
async fn disabled_policy_preserves_all_addresses_after_a_failed_connect() -> TestResult {
    let cache = AddressCache::with_resolver(
        long_lived(),
        AddressResolver::from_fn(|_| async { Ok(vec![V4, V4_OTHER]) }),
    );
    first(&cache).await?.failed_connect()?;
    assert_eq!(first(&cache).await?.address().ip(), V4);
    Ok(())
}

#[tokio::test]
async fn zero_lifetime_does_not_invent_cross_request_failure_retention() -> TestResult {
    let mut settings = long_lived();
    settings.ttl = Duration::ZERO;
    settings.address_failure_policy = DnsAddressFailurePolicy::Record {
        max_unusable_addresses: NonZeroUsize::MIN,
    };
    let cache = AddressCache::with_resolver(
        settings,
        AddressResolver::from_fn(|_| async { Ok(vec![V4, V4_OTHER]) }),
    );
    first(&cache).await?.failed_connect()?;
    assert!(cache.is_empty());
    assert_eq!(first(&cache).await?.address().ip(), V4);
    Ok(())
}
