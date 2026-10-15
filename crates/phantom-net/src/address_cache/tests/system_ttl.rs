//! Native deadlines pass through the same blocking publisher as OS addresses.

use std::time::Instant;

use super::{
    AddressCache, Arc, AtomicUsize, Duration, Ordering, SocketAddr, SocketAddrV6, TestResult, V4,
    V6, settings, wait_until_published, watch,
};
use crate::host_resolver::{AddressResolver, Resolved, system_ttl::SystemTtl};

const HOST: &str = "origin.phantom.test";

#[tokio::test(flavor = "current_thread")]
async fn native_deadlines_keep_address_order_scope_and_ignore_the_profile_floor() -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut config = settings(4, Duration::from_secs(600), None);
    config.min_record_ttl = Duration::from_secs(600);
    let scoped = SocketAddr::V6(SocketAddrV6::new(std::net::Ipv6Addr::LOCALHOST, 0, 47, 9));
    let original = vec![scoped, SocketAddr::new(V4, 0), scoped];
    let captured = original.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let cache = AddressCache::with_blocking_lookup(config, move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        let addresses = captured.clone();
        Box::pin(async move {
            Ok(Resolved::System {
                addresses,
                ttl: SystemTtl::Deadline(deadline),
            })
        })
    });

    for port in [443, 8443] {
        let actual = cache.lookup(HOST, port).await?;
        let expected = original
            .iter()
            .copied()
            .map(|mut a| {
                a.set_port(port);
                a
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(cache.lock().entries[HOST].expires_at, Some(deadline));
    assert!(!cache.lock().entries[HOST].is_fresh(deadline));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn missing_native_ttl_uses_fallback_but_known_zero_or_invalid_expiry_never_does() -> TestResult
{
    for (ttl, expected_calls) in [
        (SystemTtl::Unavailable, 1),
        (SystemTtl::Deadline(Instant::now()), 2),
        (SystemTtl::Uncacheable, 2),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let cache = AddressCache::with_blocking_lookup(
            settings(4, Duration::from_secs(600), None),
            move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    Ok(Resolved::System {
                        addresses: vec![SocketAddr::new(V4, 0)],
                        ttl,
                    })
                })
            },
        );
        for port in [443, 8443] {
            assert_eq!(cache.lookup(HOST, port).await?, [SocketAddr::new(V4, port)]);
        }
        assert_eq!(calls.load(Ordering::SeqCst), expected_calls);
        assert_eq!(cache.len(), usize::from(expected_calls == 1));
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn clear_and_cancelled_waiters_do_not_republish_an_old_native_deadline() -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(60);
    let (open, gate) = watch::channel(false);
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let cache = AddressCache::with_blocking_lookup(
        settings(4, Duration::from_secs(600), None),
        move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            let mut gate = gate.clone();
            Box::pin(async move {
                gate.wait_for(|open| *open)
                    .await
                    .map_err(std::io::Error::other)?;
                Ok(Resolved::System {
                    addresses: vec![SocketAddr::new(V6, 0)],
                    ttl: SystemTtl::Deadline(deadline),
                })
            })
        },
    );
    let cancelled = cache.cached_or_pending(HOST.into())?;
    let mut remaining = cache.cached_or_pending(HOST.into())?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    drop(cancelled);
    cache.clear();
    open.send(true)?;
    wait_until_published(&mut remaining).await?;
    assert_eq!(
        cache.consume_answer(remaining, 443).await?.0,
        [SocketAddr::new(V6, 443)]
    );
    assert!(
        cache.is_empty(),
        "the pre-clear publisher restored its old result"
    );

    assert_eq!(cache.lookup(HOST, 8443).await?, [SocketAddr::new(V6, 8443)]);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(cache.lock().entries[HOST].expires_at, Some(deadline));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn enabling_native_ttl_does_not_change_custom_resolver_lifetimes() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let resolver = AddressResolver::from_fn(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        async { Ok(vec![V4]) }
    });
    let mut config = settings(4, Duration::from_secs(600), None);
    config.system_ttl = phantom_profile::SystemDnsTtlPolicy::FirefoxWindows;
    let cache = AddressCache::with_resolver(config, resolver);

    for port in [443, 8443] {
        assert_eq!(cache.lookup(HOST, port).await?, [SocketAddr::new(V4, port)]);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}
