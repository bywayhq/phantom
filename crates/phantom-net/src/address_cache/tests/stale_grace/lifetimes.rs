use super::*;
use crate::host_resolver::{AddressAnswer, AddressNegativeKind};

fn publish(cache: &AddressCache, result: io::Result<Resolved>) -> Outcome {
    let generation = cache.lock().generation;
    let (outcome, lifetime) = Outcome::from_resolution(result, cache.cache_errors());
    cache.complete(HOST, None, generation, &None, &outcome, lifetime)
}

#[test]
fn native_grace_keeps_its_absolute_anchor_and_excludes_invalid_or_overflow_expiry() -> TestResult {
    let now = Instant::now();
    for grace in [Duration::ZERO, GRACE] {
        let mut config = grace_settings(4);
        config.stale_grace = grace;
        let (cache, _, _) = scripted(config, 0);
        publish(
            &cache,
            Ok(Resolved::System {
                addresses: vec![SocketAddr::new(V4, 0)],
                ttl: crate::host_resolver::system_ttl::SystemTtl::Deadline(now),
            }),
        );
        if grace.is_zero() {
            assert!(cache.is_empty());
        } else {
            let state = cache.lock();
            let entry = state.entries.get(HOST).ok_or("zero TTL was discarded")?;
            assert_eq!(entry.expires_at, Some(now));
            assert_eq!(entry.stale_until, now.checked_add(grace));
            assert!(entry.is_in_grace(now));
            assert!(!entry.is_usable(now + grace));
        }
        publish(
            &cache,
            Ok(Resolved::System {
                addresses: vec![SocketAddr::new(V6, 0)],
                ttl: crate::host_resolver::system_ttl::SystemTtl::Uncacheable,
            }),
        );
        assert!(
            cache.is_empty(),
            "invalid native TTL reused the previous answer"
        );
    }
    let mut config = grace_settings(4);
    config.stale_grace = Duration::MAX;
    let (cache, _, _) = scripted(config, 0);
    publish(
        &cache,
        Ok(Resolved::System {
            addresses: vec![SocketAddr::new(V4, 0)],
            ttl: crate::host_resolver::system_ttl::SystemTtl::Deadline(now),
        }),
    );
    assert!(
        cache.is_empty(),
        "overflow created an infinite stale lifetime"
    );
    Ok(())
}

#[test]
fn hard_dns_lifetimes_and_negatives_never_acquire_profile_grace() -> TestResult {
    let (cache, _, _) = scripted(grace_settings(4), 0);
    let before = Instant::now();
    publish(
        &cache,
        Ok(Resolved::Answer(AddressAnswer::positive(vec![V4], TTL)?)),
    );
    {
        let state = cache.lock();
        let entry = state.entries.get(HOST).ok_or("missing hard answer")?;
        let end = entry.expires_at.ok_or("missing hard expiry")?;
        assert!(end >= before + TTL);
        assert_eq!(entry.stale_until, None);
        assert!(!entry.is_usable(end));
    }
    publish(
        &cache,
        Ok(Resolved::Answer(AddressAnswer::negative(
            AddressNegativeKind::NxDomain,
            Some(TTL),
        ))),
    );
    {
        let state = cache.lock();
        let entry = state.entries.get(HOST).ok_or("missing negative")?;
        assert!(entry.outcome.is_negative());
        assert_eq!(entry.stale_until, None);
        assert!(!entry.is_usable(entry.expires_at.ok_or("negative expiry")?));
    }
    publish(
        &cache,
        Ok(Resolved::Answer(AddressAnswer::positive(
            vec![V6],
            Duration::ZERO,
        )?)),
    );
    assert!(
        cache.is_empty(),
        "zero hard lifetime retained a prior negative"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_failed_renewal_replaces_positive_grace_with_a_negative_without_grace() -> TestResult {
    for empty in [false, true] {
        let (cache, _, replies) = scripted(grace_settings(4), 2);
        let mut replies = replies.into_iter();
        respond(
            replies.next().ok_or("initial reply")?,
            Ok(Resolved::without_ttl([V4])),
        )?;
        cache.lookup(HOST, 443).await?;
        enter_grace(&cache)?;
        assert!(cache.lookup_noting_cache(HOST, 443).await?.1);
        let mut renewal = pending(&cache)?;
        let replacement = if empty {
            Ok(Resolved::without_ttl([]))
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "lookup failed"))
        };
        respond(replies.next().ok_or("renewal reply")?, replacement)?;
        wait_until_published(&mut renewal).await?;
        let result = cache.consume_answer(renewal, 443).await;
        if empty {
            assert!(result?.0.is_empty());
        } else {
            assert_eq!(
                result.err().ok_or("failure resolved")?.kind(),
                io::ErrorKind::NotFound
            );
        }
        let (outcome, stored, _) = cache.lookup_outcome(HOST).await?;
        assert!(stored);
        assert!(
            outcome.is_negative(),
            "known failure left the old address reusable"
        );
        let state = cache.lock();
        let entry = state.entries.get(HOST).ok_or("missing negative")?;
        assert_eq!(entry.stale_until, None);
        assert!(entry.is_fresh(Instant::now()));
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn uncached_custom_error_retires_the_previous_answer_and_keeps_its_cause() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let resolver = AddressResolver::from_answer_fn(move |_| {
        let first = counter.fetch_add(1, Ordering::SeqCst) == 0;
        async move {
            if first {
                AddressAnswer::positive(vec![V4], TTL)
            } else {
                Err(io::Error::from_raw_os_error(47))
            }
        }
    });
    let mut config = grace_settings(4);
    config.address_failure_policy = phantom_profile::DnsAddressFailurePolicy::Record {
        max_unusable_addresses: NonZeroUsize::MIN,
    };
    let cache = AddressCache::with_resolver(config, resolver);
    cache.lookup(HOST, 443).await?;
    expire(&cache)?;
    let selected = cache.cached_or_pending(HOST.into())?;
    assert_eq!(cache.len(), 1, "keep the prior history until replacement");
    let error = cache
        .consume_answer(selected, 443)
        .await
        .err()
        .ok_or("error resolved")?;
    let mut cause: &(dyn Error + 'static) = &error;
    while cause
        .downcast_ref::<io::Error>()
        .and_then(io::Error::raw_os_error)
        != Some(47)
    {
        cause = cause.source().ok_or("original I/O error lost")?;
    }
    assert!(
        cache.is_empty(),
        "uncached error left the previous positive entry"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}
