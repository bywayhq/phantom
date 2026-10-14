//! Cache controls for validated DNS answers and operational failures.

use std::time::Instant;

use super::{
    AddressCache, AddressResolver, Answer, Arc, AtomicUsize, Duration, Error, Ordering,
    ResolverFailure, SocketAddr, TestResult, V4, V6, consume_failure, io, poll_lookup_once,
    settings, wait_until_published,
};
use crate::host_resolver::{AddressAnswer, AddressNegative, AddressNegativeKind, Resolved};
use tokio::sync::watch;

const HOST: &str = "origin.phantom.test";
const LONG_TTL: Duration = Duration::from_secs(600);

fn typed_cache(
    calls: &Arc<AtomicUsize>,
    settings: phantom_profile::DnsCacheSettings,
    answer: impl Fn() -> io::Result<AddressAnswer> + Send + Sync + 'static,
) -> AddressCache {
    let calls = Arc::clone(calls);
    let resolver = AddressResolver::from_answer_fn(move |_| {
        calls.fetch_add(1, Ordering::SeqCst);
        let result = answer();
        async move { result }
    });
    AddressCache::with_resolver(settings, resolver)
}

fn stored_expiry(cache: &AddressCache) -> TestResult<Instant> {
    cache
        .lock()
        .entries
        .get(HOST)
        .and_then(|entry| entry.expires_at)
        .ok_or_else(|| "no finite cache lifetime was stored".into())
}

fn negative_cause(error: &io::Error) -> TestResult<&AddressNegative> {
    let mut cause: &(dyn Error + 'static) = error;
    loop {
        if let Some(original) = cause.downcast_ref::<io::Error>()
            && let Some(negative) = original
                .get_ref()
                .and_then(|payload| payload.downcast_ref::<AddressNegative>())
        {
            return Ok(negative);
        }
        cause = cause.source().ok_or("the typed negative cause was lost")?;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn typed_addresses_keep_their_dns_deadline_order_duplicates_and_port() -> TestResult {
    let ttl = Duration::from_secs(60);
    let before = Instant::now();
    let answer = AddressAnswer::positive(vec![V6, V4, V6], ttl)?;
    let after = Instant::now();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut config = settings(4, Duration::ZERO, None);
    config.min_record_ttl = LONG_TTL;
    let cache = typed_cache(&calls, config, move || Ok(answer.clone()));

    let first = cache.lookup_noting_cache(HOST, 443).await?;
    let second = cache.lookup_noting_cache(HOST, 8443).await?;
    assert_eq!(
        first.0,
        [
            SocketAddr::new(V6, 443),
            SocketAddr::new(V4, 443),
            SocketAddr::new(V6, 443)
        ]
    );
    assert!(!first.1);
    assert_eq!(
        second.0,
        [
            SocketAddr::new(V6, 8443),
            SocketAddr::new(V4, 8443),
            SocketAddr::new(V6, 8443)
        ]
    );
    assert!(second.1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let expiry = stored_expiry(&cache)?;
    assert!(expiry >= before + ttl);
    assert!(
        expiry <= after + ttl,
        "the profile floor or publication extended the DNS lifetime"
    );
    assert!(!cache.lock().entries[HOST].is_fresh(expiry));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn typed_positive_ttl_is_not_capped_by_the_legacy_fallback_ttl() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let before = Instant::now();
    let cache = typed_cache(&calls, settings(4, Duration::from_secs(1), None), || {
        AddressAnswer::positive(vec![V4], LONG_TTL)
    });
    cache.lookup(HOST, 443).await?;
    assert!(stored_expiry(&cache)? >= before + LONG_TTL);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_zero_typed_positive_lifetime_never_uses_the_profile_floor() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut config = settings(4, LONG_TTL, Some(LONG_TTL));
    config.min_record_ttl = LONG_TTL;
    let cache = typed_cache(&calls, config, || {
        AddressAnswer::positive(vec![V4], Duration::ZERO)
    });
    for port in [443, 8443] {
        assert_eq!(cache.lookup(HOST, port).await?, [SocketAddr::new(V4, port)]);
        assert!(cache.is_empty());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_positive_held_before_publication_delivers_but_is_not_cached_after_expiry() -> TestResult
{
    let ttl = Duration::from_millis(1);
    let answer = AddressAnswer::positive(vec![V4], ttl)?;
    let constructed_at = Instant::now();
    let calls = Arc::new(AtomicUsize::new(0));
    let (open, gate) = watch::channel(false);
    let counter = Arc::clone(&calls);
    let resolver = AddressResolver::from_answer_fn(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        let mut gate = gate.clone();
        let answer = answer.clone();
        async move {
            gate.wait_for(|open| *open)
                .await
                .map_err(io::Error::other)?;
            Ok(answer)
        }
    });
    let cache = AddressCache::with_resolver(settings(4, LONG_TTL, None), resolver);
    let selected = cache.cached_or_pending(HOST.into())?;
    tokio::time::sleep(ttl + Duration::from_millis(5)).await;
    assert!(constructed_at.elapsed() >= ttl);
    open.send(true)?;
    let (addresses, stored) =
        tokio::time::timeout(Duration::from_secs(5), cache.consume_answer(selected, 443)).await??;
    assert_eq!(addresses, [SocketAddr::new(V4, 443)]);
    assert!(!stored);
    assert!(cache.is_empty());
    cache.lookup(HOST, 443).await?;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(cache.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_clone_returned_later_keeps_the_original_positive_deadline() -> TestResult {
    let before = Instant::now();
    let answer = AddressAnswer::positive(vec![V4], LONG_TTL)?;
    let after = Instant::now();
    tokio::time::sleep(Duration::from_millis(5)).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let cache = typed_cache(&calls, settings(4, LONG_TTL, None), move || {
        Ok(answer.clone())
    });
    cache.lookup(HOST, 443).await?;
    let expiry = stored_expiry(&cache)?;
    assert!(expiry >= before + LONG_TTL);
    assert!(
        expiry <= after + LONG_TTL,
        "returning a clone restarted its lifetime"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_negative_lifetime_is_bounded_by_its_soa_and_the_profile_cap() -> TestResult {
    for (reported, configured) in [(60, 600), (600, 60)] {
        let before = Instant::now();
        let answer = AddressAnswer::negative(
            AddressNegativeKind::NxDomain,
            Some(Duration::from_secs(reported)),
        );
        let after = Instant::now();
        let calls = Arc::new(AtomicUsize::new(0));
        let cache = typed_cache(
            &calls,
            settings(4, LONG_TTL, Some(Duration::from_secs(configured))),
            move || Ok(answer.clone()),
        );
        let error = cache
            .lookup(HOST, 443)
            .await
            .err()
            .ok_or("the negative returned addresses")?;
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_eq!(
            negative_cause(&error)?.kind(),
            AddressNegativeKind::NxDomain
        );
        let bound = Duration::from_secs(reported.min(configured));
        let expiry = stored_expiry(&cache)?;
        assert!(expiry >= before + bound);
        assert!(expiry <= after + bound);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn an_elapsed_negative_dns_lifetime_or_profile_cap_is_not_restarted() -> TestResult {
    let short = Duration::from_millis(1);
    for (ttl, cap) in [(short, LONG_TTL), (LONG_TTL, short)] {
        let answer = AddressAnswer::negative(AddressNegativeKind::NoData, Some(ttl));
        let after = Instant::now();
        tokio::time::sleep(short + Duration::from_millis(5)).await;
        assert!(after.elapsed() >= short);
        let calls = Arc::new(AtomicUsize::new(0));
        let cache = typed_cache(&calls, settings(4, LONG_TTL, Some(cap)), move || {
            Ok(answer.clone())
        });
        for _ in 0..2 {
            let error = cache
                .lookup(HOST, 443)
                .await
                .err()
                .ok_or("the negative returned addresses")?;
            assert_eq!(negative_cause(&error)?.kind(), AddressNegativeKind::NoData);
            assert!(
                cache.is_empty(),
                "publication restarted the negative lifetime"
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn negatives_without_a_live_dns_lifetime_and_enabled_cap_are_not_stored() -> TestResult {
    for (ttl, cap) in [
        (None, Some(LONG_TTL)),
        (Some(Duration::ZERO), Some(LONG_TTL)),
        (Some(LONG_TTL), None),
        (Some(LONG_TTL), Some(Duration::ZERO)),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let cache = typed_cache(&calls, settings(4, LONG_TTL, cap), move || {
            Ok(AddressAnswer::negative(AddressNegativeKind::NoData, ttl))
        });
        for _ in 0..2 {
            let error = cache
                .lookup(HOST, 443)
                .await
                .err()
                .ok_or("the negative returned addresses")?;
            assert_eq!(negative_cause(&error)?.kind(), AddressNegativeKind::NoData);
            assert!(cache.is_empty());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn an_unrepresentable_typed_lifetime_does_not_create_infinite_freshness() -> TestResult {
    for negative in [false, true] {
        let calls = Arc::new(AtomicUsize::new(0));
        let cache = typed_cache(
            &calls,
            settings(4, LONG_TTL, Some(Duration::MAX)),
            move || {
                if negative {
                    Ok(AddressAnswer::negative(
                        AddressNegativeKind::NxDomain,
                        Some(Duration::MAX),
                    ))
                } else {
                    AddressAnswer::positive(vec![V4], Duration::MAX)
                }
            },
        );
        let result = cache.lookup(HOST, 443).await;
        if negative {
            assert_eq!(
                negative_cause(&result.err().ok_or("negative resolved")?)?.kind(),
                AddressNegativeKind::NxDomain
            );
        } else {
            assert_eq!(result?, [SocketAddr::new(V4, 443)]);
        }
        assert!(cache.is_empty());
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn shared_and_stored_negatives_preserve_each_kind_and_the_original_cause() -> TestResult {
    for kind in [AddressNegativeKind::NxDomain, AddressNegativeKind::NoData] {
        let calls = Arc::new(AtomicUsize::new(0));
        let (open, gate) = watch::channel(false);
        let counter = Arc::clone(&calls);
        let resolver = AddressResolver::from_answer_fn(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            let mut gate = gate.clone();
            async move {
                gate.wait_for(|open| *open)
                    .await
                    .map_err(io::Error::other)?;
                Ok(AddressAnswer::negative(kind, Some(LONG_TTL)))
            }
        });
        let cache = AddressCache::with_resolver(settings(4, LONG_TTL, Some(LONG_TTL)), resolver);
        let first = cache.cached_or_pending(HOST.into())?;
        let joined = cache.cached_or_pending(HOST.into())?;
        assert!(matches!(first, Answer::Wait(_)));
        assert!(matches!(joined, Answer::Wait(_)));
        open.send(true)?;
        let first = consume_failure(&cache, first).await?;
        let joined = consume_failure(&cache, joined).await?;
        let stored = cache.cached_or_pending(HOST.into())?;
        assert!(matches!(stored, Answer::Stored(_)));
        let stored = consume_failure(&cache, stored).await?;
        let original = negative_cause(&first)?;
        assert_eq!(original.kind(), kind);
        assert!(std::ptr::eq(original, negative_cause(&joined)?));
        assert!(std::ptr::eq(original, negative_cause(&stored)?));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn operational_typed_callback_errors_keep_their_nested_cause_and_are_retried() -> TestResult {
    for kind in [
        io::ErrorKind::TimedOut,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::InvalidData,
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let identity = Arc::new(());
        let payload_identity = Arc::clone(&identity);
        let cache = typed_cache(&calls, settings(4, LONG_TTL, Some(LONG_TTL)), move || {
            Err(io::Error::new(
                kind,
                ResolverFailure {
                    identity: Arc::clone(&payload_identity),
                    cause: super::NestedResolverFailure(47),
                },
            ))
        });
        for _ in 0..2 {
            let error = cache
                .lookup(HOST, 443)
                .await
                .err()
                .ok_or("the error resolved")?;
            assert_eq!(error.kind(), kind);
            let mut source: &(dyn Error + 'static) = &error;
            loop {
                if let Some(original) = source.downcast_ref::<io::Error>()
                    && let Some(payload) = original
                        .get_ref()
                        .and_then(|payload| payload.downcast_ref::<ResolverFailure>())
                {
                    assert!(Arc::ptr_eq(&identity, &payload.identity));
                    assert_eq!(payload.cause.0, 47);
                    break;
                }
                source = source
                    .source()
                    .ok_or("the original error payload was lost")?;
            }
            assert!(
                cache.is_empty(),
                "an operational error poisoned negative caching"
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn an_err_wrapping_a_negative_cause_cannot_authorize_cache_retention() -> TestResult {
    let error = Resolved::Answer(AddressAnswer::negative(
        AddressNegativeKind::NxDomain,
        Some(LONG_TTL),
    ))
    .into_parts()
    .0
    .err()
    .ok_or("negative resolved")?;
    let cause = *negative_cause(&error)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let cache = typed_cache(&calls, settings(4, LONG_TTL, Some(LONG_TTL)), move || {
        Err(io::Error::new(io::ErrorKind::NotFound, cause))
    });
    for _ in 0..2 {
        let error = cache
            .lookup(HOST, 443)
            .await
            .err()
            .ok_or("negative resolved")?;
        assert_eq!(
            negative_cause(&error)?.kind(),
            AddressNegativeKind::NxDomain
        );
        assert!(cache.is_empty());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn operational_errors_share_the_current_lookup_but_not_the_next_lookup() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let identity = Arc::new(());
    let payload_identity = Arc::clone(&identity);
    let counter = Arc::clone(&calls);
    let (open, gate) = watch::channel(false);
    let resolver = AddressResolver::from_answer_fn(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        let identity = Arc::clone(&payload_identity);
        let mut gate = gate.clone();
        async move {
            gate.wait_for(|open| *open)
                .await
                .map_err(io::Error::other)?;
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                ResolverFailure {
                    identity,
                    cause: super::NestedResolverFailure(47),
                },
            ))
        }
    });
    let cache = AddressCache::with_resolver(settings(4, LONG_TTL, Some(LONG_TTL)), resolver);
    let first = cache.cached_or_pending(HOST.into())?;
    let joined = cache.cached_or_pending(HOST.into())?;
    open.send(true)?;
    let first = consume_failure(&cache, first).await?;
    let joined = consume_failure(&cache, joined).await?;
    assert!(std::ptr::eq(
        super::assert_typed_resolver_cause(&first, &identity)?,
        super::assert_typed_resolver_cause(&joined, &identity)?,
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(cache.is_empty());
    let next = cache.cached_or_pending(HOST.into())?;
    assert!(matches!(next, Answer::Wait(_)));
    let next = consume_failure(&cache, next).await?;
    super::assert_typed_resolver_cause(&next, &identity)?;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(cache.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn operational_errors_past_the_shared_bound_remain_uncached() -> TestResult {
    let (open, gate) = watch::channel(false);
    let resolver = AddressResolver::from_answer_fn(move |host| {
        let mut gate = gate.clone();
        async move {
            if host == "held.phantom.test" {
                gate.wait_for(|open| *open)
                    .await
                    .map_err(io::Error::other)?;
                return AddressAnswer::positive(vec![V4], LONG_TTL);
            }
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the DNS exchange timed out",
            ))
        }
    });
    let cache = AddressCache::with_resolver(settings(1, LONG_TTL, Some(LONG_TTL)), resolver);
    let mut held = cache.cached_or_pending("held.phantom.test".into())?;
    for _ in 0..2 {
        let inline = cache.cached_or_pending(HOST.into())?;
        assert!(matches!(inline, Answer::Inline { .. }));
        assert_eq!(
            consume_failure(&cache, inline).await?.kind(),
            io::ErrorKind::TimedOut
        );
        assert!(cache.is_empty());
        assert_eq!(cache.lock().shared_resolutions, 1);
    }
    open.send(true)?;
    wait_until_published(&mut held).await?;
    assert_eq!(
        cache.consume_answer(held, 443).await?.0,
        [SocketAddr::new(V4, 443)]
    );
    assert_eq!(cache.lock().shared_resolutions, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn inline_typed_answers_keep_bounded_positive_and_negative_lifetimes() -> TestResult {
    for negative in [false, true] {
        let ttl = Duration::from_secs(60);
        let before = Instant::now();
        let answer = if negative {
            AddressAnswer::negative(AddressNegativeKind::NoData, Some(ttl))
        } else {
            AddressAnswer::positive(vec![V6, V4], ttl)?
        };
        let after = Instant::now();
        let (open, gate) = watch::channel(false);
        let resolver = AddressResolver::from_answer_fn(move |host| {
            let mut gate = gate.clone();
            let answer = answer.clone();
            async move {
                if host == "held.phantom.test" {
                    gate.wait_for(|open| *open)
                        .await
                        .map_err(io::Error::other)?;
                    return AddressAnswer::positive(vec![V4], LONG_TTL);
                }
                Ok(answer)
            }
        });
        let mut config = settings(1, LONG_TTL, Some(LONG_TTL));
        config.min_record_ttl = LONG_TTL;
        let cache = AddressCache::with_resolver(config, resolver);
        let mut held = cache.cached_or_pending("held.phantom.test".into())?;
        let inline = cache.cached_or_pending(HOST.into())?;
        assert!(matches!(inline, Answer::Inline { .. }));
        let result = cache.consume_answer(inline, 8443).await;
        if negative {
            let error = result.err().ok_or("negative resolved")?;
            assert_eq!(negative_cause(&error)?.kind(), AddressNegativeKind::NoData);
        } else {
            assert_eq!(
                result?,
                (
                    vec![SocketAddr::new(V6, 8443), SocketAddr::new(V4, 8443)],
                    false
                )
            );
        }
        let expiry = stored_expiry(&cache)?;
        assert!(expiry >= before + ttl);
        assert!(expiry <= after + ttl);
        assert_eq!(cache.lock().shared_resolutions, 1);
        open.send(true)?;
        wait_until_published(&mut held).await?;
        cache.consume_answer(held, 443).await?;
        assert_eq!(cache.lock().shared_resolutions, 0);
    }
    Ok(())
}

fn gated_typed_resolver(
    active: &Arc<AtomicUsize>,
    started: &Arc<AtomicUsize>,
    gate: watch::Receiver<bool>,
) -> AddressResolver {
    let active = Arc::clone(active);
    let started = Arc::clone(started);
    AddressResolver::from_answer_fn(move |_| {
        let active = Arc::clone(&active);
        let started = Arc::clone(&started);
        let mut gate = gate.clone();
        async move {
            active.fetch_add(1, Ordering::SeqCst);
            let _live = super::LiveLookup(active);
            started.fetch_add(1, Ordering::SeqCst);
            gate.wait_for(|open| *open)
                .await
                .map_err(io::Error::other)?;
            AddressAnswer::positive(vec![V4], LONG_TTL)
        }
    })
}

#[tokio::test(flavor = "current_thread")]
async fn clear_and_inline_cancellation_preserve_typed_background_capacity() -> TestResult {
    tokio::time::timeout(Duration::from_secs(5), async {
        let active = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicUsize::new(0));
        let (open, gate) = watch::channel(false);
        let cache = AddressCache::with_resolver(
            settings(1, LONG_TTL, None),
            gated_typed_resolver(&active, &started, gate),
        );
        let first = cache.cached_or_pending(HOST.into())?;
        while started.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        drop(first);
        cache.clear();
        let inline = cache.cached_or_pending(HOST.into())?;
        assert!(matches!(inline, Answer::Inline { .. }));
        let mut inline = Box::pin(cache.consume_answer(inline, 443));
        assert!(!poll_lookup_once(&mut inline).await);
        assert_eq!(active.load(Ordering::SeqCst), 2);
        drop(inline);
        assert_eq!(active.load(Ordering::SeqCst), 1);
        assert_eq!(cache.lock().shared_resolutions, 1);
        open.send(true)?;
        while active.load(Ordering::SeqCst) != 0 {
            tokio::task::yield_now().await;
        }
        assert!(
            cache.is_empty(),
            "the pre-clear generation stored an answer"
        );
        assert_eq!(cache.lock().shared_resolutions, 0);
        assert_eq!(cache.lookup(HOST, 443).await?, [SocketAddr::new(V4, 443)]);
        assert_eq!(started.load(Ordering::SeqCst), 3);
        assert_eq!(cache.len(), 1);
        Ok::<_, Box<dyn Error>>(())
    })
    .await?
}

#[test]
fn dropping_a_typed_resolver_runtime_releases_capacity_after_clear() -> TestResult {
    let active = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(AtomicUsize::new(0));
    let (open, gate) = watch::channel(false);
    let cache = AddressCache::with_resolver(
        settings(1, LONG_TTL, None),
        gated_typed_resolver(&active, &started, gate),
    );
    let first = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    first.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            drop(cache.cached_or_pending(HOST.into())?);
            while active.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
            Ok::<_, Box<dyn Error>>(())
        })
        .await?
    })?;
    cache.clear();
    drop(first);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(cache.lock().shared_resolutions, 0);
    let second = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    open.send(true)?;
    second.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), cache.lookup(HOST, 443)).await
    })??;
    assert_eq!(started.load(Ordering::SeqCst), 2);
    assert_eq!(cache.len(), 1);
    Ok(())
}

#[test]
fn a_typed_lookup_on_another_runtime_does_not_wait_on_a_stopped_owner() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let resolver = AddressResolver::from_answer_fn(move |_| {
        let call = counter.fetch_add(1, Ordering::SeqCst);
        async move {
            if call == 0 {
                std::future::pending::<()>().await;
            }
            AddressAnswer::positive(vec![V4], LONG_TTL)
        }
    });
    let cache = AddressCache::with_resolver(settings(4, LONG_TTL, None), resolver);
    let first = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let second = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    first.block_on(async {
        drop(cache.cached_or_pending(HOST.into())?);
        Ok::<_, Box<dyn Error>>(())
    })?;
    let addresses = second.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), cache.lookup(HOST, 443)).await
    })??;
    assert_eq!(addresses, [SocketAddr::new(V4, 443)]);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        cache.lock().shared_resolutions,
        1,
        "the stopped owner's task remains owned by its runtime"
    );
    drop(first);
    assert_eq!(cache.lock().shared_resolutions, 0);
    Ok(())
}
