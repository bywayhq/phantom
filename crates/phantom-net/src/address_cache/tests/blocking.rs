use std::{sync::mpsc, thread};

use super::*;

const HOST: &str = "origin.phantom.test";

#[tokio::test(flavor = "current_thread")]
async fn a_native_worker_shares_its_answer_after_all_original_waiters_are_dropped() -> TestResult {
    let caller = thread::current().id();
    let (entered, mut started) = watch::channel(None);
    let (release, gate) = mpsc::channel();
    let gate = Mutex::new(gate);
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let cache = AddressCache::with_blocking_lookup(long_lived(), move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        entered.send_replace(Some(thread::current().id()));
        gate.lock()
            .map_err(|_| io::Error::other("native lookup gate poisoned"))?
            .recv_timeout(Duration::from_secs(5))
            .map_err(io::Error::other)?;
        Ok(Resolved::without_ttl([V6, V4, V6]))
    });
    let first = cache.cached_or_pending(HOST.into())?;
    let joined = cache.cached_or_pending(HOST.into())?;
    let admitted = tokio::time::timeout(Duration::from_secs(5), started.wait_for(Option::is_some))
        .await
        .map(|result| result.map(|worker| *worker));

    drop(first);
    drop(joined);
    let remaining = cache.cached_or_pending(HOST.into())?;
    release.send(())?;
    let worker = admitted??.ok_or("native lookup did not enter its worker")?;
    assert_ne!(worker, caller);
    let (addresses, stored) =
        tokio::time::timeout(Duration::from_secs(5), cache.consume_answer(remaining, 443))
            .await??;

    assert_eq!(
        addresses,
        [
            SocketAddr::new(V6, 443),
            SocketAddr::new(V4, 443),
            SocketAddr::new(V6, 443),
        ]
    );
    assert!(!stored);
    assert!(cache.lookup_noting_cache(HOST, 8443).await?.1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_native_worker_preserves_typed_errors_in_fresh_and_cached_deliveries() -> TestResult {
    let identity = Arc::new(());
    let captured = Arc::clone(&identity);
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let cache = AddressCache::with_blocking_lookup(
        settings(4, Duration::from_secs(600), Some(Duration::from_secs(600))),
        move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                ResolverFailure {
                    identity: Arc::clone(&captured),
                    cause: NestedResolverFailure(47),
                },
            ))
        },
    );

    for _ in 0..2 {
        let lookup = cache.lookup(HOST, 443);
        let error = tokio::time::timeout(Duration::from_secs(5), lookup)
            .await?
            .err()
            .ok_or("the native lookup returned addresses")?;
        assert_typed_resolver_cause(&error, &identity)?;
    }

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_panicked_native_worker_releases_its_publication_for_the_next_lookup() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let cache = AddressCache::with_blocking_lookup(long_lived(), move |_| {
        if counter.fetch_add(1, Ordering::SeqCst) == 0 {
            panic!("native lookup panic control");
        }
        Ok(Resolved::without_ttl([V4]))
    });

    let failed = tokio::time::timeout(Duration::from_secs(5), cache.lookup(HOST, 443)).await?;
    let error = failed.err().ok_or("the panicked native lookup answered")?;
    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert!(cache.is_empty());
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let released = {
                let state = cache.lock();
                state.shared_resolutions == 0 && state.publications.is_empty()
            };
            if released {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;

    let addresses = tokio::time::timeout(Duration::from_secs(5), cache.lookup(HOST, 443)).await??;
    assert_eq!(addresses, [SocketAddr::new(V4, 443)]);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(cache.lock().pending.is_empty());
    Ok(())
}

#[test]
fn a_shut_down_runtime_drops_a_queued_native_lookup_without_invoking_it() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let cache = AddressCache::with_blocking_lookup(long_lived(), move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok(Resolved::without_ttl([V4]))
    });
    let first = tokio::runtime::Builder::new_current_thread().build()?;
    let dead = first.handle().clone();
    first.shutdown_background();
    let second = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let dropped = second.block_on(async {
        let lookup = tokio::time::timeout(Duration::from_secs(5), cache.lookup(HOST, 443));
        let _entered = dead.enter();
        lookup.await
    })?;
    assert!(dropped.is_err(), "a dropped native lookup answered");
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let addresses = second.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), cache.lookup(HOST, 443)).await
    })??;
    assert_eq!(addresses, [SocketAddr::new(V4, 443)]);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}
