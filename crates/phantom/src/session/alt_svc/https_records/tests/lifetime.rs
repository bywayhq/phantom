use super::{
    Arc, AtomicUsize, Discovery, Duration, H3, HOST, HttpsRecordAnswer, HttpsRecordDiscovery,
    HttpsRecordLookup, HttpsRecordResolver, NonZeroUsize, Ordering, TestResult, endpoint, rdata,
    record, settle,
};
use std::time::Instant;

#[tokio::test]
async fn held_fractional_answer_satisfies_waiter_without_becoming_fresh_again() -> TestResult<()> {
    let advertised = record(&rdata(1, &[], &[H3]))?;
    let lookup = HttpsRecordLookup::new(vec![HttpsRecordAnswer::new(HOST, 300, advertised)], None)
        .with_cache_lifetime(Duration::from_millis(30));
    let cloned = lookup.clone();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(cloned.cache_deadline(Duration::from_secs(300)), None);
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let discovery = HttpsRecordDiscovery::new(
        HttpsRecordResolver::from_fn(move |_, _| {
            counted.fetch_add(1, Ordering::SeqCst);
            let lookup = cloned.clone();
            async move { Ok(lookup) }
        }),
        NonZeroUsize::MIN,
    );
    let origin = endpoint(HOST)?;
    assert!(settle(&discovery, &origin).await?);
    assert!(discovery.cache.lock_state().ready.is_empty());
    assert!(discovery.cache.lock_state().pending.is_empty());
    assert!(settle(&discovery, &origin).await?);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn empty_without_soa_and_zero_soa_results_are_not_cached() -> TestResult<()> {
    for negative_ttl in [None, Some(0)] {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let resolver = HttpsRecordResolver::from_fn(move |_, _| {
            counted.fetch_add(1, Ordering::SeqCst);
            async move { Ok(HttpsRecordLookup::new(Vec::new(), negative_ttl)) }
        });
        let discovery = HttpsRecordDiscovery::new(resolver, NonZeroUsize::MIN);
        let origin = endpoint(HOST)?;
        assert!(!settle(&discovery, &origin).await?);
        assert!(discovery.cache.lock_state().ready.is_empty());
        assert!(!settle(&discovery, &origin).await?);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
    Ok(())
}

#[tokio::test]
async fn completion_rechecks_deadline_and_releases_pending_admission() -> TestResult<()> {
    let resolver =
        HttpsRecordResolver::from_fn(|_, _| async { Ok(HttpsRecordLookup::new(Vec::new(), None)) });
    let discovery = HttpsRecordDiscovery::new(resolver, NonZeroUsize::MIN);
    let (_, result) = tokio::sync::watch::channel(None);
    let runtime = tokio::runtime::Handle::current().id();
    discovery
        .cache
        .lock_state()
        .pending
        .push(super::super::PendingEntry {
            host: HOST.into(),
            port: 443,
            lookup: 17,
            result,
            runtime,
        });
    discovery
        .cache
        .complete(17, Arc::default(), Some(Instant::now()));
    assert!(discovery.cache.lock_state().ready.is_empty());
    assert!(discovery.cache.lock_state().pending.is_empty());
    let Discovery::Pending(lookup) = discovery.discover(&endpoint("other.test")?) else {
        return Err("expired publication did not release admission".into());
    };
    assert!(!lookup.advertises_h3().await);
    Ok(())
}

#[tokio::test]
async fn finite_soa_result_is_reused_without_an_invented_lifetime() -> TestResult<()> {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let resolver = HttpsRecordResolver::from_fn(move |_, _| {
        counted.fetch_add(1, Ordering::SeqCst);
        async { Ok(HttpsRecordLookup::new(Vec::new(), Some(30))) }
    });
    let discovery = HttpsRecordDiscovery::new(resolver, NonZeroUsize::MIN);
    let origin = endpoint(HOST)?;
    assert!(!settle(&discovery, &origin).await?);
    assert!(matches!(
        discovery.discover(&origin),
        Discovery::NotAdvertised
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}
