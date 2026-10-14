use std::{
    error::Error,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use phantom_net::dns::{
    HttpsLookupError, HttpsLookupErrorKind, HttpsRecordAnswer, HttpsRecordLookup,
    HttpsRecordResolver,
};

use super::{DestinationError, ECH_A, H3, HOST, OWNER, PORT, TestResult, lookup, record};
use crate::session::alt_svc::{Discovery, HttpsRecordDiscovery};
use crate::{RequestError, RequestErrorKind, authority::Endpoint};

#[tokio::test]
async fn cached_prefixed_owner_cannot_authorize_the_selected_destination() -> TestResult {
    let records = HttpsRecordLookup::new(
        vec![HttpsRecordAnswer::new(
            OWNER,
            300,
            record(1, &[], &[H3, ECH_A])?,
        )],
        None,
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let discovery = HttpsRecordDiscovery::new(
        HttpsRecordResolver::from_fn(move |_, _| {
            counted.fetch_add(1, Ordering::SeqCst);
            let records = records.clone();
            async move { Ok(records) }
        }),
        NonZeroUsize::MIN,
    );
    for _ in 0..2 {
        assert!(matches!(
            discovery.destination_plan(HOST, PORT).await,
            Err(DestinationError::UnsupportedRecords)
        ));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn operational_failure_keeps_its_typed_cause_across_cached_default_projection() -> TestResult
{
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let discovery = HttpsRecordDiscovery::new(
        HttpsRecordResolver::from_fn(move |_, _| {
            counted.fetch_add(1, Ordering::SeqCst);
            async {
                Err(HttpsLookupError::other(std::io::Error::other(
                    "controlled lookup failure",
                )))
            }
        }),
        NonZeroUsize::MIN,
    );
    let error = match discovery.destination_plan(HOST, PORT).await {
        Ok(_) => return Err("lookup unexpectedly authorized a destination".into()),
        Err(error) => error,
    };
    let request = RequestError::alt_svc_https(error);
    assert_eq!(request.kind(), RequestErrorKind::Resolve);
    assert!(!request.is_http3_setup_failure());
    assert!(!request.is_retryable_connection_setup());
    let typed = request
        .source()
        .and_then(|source| source.downcast_ref::<DestinationError>())
        .ok_or("destination error was erased")?;
    let resolver = typed
        .source()
        .and_then(|source| source.downcast_ref::<HttpsLookupError>())
        .ok_or("resolver error was erased")?;
    assert_eq!(resolver.kind(), HttpsLookupErrorKind::Resolve);
    assert!(matches!(
        discovery.destination_plan(HOST, PORT).await,
        Err(DestinationError::Lookup(_))
    ));
    let origin = Endpoint::new("alt.test:8443".parse()?, PORT)?;
    assert!(matches!(
        discovery.discover(&origin),
        Discovery::NotAdvertised
    ));
    assert!(discovery.quic_ech(&origin).await.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn unfiltered_no_default_h3_is_reused_by_destination_but_not_default_discovery() -> TestResult
{
    let records = lookup([record(1, &[], &[H3, (2, b""), ECH_A])?]);
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let discovery = HttpsRecordDiscovery::new(
        HttpsRecordResolver::from_fn(move |host, port| {
            assert_eq!(host, HOST);
            assert_eq!(port, PORT);
            counted.fetch_add(1, Ordering::SeqCst);
            let records = records.clone();
            async move { Ok(records) }
        }),
        NonZeroUsize::MIN,
    );
    for _ in 0..2 {
        let plan = discovery.destination_plan(HOST, PORT).await?;
        assert_eq!(
            plan.ech.map(|ech| ech.as_bytes().to_vec()),
            Some(ECH_A.1.to_vec())
        );
    }
    let origin = Endpoint::new("alt.test:8443".parse()?, PORT)?;
    assert!(matches!(
        discovery.discover(&origin),
        Discovery::NotAdvertised
    ));
    assert!(discovery.quic_ech(&origin).await.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn expired_answer_serves_current_waiters_without_restarting_its_lifetime() -> TestResult {
    let records = lookup([record(1, &[], &[H3, ECH_A])?]).with_cache_deadline(Instant::now());
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let discovery = HttpsRecordDiscovery::new(
        HttpsRecordResolver::from_fn(move |_, _| {
            counted.fetch_add(1, Ordering::SeqCst);
            let records = records.clone();
            async move { Ok(records) }
        }),
        NonZeroUsize::MIN,
    );
    for _ in 0..2 {
        assert!(discovery.destination_plan(HOST, PORT).await?.ech.is_some());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn capacity_and_ip_rejection_are_not_empty_dns_answers() -> TestResult {
    let (release, released) = tokio::sync::watch::channel(false);
    let discovery = HttpsRecordDiscovery::new(
        HttpsRecordResolver::from_fn(move |_, _| {
            let mut released = released.clone();
            async move {
                let _ = released.wait_for(|value| *value).await;
                Ok(HttpsRecordLookup::new(Vec::new(), Some(30)))
            }
        }),
        NonZeroUsize::MIN,
    );
    let first = discovery.destination_plan(HOST, PORT);
    assert!(matches!(
        discovery.destination_plan("other.test", PORT).await,
        Err(DestinationError::Capacity)
    ));
    assert!(matches!(
        discovery.destination_plan("127.0.0.1", PORT).await,
        Err(DestinationError::IpLiteral)
    ));
    release.send_replace(true);
    assert!(
        tokio::time::timeout(Duration::from_secs(5), first)
            .await??
            .ech
            .is_none()
    );
    Ok(())
}

#[test]
fn runtime_shutdown_reports_cancelled_instead_of_authorizing_no_ech() -> TestResult {
    let discovery = HttpsRecordDiscovery::new(
        HttpsRecordResolver::from_fn(|_, _| async {
            std::future::pending::<Result<HttpsRecordLookup, HttpsLookupError>>().await
        }),
        NonZeroUsize::MIN,
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let pending = {
        let _entered = runtime.enter();
        discovery.destination_plan(HOST, PORT)
    };
    drop(runtime);
    let next = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let error = match next
        .block_on(async { tokio::time::timeout(Duration::from_secs(5), pending).await })?
    {
        Ok(_) => return Err("abandoned lookup authorized a destination".into()),
        Err(error) => error,
    };
    assert!(matches!(error, DestinationError::Cancelled));
    assert!(matches!(
        lookup_error_without_runtime(&discovery),
        DestinationError::RuntimeUnavailable
    ));
    Ok(())
}

fn lookup_error_without_runtime(discovery: &HttpsRecordDiscovery) -> DestinationError {
    let future = discovery.destination_plan(HOST, PORT);
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match std::future::Future::poll(future.as_mut(), &mut context) {
        std::task::Poll::Ready(Err(error)) => error,
        _ => panic!("lookup without a runtime was not rejected"),
    }
}

#[tokio::test]
async fn missing_soa_empty_answer_is_usable_without_becoming_a_cached_permission() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let discovery = HttpsRecordDiscovery::new(
        HttpsRecordResolver::from_fn(move |_, _| {
            counted.fetch_add(1, Ordering::SeqCst);
            async { Ok(HttpsRecordLookup::new(Vec::new(), None)) }
        }),
        NonZeroUsize::MIN,
    );
    for _ in 0..2 {
        assert!(discovery.destination_plan(HOST, PORT).await?.ech.is_none());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn destination_ports_have_separate_metadata_and_cache_entries() -> TestResult {
    let records = lookup([record(1, &[], &[H3, (3, &PORT.to_be_bytes()), ECH_A])?]);
    let queries = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = Arc::clone(&queries);
    let discovery = HttpsRecordDiscovery::new(
        HttpsRecordResolver::from_fn(move |host, port| {
            let result = match recorded.lock() {
                Ok(mut queries) => {
                    queries.push((host, port));
                    Ok(records.clone())
                }
                Err(_) => Err(HttpsLookupError::other(std::io::Error::other(
                    "query log poisoned",
                ))),
            };
            async move { result }
        }),
        NonZeroUsize::new(2).ok_or("zero capacity")?,
    );
    assert!(discovery.destination_plan(HOST, PORT).await?.ech.is_some());
    assert!(matches!(
        discovery.destination_plan(HOST, 443).await,
        Err(DestinationError::UnsupportedRecords)
    ));
    assert!(discovery.destination_plan(HOST, PORT).await?.ech.is_some());
    assert_eq!(
        *queries.lock().map_err(|_| "query log poisoned")?,
        [(HOST.to_owned(), PORT), (HOST.to_owned(), 443)]
    );
    Ok(())
}
