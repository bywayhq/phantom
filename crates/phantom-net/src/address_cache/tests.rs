use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::Poll,
    time::Duration,
};

use phantom_profile::DnsCacheSettings;
use tokio::sync::watch;

use super::{AddressCache, Answer};
use crate::host_resolver::{AddressResolver, Resolved};

mod routes;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const V6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
const V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const V4_OTHER: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));

fn settings(max_entries: usize, ttl: Duration, negative_ttl: Option<Duration>) -> DnsCacheSettings {
    DnsCacheSettings {
        max_entries: NonZeroUsize::new(max_entries).unwrap_or(NonZeroUsize::MIN),
        ttl,
        min_record_ttl: Duration::ZERO,
        negative_ttl,
    }
}

fn long_lived() -> DnsCacheSettings {
    settings(16, Duration::from_secs(600), None)
}

/// A resolver that records each name it is asked for and answers with a
/// fixed result once its gate opens.
#[derive(Clone)]
struct Recorder {
    names: Arc<Mutex<Vec<Box<str>>>>,
    calls: Arc<AtomicUsize>,
    gate: watch::Receiver<bool>,
}

impl Recorder {
    fn open() -> Self {
        Self::gated(watch::channel(true).1)
    }

    fn gated(gate: watch::Receiver<bool>) -> Self {
        Self {
            names: Arc::default(),
            calls: Arc::default(),
            gate,
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn names(&self) -> Vec<Box<str>> {
        self.names
            .lock()
            .map(|names| names.clone())
            .unwrap_or_default()
    }

    fn cache(
        &self,
        settings: DnsCacheSettings,
        answer: impl Fn() -> io::Result<Vec<SocketAddr>> + Send + Sync + 'static,
    ) -> AddressCache {
        let recorder = self.clone();
        let answer = Arc::new(answer);
        AddressCache::with_lookup(settings, move |host| {
            recorder.calls.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut names) = recorder.names.lock() {
                names.push(host);
            }
            let mut gate = recorder.gate.clone();
            let answer = Arc::clone(&answer);
            Box::pin(async move {
                let _ = gate.wait_for(|open| *open).await;
                answer()
            })
        })
    }
}

fn answer(
    addresses: &[IpAddr],
) -> impl Fn() -> io::Result<Vec<SocketAddr>> + Send + Sync + 'static {
    let addresses = addresses
        .iter()
        .map(|address| SocketAddr::new(*address, 0))
        .collect::<Vec<_>>();
    move || Ok(addresses.clone())
}

fn not_found() -> io::Result<Vec<SocketAddr>> {
    Err(io::Error::new(io::ErrorKind::NotFound, "no such host"))
}

/// Waits for the real resolver's publisher before consuming its selected answer.
async fn wait_until_published(answer: &mut Answer) -> TestResult {
    let Answer::Wait(receiver) = answer else {
        return Err("expected a shared resolution receiver".into());
    };
    tokio::time::timeout(Duration::from_secs(5), receiver.wait_for(Option::is_some)).await??;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_new_resolution_published_before_consumption_is_not_a_cache_hit() -> TestResult {
    let recorder = Recorder::open();
    let cache = recorder.cache(long_lived(), answer(&[V6, V4]));
    let mut selected = cache.cached_or_pending("origin.phantom.test".into())?;
    wait_until_published(&mut selected).await?;

    let (addresses, stored) = cache.consume_answer(selected, 8443).await?;

    assert_eq!(
        addresses,
        [SocketAddr::new(V6, 8443), SocketAddr::new(V4, 8443)]
    );
    assert_eq!(recorder.calls(), 1);
    assert_eq!(cache.len(), 1, "the real publisher stored its answer");
    assert!(
        !stored,
        "publication does not turn a resolution into a cache hit"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_joined_resolution_published_before_consumption_is_not_a_cache_hit() -> TestResult {
    let (open, gate) = watch::channel(false);
    let recorder = Recorder::gated(gate);
    let cache = recorder.cache(long_lived(), answer(&[V4]));
    let first = cache.cached_or_pending("origin.phantom.test".into())?;
    let mut joined = cache.cached_or_pending("origin.phantom.test".into())?;
    assert_eq!(
        recorder.calls(),
        1,
        "the second lookup joined real pending work"
    );
    open.send(true)?;
    wait_until_published(&mut joined).await?;

    let (addresses, stored) = cache.consume_answer(joined, 443).await?;

    assert_eq!(addresses, [SocketAddr::new(V4, 443)]);
    assert_eq!(recorder.calls(), 1);
    assert_eq!(cache.len(), 1, "the shared publisher stored its answer");
    assert!(!stored, "a pending waiter did not select a stored entry");
    drop(first);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_fresh_stored_entry_reports_a_cache_hit_without_another_resolution() -> TestResult {
    let recorder = Recorder::open();
    let cache = recorder.cache(long_lived(), answer(&[V4]));
    cache.lookup("origin.phantom.test", 443).await?;

    let (addresses, stored) = cache
        .lookup_noting_cache("Origin.Phantom.TEST", 8443)
        .await?;

    assert_eq!(addresses, [SocketAddr::new(V4, 8443)]);
    assert_eq!(recorder.calls(), 1);
    assert!(stored);

    let (literal, stored) = cache.lookup_noting_cache("127.0.0.1", 443).await?;
    assert_eq!(literal, [SocketAddr::new(V4, 443)]);
    assert!(!stored, "an IP literal is not a cache entry");
    assert_eq!(recorder.calls(), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn repeated_lookups_within_the_ttl_resolve_once() -> TestResult {
    let recorder = Recorder::open();
    let cache = recorder.cache(long_lived(), answer(&[V4]));

    let first = cache.lookup("origin.phantom.test", 443).await?;
    let second = cache.lookup("origin.phantom.test", 8443).await?;

    assert_eq!(first, [SocketAddr::new(V4, 443)]);
    assert_eq!(second, [SocketAddr::new(V4, 8443)]);
    assert_eq!(recorder.calls(), 1);
    assert_eq!(cache.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn answers_keep_the_resolver_order() -> TestResult {
    let recorder = Recorder::open();
    let cache = recorder.cache(long_lived(), answer(&[V4_OTHER, V6, V4]));

    let _ = cache.lookup("origin.phantom.test", 443).await?;
    let cached = cache.lookup("origin.phantom.test", 443).await?;

    assert_eq!(
        cached,
        [
            SocketAddr::new(V4_OTHER, 443),
            SocketAddr::new(V6, 443),
            SocketAddr::new(V4, 443),
        ]
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn names_differing_only_in_case_share_an_entry() -> TestResult {
    let recorder = Recorder::open();
    let cache = recorder.cache(long_lived(), answer(&[V4]));

    let _ = cache.lookup("Origin.Phantom.TEST", 443).await?;
    let _ = cache.lookup("origin.phantom.test", 443).await?;

    assert_eq!(recorder.calls(), 1);
    assert_eq!(recorder.names(), [Box::from("origin.phantom.test")]);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn an_expired_answer_is_resolved_again() -> TestResult {
    let recorder = Recorder::open();
    let cache = recorder.cache(settings(16, Duration::from_millis(50), None), answer(&[V4]));

    let _ = cache.lookup("origin.phantom.test", 443).await?;
    tokio::time::sleep(Duration::from_millis(120)).await;
    let _ = cache.lookup("origin.phantom.test", 443).await?;

    assert_eq!(recorder.calls(), 2);
    Ok(())
}

/// A resolver whose answers carry `record_ttl`, counting its lookups.
fn with_record_ttl(calls: &Arc<AtomicUsize>, record_ttl: Duration) -> AddressResolver {
    let calls = Arc::clone(calls);
    AddressResolver::from_resolved_fn(move |_| {
        calls.fetch_add(1, Ordering::SeqCst);
        async move {
            let mut resolved = Resolved::without_ttl([V4]);
            resolved.ttl = Some(record_ttl);
            Ok(resolved)
        }
    })
}

#[tokio::test(flavor = "current_thread")]
async fn an_answer_with_a_record_ttl_is_kept_for_that_ttl_instead_of_the_ttl() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut settings = settings(16, Duration::from_secs(600), None);
    settings.min_record_ttl = Duration::from_millis(10);
    let cache =
        AddressCache::with_resolver(settings, with_record_ttl(&calls, Duration::from_millis(50)));

    let _ = cache.lookup("origin.phantom.test", 443).await?;
    let _ = cache.lookup("origin.phantom.test", 443).await?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    tokio::time::sleep(Duration::from_millis(120)).await;
    let _ = cache.lookup("origin.phantom.test", 443).await?;

    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_record_ttl_below_the_minimum_is_kept_for_the_minimum() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut settings = settings(16, Duration::ZERO, None);
    settings.min_record_ttl = Duration::from_secs(600);
    let cache = AddressCache::with_resolver(settings, with_record_ttl(&calls, Duration::ZERO));

    let _ = cache.lookup("origin.phantom.test", 443).await?;
    let _ = cache.lookup("origin.phantom.test", 443).await?;

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_lookups_share_one_resolution() -> TestResult {
    let (open, gate) = watch::channel(false);
    let recorder = Recorder::gated(gate);
    let cache = recorder.cache(long_lived(), answer(&[V6, V4]));
    let mut lookups = (0..8)
        .map(|_| Box::pin(cache.lookup_noting_cache("origin.phantom.test", 443)))
        .collect::<Vec<_>>();

    for lookup in &mut lookups {
        if let Poll::Ready(result) =
            poll_fn(|context| Poll::Ready(lookup.as_mut().poll(context))).await
        {
            result?;
            return Err("a gated lookup finished before its resolver was released".into());
        }
    }
    assert_eq!(
        recorder.calls(),
        1,
        "all eight lookups selected pending work"
    );

    open.send(true)?;
    for lookup in lookups {
        let (addresses, stored) = tokio::time::timeout(Duration::from_secs(5), lookup).await??;

        assert_eq!(
            addresses,
            [SocketAddr::new(V6, 443), SocketAddr::new(V4, 443)]
        );
        assert!(!stored, "a pending lookup did not select a stored answer");
    }
    assert_eq!(recorder.calls(), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_resolution_fills_the_cache_after_its_lookups_are_dropped() -> TestResult {
    let (open, gate) = watch::channel(false);
    let recorder = Recorder::gated(gate);
    let cache = recorder.cache(long_lived(), answer(&[V4]));

    let abandoned = tokio::time::timeout(
        Duration::from_millis(20),
        cache.lookup("origin.phantom.test", 443),
    )
    .await;
    assert!(abandoned.is_err(), "the gated lookup finished early");
    open.send(true)?;
    let _ = cache.lookup("origin.phantom.test", 443).await?;
    let _ = cache.lookup("origin.phantom.test", 443).await?;

    assert_eq!(recorder.calls(), 1);
    Ok(())
}

#[test]
fn a_lookup_does_not_depend_on_another_runtime_being_driven() -> TestResult {
    let (open, gate) = watch::channel(false);
    let recorder = Recorder::gated(gate);
    let cache = recorder.cache(long_lived(), answer(&[V4]));
    let first = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut first_lookup = Box::pin(cache.lookup_noting_cache("origin.phantom.test", 443));

    let first_poll = first.block_on(poll_fn(|context| {
        Poll::Ready(first_lookup.as_mut().poll(context))
    }));
    let first_calls = recorder.calls();

    // The first runtime and its pending lookup stay alive without being driven.
    let observed = std::thread::scope(|scope| -> TestResult {
        let (ready, readiness) = std::sync::mpsc::channel();
        let (completed, completion) = std::sync::mpsc::channel();
        let second = match std::thread::Builder::new().spawn_scoped(scope, {
            let cache = cache.clone();
            move || {
                let result = (|| -> io::Result<(Vec<SocketAddr>, bool)> {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    let mut lookup =
                        Box::pin(cache.lookup_noting_cache("origin.phantom.test", 443));

                    runtime.block_on(async {
                        if let Poll::Ready(result) =
                            poll_fn(|context| Poll::Ready(lookup.as_mut().poll(context))).await
                        {
                            result?;
                            return Err(io::Error::other(
                                "the second lookup finished before its resolver was released",
                            ));
                        }

                        ready.send(()).map_err(io::Error::other)?;

                        tokio::time::timeout(Duration::from_secs(5), lookup)
                            .await
                            .map_err(io::Error::other)?
                    })
                })();

                completed.send(result)
            }
        }) {
            Ok(second) => second,
            Err(error) => {
                open.send(true)?;
                return Err(error.into());
            }
        };

        let ready_result = readiness.recv_timeout(Duration::from_secs(5));
        let calls_before_release = recorder.calls();
        let released = open.send(true);
        let second_result = completion.recv_timeout(Duration::from_secs(10));
        let joined = second.join().map_err(|_| "the second lookup panicked");

        // Release the resolver and observe the thread before any failing assertion.
        joined??;

        if let Poll::Ready(result) = first_poll {
            result?;
            return Err("the first lookup finished before its resolver was released".into());
        }

        let (addresses, stored) = second_result??;
        ready_result?;
        released?;

        assert_eq!(first_calls, 1, "the first lookup invoked the real resolver");
        assert_eq!(
            calls_before_release, 1,
            "the second lookup joined pending work"
        );
        assert_eq!(addresses, [SocketAddr::new(V4, 443)]);
        assert!(!stored, "the second runtime did not select a stored answer");
        assert_eq!(recorder.calls(), 1);
        Ok(())
    });

    drop(first_lookup);
    drop(first);
    observed
}

#[test]
fn a_resolution_a_shut_down_runtime_drops_is_released_and_restarted() -> TestResult {
    let recorder = Recorder::open();
    let cache = recorder.cache(long_lived(), answer(&[V4]));
    let first = tokio::runtime::Builder::new_current_thread().build()?;
    let dead = first.handle().clone();
    first.shutdown_background();
    let second = tokio::runtime::Builder::new_current_thread().build()?;

    // The resolution is spawned on the shut-down runtime, which drops it.
    let dropped = second.block_on(async {
        let lookup = cache.lookup("origin.phantom.test", 443);
        let _entered = dead.enter();
        lookup.await
    });
    assert!(dropped.is_err(), "a dropped resolution answered");
    let addresses = second.block_on(cache.lookup("origin.phantom.test", 443))?;

    assert_eq!(addresses, [SocketAddr::new(V4, 443)]);
    assert_eq!(
        recorder.calls(),
        2,
        "the next lookup started a new resolution"
    );
    Ok(())
}

#[test]
fn resolutions_in_flight_are_bounded_by_the_blocking_pool() -> TestResult {
    const POOL: usize = 2;
    let running = Arc::new(AtomicUsize::new(0));
    let most = Arc::new(AtomicUsize::new(0));
    let cache = AddressCache::with_lookup(long_lived(), {
        let running = Arc::clone(&running);
        let most = Arc::clone(&most);
        move |_| {
            let running = Arc::clone(&running);
            let most = Arc::clone(&most);
            Box::pin(async move {
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                most.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(20));
                running.fetch_sub(1, Ordering::SeqCst);
                Ok(vec![SocketAddr::new(V4, 0)])
            })
        }
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(POOL)
        .build()?;

    let answers = runtime.block_on(async {
        let lookups = (0..12)
            .map(|index| {
                let cache = cache.clone();
                tokio::spawn(async move {
                    cache
                        .lookup(&format!("host{index}.phantom.test"), 443)
                        .await
                })
            })
            .collect::<Vec<_>>();
        let mut answers = 0;
        for lookup in lookups {
            if lookup.await.is_ok_and(|result| result.is_ok()) {
                answers += 1;
            }
        }
        answers
    });

    assert_eq!(answers, 12);
    assert_eq!(cache.len(), 12);
    assert!(
        most.load(Ordering::SeqCst) <= POOL,
        "more resolutions ran than the pool allows"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_scoped_ipv6_address_keeps_its_scope_and_flow_label() -> TestResult {
    let link_local = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        0,
        7,
        3,
    ));
    let recorder = Recorder::open();
    let cache = recorder.cache(long_lived(), move || Ok(vec![link_local]));

    let _ = cache.lookup("router.phantom.test", 443).await?;
    let cached = cache.lookup("router.phantom.test", 8443).await?;

    let SocketAddr::V6(address) = cached.first().copied().ok_or("no address")? else {
        return Err("the address lost its family".into());
    };
    assert_eq!(address.port(), 8443);
    assert_eq!(address.scope_id(), 3);
    assert_eq!(address.flowinfo(), 7);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_ttl_beyond_the_clock_range_never_expires() -> TestResult {
    let recorder = Recorder::open();
    let cache = recorder.cache(settings(16, Duration::MAX, None), answer(&[V4]));

    let _ = cache.lookup("origin.phantom.test", 443).await?;
    let _ = cache.lookup("origin.phantom.test", 443).await?;

    assert_eq!(recorder.calls(), 1);
    assert_eq!(cache.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn the_cache_keeps_at_most_max_entries_names() -> TestResult {
    let recorder = Recorder::open();
    let cache = recorder.cache(settings(2, Duration::from_secs(600), None), answer(&[V4]));

    for host in ["a.phantom.test", "b.phantom.test", "c.phantom.test"] {
        let _ = cache.lookup(host, 443).await?;
        // Distinct expiry times make the eviction order deterministic.
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(cache.len(), 2);
    let _ = cache.lookup("c.phantom.test", 443).await?;
    let _ = cache.lookup("b.phantom.test", 443).await?;
    assert_eq!(recorder.calls(), 3, "b and c are still cached");
    let _ = cache.lookup("a.phantom.test", 443).await?;

    assert_eq!(recorder.calls(), 4, "a, which expired soonest, was evicted");
    assert_eq!(cache.len(), 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn failures_are_not_kept_without_a_negative_ttl() -> TestResult {
    let recorder = Recorder::open();
    let cache = recorder.cache(long_lived(), not_found);

    for _ in 0..2 {
        let error = cache
            .lookup("missing.phantom.test", 443)
            .await
            .err()
            .ok_or("the lookup resolved")?;
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    assert_eq!(recorder.calls(), 2);
    assert!(cache.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn failures_are_kept_for_the_negative_ttl() -> TestResult {
    let recorder = Recorder::open();
    let cache = recorder.cache(
        settings(16, Duration::from_secs(600), Some(Duration::from_secs(600))),
        not_found,
    );

    for _ in 0..2 {
        let error = cache
            .lookup("missing.phantom.test", 443)
            .await
            .err()
            .ok_or("the lookup resolved")?;
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error.to_string().contains("no such host"), "{error}");
    }

    assert_eq!(recorder.calls(), 1);
    Ok(())
}

#[derive(Debug)]
struct ResolverFailure {
    identity: Arc<()>,
    cause: NestedResolverFailure,
}

impl fmt::Display for ResolverFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("resolver refused the name")
    }
}

impl Error for ResolverFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.cause)
    }
}

#[derive(Debug)]
struct NestedResolverFailure(u32);

impl fmt::Display for NestedResolverFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "resolver detail {}", self.0)
    }
}

impl Error for NestedResolverFailure {}

fn failing_resolver(
    identity: &Arc<()>,
    calls: &Arc<AtomicUsize>,
    gate: watch::Receiver<bool>,
) -> AddressResolver {
    let identity = Arc::clone(identity);
    let calls = Arc::clone(calls);
    AddressResolver::from_fn(move |host| {
        calls.fetch_add(1, Ordering::SeqCst);
        let identity = Arc::clone(&identity);
        let mut gate = gate.clone();
        async move {
            if host == "held.phantom.test" {
                gate.wait_for(|open| *open)
                    .await
                    .map_err(io::Error::other)?;
                return Ok(vec![V4]);
            }

            gate.wait_for(|open| *open)
                .await
                .map_err(io::Error::other)?;
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                ResolverFailure {
                    identity,
                    cause: NestedResolverFailure(47),
                },
            ))
        }
    })
}

fn assert_typed_resolver_cause<'a>(
    error: &'a io::Error,
    identity: &Arc<()>,
) -> TestResult<&'a io::Error> {
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "resolver refused the name");
    let mut cause: &(dyn Error + 'static) = error;
    loop {
        if let Some(original) = cause.downcast_ref::<io::Error>()
            && let Some(resolver) = original
                .get_ref()
                .and_then(|payload| payload.downcast_ref::<ResolverFailure>())
        {
            assert!(Arc::ptr_eq(&resolver.identity, identity));
            let nested = original
                .source()
                .and_then(|source| source.downcast_ref::<NestedResolverFailure>())
                .ok_or("the resolver's nested source was lost")?;
            assert_eq!(nested.0, 47);
            return Ok(original);
        }

        cause = cause
            .source()
            .ok_or("the original resolver error was lost")?;
    }
}

async fn consume_failure(cache: &AddressCache, answer: Answer) -> TestResult<io::Error> {
    tokio::time::timeout(Duration::from_secs(5), cache.consume_answer(answer, 443))
        .await?
        .err()
        .ok_or_else(|| "the failing resolver returned addresses".into())
}

#[tokio::test(flavor = "current_thread")]
async fn an_uncached_resolver_preserves_its_typed_and_nested_cause() -> TestResult {
    let identity = Arc::new(());
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver = failing_resolver(&identity, &calls, watch::channel(true).1);

    let error = resolver
        .lookup("missing.phantom.test")
        .await
        .err()
        .ok_or("the failing resolver returned addresses")?;

    assert_typed_resolver_cause(&error, &identity)?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_first_cached_lookup_preserves_the_resolver_cause() -> TestResult {
    let identity = Arc::new(());
    let calls = Arc::new(AtomicUsize::new(0));
    let cache = AddressCache::with_resolver(
        long_lived(),
        failing_resolver(&identity, &calls, watch::channel(true).1),
    );
    let selected = cache.cached_or_pending("missing.phantom.test".into())?;
    assert!(matches!(selected, Answer::Wait(_)));

    let error = consume_failure(&cache, selected).await?;

    assert_typed_resolver_cause(&error, &identity)?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(cache.is_empty(), "no negative TTL was configured");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn joined_cached_lookups_share_the_original_resolver_cause() -> TestResult {
    let identity = Arc::new(());
    let calls = Arc::new(AtomicUsize::new(0));
    let (open, gate) = watch::channel(false);
    let cache =
        AddressCache::with_resolver(long_lived(), failing_resolver(&identity, &calls, gate));
    let first = cache.cached_or_pending("missing.phantom.test".into())?;
    let joined = cache.cached_or_pending("missing.phantom.test".into())?;
    assert!(matches!(first, Answer::Wait(_)));
    assert!(matches!(joined, Answer::Wait(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    open.send(true)?;

    let first = consume_failure(&cache, first).await?;
    let joined = consume_failure(&cache, joined).await?;

    let original = assert_typed_resolver_cause(&first, &identity)?;
    let shared = assert_typed_resolver_cause(&joined, &identity)?;
    assert!(std::ptr::eq(original, shared));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_stored_negative_answer_preserves_the_original_resolver_cause() -> TestResult {
    let identity = Arc::new(());
    let calls = Arc::new(AtomicUsize::new(0));
    let cache = AddressCache::with_resolver(
        settings(1, Duration::from_secs(600), Some(Duration::from_secs(600))),
        failing_resolver(&identity, &calls, watch::channel(true).1),
    );
    let first = cache.cached_or_pending("missing.phantom.test".into())?;
    let first = consume_failure(&cache, first).await?;
    let stored = cache.cached_or_pending("missing.phantom.test".into())?;
    assert!(matches!(stored, Answer::Stored(_)));
    assert_eq!(cache.len(), 1);

    let stored = consume_failure(&cache, stored).await?;

    let original = assert_typed_resolver_cause(&first, &identity)?;
    let retained = assert_typed_resolver_cause(&stored, &identity)?;
    assert!(std::ptr::eq(original, retained));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn an_inline_lookup_preserves_the_resolver_cause_without_new_shared_work() -> TestResult {
    let identity = Arc::new(());
    let calls = Arc::new(AtomicUsize::new(0));
    let (open, gate) = watch::channel(false);
    let cache = AddressCache::with_resolver(
        settings(1, Duration::from_secs(600), None),
        failing_resolver(&identity, &calls, gate),
    );
    let held = cache.cached_or_pending("held.phantom.test".into())?;
    assert!(matches!(held, Answer::Wait(_)));
    let inline = cache.cached_or_pending("missing.phantom.test".into())?;
    assert!(matches!(inline, Answer::Inline { .. }));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    open.send(true)?;

    let error = consume_failure(&cache, inline).await?;
    let (addresses, stored) =
        tokio::time::timeout(Duration::from_secs(5), cache.consume_answer(held, 443)).await??;

    assert_typed_resolver_cause(&error, &identity)?;
    assert_eq!(addresses, [SocketAddr::new(V4, 443)]);
    assert!(!stored);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cached_failures_retain_the_original_os_error_code() -> TestResult {
    const OS_CODE: i32 = 0x5a31;
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver = AddressResolver::from_fn({
        let calls = Arc::clone(&calls);
        move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err(io::Error::from_raw_os_error(OS_CODE)) }
        }
    });
    let cache = AddressCache::with_resolver(
        settings(1, Duration::from_secs(600), Some(Duration::from_secs(600))),
        resolver,
    );
    let expected = io::Error::from_raw_os_error(OS_CODE);

    for _ in 0..2 {
        let error = cache
            .lookup("missing.phantom.test", 443)
            .await
            .err()
            .ok_or("the failing resolver returned addresses")?;
        assert_eq!(error.kind(), expected.kind());
        assert_eq!(error.to_string(), expected.to_string());
        let mut cause: &(dyn Error + 'static) = &error;
        loop {
            if let Some(original) = cause.downcast_ref::<io::Error>()
                && original.raw_os_error() == Some(OS_CODE)
            {
                break;
            }

            cause = cause
                .source()
                .ok_or("the original OS error code was lost")?;
        }
    }

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn an_empty_answer_is_returned_and_kept_as_a_failure() -> TestResult {
    let recorder = Recorder::open();
    let uncached = recorder.cache(long_lived(), answer(&[]));
    let negative = recorder.cache(
        settings(16, Duration::from_secs(600), Some(Duration::from_secs(600))),
        answer(&[]),
    );

    for _ in 0..2 {
        assert!(uncached.lookup("empty.phantom.test", 443).await?.is_empty());
    }
    assert!(uncached.is_empty());
    assert_eq!(recorder.calls(), 2);
    for _ in 0..2 {
        assert!(negative.lookup("empty.phantom.test", 443).await?.is_empty());
    }

    assert_eq!(
        recorder.calls(),
        3,
        "the negative lifetime kept the empty answer"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_zero_ttl_resolves_every_sequential_lookup() -> TestResult {
    let recorder = Recorder::open();
    let cache = recorder.cache(settings(16, Duration::ZERO, None), answer(&[V4]));

    let _ = cache.lookup("origin.phantom.test", 443).await?;
    let _ = cache.lookup("origin.phantom.test", 443).await?;

    assert_eq!(recorder.calls(), 2);
    assert!(cache.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn ip_literals_are_used_without_a_lookup() -> TestResult {
    let recorder = Recorder::open();
    let cache = recorder.cache(long_lived(), answer(&[V4_OTHER]));

    let v4 = cache.lookup("127.0.0.1", 443).await?;
    let v6 = cache.lookup("::1", 443).await?;

    assert_eq!(v4, [SocketAddr::new(V4, 443)]);
    assert_eq!(v6, [SocketAddr::new(V6, 443)]);
    assert_eq!(recorder.calls(), 0);
    assert!(cache.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn clear_forgets_answers_and_drops_resolutions_in_flight() -> TestResult {
    let (open, gate) = watch::channel(false);
    let recorder = Recorder::gated(gate);
    let cache = recorder.cache(long_lived(), answer(&[V4]));
    let mut in_flight = Box::pin(cache.lookup_noting_cache("origin.phantom.test", 443));

    if let Poll::Ready(result) =
        poll_fn(|context| Poll::Ready(in_flight.as_mut().poll(context))).await
    {
        result?;
        return Err("the pre-clear lookup finished before its resolver was released".into());
    }
    assert_eq!(recorder.calls(), 1, "the pre-clear resolution was invoked");

    cache.clear();
    open.send(true)?;
    let (addresses, stored) = tokio::time::timeout(Duration::from_secs(5), in_flight).await??;

    assert_eq!(addresses, [SocketAddr::new(V4, 443)]);
    assert!(
        !stored,
        "the pre-clear lookup did not select a stored answer"
    );
    assert!(
        cache.is_empty(),
        "an answer started before the clear was stored"
    );

    let _ = cache.lookup("origin.phantom.test", 443).await?;
    cache.clear();
    let _ = cache.lookup("origin.phantom.test", 443).await?;

    assert_eq!(recorder.calls(), 3);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn clones_share_one_cache() -> TestResult {
    let recorder = Recorder::open();
    let cache = recorder.cache(long_lived(), answer(&[V4]));
    let clone = cache.clone();

    let _ = cache.lookup("origin.phantom.test", 443).await?;
    let _ = clone.lookup("origin.phantom.test", 443).await?;

    assert_eq!(recorder.calls(), 1);
    assert_eq!(clone.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn the_system_resolver_answers_through_the_cache() -> TestResult {
    let cache = AddressCache::new(long_lived());

    let addresses = cache.lookup("localhost", 443).await?;

    assert!(!addresses.is_empty());
    assert!(addresses.iter().all(|address| address.ip().is_loopback()));
    assert_eq!(cache.len(), 1);
    Ok(())
}

/// A caller's resolver whose first lookup never answers and whose later
/// lookups answer with the loopback address.
fn first_lookup_hangs(calls: &Arc<AtomicUsize>) -> AddressResolver {
    let calls = Arc::clone(calls);
    AddressResolver::from_fn(move |_| {
        let call = calls.fetch_add(1, Ordering::SeqCst);
        async move {
            if call == 0 {
                std::future::pending::<()>().await;
            }
            Ok(vec![V4])
        }
    })
}

#[test]
fn a_lookup_on_another_runtime_does_not_wait_on_a_stopped_one() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let cache = AddressCache::with_resolver(long_lived(), first_lookup_hangs(&calls));
    let first = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let second = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    // The first runtime starts the shared resolution, then is no longer
    // driven, so its task never runs again.
    let abandoned = first.block_on(async {
        tokio::time::timeout(
            Duration::from_millis(20),
            cache.lookup("origin.phantom.test", 443),
        )
        .await
    });
    let answered = second.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(5),
            cache.lookup("origin.phantom.test", 443),
        )
        .await
    })??;

    assert!(abandoned.is_err());
    assert_eq!(answered, [SocketAddr::new(V4, 443)]);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    drop(first);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn lookups_past_the_shared_bound_run_inline_and_are_stored() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let cache = AddressCache::with_resolver(
        settings(1, Duration::from_secs(600), None),
        first_lookup_hangs(&calls),
    );
    let hung = tokio::spawn({
        let cache = cache.clone();
        async move { cache.lookup("hung.phantom.test", 443).await }
    });
    while calls.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }

    let answered = cache.lookup("origin.phantom.test", 443).await?;

    assert_eq!(answered, [SocketAddr::new(V4, 443)]);
    assert_eq!(cache.lock().pending.len(), 1, "the bound holds");
    assert_eq!(cache.len(), 1, "the inline answer is stored");
    let _ = cache.lookup("origin.phantom.test", 443).await?;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    hung.abort();
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn clearing_and_cancelling_lookups_preserves_the_background_work_bound() -> TestResult {
    tokio::time::timeout(Duration::from_secs(5), async {
        let active = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicUsize::new(0));
        let (open, gate) = watch::channel(false);
        let resolver = gated_resolver(&active, &started, gate);
        let cache =
            AddressCache::with_resolver(settings(1, Duration::from_secs(600), None), resolver);

        let mut first = Box::pin(cache.lookup("origin.phantom.test", 443));
        assert!(!poll_lookup_once(&mut first).await);
        while active.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        drop(first);

        for expected in 2..=5 {
            cache.clear();
            let mut next = Box::pin(cache.lookup("origin.phantom.test", 443));
            assert!(!poll_lookup_once(&mut next).await);
            drop(next);
            while started.load(Ordering::SeqCst) < expected {
                tokio::task::yield_now().await;
            }

            assert_eq!(
                active.load(Ordering::SeqCst),
                1,
                "a cleared lookup must still count against background capacity"
            );
        }

        open.send(true)?;
        while active.load(Ordering::SeqCst) != 0 {
            tokio::task::yield_now().await;
        }
        assert!(cache.is_empty(), "the old generation must not publish");

        open.send(false)?;
        let mut later = Box::pin(cache.lookup("origin.phantom.test", 443));
        assert!(!poll_lookup_once(&mut later).await);
        drop(later);
        while started.load(Ordering::SeqCst) < 6 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            active.load(Ordering::SeqCst),
            1,
            "completed old work must release capacity for a new background lookup"
        );

        open.send(true)?;
        assert_eq!(
            cache.lookup("origin.phantom.test", 443).await?,
            [SocketAddr::new(V4, 443)]
        );
        assert_eq!(active.load(Ordering::SeqCst), 0);
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await?
}

#[test]
fn dropping_the_resolver_runtime_releases_background_capacity_after_clear() -> TestResult {
    let active = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(AtomicUsize::new(0));
    let (open, gate) = watch::channel(false);
    let cache = AddressCache::with_resolver(
        settings(1, Duration::from_secs(600), None),
        gated_resolver(&active, &started, gate),
    );
    let first = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    first.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut lookup = Box::pin(cache.lookup("origin.phantom.test", 443));
            assert!(!poll_lookup_once(&mut lookup).await);
            while active.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
    })?;
    cache.clear();
    drop(first);
    assert_eq!(active.load(Ordering::SeqCst), 0);

    let second = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    second.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut lookup = Box::pin(cache.lookup("origin.phantom.test", 443));
            assert!(!poll_lookup_once(&mut lookup).await);
            drop(lookup);
            while started.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
            assert_eq!(
                active.load(Ordering::SeqCst),
                1,
                "a dropped runtime must free the old background reservation"
            );

            open.send(true)?;
            assert_eq!(
                cache.lookup("origin.phantom.test", 443).await?,
                [SocketAddr::new(V4, 443)]
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await?
    })
}

/// Counts live resolver futures independently of the cache's bookkeeping.
struct LiveLookup(Arc<AtomicUsize>);

impl Drop for LiveLookup {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn gated_resolver(
    active: &Arc<AtomicUsize>,
    started: &Arc<AtomicUsize>,
    gate: watch::Receiver<bool>,
) -> AddressResolver {
    let active = Arc::clone(active);
    let started = Arc::clone(started);
    AddressResolver::from_fn(move |_| {
        let active = Arc::clone(&active);
        let started = Arc::clone(&started);
        let mut gate = gate.clone();
        async move {
            active.fetch_add(1, Ordering::SeqCst);
            let _live = LiveLookup(active);
            started.fetch_add(1, Ordering::SeqCst);
            gate.wait_for(|open| *open)
                .await
                .map_err(io::Error::other)?;
            Ok(vec![V4])
        }
    })
}

async fn poll_lookup_once<F: Future>(lookup: &mut Pin<Box<F>>) -> bool {
    poll_fn(|context| Poll::Ready(lookup.as_mut().poll(context).is_ready())).await
}
