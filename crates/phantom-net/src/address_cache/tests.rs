use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    num::NonZeroUsize,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use phantom_profile::DnsCacheSettings;
use tokio::sync::watch;

use super::AddressCache;
use crate::host_resolver::AddressResolver;

mod routes;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const V6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
const V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const V4_OTHER: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));

fn settings(max_entries: usize, ttl: Duration, negative_ttl: Option<Duration>) -> DnsCacheSettings {
    DnsCacheSettings {
        max_entries: NonZeroUsize::new(max_entries).unwrap_or(NonZeroUsize::MIN),
        ttl,
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

#[tokio::test(flavor = "current_thread")]
async fn concurrent_lookups_share_one_resolution() -> TestResult {
    let (open, gate) = watch::channel(false);
    let recorder = Recorder::gated(gate);
    let cache = recorder.cache(long_lived(), answer(&[V6, V4]));

    let lookups = (0..8)
        .map(|_| {
            let cache = cache.clone();
            tokio::spawn(async move { cache.lookup("origin.phantom.test", 443).await })
        })
        .collect::<Vec<_>>();
    tokio::task::yield_now().await;
    open.send(true)?;
    for lookup in lookups {
        assert_eq!(
            lookup.await??,
            [SocketAddr::new(V6, 443), SocketAddr::new(V4, 443)]
        );
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

    // The first runtime starts the shared resolution, then is never driven
    // again while it stays alive.
    let first = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let abandoned = first.block_on(async {
        tokio::time::timeout(
            Duration::from_millis(20),
            cache.lookup("origin.phantom.test", 443),
        )
        .await
    });
    assert!(abandoned.is_err(), "the gated lookup finished early");
    let second = std::thread::spawn({
        let cache = cache.clone();
        move || -> Result<Vec<SocketAddr>, String> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .map_err(|error| error.to_string())?;
            runtime
                .block_on(cache.lookup("origin.phantom.test", 443))
                .map_err(|error| error.to_string())
        }
    });
    std::thread::sleep(Duration::from_millis(20));
    open.send(true)?;
    let addresses = second.join().map_err(|_| "the second lookup panicked")??;

    assert_eq!(addresses, [SocketAddr::new(V4, 443)]);
    assert_eq!(
        recorder.calls(),
        1,
        "the second runtime joined the first resolution"
    );
    drop(first);
    Ok(())
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

    let in_flight = tokio::spawn({
        let cache = cache.clone();
        async move { cache.lookup("origin.phantom.test", 443).await }
    });
    tokio::task::yield_now().await;
    cache.clear();
    open.send(true)?;
    assert_eq!(in_flight.await??, [SocketAddr::new(V4, 443)]);
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
