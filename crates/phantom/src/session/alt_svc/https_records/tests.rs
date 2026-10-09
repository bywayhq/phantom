use std::{
    num::NonZeroUsize,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use http::uri::Authority;
use phantom_net::dns::{HttpsRecord, HttpsRecordAnswer, HttpsRecordLookup, HttpsRecordResolver};
use phantom_testkit::dns::{DnsAnswer, DnsQuery, DnsReply, DnsServer};

use super::{Discovery, HttpsRecordDiscovery, advertises_h3, summarize};
use crate::authority::Endpoint;

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

const HOST: &str = "origin.test";
const OWNER: &str = "_8443._https.origin.test";

fn rdata(priority: u16, target: &[&str], params: &[(u16, &[u8])]) -> Vec<u8> {
    let mut bytes = priority.to_be_bytes().to_vec();
    for label in target {
        bytes.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    for (key, value) in params {
        bytes.extend_from_slice(&key.to_be_bytes());
        bytes.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
        bytes.extend_from_slice(value);
    }
    bytes
}

#[derive(Default)]
struct LookupCounts {
    started: AtomicUsize,
    active: AtomicUsize,
    hosts: Mutex<Vec<String>>,
    changed: tokio::sync::Notify,
}

impl LookupCounts {
    fn enter(self: &Arc<Self>, host: String) -> ActiveLookup {
        self.hosts.lock().expect("fixture hosts lock").push(host);
        self.active.fetch_add(1, Ordering::SeqCst);
        self.started.fetch_add(1, Ordering::SeqCst);
        self.changed.notify_one();
        ActiveLookup(Arc::clone(self))
    }

    async fn wait_started(&self, expected: usize) -> TestResult<()> {
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.started.load(Ordering::SeqCst) < expected {
                self.changed.notified().await;
            }
        })
        .await
        .map_err(|_| "controlled lookup did not start".into())
    }

    async fn wait_inactive(&self) -> TestResult<()> {
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.active.load(Ordering::SeqCst) != 0 {
                self.changed.notified().await;
            }
        })
        .await
        .map_err(|_| "controlled lookup remained active".into())
    }
}

struct ActiveLookup(Arc<LookupCounts>);

impl Drop for ActiveLookup {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0.changed.notify_one();
    }
}

fn controlled_discovery() -> TestResult<(
    HttpsRecordDiscovery,
    Arc<LookupCounts>,
    tokio::sync::watch::Sender<bool>,
)> {
    let counts = Arc::new(LookupCounts::default());
    let advertised = record(&rdata(1, &[], &[H3]))?;
    let (release, released) = tokio::sync::watch::channel(false);
    let resolver = {
        let counts = Arc::clone(&counts);
        HttpsRecordResolver::from_fn(move |host, _| {
            let counts = Arc::clone(&counts);
            let advertised = advertised.clone();
            let mut released = released.clone();
            async move {
                let _active = counts.enter(host.clone());
                while !*released.borrow() {
                    if released.changed().await.is_err() {
                        break;
                    }
                }
                Ok(HttpsRecordLookup::new(
                    vec![HttpsRecordAnswer::new(host, 300, advertised)],
                    None,
                ))
            }
        })
    };
    let discovery = HttpsRecordDiscovery::new(resolver, NonZeroUsize::MIN);
    Ok((discovery, counts, release))
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_waiters_and_origin_churn_keep_lookup_work_bounded() -> TestResult<()> {
    let (discovery, counts, release) = controlled_discovery()?;
    let first = endpoint("first.test")?;
    let second = endpoint("second.test")?;

    let Discovery::Pending(lookup) = discovery.discover(&first) else {
        return Err("first lookup was not started".into());
    };
    drop(lookup);
    counts.wait_started(1).await?;

    assert!(matches!(
        discovery.discover(&second),
        Discovery::NotAdvertised
    ));
    let Discovery::Pending(joined) = discovery.discover(&first) else {
        return Err("same-origin lookup was not shared".into());
    };
    drop(joined);
    tokio::task::yield_now().await;
    assert_eq!(counts.started.load(Ordering::SeqCst), 1);
    assert_eq!(counts.active.load(Ordering::SeqCst), 1);
    assert_eq!(
        *counts.hosts.lock().expect("fixture hosts lock"),
        ["first.test"]
    );

    release.send_replace(true);
    assert!(settle(&discovery, &first).await?);
    counts.wait_inactive().await?;
    assert!(matches!(discovery.discover(&first), Discovery::Advertised));

    assert!(settle(&discovery, &second).await?);
    counts.wait_started(2).await?;
    counts.wait_inactive().await?;
    assert!(matches!(discovery.discover(&second), Discovery::Advertised));
    assert!(settle(&discovery, &first).await?);
    assert_eq!(counts.started.load(Ordering::SeqCst), 3);
    assert_eq!(counts.active.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn runtime_shutdown_releases_lookup_work_after_waiter_cancellation() -> TestResult<()> {
    let (discovery, counts, _release) = controlled_discovery()?;
    let origin = endpoint("origin.test")?;

    for (drive_lookup, expected) in [(false, 0), (true, 1), (true, 2)] {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let Discovery::Pending(lookup) = discovery.discover(&origin) else {
                return Err("lookup was not started on its runtime".into());
            };
            drop(lookup);
            if drive_lookup {
                counts.wait_started(expected).await?;
                assert_eq!(counts.active.load(Ordering::SeqCst), 1);
            } else {
                assert_eq!(counts.started.load(Ordering::SeqCst), 0);
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;

        drop(runtime);
        assert_eq!(counts.active.load(Ordering::SeqCst), 0);
        assert!(discovery.cache.lock_state().pending.is_empty());
    }
    Ok(())
}

#[test]
fn completed_cache_churn_does_not_duplicate_a_pending_origin() -> TestResult<()> {
    let counts = Arc::new(LookupCounts::default());
    let advertised = record(&rdata(1, &[], &[H3]))?;
    let (release, released) = tokio::sync::watch::channel(false);
    let resolver = {
        let counts = Arc::clone(&counts);
        HttpsRecordResolver::from_fn(move |host, _| {
            let counts = Arc::clone(&counts);
            let advertised = advertised.clone();
            let mut released = released.clone();
            async move {
                let _active = counts.enter(host.clone());
                if host == "first.test" {
                    while !*released.borrow() {
                        if released.changed().await.is_err() {
                            break;
                        }
                    }
                }
                Ok(HttpsRecordLookup::new(
                    vec![HttpsRecordAnswer::new(host, 300, advertised)],
                    None,
                ))
            }
        })
    };
    let discovery = HttpsRecordDiscovery::new(resolver, NonZeroUsize::MIN);
    let first = endpoint("first.test")?;
    let second = endpoint("second.test")?;
    let first_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let second_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    first_runtime.block_on(async {
        let Discovery::Pending(lookup) = discovery.discover(&first) else {
            return Err("first lookup was not started".into());
        };
        drop(lookup);
        counts.wait_started(1).await
    })?;
    assert!(second_runtime.block_on(settle(&discovery, &second))?);
    assert_eq!(counts.started.load(Ordering::SeqCst), 2);
    assert_eq!(counts.active.load(Ordering::SeqCst), 1);

    first_runtime.block_on(async {
        let Discovery::Pending(joined) = discovery.discover(&first) else {
            return Err("cache churn lost the pending lookup".into());
        };
        drop(joined);
        tokio::task::yield_now().await;
        assert_eq!(counts.started.load(Ordering::SeqCst), 2);
        assert_eq!(counts.active.load(Ordering::SeqCst), 1);
        assert_eq!(discovery.cache.lock_state().ready.len(), 1);
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;

    release.send_replace(true);
    assert!(first_runtime.block_on(settle(&discovery, &first))?);
    assert_eq!(counts.active.load(Ordering::SeqCst), 0);
    assert!(second_runtime.block_on(settle(&discovery, &second))?);
    assert_eq!(counts.started.load(Ordering::SeqCst), 3);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_panic_releases_its_lookup_reservation() -> TestResult<()> {
    let counts = Arc::new(LookupCounts::default());
    let advertised = record(&rdata(1, &[], &[H3]))?;
    let resolver = {
        let counts = Arc::clone(&counts);
        HttpsRecordResolver::from_fn(move |host, _| {
            let counts = Arc::clone(&counts);
            let advertised = advertised.clone();
            async move {
                let _active = counts.enter(host.clone());
                if host == "panic.test" {
                    panic!("controlled resolver panic");
                }
                Ok(HttpsRecordLookup::new(
                    vec![HttpsRecordAnswer::new(host, 300, advertised)],
                    None,
                ))
            }
        })
    };
    let discovery = HttpsRecordDiscovery::new(resolver, NonZeroUsize::MIN);
    let panicking = endpoint("panic.test")?;
    let valid = endpoint("valid.test")?;

    assert!(!settle(&discovery, &panicking).await?);
    assert_eq!(counts.started.load(Ordering::SeqCst), 1);
    assert_eq!(counts.active.load(Ordering::SeqCst), 0);
    assert!(discovery.cache.lock_state().pending.is_empty());

    assert!(settle(&discovery, &valid).await?);
    assert_eq!(counts.started.load(Ordering::SeqCst), 2);
    assert_eq!(counts.active.load(Ordering::SeqCst), 0);
    Ok(())
}

fn record(bytes: &[u8]) -> TestResult<HttpsRecord> {
    Ok(HttpsRecord::from_rdata(bytes)?)
}

fn advertises(records: &[Vec<u8>]) -> TestResult<bool> {
    let parsed = records
        .iter()
        .map(|bytes| record(bytes))
        .collect::<TestResult<Vec<_>>>()?;
    let answers = parsed
        .iter()
        .map(|record| (OWNER, record))
        .collect::<Vec<_>>();
    Ok(advertises_h3(&answers, HOST, 8443))
}

const H3: (u16, &[u8]) = (1, b"\x02h3");

#[test]
fn service_record_listing_h3_for_the_origin_advertises_it() -> TestResult<()> {
    assert!(advertises(&[rdata(1, &[], &[H3])])?);
    assert!(advertises(&[rdata(1, &["Origin", "Test"], &[H3])])?);
    assert!(advertises(&[rdata(
        1,
        &["_8443", "_https", "origin", "test"],
        &[H3]
    )])?);
    assert!(advertises(&[rdata(
        1,
        &[],
        &[H3, (3, &8443_u16.to_be_bytes())]
    )])?);
    // Any kept record may carry h3, whatever its priority.
    assert!(advertises(&[
        rdata(1, &[], &[(1, b"\x02h2")]),
        rdata(2, &[], &[H3]),
    ])?);
    Ok(())
}

#[test]
fn records_chromium_ignores_do_not_advertise_h3() -> TestResult<()> {
    let cases = [
        ("no h3", vec![rdata(1, &[], &[(1, b"\x02h2")])]),
        ("no records", vec![]),
        (
            "an alias record hides every record",
            vec![rdata(0, &["cdn", "test"], &[]), rdata(1, &[], &[H3])],
        ),
        ("another target", vec![rdata(1, &["cdn", "test"], &[H3])]),
        (
            "another port",
            vec![rdata(1, &[], &[H3, (3, &443_u16.to_be_bytes())])],
        ),
        (
            "an unsupported mandatory key",
            vec![rdata(1, &[], &[(0, &[0, 7]), H3, (7, b"x")])],
        ),
        (
            "every record sets no-default-alpn",
            vec![rdata(1, &[], &[H3, (2, b"")])],
        ),
    ];
    for (name, records) in cases {
        assert!(!advertises(&records)?, "{name}");
    }
    // One record without no-default-alpn keeps the others.
    assert!(advertises(&[
        rdata(1, &[], &[H3, (2, b"")]),
        rdata(2, &[], &[(1, b"\x02h2")]),
    ])?);
    // A supported mandatory key keeps the record.
    assert!(advertises(&[rdata(1, &[], &[(0, &[0, 1]), H3])])?);
    Ok(())
}

fn endpoint(authority: &'static str) -> TestResult<Endpoint> {
    Ok(Endpoint::new(Authority::from_static(authority), 443).map_err(|error| error.message())?)
}

async fn server(ttl: u32, delay: Duration) -> TestResult<DnsServer> {
    Ok(DnsServer::spawn(move |_: &DnsQuery| {
        DnsReply::new(DnsAnswer::Records {
            ttl,
            rdata: vec![rdata(1, &[], &[H3])],
        })
        .delayed(delay)
    })
    .await?)
}

fn discovery(server: &DnsServer, capacity: usize) -> TestResult<HttpsRecordDiscovery> {
    Ok(HttpsRecordDiscovery::new(
        HttpsRecordResolver::with_nameservers([server.address()])?,
        NonZeroUsize::new(capacity).ok_or("zero capacity")?,
    ))
}

async fn settle(discovery: &HttpsRecordDiscovery, origin: &Endpoint) -> TestResult<bool> {
    match discovery.discover(origin) {
        Discovery::Pending(lookup) => Ok(lookup.advertises_h3().await),
        Discovery::Advertised => Ok(true),
        Discovery::NotAdvertised => Ok(false),
    }
}

#[tokio::test]
async fn concurrent_requests_share_one_lookup_and_reuse_its_result() -> TestResult<()> {
    let server = server(300, Duration::from_millis(100)).await?;
    let discovery = discovery(&server, 4)?;
    let origin = endpoint("origin.test:8443")?;

    let first = discovery.discover(&origin);
    let second = discovery.discover(&origin);
    let (Discovery::Pending(first), Discovery::Pending(second)) = (first, second) else {
        return Err("an uncached origin did not start a lookup".into());
    };
    assert!(first.advertises_h3().await);
    assert!(second.advertises_h3().await);
    assert!(matches!(discovery.discover(&origin), Discovery::Advertised));
    assert_eq!(server.queries().len(), 1);
    assert_eq!(server.queries()[0].name(), OWNER);
    Ok(())
}

#[tokio::test]
async fn expired_results_are_looked_up_again() -> TestResult<()> {
    let server = server(0, Duration::ZERO).await?;
    let discovery = discovery(&server, 4)?;
    let origin = endpoint("origin.test:8443")?;
    assert!(settle(&discovery, &origin).await?);
    assert!(matches!(discovery.discover(&origin), Discovery::Pending(_)));
    Ok(())
}

#[tokio::test]
async fn cache_holds_at_most_its_capacity() -> TestResult<()> {
    let server = server(300, Duration::ZERO).await?;
    let discovery = discovery(&server, 1)?;
    let first = endpoint("origin.test:8443")?;
    let second = endpoint("other.test")?;
    assert!(settle(&discovery, &first).await?);
    assert!(settle(&discovery, &second).await?);
    assert_eq!(discovery.cache.lock_state().ready.len(), 1);
    // The first origin was evicted, so it is queried again.
    let Discovery::Pending(lookup) = discovery.discover(&first) else {
        return Err("an evicted origin was still cached".into());
    };
    assert!(lookup.advertises_h3().await);
    assert_eq!(server.queries().len(), 3);
    Ok(())
}

#[tokio::test]
async fn failed_lookup_is_remembered_as_no_advertisement() -> TestResult<()> {
    let server = DnsServer::spawn(|_| DnsReply::new(DnsAnswer::ServerFailure)).await?;
    let discovery = discovery(&server, 4)?;
    let origin = endpoint("origin.test:8443")?;
    assert!(!settle(&discovery, &origin).await?);
    let queries = server.queries().len();
    assert!(matches!(
        discovery.discover(&origin),
        Discovery::NotAdvertised
    ));
    assert_eq!(server.queries().len(), queries);
    Ok(())
}

/// A lookup pending on another runtime is not waited on: one whose task
/// ended without a result because its runtime shut down, or one on a
/// runtime that is alive but no longer driven. The next request starts a
/// lookup of its own on its runtime.
#[test]
fn lookup_pending_on_another_runtime_is_started_again() -> TestResult<()> {
    for keep_first_runtime in [false, true] {
        let advertised = record(&rdata(1, &[], &[H3]))?;
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = {
            let calls = Arc::clone(&calls);
            HttpsRecordResolver::from_fn(move |_, _| {
                let first = calls.fetch_add(1, Ordering::SeqCst) == 0;
                let advertised = advertised.clone();
                async move {
                    if first {
                        std::future::pending::<()>().await;
                    }
                    Ok(HttpsRecordLookup::new(
                        vec![HttpsRecordAnswer::new(OWNER, 300, advertised)],
                        None,
                    ))
                }
            })
        };
        let discovery = HttpsRecordDiscovery::new(resolver, NonZeroUsize::MIN);
        let origin = endpoint("origin.test:8443")?;

        let first = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        first.block_on(async {
            assert!(matches!(discovery.discover(&origin), Discovery::Pending(_)));
            tokio::task::yield_now().await;
        });
        let kept = keep_first_runtime.then_some(first);
        let second = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let advertises = second.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), settle(&discovery, &origin))
                .await
                .map_err(|_| "the lookup waited on another runtime")?
        })?;
        assert!(advertises);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        drop(kept);
    }
    Ok(())
}

/// Two driven runtimes that alternate requests while a lookup is in flight
/// each start at most one lookup, and the result is cached for both.
#[test]
fn alternating_runtimes_each_start_at_most_one_lookup() -> TestResult<()> {
    let advertised = record(&rdata(1, &[], &[H3]))?;
    let calls = Arc::new(AtomicUsize::new(0));
    let (release, released) = tokio::sync::watch::channel(false);
    let resolver = {
        let calls = Arc::clone(&calls);
        HttpsRecordResolver::from_fn(move |_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            let advertised = advertised.clone();
            let mut released = released.clone();
            async move {
                let _ = released.wait_for(|released| *released).await;
                Ok(HttpsRecordLookup::new(
                    vec![HttpsRecordAnswer::new(OWNER, 300, advertised)],
                    None,
                ))
            }
        })
    };
    let discovery = HttpsRecordDiscovery::new(resolver, NonZeroUsize::new(4).ok_or("zero")?);
    let origin = endpoint("origin.test:8443")?;
    let runtimes = [
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()?,
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()?,
    ];

    let mut lookups = Vec::new();
    for _ in 0..2 {
        for runtime in &runtimes {
            let Discovery::Pending(lookup) =
                runtime.block_on(async { discovery.discover(&origin) })
            else {
                return Err("an origin with a lookup in flight was not pending".into());
            };
            lookups.push(lookup);
        }
    }
    let _ = release.send(true);
    for (lookup, runtime) in lookups.into_iter().zip(runtimes.iter().cycle()) {
        assert!(runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), lookup.advertises_h3()).await
        })?);
    }

    for runtime in &runtimes {
        assert!(matches!(
            runtime.block_on(async { discovery.discover(&origin) }),
            Discovery::Advertised
        ));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(discovery.cache.lock_state().ready.len(), 1);
    Ok(())
}

#[tokio::test]
async fn ip_literal_origins_are_never_queried() -> TestResult<()> {
    let server = server(300, Duration::ZERO).await?;
    let discovery = discovery(&server, 4)?;
    for authority in ["127.0.0.1:8443", "[::1]:8443"] {
        assert!(matches!(
            discovery.discover(&endpoint(authority)?),
            Discovery::NotAdvertised
        ));
    }
    tokio::task::yield_now().await;
    assert!(server.queries().is_empty());
    Ok(())
}

fn tcp_ech(records: &[Vec<u8>]) -> TestResult<Option<Vec<u8>>> {
    let parsed = records
        .iter()
        .map(|bytes| record(bytes))
        .collect::<TestResult<Vec<_>>>()?;
    let answers = parsed
        .iter()
        .map(|record| (OWNER, record))
        .collect::<Vec<_>>();
    let alpn = [Box::from(&b"h2"[..]), Box::from(&b"http/1.1"[..])];
    Ok(summarize(&answers, HOST, 8443)
        .tcp_ech(&alpn)
        .map(|list| list.as_bytes().to_vec()))
}

const ECH_A: (u16, &[u8]) = (5, b"\x00\x01\xaa");
const ECH_B: (u16, &[u8]) = (5, b"\x00\x01\xbb");
const H2: (u16, &[u8]) = (1, b"\x02h2");
const NO_DEFAULT_ALPN: (u16, &[u8]) = (2, b"");

#[test]
fn tcp_uses_the_ech_of_the_first_record_by_priority() -> TestResult<()> {
    let records = [rdata(2, &[], &[H2, ECH_B]), rdata(1, &[], &[H2, ECH_A])];
    assert_eq!(tcp_ech(&records)?.as_deref(), Some(&b"\x00\x01\xaa"[..]));
    Ok(())
}

#[test]
fn a_first_record_without_ech_means_no_ech() -> TestResult<()> {
    let records = [rdata(1, &[], &[H2]), rdata(2, &[], &[H2, ECH_A])];
    assert_eq!(tcp_ech(&records)?, None);
    Ok(())
}

#[test]
fn records_tcp_cannot_use_are_skipped() -> TestResult<()> {
    // HTTP/3 only: no `h2`, and `no-default-alpn` drops `http/1.1`.
    let quic_only = rdata(1, &[], &[H3, NO_DEFAULT_ALPN, ECH_B]);
    let records = [quic_only, rdata(2, &[], &[H2, ECH_A])];
    assert_eq!(tcp_ech(&records)?.as_deref(), Some(&b"\x00\x01\xaa"[..]));
    Ok(())
}

#[test]
fn records_chromium_ignores_carry_no_ech() -> TestResult<()> {
    let alias = rdata(0, &["elsewhere", "test"], &[]);
    assert_eq!(tcp_ech(&[alias, rdata(1, &[], &[H2, ECH_A])])?, None);
    let other_port = rdata(1, &[], &[H2, (3, b"\x00\x01"), ECH_A]);
    assert_eq!(tcp_ech(&[other_port])?, None);
    let other_target = rdata(1, &["cdn", "test"], &[H2, ECH_A]);
    assert_eq!(tcp_ech(&[other_target])?, None);
    Ok(())
}
