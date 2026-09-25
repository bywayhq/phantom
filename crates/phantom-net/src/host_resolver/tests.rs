use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroUsize,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use phantom_profile::DnsCacheSettings;

use super::{AddressResolver, HostResolver, resolve};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const RESOLVED: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3));
const OVERRIDE_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
const OVERRIDE_V6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

fn settings(ttl: Duration) -> DnsCacheSettings {
    DnsCacheSettings {
        max_entries: NonZeroUsize::new(16).unwrap_or(NonZeroUsize::MIN),
        ttl,
        negative_ttl: None,
    }
}

/// An [`AddressResolver`] that records the names it is asked for and
/// answers each after a timer, which only a runtime task can wait on.
#[derive(Clone, Default)]
struct Counting {
    calls: Arc<AtomicUsize>,
    names: Arc<Mutex<Vec<String>>>,
}

impl Counting {
    fn resolver(&self, answer: fn() -> io::Result<Vec<IpAddr>>) -> AddressResolver {
        let counting = self.clone();
        AddressResolver::from_fn(move |host| {
            counting.calls.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut names) = counting.names.lock() {
                names.push(host);
            }
            async move {
                tokio::time::sleep(Duration::from_millis(5)).await;
                answer()
            }
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn names(&self) -> Vec<String> {
        self.names
            .lock()
            .map(|names| names.clone())
            .unwrap_or_default()
    }
}

fn resolved() -> io::Result<Vec<IpAddr>> {
    Ok(vec![RESOLVED])
}

fn not_found() -> io::Result<Vec<IpAddr>> {
    Err(io::Error::new(io::ErrorKind::NotFound, "no such test host"))
}

#[tokio::test(flavor = "current_thread")]
async fn an_override_answers_in_order_without_the_resolver_or_cache() -> TestResult {
    let counting = Counting::default();
    let resolver = HostResolver::new()
        .with_resolver(counting.resolver(resolved))
        .with_cache(settings(Duration::from_secs(600)))
        .with_override("Origin.Phantom.Test", [OVERRIDE_V6, OVERRIDE_V4]);

    let addresses = resolve(Some(&resolver), "ORIGIN.phantom.test", 8443).await?;

    assert_eq!(
        addresses,
        [
            SocketAddr::new(OVERRIDE_V6, 8443),
            SocketAddr::new(OVERRIDE_V4, 8443)
        ]
    );
    assert_eq!(counting.calls(), 0);
    assert_eq!(resolver.cache().map(super::AddressCache::len), Some(0));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn later_overrides_replace_earlier_ones_and_an_empty_one_resolves_nothing() -> TestResult {
    let resolver = HostResolver::new()
        .with_override("origin.phantom.test", [OVERRIDE_V4])
        .with_override("origin.phantom.test", [OVERRIDE_V6])
        .with_override("blocked.phantom.test", []);

    let replaced = resolve(Some(&resolver), "origin.phantom.test", 443).await?;
    let blocked = resolve(Some(&resolver), "blocked.phantom.test", 443).await?;

    assert_eq!(replaced, [SocketAddr::new(OVERRIDE_V6, 443)]);
    assert!(blocked.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn ip_literals_are_used_as_written() -> TestResult {
    let resolver = HostResolver::new().with_override("127.0.0.1", [OVERRIDE_V4]);

    let without = resolve(None, "127.0.0.1", 443).await?;
    let with = resolve(Some(&resolver), "127.0.0.1", 443).await?;

    let expected = [SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443)];
    assert_eq!(without, expected);
    assert_eq!(with, expected);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_resolver_without_a_cache_is_asked_for_every_lookup() -> TestResult {
    let counting = Counting::default();
    let resolver = HostResolver::new().with_resolver(counting.resolver(resolved));

    let first = resolve(Some(&resolver), "Origin.Phantom.Test", 443).await?;
    let second = resolve(Some(&resolver), "origin.phantom.test", 80).await?;

    assert_eq!(first, [SocketAddr::new(RESOLVED, 443)]);
    assert_eq!(second, [SocketAddr::new(RESOLVED, 80)]);
    assert_eq!(
        counting.names(),
        ["origin.phantom.test", "origin.phantom.test"]
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_cached_resolver_is_asked_once_per_lifetime() -> TestResult {
    let counting = Counting::default();
    let resolver = HostResolver::new()
        .with_resolver(counting.resolver(resolved))
        .with_cache(settings(Duration::from_millis(200)));

    let (first, second) = tokio::join!(
        resolve(Some(&resolver), "origin.phantom.test", 443),
        resolve(Some(&resolver), "origin.phantom.test", 443),
    );
    let third = resolve(Some(&resolver), "origin.phantom.test", 8443).await?;
    assert_eq!(counting.calls(), 1);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = resolve(Some(&resolver), "origin.phantom.test", 443).await?;

    assert_eq!(first?, [SocketAddr::new(RESOLVED, 443)]);
    assert_eq!(second?, [SocketAddr::new(RESOLVED, 443)]);
    assert_eq!(third, [SocketAddr::new(RESOLVED, 8443)]);
    assert_eq!(counting.calls(), 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_errors_keep_their_kind_with_or_without_a_cache() -> TestResult {
    let counting = Counting::default();
    let uncached = HostResolver::new().with_resolver(counting.resolver(not_found));
    let cached = uncached
        .clone()
        .with_cache(settings(Duration::from_secs(600)));

    for resolver in [uncached, cached] {
        let Err(error) = resolve(Some(&resolver), "missing.phantom.test", 443).await else {
            return Err("a failed resolver answered".into());
        };
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error.to_string().contains("no such test host"));
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_resolver_set_after_the_cache_answers_through_it() -> TestResult {
    let counting = Counting::default();
    let resolver = HostResolver::new()
        .with_cache(settings(Duration::from_secs(600)))
        .with_resolver(counting.resolver(resolved));

    let addresses = resolve(Some(&resolver), "origin.phantom.test", 443).await?;

    assert_eq!(addresses, [SocketAddr::new(RESOLVED, 443)]);
    assert_eq!(counting.calls(), 1);
    assert_eq!(resolver.cache().map(super::AddressCache::len), Some(1));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn an_emptied_copy_keeps_the_overrides_and_resolver_but_not_the_answers() -> TestResult {
    let counting = Counting::default();
    let resolver = HostResolver::new()
        .with_resolver(counting.resolver(resolved))
        .with_cache(settings(Duration::from_secs(600)))
        .with_override("pinned.phantom.test", [OVERRIDE_V4]);
    let _ = resolve(Some(&resolver), "origin.phantom.test", 443).await?;

    let emptied = resolver.with_empty_cache();
    let pinned = resolve(Some(&emptied), "pinned.phantom.test", 443).await?;
    let _ = resolve(Some(&emptied), "origin.phantom.test", 443).await?;

    assert_eq!(pinned, [SocketAddr::new(OVERRIDE_V4, 443)]);
    assert_eq!(counting.calls(), 2);
    assert_eq!(resolver.cache().map(super::AddressCache::len), Some(1));
    assert_eq!(emptied.cache().map(super::AddressCache::len), Some(1));
    Ok(())
}
