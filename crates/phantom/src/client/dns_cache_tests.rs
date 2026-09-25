//! The client's address cache, driven through requests to a loopback origin.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use phantom_net::{address_cache::AddressCache, host_resolver::HostResolver};
use phantom_profile::{ClientProfile, DnsCacheSettings, Http3ClientSettings, chromium, firefox};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::watch,
    task::JoinHandle,
};

use super::{Client, ClientInner, HttpProtocol};
use crate::{HttpProxy, Route};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const ORIGIN: &str = "origin.phantom.test";

/// A plaintext HTTP/1.1 origin that answers each request on a fresh
/// connection and closes it, so every request needs a new connection.
struct ClosingOrigin {
    port: u16,
    task: JoinHandle<()>,
}

impl ClosingOrigin {
    async fn bind() -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut buffer = [0; 1024];
                    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                        match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => head.extend_from_slice(&buffer[..read]),
                        }
                    }
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                });
            }
        });
        Ok(Self { port, task })
    }

    fn url(&self) -> String {
        format!("http://{ORIGIN}:{}/", self.port)
    }
}

impl Drop for ClosingOrigin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn settings() -> DnsCacheSettings {
    DnsCacheSettings {
        max_entries: NonZeroUsize::new(16).unwrap_or(NonZeroUsize::MIN),
        ttl: Duration::from_secs(600),
        negative_ttl: None,
    }
}

fn profile() -> ClientProfile {
    ClientProfile::new(chromium::v154_tls()).with_http1(chromium::v154_http1())
}

/// Replaces the client's address cache with one that answers every name
/// with the loopback address once `gate` opens, counting its lookups.
fn with_counting_cache(client: &Client, gate: watch::Receiver<bool>) -> (Client, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let cache = AddressCache::with_lookup(settings(), {
        let calls = Arc::clone(&calls);
        move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            let mut gate = gate.clone();
            Box::pin(async move {
                let _ = gate.wait_for(|open| *open).await;
                Ok(vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)])
            })
        }
    });
    let mut inner = ClientInner::clone(&client.inner);
    inner.bind_host_resolver(HostResolver::new().with_address_cache(cache));
    let client = Client {
        inner: Arc::new(inner),
        state: Arc::clone(&client.state),
    };
    (client, calls)
}

async fn get(client: &Client, url: &str) -> TestResult {
    let response = client.get(HttpProtocol::Http1, url)?.send().await?;
    let body = response.into_body().collect_with_limit(16).await?;
    assert_eq!(&body[..], b"ok");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn repeated_requests_to_one_host_resolve_it_once() -> TestResult {
    let origin = ClosingOrigin::bind().await?;
    let client = Client::builder(profile()).dns_cache(settings()).build()?;
    let (client, calls) = with_counting_cache(&client, watch::channel(true).1);

    for _ in 0..3 {
        get(&client, &origin.url()).await?;
    }

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_requests_to_one_host_share_one_lookup() -> TestResult {
    let origin = ClosingOrigin::bind().await?;
    let client = Client::builder(profile()).dns_cache(settings()).build()?;
    let (open, gate) = watch::channel(false);
    let (client, calls) = with_counting_cache(&client, gate);

    let requests = (0..4)
        .map(|_| {
            let client = client.clone();
            let url = origin.url();
            tokio::spawn(async move { get(&client, &url).await.map_err(|error| error.to_string()) })
        })
        .collect::<Vec<_>>();
    tokio::time::sleep(Duration::from_millis(20)).await;
    open.send(true)?;
    for request in requests {
        request.await??;
    }

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn clones_share_the_cache_and_sessions_start_empty() -> TestResult {
    let origin = ClosingOrigin::bind().await?;
    let client = Client::builder(profile()).dns_cache(settings()).build()?;
    let (client, calls) = with_counting_cache(&client, watch::channel(true).1);

    get(&client, &origin.url()).await?;
    get(&client.clone(), &origin.url()).await?;
    let session = client.session();

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let session_cache = session
        .inner
        .host_resolver
        .as_ref()
        .and_then(HostResolver::cache)
        .ok_or("the session has no address cache")?;
    assert!(session_cache.is_empty());
    assert_eq!(session_cache.settings(), &settings());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn clear_dns_cache_resolves_the_host_again() -> TestResult {
    let origin = ClosingOrigin::bind().await?;
    let client = Client::builder(profile()).dns_cache(settings()).build()?;
    let (client, calls) = with_counting_cache(&client, watch::channel(true).1);

    get(&client, &origin.url()).await?;
    client.clear_dns_cache();
    get(&client, &origin.url()).await?;

    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[test]
fn profile_dns_cache_reaches_every_connector() -> TestResult {
    let http3 = Http3ClientSettings::new(
        chromium::v154_http3_tls(),
        chromium::v154_quic(),
        chromium::v154_http3(),
        chromium::v154_http3_request(),
    );
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_dns_cache(chromium::v154_dns_cache())
        .with_http2(chromium::v154_http2())
        .with_http3(http3);
    #[cfg(feature = "websocket")]
    let profile = profile.with_websocket(chromium::v154_websocket());
    let route = Route::http_connect(HttpProxy::new("https://proxy.example")?);
    let client = Client::builder(profile).route(route).build()?;
    let inner = &client.inner;
    let expected = Some(chromium::v154_dns_cache());
    let settings = |resolver: Option<&HostResolver>| {
        resolver
            .and_then(HostResolver::cache)
            .map(|cache| *cache.settings())
    };

    assert_eq!(settings(inner.host_resolver.as_ref()), expected);
    assert_eq!(
        settings(inner.http1.as_ref().and_then(|c| c.host_resolver())),
        expected
    );
    assert_eq!(
        settings(inner.http2.as_ref().and_then(|c| c.host_resolver())),
        expected
    );
    assert_eq!(
        settings(inner.http1_or_2.as_ref().and_then(|c| c.host_resolver())),
        expected
    );
    assert_eq!(
        settings(inner.http3.as_ref().and_then(|c| c.host_resolver())),
        expected
    );
    assert_eq!(
        settings(inner.https_proxy.as_ref().and_then(|c| c.host_resolver())),
        expected
    );
    let connect_udp = inner
        .connect_udp_proxy
        .as_ref()
        .ok_or("no CONNECT-UDP connectors")?;
    assert_eq!(
        settings(connect_udp.http3.as_ref().and_then(|c| c.host_resolver())),
        expected
    );
    assert_eq!(
        settings(connect_udp.tcp.as_ref().and_then(|c| c.host_resolver())),
        expected
    );
    #[cfg(feature = "websocket")]
    assert_eq!(
        settings(
            inner
                .websocket_http1
                .as_ref()
                .and_then(|c| c.host_resolver())
        ),
        expected
    );
    Ok(())
}

#[test]
fn builder_settings_replace_or_disable_the_profiles() -> TestResult {
    let caching = || profile().with_dns_cache(chromium::v154_dns_cache());

    let replaced = Client::builder(caching())
        .dns_cache(firefox::v156_dns_cache())
        .build()?;
    let disabled = Client::builder(caching()).no_dns_cache().build()?;
    let without = Client::builder(profile()).build()?;

    assert_eq!(
        replaced
            .inner
            .host_resolver
            .as_ref()
            .and_then(HostResolver::cache)
            .map(|cache| *cache.settings()),
        Some(firefox::v156_dns_cache())
    );
    assert!(disabled.inner.host_resolver.is_none());
    assert!(
        disabled
            .inner
            .http1
            .as_ref()
            .is_some_and(|c| c.host_resolver().is_none())
    );
    assert!(without.inner.host_resolver.is_none());
    assert!(without.session().inner.host_resolver.is_none());
    Ok(())
}

#[test]
fn overrides_without_a_cache_reach_the_connectors_and_sessions() -> TestResult {
    let pinned = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9));
    let client = Client::builder(profile().with_http2(chromium::v154_http2()))
        .no_dns_cache()
        .resolve("Pinned.Phantom.Test", [pinned])
        .build()?;
    let session = client.session();
    let pinned_in = |resolver: Option<&HostResolver>| {
        resolver.and_then(|resolver| {
            resolver
                .override_for("pinned.phantom.test")
                .map(<[_]>::to_vec)
        })
    };

    for inner in [&client.inner, &session.inner] {
        let resolver = inner.host_resolver.as_ref();
        assert!(resolver.is_some_and(|resolver| resolver.cache().is_none()));
        assert_eq!(pinned_in(resolver), Some(vec![pinned]));
        assert_eq!(
            pinned_in(inner.http1.as_ref().and_then(|c| c.host_resolver())),
            Some(vec![pinned])
        );
        assert_eq!(
            pinned_in(inner.http2.as_ref().and_then(|c| c.host_resolver())),
            Some(vec![pinned])
        );
    }
    Ok(())
}
