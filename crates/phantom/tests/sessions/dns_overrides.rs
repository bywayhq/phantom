//! Host overrides and a caller-supplied address resolver, against loopback
//! servers reached only by names that never resolve in public DNS.

use crate::support::socks5 as socks5_support;
use crate::support::tls;
use crate::support::tunnel_proxy;

use std::{
    error::Error,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use btls::ssl::NameType;
use http_body_util::BodyExt;
use phantom::{
    AddressResolver, BuildErrorKind, Client, ConnectUdpProxy, HttpProtocol, HttpProxy,
    RequestErrorKind, Route, Socks5Proxy,
    profile::{ClientProfile, DnsCacheSettings, Http3ClientSettings, Http3PseudoHeader, chromium},
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};

use socks5_support::forward_one_socks5;
use tls::{H1_ALPN, TestIdentity, TestResult, accept_tls_stream, client_builder, read_head};

const ORIGIN: &str = "origin.phantom.test";
const PROXY: &str = "proxy.phantom.test";
/// An address from TEST-NET-1 (RFC 5737). A connection to it would never
/// complete, so a test that reaches its server proves it was not used.
const UNUSED: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// What a TLS origin saw on its one connection.
struct Observed {
    server_name: Option<String>,
    head: Vec<u8>,
}

/// A TLS HTTP/1.1 origin for [`ORIGIN`] that answers one request.
struct TlsOrigin {
    address: SocketAddr,
    task: JoinHandle<TestResult<Observed>>,
}

impl TlsOrigin {
    async fn bind(identity: &TestIdentity) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, acceptor).await?;
            let server_name = stream
                .ssl()
                .servername(NameType::HOST_NAME)
                .map(str::to_owned);
            let head = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await?;
            stream.shutdown().await?;
            Ok(Observed { server_name, head })
        });
        Ok(Self { address, task })
    }

    fn url(&self) -> String {
        format!("https://{ORIGIN}:{}/", self.address.port())
    }

    async fn observed(self) -> TestResult<Observed> {
        self.task.await?
    }
}

async fn get_ok(client: &phantom::Client, url: &str) -> TestResult<()> {
    let response = client.get(HttpProtocol::Http1, url)?.send().await?;
    assert_eq!(response.status(), 200);
    assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
    Ok(())
}

fn assert_origin_saw_its_name(observed: &Observed, port: u16) {
    assert_eq!(observed.server_name.as_deref(), Some(ORIGIN));
    let head = String::from_utf8_lossy(&observed.head);
    assert!(
        head.contains(&format!("\r\nHost: {ORIGIN}:{port}\r\n")),
        "{head}"
    );
}

#[tokio::test]
async fn an_override_routes_a_name_to_its_address_and_keeps_the_server_name() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN)?;
        let origin = TlsOrigin::bind(&identity).await?;
        let client = client_builder(&identity, false)
            .resolve("Origin.Phantom.Test", [LOOPBACK])
            .build()?;

        get_ok(&client, &origin.url()).await?;

        let port = origin.address.port();
        assert_origin_saw_its_name(&origin.observed().await?, port);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn an_http_proxy_route_overrides_the_proxy_host_but_not_the_target() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN)?;
        let origin = TlsOrigin::bind(&identity).await?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_port = proxy_listener.local_addr()?.port();
        let proxy = tokio::spawn(tunnel_proxy::http1_connect(proxy_listener, origin.address));
        let route = Route::http_connect(HttpProxy::new(&format!("http://{PROXY}:{proxy_port}"))?);
        let client = client_builder(&identity, false)
            .route(route)
            .resolve(PROXY, [LOOPBACK])
            .resolve(ORIGIN, [UNUSED])
            .build()?;

        get_ok(&client, &origin.url()).await?;

        let port = origin.address.port();
        let connect = String::from_utf8(proxy.await??)?;
        assert!(
            connect.starts_with(&format!("CONNECT {ORIGIN}:{port} HTTP/1.1\r\n")),
            "{connect}"
        );
        assert_origin_saw_its_name(&origin.observed().await?, port);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_remote_dns_socks5_route_sends_the_name_and_ignores_its_override() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN)?;
        let origin = TlsOrigin::bind(&identity).await?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_port = proxy_listener.local_addr()?.port();
        let proxy = tokio::spawn(forward_one_socks5(proxy_listener, origin.address));
        let route = Route::socks5(Socks5Proxy::new(&format!(
            "socks5h://{PROXY}:{proxy_port}"
        ))?);
        let client = client_builder(&identity, false)
            .route(route)
            .resolve(PROXY, [LOOPBACK])
            .resolve(ORIGIN, [UNUSED])
            .build()?;

        get_ok(&client, &origin.url()).await?;

        let port = origin.address.port();
        let target = proxy.await??;
        assert_eq!((target.host.as_str(), target.port), (ORIGIN, port));
        assert_origin_saw_its_name(&origin.observed().await?, port);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_local_dns_socks5_route_sends_the_overridden_address() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN)?;
        let origin = TlsOrigin::bind(&identity).await?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_port = proxy_listener.local_addr()?.port();
        let proxy = tokio::spawn(forward_one_socks5(proxy_listener, origin.address));
        let route = Route::socks5(Socks5Proxy::new(&format!("socks5://{PROXY}:{proxy_port}"))?);
        let target_address = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 7));
        let client = client_builder(&identity, false)
            .route(route)
            .resolve(PROXY, [LOOPBACK])
            .resolve(ORIGIN, [target_address])
            .build()?;

        get_ok(&client, &origin.url()).await?;

        let port = origin.address.port();
        let target = proxy.await??;
        assert_eq!(
            (target.host.as_str(), target.port),
            (target_address.to_string().as_str(), port)
        );
        assert_origin_saw_its_name(&origin.observed().await?, port);
        Ok(())
    })
    .await
}

/// A plaintext HTTP/1.1 origin that closes each connection after one
/// response, so every request opens a new connection and resolves again.
async fn closing_origin() -> TestResult<(u16, JoinHandle<()>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(answer_and_close(stream));
        }
    });
    Ok((port, task))
}

async fn answer_and_close(mut stream: TcpStream) {
    if read_head(&mut stream).await.is_ok() {
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await;
    }
}

fn counting_resolver(calls: &Arc<AtomicUsize>) -> AddressResolver {
    let calls = Arc::clone(calls);
    AddressResolver::from_fn(move |host| {
        calls.fetch_add(1, Ordering::SeqCst);
        async move {
            // A timer only a runtime task can wait on.
            tokio::time::sleep(Duration::from_millis(1)).await;
            if host == ORIGIN {
                Ok(vec![LOOPBACK])
            } else {
                Err(io::Error::new(io::ErrorKind::NotFound, "no such test host"))
            }
        }
    })
}

fn cache_for(ttl: Duration) -> DnsCacheSettings {
    DnsCacheSettings {
        max_entries: NonZeroUsize::new(16).unwrap_or(NonZeroUsize::MIN),
        ttl,
        negative_ttl: None,
    }
}

#[tokio::test]
async fn a_cached_resolver_is_asked_once_per_lifetime() -> TestResult<()> {
    bounded(async {
        let (port, origin) = closing_origin().await?;
        let calls = Arc::new(AtomicUsize::new(0));
        let identity = TestIdentity::generate_for_dns(ORIGIN)?;
        let client = client_builder(&identity, false)
            .dns_resolver(counting_resolver(&calls))
            .dns_cache(cache_for(Duration::from_millis(500)))
            .build()?;
        let url = format!("http://{ORIGIN}:{port}/");

        for _ in 0..3 {
            get_ok(&client, &url).await?;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(600)).await;
        get_ok(&client, &url).await?;

        assert_eq!(calls.load(Ordering::SeqCst), 2);
        origin.abort();
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_resolver_without_a_cache_is_asked_for_every_connection() -> TestResult<()> {
    bounded(async {
        let (port, origin) = closing_origin().await?;
        let calls = Arc::new(AtomicUsize::new(0));
        let identity = TestIdentity::generate_for_dns(ORIGIN)?;
        let client = client_builder(&identity, false)
            .dns_resolver(counting_resolver(&calls))
            .no_dns_cache()
            .build()?;
        let url = format!("http://{ORIGIN}:{port}/");

        get_ok(&client, &url).await?;
        get_ok(&client, &url).await?;

        assert_eq!(calls.load(Ordering::SeqCst), 2);
        origin.abort();
        Ok(())
    })
    .await
}

#[tokio::test]
async fn resolver_errors_are_classified_as_system_lookup_failures() -> TestResult<()> {
    bounded(async {
        let calls = Arc::new(AtomicUsize::new(0));
        let identity = TestIdentity::generate_for_dns(ORIGIN)?;
        let direct = client_builder(&identity, false)
            .dns_resolver(counting_resolver(&calls))
            .build()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let route = Route::socks5(Socks5Proxy::new(&format!("socks5://{proxy_address}"))?);
        let local_socks5 = client_builder(&identity, false)
            .route(route)
            .dns_resolver(counting_resolver(&calls))
            .build()?;
        let url = "http://missing.phantom.test/";

        let direct_error = request_error(&direct, HttpProtocol::Http1, url).await?;
        let socks5_error = request_error(&local_socks5, HttpProtocol::Http1, url).await?;

        assert_eq!(direct_error.kind(), RequestErrorKind::Connect);
        assert_eq!(socks5_error.kind(), RequestErrorKind::Resolve);
        for error in [&direct_error, &socks5_error] {
            let source = io_source(error).ok_or("the resolver's error is not a source")?;
            assert_eq!(source.kind(), io::ErrorKind::NotFound);
            assert!(source.to_string().contains("no such test host"));
        }
        drop(proxy_listener);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn resolver_errors_for_proxy_hosts_and_http3_origins_keep_their_path_kinds() -> TestResult<()>
{
    bounded(async {
        let calls = Arc::new(AtomicUsize::new(0));
        let identity = TestIdentity::generate_for_dns(ORIGIN)?;
        let proxy = Route::http_connect(HttpProxy::new("http://missing.phantom.test:8080")?);
        let http_proxy = client_builder(&identity, false)
            .route(proxy)
            .dns_resolver(counting_resolver(&calls))
            .build()?;
        let direct_http3 = Client::builder(http3_profile())
            .dns_resolver(counting_resolver(&calls))
            .build()?;
        let connect_udp = Client::builder(http3_profile())
            .route(Route::connect_udp(ConnectUdpProxy::new(
                "https://missing.phantom.test:4433/.well-known/masque/udp/{target_host}/{target_port}/",
            )?))
            .dns_resolver(counting_resolver(&calls))
            .build()?;
        let origin = format!("https://{ORIGIN}/");

        let proxy_error = request_error(&http_proxy, HttpProtocol::Http1, &origin).await?;
        let http3_error = request_error(
            &direct_http3,
            HttpProtocol::Http3,
            "https://missing.phantom.test/",
        )
        .await?;
        let connect_udp_error = request_error(&connect_udp, HttpProtocol::Http3, &origin).await?;

        assert_eq!(proxy_error.kind(), RequestErrorKind::Proxy);
        assert_eq!(http3_error.kind(), RequestErrorKind::Resolve);
        assert_eq!(
            connect_udp_error.kind(),
            RequestErrorKind::Resolve,
            "{connect_udp_error:?}"
        );
        for error in [&proxy_error, &http3_error, &connect_udp_error] {
            let source =
                io_source(error).ok_or_else(|| format!("no resolver source in {error:?}"))?;
            assert_eq!(source.kind(), io::ErrorKind::NotFound);
        }
        Ok(())
    })
    .await
}

/// A Chrome HTTP/3 profile with the extended CONNECT order a CONNECT-UDP
/// proxy leg needs.
fn http3_profile() -> ClientProfile {
    let mut request = chromium::v154_http3_request();
    request.extended_connect_pseudo_header_order = Some(vec![
        Http3PseudoHeader::Method,
        Http3PseudoHeader::Protocol,
        Http3PseudoHeader::Scheme,
        Http3PseudoHeader::Authority,
        Http3PseudoHeader::Path,
    ]);
    ClientProfile::new(chromium::v154_tls()).with_http3(Http3ClientSettings::new(
        chromium::v154_http3_tls(),
        chromium::v154_quic(),
        chromium::v154_http3(),
        request,
    ))
}

#[tokio::test]
async fn a_unicode_override_matches_the_a_label_host() -> TestResult<()> {
    bounded(async {
        const A_LABEL: &str = "xn--bcher-kva.phantom.test";
        let identity = TestIdentity::generate_for_dns(A_LABEL)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let origin = tokio::spawn(serve_keep_alive(listener, identity.acceptor(H1_ALPN)?));
        let client = client_builder(&identity, false)
            .resolve("B\u{fc}cher.Phantom.Test", [LOOPBACK])
            .build()?;

        get_ok(&client, &format!("https://{A_LABEL}:{port}/")).await?;

        drop(client);
        let connections = origin.await??;
        assert_eq!(connections, [Some(A_LABEL.to_owned())]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn names_sent_to_one_address_keep_separate_pooled_connections() -> TestResult<()> {
    bounded(async {
        const OTHER: &str = "other.phantom.test";
        let identity = TestIdentity::generate_for_dns_names(&[ORIGIN, OTHER])?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let origin = tokio::spawn(serve_keep_alive(listener, identity.acceptor(H1_ALPN)?));
        let client = client_builder(&identity, false)
            .resolve("ORIGIN.phantom.test", [LOOPBACK])
            .resolve(OTHER, [LOOPBACK])
            .build()?;

        for host in [ORIGIN, ORIGIN, OTHER] {
            get_ok(&client, &format!("https://{host}:{port}/")).await?;
        }

        drop(client);
        let connections = origin.await??;
        assert_eq!(
            connections,
            [Some(ORIGIN.to_owned()), Some(OTHER.to_owned())],
            "one reused connection per name"
        );
        Ok(())
    })
    .await
}

/// Accepts TLS connections that each answer requests until the client
/// closes them, and returns each connection's server name once no new
/// connection arrives for a while.
async fn serve_keep_alive(
    listener: TcpListener,
    acceptor: btls::ssl::SslAcceptor,
) -> TestResult<Vec<Option<String>>> {
    let mut connections = Vec::new();
    let mut served = Vec::new();
    while let Ok(accepted) = timeout(Duration::from_millis(500), listener.accept()).await {
        let (tcp, _) = accepted?;
        let mut stream = accept_tls_stream(tcp, acceptor.clone()).await?;
        connections.push(
            stream
                .ssl()
                .servername(NameType::HOST_NAME)
                .map(str::to_owned),
        );
        served.push(tokio::spawn(async move {
            while read_head(&mut stream).await.is_ok() {
                if stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }));
    }
    for task in served {
        task.abort();
    }
    Ok(connections)
}

#[test]
fn an_override_for_an_ip_address_in_any_form_fails_the_build() -> TestResult<()> {
    let identity = TestIdentity::generate_for_dns(ORIGIN)?;
    for host in [
        "127.0.0.1",
        "127.1",
        "0x7f.1",
        "[::1]",
        "\u{ff11}\u{ff12}\u{ff17}.0.0.1",
        "",
        "bad host",
    ] {
        let error = client_builder(&identity, false)
            .resolve(host, [LOOPBACK])
            .build()
            .err()
            .ok_or_else(|| format!("the build accepted an override for {host:?}"))?;
        assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy, "{host:?}");
    }
    Ok(())
}

async fn request_error(
    client: &phantom::Client,
    protocol: HttpProtocol,
    url: &str,
) -> TestResult<phantom::RequestError> {
    match client.get(protocol, url)?.send().await {
        Ok(_) => Err(format!("{url} answered through a failing resolver").into()),
        Err(error) => Ok(error),
    }
}

/// Returns the first `io::Error` in `error`'s source chain.
fn io_source<'a>(error: &'a (dyn Error + 'static)) -> Option<&'a io::Error> {
    let mut source = error.source();
    while let Some(current) = source {
        if let Some(io) = current.downcast_ref::<io::Error>() {
            return Some(io);
        }
        source = current.source();
    }
    None
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "DNS override integration test exceeded its deadline")?
}
