//! A client bound to a local address sends every connection from it.

use std::{
    error::Error,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use phantom::{
    BuildErrorKind, Client, HttpProtocol, HttpProxy, RequestError, RequestErrorKind, Route,
    Socks5Proxy,
    profile::{ClientProfile, chromium},
};
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::oneshot, time::timeout};

use crate::support::{
    h3 as h3_support, socks5_udp::forward_one_socks5_udp_associate, tls as tls_support,
};
use tls_support::{TestIdentity, TestResult, read_head};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const NO_CONNECTION_WINDOW: Duration = Duration::from_millis(200);
const IPV4_LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const IPV6_LOOPBACK: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

/// The loopback interface's name, on the platforms that bind an interface by
/// name: on Windows its NDIS name, which no display language changes.
#[cfg(any(target_os = "android", target_os = "linux"))]
const LOOPBACK_INTERFACE: &str = "lo";
#[cfg(target_vendor = "apple")]
const LOOPBACK_INTERFACE: &str = "lo0";
#[cfg(windows)]
const LOOPBACK_INTERFACE: &str = "loopback_0";
#[cfg(not(any(
    target_os = "android",
    target_os = "linux",
    target_vendor = "apple",
    windows
)))]
const LOOPBACK_INTERFACE: &str = "lo0";

/// A Chromium profile, so connections race IPv6 against IPv4.
fn profile() -> ClientProfile {
    ClientProfile::new(chromium::v154_tls()).with_tcp(chromium::v154_tcp())
}

/// Accepts one HTTP/1.1 request and answers it, returning the peer address.
async fn answer_one(listener: &TcpListener) -> TestResult<SocketAddr> {
    let (mut stream, peer) = listener.accept().await?;
    read_head(&mut stream).await?;
    stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await?;
    Ok(peer)
}

async fn get(client: &Client, url: String) -> Result<(), RequestError> {
    let response = client.get(HttpProtocol::Http1, &url)?.send().await?;
    drop(response);
    Ok(())
}

/// Returns the first `io::Error` in `error`'s source chain.
fn io_error_kind(error: &(dyn Error + 'static)) -> Option<io::ErrorKind> {
    let mut source = Some(error);
    while let Some(error) = source {
        if let Some(error) = error.downcast_ref::<io::Error>() {
            return Some(error.kind());
        }
        source = error.source();
    }
    None
}

/// Binds IPv4 and IPv6 loopback listeners to one port number.
async fn dual_stack_listeners() -> TestResult<(TcpListener, TcpListener)> {
    for _ in 0..64 {
        let ipv4 = TcpListener::bind((IPV4_LOOPBACK, 0)).await?;
        let port = ipv4.local_addr()?.port();
        match TcpListener::bind((IPV6_LOOPBACK, port)).await {
            Ok(ipv6) => return Ok((ipv4, ipv6)),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err("no port was free on both loopback addresses".into())
}

#[tokio::test]
async fn origin_sees_the_bound_address() -> TestResult<()> {
    let listener = TcpListener::bind((IPV4_LOOPBACK, 0)).await?;
    let address = listener.local_addr()?;
    let client = Client::builder(profile())
        .local_address(IPV4_LOOPBACK)
        .build()?;

    let (peer, sent) = timeout(TEST_TIMEOUT, async {
        tokio::join!(
            answer_one(&listener),
            get(&client, format!("http://{address}/"))
        )
    })
    .await?;
    sent?;

    assert_eq!(peer?.ip(), IPV4_LOOPBACK);
    Ok(())
}

#[tokio::test]
async fn a_dual_stack_host_is_reached_over_the_bound_family() -> TestResult<()> {
    for (source, expected_ipv6) in [(IPV4_LOOPBACK, false), (IPV6_LOOPBACK, true)] {
        let (ipv4, ipv6) = dual_stack_listeners().await?;
        let port = ipv4.local_addr()?.port();
        // The profile races IPv6 first, so an unbound client reaches `ipv6`.
        let client = Client::builder(profile())
            .resolve("dual.test", [IPV6_LOOPBACK, IPV4_LOOPBACK])
            .local_address(source)
            .build()?;
        let (bound, other) = if expected_ipv6 {
            (&ipv6, &ipv4)
        } else {
            (&ipv4, &ipv6)
        };

        let (peer, sent) = timeout(TEST_TIMEOUT, async {
            tokio::join!(
                answer_one(bound),
                get(&client, format!("http://dual.test:{port}/"))
            )
        })
        .await?;
        sent?;

        assert_eq!(peer?.ip(), source);
        assert!(
            timeout(NO_CONNECTION_WINDOW, other.accept()).await.is_err(),
            "a {source} binding connected over the other family"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_host_without_an_address_of_the_bound_family_fails_before_connecting() -> TestResult<()> {
    let listener = TcpListener::bind((IPV4_LOOPBACK, 0)).await?;
    let address = listener.local_addr()?;
    let client = Client::builder(profile())
        .local_address(IPV6_LOOPBACK)
        .build()?;

    let error = match timeout(TEST_TIMEOUT, get(&client, format!("http://{address}/"))).await? {
        Ok(()) => return Err("an IPv6-bound client reached an IPv4 origin".into()),
        Err(error) => error,
    };

    assert_eq!(error.kind(), RequestErrorKind::Connect);
    assert_eq!(io_error_kind(&error), Some(io::ErrorKind::AddrNotAvailable));
    assert!(
        timeout(NO_CONNECTION_WINDOW, listener.accept())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn proxy_connections_use_the_binding() -> TestResult<()> {
    let listener = TcpListener::bind((IPV4_LOOPBACK, 0)).await?;
    let proxy = listener.local_addr()?;
    let routes = [
        Route::http_proxy(HttpProxy::new(&format!("http://{proxy}"))?),
        Route::http_proxy(HttpProxy::new(&format!("http://{proxy}"))?),
        Route::socks5(Socks5Proxy::new(&format!("socks5h://{proxy}"))?),
    ];
    for route in routes {
        let client = Client::builder(profile())
            .local_address(IPV6_LOOPBACK)
            .route(route)
            .build()?;

        let error =
            match timeout(TEST_TIMEOUT, get(&client, "http://origin.test/".to_owned())).await? {
                Ok(()) => return Err("an IPv6-bound client reached an IPv4 proxy".into()),
                Err(error) => error,
            };

        assert_eq!(error.kind(), RequestErrorKind::Proxy, "{error}");
        assert_eq!(
            io_error_kind(&error),
            Some(io::ErrorKind::AddrNotAvailable),
            "{error}"
        );
    }
    assert!(
        timeout(NO_CONNECTION_WINDOW, listener.accept())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn http3_leaves_from_the_bound_address() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = h3_support::server_endpoint(&identity)?;
    let client = Client::builder(
        ClientProfile::new(chromium::v154_tls()).with_http3(h3_support::client_settings()),
    )
    .add_root_certificate_der(identity.root_der.clone())
    .local_address(IPV4_LOOPBACK)
    .build()?;

    let server = async {
        let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
        let peer = incoming.remote_address();
        drop(incoming.accept()?);
        Ok::<_, Box<dyn Error + Send + Sync>>(peer)
    };
    let request = async {
        let _ = client
            .get(HttpProtocol::Http3, &format!("https://{address}/"))?
            .send()
            .await;
        Ok::<_, RequestError>(())
    };
    let (peer, sent) = timeout(TEST_TIMEOUT, async { tokio::join!(server, request) }).await?;
    sent?;

    assert_eq!(peer?.ip(), IPV4_LOOPBACK);
    Ok(())
}

#[tokio::test]
async fn http3_without_an_address_of_the_bound_family_fails() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = h3_support::server_endpoint(&identity)?;
    let client = Client::builder(
        ClientProfile::new(chromium::v154_tls()).with_http3(h3_support::client_settings()),
    )
    .add_root_certificate_der(identity.root_der.clone())
    .local_address(IPV6_LOOPBACK)
    .build()?;

    let error = match timeout(
        TEST_TIMEOUT,
        client
            .get(HttpProtocol::Http3, &format!("https://{address}/"))?
            .send(),
    )
    .await?
    {
        Ok(_) => return Err("an IPv6-bound client reached an IPv4 HTTP/3 origin".into()),
        Err(error) => error,
    };

    assert_eq!(error.kind(), RequestErrorKind::Connect, "{error}");
    assert_eq!(io_error_kind(&error), Some(io::ErrorKind::AddrNotAvailable));
    assert!(
        timeout(NO_CONNECTION_WINDOW, endpoint.accept())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn socks5_udp_association_sends_from_the_bound_address() -> TestResult<()> {
    // A second loopback address shows the binding, since an unbound client
    // would leave from 127.0.0.1. macOS has only 127.0.0.1 by default.
    let source = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    if phantom_testkit::udp::bind((source, 0).into()).is_err() {
        eprintln!("skipped: 127.0.0.2 is not a local address on this host");
        return Ok(());
    }
    let identity = TestIdentity::generate()?;
    let (origin, endpoint) = h3_support::server_endpoint(&identity)?;
    let proxy_listener = TcpListener::bind((IPV4_LOOPBACK, 0)).await?;
    let proxy_address = proxy_listener.local_addr()?;
    let proxy = tokio::spawn(forward_one_socks5_udp_associate(proxy_listener, origin));
    let (done, done_received) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (_, mut stream, _connection) = h3_support::accept_request(&endpoint).await?;
        stream
            .send_response(
                http::Response::builder()
                    .status(http::StatusCode::NO_CONTENT)
                    .body(())?,
            )
            .await?;
        stream.finish().await?;
        let _ = done_received.await;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });
    let client = Client::builder(
        ClientProfile::new(chromium::v154_tls()).with_http3(h3_support::client_settings()),
    )
    .add_root_certificate_der(identity.root_der.clone())
    .route(Route::socks5(Socks5Proxy::new(&format!(
        "socks5://{proxy_address}"
    ))?))
    .local_address(source)
    .build()?;

    let response = timeout(
        TEST_TIMEOUT,
        client
            .get(HttpProtocol::Http3, &format!("https://{origin}/"))?
            .send(),
    )
    .await??;
    assert_eq!(response.status(), http::StatusCode::NO_CONTENT);
    drop(response);
    drop(client);
    let _ = done.send(());
    timeout(TEST_TIMEOUT, server).await???;
    let observed = timeout(TEST_TIMEOUT, proxy).await???;

    assert!(observed.client_datagrams > 0);
    assert_eq!(observed.client_peer.map(|peer| peer.ip()), Some(source));
    Ok(())
}

#[test]
fn an_address_that_cannot_be_a_source_is_an_invalid_policy() -> Result<(), &'static str> {
    for address in [
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::BROADCAST),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    ] {
        let error = Client::builder(profile())
            .local_address(address)
            .build()
            .err()
            .ok_or("an unusable source address was accepted")?;
        assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);
    }
    Ok(())
}

#[test]
fn interface_binding_builds_only_where_the_platform_has_it() {
    let result = Client::builder(profile())
        .interface(LOOPBACK_INTERFACE)
        .build();

    if cfg!(any(
        target_os = "android",
        target_os = "linux",
        target_vendor = "apple",
        windows
    )) {
        assert!(result.is_ok());
    } else {
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(BuildErrorKind::InvalidPolicy)
        );
    }
}

#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_vendor = "apple",
    windows
))]
#[tokio::test]
async fn an_interface_no_host_has_fails_each_connection() -> TestResult<()> {
    let listener = TcpListener::bind((IPV4_LOOPBACK, 0)).await?;
    let address = listener.local_addr()?;
    let client = Client::builder(profile())
        .interface("phantom-none0")
        .build()?;

    let error = timeout(TEST_TIMEOUT, get(&client, format!("http://{address}/")))
        .await?
        .err()
        .ok_or("a request through an unknown interface succeeded")?;

    assert_eq!(error.kind(), RequestErrorKind::Connect);
    if cfg!(any(target_vendor = "apple", windows)) {
        assert_eq!(io_error_kind(&error), Some(io::ErrorKind::NotFound));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_vendor = "apple", windows))]
#[tokio::test]
async fn interface_binding_reaches_a_loopback_origin() -> TestResult<()> {
    let listener = TcpListener::bind((IPV4_LOOPBACK, 0)).await?;
    let address = listener.local_addr()?;
    let client = Client::builder(profile())
        .interface(LOOPBACK_INTERFACE)
        .build()?;
    let server =
        tokio::spawn(async move { answer_one(&listener).await.map_err(|e| e.to_string()) });

    match timeout(TEST_TIMEOUT, get(&client, format!("http://{address}/"))).await? {
        Ok(()) => {}
        // Linux before 5.7 lets only CAP_NET_RAW bind to an interface.
        Err(error)
            if cfg!(target_os = "linux")
                && io_error_kind(&error) == Some(io::ErrorKind::PermissionDenied) =>
        {
            eprintln!("skipped: this kernel refuses SO_BINDTODEVICE without CAP_NET_RAW");
            server.abort();
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    }
    let peer = timeout(TEST_TIMEOUT, server).await??;

    assert_eq!(peer?.ip(), IPV4_LOOPBACK);
    Ok(())
}
