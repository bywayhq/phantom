//! The HTTP layers report a connection's life to its keepalive schedule on
//! every path a Firefox profile opens: requests on plaintext HTTP/1.1, an
//! upgrade, and HTTP/1.1 or HTTP/2 chosen by ALPN.

use http_body_util::BodyExt as _;
use phantom_profile::{chromium, firefox};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

use crate::{
    http1::{Http1TlsConnector, Http1UpgradeOutcome},
    http1_or_2::{Http1Or2Connection, Http1Or2TlsConnector},
    proxy::{HttpConnectHeader, HttpsProxyConnector, HttpsProxyProtocol},
    request::{OriginForm, RequestHeader},
    tcp::keepalive_schedule::{KeepalivePhase, TcpKeepaliveControl, observed},
    tls::test_support::{
        TEST_SERVER_NAME, TestIdentity, TestResult, TestServerAlpn, accept_tls, loopback_listener,
    },
};

const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

async fn read_head(stream: &mut (impl AsyncReadExt + Unpin)) -> TestResult<Vec<u8>> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        if stream.read(&mut byte).await? == 0 {
            return Err("the client closed before a request head".into());
        }
        head.push(byte[0]);
    }
    Ok(head)
}

/// A plaintext origin that answers `responses` requests on one connection.
async fn http1_origin(responses: usize) -> TestResult<(u16, JoinHandle<TestResult<()>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        for _ in 0..responses {
            read_head(&mut stream).await?;
            stream.write_all(RESPONSE).await?;
        }
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest).await;
        Ok(())
    });
    Ok((port, task))
}

fn only_schedule() -> TestResult<TcpKeepaliveControl> {
    let mut controls = observed::take();
    let control = controls.pop().ok_or("no keepalive schedule was opened")?;
    assert!(controls.is_empty(), "more than one schedule was opened");
    Ok(control)
}

fn get() -> TestResult<(OriginForm, Vec<RequestHeader>)> {
    Ok((
        OriginForm::parse("/")?,
        vec![RequestHeader::new("Host", "127.0.0.1")],
    ))
}

#[tokio::test(flavor = "current_thread")]
async fn plaintext_requests_keep_one_short_lived_schedule() -> TestResult<()> {
    let (port, origin) = http1_origin(2).await?;
    observed::take();
    let connector =
        Http1TlsConnector::new(&firefox::v157_tls())?.with_tcp_settings(&firefox::v157_tcp());

    let connection = connector
        .connect(crate::route::Http1Route::Origin(
            crate::route::OriginRoute::Plaintext {
                tcp: crate::route::TcpRoute::Direct(crate::route::Endpoint {
                    host: "127.0.0.1",
                    port: port,
                }),
                family: None,
            },
        ))
        .await?;
    let control = only_schedule()?;
    for _ in 0..2 {
        let (target, headers) = get()?;
        let response = connection.send_get(target, headers).await?;
        assert!(!control.is_idle(), "idle while a response was unread");
        response.into_body().collect().await?;
        assert!(control.is_idle(), "not idle after the response completed");
    }
    drop(connection);
    origin.await??;

    assert_eq!(control.applied_phases(), [KeepalivePhase::ShortLived]);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_switch_of_protocols_makes_keepalive_long_lived() -> TestResult<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let origin = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        read_head(&mut stream).await?;
        stream
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n")
            .await?;
        let mut byte = [0];
        stream.read_exact(&mut byte).await?;
        TestResult::<()>::Ok(())
    });
    observed::take();
    let connector =
        Http1TlsConnector::new(&firefox::v157_tls())?.with_tcp_settings(&firefox::v157_tcp());

    let (target, mut headers) = get()?;
    headers.push(RequestHeader::new("Connection", "Upgrade"));
    headers.push(RequestHeader::new("Upgrade", "websocket"));
    let outcome = connector
        .upgrade_get_plaintext_direct("127.0.0.1", port, target, headers)
        .await?;
    let Http1UpgradeOutcome::Upgraded(response) = outcome else {
        return Err("the origin's 101 was not an upgrade".into());
    };
    let mut upgraded = response.into_body();
    upgraded.write_all(b"x").await?;
    origin.await??;

    let control = only_schedule()?;
    assert_eq!(
        control.applied_phases(),
        [KeepalivePhase::ShortLived, KeepalivePhase::LongLived]
    );
    Ok(())
}

/// Opens one negotiated connection to a TLS origin that selects `alpn`, and
/// returns the schedule the connection opened.
async fn negotiated(alpn: TestServerAlpn) -> TestResult<TcpKeepaliveControl> {
    let identity = TestIdentity::generate()?;
    let acceptor = identity.acceptor(alpn)?;
    let (address, listener) = loopback_listener().await?;
    let origin = tokio::spawn(async move {
        let (mut stream, _) = accept_tls(listener, acceptor).await?;
        let mut first = [0; 24];
        stream.read_exact(&mut first).await?;
        TestResult::<()>::Ok(())
    });
    observed::take();
    let connector = Http1Or2TlsConnector::new_with_additional_roots(
        &firefox::v157_tls(),
        &firefox::v157_http2(),
        [identity.root_der()],
    )?
    .with_tcp_settings(&firefox::v157_tcp());

    let connection = connector
        .connect(crate::route::OriginRoute::Tls {
            tcp: crate::route::TcpRoute::Direct(crate::route::Endpoint {
                host: "127.0.0.1",
                port: address.port(),
            }),
            server_name: "server.phantom.test",
            setup: crate::route::DirectTlsSetup::Default,
        })
        .await;
    if let Ok((Http1Or2Connection::Http1(connection), _)) = &connection {
        let (target, headers) = get()?;
        let _ = connection.send_get(target, headers).await;
    }
    let _ = origin.await;
    drop(connection);
    only_schedule()
}

#[tokio::test(flavor = "current_thread")]
async fn http2_negotiated_by_alpn_turns_keepalive_off() -> TestResult<()> {
    let control = negotiated(TestServerAlpn::H2).await?;

    assert_eq!(
        control.applied_phases(),
        [KeepalivePhase::ShortLived, KeepalivePhase::Disabled]
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn http1_negotiated_by_alpn_stays_short_lived() -> TestResult<()> {
    let control = negotiated(TestServerAlpn::Http1).await?;

    assert_eq!(control.applied_phases(), [KeepalivePhase::ShortLived]);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_chromium_profile_opens_no_schedule() -> TestResult<()> {
    let (port, origin) = http1_origin(1).await?;
    observed::take();
    let connector =
        Http1TlsConnector::new(&chromium::v154_tls())?.with_tcp_settings(&chromium::v154_tcp());

    let connection = connector
        .connect(crate::route::Http1Route::Origin(
            crate::route::OriginRoute::Plaintext {
                tcp: crate::route::TcpRoute::Direct(crate::route::Endpoint {
                    host: "127.0.0.1",
                    port: port,
                }),
                family: None,
            },
        ))
        .await?;
    let (target, headers) = get()?;
    connection
        .send_get(target, headers)
        .await?
        .into_body()
        .collect()
        .await?;
    drop(connection);
    origin.await??;

    assert!(observed::take().is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_firefox_socket_has_its_send_buffer_and_no_keepalive_before_io() -> TestResult<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let stream = super::connect("127.0.0.1", port, Some(firefox::v157_tcp()), None, None).await?;
    let _accepted: (TcpStream, _) = listener.accept().await?;

    let socket = socket2::SockRef::from(&stream);
    assert!(socket.tcp_nodelay()?);
    // Linux caps the value at `net.core.wmem_max` and reports it doubled.
    #[cfg(windows)]
    assert_eq!(socket.send_buffer_size()?, 524_288);
    // Keepalive waits for the first read or write.
    assert!(!socket.keepalive()?);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn an_http2_proxy_connection_turns_keepalive_off() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let acceptor = identity.acceptor(TestServerAlpn::H2)?;
    let (address, listener) = loopback_listener().await?;
    let proxy_server = tokio::spawn(async move {
        let (mut stream, _) = accept_tls(listener, acceptor).await?;
        let mut preface = [0; 24];
        stream.read_exact(&mut preface).await?;
        TestResult::<()>::Ok(())
    });
    observed::take();
    let proxy = HttpsProxyConnector::new_with_additional_roots(
        &firefox::v157_tls(),
        [identity.root_der()],
    )?
    .with_http2_settings(&firefox::v157_http2())
    .with_protocol(HttpsProxyProtocol::Http2)
    .with_tcp_settings(&firefox::v157_tcp());
    let origin = Http1TlsConnector::new(&firefox::v157_tls())?;

    let _ = origin
        .connect(crate::route::Http1Route::Origin(
            crate::route::OriginRoute::Tls {
                tcp: crate::route::TcpRoute::HttpConnect(crate::route::HttpConnectRoute {
                    proxy: crate::route::ProxyTransport::Tls {
                        endpoint: crate::route::Endpoint {
                            host: "127.0.0.1",
                            port: address.port(),
                        },
                        server_name: TEST_SERVER_NAME,
                        connector: &proxy,
                    },
                    authority: "server.phantom.test:443",
                    headers: &[HttpConnectHeader::authority("Host")],
                    credentials: None,
                }),
                server_name: TEST_SERVER_NAME,
                setup: crate::route::DirectTlsSetup::Default,
            },
        ))
        .await;
    let _ = proxy_server.await;

    let control = only_schedule()?;
    assert_eq!(
        control.applied_phases(),
        [KeepalivePhase::ShortLived, KeepalivePhase::Disabled]
    );
    Ok(())
}
