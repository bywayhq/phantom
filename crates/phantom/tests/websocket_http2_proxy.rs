//! HTTP/2 WebSocket extended CONNECT carried through proxy routes, plus the
//! HTTP/1 WebSocket over an HTTP/2 proxy transport.
#![cfg(feature = "websocket")]

#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls;
#[allow(dead_code)]
#[path = "support/tunnel_proxy.rs"]
mod tunnel_proxy;
#[allow(dead_code)]
#[path = "support/websocket_origin.rs"]
mod websocket_origin;

use std::{
    error::Error as StdError,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use phantom::{
    Client, HttpProtocol, HttpProxy, Route, Socks5Proxy, WebSocket, WebSocketCloseFrame,
    WebSocketErrorKind, WebSocketMessage,
    profile::{ClientProfile, Http2PseudoHeader, chromium},
};
use phantom_net::proxy::HttpConnectError;
use tokio::{net::TcpListener, sync::oneshot, time::timeout};

use tls::{H1_ALPN, H2_ALPN, TestIdentity, TestResult, client_builder, tls_settings};
use tunnel_proxy::Socks5Target;
use websocket_origin::{ClientFrame, header_value};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const ORIGIN_NAME: &str = "localhost";

#[tokio::test]
async fn h2_websocket_over_http_connect_exchanges_messages() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (origin_address, origin) = spawn_h2_origin(&identity).await?;
        let (proxy_address, proxy_listener) = bind().await?;
        let proxy = tokio::spawn(tunnel_proxy::http1_connect(proxy_listener, origin_address));

        let client = h2_websocket_client(
            &identity,
            None,
            Route::http_proxy(HttpProxy::new(&format!("http://{proxy_address}"))?),
        )?;
        let socket = client
            .websocket_with_protocol(
                HttpProtocol::Http2,
                &format!("wss://{origin_address}/events?via=connect"),
            )?
            .connect()
            .await?;
        exchange_echo(socket).await?;

        assert_eq!(
            proxy.await??,
            format!("CONNECT {origin_address} HTTP/1.1\r\nHost: {origin_address}\r\n\r\n")
                .as_bytes()
        );
        let record = origin.await??;
        assert_eq!(record.scheme.as_deref(), Some("https"));
        assert_eq!(
            record.authority.as_deref(),
            Some(origin_address.to_string().as_str())
        );
        assert_eq!(record.path.as_deref(), Some("/events?via=connect"));
        assert_eq!(record.protocol.as_deref(), Some("websocket"));
        assert_eq!(record.message, text_frame("hello"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn h2_websocket_over_https_connect_basic_challenge_replays_once() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (origin_address, origin) = spawn_h2_origin(&identity).await?;
        let proxy_identity = TestIdentity::generate()?;
        let (proxy_address, proxy_listener) = bind().await?;
        let proxy = tokio::spawn(tunnel_proxy::https1_challenge_then_connect(
            proxy_listener,
            proxy_identity.acceptor(H1_ALPN)?,
            origin_address,
        ));

        let client = h2_websocket_client(
            &identity,
            Some(proxy_identity.root_der.clone()),
            Route::http_proxy(
                HttpProxy::new(&format!("https://{proxy_address}"))?
                    .with_basic_auth("alice", "secret")?,
            ),
        )?;
        let socket = client
            .websocket_with_protocol(
                HttpProtocol::Http2,
                &format!("wss://{origin_address}/authenticated"),
            )?
            .connect()
            .await?;
        exchange_echo(socket).await?;

        let (anonymous, authorized, challenged_reused) = proxy.await??;
        assert!(anonymous.starts_with(format!("CONNECT {origin_address} HTTP/1.1\r\n").as_bytes()));
        assert_eq!(header_value(&anonymous, "proxy-authorization"), None);
        assert_eq!(
            header_value(&authorized, "proxy-authorization"),
            Some("Basic YWxpY2U6c2VjcmV0")
        );
        assert!(!challenged_reused, "challenged proxy connection was reused");
        let record = origin.await??;
        assert_eq!(record.path.as_deref(), Some("/authenticated"));
        assert_eq!(record.message, text_frame("hello"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn h2_websocket_over_h2_proxy_transport_exchanges_messages() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (origin_address, origin) = spawn_h2_origin(&identity).await?;
        let proxy_identity = TestIdentity::generate()?;
        let (proxy_address, proxy_listener) = bind().await?;
        let proxy = tokio::spawn(tunnel_proxy::http2_connect(
            proxy_listener,
            proxy_identity.acceptor(H2_ALPN)?,
            origin_address,
        ));

        let client = h2_websocket_client(
            &identity,
            Some(proxy_identity.root_der.clone()),
            Route::http_proxy(
                HttpProxy::new(&format!("https://{proxy_address}"))?.with_http2_transport()?,
            ),
        )?;
        let socket = client
            .websocket_with_protocol(
                HttpProtocol::Http2,
                &format!("wss://{origin_address}/nested"),
            )?
            .connect()
            .await?;
        exchange_echo(socket).await?;

        let record = proxy.await??;
        assert_eq!(
            record.authority.as_deref(),
            Some(origin_address.to_string().as_str())
        );
        assert!(record.fields.is_empty(), "{:?}", record.fields);
        let origin_record = origin.await??;
        assert_eq!(origin_record.protocol.as_deref(), Some("websocket"));
        assert_eq!(origin_record.path.as_deref(), Some("/nested"));
        assert_eq!(origin_record.message, text_frame("hello"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn h2_websocket_over_socks5_local_and_remote_dns() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN_NAME)?;
        for scheme in ["socks5", "socks5h"] {
            let (origin_address, origin) = spawn_h2_origin(&identity).await?;
            let (proxy_address, proxy_listener) = bind().await?;
            let proxy = tokio::spawn(tunnel_proxy::socks5_connect(proxy_listener, origin_address));

            let client = h2_websocket_client(
                &identity,
                None,
                Route::socks5(Socks5Proxy::new(&format!("{scheme}://{proxy_address}"))?),
            )?;
            let port = origin_address.port();
            let socket = client
                .websocket_with_protocol(
                    HttpProtocol::Http2,
                    &format!("wss://{ORIGIN_NAME}:{port}/{scheme}"),
                )?
                .connect()
                .await?;
            exchange_echo(socket).await?;

            let (target, target_port) = proxy.await??;
            assert_eq!(target_port, port);
            match (scheme, target) {
                ("socks5", Socks5Target::Ip(address)) => assert!(address.is_loopback()),
                ("socks5h", Socks5Target::Domain(name)) => assert_eq!(name, ORIGIN_NAME),
                (scheme, target) => {
                    return Err(format!("{scheme} sent unexpected target {target:?}").into());
                }
            }
            let record = origin.await??;
            let expected_authority = format!("{ORIGIN_NAME}:{port}");
            assert_eq!(
                record.authority.as_deref(),
                Some(expected_authority.as_str())
            );
            assert_eq!(record.path.as_deref(), Some(format!("/{scheme}").as_str()));
            assert_eq!(record.message, text_frame("hello"));
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn h2_websocket_proxy_failure_never_falls_back() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;

        let (proxy_address, proxy_listener) = bind().await?;
        let proxy = tokio::spawn(tunnel_proxy::http1_connect_status(proxy_listener, 502));
        let client = h2_websocket_client(
            &identity,
            None,
            Route::http_proxy(HttpProxy::new(&format!("http://{proxy_address}"))?),
        )?;
        let error = expect_error(
            client
                .websocket_with_protocol(HttpProtocol::Http2, &format!("wss://{origin_address}/"))?
                .connect()
                .await,
        )?;
        assert_eq!(error.kind(), WebSocketErrorKind::Proxy);
        assert!(matches!(
            connect_error(&error),
            Some(HttpConnectError::Rejected { status: 502 })
        ));
        assert!(proxy.await??.starts_with(b"CONNECT "));

        let (socks_address, socks_listener) = bind().await?;
        let socks = tokio::spawn(tunnel_proxy::socks5_refuse(socks_listener));
        let client = h2_websocket_client(
            &identity,
            None,
            Route::socks5(Socks5Proxy::new(&format!("socks5://{socks_address}"))?),
        )?;
        let error = expect_error(
            client
                .websocket_with_protocol(HttpProtocol::Http2, &format!("wss://{origin_address}/"))?
                .connect()
                .await,
        )?;
        assert_eq!(error.kind(), WebSocketErrorKind::Proxy);
        assert_eq!(
            socks.await??,
            (
                Socks5Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                origin_address.port()
            )
        );

        // Neither a direct H2 connection nor an H1 Upgrade reached the origin.
        assert!(matches!(
            origin.accept(),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn h2_websocket_over_proxy_requires_peer_setting() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (origin_address, origin_listener) = bind().await?;
        let (client_done, done_signal) = oneshot::channel();
        let origin = tokio::spawn(websocket_origin::serve_h2_without_connect_protocol(
            origin_listener,
            identity.acceptor(H2_ALPN)?,
            done_signal,
        ));
        let (proxy_address, proxy_listener) = bind().await?;
        let proxy = tokio::spawn(tunnel_proxy::http1_connect(proxy_listener, origin_address));

        let client = h2_websocket_client(
            &identity,
            None,
            Route::http_proxy(HttpProxy::new(&format!("http://{proxy_address}"))?),
        )?;
        let error = expect_error(
            client
                .websocket_with_protocol(
                    HttpProtocol::Http2,
                    &format!("wss://{origin_address}/no-capability"),
                )?
                .connect()
                .await,
        )?;
        assert_eq!(error.kind(), WebSocketErrorKind::Http2);
        client_done
            .send(())
            .map_err(|()| "origin dropped completion receiver")?;

        proxy.await??;
        assert!(
            !origin.await??,
            "extended CONNECT HEADERS were sent without the peer setting"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn plaintext_ws_over_h2_rejected_before_io() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;
        let proxy = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        proxy.set_nonblocking(true)?;
        let proxy_address = proxy.local_addr()?;

        let routes = [
            Route::direct(),
            Route::http_proxy(HttpProxy::new(&format!("http://{proxy_address}"))?),
            Route::http_proxy(
                HttpProxy::new(&format!("https://{proxy_address}"))?.with_http2_transport()?,
            ),
            Route::socks5(Socks5Proxy::new(&format!("socks5h://{proxy_address}"))?),
        ];
        for route in routes {
            let client = h2_websocket_client(&identity, None, route)?;
            let error = expect_error(
                client
                    .websocket_with_protocol(
                        HttpProtocol::Http2,
                        &format!("ws://{origin_address}/plaintext"),
                    )?
                    .connect()
                    .await,
            )?;
            assert_eq!(error.kind(), WebSocketErrorKind::UnsupportedRoute);
        }

        assert!(matches!(
            origin.accept(),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        assert!(matches!(
            proxy.accept(),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http1_websocket_over_h2_proxy_transport_exchanges_messages() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (origin_address, origin_listener) = bind().await?;
        let origin = tokio::spawn(websocket_origin::serve_h1_echo(
            origin_listener,
            identity.acceptor(H1_ALPN)?,
        ));
        let proxy_identity = TestIdentity::generate()?;
        let (proxy_address, proxy_listener) = bind().await?;
        let proxy = tokio::spawn(tunnel_proxy::http2_connect(
            proxy_listener,
            proxy_identity.acceptor(H2_ALPN)?,
            origin_address,
        ));

        let route = Route::http_proxy(
            HttpProxy::new(&format!("https://{proxy_address}"))?.with_http2_transport()?,
        );
        let client = client_builder(&identity, true)
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .route(route)
            .build()?;
        let socket = client
            .websocket(&format!("wss://{origin_address}/h1-in-h2"))?
            .connect()
            .await?;
        assert_eq!(socket.handshake_response().status(), 101);
        exchange_echo(socket).await?;

        let record = proxy.await??;
        assert_eq!(
            record.authority.as_deref(),
            Some(origin_address.to_string().as_str())
        );
        let (request, message) = origin.await??;
        assert!(request.starts_with(b"GET /h1-in-h2 HTTP/1.1\r\n"));
        assert_eq!(message, text_frame("hello"));

        // Plaintext `ws://` uses absolute-form forwarding, which the HTTP/2
        // proxy transport cannot carry; it fails before proxy I/O instead of
        // switching to CONNECT or HTTP/1.1.
        let unused_proxy = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        unused_proxy.set_nonblocking(true)?;
        let unused_address = unused_proxy.local_addr()?;
        let client = client_builder(&identity, true)
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .route(Route::http_proxy(
                HttpProxy::new(&format!("https://{unused_address}"))?.with_http2_transport()?,
            ))
            .build()?;
        let error = expect_error(
            client
                .websocket(&format!("ws://{origin_address}/plaintext"))?
                .connect()
                .await,
        )?;
        assert_eq!(error.kind(), WebSocketErrorKind::Proxy);
        assert!(matches!(
            connect_error(&error),
            Some(HttpConnectError::ForwardingRequiresHttp1)
        ));
        assert!(matches!(
            unused_proxy.accept(),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        Ok(())
    })
    .await
}

type OriginTask = tokio::task::JoinHandle<TestResult<websocket_origin::ExtendedConnectRecord>>;

async fn spawn_h2_origin(identity: &TestIdentity) -> TestResult<(SocketAddr, OriginTask)> {
    let (address, listener) = bind().await?;
    let acceptor = identity.acceptor(H2_ALPN)?;
    Ok((
        address,
        tokio::spawn(websocket_origin::serve_h2_echo(listener, acceptor)),
    ))
}

async fn bind() -> TestResult<(SocketAddr, TcpListener)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    Ok((listener.local_addr()?, listener))
}

fn h2_websocket_client(
    origin: &TestIdentity,
    proxy_root: Option<Vec<u8>>,
    route: Route,
) -> TestResult<Client> {
    let mut http2 = chromium::v152_macos_http2();
    http2.extended_connect_pseudo_header_order = Some(vec![
        Http2PseudoHeader::Method,
        Http2PseudoHeader::Protocol,
        Http2PseudoHeader::Authority,
        Http2PseudoHeader::Scheme,
        Http2PseudoHeader::Path,
    ]);
    let profile = ClientProfile::new(tls_settings()).with_http2(http2);
    let mut builder = Client::builder(profile)
        .add_root_certificate_der(origin.root_der.clone())
        .route(route);
    if let Some(root) = proxy_root {
        builder = builder.add_proxy_root_certificate_der(root);
    }
    Ok(builder.build()?)
}

/// Sends `hello`, expects `echo:hello`, and completes the Close handshake.
async fn exchange_echo(mut socket: WebSocket) -> TestResult<()> {
    socket.send(WebSocketMessage::Text("hello".into())).await?;
    assert_eq!(
        socket.receive().await?,
        WebSocketMessage::Text("echo:hello".into())
    );
    let close = WebSocketCloseFrame::new(1000, "done")?;
    socket.close(Some(close.clone())).await?;
    assert_eq!(
        socket.receive().await?,
        WebSocketMessage::Close(Some(close))
    );
    Ok(())
}

fn text_frame(text: &str) -> ClientFrame {
    ClientFrame {
        opcode: 0x1,
        payload: text.as_bytes().to_vec(),
    }
}

fn expect_error<T>(
    result: Result<T, phantom::WebSocketError>,
) -> TestResult<phantom::WebSocketError> {
    match result {
        Ok(_) => Err("WebSocket connection unexpectedly succeeded".into()),
        Err(error) => Ok(error),
    }
}

fn connect_error<'a>(error: &'a (dyn StdError + 'static)) -> Option<&'a HttpConnectError> {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(found) = error.downcast_ref::<HttpConnectError>() {
            return Some(found);
        }
        current = error.source();
    }
    None
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "proxied WebSocket integration test exceeded its deadline")?
}
