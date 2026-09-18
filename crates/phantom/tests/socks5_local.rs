//! Public local-DNS SOCKS5 route integration tests.

#[path = "support/socks5.rs"]
#[allow(dead_code)]
mod socks5_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls;

use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use http::Response;
use http_body_util::BodyExt;
#[cfg(feature = "websocket")]
use phantom::WebSocketMessage;
use phantom::{HttpProtocol, RequestHeader, Route, Socks5Proxy};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

use socks5_support::{
    ObservedSocks5Authentication, ObservedSocks5Connect, forward_one_authenticated_socks5,
    forward_one_socks5,
};
use tls::{H1_ALPN, H2_ALPN, TestIdentity, TestResult, accept_tls, client_builder, read_head};

const ORIGIN_NAME: &str = "localhost";
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn authenticated_http1_sends_a_locally_resolved_ip() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN_NAME)?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let origin = tokio::spawn(async move {
            let mut stream = accept_tls(origin_listener, acceptor).await?;
            let request = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nauth")
                .await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(request)
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(forward_one_authenticated_socks5(
            proxy_listener,
            origin_address,
        ));
        let route = Route::socks5(
            Socks5Proxy::new(&format!("socks5://{proxy_address}"))?
                .with_username_password("local-user", "local-password")?,
        );
        let client = client_builder(&identity, false).route(route).build()?;

        let response = client
            .get(
                HttpProtocol::Http1,
                &format!(
                    "https://{ORIGIN_NAME}:{}/authenticated",
                    origin_address.port()
                ),
            )?
            .send()
            .await?;
        assert_eq!(response.status(), 200);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "auth");
        drop(client);

        assert!(
            origin
                .await??
                .starts_with(b"GET /authenticated HTTP/1.1\r\n")
        );
        let observed = proxy.await??;
        assert_eq!(
            observed.authentication,
            ObservedSocks5Authentication {
                username: "local-user".to_owned(),
                password: "local-password".to_owned(),
            }
        );
        assert_local_target(observed.connect, origin_address.port())?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http1_sends_a_locally_resolved_ip_to_the_proxy() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN_NAME)?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let origin = tokio::spawn(async move {
            let mut stream = accept_tls(origin_listener, acceptor).await?;
            let request = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nlocal")
                .await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(request)
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(forward_one_socks5(proxy_listener, origin_address));
        let route = Route::socks5(Socks5Proxy::new(&format!("socks5://{proxy_address}"))?);
        let client = client_builder(&identity, false).route(route).build()?;

        let response = client
            .get(
                HttpProtocol::Http1,
                &format!("https://{ORIGIN_NAME}:{}/local", origin_address.port()),
            )?
            .header(RequestHeader::new("X-Origin", "local"))
            .send()
            .await?;
        assert_eq!(response.status(), 200);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "local");
        drop(client);

        assert_eq!(
            origin.await??,
            format!(
                "GET /local HTTP/1.1\r\nHost: {ORIGIN_NAME}:{}\r\nX-Origin: local\r\n\r\n",
                origin_address.port()
            )
            .as_bytes()
        );
        assert_local_target(proxy.await??, origin_address.port())?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn session_reuses_one_http2_connection_and_local_dns_tunnel() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN_NAME)?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let origin = tokio::spawn(async move {
            let stream = accept_tls(origin_listener, acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let mut observed = Vec::new();
            for _ in 0..2 {
                let (request, mut respond) = connection
                    .accept()
                    .await
                    .ok_or("connection closed before expected request")??;
                observed.push((
                    respond.stream_id().as_u32(),
                    request.uri().path().to_owned(),
                ));
                respond.send_response(Response::builder().status(204).body(())?, true)?;
            }
            std::future::poll_fn(|context| connection.poll_closed(context)).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(observed)
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(forward_one_socks5(proxy_listener, origin_address));
        let route = Route::socks5(Socks5Proxy::new(&format!("socks5://{proxy_address}"))?);
        let session = client_builder(&identity, true)
            .route(route)
            .build()?
            .session();

        for path in ["/first", "/second"] {
            let response = session
                .get(
                    HttpProtocol::Http2,
                    &format!("https://{ORIGIN_NAME}:{}{path}", origin_address.port()),
                )?
                .send()
                .await?;
            assert_eq!(response.status(), 204);
            response.into_body().collect().await?;
        }
        drop(session);

        assert_eq!(
            origin.await??,
            [(1, "/first".to_owned()), (3, "/second".to_owned())]
        );
        assert_local_target(proxy.await??, origin_address.port())?;
        Ok(())
    })
    .await
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn authenticated_plaintext_websocket_uses_local_dns_route() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN_NAME)?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let origin = tokio::spawn(async move {
            let (mut stream, _) = origin_listener.accept().await?;
            let request = read_head(&mut stream).await?;
            let key = header_value(&request, "sec-websocket-key").ok_or("missing key")?;
            let accept = websocket_accept(key);
            let mut response = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\r\n"
            )
            .into_bytes();
            response.extend_from_slice(&[0x81, 5]);
            response.extend_from_slice(b"local");
            stream.write_all(&response).await?;
            stream.flush().await?;
            let mut byte = [0_u8; 1];
            let read = tokio::io::AsyncReadExt::read(&mut stream, &mut byte).await?;
            if read != 0 {
                return Err("WebSocket sent unexpected data before drop".into());
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(request)
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(forward_one_authenticated_socks5(
            proxy_listener,
            origin_address,
        ));
        let route = Route::socks5(
            Socks5Proxy::new(&format!("socks5://{proxy_address}"))?
                .with_username_password("ws-user", "ws-password")?,
        );
        let client = client_builder(&identity, false).route(route).build()?;
        let mut socket = client
            .websocket(&format!(
                "ws://{ORIGIN_NAME}:{}/plain",
                origin_address.port()
            ))?
            .connect()
            .await?;
        assert_eq!(
            socket.receive().await?,
            WebSocketMessage::Text("local".into())
        );
        drop(socket);
        drop(client);

        let request = origin.await??;
        assert!(request.starts_with(b"GET /plain HTTP/1.1\r\n"));
        assert_eq!(header_value(&request, "upgrade"), Some("websocket"));
        assert_eq!(header_value(&request, "connection"), Some("Upgrade"));
        let authority = format!("{ORIGIN_NAME}:{}", origin_address.port());
        assert_eq!(header_value(&request, "host"), Some(authority.as_str()));
        let observed = proxy.await??;
        assert_eq!(
            observed.authentication,
            ObservedSocks5Authentication {
                username: "ws-user".to_owned(),
                password: "ws-password".to_owned(),
            }
        );
        assert_local_target(observed.connect, origin_address.port())?;
        Ok(())
    })
    .await
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn websocket_uses_the_same_local_dns_route() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN_NAME)?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let origin = tokio::spawn(async move {
            let mut stream = accept_tls(origin_listener, acceptor).await?;
            let request = read_head(&mut stream).await?;
            let key = header_value(&request, "sec-websocket-key").ok_or("missing key")?;
            let accept = websocket_accept(key);
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 101 Switching Protocols\r\n\
                         Upgrade: websocket\r\n\
                         Connection: Upgrade\r\n\
                         Sec-WebSocket-Accept: {accept}\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await?;
            stream.flush().await?;
            let mut byte = [0_u8; 1];
            let read = tokio::io::AsyncReadExt::read(&mut stream, &mut byte).await?;
            if read != 0 {
                return Err("WebSocket sent unexpected data before drop".into());
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(request)
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(forward_one_socks5(proxy_listener, origin_address));
        let route = Route::socks5(Socks5Proxy::new(&format!("socks5://{proxy_address}"))?);
        let client = client_builder(&identity, false).route(route).build()?;
        let socket = client
            .websocket(&format!(
                "wss://{ORIGIN_NAME}:{}/events",
                origin_address.port()
            ))?
            .connect()
            .await?;
        drop(socket);
        drop(client);

        assert!(origin.await??.starts_with(b"GET /events HTTP/1.1\r\n"));
        assert_local_target(proxy.await??, origin_address.port())?;
        Ok(())
    })
    .await
}

fn assert_local_target(target: ObservedSocks5Connect, port: u16) -> TestResult<()> {
    let address = target.host.parse::<IpAddr>()?;
    if !address.is_loopback() {
        return Err(format!("local DNS returned non-loopback address {address}").into());
    }
    assert_eq!(target.port, port);
    Ok(())
}

#[cfg(feature = "websocket")]
fn header_value<'a>(head: &'a [u8], name: &str) -> Option<&'a str> {
    let text = std::str::from_utf8(head).ok()?;
    text.split("\r\n").skip(1).find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        candidate.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

#[cfg(feature = "websocket")]
fn websocket_accept(key: &str) -> String {
    let mut input = Vec::with_capacity(key.len() + 36);
    input.extend_from_slice(key.as_bytes());
    input.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    btls::base64::encode_block(&btls::sha::sha1(&input))
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "local-DNS SOCKS5 integration test exceeded its deadline")?
}
