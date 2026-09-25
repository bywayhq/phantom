//! Public remote-DNS SOCKS5 route integration tests.

#[path = "socks5/auth.rs"]
mod auth;
#[path = "support/socks5.rs"]
mod socks5_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls;

use std::{future::Future, io, net::Ipv4Addr, time::Duration};

use http::Response;
use http_body_util::BodyExt;
use phantom::{HttpProtocol, RequestErrorKind, RequestHeader, Route, Socks5Proxy};
#[cfg(feature = "websocket")]
use phantom::{WebSocketErrorKind, WebSocketMessage};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

use socks5_support::{ObservedSocks5Connect, forward_one_socks5, reject_one_socks5};
use tls::{H1_ALPN, H2_ALPN, TestIdentity, TestResult, accept_tls, client_builder, read_head};

const ORIGIN_NAME: &str = "origin.phantom.test";
const UNICODE_ORIGIN_NAME: &str = "bücher.example";
const ASCII_ORIGIN_NAME: &str = "xn--bcher-kva.example";
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn http1_canonicalizes_unicode_before_proxy_owned_dns() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ASCII_ORIGIN_NAME)?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let origin = tokio::spawn(async move {
            let mut stream = accept_tls(origin_listener, acceptor).await?;
            let request = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nthrough")
                .await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(request)
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(forward_one_socks5(proxy_listener, origin_address));
        let route = Route::socks5(Socks5Proxy::new(&format!("socks5h://{proxy_address}"))?);
        let client = client_builder(&identity, false).route(route).build()?;

        let response = client
            .get(
                HttpProtocol::Http1,
                &format!(
                    "https://{UNICODE_ORIGIN_NAME}:{}/proxied",
                    origin_address.port()
                ),
            )?
            .header(RequestHeader::new("X-Origin", "only"))
            .send()
            .await?;
        assert_eq!(response.status(), 200);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "through");
        drop(client);

        let request = origin.await??;
        assert_eq!(
            request,
            format!(
                "GET /proxied HTTP/1.1\r\nHost: {ASCII_ORIGIN_NAME}:{}\r\nX-Origin: only\r\n\r\n",
                origin_address.port()
            )
            .as_bytes()
        );
        assert_eq!(
            proxy.await??,
            ObservedSocks5Connect {
                host: ASCII_ORIGIN_NAME.to_owned(),
                port: origin_address.port(),
            }
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn session_reuses_one_http2_connection_and_socks5_tunnel() -> TestResult<()> {
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
        let route = Route::socks5(Socks5Proxy::new(&format!("socks5h://{proxy_address}"))?);
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
        assert_eq!(
            proxy.await??,
            ObservedSocks5Connect {
                host: ORIGIN_NAME.to_owned(),
                port: origin_address.port(),
            }
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn rejection_never_opens_a_direct_origin_connection() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN_NAME)?;
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(reject_one_socks5(proxy_listener, 5));
        let route = Route::socks5(Socks5Proxy::new(&format!("socks5h://{proxy_address}"))?);
        let client = client_builder(&identity, false).route(route).build()?;

        let error = match client
            .get(
                HttpProtocol::Http1,
                &format!("https://{ORIGIN_NAME}:{}/", origin_address.port()),
            )?
            .send()
            .await
        {
            Ok(_) => return Err("rejected SOCKS5 request succeeded".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        assert!(matches!(
            origin.accept(),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        assert_eq!(
            proxy.await??,
            ObservedSocks5Connect {
                host: ORIGIN_NAME.to_owned(),
                port: origin_address.port(),
            }
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn invalid_origin_field_fails_before_socks5_io() -> TestResult<()> {
    let identity = TestIdentity::generate_for_dns(ORIGIN_NAME)?;
    let proxy = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    proxy.set_nonblocking(true)?;
    let proxy_address = proxy.local_addr()?;
    let route = Route::socks5(Socks5Proxy::new(&format!("socks5h://{proxy_address}"))?);
    let client = client_builder(&identity, false).route(route).build()?;

    let error = match client
        .get(HttpProtocol::Http1, &format!("https://{ORIGIN_NAME}/"))?
        .header(RequestHeader::new("Bad Header", "invalid"))
        .send()
        .await
    {
        Ok(_) => return Err("invalid origin field touched the SOCKS5 proxy".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::Http1);
    assert!(matches!(
        proxy.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    Ok(())
}

#[test]
fn io_disabled_runtime_returns_typed_error() -> TestResult<()> {
    let identity = TestIdentity::generate_for_dns(ORIGIN_NAME)?;
    let route = Route::socks5(Socks5Proxy::new("socks5h://127.0.0.1:9")?);
    let client = client_builder(&identity, false).route(route).build()?;
    let request = client
        .get(HttpProtocol::Http1, &format!("https://{ORIGIN_NAME}/"))?
        .send();
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let error = match runtime.block_on(request) {
        Ok(_) => return Err("SOCKS5 request completed without runtime I/O".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::RuntimeUnavailable);
    Ok(())
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn plaintext_websocket_canonicalizes_host_through_remote_dns() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ASCII_ORIGIN_NAME)?;
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
            response.extend_from_slice(&[0x81, 6]);
            response.extend_from_slice(b"remote");
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
        let proxy = tokio::spawn(forward_one_socks5(proxy_listener, origin_address));
        let route = Route::socks5(Socks5Proxy::new(&format!("socks5h://{proxy_address}"))?);
        let client = client_builder(&identity, false).route(route).build()?;
        let mut socket = client
            .websocket(&format!(
                "ws://{UNICODE_ORIGIN_NAME}:{}/plain",
                origin_address.port()
            ))?
            .connect()
            .await?;
        assert_eq!(
            socket.receive().await?,
            WebSocketMessage::Text("remote".into())
        );
        drop(socket);
        drop(client);

        let request = origin.await??;
        assert!(request.starts_with(b"GET /plain HTTP/1.1\r\n"));
        assert_eq!(header_value(&request, "upgrade"), Some("websocket"));
        assert_eq!(header_value(&request, "connection"), Some("Upgrade"));
        let authority = format!("{ASCII_ORIGIN_NAME}:{}", origin_address.port());
        assert_eq!(header_value(&request, "host"), Some(authority.as_str()));
        assert_eq!(
            proxy.await??,
            ObservedSocks5Connect {
                host: ASCII_ORIGIN_NAME.to_owned(),
                port: origin_address.port(),
            }
        );
        Ok(())
    })
    .await
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn rejected_plaintext_websocket_never_falls_back_direct() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN_NAME)?;
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(reject_one_socks5(proxy_listener, 5));
        let route = Route::socks5(Socks5Proxy::new(&format!("socks5h://{proxy_address}"))?);
        let client = client_builder(&identity, false).route(route).build()?;

        let error = match client
            .websocket(&format!(
                "ws://{ORIGIN_NAME}:{}/rejected",
                origin_address.port()
            ))?
            .connect()
            .await
        {
            Ok(_) => return Err("rejected SOCKS5 WebSocket succeeded".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::Proxy);
        assert!(matches!(
            origin.accept(),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        assert_eq!(
            proxy.await??,
            ObservedSocks5Connect {
                host: ORIGIN_NAME.to_owned(),
                port: origin_address.port(),
            }
        );
        Ok(())
    })
    .await
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn invalid_plaintext_websocket_field_fails_before_socks5_io() -> TestResult<()> {
    let identity = TestIdentity::generate_for_dns(ORIGIN_NAME)?;
    let proxy = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    proxy.set_nonblocking(true)?;
    let proxy_address = proxy.local_addr()?;
    let route = Route::socks5(Socks5Proxy::new(&format!("socks5h://{proxy_address}"))?);
    let client = client_builder(&identity, false).route(route).build()?;

    let error = match client
        .websocket(&format!("ws://{ORIGIN_NAME}/"))?
        .header(RequestHeader::new("Bad Header", "invalid"))
        .connect()
        .await
    {
        Ok(_) => return Err("invalid WebSocket field touched the SOCKS5 proxy".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), WebSocketErrorKind::Http1);
    assert!(matches!(
        proxy.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    Ok(())
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn websocket_canonicalizes_host_on_the_same_remote_dns_route() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ASCII_ORIGIN_NAME)?;
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
        let route = Route::socks5(Socks5Proxy::new(&format!("socks5h://{proxy_address}"))?);
        let client = client_builder(&identity, false).route(route).build()?;
        let socket = client
            .websocket(&format!(
                "wss://{UNICODE_ORIGIN_NAME}:{}/events",
                origin_address.port()
            ))?
            .connect()
            .await?;
        drop(socket);
        drop(client);

        let request = origin.await??;
        assert!(request.starts_with(b"GET /events HTTP/1.1\r\n"));
        let authority = format!("{ASCII_ORIGIN_NAME}:{}", origin_address.port());
        assert_eq!(header_value(&request, "host"), Some(authority.as_str()));
        assert_eq!(
            proxy.await??,
            ObservedSocks5Connect {
                host: ASCII_ORIGIN_NAME.to_owned(),
                port: origin_address.port(),
            }
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn plaintext_http1_uses_the_remote_dns_tunnel() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN_NAME)?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let origin = tokio::spawn(async move {
            let (mut stream, _) = origin_listener.accept().await?;
            let request = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nplain")
                .await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(request)
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(forward_one_socks5(proxy_listener, origin_address));
        let route = Route::socks5(Socks5Proxy::new(&format!("socks5h://{proxy_address}"))?);
        let client = client_builder(&identity, false).route(route).build()?;

        let response = client
            .get(
                HttpProtocol::Http1,
                &format!("http://{ORIGIN_NAME}:{}/plain", origin_address.port()),
            )?
            .send()
            .await?;
        assert_eq!(response.status(), 200);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "plain");
        drop(client);

        // The origin reads the request head in the clear: no TLS ran.
        assert_eq!(
            origin.await??,
            format!(
                "GET /plain HTTP/1.1\r\nHost: {ORIGIN_NAME}:{}\r\n\r\n",
                origin_address.port()
            )
            .as_bytes()
        );
        assert_eq!(
            proxy.await??,
            ObservedSocks5Connect {
                host: ORIGIN_NAME.to_owned(),
                port: origin_address.port(),
            }
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn negotiated_plaintext_http1_uses_the_remote_dns_tunnel() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN_NAME)?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let origin = tokio::spawn(async move {
            let (mut stream, _) = origin_listener.accept().await?;
            let request = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nplain")
                .await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(request)
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(forward_one_socks5(proxy_listener, origin_address));
        let route = Route::socks5(Socks5Proxy::new(&format!("socks5h://{proxy_address}"))?);
        let client = client_builder(&identity, true).route(route).build()?;

        let response = client
            .get_negotiated(&format!(
                "http://{ORIGIN_NAME}:{}/negotiated",
                origin_address.port()
            ))?
            .send()
            .await?;
        assert_eq!(response.status(), 200);
        let protocol = response
            .extensions()
            .get::<phantom::ResponseInfo>()
            .map(phantom::ResponseInfo::protocol);
        assert_eq!(protocol, Some(HttpProtocol::Http1));
        assert_eq!(response.into_body().collect().await?.to_bytes(), "plain");
        drop(client);

        assert_eq!(
            origin.await??,
            format!(
                "GET /negotiated HTTP/1.1\r\nHost: {ORIGIN_NAME}:{}\r\n\r\n",
                origin_address.port()
            )
            .as_bytes()
        );
        assert_eq!(
            proxy.await??,
            ObservedSocks5Connect {
                host: ORIGIN_NAME.to_owned(),
                port: origin_address.port(),
            }
        );
        Ok(())
    })
    .await
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
        .map_err(|_| "SOCKS5 integration test exceeded its deadline")?
}
