//! WebSocket facade integration tests.

use std::{error::Error, io, net::Ipv4Addr, num::NonZeroUsize};

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use phantom::{
    HttpProxy, OrderedResponseHeaders, RequestHeader, Route, WebSocketCloseFrame,
    WebSocketErrorKind, WebSocketHeader, WebSocketLimits, WebSocketMessage,
};
use tokio::{io::AsyncWriteExt, net::TcpListener};
use tracing::instrument::WithSubscriber;

use crate::support::tls as tls_support;
use crate::support::tracing as tracing_support;
use crate::support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup};
use crate::support::websocket as websocket_support;
use tls_support::{
    H1_ALPN, TestIdentity, TestResult, accept_tls, client_builder, read_head, test_client,
};
use tracing_support::OutcomeSubscriber;
use websocket_support::*;

mod adversarial;
#[cfg(feature = "websocket-deflate")]
mod compression;
mod routing;

#[tokio::test]
async fn plaintext_direct_preserves_order_and_upgraded_bytes() -> TestResult<()> {
    let mut server = None;
    let caller = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        server = Some(ConnectionPeer::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let request = read_head(&mut stream).await?;
            let key = header_value(&request, "sec-websocket-key")
                .ok_or("opening handshake omitted Sec-WebSocket-Key")?;
            let accept = websocket_accept(key);
            let mut response = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\r\n"
            )
            .into_bytes();
            append_server_frame(&mut response, true, 0x9, b"plaintext");
            stream.write_all(&response).await?;
            stream.flush().await?;
            let pong = read_client_frame(&mut stream).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((request, pong))
        }));

        let client = test_client(&identity, false)?;
        let mut socket = client
            .websocket(&format!("ws://{address}/events?transport=plain"))?
            .connect()
            .await?;
        assert_eq!(
            socket.receive().await?,
            WebSocketMessage::Ping(Bytes::from_static(b"plaintext"))
        );
        drop(socket);

        let (request, pong) = server
            .as_mut()
            .ok_or("websocket fixture peer was not acquired")?
            .join()
            .await??;
        let authority = address.to_string();
        let key = header_value(&request, "sec-websocket-key").ok_or("missing key")?;
        let expected = format!(
            "GET /events?transport=plain HTTP/1.1\r\n\
             Host: {authority}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        );
        assert_eq!(request, expected.as_bytes());
        assert_eq!(
            pong,
            ClientFrame {
                rsv1: false,
                opcode: 0xA,
                payload: b"plaintext".to_vec(),
            }
        );
        Ok(())
    })
    .await;
    let cleanup = match server.as_mut() {
        Some(peer) => peer.shutdown().await,
        None => Ok(()),
    };
    finish_with_cleanup(caller, cleanup)
}

#[tokio::test]
async fn ordered_handshake_and_bounded_message_lifecycle_survives_refresh() -> TestResult<()> {
    let mut server = None;
    let caller = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        server = Some(ConnectionPeer::spawn(async move {
            let mut stream = accept_tls(listener, acceptor).await?;
            let request = read_head(&mut stream).await?;
            let key = header_value(&request, "sec-websocket-key")
                .ok_or("opening handshake omitted Sec-WebSocket-Key")?;
            let accept = websocket_accept(key);
            let mut response = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: keep-alive, Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\
                 Sec-WebSocket-Protocol: unique-protocol-secret\r\n\
                 X-MiXeD: response\r\n\r\n"
            )
            .into_bytes();
            append_server_frame(&mut response, true, 0x9, b"probe");
            append_server_frame(&mut response, false, 0x1, b"hel");
            append_server_frame(&mut response, true, 0x0, b"lo");
            stream.write_all(&response).await?;
            stream.flush().await?;

            let pong = read_client_frame(&mut stream).await?;
            let binary = read_client_frame(&mut stream).await?;
            append_and_write_server_frame(&mut stream, true, 0x8, &1000_u16.to_be_bytes()).await?;
            let close = read_client_frame(&mut stream).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((request, pong, binary, close))
        }));

        let headers = vec![
            WebSocketHeader::authority("host"),
            WebSocketHeader::field(RequestHeader::new("X-First", "one")),
            WebSocketHeader::field(RequestHeader::new("uPgRaDe", "websocket")),
            WebSocketHeader::field(RequestHeader::new("Connection", "keep-alive, Upgrade")),
            WebSocketHeader::key("Sec-WebSocket-Key"),
            WebSocketHeader::field(RequestHeader::new("Sec-WebSocket-Version", "13")),
            WebSocketHeader::field(RequestHeader::new(
                "Sec-WebSocket-Protocol",
                "unique-protocol-secret, superchat",
            )),
        ];
        let client = test_client(&identity, false)?;
        let mut socket = client
            .websocket(&format!("wss://{address}/events?channel=one"))?
            .headers(headers)
            .connect()
            .await?;

        client.close_idle_connections().await;
        client.refresh_connections().await;

        assert_eq!(socket.selected_protocol(), Some("unique-protocol-secret"));
        assert!(!format!("{socket:?}").contains("unique-protocol-secret"));
        let ordered = socket
            .handshake_response()
            .extensions()
            .get::<OrderedResponseHeaders>()
            .ok_or("101 response omitted ordered fields")?;
        assert_eq!(
            ordered
                .iter()
                .map(|header| header.name())
                .collect::<Vec<_>>(),
            [
                "Upgrade",
                "Connection",
                "Sec-WebSocket-Accept",
                "Sec-WebSocket-Protocol",
                "X-MiXeD",
            ]
        );
        assert_eq!(
            socket.receive().await?,
            WebSocketMessage::Ping(Bytes::from_static(b"probe"))
        );
        assert_eq!(
            socket.receive().await?,
            WebSocketMessage::Text("hello".into())
        );
        socket
            .send(WebSocketMessage::Binary(Bytes::from_static(b"client-data")))
            .await?;
        assert_eq!(
            socket.receive().await?,
            WebSocketMessage::Close(Some(WebSocketCloseFrame::new(1000, "")?))
        );

        let (request, pong, binary, close) = server
            .as_mut()
            .ok_or("websocket fixture peer was not acquired")?
            .join()
            .await??;
        let key = header_value(&request, "sec-websocket-key").ok_or("missing key")?;
        let expected = format!(
            "GET /events?channel=one HTTP/1.1\r\n\
             host: {address}\r\n\
             X-First: one\r\n\
             uPgRaDe: websocket\r\n\
             Connection: keep-alive, Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Protocol: unique-protocol-secret, superchat\r\n\r\n"
        );
        assert_eq!(request, expected.as_bytes());
        assert_eq!(
            pong,
            ClientFrame {
                rsv1: false,
                opcode: 0xA,
                payload: b"probe".to_vec()
            }
        );
        assert_eq!(
            binary,
            ClientFrame {
                rsv1: false,
                opcode: 0x2,
                payload: b"client-data".to_vec()
            }
        );
        assert_eq!(
            close,
            ClientFrame {
                rsv1: false,
                opcode: 0x8,
                payload: 1000_u16.to_be_bytes().to_vec()
            }
        );
        Ok(())
    })
    .await;
    let cleanup = match server.as_mut() {
        Some(peer) => peer.shutdown().await,
        None => Ok(()),
    };
    finish_with_cleanup(caller, cleanup)
}

#[tokio::test]
async fn rejected_handshake_retains_streaming_http_response() -> TestResult<()> {
    let mut server = None;
    let caller = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        server = Some(ConnectionPeer::spawn(async move {
            let mut stream = accept_tls(listener, acceptor).await?;
            read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 401 Unauthorized\r\nX-Reason: unique-response-secret\r\nContent-Length: 6\r\n\r\ndenied")
                .await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }));

        let client = test_client(&identity, false)?;
        let error = match client
            .websocket(&format!("wss://{address}/socket"))?
            .connect()
            .await
        {
            Ok(_) => return Err("rejected opening handshake succeeded".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::HandshakeRejected);
        assert!(!format!("{error:?}").contains("unique-response-secret"));
        let response = error.into_response().ok_or("rejection omitted HTTP response")?;
        assert_eq!(response.status(), 401);
        assert_eq!(http_body_util::BodyExt::collect(response.into_body()).await?.to_bytes(), "denied");
        server.as_mut().ok_or("websocket fixture peer was not acquired")?.join().await??;
        Ok(())
    })
    .await;
    let cleanup = match server.as_mut() {
        Some(peer) => peer.shutdown().await,
        None => Ok(()),
    };
    finish_with_cleanup(caller, cleanup)
}

#[tokio::test]
async fn declared_frame_length_exceeding_bound_is_rejected() -> TestResult<()> {
    let mut server = None;
    let caller = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        server = Some(ConnectionPeer::spawn(async move {
            let mut stream = accept_tls(listener, acceptor).await?;
            let request = read_head(&mut stream).await?;
            let key = header_value(&request, "sec-websocket-key").ok_or("missing key")?;
            let accept = websocket_accept(key);
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await?;
            stream.write_all(&[0x82, 126, 0, 5]).await?;
            stream.flush().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }));

        let limit = NonZeroUsize::new(4).ok_or("nonzero construction failed")?;
        let limits = WebSocketLimits::new(limit, limit)?;
        let client = test_client(&identity, false)?;
        let mut socket = client
            .websocket(&format!("wss://{address}/"))?
            .limits(limits)
            .connect()
            .await?;
        let subscriber = OutcomeSubscriber::default();
        let error = match socket
            .send(WebSocketMessage::Text("12345".into()))
            .with_subscriber(subscriber.dispatch())
            .await
        {
            Ok(()) => return Err("oversized outgoing message succeeded".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::Capacity);
        assert_eq!(subscriber.outcomes_for("websocket.send"), ["error"]);
        assert_eq!(
            subscriber.error_kinds_for("websocket.send"),
            ["Capacity"]
        );
        let error = match socket.receive().await {
            Ok(_) => return Err("oversized declared frame succeeded".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::Capacity);
        server.as_mut().ok_or("websocket fixture peer was not acquired")?.join().await??;
        Ok(())
    })
    .await;
    let cleanup = match server.as_mut() {
        Some(peer) => peer.shutdown().await,
        None => Ok(()),
    };
    finish_with_cleanup(caller, cleanup)
}

#[tokio::test]
async fn invalid_template_and_limits_fail_before_network_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let client = test_client(&identity, false)?;
    assert_eq!(
        WebSocketLimits::default().max_message_fragments().get(),
        128 * 1024
    );
    let debug = format!(
        "{:?}",
        client
            .websocket(&format!("wss://{address}/"))?
            .header(RequestHeader::new("Authorization", "unique-builder-secret",))
    );
    assert!(!debug.contains("unique-builder-secret"));
    let error = match client
        .websocket(&format!("wss://{address}/"))?
        .headers(vec![WebSocketHeader::authority("Host")])
        .connect()
        .await
    {
        Ok(_) => return Err("invalid template touched the network".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), WebSocketErrorKind::InvalidRequest);
    assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));

    let frame = NonZeroUsize::new(2).ok_or("nonzero construction failed")?;
    let message = NonZeroUsize::new(1).ok_or("nonzero construction failed")?;
    let error = match WebSocketLimits::new(frame, message) {
        Ok(_) => return Err("inverted limits succeeded".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), WebSocketErrorKind::Capacity);
    Ok(())
}

#[cfg(feature = "cookies")]
#[tokio::test]
async fn session_injects_and_learns_cookies_at_the_typed_placeholder() -> TestResult<()> {
    let mut server = None;
    let caller = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        server = Some(ConnectionPeer::spawn(async move {
            let mut stream = accept_tls(listener, acceptor).await?;
            let request = read_head(&mut stream).await?;
            let key = header_value(&request, "sec-websocket-key").ok_or("missing key")?;
            let accept = websocket_accept(key);
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 101 Switching Protocols\r\n\
                         Upgrade: websocket\r\n\
                         Connection: Upgrade\r\n\
                         Sec-WebSocket-Accept: {accept}\r\n\
                         Set-Cookie: learned=two; Secure; Path=/\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(request)
        }));

        let session = client_builder(&identity, false).cookies().build()?;
        let origin = format!("https://{address}/");
        session
            .cookie_jar()
            .ok_or("session omitted cookie jar")?
            .set_cookie(&origin, "initial=one; Secure; Path=/")?;
        let socket = session
            .websocket(&format!("wss://{address}/cookies"))?
            .connect()
            .await?;
        drop(socket);

        let request = server
            .as_mut()
            .ok_or("websocket fixture peer was not acquired")?
            .join()
            .await??;
        let cookie_position = request
            .windows(b"Cookie: initial=one\r\n".len())
            .position(|window| window == b"Cookie: initial=one\r\n")
            .ok_or("session cookie was not emitted")?;
        let version_position = request
            .windows(b"Sec-WebSocket-Version: 13\r\n".len())
            .position(|window| window == b"Sec-WebSocket-Version: 13\r\n")
            .ok_or("version field was not emitted")?;
        assert!(cookie_position > version_position);
        let stored = session
            .cookie_jar()
            .ok_or("session omitted cookie jar")?
            .request_value(&origin)?
            .ok_or("learned cookie was not stored")?;
        assert_eq!(stored, "initial=one; learned=two");
        Ok(())
    })
    .await;
    let cleanup = match server.as_mut() {
        Some(peer) => peer.shutdown().await,
        None => Ok(()),
    };
    finish_with_cleanup(caller, cleanup)
}

#[test]
fn io_disabled_runtime_returns_typed_error() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity, false)?;
    let request = client.websocket("wss://127.0.0.1:9/")?;
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let error = match runtime.block_on(request.connect()) {
        Ok(_) => return Err("WebSocket connected without runtime I/O".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), WebSocketErrorKind::RuntimeUnavailable);
    Ok(())
}

#[tokio::test]
async fn caller_failure_collects_the_original_opening_peer() -> TestResult<()> {
    use tokio::{io::AsyncReadExt, net::TcpStream, time::timeout};

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let mut peer = ConnectionPeer::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let request = read_head(&mut stream).await?;
        assert_eq!(request, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        stream
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
            .await?;
        stream.flush().await?;
        stream.read_u8().await?;
        TestResult::Ok(())
    });
    let primary = Box::new(io::Error::new(
        io::ErrorKind::InvalidInput,
        "opening caller failed",
    ));
    let original = primary.as_ref() as *const io::Error;
    let mut client = None;
    let caller = bounded(async {
        client = Some(TcpStream::connect(address).await?);
        let client = client.as_mut().ok_or("opening client was not acquired")?;
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await?;
        assert_eq!(
            read_head(client).await?,
            b"HTTP/1.1 101 Switching Protocols\r\n\r\n"
        );
        Err(primary as Box<dyn Error + Send + Sync>)
    })
    .await;
    let error = finish_with_cleanup(caller, peer.shutdown().await)
        .err()
        .ok_or("opening caller failure was discarded")?;
    let retained = error
        .downcast_ref::<io::Error>()
        .ok_or("original caller cause was lost")?;
    assert_eq!(retained as *const io::Error, original);
    assert_eq!(retained.kind(), io::ErrorKind::InvalidInput);
    assert!(peer.is_finished());
    let client = client.as_mut().ok_or("opening client was not acquired")?;
    let closed = timeout(TEST_TIMEOUT, client.read(&mut [0_u8; 1])).await?;
    assert!(
        matches!(closed, Ok(0))
            || matches!(closed, Err(ref error) if tls_support::is_peer_gone(error))
    );
    assert_eq!(TcpListener::bind(address).await?.local_addr()?, address);
    Ok(())
}

#[tokio::test]
async fn caller_timeout_keeps_elapsed_and_the_original_completed_peer_failure() -> TestResult<()> {
    use crate::support::tunnel_proxy::connection_peer::FixtureFailures;
    use tokio::{
        net::TcpStream,
        time::{advance, pause, resume},
    };

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let cleanup = Box::new(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "opening peer failed",
    ));
    let original = cleanup.as_ref() as *const io::Error;
    let mut peer = ConnectionPeer::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        read_head(&mut stream).await?;
        stream
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
            .await?;
        stream.flush().await?;
        TestResult::<()>::Err(cleanup)
    });
    let setup = bounded(async {
        let mut client = TcpStream::connect(address).await?;
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await?;
        read_head(&mut client).await?;
        while !peer.is_finished() {
            tokio::task::yield_now().await;
        }
        Ok(())
    })
    .await;
    if let Err(error) = setup {
        return finish_with_cleanup(Err(error), peer.shutdown().await);
    }

    pause();
    let caller = bounded(std::future::pending::<TestResult<()>>());
    tokio::pin!(caller);
    assert!(futures_util::poll!(&mut caller).is_pending());
    advance(TEST_TIMEOUT).await;
    let caller = caller.await;
    resume();
    let error = finish_with_cleanup(caller, peer.shutdown().await)
        .err()
        .ok_or("opening caller and peer failures were discarded")?;
    let causes = error
        .downcast_ref::<FixtureFailures>()
        .ok_or("compound causes were lost")?;
    assert!(
        causes
            .primary
            .source()
            .is_some_and(|source| source.is::<tokio::time::error::Elapsed>())
    );
    let retained = causes
        .cleanup
        .downcast_ref::<io::Error>()
        .ok_or("original peer cause was lost")?;
    assert_eq!(retained as *const io::Error, original);
    assert_eq!(retained.kind(), io::ErrorKind::PermissionDenied);
    assert!(peer.is_finished());
    Ok(())
}

mod socks_retention;
