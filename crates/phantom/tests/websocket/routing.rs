use super::*;

const SWITCHING_PROTOCOLS: &str = "HTTP/1.1 101 Switching Protocols\r\n\
    Upgrade: websocket\r\n\
    Connection: Upgrade\r\n";

/// Answers a CONNECT on `stream` with 200, then plays the origin: reads the
/// opening inside the tunnel, accepts it, and sends one Ping.
///
/// Returns the CONNECT head, the opening head, and the client's Pong.
async fn tunnel_and_accept<S>(
    stream: &mut S,
    ping: &'static [u8],
) -> TestResult<(Vec<u8>, Vec<u8>, ClientFrame)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let connect = read_head(stream).await?;
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    stream.flush().await?;
    let opening = read_head(stream).await?;
    let key = header_value(&opening, "sec-websocket-key").ok_or("missing key")?;
    let accept = websocket_accept(key);
    let mut response =
        format!("{SWITCHING_PROTOCOLS}Sec-WebSocket-Accept: {accept}\r\n\r\n").into_bytes();
    append_server_frame(&mut response, true, 0x9, ping);
    stream.write_all(&response).await?;
    stream.flush().await?;
    let pong = read_client_frame(stream).await?;
    Ok((connect, opening, pong))
}

/// Answers the opening inside an established tunnel without a Ping.
async fn accept_opening<S>(stream: &mut S) -> TestResult<Vec<u8>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let opening = read_head(stream).await?;
    let key = header_value(&opening, "sec-websocket-key").ok_or("missing key")?;
    let accept = websocket_accept(key);
    stream
        .write_all(
            format!("{SWITCHING_PROTOCOLS}Sec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes(),
        )
        .await?;
    stream.flush().await?;
    Ok(opening)
}

async fn challenge<S>(stream: &mut S, challenge: &[u8]) -> io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    stream
        .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n")
        .await?;
    stream.write_all(challenge).await?;
    stream.write_all(b"Content-Length: 0\r\n\r\n").await?;
    stream.flush().await
}

#[tokio::test]
async fn plaintext_http_proxy_tunnels_ws_and_sends_the_direct_opening_inside() -> TestResult<()> {
    bounded(async {
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = proxy_listener.accept().await?;
            tunnel_and_accept(&mut stream, b"tunneled").await
        });

        let headers = vec![
            WebSocketHeader::authority("host"),
            WebSocketHeader::field(RequestHeader::new("X-First", "one")),
            WebSocketHeader::field(RequestHeader::new("uPgRaDe", "websocket")),
            WebSocketHeader::field(RequestHeader::new("Connection", "Upgrade")),
            WebSocketHeader::key("Sec-WebSocket-Key"),
            WebSocketHeader::field(RequestHeader::new("Sec-WebSocket-Version", "13")),
            WebSocketHeader::field(RequestHeader::new("X-Last", "two")),
        ];
        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(HttpProxy::new(&format!("http://{proxy_address}"))?);
        let client = client_builder(&identity, false).route(route).build()?;
        let mut socket = client
            .websocket(&format!("ws://{origin_address}/events?transport=tunnel"))?
            .headers(headers)
            .connect()
            .await?;
        assert_eq!(
            socket.receive().await?,
            WebSocketMessage::Ping(Bytes::from_static(b"tunneled"))
        );
        drop(socket);

        let (connect, opening, pong) = proxy.await??;
        assert_eq!(
            connect,
            format!("CONNECT {origin_address} HTTP/1.1\r\nHost: {origin_address}\r\n\r\n")
                .as_bytes()
        );
        let key = header_value(&opening, "sec-websocket-key").ok_or("missing key")?;
        assert_eq!(
            opening,
            format!(
                "GET /events?transport=tunnel HTTP/1.1\r\n\
                 host: {origin_address}\r\n\
                 X-First: one\r\n\
                 uPgRaDe: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Key: {key}\r\n\
                 Sec-WebSocket-Version: 13\r\n\
                 X-Last: two\r\n\r\n"
            )
            .as_bytes()
        );
        assert_eq!(
            pong,
            ClientFrame {
                rsv1: false,
                opcode: 0xA,
                payload: b"tunneled".to_vec(),
            }
        );
        assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn verified_https_proxy_tunnels_ws_without_origin_tls() -> TestResult<()> {
    bounded(async {
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;
        let proxy_identity = TestIdentity::generate()?;
        let proxy_acceptor = proxy_identity.acceptor(H1_ALPN)?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let mut stream = accept_tls(proxy_listener, proxy_acceptor).await?;
            tunnel_and_accept(&mut stream, b"secure-tunnel").await
        });

        let unrelated_origin_identity = TestIdentity::generate()?;
        let route = Route::http_proxy(HttpProxy::new(&format!("https://{proxy_address}"))?);
        let client = client_builder(&unrelated_origin_identity, false)
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .route(route)
            .build()?;
        let mut socket = client
            .websocket(&format!("ws://{origin_address}/secure?tunnel=yes"))?
            .connect()
            .await?;
        assert_eq!(
            socket.receive().await?,
            WebSocketMessage::Ping(Bytes::from_static(b"secure-tunnel"))
        );
        drop(socket);

        let (connect, opening, pong) = proxy.await??;
        assert_eq!(
            connect,
            format!("CONNECT {origin_address} HTTP/1.1\r\nHost: {origin_address}\r\n\r\n")
                .as_bytes()
        );
        // The opening arrives as plaintext bytes inside the proxy's TLS
        // session: no second TLS handshake runs for a `ws://` origin.
        let key = header_value(&opening, "sec-websocket-key").ok_or("missing key")?;
        assert_eq!(
            opening,
            format!(
                "GET /secure?tunnel=yes HTTP/1.1\r\n\
                 Host: {origin_address}\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Key: {key}\r\n\
                 Sec-WebSocket-Version: 13\r\n\r\n"
            )
            .as_bytes()
        );
        assert_eq!(pong.opcode, 0xA);
        assert_eq!(pong.payload, b"secure-tunnel");
        assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn https_proxy_basic_challenge_replays_on_the_challenged_connection_before_the_ws_tunnel()
-> TestResult<()> {
    bounded(async {
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;
        let proxy_identity = TestIdentity::generate()?;
        let acceptor = proxy_identity.acceptor(H1_ALPN)?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (anonymous_tcp, _) = proxy_listener.accept().await?;
            let mut anonymous = tls_support::accept_tls_stream(anonymous_tcp, acceptor).await?;
            let anonymous_connect = read_head(&mut anonymous).await?;
            challenge(
                &mut anonymous,
                b"Proxy-Authenticate: Basic realm=https-websocket\r\n",
            )
            .await?;

            // The keep-alive 407 leaves the TLS connection open for the replay.
            let mut authorized = anonymous;
            let authorized_connect = read_head(&mut authorized).await?;
            authorized
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            let opening = accept_opening(&mut authorized).await?;
            let second_connection = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                proxy_listener.accept(),
            )
            .await
            .is_ok();
            Ok::<_, Box<dyn Error + Send + Sync>>((
                anonymous_connect,
                authorized_connect,
                opening,
                second_connection,
            ))
        });

        let unrelated_origin_identity = TestIdentity::generate()?;
        let route = Route::http_proxy(
            HttpProxy::new(&format!("https://{proxy_address}"))?
                .with_basic_auth("alice", "secret")?,
        );
        let socket = client_builder(&unrelated_origin_identity, false)
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .route(route)
            .build()?
            .websocket(&format!("ws://{origin_address}/https-auth"))?
            .connect()
            .await?;
        drop(socket);

        let (anonymous, authorized, opening, second_connection) = proxy.await??;
        assert!(!second_connection);
        let connect_line = format!("CONNECT {origin_address} HTTP/1.1\r\n");
        assert!(anonymous.starts_with(connect_line.as_bytes()));
        assert!(authorized.starts_with(connect_line.as_bytes()));
        assert!(header_value(&anonymous, "proxy-authorization").is_none());
        assert_eq!(
            header_value(&authorized, "proxy-authorization"),
            Some("Basic YWxpY2U6c2VjcmV0")
        );
        assert!(opening.starts_with(b"GET /https-auth HTTP/1.1\r\n"));
        assert!(header_value(&opening, "proxy-authorization").is_none());
        assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn later_websocket_tunnels_send_remembered_proxy_credentials_first() -> TestResult<()> {
    bounded(async {
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut anonymous_stream, _) = proxy_listener.accept().await?;
            let anonymous = read_head(&mut anonymous_stream).await?;
            challenge(
                &mut anonymous_stream,
                b"Proxy-Authenticate: Basic realm=websocket-tunnel\r\n",
            )
            .await?;
            let mut tunnels = Vec::new();
            // The replay reuses the challenged connection; the second tunnel
            // opens its own.
            let mut challenged = Some(anonymous_stream);
            for _ in 0..2 {
                let mut stream = match challenged.take() {
                    Some(stream) => stream,
                    None => proxy_listener.accept().await?.0,
                };
                let connect = read_head(&mut stream).await?;
                stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
                let opening = accept_opening(&mut stream).await?;
                tunnels.push((connect, opening));
            }
            let third = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                proxy_listener.accept(),
            )
            .await;
            Ok::<_, Box<dyn Error + Send + Sync>>((anonymous, tunnels, third.is_err()))
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(
            HttpProxy::new(&format!("http://{proxy_address}"))?
                .with_basic_auth("alice", "secret")?,
        );
        let client = client_builder(&identity, false).route(route).build()?;
        for path in ["first", "second"] {
            let socket = client
                .websocket(&format!("ws://{origin_address}/{path}"))?
                .connect()
                .await?;
            drop(socket);
        }

        let (anonymous, tunnels, no_third_connection) = proxy.await??;
        assert!(header_value(&anonymous, "proxy-authorization").is_none());
        let authorized = format!(
            "CONNECT {origin_address} HTTP/1.1\r\nHost: {origin_address}\r\n\
             Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n"
        );
        for ((connect, opening), path) in tunnels.iter().zip(["first", "second"]) {
            assert_eq!(connect, authorized.as_bytes());
            assert!(opening.starts_with(format!("GET /{path} HTTP/1.1\r\n").as_bytes()));
            assert!(header_value(opening, "proxy-authorization").is_none());
        }
        assert!(no_third_connection);
        assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn proxy_basic_authentication_is_fresh_per_logical_websocket_when_not_remembered()
-> TestResult<()> {
    bounded(async {
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let mut requests = Vec::new();
            for _ in 0..2 {
                let (mut anonymous_stream, _) = proxy_listener.accept().await?;
                let anonymous = read_head(&mut anonymous_stream).await?;
                challenge(
                    &mut anonymous_stream,
                    b"Proxy-Authenticate: Basic realm=websocket-tunnel\r\n",
                )
                .await?;

                // The keep-alive 407 leaves the connection open for the replay.
                let mut authorized_stream = anonymous_stream;
                let authorized = read_head(&mut authorized_stream).await?;
                authorized_stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
                let opening = accept_opening(&mut authorized_stream).await?;
                requests.push((anonymous, authorized, opening));
            }
            Ok::<_, Box<dyn Error + Send + Sync>>(requests)
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(
            HttpProxy::new(&format!("http://{proxy_address}"))?
                .with_basic_auth("alice", "secret")?,
        );
        let client = client_builder(&identity, false)
            .route(route)
            .preemptive_proxy_authentication(false)
            .build()?;
        for path in ["first", "second"] {
            let socket = client
                .websocket(&format!("ws://{origin_address}/{path}"))?
                .connect()
                .await?;
            drop(socket);
        }

        let requests = proxy.await??;
        assert_eq!(requests.len(), 2);
        for (index, (anonymous, authorized, opening)) in requests.iter().enumerate() {
            let path = if index == 0 { "first" } else { "second" };
            assert_eq!(
                anonymous,
                format!("CONNECT {origin_address} HTTP/1.1\r\nHost: {origin_address}\r\n\r\n")
                    .as_bytes()
            );
            assert_eq!(
                authorized,
                format!(
                    "CONNECT {origin_address} HTTP/1.1\r\nHost: {origin_address}\r\n\
                     Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n"
                )
                .as_bytes()
            );
            assert!(opening.starts_with(format!("GET /{path} HTTP/1.1\r\n").as_bytes()));
            assert!(header_value(opening, "proxy-authorization").is_none());
        }
        assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn configured_basic_is_not_preemptively_sent_or_retried_after_an_open_tunnel()
-> TestResult<()> {
    bounded(async {
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = proxy_listener.accept().await?;
            let connect = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            accept_opening(&mut stream).await?;
            let second = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                proxy_listener.accept(),
            )
            .await;
            Ok::<_, Box<dyn Error + Send + Sync>>((connect, second.is_err()))
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(
            HttpProxy::new(&format!("http://{proxy_address}"))?
                .with_basic_auth("alice", "secret")?,
        );
        let socket = client_builder(&identity, false)
            .route(route)
            .build()?
            .websocket(&format!("ws://{origin_address}/immediate"))?
            .connect()
            .await?;
        drop(socket);

        let (connect, had_no_second_proxy_connection) = proxy.await??;
        assert!(connect.starts_with(b"CONNECT "));
        assert!(header_value(&connect, "proxy-authorization").is_none());
        assert!(had_no_second_proxy_connection);
        assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn caller_proxy_authorization_is_rejected_before_proxy_io() -> TestResult<()> {
    let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    origin.set_nonblocking(true)?;
    let origin_address = origin.local_addr()?;
    let proxy = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    proxy.set_nonblocking(true)?;
    let proxy_address = proxy.local_addr()?;
    let identity = TestIdentity::generate()?;
    let route = Route::http_proxy(HttpProxy::new(&format!("http://{proxy_address}"))?);
    let client = client_builder(&identity, false).route(route).build()?;

    let error = match client
        .websocket(&format!("ws://{origin_address}/"))?
        .header(RequestHeader::new(
            "Proxy-Authorization",
            "Basic caller-secret",
        ))
        .connect()
        .await
    {
        Ok(_) => return Err("caller Proxy-Authorization reached the proxy".into()),
        Err(error) => error,
    };

    assert_eq!(error.kind(), WebSocketErrorKind::InvalidRequest);
    assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    assert!(matches!(proxy.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    Ok(())
}

#[tokio::test]
async fn oversized_ws_opening_is_rejected_before_proxy_io() -> TestResult<()> {
    let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    origin.set_nonblocking(true)?;
    let origin_address = origin.local_addr()?;
    let proxy = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    proxy.set_nonblocking(true)?;
    let proxy_address = proxy.local_addr()?;

    // With `Host`, 101 fields: one more than an HTTP/1.1 request may carry.
    let mut headers = vec![
        WebSocketHeader::authority("Host"),
        WebSocketHeader::field(RequestHeader::new("Upgrade", "websocket")),
        WebSocketHeader::field(RequestHeader::new("Connection", "Upgrade")),
        WebSocketHeader::key("Sec-WebSocket-Key"),
        WebSocketHeader::field(RequestHeader::new("Sec-WebSocket-Version", "13")),
    ];
    headers.extend((0..96).map(|_| WebSocketHeader::field(RequestHeader::new("X-Pad", "value"))));

    let identity = TestIdentity::generate()?;
    let route = Route::http_proxy(
        HttpProxy::new(&format!("http://{proxy_address}"))?.with_basic_auth("alice", "secret")?,
    );
    let error = match client_builder(&identity, false)
        .route(route)
        .build()?
        .websocket(&format!("ws://{origin_address}/bounded"))?
        .headers(headers)
        .connect()
        .await
    {
        Ok(_) => return Err("oversized opening reached the proxy".into()),
        Err(error) => error,
    };

    assert_eq!(error.kind(), WebSocketErrorKind::Http1);
    assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    assert!(matches!(proxy.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    Ok(())
}

/// Serves one CONNECT with a 407 carrying `proxy_authenticate`, then reports
/// the CONNECT head and whether no second proxy connection arrived.
async fn challenge_once(
    listener: TcpListener,
    proxy_authenticate: &'static [u8],
) -> TestResult<(Vec<u8>, bool)> {
    let (mut stream, _) = listener.accept().await?;
    let connect = read_head(&mut stream).await?;
    challenge(&mut stream, proxy_authenticate).await?;
    let second =
        tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept()).await;
    Ok((connect, second.is_err()))
}

#[tokio::test]
async fn malformed_proxy_basic_challenge_has_no_direct_fallback() -> TestResult<()> {
    bounded(async {
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(challenge_once(
            proxy_listener,
            b"Proxy-Authenticate: Basic realm=\"unterminated\r\n",
        ));

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(
            HttpProxy::new(&format!("http://{proxy_address}"))?
                .with_basic_auth("alice", "secret")?,
        );
        let error = match client_builder(&identity, false)
            .route(route)
            .build()?
            .websocket(&format!("ws://{origin_address}/malformed"))?
            .connect()
            .await
        {
            Ok(_) => return Err("malformed proxy challenge upgraded WebSocket".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::Proxy);

        let (connect, had_no_second_proxy_connection) = proxy.await??;
        assert!(connect.starts_with(format!("CONNECT {origin_address} HTTP/1.1\r\n").as_bytes()));
        assert!(had_no_second_proxy_connection);
        assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn supported_non_basic_proxy_challenge_is_rejected_without_retry() -> TestResult<()> {
    bounded(async {
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(challenge_once(
            proxy_listener,
            b"Proxy-Authenticate: Digest realm=websocket\r\n",
        ));

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(
            HttpProxy::new(&format!("http://{proxy_address}"))?
                .with_basic_auth("alice", "secret")?,
        );
        let error = match client_builder(&identity, false)
            .route(route)
            .build()?
            .websocket(&format!("ws://{origin_address}/digest"))?
            .connect()
            .await
        {
            Ok(_) => return Err("non-Basic proxy challenge upgraded WebSocket".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::Proxy);

        let (connect, had_no_second_proxy_connection) = proxy.await??;
        assert!(header_value(&connect, "proxy-authorization").is_none());
        assert!(had_no_second_proxy_connection);
        assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn second_proxy_basic_challenge_is_terminal_without_fallback() -> TestResult<()> {
    bounded(async {
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut anonymous_stream, _) = proxy_listener.accept().await?;
            let anonymous = read_head(&mut anonymous_stream).await?;
            challenge(
                &mut anonymous_stream,
                b"Proxy-Authenticate: Basic realm=first-private-realm\r\n",
            )
            .await?;

            let mut authorized_stream = anonymous_stream;
            let authorized = read_head(&mut authorized_stream).await?;
            challenge(
                &mut authorized_stream,
                b"Proxy-Authenticate: Basic realm=second-private-realm\r\n",
            )
            .await?;
            let second = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                proxy_listener.accept(),
            )
            .await;
            Ok::<_, Box<dyn Error + Send + Sync>>((anonymous, authorized, second.is_err()))
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(
            HttpProxy::new(&format!("http://{proxy_address}"))?
                .with_basic_auth("marker-user", "marker-password")?,
        );
        let error = match client_builder(&identity, false)
            .route(route)
            .build()?
            .websocket(&format!("ws://{origin_address}/rejected-twice"))?
            .connect()
            .await
        {
            Ok(_) => return Err("second proxy challenge upgraded WebSocket".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::Proxy);
        let mut diagnostic = format!("{error:?} {error}");
        let mut source = error.source();
        while let Some(current) = source {
            diagnostic.push_str(&current.to_string());
            source = current.source();
        }
        for secret in [
            "marker-user",
            "marker-password",
            "first-private-realm",
            "second-private-realm",
            "bWFya2VyLXVzZXI6bWFya2VyLXBhc3N3b3Jk",
        ] {
            assert!(!diagnostic.contains(secret));
        }

        let (anonymous, authorized, had_no_second_proxy_connection) = proxy.await??;
        assert!(header_value(&anonymous, "proxy-authorization").is_none());
        assert_eq!(
            header_value(&authorized, "proxy-authorization"),
            Some("Basic bWFya2VyLXVzZXI6bWFya2VyLXBhc3N3b3Jk")
        );
        assert!(had_no_second_proxy_connection);
        assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn unauthenticated_407_to_ws_connect_fails_without_retry_or_direct_fallback() -> TestResult<()>
{
    bounded(async {
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(challenge_once(
            proxy_listener,
            b"Proxy-Authenticate: Basic realm=available\r\n",
        ));

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(HttpProxy::new(&format!("http://{proxy_address}"))?);
        let error = match client_builder(&identity, false)
            .route(route)
            .build()?
            .websocket(&format!("ws://{origin_address}/rejected"))?
            .connect()
            .await
        {
            Ok(_) => return Err("rejected proxy tunnel upgraded WebSocket".into()),
            Err(error) => error,
        };
        // A refused CONNECT is a proxy failure, as for `wss://`; no opening
        // was sent, so there is no handshake response to return.
        assert_eq!(error.kind(), WebSocketErrorKind::Proxy);
        assert!(error.into_response().is_none());

        let (connect, had_no_second_proxy_connection) = proxy.await??;
        assert_eq!(
            connect,
            format!("CONNECT {origin_address} HTTP/1.1\r\nHost: {origin_address}\r\n\r\n")
                .as_bytes()
        );
        assert!(had_no_second_proxy_connection);
        assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn origin_rejection_inside_a_ws_tunnel_is_returned_with_its_body() -> TestResult<()> {
    bounded(async {
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = proxy_listener.accept().await?;
            let connect = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            let opening = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\n\r\ndenied")
                .await?;
            stream.flush().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((connect, opening))
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(HttpProxy::new(&format!("http://{proxy_address}"))?);
        let error = match client_builder(&identity, false)
            .route(route)
            .build()?
            .websocket("ws://origin.test:8080/rejected")?
            .connect()
            .await
        {
            Ok(_) => return Err("rejected opening upgraded WebSocket".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::HandshakeRejected);
        let response = error
            .into_response()
            .ok_or("origin rejection omitted HTTP response")?;
        assert_eq!(response.status(), 403);
        assert_eq!(
            http_body_util::BodyExt::collect(response.into_body())
                .await?
                .to_bytes(),
            "denied"
        );

        let (connect, opening) = proxy.await??;
        assert_eq!(
            connect,
            b"CONNECT origin.test:8080 HTTP/1.1\r\nHost: origin.test:8080\r\n\r\n".as_slice()
        );
        assert!(opening.starts_with(b"GET /rejected HTTP/1.1\r\nHost: origin.test:8080\r\n"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn connects_through_http_connect_without_origin_fallback() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let origin = tokio::spawn(async move {
            let mut stream = accept_tls(origin_listener, acceptor).await?;
            let request = read_head(&mut stream).await?;
            let key = header_value(&request, "sec-websocket-key").ok_or("missing key")?;
            let accept = websocket_accept(key);
            stream.write_all(format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            ).as_bytes()).await?;
            let close = read_client_frame(&mut stream).await?;
            append_and_write_server_frame(&mut stream, true, 0x8, &close.payload).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(request)
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(forward_one_connect(proxy_listener, origin_address));
        let route = Route::http_connect(HttpProxy::new(&format!("http://{proxy_address}"))?);
        let client = client_builder(&identity, false).route(route).build()?;
        let mut socket = client
            .websocket(&format!("wss://{origin_address}/through-proxy"))?
            .connect()
            .await?;
        socket.close(Some(WebSocketCloseFrame::new(1000, "done")?)).await?;
        assert!(matches!(socket.receive().await?, WebSocketMessage::Close(_)));
        drop(socket);

        assert_eq!(
            proxy.await??,
            format!("CONNECT {origin_address} HTTP/1.1\r\nHost: {origin_address}\r\n\r\n").as_bytes()
        );
        assert!(origin.await??.starts_with(b"GET /through-proxy HTTP/1.1\r\n"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn basic_proxy_challenge_reconnects_before_websocket_upgrade() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let origin = tokio::spawn(async move {
            let mut stream = accept_tls(origin_listener, acceptor).await?;
            let request = read_head(&mut stream).await?;
            let key = header_value(&request, "sec-websocket-key").ok_or("missing key")?;
            let accept = websocket_accept(key);
            stream.write_all(format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            ).as_bytes()).await?;
            let close = read_client_frame(&mut stream).await?;
            append_and_write_server_frame(&mut stream, true, 0x8, &close.payload).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(request)
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(challenge_then_forward_connect(
            proxy_listener,
            origin_address,
        ));
        let route = Route::http_connect(
            HttpProxy::new(&format!("http://{proxy_address}"))?
                .connect_headers(vec![
                    phantom::HttpConnectHeader::authority("Host"),
                    phantom::HttpConnectHeader::proxy_authorization("Proxy-Authorization"),
                ])
                .with_basic_auth("alice", "secret")?,
        );
        let client = client_builder(&identity, false).route(route).build()?;
        let mut socket = client
            .websocket(&format!("wss://{origin_address}/authenticated-proxy"))?
            .connect()
            .await?;
        socket
            .close(Some(WebSocketCloseFrame::new(1000, "done")?))
            .await?;
        assert!(matches!(
            socket.receive().await?,
            WebSocketMessage::Close(_)
        ));
        drop(socket);

        let (anonymous, authorized) = proxy.await??;
        assert!(!header_value(&anonymous, "proxy-authorization").is_some());
        assert_eq!(
            header_value(&authorized, "proxy-authorization"),
            Some("Basic YWxpY2U6c2VjcmV0")
        );
        let origin_request = origin.await??;
        assert!(origin_request.starts_with(b"GET /authenticated-proxy HTTP/1.1\r\n"));
        assert!(header_value(&origin_request, "proxy-authorization").is_none());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn connects_through_verified_https_proxy() -> TestResult<()> {
    bounded(async {
        let origin_identity = TestIdentity::generate()?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let origin_acceptor = origin_identity.acceptor(H1_ALPN)?;
        let origin = tokio::spawn(async move {
            let mut stream = accept_tls(origin_listener, origin_acceptor).await?;
            let request = read_head(&mut stream).await?;
            let key = header_value(&request, "sec-websocket-key").ok_or("missing key")?;
            let accept = websocket_accept(key);
            stream.write_all(format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            ).as_bytes()).await?;
            let close = read_client_frame(&mut stream).await?;
            append_and_write_server_frame(&mut stream, true, 0x8, &close.payload).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(request)
        });

        let proxy_identity = TestIdentity::generate()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy_acceptor = proxy_identity.acceptor(H1_ALPN)?;
        let proxy = tokio::spawn(forward_one_https_connect(
            proxy_listener,
            proxy_acceptor,
            origin_address,
        ));
        let route = Route::http_connect(HttpProxy::new(&format!("https://{proxy_address}"))?);
        let client = client_builder(&origin_identity, false)
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .route(route)
            .build()?;
        let mut socket = client
            .websocket(&format!("wss://{origin_address}/through-secure-proxy"))?
            .connect()
            .await?;
        socket.close(Some(WebSocketCloseFrame::new(1000, "done")?)).await?;
        assert!(matches!(socket.receive().await?, WebSocketMessage::Close(_)));
        drop(socket);

        assert_eq!(
            proxy.await??,
            format!("CONNECT {origin_address} HTTP/1.1\r\nHost: {origin_address}\r\n\r\n")
                .as_bytes()
        );
        assert!(
            origin
                .await??
                .starts_with(b"GET /through-secure-proxy HTTP/1.1\r\n")
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn rejected_connect_never_opens_a_direct_websocket_connection() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = proxy_listener.accept().await?;
            let request = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, io::Error>(request)
        });
        let route = Route::http_connect(HttpProxy::new(&format!("http://{proxy_address}"))?);
        let client = client_builder(&identity, false).route(route).build()?;
        let error = match client
            .websocket(&format!("wss://{origin_address}/"))?
            .connect()
            .await
        {
            Ok(_) => return Err("rejected proxy WebSocket connection succeeded".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::Proxy);
        assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        assert_eq!(
            proxy.await??,
            format!("CONNECT {origin_address} HTTP/1.1\r\nHost: {origin_address}\r\n\r\n")
                .as_bytes()
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn stream_sink_split_supports_concurrent_message_io() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_tls(listener, acceptor).await?;
            let request = read_head(&mut stream).await?;
            let key = header_value(&request, "sec-websocket-key").ok_or("missing key")?;
            let accept = websocket_accept(key);
            let mut response = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            ).into_bytes();
            append_server_frame(&mut response, true, 0x9, b"split-ping");
            stream.write_all(&response).await?;
            stream.flush().await?;
            let first = read_client_frame(&mut stream).await?;
            let second = read_client_frame(&mut stream).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>([first, second])
        });

        let client = test_client(&identity, false)?;
        let socket = client
            .websocket(&format!("wss://{address}/split"))?
            .connect()
            .await?;
        let (mut sender, mut receiver) = socket.split();
        let (sent, received) = tokio::join!(
            sender.send(WebSocketMessage::Text("outbound".into())),
            receiver.next(),
        );
        sent?;
        assert_eq!(
            received.ok_or("split stream ended before Ping")??,
            WebSocketMessage::Ping(Bytes::from_static(b"split-ping"))
        );
        drop(sender);
        drop(receiver);

        let frames = server.await??;
        assert!(frames.iter().any(|frame| frame.opcode == 0x1 && frame.payload == b"outbound"));
        assert!(frames.iter().any(|frame| frame.opcode == 0xA && frame.payload == b"split-ping"));
        Ok(())
    })
    .await
}

async fn challenge_then_forward_connect(
    listener: TcpListener,
    origin: std::net::SocketAddr,
) -> TestResult<(Vec<u8>, Vec<u8>)> {
    let (mut first, _) = listener.accept().await?;
    let anonymous = read_head(&mut first).await?;
    first
        .write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
              Proxy-Authenticate: Basic realm=\"websocket\"\r\n\
              Content-Length: 0\r\n\r\n",
        )
        .await?;
    first.shutdown().await?;

    let (mut second, _) = listener.accept().await?;
    let authorized = read_head(&mut second).await?;
    let mut upstream = tokio::net::TcpStream::connect(origin).await?;
    second
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    second.flush().await?;
    tokio::io::copy_bidirectional(&mut second, &mut upstream).await?;
    Ok((anonymous, authorized))
}
