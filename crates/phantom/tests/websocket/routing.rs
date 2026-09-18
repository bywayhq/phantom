use super::*;

#[tokio::test]
async fn plaintext_forward_proxy_preserves_absolute_target_fields_and_upgraded_bytes()
-> TestResult<()> {
    bounded(async {
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = proxy_listener.accept().await?;
            let request = read_head(&mut stream).await?;
            let key = header_value(&request, "sec-websocket-key").ok_or("missing key")?;
            let accept = websocket_accept(key);
            let mut response = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            )
            .into_bytes();
            append_server_frame(&mut response, true, 0x9, b"forwarded");
            stream.write_all(&response).await?;
            stream.flush().await?;
            let pong = read_client_frame(&mut stream).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((request, pong))
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
            .websocket(&format!(
                "ws://{origin_address}/events?transport=forward"
            ))?
            .headers(headers)
            .connect()
            .await?;
        assert_eq!(
            socket.receive().await?,
            WebSocketMessage::Ping(Bytes::from_static(b"forwarded"))
        );
        drop(socket);

        let (request, pong) = proxy.await??;
        let key = header_value(&request, "sec-websocket-key").ok_or("missing key")?;
        assert_eq!(
            request,
            format!(
                "GET http://{origin_address}/events?transport=forward HTTP/1.1\r\n\
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
                payload: b"forwarded".to_vec(),
            }
        );
        assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn verified_https_forward_proxy_uses_absolute_form_without_connect() -> TestResult<()> {
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
            let request = read_head(&mut stream).await?;
            let key = header_value(&request, "sec-websocket-key").ok_or("missing key")?;
            let accept = websocket_accept(key);
            let mut response = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            )
            .into_bytes();
            append_server_frame(&mut response, true, 0x9, b"secure-forward");
            stream.write_all(&response).await?;
            stream.flush().await?;
            let pong = read_client_frame(&mut stream).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((request, pong))
        });

        let unrelated_origin_identity = TestIdentity::generate()?;
        let route = Route::http_proxy(HttpProxy::new(&format!("https://{proxy_address}"))?);
        let client = client_builder(&unrelated_origin_identity, false)
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .route(route)
            .build()?;
        let mut socket = client
            .websocket(&format!("ws://{origin_address}/secure?forward=yes"))?
            .connect()
            .await?;
        assert_eq!(
            socket.receive().await?,
            WebSocketMessage::Ping(Bytes::from_static(b"secure-forward"))
        );
        drop(socket);

        let (request, pong) = proxy.await??;
        let key = header_value(&request, "sec-websocket-key").ok_or("missing key")?;
        assert_eq!(
            request,
            format!(
                "GET http://{origin_address}/secure?forward=yes HTTP/1.1\r\n\
                 Host: {origin_address}\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Key: {key}\r\n\
                 Sec-WebSocket-Version: 13\r\n\r\n"
            )
            .as_bytes()
        );
        assert_eq!(pong.opcode, 0xA);
        assert_eq!(pong.payload, b"secure-forward");
        assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn https_forward_basic_challenge_retries_on_a_fresh_verified_tls_connection() -> TestResult<()>
{
    bounded(async {
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;
        let proxy_identity = TestIdentity::generate()?;
        let anonymous_acceptor = proxy_identity.acceptor(H1_ALPN)?;
        let authorized_acceptor = proxy_identity.acceptor(H1_ALPN)?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (anonymous_tcp, _) = proxy_listener.accept().await?;
            let mut anonymous =
                tls_support::accept_tls_stream(anonymous_tcp, anonymous_acceptor).await?;
            let anonymous_alpn = anonymous
                .ssl()
                .selected_alpn_protocol()
                .map(<[u8]>::to_vec);
            let anonymous_head = read_head(&mut anonymous).await?;
            anonymous
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=https-websocket\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await?;

            let (authorized_tcp, _) = proxy_listener.accept().await?;
            let mut authorized =
                tls_support::accept_tls_stream(authorized_tcp, authorized_acceptor).await?;
            let authorized_alpn = authorized
                .ssl()
                .selected_alpn_protocol()
                .map(<[u8]>::to_vec);
            let authorized_head = read_head(&mut authorized).await?;
            let key = header_value(&authorized_head, "sec-websocket-key").ok_or("missing key")?;
            let accept = websocket_accept(key);
            authorized
                .write_all(
                    format!(
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await?;
            authorized.flush().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((
                anonymous_alpn,
                anonymous_head,
                authorized_alpn,
                authorized_head,
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

        let (anonymous_alpn, anonymous, authorized_alpn, authorized) = proxy.await??;
        assert_eq!(anonymous_alpn.as_deref(), Some(b"http/1.1".as_slice()));
        assert_eq!(authorized_alpn.as_deref(), Some(b"http/1.1".as_slice()));
        assert!(anonymous.starts_with(
            format!("GET http://{origin_address}/https-auth HTTP/1.1\r\n").as_bytes()
        ));
        assert!(authorized.starts_with(
            format!("GET http://{origin_address}/https-auth HTTP/1.1\r\n").as_bytes()
        ));
        assert!(header_value(&anonymous, "proxy-authorization").is_none());
        assert_eq!(
            header_value(&authorized, "proxy-authorization"),
            Some("Basic YWxpY2U6c2VjcmV0")
        );
        assert_eq!(
            header_value(&anonymous, "sec-websocket-key"),
            header_value(&authorized, "sec-websocket-key")
        );
        assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn forward_basic_authentication_is_fresh_per_logical_websocket() -> TestResult<()> {
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
                anonymous_stream
                    .write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                          Proxy-Authenticate: Basic realm=websocket-forward\r\n\
                          Content-Length: 0\r\n\r\n",
                    )
                    .await?;

                // Keep the challenged transport alive while accepting the retry,
                // proving authentication opens a fresh proxy connection.
                let (mut authorized_stream, _) = proxy_listener.accept().await?;
                let authorized = read_head(&mut authorized_stream).await?;
                let key = header_value(&authorized, "sec-websocket-key").ok_or("missing key")?;
                let accept = websocket_accept(key);
                authorized_stream
                    .write_all(
                        format!(
                            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await?;
                authorized_stream.flush().await?;
                requests.push((anonymous, authorized));
            }
            Ok::<_, Box<dyn Error + Send + Sync>>(requests)
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

        let requests = proxy.await??;
        assert_eq!(requests.len(), 2);
        for (index, (anonymous, authorized)) in requests.iter().enumerate() {
            let path = if index == 0 { "first" } else { "second" };
            assert!(anonymous.starts_with(
                format!("GET http://{origin_address}/{path} HTTP/1.1\r\n").as_bytes()
            ));
            assert!(authorized.starts_with(
                format!("GET http://{origin_address}/{path} HTTP/1.1\r\n").as_bytes()
            ));
            assert!(header_value(anonymous, "proxy-authorization").is_none());
            assert_eq!(
                header_value(authorized, "proxy-authorization"),
                Some("Basic YWxpY2U6c2VjcmV0")
            );
            assert_eq!(
                header_value(anonymous, "sec-websocket-key"),
                header_value(authorized, "sec-websocket-key")
            );
            assert!(authorized.ends_with(
                b"Sec-WebSocket-Version: 13\r\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n"
            ));
        }
        assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn configured_basic_is_not_preemptively_sent_or_retried_after_immediate_upgrade()
-> TestResult<()> {
    bounded(async {
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = proxy_listener.accept().await?;
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
            let second = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                proxy_listener.accept(),
            )
            .await;
            Ok::<_, Box<dyn Error + Send + Sync>>((request, second.is_err()))
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

        let (request, had_no_second_proxy_connection) = proxy.await??;
        assert!(header_value(&request, "proxy-authorization").is_none());
        assert!(had_no_second_proxy_connection);
        assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn caller_proxy_authorization_is_rejected_before_forward_proxy_io() -> TestResult<()> {
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
        Ok(_) => return Err("caller Proxy-Authorization reached the forward proxy".into()),
        Err(error) => error,
    };

    assert_eq!(error.kind(), WebSocketErrorKind::InvalidRequest);
    assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    assert!(matches!(proxy.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    Ok(())
}

#[tokio::test]
async fn authenticated_forward_headers_are_bounded_before_proxy_io() -> TestResult<()> {
    let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    origin.set_nonblocking(true)?;
    let origin_address = origin.local_addr()?;
    let proxy = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    proxy.set_nonblocking(true)?;
    let proxy_address = proxy.local_addr()?;

    let mut headers = vec![
        WebSocketHeader::authority("Host"),
        WebSocketHeader::field(RequestHeader::new("Upgrade", "websocket")),
        WebSocketHeader::field(RequestHeader::new("Connection", "Upgrade")),
        WebSocketHeader::key("Sec-WebSocket-Key"),
        WebSocketHeader::field(RequestHeader::new("Sec-WebSocket-Version", "13")),
    ];
    headers.extend((0..95).map(|_| WebSocketHeader::field(RequestHeader::new("X-Pad", "value"))));

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
        Ok(_) => return Err("oversized authenticated handshake reached the proxy".into()),
        Err(error) => error,
    };

    assert_eq!(error.kind(), WebSocketErrorKind::Http1);
    assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    assert!(matches!(proxy.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    Ok(())
}

#[tokio::test]
async fn malformed_forward_basic_challenge_has_no_direct_fallback() -> TestResult<()> {
    bounded(async {
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = proxy_listener.accept().await?;
            let request = read_head(&mut stream).await?;
            stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=\"unterminated\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await?;
            let second = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                proxy_listener.accept(),
            )
            .await;
            Ok::<_, Box<dyn Error + Send + Sync>>((request, second.is_err()))
        });

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

        let (request, had_no_second_proxy_connection) = proxy.await??;
        assert!(
            request.starts_with(
                format!("GET http://{origin_address}/malformed HTTP/1.1\r\n").as_bytes()
            )
        );
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
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = proxy_listener.accept().await?;
            let request = read_head(&mut stream).await?;
            stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Digest realm=websocket\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await?;
            let second = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                proxy_listener.accept(),
            )
            .await;
            Ok::<_, Box<dyn Error + Send + Sync>>((request, second.is_err()))
        });

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

        let (request, had_no_second_proxy_connection) = proxy.await??;
        assert!(header_value(&request, "proxy-authorization").is_none());
        assert!(had_no_second_proxy_connection);
        assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn second_forward_basic_challenge_is_terminal_without_fallback() -> TestResult<()> {
    bounded(async {
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut anonymous_stream, _) = proxy_listener.accept().await?;
            let anonymous = read_head(&mut anonymous_stream).await?;
            anonymous_stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=first-private-realm\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await?;

            let (mut authorized_stream, _) = proxy_listener.accept().await?;
            let authorized = read_head(&mut authorized_stream).await?;
            authorized_stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=second-private-realm\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await?;
            let third = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                proxy_listener.accept(),
            )
            .await;
            Ok::<_, Box<dyn Error + Send + Sync>>((anonymous, authorized, third.is_err()))
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

        let (anonymous, authorized, had_no_third_proxy_connection) = proxy.await??;
        assert!(header_value(&anonymous, "proxy-authorization").is_none());
        assert_eq!(
            header_value(&authorized, "proxy-authorization"),
            Some("Basic bWFya2VyLXVzZXI6bWFya2VyLXBhc3N3b3Jk")
        );
        assert_eq!(
            header_value(&anonymous, "sec-websocket-key"),
            header_value(&authorized, "sec-websocket-key")
        );
        assert!(had_no_third_proxy_connection);
        assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn unauthenticated_407_is_returned_without_retry_or_direct_fallback() -> TestResult<()> {
    bounded(async {
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = proxy_listener.accept().await?;
            let request = read_head(&mut stream).await?;
            stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=available\r\n\
                      Content-Length: 6\r\n\r\n\
                      denied",
                )
                .await?;
            let second = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                proxy_listener.accept(),
            )
            .await;
            Ok::<_, Box<dyn Error + Send + Sync>>((request, second.is_err()))
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(HttpProxy::new(&format!("http://{proxy_address}"))?);
        let error = match client_builder(&identity, false)
            .route(route)
            .build()?
            .websocket(&format!("ws://{origin_address}/rejected"))?
            .connect()
            .await
        {
            Ok(_) => return Err("rejected forward proxy upgraded WebSocket".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::HandshakeRejected);
        let response = error
            .into_response()
            .ok_or("forward rejection omitted HTTP response")?;
        assert_eq!(response.status(), 407);
        assert_eq!(
            http_body_util::BodyExt::collect(response.into_body())
                .await?
                .to_bytes(),
            "denied"
        );

        let (request, had_no_second_proxy_connection) = proxy.await??;
        assert!(
            request.starts_with(
                format!("GET http://{origin_address}/rejected HTTP/1.1\r\n").as_bytes()
            )
        );
        assert!(had_no_second_proxy_connection);
        assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
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
