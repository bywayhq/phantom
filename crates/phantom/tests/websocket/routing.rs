use super::*;

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
