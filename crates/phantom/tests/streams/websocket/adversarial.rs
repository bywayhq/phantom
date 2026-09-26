use super::*;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    time::timeout,
};

#[tokio::test]
async fn invalid_accept_is_rejected() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_tls(listener, acceptor).await?;
            read_head(&mut stream).await?;
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\n\
                      Upgrade: websocket\r\n\
                      Connection: Upgrade\r\n\
                      Sec-WebSocket-Accept: invalid\r\n\r\n",
                )
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let client = test_client(&identity, false)?;
        let error = match client
            .websocket(&format!("wss://{address}/"))?
            .connect()
            .await
        {
            Ok(_) => return Err("invalid opening handshake succeeded".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::InvalidHandshake);
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn unsolicited_subprotocol_is_a_typed_handshake_error() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_tls(listener, acceptor).await?;
            let request = read_head(&mut stream).await?;
            if header_value(&request, "sec-websocket-protocol").is_some() {
                return Err("client unexpectedly offered a WebSocket subprotocol".into());
            }
            let key = header_value(&request, "sec-websocket-key").ok_or("missing key")?;
            let accept = websocket_accept(key);
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 101 Switching Protocols\r\n\
                         Upgrade: websocket\r\n\
                         Connection: Upgrade\r\n\
                         Sec-WebSocket-Accept: {accept}\r\n\
                         Sec-WebSocket-Protocol: unsolicited\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await?;
            stream.flush().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let client = test_client(&identity, false)?;
        let error = match client
            .websocket(&format!("wss://{address}/"))?
            .connect()
            .await
        {
            Ok(_) => return Err("unsolicited WebSocket subprotocol was accepted".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::InvalidHandshake);
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn masked_server_frame_closes_transport_and_traces_closed_send() -> TestResult<()> {
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
            stream
                .write_all(&[0x81, 0x81, 1, 2, 3, 4, b'x' ^ 1])
                .await?;
            stream.flush().await?;

            let mut byte = [0_u8; 1];
            let closed = match timeout(TEST_TIMEOUT, stream.read(&mut byte)).await {
                Ok(Ok(0) | Err(_)) => true,
                Ok(Ok(_)) | Err(_) => false,
            };
            Ok::<_, Box<dyn Error + Send + Sync>>(closed)
        });

        let client = test_client(&identity, false)?;
        let mut socket = client
            .websocket(&format!("wss://{address}/"))?
            .connect()
            .await?;
        let error = match socket.receive().await {
            Ok(_) => return Err("masked server frame was accepted".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::Protocol);

        let subscriber = OutcomeSubscriber::default();
        let error = match socket
            .send(WebSocketMessage::Text("must-not-send".into()))
            .with_subscriber(subscriber.dispatch())
            .await
        {
            Ok(()) => return Err("send succeeded after a fatal receive error".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::Closed);
        assert_eq!(subscriber.outcomes_for("websocket.send"), ["error"]);
        assert_eq!(subscriber.error_kinds_for("websocket.send"), ["Closed"]);
        assert!(server.await??, "fatal frame error retained the transport");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn invalid_peer_close_code_is_rejected_in_each_close_state() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_tls(listener, acceptor).await?;
            write_handshake_response(&mut stream).await?;
            append_and_write_server_frame(&mut stream, true, 0x8, &1005_u16.to_be_bytes()).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });
        let client = test_client(&identity, false)?;
        let mut socket = client
            .websocket(&format!("wss://{address}/"))?
            .connect()
            .await?;
        let error = match socket.receive().await {
            Ok(_) => return Err("forbidden peer Close code was accepted".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::Protocol);
        server.await??;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_tls(listener, acceptor).await?;
            write_handshake_response(&mut stream).await?;
            let close = read_client_frame(&mut stream).await?;
            if close.opcode != 0x8 {
                return Err("client did not send a Close frame".into());
            }
            append_and_write_server_frame(&mut stream, true, 0x8, &1005_u16.to_be_bytes()).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });
        let mut socket = client
            .websocket(&format!("wss://{address}/"))?
            .connect()
            .await?;
        socket
            .close(Some(WebSocketCloseFrame::new(1000, "done")?))
            .await?;
        let error = match socket.receive().await {
            Ok(_) => return Err("forbidden Close reply was accepted".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::Protocol);
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn invalid_utf8_error_does_not_disclose_fragment_bytes() -> TestResult<()> {
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
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\r\n"
            )
            .into_bytes();
            append_server_frame(&mut response, false, 0x1, &[226, 130]);
            append_server_frame(&mut response, true, 0x0, &[]);
            stream.write_all(&response).await?;
            stream.flush().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let client = test_client(&identity, false)?;
        let mut socket = client
            .websocket(&format!("wss://{address}/"))?
            .connect()
            .await?;
        let error = match socket.receive().await {
            Ok(_) => return Err("invalid fragmented UTF-8 was accepted".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::InvalidUtf8);

        let mut rendered = error.to_string();
        let mut source = error.source();
        while let Some(current) = source {
            rendered.push_str(&current.to_string());
            source = current.source();
        }
        assert!(!rendered.contains("226"));
        assert!(!rendered.contains("130"));
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn fragment_count_limit_ignores_control_frames_and_closes_transport() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_tls(listener, acceptor).await?;
            write_handshake_response(&mut stream).await?;
            let mut frames = Vec::new();
            append_server_frame(&mut frames, false, 0x1, &[]);
            append_server_frame(&mut frames, true, 0x9, b"still-alive");
            append_server_frame(&mut frames, false, 0x0, &[]);
            append_server_frame(&mut frames, true, 0x0, &[]);
            stream.write_all(&frames).await?;
            stream.flush().await?;

            let pong = read_client_frame(&mut stream).await?;
            let mut byte = [0_u8; 1];
            let closed = match timeout(TEST_TIMEOUT, stream.read(&mut byte)).await {
                Ok(Ok(0) | Err(_)) => true,
                Ok(Ok(_)) | Err(_) => false,
            };
            Ok::<_, Box<dyn Error + Send + Sync>>((pong, closed))
        });

        let maximum = NonZeroUsize::new(2).ok_or("nonzero construction failed")?;
        let limits = WebSocketLimits::default().with_max_message_fragments(maximum);
        assert_eq!(limits.max_message_fragments(), maximum);
        let client = test_client(&identity, false)?;
        let mut socket = client
            .websocket(&format!("wss://{address}/"))?
            .limits(limits)
            .connect()
            .await?;

        assert_eq!(
            socket.receive().await?,
            WebSocketMessage::Ping(Bytes::from_static(b"still-alive"))
        );
        let error = match socket.receive().await {
            Ok(_) => return Err("excessively fragmented message was accepted".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::Capacity);
        let closed_error = match socket.receive().await {
            Ok(_) => return Err("receive succeeded after fragment-limit failure".into()),
            Err(error) => error,
        };
        assert_eq!(closed_error.kind(), WebSocketErrorKind::Closed);

        let (pong, closed) = server.await??;
        assert_eq!(pong.opcode, 0xA);
        assert_eq!(pong.payload, b"still-alive");
        assert!(closed, "fragment-limit failure retained the transport");
        Ok(())
    })
    .await
}

async fn write_handshake_response(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
) -> TestResult<()> {
    let request = read_head(stream).await?;
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
    Ok(())
}
