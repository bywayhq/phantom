use std::{error::Error, io, net::Ipv4Addr};

use phantom::{
    PerMessageDeflate, PerMessageDeflateOfferParameter, RequestHeader, WebSocketErrorKind,
    WebSocketHeader, WebSocketMessage,
};
use tokio::{io::AsyncWriteExt, net::TcpListener};

use super::{tls_support::*, websocket_support::*};

#[tokio::test]
async fn negotiates_and_transfers_compressed_messages() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_tls(listener, acceptor).await?;
            let request = read_head(&mut stream).await?;
            let key = header_value(&request, "sec-websocket-key")
                .ok_or("opening handshake omitted Sec-WebSocket-Key")?;
            let accept = websocket_accept(key);
            let mut response = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\
                 Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_max_window_bits=8\r\n\r\n"
            )
            .into_bytes();
            append_server_frame_with_rsv1(
                &mut response,
                true,
                true,
                0x1,
                &[0xca, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00],
            );
            stream.write_all(&response).await?;
            stream.flush().await?;
            let frame = read_client_frame(&mut stream).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((request, frame))
        });

        let client = test_client(&identity, false)?;
        let mut socket = client
            .websocket(&format!("wss://{address}/compressed"))?
            .permessage_deflate(PerMessageDeflate::new())
            .connect()
            .await?;

        let negotiated = socket
            .negotiated_permessage_deflate()
            .ok_or("server compression selection was not retained")?;
        assert!(negotiated.server_no_context_takeover());
        assert!(!negotiated.client_no_context_takeover());
        assert_eq!(negotiated.server_max_window_bits(), 15);
        assert_eq!(negotiated.client_max_window_bits(), 8);
        assert_eq!(socket.receive().await?, WebSocketMessage::Text("hello".into()));
        socket.send(WebSocketMessage::Text("client hello".into())).await?;

        let (request, frame) = server.await??;
        let request = std::str::from_utf8(&request)?;
        assert!(request.contains(
            "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
        ));
        assert!(frame.rsv1);
        assert_eq!(frame.opcode, 0x1);
        assert_ne!(frame.payload, b"client hello");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn enabled_compression_requires_its_typed_placeholder_before_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let headers = vec![
        WebSocketHeader::authority("Host"),
        WebSocketHeader::field(RequestHeader::new("Upgrade", "websocket")),
        WebSocketHeader::field(RequestHeader::new("Connection", "Upgrade")),
        WebSocketHeader::key("Sec-WebSocket-Key"),
        WebSocketHeader::field(RequestHeader::new("Sec-WebSocket-Version", "13")),
    ];
    let client = test_client(&identity, false)?;
    let error = match client
        .websocket(&format!("wss://{address}/"))?
        .headers(headers)
        .permessage_deflate(PerMessageDeflate::new())
        .connect()
        .await
    {
        Ok(_) => return Err("missing compression placeholder reached network I/O".into()),
        Err(error) => error,
    };

    assert_eq!(error.kind(), WebSocketErrorKind::InvalidRequest);
    assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    Ok(())
}

#[tokio::test]
async fn preserves_custom_offer_parameter_order_and_values() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_tls(listener, acceptor).await?;
            let request = read_head(&mut stream).await?;
            let key = header_value(&request, "sec-websocket-key")
                .ok_or("opening handshake omitted Sec-WebSocket-Key")?;
            let accept = websocket_accept(key);
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\
                 Sec-WebSocket-Extensions: permessage-deflate; server_max_window_bits=12\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).await?;
            stream.flush().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(request)
        });

        use PerMessageDeflateOfferParameter::{
            ClientMaxWindowBits, ClientNoContextTakeover, ServerMaxWindowBits,
        };
        let policy = PerMessageDeflate::new().offer_parameters([
            ClientNoContextTakeover,
            ClientMaxWindowBits(Some(10)),
            ServerMaxWindowBits(12),
        ])?;
        let socket = test_client(&identity, false)?
            .websocket(&format!("wss://{address}/custom-compression"))?
            .permessage_deflate(policy)
            .connect()
            .await?;

        let negotiated = socket
            .negotiated_permessage_deflate()
            .ok_or("server compression selection was not retained")?;
        assert!(negotiated.client_no_context_takeover());
        assert_eq!(negotiated.client_max_window_bits(), 10);
        assert_eq!(negotiated.server_max_window_bits(), 12);
        let request = server.await??;
        let request = std::str::from_utf8(&request)?;
        assert!(request.contains(
            "Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; client_max_window_bits=10; server_max_window_bits=12\r\n"
        ));
        Ok(())
    })
    .await
}

/// The retained `accept-deflate` and `h1-accept-deflate` captures disagree on
/// one message only: Chrome 153 and Edge 153 deflate a zero-length text
/// message into a one-byte frame with RSV1 set, while Firefox 156 sends it
/// with RSV1 clear and an empty payload. Every non-empty message stays
/// compressed in both.
#[tokio::test]
async fn empty_message_follows_the_configured_compression_rule() -> TestResult<()> {
    for (compress_empty, expected_rsv1, expected_payload_len) in
        [(true, true, 1_usize), (false, false, 0_usize)]
    {
        bounded(async move {
            let identity = TestIdentity::generate()?;
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let acceptor = identity.acceptor(H1_ALPN)?;
            let server = tokio::spawn(async move {
                let mut stream = accept_tls(listener, acceptor).await?;
                let request = read_head(&mut stream).await?;
                let key = header_value(&request, "sec-websocket-key")
                    .ok_or("opening handshake omitted Sec-WebSocket-Key")?;
                let accept = websocket_accept(key);
                let response = format!(
                    "HTTP/1.1 101 Switching Protocols\r\n\
                     Upgrade: websocket\r\n\
                     Connection: Upgrade\r\n\
                     Sec-WebSocket-Accept: {accept}\r\n\
                     Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
                );
                stream.write_all(response.as_bytes()).await?;
                stream.flush().await?;
                let empty = read_client_frame(&mut stream).await?;
                let non_empty = read_client_frame(&mut stream).await?;
                Ok::<_, Box<dyn Error + Send + Sync>>((empty, non_empty))
            });

            let mut socket = test_client(&identity, false)?
                .websocket(&format!("wss://{address}/empty-message"))?
                .permessage_deflate(
                    PerMessageDeflate::new().compress_empty_messages(compress_empty),
                )
                .connect()
                .await?;
            socket.send(WebSocketMessage::Text(String::new())).await?;
            socket
                .send(WebSocketMessage::Text("compressible".into()))
                .await?;

            let (empty, non_empty) = server.await??;
            assert_eq!(empty.opcode, 0x1, "empty opcode with {compress_empty}");
            assert_eq!(
                empty.rsv1, expected_rsv1,
                "empty RSV1 with {compress_empty}"
            );
            assert_eq!(
                empty.payload.len(),
                expected_payload_len,
                "empty payload with {compress_empty}"
            );
            // The rule applies to empty messages only.
            assert!(non_empty.rsv1, "non-empty RSV1 with {compress_empty}");
            assert_ne!(non_empty.payload, b"compressible");
            Ok(())
        })
        .await?;
    }
    Ok(())
}
