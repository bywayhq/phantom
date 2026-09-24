//! HTTP/2 WebSocket extended CONNECT integration tests.
#![cfg(feature = "websocket")]

#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;
#[allow(dead_code)]
#[path = "support/websocket.rs"]
mod websocket_support;

use std::{
    error::Error,
    io,
    net::Ipv4Addr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::{Method, Response, Version};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, RequestHeader, WebSocketCloseFrame, WebSocketErrorKind, WebSocketMessage,
    profile::{ClientProfile, Http2PseudoHeader, chromium},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
    sync::oneshot,
    time::timeout,
};

use tls_support::{H2_ALPN, TestIdentity, TestResult, accept_tls, tls_settings};
use websocket_support::{ClientFrame, append_server_frame, bounded};

#[derive(Debug)]
struct ExtendedConnectRequest {
    method: Method,
    version: Version,
    scheme: Option<String>,
    authority: Option<String>,
    path_and_query: Option<String>,
    protocol: Option<String>,
    fields: Vec<String>,
    frame: ClientFrame,
    close: ClientFrame,
    pseudo_header_representations: Vec<HpackRepresentation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HpackRepresentation {
    Indexed(usize),
    IncrementalIndexedName(usize),
    IncrementalNewName,
    UnindexedIndexedName(usize),
}

#[tokio::test]
async fn exact_http2_websocket_uses_extended_connect_and_exchanges_frames() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (done_tx, done_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let stream = accept_tls(listener, acceptor).await?;
            let recorded = Arc::new(Mutex::new(Vec::new()));
            let stream = RecordingIo::new(stream, Arc::clone(&recorded));
            let mut builder = ::http2::server::Builder::new();
            builder.enable_connect_protocol();
            let mut connection = builder.handshake::<_, Bytes>(stream).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before extended CONNECT")??;
            let pseudo_header_representations = {
                let wire = recorded
                    .lock()
                    .map_err(|_| "recorded HTTP/2 wire lock was poisoned")?;
                hpack_representations(&request_header_block(&wire)?, 5)?
            };
            let response = Response::builder()
                .status(201)
                .header("x-handshake", "h2")
                .body(())?;
            let mut send = respond.send_response(response, false)?;
            let handler = tokio::spawn(async move {
                let method = request.method().clone();
                let version = request.version();
                let scheme = request.uri().scheme_str().map(str::to_owned);
                let authority = request.uri().authority().map(ToString::to_string);
                let path_and_query = request.uri().path_and_query().map(ToString::to_string);
                let protocol = request
                    .extensions()
                    .get::<::http2::ext::Protocol>()
                    .map(|protocol| protocol.as_str().to_owned());
                let fields = request
                    .headers()
                    .keys()
                    .map(|name| name.as_str().to_owned())
                    .collect();
                let mut body = request.into_body();
                let frame = read_client_frame(&mut body).await?;

                let mut response_frame = Vec::new();
                append_server_frame(&mut response_frame, true, 0x1, b"from-server");
                send.send_data(Bytes::from(response_frame), false)?;

                let close = read_client_frame(&mut body).await?;
                let mut close_response = Vec::new();
                append_server_frame(&mut close_response, true, 0x8, &close.payload);
                send.send_data(Bytes::from(close_response), false)?;
                while let Some(data) = body.data().await {
                    let data = data.map_err(|error| {
                        format!("client reset extended CONNECT instead of ending DATA: {error}")
                    })?;
                    if !data.is_empty() {
                        return Err("client sent DATA after its WebSocket Close frame".into());
                    }
                }
                if body.trailers().await?.is_some() {
                    return Err("client ended extended CONNECT with trailers".into());
                }
                send.send_data(Bytes::new(), true)?;
                done_rx
                    .await
                    .map_err(|_| "client dropped completion signal")?;

                Ok::<_, Box<dyn Error + Send + Sync>>(ExtendedConnectRequest {
                    method,
                    version,
                    scheme,
                    authority,
                    path_and_query,
                    protocol,
                    fields,
                    frame,
                    close,
                    pseudo_header_representations,
                })
            });
            tokio::pin!(handler);

            tokio::select! {
                result = &mut handler => result?,
                accepted = connection.accept() => match accepted {
                    Some(Ok(_)) => Err("server received an unexpected second stream".into()),
                    Some(Err(error)) => Err(error.into()),
                    None => handler.await?,
                },
            }
        });

        let client = http2_websocket_client(&identity)?;
        let mut socket = client
            .websocket_with_protocol(
                HttpProtocol::Http2,
                &format!("wss://{address}/events?channel=h2"),
            )?
            .header(RequestHeader::new("x-test-order", "last"))
            .connect()
            .await?;
        assert_eq!(socket.handshake_response().status(), 201);
        assert_eq!(socket.handshake_response().version(), Version::HTTP_2);
        assert_eq!(socket.handshake_response().headers()["x-handshake"], "h2");
        assert!(
            !socket
                .handshake_response()
                .headers()
                .contains_key("upgrade")
        );
        assert!(
            !socket
                .handshake_response()
                .headers()
                .contains_key("sec-websocket-accept")
        );

        socket
            .send(WebSocketMessage::Text("from-client".into()))
            .await?;
        assert_eq!(
            socket.receive().await?,
            WebSocketMessage::Text("from-server".into())
        );
        let close = WebSocketCloseFrame::new(1000, "complete")?;
        socket.close(Some(close.clone())).await?;
        assert_eq!(
            socket.receive().await?,
            WebSocketMessage::Close(Some(close))
        );
        let terminal = match socket.receive().await {
            Ok(_) => return Err("WebSocket remained open after peer Close and END_STREAM".into()),
            Err(error) => error,
        };
        assert_eq!(terminal.kind(), WebSocketErrorKind::Closed);
        done_tx
            .send(())
            .map_err(|()| "server dropped completion receiver")?;
        drop(socket);

        let request = server.await??;
        assert_eq!(request.method, Method::CONNECT);
        assert_eq!(request.version, Version::HTTP_2);
        assert_eq!(request.scheme.as_deref(), Some("https"));
        let expected_authority = address.to_string();
        assert_eq!(
            request.authority.as_deref(),
            Some(expected_authority.as_str())
        );
        assert_eq!(
            request.path_and_query.as_deref(),
            Some("/events?channel=h2")
        );
        assert_eq!(request.protocol.as_deref(), Some("websocket"));
        assert_eq!(
            request.pseudo_header_representations,
            [
                HpackRepresentation::IncrementalIndexedName(2),
                HpackRepresentation::IncrementalNewName,
                HpackRepresentation::IncrementalIndexedName(1),
                HpackRepresentation::Indexed(7),
                HpackRepresentation::UnindexedIndexedName(4),
            ]
        );
        assert_eq!(
            request.frame,
            ClientFrame {
                rsv1: false,
                opcode: 0x1,
                payload: b"from-client".to_vec(),
            }
        );
        assert_eq!(request.close.opcode, 0x8);
        let mut expected_close_payload = 1000_u16.to_be_bytes().to_vec();
        expected_close_payload.extend_from_slice(b"complete");
        assert_eq!(request.close.payload, expected_close_payload);
        assert!(
            request
                .fields
                .iter()
                .any(|name| name == "sec-websocket-version")
        );
        assert!(request.fields.iter().any(|name| name == "x-test-order"));
        for forbidden in [
            "connection",
            "host",
            "sec-websocket-accept",
            "sec-websocket-key",
            "upgrade",
        ] {
            assert!(
                !request.fields.iter().any(|name| name == forbidden),
                "extended CONNECT contained forbidden field {forbidden}"
            );
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn missing_peer_setting_is_typed_http2_and_sends_no_request() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let stream = accept_tls(listener, acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            match timeout(Duration::from_millis(250), connection.accept()).await {
                Err(_) | Ok(None) => Ok::<_, Box<dyn Error + Send + Sync>>(()),
                Ok(Some(Ok(_))) => Err("client sent HEADERS without peer capability".into()),
                Ok(Some(Err(error))) if error.is_io() => Ok(()),
                Ok(Some(Err(error))) => Err(error.into()),
            }
        });

        let client = http2_websocket_client(&identity)?;
        let error = match client
            .websocket_with_protocol(
                HttpProtocol::Http2,
                &format!("wss://{address}/no-capability"),
            )?
            .connect()
            .await
        {
            Ok(_) => return Err("extended CONNECT succeeded without the peer setting".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::Http2);
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn non_success_response_preserves_status_and_body() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (done_tx, done_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let stream = accept_tls(listener, acceptor).await?;
            let mut builder = ::http2::server::Builder::new();
            builder.enable_connect_protocol();
            let mut connection = builder.handshake::<_, Bytes>(stream).await?;
            let (_, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before rejected extended CONNECT")??;
            let mut send = respond.send_response(
                Response::builder()
                    .status(403)
                    .header("content-length", "6")
                    .body(())?,
                false,
            )?;
            send.send_data(Bytes::from_static(b"denied"), true)?;

            tokio::select! {
                result = done_rx => {
                    result.map_err(|_| "client dropped completion signal")?;
                    Ok::<_, Box<dyn Error + Send + Sync>>(())
                },
                accepted = connection.accept() => match accepted {
                    Some(Ok(_)) => Err("server received an unexpected second stream".into()),
                    Some(Err(error)) => Err(error.into()),
                    None => Err("connection closed before rejection body was read".into()),
                },
            }
        });

        let client = http2_websocket_client(&identity)?;
        let error = match client
            .websocket_with_protocol(HttpProtocol::Http2, &format!("wss://{address}/denied"))?
            .connect()
            .await
        {
            Ok(_) => return Err("rejected extended CONNECT succeeded".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::HandshakeRejected);
        let response = error
            .into_response()
            .ok_or("HTTP/2 rejection omitted its response")?;
        assert_eq!(response.status(), 403);
        assert_eq!(response.version(), Version::HTTP_2);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "denied");
        done_tx
            .send(())
            .map_err(|()| "server dropped completion receiver")?;
        server.await??;
        Ok(())
    })
    .await
}

fn http2_websocket_client(identity: &TestIdentity) -> TestResult<Client> {
    let mut http2 = chromium::v154_http2();
    http2.extended_connect_pseudo_header_order = Some(vec![
        Http2PseudoHeader::Method,
        Http2PseudoHeader::Protocol,
        Http2PseudoHeader::Authority,
        Http2PseudoHeader::Scheme,
        Http2PseudoHeader::Path,
    ]);
    let profile = ClientProfile::new(tls_settings()).with_http2(http2);
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}

async fn read_client_frame(body: &mut ::http2::RecvStream) -> TestResult<ClientFrame> {
    let mut wire = Vec::new();
    loop {
        if let Some(frame) = decode_client_frame(&wire)? {
            return Ok(frame);
        }
        let chunk = body
            .data()
            .await
            .ok_or("client ended the HTTP/2 stream before one WebSocket frame")??;
        body.flow_control().release_capacity(chunk.len())?;
        wire.extend_from_slice(&chunk);
    }
}

fn decode_client_frame(wire: &[u8]) -> io::Result<Option<ClientFrame>> {
    if wire.len() < 2 {
        return Ok(None);
    }
    if wire[1] & 0x80 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client WebSocket frame was not masked",
        ));
    }

    let mut cursor = 2;
    let length = match wire[1] & 0x7f {
        length @ 0..=125 => usize::from(length),
        126 => {
            if wire.len() < cursor + 2 {
                return Ok(None);
            }
            let length = usize::from(u16::from_be_bytes([wire[cursor], wire[cursor + 1]]));
            cursor += 2;
            length
        }
        127 => {
            if wire.len() < cursor + 8 {
                return Ok(None);
            }
            let mut encoded = [0; 8];
            encoded.copy_from_slice(&wire[cursor..cursor + 8]);
            cursor += 8;
            usize::try_from(u64::from_be_bytes(encoded)).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "WebSocket frame length overflow",
                )
            })?
        }
        _ => unreachable!(),
    };
    let total = cursor
        .checked_add(4)
        .and_then(|length_with_mask| length_with_mask.checked_add(length))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "frame length overflow"))?;
    if wire.len() < total {
        return Ok(None);
    }
    let mask = &wire[cursor..cursor + 4];
    cursor += 4;
    let mut payload = wire[cursor..cursor + length].to_vec();
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % mask.len()];
    }
    Ok(Some(ClientFrame {
        rsv1: wire[0] & 0x40 != 0,
        opcode: wire[0] & 0x0f,
        payload,
    }))
}

struct RecordingIo<T> {
    inner: T,
    read: Arc<Mutex<Vec<u8>>>,
}

impl<T> RecordingIo<T> {
    fn new(inner: T, read: Arc<Mutex<Vec<u8>>>) -> Self {
        Self { inner, read }
    }
}

impl<T> AsyncRead for RecordingIo<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        match Pin::new(&mut this.inner).poll_read(context, buffer) {
            Poll::Ready(Ok(())) => {
                let mut read = match this.read.lock() {
                    Ok(read) => read,
                    Err(_) => {
                        return Poll::Ready(Err(io::Error::other(
                            "recorded HTTP/2 wire lock was poisoned",
                        )));
                    }
                };
                read.extend_from_slice(&buffer.filled()[before..]);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<T> AsyncWrite for RecordingIo<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

fn request_header_block(wire: &[u8]) -> TestResult<Vec<u8>> {
    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if !wire.starts_with(PREFACE) {
        return Err("recorded HTTP/2 stream omitted the client preface".into());
    }

    let mut cursor = PREFACE.len();
    while cursor + 9 <= wire.len() {
        let length = usize::from(wire[cursor]) << 16
            | usize::from(wire[cursor + 1]) << 8
            | usize::from(wire[cursor + 2]);
        let kind = wire[cursor + 3];
        let flags = wire[cursor + 4];
        let stream_id = u32::from_be_bytes([
            wire[cursor + 5],
            wire[cursor + 6],
            wire[cursor + 7],
            wire[cursor + 8],
        ]) & 0x7fff_ffff;
        cursor += 9;
        let end = cursor
            .checked_add(length)
            .ok_or("recorded HTTP/2 frame length overflow")?;
        if end > wire.len() {
            return Err("recorded HTTP/2 frame was truncated".into());
        }
        if kind != 0x1 || stream_id == 0 {
            cursor = end;
            continue;
        }

        let (mut block, end_headers) = headers_fragment(&wire[cursor..end], flags)?;
        cursor = end;
        if end_headers {
            return Ok(block);
        }
        loop {
            if cursor + 9 > wire.len() {
                return Err("recorded HTTP/2 continuation frame was truncated".into());
            }
            let continuation_length = usize::from(wire[cursor]) << 16
                | usize::from(wire[cursor + 1]) << 8
                | usize::from(wire[cursor + 2]);
            let continuation_kind = wire[cursor + 3];
            let continuation_flags = wire[cursor + 4];
            let continuation_stream = u32::from_be_bytes([
                wire[cursor + 5],
                wire[cursor + 6],
                wire[cursor + 7],
                wire[cursor + 8],
            ]) & 0x7fff_ffff;
            cursor += 9;
            let continuation_end = cursor
                .checked_add(continuation_length)
                .ok_or("recorded HTTP/2 continuation length overflow")?;
            if continuation_end > wire.len() {
                return Err("recorded HTTP/2 continuation payload was truncated".into());
            }
            if continuation_kind != 0x9 || continuation_stream != stream_id {
                return Err("recorded HTTP/2 header block was interleaved".into());
            }
            block.extend_from_slice(&wire[cursor..continuation_end]);
            cursor = continuation_end;
            if continuation_flags & 0x4 != 0 {
                return Ok(block);
            }
        }
    }
    Err("recorded HTTP/2 stream omitted request HEADERS".into())
}

fn headers_fragment(payload: &[u8], flags: u8) -> TestResult<(Vec<u8>, bool)> {
    let mut start = 0;
    let padding = if flags & 0x8 != 0 {
        let length = payload.first().ok_or("padded HEADERS omitted pad length")?;
        start = 1;
        usize::from(*length)
    } else {
        0
    };
    if flags & 0x20 != 0 {
        start += 5;
    }
    let end = payload
        .len()
        .checked_sub(padding)
        .ok_or("HEADERS padding exceeded its payload")?;
    if start > end {
        return Err("HEADERS metadata exceeded its payload".into());
    }
    Ok((payload[start..end].to_vec(), flags & 0x4 != 0))
}

fn hpack_representations(block: &[u8], count: usize) -> TestResult<Vec<HpackRepresentation>> {
    let mut cursor = 0;
    let mut representations = Vec::with_capacity(count);
    while representations.len() < count {
        let first = *block
            .get(cursor)
            .ok_or("HPACK block ended before all pseudo headers")?;
        let representation = if first & 0x80 != 0 {
            HpackRepresentation::Indexed(read_hpack_integer(block, &mut cursor, 7)?)
        } else if first & 0x40 != 0 {
            let name = read_hpack_integer(block, &mut cursor, 6)?;
            if name == 0 {
                skip_hpack_string(block, &mut cursor)?;
                skip_hpack_string(block, &mut cursor)?;
                HpackRepresentation::IncrementalNewName
            } else {
                skip_hpack_string(block, &mut cursor)?;
                HpackRepresentation::IncrementalIndexedName(name)
            }
        } else if first & 0x20 != 0 {
            return Err("unexpected HPACK table-size update among pseudo headers".into());
        } else {
            let name = read_hpack_integer(block, &mut cursor, 4)?;
            if name == 0 {
                return Err("unexpected literal pseudo-header name without indexing".into());
            }
            skip_hpack_string(block, &mut cursor)?;
            HpackRepresentation::UnindexedIndexedName(name)
        };
        representations.push(representation);
    }
    Ok(representations)
}

fn skip_hpack_string(block: &[u8], cursor: &mut usize) -> TestResult<()> {
    let length = read_hpack_integer(block, cursor, 7)?;
    *cursor = cursor
        .checked_add(length)
        .ok_or("HPACK string length overflow")?;
    if *cursor > block.len() {
        return Err("HPACK string was truncated".into());
    }
    Ok(())
}

fn read_hpack_integer(block: &[u8], cursor: &mut usize, prefix_bits: u8) -> TestResult<usize> {
    let first = *block.get(*cursor).ok_or("HPACK integer was truncated")?;
    *cursor += 1;
    let mask = (1_u8 << prefix_bits) - 1;
    let mut value = usize::from(first & mask);
    if value < usize::from(mask) {
        return Ok(value);
    }

    let mut shift = 0;
    loop {
        let byte = *block
            .get(*cursor)
            .ok_or("HPACK integer continuation was truncated")?;
        *cursor += 1;
        let addition = usize::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or("HPACK integer shift overflow")?;
        value = value
            .checked_add(addition)
            .ok_or("HPACK integer value overflow")?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift = shift.checked_add(7).ok_or("HPACK integer shift overflow")?;
    }
}
