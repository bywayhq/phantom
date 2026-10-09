//! Loopback WebSocket origins that echo one message and answer Close.

use std::{error::Error, io, time::Duration};

use btls::ssl::SslAcceptor;
use bytes::Bytes;
use http::Response;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::timeout,
};

use super::tls::{TestResult, accept_tls, is_peer_gone, read_head};

/// One masked client frame after unmasking.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ClientFrame {
    pub(crate) opcode: u8,
    pub(crate) payload: Vec<u8>,
}

/// The extended CONNECT request observed by an HTTP/2 origin.
#[derive(Debug)]
pub(crate) struct ExtendedConnectRecord {
    pub(crate) scheme: Option<String>,
    pub(crate) authority: Option<String>,
    pub(crate) path: Option<String>,
    pub(crate) protocol: Option<String>,
    pub(crate) message: ClientFrame,
}

/// Accepts one HTTP/2 connection that enables extended CONNECT, accepts one
/// WebSocket stream, echoes one text message as `echo:<text>`, and answers
/// the client's Close.
pub(crate) async fn serve_h2_echo(
    listener: TcpListener,
    acceptor: SslAcceptor,
) -> TestResult<ExtendedConnectRecord> {
    let stream = accept_tls(listener, acceptor).await?;
    let mut builder = ::http2::server::Builder::new();
    builder.enable_connect_protocol();
    let mut connection = builder.handshake::<_, Bytes>(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("origin connection closed before extended CONNECT")??;
    let scheme = request.uri().scheme_str().map(str::to_owned);
    let authority = request.uri().authority().map(ToString::to_string);
    let path = request.uri().path_and_query().map(ToString::to_string);
    let protocol = request
        .extensions()
        .get::<::http2::ext::Protocol>()
        .map(|protocol| protocol.as_str().to_owned());
    let mut send = respond.send_response(Response::new(()), false)?;

    let handler = tokio::spawn(async move {
        let mut body = request.into_body();
        let mut wire = Vec::new();
        let message = next_h2_frame(&mut body, &mut wire).await?;
        let mut reply = Vec::new();
        append_server_frame(&mut reply, 0x1, &[b"echo:", &message.payload[..]].concat());
        send.send_data(Bytes::from(reply), false)?;

        let close = next_h2_frame(&mut body, &mut wire).await?;
        if close.opcode != 0x8 {
            return Err("client sent a non-Close second frame".into());
        }
        let mut reply = Vec::new();
        append_server_frame(&mut reply, 0x8, &close.payload);
        send.send_data(Bytes::from(reply), false)?;
        // The client either ends the stream after reading Close or resets it
        // when dropped; both prove the Close reply was delivered.
        while let Some(Ok(chunk)) = body.data().await {
            let _ = body.flow_control().release_capacity(chunk.len());
        }
        let _ = send.send_data(Bytes::new(), true);
        Ok::<_, Box<dyn Error + Send + Sync>>(message)
    });
    tokio::pin!(handler);
    let message = tokio::select! {
        result = &mut handler => result??,
        accepted = connection.accept() => match accepted {
            Some(Ok(_)) => return Err("origin received an unexpected second stream".into()),
            Some(Err(error)) if error.is_io() => handler.await??,
            Some(Err(error)) => return Err(error.into()),
            None => handler.await??,
        },
    };
    Ok(ExtendedConnectRecord {
        scheme,
        authority,
        path,
        protocol,
        message,
    })
}

/// Accepts one HTTP/2 connection that never enables extended CONNECT and
/// reports whether the client sent HEADERS during the observation window.
pub(crate) async fn serve_h2_without_connect_protocol(
    listener: TcpListener,
    acceptor: SslAcceptor,
    client_done: oneshot::Receiver<()>,
) -> TestResult<bool> {
    let stream = accept_tls(listener, acceptor).await?;
    observe_h2_without_connect_protocol(stream, client_done).await
}

async fn observe_h2_without_connect_protocol<S>(
    mut stream: S,
    client_done: oneshot::Receiver<()>,
) -> TestResult<bool>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut preface = [0; 24];
    stream.read_exact(&mut preface).await?;
    if &preface != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP/2 preface").into());
    }
    super::h2::write_frame(&mut stream, 4, 0, 0, &[]).await?;
    stream.flush().await?;
    let mut incomplete_frame = false;
    let observation = {
        let frames = observe_h2_headers(&mut stream, &mut incomplete_frame);
        tokio::pin!(frames);
        tokio::select! {
            result = &mut frames => Some(result),
            _ = client_done => {
                // This finite window checks a completed client's queued bytes.
                // It does not prove that a live peer will never send HEADERS.
                timeout(Duration::from_secs(1), &mut frames).await.ok()
            }
        }
    };
    match observation {
        Some(result) => result,
        None if incomplete_frame => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete HTTP/2 frame at end of observation",
        )
        .into()),
        None => Ok(false),
    }
}

/// An absence oracle must observe HEADERS before HPACK can reject them.
/// Other frame failures remain errors, not evidence that no request was sent.
async fn observe_h2_headers<S>(stream: &mut S, incomplete_frame: &mut bool) -> TestResult<bool>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut first_frame = true;
    loop {
        let mut head = [0; 9];
        match stream.read(&mut head[..1]).await {
            Ok(0) => return Ok(false),
            Err(error) if is_peer_gone(&error) => return Ok(false),
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        *incomplete_frame = true;
        stream.read_exact(&mut head[1..]).await?;
        let length =
            (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
        let kind = head[3];
        let flags = head[4];
        let stream_id = u32::from_be_bytes([head[5] & 0x7f, head[6], head[7], head[8]]);
        if kind == 1 {
            // Even invalid HPACK or a missing payload is an observed attempt.
            return Ok(true);
        }
        if length > 16_384 || (first_frame && (kind != 4 || flags & 1 != 0)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid initial HTTP/2 frame or frame length",
            )
            .into());
        }
        first_frame = false;
        let mut payload = vec![0; length];
        stream.read_exact(&mut payload).await?;
        let valid = match kind {
            2 => {
                stream_id != 0
                    && length == 5
                    && u32::from_be_bytes([payload[0] & 0x7f, payload[1], payload[2], payload[3]])
                        != stream_id
            }
            // Without HEADERS, a nonzero stream is still idle. RST_STREAM or
            // WINDOW_UPDATE on it is a connection protocol error.
            3 => false,
            4 => {
                stream_id == 0
                    && if flags & 1 != 0 {
                        length == 0
                    } else {
                        length.is_multiple_of(6)
                            && payload.chunks_exact(6).all(|setting| {
                                let id = u16::from_be_bytes([setting[0], setting[1]]);
                                let value = u32::from_be_bytes([
                                    setting[2], setting[3], setting[4], setting[5],
                                ]);
                                match id {
                                    2 | 8 => value <= 1,
                                    4 => value <= 0x7fff_ffff,
                                    5 => (16_384..=16_777_215).contains(&value),
                                    _ => true,
                                }
                            })
                    }
            }
            6 => stream_id == 0 && length == 8,
            7 => stream_id == 0 && length >= 8,
            8 => {
                stream_id == 0
                    && length == 4
                    && u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                        & 0x7fff_ffff
                        != 0
            }
            // No request stream exists here, so these cannot be valid.
            0 | 5 | 9 => false,
            // HTTP/2 ignores unknown frame types (RFC 9113 section 4.1).
            _ => true,
        };
        if !valid {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP/2 control frame").into(),
            );
        }
        match kind {
            4 | 6 if flags & 1 == 0 => {
                let acknowledgement = if kind == 6 { payload.as_slice() } else { &[] };
                super::h2::write_frame(stream, kind, 1, 0, acknowledgement).await?;
                stream.flush().await?;
            }
            7 => {
                if payload[4..8] != [0, 0, 0, 0] {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "peer sent HTTP/2 GOAWAY with an error",
                    )
                    .into());
                }
            }
            _ => {}
        }
        *incomplete_frame = false;
    }
}

/// Accepts one TLS HTTP/1.1 WebSocket Upgrade, echoes one text message as
/// `echo:<text>`, answers Close, and returns the request head.
pub(crate) async fn serve_h1_echo(
    listener: TcpListener,
    acceptor: SslAcceptor,
) -> TestResult<(Vec<u8>, ClientFrame)> {
    let stream = accept_tls(listener, acceptor).await?;
    echo_h1(stream).await
}

/// Like [`serve_h1_echo`], over plaintext TCP: the origin of a `ws://`
/// opening, or the far end of a proxy tunnel that carries one.
pub(crate) async fn serve_plaintext_h1_echo(
    listener: TcpListener,
) -> TestResult<(Vec<u8>, ClientFrame)> {
    let (stream, _) = listener.accept().await?;
    echo_h1(stream).await
}

async fn echo_h1(
    mut stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
) -> TestResult<(Vec<u8>, ClientFrame)> {
    let request = read_head(&mut stream).await?;
    let key = header_value(&request, "sec-websocket-key").ok_or("missing Sec-WebSocket-Key")?;
    let accept = websocket_accept(key);
    stream
        .write_all(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                 Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
    stream.flush().await?;

    let mut wire = Vec::new();
    let message = next_stream_frame(&mut stream, &mut wire).await?;
    let mut reply = Vec::new();
    append_server_frame(&mut reply, 0x1, &[b"echo:", &message.payload[..]].concat());
    stream.write_all(&reply).await?;
    let close = next_stream_frame(&mut stream, &mut wire).await?;
    if close.opcode != 0x8 {
        return Err("client sent a non-Close second frame".into());
    }
    let mut reply = Vec::new();
    append_server_frame(&mut reply, 0x8, &close.payload);
    stream.write_all(&reply).await?;
    stream.flush().await?;
    let mut rest = Vec::new();
    // Drain until the client hangs up so the Close reply is not reset away.
    let _ = stream.read_to_end(&mut rest).await;
    Ok((request, message))
}

pub(crate) fn header_value<'a>(head: &'a [u8], name: &str) -> Option<&'a str> {
    let text = std::str::from_utf8(head).ok()?;
    text.split("\r\n").skip(1).find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        candidate.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn websocket_accept(key: &str) -> String {
    let mut input = Vec::with_capacity(key.len() + 36);
    input.extend_from_slice(key.as_bytes());
    input.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    btls::base64::encode_block(&btls::sha::sha1(&input))
}

async fn next_h2_frame(
    body: &mut ::http2::RecvStream,
    wire: &mut Vec<u8>,
) -> TestResult<ClientFrame> {
    loop {
        if let Some(frame) = take_client_frame(wire)? {
            return Ok(frame);
        }
        let chunk = body
            .data()
            .await
            .ok_or("client ended the HTTP/2 stream before a WebSocket frame")??;
        body.flow_control().release_capacity(chunk.len())?;
        wire.extend_from_slice(&chunk);
    }
}

async fn next_stream_frame(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
    wire: &mut Vec<u8>,
) -> TestResult<ClientFrame> {
    let mut buffer = [0_u8; 1024];
    loop {
        if let Some(frame) = take_client_frame(wire)? {
            return Ok(frame);
        }
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            return Err("client closed before a WebSocket frame".into());
        }
        wire.extend_from_slice(&buffer[..count]);
    }
}

/// Removes one complete masked client frame from the front of `wire`.
fn take_client_frame(wire: &mut Vec<u8>) -> io::Result<Option<ClientFrame>> {
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
            if wire.len() < 4 {
                return Ok(None);
            }
            cursor = 4;
            usize::from(u16::from_be_bytes([wire[2], wire[3]]))
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "test frame exceeded its bound",
            ));
        }
    };
    let total = cursor + 4 + length;
    if wire.len() < total {
        return Ok(None);
    }
    let mask = [
        wire[cursor],
        wire[cursor + 1],
        wire[cursor + 2],
        wire[cursor + 3],
    ];
    let mut payload = wire[cursor + 4..total].to_vec();
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % mask.len()];
    }
    let opcode = wire[0] & 0x0f;
    wire.drain(..total);
    Ok(Some(ClientFrame { opcode, payload }))
}

fn append_server_frame(output: &mut Vec<u8>, opcode: u8, payload: &[u8]) {
    output.push(0x80 | opcode);
    let length = u8::try_from(payload.len()).unwrap_or(u8::MAX);
    assert!(length < 126, "test server frames stay below 126 bytes");
    output.push(length);
    output.extend_from_slice(payload);
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::oneshot,
        task::JoinSet,
        time::timeout,
    };

    use super::{TestResult, echo_h1, observe_h2_without_connect_protocol};

    async fn observed_h2_frames(frames: &[u8]) -> TestResult<bool> {
        let (mut client, server) = tokio::io::duplex(4096);
        let (done, client_done) = oneshot::channel();
        let mut observers = JoinSet::new();
        observers.spawn(observe_h2_without_connect_protocol(server, client_done));
        client
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await?;
        client.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await?;
        client.write_all(frames).await?;
        client.shutdown().await?;
        // The observer may already have rejected the independent peer bytes.
        let _ = done.send(());
        timeout(Duration::from_secs(2), observers.join_next())
            .await?
            .ok_or("missing observer task")??
    }

    #[tokio::test]
    async fn forbidden_malformed_headers_cannot_prove_absence() -> TestResult<()> {
        // HPACK indexed field with an unterminated integer on stream 1.
        assert!(observed_h2_frames(&[0, 0, 1, 1, 4, 0, 0, 0, 1, 0xff]).await?);
        Ok(())
    }

    #[tokio::test]
    async fn forbidden_valid_headers_are_observed() -> TestResult<()> {
        // Static HPACK indexes: :method GET, :scheme https, :path /.
        assert!(observed_h2_frames(&[0, 0, 3, 1, 4, 0, 0, 0, 1, 0x82, 0x87, 0x84]).await?);
        Ok(())
    }

    #[tokio::test]
    async fn truncated_frame_cannot_prove_absence() -> TestResult<()> {
        let error = observed_h2_frames(&[0, 0])
            .await
            .err()
            .ok_or("truncated frame was accepted")?;
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .ok_or("expected an I/O error")?
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        Ok(())
    }

    #[tokio::test]
    async fn protocol_error_cannot_prove_absence() -> TestResult<()> {
        // PING payloads must contain eight bytes, not one.
        let error = observed_h2_frames(&[0, 0, 1, 6, 0, 0, 0, 0, 0, 0])
            .await
            .err()
            .ok_or("invalid PING length was accepted")?;
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .ok_or("expected an I/O error")?
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        Ok(())
    }

    #[tokio::test]
    async fn clean_h2_close_without_headers_proves_no_request() -> TestResult<()> {
        assert!(!observed_h2_frames(&[]).await?);
        Ok(())
    }

    async fn observe_live_h2_peer(frames: &[u8]) -> TestResult<bool> {
        let (mut peer, stream) = tokio::io::duplex(4096);
        let (done, client_done) = oneshot::channel();
        let mut observers = JoinSet::new();
        observers.spawn(observe_h2_without_connect_protocol(stream, client_done));
        peer.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await?;
        peer.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await?;
        peer.write_all(frames).await?;
        // The live peer stays open through the observer's finite quiet window.
        let _ = done.send(());
        timeout(Duration::from_secs(2), observers.join_next())
            .await?
            .ok_or("missing observer task")??
    }

    #[tokio::test]
    async fn forbidden_headers_are_observed_before_the_payload_arrives() -> TestResult<()> {
        assert!(observe_live_h2_peer(&[0, 0, 3, 1, 4, 0, 0, 0, 1]).await?);
        Ok(())
    }

    #[tokio::test]
    async fn an_incomplete_live_frame_cannot_satisfy_the_quiet_window() -> TestResult<()> {
        let error = observe_live_h2_peer(&[0, 0])
            .await
            .err()
            .ok_or("incomplete frame was accepted")?;
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .ok_or("expected an I/O error")?
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_live_idle_peer_has_only_finite_absence_evidence() -> TestResult<()> {
        assert!(!observe_live_h2_peer(&[]).await?);
        Ok(())
    }

    async fn observed_h1_second_frame(opcode: u8) -> TestResult<()> {
        let (mut client, server) = tokio::io::duplex(4096);
        let mut origins = JoinSet::new();
        origins.spawn(echo_h1(server));
        client
            .write_all(b"GET / HTTP/1.1\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
            .await?;
        // Zero masks are legal and keep these independent peer bytes readable.
        client
            .write_all(&[0x81, 0x85, 0, 0, 0, 0, b'h', b'e', b'l', b'l', b'o'])
            .await?;
        client
            .write_all(&[0x80 | opcode, 0x82, 0, 0, 0, 0, 0x03, 0xe8])
            .await?;
        client.shutdown().await?;

        let mut reply = Vec::new();
        timeout(Duration::from_secs(2), client.read_to_end(&mut reply)).await??;
        let (_, message) = timeout(Duration::from_secs(2), origins.join_next())
            .await?
            .ok_or("missing origin task")???;
        assert_eq!(message.opcode, 1);
        assert_eq!(message.payload, b"hello");
        assert!(reply.ends_with(&[0x88, 2, 0x03, 0xe8]));
        Ok(())
    }

    #[tokio::test]
    async fn h1_echo_rejects_ping_in_place_of_close() -> TestResult<()> {
        let error = observed_h1_second_frame(9)
            .await
            .err()
            .ok_or("Ping was accepted as Close")?;
        assert_eq!(error.to_string(), "client sent a non-Close second frame");
        Ok(())
    }

    #[tokio::test]
    async fn h1_echo_answers_an_observed_close() -> TestResult<()> {
        observed_h1_second_frame(8).await
    }
}
