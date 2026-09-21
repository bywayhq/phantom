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

use super::tls::{TestResult, accept_tls, read_head};

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
/// reports whether the client opened any stream before `client_done` fired.
pub(crate) async fn serve_h2_without_connect_protocol(
    listener: TcpListener,
    acceptor: SslAcceptor,
    client_done: oneshot::Receiver<()>,
) -> TestResult<bool> {
    let stream = accept_tls(listener, acceptor).await?;
    let mut connection = ::http2::server::handshake(stream).await?;
    tokio::select! {
        accepted = connection.accept() => Ok(matches!(accepted, Some(Ok(_)))),
        _ = client_done => {
            // The client already returned its error, so any HEADERS it sent
            // are already on the wire. The bound only limits how long an idle
            // but still-open client connection is observed; it cannot turn a
            // sent request into a pass.
            match timeout(Duration::from_secs(1), connection.accept()).await {
                Ok(Some(Ok(_))) => Ok(true),
                Ok(Some(Err(_)) | None) | Err(_) => Ok(false),
            }
        }
    }
}

/// Accepts one TLS HTTP/1.1 WebSocket Upgrade, echoes one text message as
/// `echo:<text>`, answers Close, and returns the request head.
pub(crate) async fn serve_h1_echo(
    listener: TcpListener,
    acceptor: SslAcceptor,
) -> TestResult<(Vec<u8>, ClientFrame)> {
    let mut stream = accept_tls(listener, acceptor).await?;
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
