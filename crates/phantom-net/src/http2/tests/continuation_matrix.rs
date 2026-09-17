use bytes::Bytes;
use http_body_util::BodyExt;
use phantom_profile::chromium::v152_macos_http2;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex},
    sync::oneshot,
};

use super::{TestResult, bounded_peer_test, target};
use crate::http2::Http2Connection;

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const MAX_CLIENT_FRAME_LEN: usize = 64 * 1024;
const MAX_CLIENT_FRAMES: usize = 32;
const MAX_CLIENT_BYTES: usize = 256 * 1024;

// Equivalent HPACK blocks using distinct legal representations and splits.
const RAW_103: &[u8] = &[0x08, 0x03, b'1', b'0', b'3'];
const HUFFMAN_103: &[u8] = &[0x08, 0x82, 0x08, 0x19];
const INCREMENTAL_103: &[u8] = &[0x48, 0x03, b'1', b'0', b'3'];
const DYNAMIC_INDEXED_103: &[u8] = &[0xbe];
const FINAL_HTML: &[u8] = &[
    0x88, 0x0f, 0x10, 0x18, b't', b'e', b'x', b't', b'/', b'h', b't', b'm', b'l', b';', b' ', b'c',
    b'h', b'a', b'r', b's', b'e', b't', b'=', b'u', b't', b'f', b'-', b'8',
];
const FINAL_BODY: &[u8] = b"continuation matrix accepted";

#[tokio::test]
async fn continuation_matrix_preserves_final_response_and_reuse() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = duplex(64 * 1024);
        let (finish_tx, finish_rx) = oneshot::channel();
        let peer = tokio::spawn(run_peer(server, finish_rx));

        let connection = Http2Connection::connect(client, &v152_macos_http2()).await?;
        let response = connection
            .send_get("example.test", target()?, Vec::new())
            .await?;
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers().len(), 1);
        assert_eq!(
            response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .map(http::HeaderValue::as_bytes),
            Some(b"text/html; charset=utf-8".as_slice())
        );
        assert_eq!(
            response.into_body().collect().await?.to_bytes(),
            Bytes::from_static(FINAL_BODY)
        );

        let followup = connection
            .send_get("example.test", target()?, Vec::new())
            .await?;
        assert_eq!(followup.status(), 204);
        assert!(followup.into_body().collect().await?.to_bytes().is_empty());
        assert!(!connection.is_closed());

        finish_tx
            .send(())
            .map_err(|_| "raw peer stopped before connection reuse was checked")?;
        drop(connection);
        peer.await??;
        Ok(())
    })
    .await
}

async fn run_peer(mut stream: DuplexStream, finish: oneshot::Receiver<()>) -> TestResult<()> {
    let mut preface = [0_u8; CLIENT_PREFACE.len()];
    stream.read_exact(&mut preface).await?;
    if preface.as_slice() != CLIENT_PREFACE {
        return Err("client sent an invalid HTTP/2 connection preface".into());
    }

    write_frame(&mut stream, 0x04, 0, 0, &[]).await?;
    stream.flush().await?;

    let mut bounds = PeerBounds::default();
    observe_initial_request(&mut stream, &mut bounds).await?;
    write_continuation_matrix(&mut stream).await?;

    observe_request(&mut stream, 3, &mut bounds).await?;
    write_frame(&mut stream, 0x01, 0x05, 3, &[0x89]).await?;
    stream.flush().await?;

    finish
        .await
        .map_err(|_| "client stopped before confirming stream 3 reuse")?;
    Ok(())
}

async fn observe_initial_request(
    stream: &mut DuplexStream,
    bounds: &mut PeerBounds,
) -> TestResult<()> {
    let mut request_complete = false;
    let mut client_settings = false;
    let mut settings_ack = false;

    while !(request_complete && client_settings && settings_ack) {
        let frame = read_frame(stream, bounds).await?;
        match (frame.frame_type, frame.flags) {
            (0x04, flags) if flags & 0x01 == 0 => {
                if frame.stream_id != 0 || frame.payload.len() % 6 != 0 {
                    return Err("client emitted invalid initial SETTINGS".into());
                }
                client_settings = true;
                write_frame(stream, 0x04, 0x01, 0, &[]).await?;
                stream.flush().await?;
            }
            (0x04, flags) if flags & 0x01 != 0 => {
                if frame.stream_id != 0 || !frame.payload.is_empty() {
                    return Err("client emitted an invalid SETTINGS acknowledgement".into());
                }
                settings_ack = true;
            }
            (0x01, _) => {
                if frame.stream_id != 1 {
                    return Err(format!(
                        "received HEADERS on stream {}, expected stream 1",
                        frame.stream_id
                    )
                    .into());
                }
                finish_field_block(stream, frame, bounds).await?;
                request_complete = true;
            }
            _ => {}
        }
    }
    Ok(())
}

async fn observe_request(
    stream: &mut DuplexStream,
    expected_stream_id: u32,
    bounds: &mut PeerBounds,
) -> TestResult<()> {
    loop {
        let frame = read_frame(stream, bounds).await?;
        match (frame.frame_type, frame.flags) {
            (0x01, _) => {
                if frame.stream_id != expected_stream_id {
                    return Err(format!(
                        "received HEADERS on stream {}, expected stream {expected_stream_id}",
                        frame.stream_id
                    )
                    .into());
                }
                finish_field_block(stream, frame, bounds).await?;
                return Ok(());
            }
            (0x04, flags) if flags & 0x01 == 0 => {
                if frame.stream_id != 0 || frame.payload.len() % 6 != 0 {
                    return Err("client emitted invalid follow-up SETTINGS".into());
                }
                write_frame(stream, 0x04, 0x01, 0, &[]).await?;
                stream.flush().await?;
            }
            _ => {}
        }
    }
}

async fn finish_field_block(
    stream: &mut DuplexStream,
    headers: RawFrame,
    bounds: &mut PeerBounds,
) -> TestResult<()> {
    if headers.flags & 0x04 != 0 {
        return Ok(());
    }
    loop {
        let continuation = read_frame(stream, bounds).await?;
        if continuation.frame_type != 0x09 || continuation.stream_id != headers.stream_id {
            return Err("request HEADERS were interrupted before END_HEADERS".into());
        }
        if continuation.flags & 0x04 != 0 {
            return Ok(());
        }
    }
}

async fn write_continuation_matrix(stream: &mut DuplexStream) -> TestResult<()> {
    write_field_block(stream, RAW_103, &[0, 2, 3]).await?;
    write_field_block(stream, HUFFMAN_103, &[1, 1, 2]).await?;
    write_field_block(stream, INCREMENTAL_103, &[2, 3]).await?;
    write_field_block(stream, DYNAMIC_INDEXED_103, &[1, 0]).await?;
    write_field_block(stream, FINAL_HTML, &[0, 0, FINAL_HTML.len()]).await?;
    write_frame(stream, 0x00, 0x01, 1, FINAL_BODY).await?;
    stream.flush().await?;
    Ok(())
}

async fn write_field_block(
    stream: &mut DuplexStream,
    block: &[u8],
    fragment_lengths: &[usize],
) -> TestResult<()> {
    if fragment_lengths.len() < 2 || fragment_lengths.iter().sum::<usize>() != block.len() {
        return Err("invalid fixed continuation matrix layout".into());
    }

    let mut cursor = 0;
    for (index, &length) in fragment_lengths.iter().enumerate() {
        let end = cursor + length;
        let frame_type = if index == 0 { 0x01 } else { 0x09 };
        let flags = if index + 1 == fragment_lengths.len() {
            0x04
        } else {
            0
        };
        write_frame(stream, frame_type, flags, 1, &block[cursor..end]).await?;
        cursor = end;
    }
    Ok(())
}

async fn write_frame(
    stream: &mut DuplexStream,
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: &[u8],
) -> TestResult<()> {
    let length = u32::try_from(payload.len()).map_err(|_| "peer frame length overflow")?;
    if length > 0x00ff_ffff {
        return Err("peer frame exceeds the HTTP/2 length field".into());
    }
    let mut header = [0_u8; 9];
    header[..3].copy_from_slice(&length.to_be_bytes()[1..]);
    header[3] = frame_type;
    header[4] = flags;
    header[5..].copy_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    stream.write_all(&header).await?;
    stream.write_all(payload).await?;
    Ok(())
}

async fn read_frame(stream: &mut DuplexStream, bounds: &mut PeerBounds) -> TestResult<RawFrame> {
    bounds.frames += 1;
    if bounds.frames > MAX_CLIENT_FRAMES {
        return Err("client exceeded the raw peer frame-count bound".into());
    }

    let mut header = [0_u8; 9];
    stream.read_exact(&mut header).await?;
    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    if length > MAX_CLIENT_FRAME_LEN {
        return Err("client frame exceeded the raw peer length bound".into());
    }
    bounds.bytes = bounds
        .bytes
        .checked_add(9 + length)
        .ok_or("raw peer byte count overflow")?;
    if bounds.bytes > MAX_CLIENT_BYTES {
        return Err("client exceeded the raw peer byte bound".into());
    }

    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).await?;
    Ok(RawFrame {
        frame_type: header[3],
        flags: header[4],
        stream_id: u32::from_be_bytes(header[5..9].try_into()?) & 0x7fff_ffff,
        payload,
    })
}

#[derive(Default)]
struct PeerBounds {
    frames: usize,
    bytes: usize,
}

struct RawFrame {
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}
