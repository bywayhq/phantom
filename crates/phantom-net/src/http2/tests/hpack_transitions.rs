use http_body_util::BodyExt;
use phantom_profile::chromium::v152_http2;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex},
    sync::oneshot,
};

use super::{TestResult, bounded_peer_test, target};
use crate::http2::Http2Connection;

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const PING_PAYLOAD: &[u8] = b"PHANTM01";
const MAX_CLIENT_FRAME_LEN: usize = 64 * 1024;
const MAX_CLIENT_FRAMES: usize = 32;
const MAX_FIELD_BLOCK_LEN: usize = 64 * 1024;

const HEADER_TABLE_ZERO_AND_UNKNOWN: &[u8] = &[
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // HEADER_TABLE_SIZE = 0
    0xf0, 0xf0, 0x52, 0x50, 0x52, 0x31, // unknown = "RPR1"
];
const HEADER_TABLE_ZERO_UNKNOWN_AND_DEFAULT: &[u8] = &[
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // HEADER_TABLE_SIZE = 0
    0xf0, 0xf0, 0x52, 0x50, 0x52, 0x31, // unknown = "RPR1"
    0x00, 0x01, 0x00, 0x00, 0x10, 0x00, // HEADER_TABLE_SIZE = 4096
];

const HEADER_TABLE_65536: &[u8] = &[
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // HEADER_TABLE_SIZE = 65,536
];
const HEADER_TABLE_MAXIMUM: &[u8] = &[
    0x00, 0x01, 0xff, 0xff, 0xff, 0xff, // HEADER_TABLE_SIZE = 2^32 - 1
];

#[tokio::test]
async fn initial_zero_table_size_starts_first_field_block_with_update() -> TestResult<()> {
    bounded_peer_test(run_case(HEADER_TABLE_ZERO_AND_UNKNOWN, &[0x20])).await
}

#[tokio::test]
async fn duplicate_initial_table_sizes_preserve_minimum_then_final_update() -> TestResult<()> {
    bounded_peer_test(run_case(
        HEADER_TABLE_ZERO_UNKNOWN_AND_DEFAULT,
        &[0x20, 0x3f, 0xe1, 0x1f],
    ))
    .await
}

// Chromium's quiche HpackEncoder and Firefox's Http2Compressor both adopt a
// larger peer table size without a cap and announce it in the next field
// block, so the update must not be clamped.
#[tokio::test]
async fn larger_peer_table_size_is_announced_uncapped() -> TestResult<()> {
    bounded_peer_test(run_case(HEADER_TABLE_65536, &[0x3f, 0xe1, 0xff, 0x03])).await
}

#[tokio::test]
async fn maximum_peer_table_size_is_announced_and_connection_stays_usable() -> TestResult<()> {
    bounded_peer_test(run_case(
        HEADER_TABLE_MAXIMUM,
        &[0x3f, 0xe0, 0xff, 0xff, 0xff, 0x0f],
    ))
    .await
}

async fn run_case(settings: &'static [u8], expected_prefix: &'static [u8]) -> TestResult<()> {
    let (client, server) = duplex(64 * 1024);
    let (ready_tx, ready_rx) = oneshot::channel();
    let (finish_tx, finish_rx) = oneshot::channel();
    let peer = tokio::spawn(run_peer(
        server,
        settings,
        expected_prefix,
        ready_tx,
        finish_rx,
    ));

    let connection = Http2Connection::connect(client, &v152_http2()).await?;
    ready_rx
        .await
        .map_err(|_| "raw peer stopped before acknowledging initial controls")?;

    for _ in 0..2 {
        let response = connection
            .send_get("example.test", target()?, Vec::new())
            .await?;
        assert_eq!(response.status(), 204);
        assert!(response.into_body().collect().await?.to_bytes().is_empty());
    }
    assert!(!connection.is_closed());

    finish_tx
        .send(())
        .map_err(|_| "raw peer stopped before connection reuse was checked")?;
    drop(connection);
    peer.await??;
    Ok(())
}

async fn run_peer(
    mut stream: DuplexStream,
    settings: &'static [u8],
    expected_prefix: &'static [u8],
    ready: oneshot::Sender<()>,
    finish: oneshot::Receiver<()>,
) -> TestResult<()> {
    let mut preface = [0_u8; CLIENT_PREFACE.len()];
    stream.read_exact(&mut preface).await?;
    if preface.as_slice() != CLIENT_PREFACE {
        return Err("client sent an invalid HTTP/2 connection preface".into());
    }

    write_frame(&mut stream, 0x04, 0, 0, settings).await?;
    write_frame(&mut stream, 0x06, 0, 0, PING_PAYLOAD).await?;
    stream.flush().await?;

    let mut frame_count = 0;
    observe_initial_control_exchange(&mut stream, &mut frame_count).await?;
    ready
        .send(())
        .map_err(|_| "client stopped before the initial control exchange completed")?;

    let first = read_field_block(&mut stream, 1, &mut frame_count).await?;
    if !first.starts_with(expected_prefix) {
        return Err(format!(
            "stream 1 HPACK block started with {:02x?}, expected {:02x?}",
            first.get(..expected_prefix.len()),
            expected_prefix,
        )
        .into());
    }
    write_no_content_response(&mut stream, 1).await?;

    let second = read_field_block(&mut stream, 3, &mut frame_count).await?;
    if second.is_empty() {
        return Err("stream 3 carried an empty HPACK field block".into());
    }
    write_no_content_response(&mut stream, 3).await?;

    finish
        .await
        .map_err(|_| "client stopped before confirming connection reuse")?;
    Ok(())
}

async fn observe_initial_control_exchange(
    stream: &mut DuplexStream,
    frame_count: &mut usize,
) -> TestResult<()> {
    let mut observed_settings_ack = false;
    let mut observed_ping_ack = false;

    while !(observed_settings_ack && observed_ping_ack) {
        let frame = read_frame(stream, frame_count).await?;
        match (frame.frame_type, frame.flags) {
            (0x04, flags) if flags & 0x01 == 0 => {
                if frame.stream_id != 0 || frame.payload.len() % 6 != 0 {
                    return Err("client emitted invalid initial SETTINGS".into());
                }
                write_frame(stream, 0x04, 0x01, 0, &[]).await?;
                stream.flush().await?;
            }
            (0x04, flags) if flags & 0x01 != 0 => {
                if frame.stream_id != 0 || !frame.payload.is_empty() {
                    return Err("client emitted an invalid SETTINGS acknowledgement".into());
                }
                observed_settings_ack = true;
            }
            (0x06, flags) if flags & 0x01 != 0 => {
                if frame.stream_id != 0 || frame.payload.as_slice() != PING_PAYLOAD {
                    return Err("client PING acknowledgement changed the opaque payload".into());
                }
                observed_ping_ack = true;
            }
            _ => {}
        }
    }
    Ok(())
}

async fn read_field_block(
    stream: &mut DuplexStream,
    expected_stream_id: u32,
    frame_count: &mut usize,
) -> TestResult<Vec<u8>> {
    let headers = loop {
        let frame = read_frame(stream, frame_count).await?;
        if frame.frame_type == 0x01 {
            if frame.stream_id != expected_stream_id {
                return Err(format!(
                    "received HEADERS on stream {}, expected stream {expected_stream_id}",
                    frame.stream_id
                )
                .into());
            }
            break frame;
        }
    };

    let end_headers = headers.flags & 0x04 != 0;
    let mut field_block = headers_fragment(&headers)?;
    ensure_field_block_bound(&field_block)?;
    if end_headers {
        return Ok(field_block);
    }

    loop {
        let continuation = read_frame(stream, frame_count).await?;
        if continuation.frame_type != 0x09 || continuation.stream_id != expected_stream_id {
            return Err("HEADERS field block was interrupted before END_HEADERS".into());
        }
        field_block.extend_from_slice(&continuation.payload);
        ensure_field_block_bound(&field_block)?;
        if continuation.flags & 0x04 != 0 {
            return Ok(field_block);
        }
    }
}

fn headers_fragment(frame: &RawFrame) -> TestResult<Vec<u8>> {
    let mut start = 0;
    let padding = if frame.flags & 0x08 != 0 {
        let padding = usize::from(
            *frame
                .payload
                .first()
                .ok_or("padded HEADERS omitted the pad length")?,
        );
        start += 1;
        padding
    } else {
        0
    };
    if frame.flags & 0x20 != 0 {
        start += 5;
    }
    let end = frame
        .payload
        .len()
        .checked_sub(padding)
        .ok_or("HEADERS padding exceeded its payload")?;
    if start > end {
        return Err("HEADERS metadata exceeded its payload".into());
    }
    Ok(frame.payload[start..end].to_vec())
}

fn ensure_field_block_bound(field_block: &[u8]) -> TestResult<()> {
    if field_block.len() > MAX_FIELD_BLOCK_LEN {
        return Err("client HPACK field block exceeded the peer bound".into());
    }
    Ok(())
}

async fn write_no_content_response(stream: &mut DuplexStream, stream_id: u32) -> TestResult<()> {
    write_frame(stream, 0x01, 0x05, stream_id, &[0x89]).await?;
    stream.flush().await?;
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

async fn read_frame(stream: &mut DuplexStream, frame_count: &mut usize) -> TestResult<RawFrame> {
    *frame_count += 1;
    if *frame_count > MAX_CLIENT_FRAMES {
        return Err("client exceeded the raw peer frame-count bound".into());
    }

    let mut header = [0_u8; 9];
    stream.read_exact(&mut header).await?;
    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    if length > MAX_CLIENT_FRAME_LEN {
        return Err("client frame exceeded the raw peer length bound".into());
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

struct RawFrame {
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}
