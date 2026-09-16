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
const PING_PAYLOAD: &[u8] = b"REAPER01";
const MAX_PEER_FRAME_LEN: usize = 64 * 1024;

#[tokio::test]
async fn legal_control_and_fragmentation_probes_preserve_connection() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = duplex(64 * 1024);
        let (finish_tx, finish_rx) = oneshot::channel();
        let peer = tokio::spawn(run_adversarial_peer(server, finish_rx));

        let connection = Http2Connection::connect(client, &v152_macos_http2()).await?;
        let first = connection
            .send_get("example.test", target()?, Vec::new())
            .await?;
        assert_eq!(first.status(), 200);
        assert_eq!(
            first
                .headers()
                .get("x-probe")
                .and_then(|value| value.to_str().ok()),
            Some("accepted")
        );
        assert_eq!(
            first.into_body().collect().await?.to_bytes(),
            Bytes::from_static(b"first")
        );

        let second = connection
            .send_get("example.test", target()?, Vec::new())
            .await?;
        assert_eq!(second.status(), 204);
        assert!(second.into_body().collect().await?.to_bytes().is_empty());
        assert!(!connection.is_closed());

        finish_tx
            .send(())
            .map_err(|_| "adversarial peer stopped before connection reuse was checked")?;
        drop(connection);
        peer.await??;
        Ok(())
    })
    .await
}

async fn run_adversarial_peer(
    mut stream: DuplexStream,
    finish: oneshot::Receiver<()>,
) -> TestResult<()> {
    let mut preface = [0_u8; CLIENT_PREFACE.len()];
    stream.read_exact(&mut preface).await?;
    if preface.as_slice() != CLIENT_PREFACE {
        return Err("client sent an invalid HTTP/2 connection preface".into());
    }

    let mut settings = Vec::with_capacity(6);
    settings.extend_from_slice(&0xf0f0_u16.to_be_bytes());
    settings.extend_from_slice(&0x5250_5231_u32.to_be_bytes());
    write_frame(&mut stream, 0x04, 0, 0, &settings).await?;
    write_frame(&mut stream, 0xf0, 0, 0, &[]).await?;
    write_frame(&mut stream, 0x06, 0, 0, PING_PAYLOAD).await?;
    stream.flush().await?;

    observe_request_and_control_acks(&mut stream, 1).await?;
    write_fragmented_response(&mut stream).await?;

    observe_request(&mut stream, 3).await?;
    write_frame(&mut stream, 0x01, 0x05, 3, &[0x89]).await?;
    stream.flush().await?;

    finish
        .await
        .map_err(|_| "client stopped before confirming connection reuse")?;
    Ok(())
}

async fn observe_request_and_control_acks(
    stream: &mut DuplexStream,
    expected_stream_id: u32,
) -> TestResult<()> {
    let mut observed_request = false;
    let mut observed_settings_ack = false;
    let mut observed_ping_ack = false;

    while !(observed_request && observed_settings_ack && observed_ping_ack) {
        let frame = read_frame(stream).await?;
        match (frame.frame_type, frame.flags) {
            (0x04, flags) if flags & 0x01 == 0 => {
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
            (0x01, _) if frame.stream_id == expected_stream_id => observed_request = true,
            _ => {}
        }
    }
    Ok(())
}

async fn observe_request(stream: &mut DuplexStream, expected_stream_id: u32) -> TestResult<()> {
    loop {
        let frame = read_frame(stream).await?;
        if frame.frame_type == 0x01 && frame.stream_id == expected_stream_id {
            return Ok(());
        }
    }
}

async fn write_fragmented_response(stream: &mut DuplexStream) -> TestResult<()> {
    let mut field_block = Vec::from([0x88, 0x00, 0x07]);
    field_block.extend_from_slice(b"x-probe");
    field_block.push(0x08);
    field_block.extend_from_slice(b"accepted");

    write_frame(stream, 0x01, 0, 1, &field_block[..1]).await?;
    write_frame(stream, 0x09, 0, 1, &[]).await?;
    write_frame(stream, 0x09, 0x04, 1, &field_block[1..]).await?;
    write_frame(stream, 0x00, 0x01, 1, b"first").await?;
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

async fn read_frame(stream: &mut DuplexStream) -> TestResult<RawFrame> {
    let mut header = [0_u8; 9];
    stream.read_exact(&mut header).await?;
    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    if length > MAX_PEER_FRAME_LEN {
        return Err("client frame exceeded the adversarial peer bound".into());
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
