use phantom_profile::{Http2Setting, Http2Settings, chromium::v152_macos_http2};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

use super::{TestResult, bounded_peer_test, target};
use crate::http2::Http2Connection;

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const MAX_PEER_FRAME_LEN: usize = 64 * 1024;

#[tokio::test]
async fn settings_ack_payload_emits_frame_size_error() -> TestResult<()> {
    bounded_peer_test(run_case(MalformedCase::SettingsAckPayload)).await
}

#[tokio::test]
async fn settings_on_stream_emits_protocol_error() -> TestResult<()> {
    bounded_peer_test(run_case(MalformedCase::SettingsOnStream)).await
}

#[tokio::test]
async fn ping_wrong_length_emits_frame_size_error() -> TestResult<()> {
    bounded_peer_test(run_case(MalformedCase::PingWrongLength)).await
}

#[tokio::test]
async fn ping_on_stream_emits_protocol_error() -> TestResult<()> {
    bounded_peer_test(run_case(MalformedCase::PingOnStream)).await
}

#[tokio::test]
async fn invalid_huffman_eos_emits_compression_error() -> TestResult<()> {
    bounded_peer_test(run_case(MalformedCase::InvalidHuffmanEos)).await
}

#[tokio::test]
async fn interrupted_header_block_emits_protocol_error() -> TestResult<()> {
    bounded_peer_test(run_case(MalformedCase::InterruptedHeaderBlock)).await
}

#[tokio::test]
async fn zero_maximum_frame_size_emits_one_protocol_error() -> TestResult<()> {
    bounded_peer_test(run_case(MalformedCase::ZeroMaximumFrameSize)).await
}

#[tokio::test]
async fn excessive_maximum_frame_size_emits_one_protocol_error() -> TestResult<()> {
    bounded_peer_test(run_case(MalformedCase::ExcessiveMaximumFrameSize)).await
}

#[tokio::test]
async fn empty_continuation_flood_emits_one_calm_error() -> TestResult<()> {
    bounded_peer_test(run_case(MalformedCase::EmptyContinuationFlood)).await
}

#[tokio::test]
async fn cumulative_header_abuse_emits_one_calm_error() -> TestResult<()> {
    bounded_peer_test(run_case(MalformedCase::CumulativeHeaderAbuse)).await
}

#[tokio::test]
async fn encoded_header_block_abuse_emits_one_calm_error() -> TestResult<()> {
    bounded_peer_test(run_case(MalformedCase::EncodedHeaderBlockAbuse)).await
}

#[tokio::test]
async fn nonempty_continuation_flood_emits_one_calm_error() -> TestResult<()> {
    bounded_peer_test(run_case(MalformedCase::NonemptyContinuationFlood)).await
}

async fn run_case(case: MalformedCase) -> TestResult<()> {
    let (client, server) = duplex(64 * 1024);
    let peer = tokio::spawn(run_malformed_peer(server, case));
    let settings = settings_for(case)?;
    let connection = Http2Connection::connect(client, &settings).await?;

    if connection
        .send_get("example.test", target()?, Vec::new())
        .await
        .is_ok()
    {
        return Err(format!("{} was accepted as a response", case.name()).into());
    }

    peer.await??;
    if !connection.is_closed() {
        return Err(format!("{} did not close the connection", case.name()).into());
    }
    Ok(())
}

fn settings_for(case: MalformedCase) -> TestResult<Http2Settings> {
    let mut settings = v152_macos_http2();
    if case.uses_small_header_budget() {
        let maximum = settings
            .initial_settings
            .iter_mut()
            .find_map(|setting| match setting {
                Http2Setting::MaxHeaderListSize(maximum) => Some(maximum),
                _ => None,
            })
            .ok_or("Chrome HTTP/2 fixture omitted MAX_HEADER_LIST_SIZE")?;
        *maximum = 1_024;
    }
    Ok(settings)
}

async fn run_malformed_peer(mut stream: DuplexStream, case: MalformedCase) -> TestResult<()> {
    establish_baseline(&mut stream).await?;
    write_fault(&mut stream, case).await?;
    stream.flush().await?;

    let frame = read_frame(&mut stream)
        .await?
        .ok_or_else(|| format!("{} closed without GOAWAY", case.name()))?;
    if frame.frame_type != 0x07 || frame.flags != 0 || frame.stream_id != 0 {
        return Err(format!(
            "{} produced frame type {:#04x} instead of GOAWAY",
            case.name(),
            frame.frame_type
        )
        .into());
    }
    if frame.payload.len() < 8 {
        return Err(format!("{} produced a truncated GOAWAY", case.name()).into());
    }
    let last_stream_id = u32::from_be_bytes(frame.payload[..4].try_into()?);
    if last_stream_id != 0 {
        return Err(format!(
            "{} produced GOAWAY last-stream ID {last_stream_id}, expected 0",
            case.name()
        )
        .into());
    }
    let reason = u32::from_be_bytes(frame.payload[4..8].try_into()?);
    if reason != case.expected_reason() {
        return Err(format!(
            "{} produced GOAWAY code {reason}, expected {}",
            case.name(),
            case.expected_reason()
        )
        .into());
    }
    let expected = case.expected_debug_data();
    if &frame.payload[8..] != expected {
        return Err(format!(
            "{} produced GOAWAY debug data {:?}, expected {:?}",
            case.name(),
            &frame.payload[8..],
            expected
        )
        .into());
    }
    if read_frame(&mut stream).await?.is_some() {
        return Err(format!("{} produced more than one terminal reaction", case.name()).into());
    }
    Ok(())
}

async fn establish_baseline(stream: &mut DuplexStream) -> TestResult<()> {
    let mut preface = [0_u8; CLIENT_PREFACE.len()];
    stream.read_exact(&mut preface).await?;
    if preface.as_slice() != CLIENT_PREFACE {
        return Err("client sent an invalid HTTP/2 connection preface".into());
    }

    write_frame(stream, 0x04, 0, 0, &[]).await?;
    stream.flush().await?;

    let mut observed_client_settings = false;
    let mut observed_settings_ack = false;
    let mut observed_request = false;
    while !(observed_client_settings && observed_settings_ack && observed_request) {
        let frame = read_frame(stream)
            .await?
            .ok_or("client closed during the valid SETTINGS exchange")?;
        match (frame.frame_type, frame.flags) {
            (0x04, flags) if flags & 0x01 == 0 => {
                if frame.stream_id != 0 {
                    return Err("client sent SETTINGS on a nonzero stream".into());
                }
                observed_client_settings = true;
                write_frame(stream, 0x04, 0x01, 0, &[]).await?;
                stream.flush().await?;
            }
            (0x04, flags) if flags & 0x01 != 0 => {
                if frame.stream_id != 0 || !frame.payload.is_empty() {
                    return Err("client sent an invalid SETTINGS acknowledgement".into());
                }
                observed_settings_ack = true;
            }
            (0x01, _) if frame.stream_id == 1 => observed_request = true,
            _ => {}
        }
    }
    Ok(())
}

async fn write_fault(stream: &mut DuplexStream, case: MalformedCase) -> TestResult<()> {
    match case {
        MalformedCase::SettingsAckPayload => {
            write_frame(stream, 0x04, 0x01, 0, &[0; 6]).await?;
        }
        MalformedCase::SettingsOnStream => {
            write_frame(stream, 0x04, 0, 1, &[]).await?;
        }
        MalformedCase::PingWrongLength => {
            write_frame(stream, 0x06, 0, 0, &[0; 7]).await?;
        }
        MalformedCase::PingOnStream => {
            write_frame(stream, 0x06, 0, 1, &[0; 8]).await?;
        }
        MalformedCase::InvalidHuffmanEos => {
            let field_block = [0x88, 0x00, 0x84, 0xff, 0xff, 0xff, 0xff, 0x00];
            write_frame(stream, 0x01, 0x04, 1, &field_block).await?;
        }
        MalformedCase::InterruptedHeaderBlock => {
            write_frame(stream, 0x01, 0, 1, &[0x88]).await?;
            write_frame(stream, 0x00, 0x01, 1, &[]).await?;
        }
        MalformedCase::ZeroMaximumFrameSize => {
            write_setting(stream, 0x05, 0).await?;
        }
        MalformedCase::ExcessiveMaximumFrameSize => {
            write_setting(stream, 0x05, 0x0100_0000).await?;
        }
        MalformedCase::EmptyContinuationFlood => {
            write_frame(stream, 0x01, 0, 1, &[0x88]).await?;
            for _ in 0..17 {
                write_frame(stream, 0x09, 0, 1, &[]).await?;
            }
        }
        MalformedCase::CumulativeHeaderAbuse => {
            write_cumulative_header_abuse(stream).await?;
        }
        MalformedCase::EncodedHeaderBlockAbuse => {
            let payload = vec![0; 4_109];
            write_frame(stream, 0x01, 0x04, 1, &payload).await?;
        }
        MalformedCase::NonemptyContinuationFlood => {
            write_frame(stream, 0x01, 0, 1, &[0x00, 0x01, b'x', 0xe4]).await?;
            for _ in 0..17 {
                write_frame(stream, 0x09, 0, 1, &[0]).await?;
            }
        }
    }
    Ok(())
}

async fn write_setting(stream: &mut DuplexStream, identifier: u16, value: u32) -> TestResult<()> {
    let mut payload = [0_u8; 6];
    payload[..2].copy_from_slice(&identifier.to_be_bytes());
    payload[2..].copy_from_slice(&value.to_be_bytes());
    write_frame(stream, 0x04, 0, 0, &payload).await
}

async fn write_cumulative_header_abuse(stream: &mut DuplexStream) -> TestResult<()> {
    // Each five-byte block is the legal HPACK literal `x: a`; the value uses
    // the static Huffman code for `a`. Its decoded header-list cost is 34 bytes.
    const HUFFMAN_FIELD: &[u8] = &[0x00, 0x01, b'x', 0x81, 0x1f];
    const FIELDS_PER_FRAGMENT: usize = 40;
    const CONTINUATION_FRAGMENTS: usize = 3;

    write_frame(stream, 0x01, 0, 1, &[0x88]).await?;
    let fragment = HUFFMAN_FIELD.repeat(FIELDS_PER_FRAGMENT);
    for _ in 0..CONTINUATION_FRAGMENTS {
        write_frame(stream, 0x09, 0, 1, &fragment).await?;
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

async fn read_frame(stream: &mut DuplexStream) -> TestResult<Option<RawFrame>> {
    let mut header = [0_u8; 9];
    if stream.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut header[1..]).await?;
    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    if length > MAX_PEER_FRAME_LEN {
        return Err("client frame exceeded the malformed peer bound".into());
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).await?;
    Ok(Some(RawFrame {
        frame_type: header[3],
        flags: header[4],
        stream_id: u32::from_be_bytes(header[5..9].try_into()?),
        payload,
    }))
}

#[derive(Clone, Copy)]
enum MalformedCase {
    SettingsAckPayload,
    SettingsOnStream,
    PingWrongLength,
    PingOnStream,
    InvalidHuffmanEos,
    InterruptedHeaderBlock,
    ZeroMaximumFrameSize,
    ExcessiveMaximumFrameSize,
    EmptyContinuationFlood,
    CumulativeHeaderAbuse,
    EncodedHeaderBlockAbuse,
    NonemptyContinuationFlood,
}

impl MalformedCase {
    fn name(self) -> &'static str {
        match self {
            Self::SettingsAckPayload => "SETTINGS ACK payload",
            Self::SettingsOnStream => "SETTINGS on stream 1",
            Self::PingWrongLength => "PING wrong length",
            Self::PingOnStream => "PING on stream 1",
            Self::InvalidHuffmanEos => "invalid HPACK Huffman EOS",
            Self::InterruptedHeaderBlock => "interrupted header block",
            Self::ZeroMaximumFrameSize => "zero SETTINGS_MAX_FRAME_SIZE",
            Self::ExcessiveMaximumFrameSize => "excessive SETTINGS_MAX_FRAME_SIZE",
            Self::EmptyContinuationFlood => "empty CONTINUATION flood",
            Self::CumulativeHeaderAbuse => "cumulative header-list abuse",
            Self::EncodedHeaderBlockAbuse => "encoded header-block abuse",
            Self::NonemptyContinuationFlood => "nonempty CONTINUATION flood",
        }
    }

    fn expected_reason(self) -> u32 {
        match self {
            Self::SettingsAckPayload | Self::PingWrongLength => 6,
            Self::SettingsOnStream
            | Self::PingOnStream
            | Self::InterruptedHeaderBlock
            | Self::ZeroMaximumFrameSize
            | Self::ExcessiveMaximumFrameSize => 1,
            Self::InvalidHuffmanEos => 9,
            Self::EmptyContinuationFlood
            | Self::CumulativeHeaderAbuse
            | Self::EncodedHeaderBlockAbuse
            | Self::NonemptyContinuationFlood => 11,
        }
    }

    fn expected_debug_data(self) -> &'static [u8] {
        match self {
            Self::EmptyContinuationFlood => b"too_many_empty_continuations",
            Self::CumulativeHeaderAbuse => b"header_list_way_too_large",
            Self::EncodedHeaderBlockAbuse => b"header_block_too_large",
            Self::NonemptyContinuationFlood => b"too_many_continuations",
            _ => b"",
        }
    }

    fn uses_small_header_budget(self) -> bool {
        matches!(
            self,
            Self::CumulativeHeaderAbuse
                | Self::EncodedHeaderBlockAbuse
                | Self::NonemptyContinuationFlood
        )
    }
}

struct RawFrame {
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}
