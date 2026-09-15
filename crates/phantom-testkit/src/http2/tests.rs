use std::{
    io::Cursor,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};

use super::{
    CLIENT_CONNECTION_PREFACE, CaptureCompletion, CaptureError, CaptureLimits, SettingsDecodeError,
    capture_client_frames,
};

const GENEROUS_LIMITS: CaptureLimits = CaptureLimits::new(64 * 1024, 128 * 1024, 16);

fn frame(frame_type: u8, flags: u8, raw_stream_id: u32, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= 0x00ff_ffff);
    let length = payload.len();
    let mut wire = vec![
        ((length >> 16) & 0xff) as u8,
        ((length >> 8) & 0xff) as u8,
        (length & 0xff) as u8,
        frame_type,
        flags,
    ];
    wire.extend_from_slice(&raw_stream_id.to_be_bytes());
    wire.extend_from_slice(payload);
    wire
}

fn setting(identifier: u16, value: u32) -> [u8; 6] {
    let identifier = identifier.to_be_bytes();
    let value = value.to_be_bytes();
    [
        identifier[0],
        identifier[1],
        value[0],
        value[1],
        value[2],
        value[3],
    ]
}

fn client_bytes(frames: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    let mut wire = CLIENT_CONNECTION_PREFACE.to_vec();
    for frame in frames {
        wire.extend_from_slice(&frame);
    }
    wire
}

async fn capture(
    bytes: Vec<u8>,
    completion: CaptureCompletion,
) -> Result<super::ClientFrameCapture, CaptureError> {
    let mut reader = OneByteReader::new(bytes, usize::MAX);
    capture_client_frames(
        &mut reader,
        tokio::time::Instant::now() + Duration::from_secs(1),
        GENEROUS_LIMITS,
        completion,
    )
    .await
}

#[tokio::test]
async fn captures_settings_and_connection_window_update_from_one_byte_reads()
-> Result<(), Box<dyn std::error::Error>> {
    let mut settings_payload = Vec::new();
    settings_payload.extend_from_slice(&setting(1, 65_536));
    settings_payload.extend_from_slice(&setting(0xf0f0, 7));
    let settings = frame(0x04, 0, 0, &settings_payload);
    let ping = frame(0x06, 0, 0, b"12345678");
    let window_update = frame(0x08, 0, 0, &15_663_105u32.to_be_bytes());
    let wire = client_bytes([settings.clone(), ping.clone(), window_update.clone()]);
    let mut reader = OneByteReader::new(wire, 1);

    let captured = capture_client_frames(
        &mut reader,
        tokio::time::Instant::now() + Duration::from_secs(1),
        GENEROUS_LIMITS,
        CaptureCompletion::InitialSettingsAndConnectionWindowUpdate,
    )
    .await?;

    assert_eq!(captured.preface_bytes(), CLIENT_CONNECTION_PREFACE);
    assert_eq!(captured.frames().len(), 3);
    assert_eq!(captured.frames()[0].wire_bytes(), settings);
    assert_eq!(captured.frames()[1].wire_bytes(), ping);
    assert_eq!(captured.frames()[2].wire_bytes(), window_update);
    assert_eq!(captured.frames()[0].payload(), settings_payload);

    let Some(decoded) = captured.frames()[0].settings()? else {
        panic!("first captured frame must be SETTINGS");
    };
    assert!(!decoded.is_acknowledgement());
    assert_eq!(decoded.entries().len(), 2);
    assert_eq!(decoded.entries()[0].identifier(), 1);
    assert_eq!(decoded.entries()[0].value(), 65_536);
    assert_eq!(decoded.entries()[1].identifier(), 0xf0f0);
    assert_eq!(decoded.entries()[1].value(), 7);
    Ok(())
}

#[tokio::test]
async fn settings_completion_stops_before_following_frame() -> Result<(), Box<dyn std::error::Error>>
{
    let settings = frame(0x04, 0, 0, &setting(2, 0));
    let trailing = frame(0x01, 0x05, 1, &[0xaa]);
    let wire = client_bytes([settings.clone(), trailing]);
    let mut reader = OneByteReader::new(wire, usize::MAX);

    let captured = capture_client_frames(
        &mut reader,
        tokio::time::Instant::now() + Duration::from_secs(1),
        GENEROUS_LIMITS,
        CaptureCompletion::InitialSettings,
    )
    .await?;

    assert_eq!(captured.frames().len(), 1);
    assert_eq!(captured.frames()[0].wire_bytes(), settings);
    assert_eq!(
        reader.consumed(),
        CLIENT_CONNECTION_PREFACE.len() + settings.len()
    );
    Ok(())
}

#[tokio::test]
async fn frame_header_preserves_bytes_and_normalizes_reserved_stream_bit()
-> Result<(), Box<dyn std::error::Error>> {
    let reserved_ping = frame(0x06, 0xa5, 0x8000_0003, b"12345678");
    let settings = frame(0x04, 0, 0, &[]);
    let captured = capture(
        client_bytes([reserved_ping.clone(), settings]),
        CaptureCompletion::InitialSettings,
    )
    .await?;
    let header = captured.frames()[0].header();

    assert_eq!(header.wire_bytes(), &reserved_ping[..9]);
    assert_eq!(header.payload_length(), 8);
    assert_eq!(header.frame_type(), 0x06);
    assert_eq!(header.flags(), 0xa5);
    assert!(header.reserved_bit());
    assert_eq!(header.stream_id(), 3);
    assert!(captured.frames()[0].settings()?.is_none());
    Ok(())
}

#[tokio::test]
async fn settings_preserve_duplicate_identifiers_in_wire_order()
-> Result<(), Box<dyn std::error::Error>> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&setting(4, 65_535));
    payload.extend_from_slice(&setting(1, 4_096));
    payload.extend_from_slice(&setting(4, 6_291_456));
    let captured = capture(
        client_bytes([frame(0x04, 0, 0, &payload)]),
        CaptureCompletion::InitialSettings,
    )
    .await?;
    let Some(settings) = captured.frames()[0].settings()? else {
        panic!("captured frame must be SETTINGS");
    };

    let entries: Vec<_> = settings
        .entries()
        .iter()
        .map(|entry| (entry.identifier(), entry.value()))
        .collect();
    assert_eq!(entries, [(4, 65_535), (1, 4_096), (4, 6_291_456)]);
    Ok(())
}

#[tokio::test]
async fn accepts_empty_settings_acknowledgement_before_initial_settings()
-> Result<(), Box<dyn std::error::Error>> {
    let acknowledgement = frame(0x04, 0x01, 0, &[]);
    let initial = frame(0x04, 0, 0, &setting(6, 262_144));
    let captured = capture(
        client_bytes([acknowledgement, initial]),
        CaptureCompletion::InitialSettings,
    )
    .await?;

    assert_eq!(captured.frames().len(), 2);
    let Some(ack) = captured.frames()[0].settings()? else {
        panic!("captured frame must be SETTINGS");
    };
    assert!(ack.is_acknowledgement());
    assert!(ack.entries().is_empty());
    Ok(())
}

#[tokio::test]
async fn rejects_settings_on_a_stream() {
    let result = capture(
        client_bytes([frame(0x04, 0, 3, &[])]),
        CaptureCompletion::InitialSettings,
    )
    .await;

    assert!(matches!(
        result,
        Err(CaptureError::InvalidSettings(
            SettingsDecodeError::NonZeroStream { stream_id: 3 }
        ))
    ));
}

#[tokio::test]
async fn rejects_settings_acknowledgement_with_payload() {
    let result = capture(
        client_bytes([frame(0x04, 0x01, 0, &setting(1, 10))]),
        CaptureCompletion::InitialSettings,
    )
    .await;

    assert!(matches!(
        result,
        Err(CaptureError::InvalidSettings(
            SettingsDecodeError::AckWithPayload { length: 6 }
        ))
    ));
}

#[tokio::test]
async fn rejects_settings_payload_not_divisible_into_entries() {
    let result = capture(
        client_bytes([frame(0x04, 0, 0, &[0; 5])]),
        CaptureCompletion::InitialSettings,
    )
    .await;

    assert!(matches!(
        result,
        Err(CaptureError::InvalidSettings(
            SettingsDecodeError::InvalidPayloadLength { length: 5 }
        ))
    ));
}

#[tokio::test]
async fn rejects_invalid_and_truncated_prefaces() {
    let mut invalid = CLIENT_CONNECTION_PREFACE.to_vec();
    invalid[5] = b'!';
    assert!(matches!(
        capture(invalid, CaptureCompletion::InitialSettings).await,
        Err(CaptureError::InvalidPreface {
            index: 5,
            expected: b' ',
            actual: b'!'
        })
    ));

    assert!(matches!(
        capture(
            CLIENT_CONNECTION_PREFACE[..23].to_vec(),
            CaptureCompletion::InitialSettings
        )
        .await,
        Err(CaptureError::TruncatedPreface)
    ));
}

#[tokio::test]
async fn rejects_truncated_frame_header_and_payload() {
    let mut truncated_header = CLIENT_CONNECTION_PREFACE.to_vec();
    truncated_header.extend_from_slice(&[0, 0, 6, 4]);
    assert!(matches!(
        capture(truncated_header, CaptureCompletion::InitialSettings).await,
        Err(CaptureError::TruncatedFrameHeader)
    ));

    let mut truncated_payload = CLIENT_CONNECTION_PREFACE.to_vec();
    truncated_payload.extend_from_slice(&frame(0x04, 0, 0, &setting(1, 1))[..12]);
    assert!(matches!(
        capture(truncated_payload, CaptureCompletion::InitialSettings).await,
        Err(CaptureError::TruncatedFramePayload { expected: 6 })
    ));
}

#[tokio::test]
async fn enforces_preface_total_limit_before_reading() {
    let wire = client_bytes([frame(0x04, 0, 0, &[])]);
    let mut reader = OneByteReader::new(wire, usize::MAX);
    let limits = CaptureLimits::new(64, CLIENT_CONNECTION_PREFACE.len() - 1, 1);

    let result = capture_client_frames(
        &mut reader,
        tokio::time::Instant::now() + Duration::from_secs(1),
        limits,
        CaptureCompletion::InitialSettings,
    )
    .await;

    assert!(matches!(
        result,
        Err(CaptureError::TotalByteLimitExceeded {
            attempted: 24,
            maximum: 23
        })
    ));
    assert_eq!(reader.consumed(), 0);
}

#[tokio::test]
async fn enforces_frame_count_limit_before_reading_a_header() {
    let wire = client_bytes([frame(0x04, 0, 0, &[])]);
    let mut reader = OneByteReader::new(wire, usize::MAX);
    let limits = CaptureLimits::new(64, 128, 0);

    let result = capture_client_frames(
        &mut reader,
        tokio::time::Instant::now() + Duration::from_secs(1),
        limits,
        CaptureCompletion::InitialSettings,
    )
    .await;

    assert!(matches!(
        result,
        Err(CaptureError::FrameCountLimitExceeded { maximum: 0 })
    ));
    assert_eq!(reader.consumed(), CLIENT_CONNECTION_PREFACE.len());
}

#[tokio::test]
async fn enforces_frame_payload_limit_before_reading_or_allocating_payload() {
    let wire = client_bytes([frame(0x04, 0, 0, &setting(1, 1))]);
    let mut reader = OneByteReader::new(wire, usize::MAX);
    let limits = CaptureLimits::new(5, 128, 1);

    let result = capture_client_frames(
        &mut reader,
        tokio::time::Instant::now() + Duration::from_secs(1),
        limits,
        CaptureCompletion::InitialSettings,
    )
    .await;

    assert!(matches!(
        result,
        Err(CaptureError::FramePayloadLimitExceeded {
            length: 6,
            maximum: 5
        })
    ));
    assert_eq!(reader.consumed(), CLIENT_CONNECTION_PREFACE.len() + 9);
}

#[tokio::test]
async fn enforces_total_limit_before_reading_or_allocating_payload() {
    let wire = client_bytes([frame(0x04, 0, 0, &setting(1, 1))]);
    let mut reader = OneByteReader::new(wire, usize::MAX);
    let maximum = CLIENT_CONNECTION_PREFACE.len() + 9 + 5;
    let limits = CaptureLimits::new(64, maximum, 1);

    let result = capture_client_frames(
        &mut reader,
        tokio::time::Instant::now() + Duration::from_secs(1),
        limits,
        CaptureCompletion::InitialSettings,
    )
    .await;

    assert!(matches!(
        result,
        Err(CaptureError::TotalByteLimitExceeded { attempted, maximum: limit })
            if attempted == CLIENT_CONNECTION_PREFACE.len() + 9 + 6 && limit == maximum
    ));
    assert_eq!(reader.consumed(), CLIENT_CONNECTION_PREFACE.len() + 9);
}

#[tokio::test]
async fn enforces_frame_header_total_limit_before_reading_header() {
    let wire = client_bytes([frame(0x04, 0, 0, &[])]);
    let mut reader = OneByteReader::new(wire, usize::MAX);
    let maximum = CLIENT_CONNECTION_PREFACE.len() + 8;
    let limits = CaptureLimits::new(64, maximum, 1);

    let result = capture_client_frames(
        &mut reader,
        tokio::time::Instant::now() + Duration::from_secs(1),
        limits,
        CaptureCompletion::InitialSettings,
    )
    .await;

    assert!(matches!(
        result,
        Err(CaptureError::TotalByteLimitExceeded { attempted, maximum: limit })
            if attempted == CLIENT_CONNECTION_PREFACE.len() + 9 && limit == maximum
    ));
    assert_eq!(reader.consumed(), CLIENT_CONNECTION_PREFACE.len());
}

#[tokio::test]
async fn deadline_does_not_restart_when_reads_make_progress() {
    let (mut reader, mut writer) = tokio::io::duplex(64);
    let wire = client_bytes([frame(0x04, 0, 0, &setting(1, 1))]);
    let writes = Arc::new(AtomicUsize::new(0));
    let observed_writes = Arc::clone(&writes);
    let writer_task = tokio::spawn(async move {
        for byte in wire {
            if writer.write_all(&[byte]).await.is_err() {
                break;
            }
            observed_writes.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });

    let result = capture_client_frames(
        &mut reader,
        tokio::time::Instant::now() + Duration::from_millis(35),
        GENEROUS_LIMITS,
        CaptureCompletion::InitialSettings,
    )
    .await;
    writer_task.abort();
    let _ = writer_task.await;

    assert!(writes.load(Ordering::SeqCst) > 1);
    assert!(matches!(result, Err(CaptureError::DeadlineExceeded)));
}

struct OneByteReader {
    bytes: Cursor<Vec<u8>>,
    max_read: usize,
}

impl OneByteReader {
    fn new(bytes: Vec<u8>, max_read: usize) -> Self {
        Self {
            bytes: Cursor::new(bytes),
            max_read,
        }
    }

    fn consumed(&self) -> usize {
        usize::try_from(self.bytes.position()).unwrap_or(usize::MAX)
    }
}

impl AsyncRead for OneByteReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let start = self.consumed();
        let available = self.bytes.get_ref().len().saturating_sub(start);
        let count = available.min(buffer.remaining()).min(self.max_read);
        if count > 0 {
            buffer.put_slice(&self.bytes.get_ref()[start..start + count]);
            self.bytes.set_position((start + count) as u64);
        }
        Poll::Ready(Ok(()))
    }
}
