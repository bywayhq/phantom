use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use tokio::io::AsyncWriteExt;

use super::*;

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
async fn stream_window_update_does_not_complete_connection_capture() {
    let settings = frame(0x04, 0, 0, &[]);
    let stream_update = frame(0x08, 0, 1, &42u32.to_be_bytes());
    let result = capture(
        client_bytes([settings, stream_update]),
        CaptureCompletion::InitialSettingsAndConnectionWindowUpdate,
    )
    .await;

    assert!(matches!(
        result,
        Err(CaptureError::InputEndedBeforeCompletion {
            completion: CaptureCompletion::InitialSettingsAndConnectionWindowUpdate
        })
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
async fn distinguishes_clean_end_before_completion_from_partial_frame_header() {
    let settings = frame(0x04, 0, 0, &[]);
    let clean_end = capture(
        client_bytes([settings.clone()]),
        CaptureCompletion::InitialSettingsAndConnectionWindowUpdate,
    )
    .await;
    assert!(matches!(
        clean_end,
        Err(CaptureError::InputEndedBeforeCompletion {
            completion: CaptureCompletion::InitialSettingsAndConnectionWindowUpdate
        })
    ));

    let mut partial = client_bytes([settings]);
    partial.push(0);
    assert!(matches!(
        capture(
            partial,
            CaptureCompletion::InitialSettingsAndConnectionWindowUpdate
        )
        .await,
        Err(CaptureError::TruncatedFrameHeader)
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
