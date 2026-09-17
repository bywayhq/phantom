use super::super::{SettingsDecodeError, WindowUpdateDecodeError};
use super::*;
use crate::http2::{CapturedFrame, FrameDecodeError};

#[test]
fn decodes_one_complete_frame_from_wire_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let wire = frame(0x04, 0, 0, &setting(1, 4_096));
    let captured = CapturedFrame::from_wire_bytes(&wire)?;

    assert_eq!(captured.wire_bytes(), wire);
    let settings = captured.settings()?.ok_or("frame was not SETTINGS")?;
    assert_eq!(settings.entries().len(), 1);
    assert_eq!(settings.entries()[0].identifier(), 1);
    assert_eq!(settings.entries()[0].value(), 4_096);
    Ok(())
}

#[test]
fn rejects_incomplete_or_overlong_complete_frames() {
    assert!(matches!(
        CapturedFrame::from_wire_bytes(&[0; 8]),
        Err(FrameDecodeError::TruncatedHeader { length: 8 })
    ));

    let truncated = frame(0x04, 0, 0, &setting(1, 4_096));
    assert!(matches!(
        CapturedFrame::from_wire_bytes(&truncated[..truncated.len() - 1]),
        Err(FrameDecodeError::PayloadLengthMismatch {
            declared: 6,
            actual: 5
        })
    ));

    let mut overlong = frame(0x04, 0, 0, &[]);
    overlong.push(0);
    assert!(matches!(
        CapturedFrame::from_wire_bytes(&overlong),
        Err(FrameDecodeError::PayloadLengthMismatch {
            declared: 0,
            actual: 1
        })
    ));
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
    let Some(decoded_window) = captured.frames()[2].window_update()? else {
        panic!("third captured frame must be WINDOW_UPDATE");
    };
    assert!(!decoded_window.reserved_bit());
    assert_eq!(decoded_window.increment(), 15_663_105);

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
async fn frame_header_preserves_bytes_and_normalizes_reserved_stream_bit()
-> Result<(), Box<dyn std::error::Error>> {
    let reserved_ping = frame(0x06, 0xa5, 0x8000_0003, b"12345678");
    let settings = frame(0x04, 0, 0, &[]);
    let window_update = frame(0x08, 0, 0, &1u32.to_be_bytes());
    let captured = capture(
        client_bytes([settings, reserved_ping.clone(), window_update]),
        CaptureCompletion::InitialSettingsAndConnectionWindowUpdate,
    )
    .await?;
    let header = captured.frames()[1].header();

    assert_eq!(header.wire_bytes(), &reserved_ping[..9]);
    assert_eq!(header.payload_length(), 8);
    assert_eq!(header.frame_type(), 0x06);
    assert_eq!(header.flags(), 0xa5);
    assert!(header.reserved_bit());
    assert_eq!(header.stream_id(), 3);
    assert!(captured.frames()[1].settings()?.is_none());
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
async fn rejects_settings_acknowledgement_as_the_initial_frame() {
    let acknowledgement = frame(0x04, 0x01, 0, &[]);
    let initial = frame(0x04, 0, 0, &setting(6, 262_144));
    let result = capture(
        client_bytes([acknowledgement, initial]),
        CaptureCompletion::InitialSettings,
    )
    .await;

    assert!(matches!(
        result,
        Err(CaptureError::InitialSettingsAcknowledgement)
    ));
}

#[tokio::test]
async fn rejects_non_settings_initial_frame() {
    let result = capture(
        client_bytes([frame(0x06, 0, 0, b"12345678")]),
        CaptureCompletion::InitialSettings,
    )
    .await;

    assert!(matches!(
        result,
        Err(CaptureError::InitialFrameNotSettings { frame_type: 0x06 })
    ));
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
async fn validates_every_occurrence_of_known_settings() {
    let cases = [
        (
            setting(2, 2).to_vec(),
            SettingsDecodeError::InvalidEnablePush { value: 2 },
        ),
        (
            setting(4, 0x8000_0000).to_vec(),
            SettingsDecodeError::InitialWindowSizeTooLarge {
                value: 0x8000_0000,
                maximum: 0x7fff_ffff,
            },
        ),
        (
            setting(5, 16_383).to_vec(),
            SettingsDecodeError::InvalidMaxFrameSize {
                value: 16_383,
                minimum: 16_384,
                maximum: 0x00ff_ffff,
            },
        ),
        (
            setting(5, 0x0100_0000).to_vec(),
            SettingsDecodeError::InvalidMaxFrameSize {
                value: 0x0100_0000,
                minimum: 16_384,
                maximum: 0x00ff_ffff,
            },
        ),
    ];

    for (payload, expected) in cases {
        let result = capture(
            client_bytes([frame(0x04, 0, 0, &payload)]),
            CaptureCompletion::InitialSettings,
        )
        .await;
        assert!(
            matches!(result, Err(CaptureError::InvalidSettings(ref error)) if error == &expected),
            "expected {expected:?}, received {result:?}"
        );
    }

    let mut duplicate_with_invalid_second = setting(2, 0).to_vec();
    duplicate_with_invalid_second.extend_from_slice(&setting(2, 3));
    let result = capture(
        client_bytes([frame(0x04, 0, 0, &duplicate_with_invalid_second)]),
        CaptureCompletion::InitialSettings,
    )
    .await;
    assert!(matches!(
        result,
        Err(CaptureError::InvalidSettings(
            SettingsDecodeError::InvalidEnablePush { value: 3 }
        ))
    ));
}

#[tokio::test]
async fn accepts_known_settings_boundaries_and_unknown_values()
-> Result<(), Box<dyn std::error::Error>> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&setting(2, 1));
    payload.extend_from_slice(&setting(4, 0x7fff_ffff));
    payload.extend_from_slice(&setting(5, 16_384));
    payload.extend_from_slice(&setting(5, 0x00ff_ffff));
    payload.extend_from_slice(&setting(0xf0f0, u32::MAX));

    let captured = capture(
        client_bytes([frame(0x04, 0, 0, &payload)]),
        CaptureCompletion::InitialSettings,
    )
    .await?;
    let Some(settings) = captured.frames()[0].settings()? else {
        panic!("captured frame must be SETTINGS");
    };
    assert_eq!(settings.entries().len(), 5);
    assert_eq!(settings.entries()[4].identifier(), 0xf0f0);
    assert_eq!(settings.entries()[4].value(), u32::MAX);
    Ok(())
}

#[tokio::test]
async fn window_update_exposes_reserved_bit_and_normalized_increment()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = frame(0x04, 0, 0, &[]);
    let update = frame(0x08, 0, 0, &0x8000_002au32.to_be_bytes());
    let captured = capture(
        client_bytes([settings, update]),
        CaptureCompletion::InitialSettingsAndConnectionWindowUpdate,
    )
    .await?;
    let Some(update) = captured.frames()[1].window_update()? else {
        panic!("captured frame must be WINDOW_UPDATE");
    };

    assert!(update.reserved_bit());
    assert_eq!(update.increment(), 42);
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_window_update_length_and_zero_increment() {
    let settings = frame(0x04, 0, 0, &[]);
    let invalid_length = capture(
        client_bytes([settings.clone(), frame(0x08, 0, 0, &[0; 3])]),
        CaptureCompletion::InitialSettingsAndConnectionWindowUpdate,
    )
    .await;
    assert!(matches!(
        invalid_length,
        Err(CaptureError::InvalidWindowUpdate(
            WindowUpdateDecodeError::InvalidPayloadLength { length: 3 }
        ))
    ));

    let zero_increment = capture(
        client_bytes([settings, frame(0x08, 0, 0, &[0; 4])]),
        CaptureCompletion::InitialSettingsAndConnectionWindowUpdate,
    )
    .await;
    assert!(matches!(
        zero_increment,
        Err(CaptureError::InvalidWindowUpdate(
            WindowUpdateDecodeError::ZeroIncrement
        ))
    ));
}
