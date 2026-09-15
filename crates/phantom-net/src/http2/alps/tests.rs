use super::{DecodeErrorKind, PeerApplicationSettings, decode};

#[test]
fn preserves_absent_empty_and_empty_settings_frame() {
    let absent = decode_ok(None);
    assert!(matches!(absent, PeerApplicationSettings::Absent));

    let empty = decode_ok(Some(&[]));
    assert_eq!(empty.frame_count(), Some(0));
    assert_eq!(empty.settings_frame_count(), Some(0));
    assert!(empty.into_initial_settings().is_none());

    let empty_frame = frame(4, 0, 0, &[]);
    let empty_frame = decode_ok(Some(&empty_frame));
    assert_eq!(empty_frame.frame_count(), Some(1));
    assert_eq!(empty_frame.settings_frame_count(), Some(1));
    assert!(empty_frame.into_initial_settings().is_some());
}

#[test]
fn applies_every_supported_setting() {
    let payload = settings(&[
        (1, 128),
        (2, 0),
        (3, 17),
        (4, 1_000_000),
        (5, 32_768),
        (6, 64_000),
        (8, 1),
        (9, 1),
    ]);
    let encoded = frame(4, 0, 0, &payload);
    let decoded = negotiated_settings(&encoded);
    assert_eq!(decoded.header_table_size(), Some(128));
    assert_eq!(decoded.is_push_enabled(), Some(false));
    assert_eq!(decoded.max_concurrent_streams(), Some(17));
    assert_eq!(decoded.initial_window_size(), Some(1_000_000));
    assert_eq!(decoded.max_frame_size(), Some(32_768));
    assert_eq!(decoded.max_header_list_size(), Some(64_000));
    assert_eq!(decoded.is_extended_connect_protocol_enabled(), Some(true));
    assert_eq!(decoded.is_no_rfc7540_priorities(), Some(true));
}

#[test]
fn multiple_frames_and_duplicates_are_final_wins() {
    let mut encoded = frame(4, 0, 0, &settings(&[(1, 100), (3, 5)]));
    encoded.extend(frame(4, 0x80, 0, &settings(&[(1, 200), (3, 7)])));
    let decoded = negotiated_settings(&encoded);
    assert_eq!(decoded.header_table_size(), Some(200));
    assert_eq!(decoded.max_concurrent_streams(), Some(7));
}

#[test]
fn setting_transition_rules_apply_between_frames_after_same_frame_final_wins() {
    let mut same_frame = frame(4, 0, 0, &settings(&[(8, 1), (8, 0), (9, 1), (9, 0)]));
    same_frame.extend(frame(4, 0, 0, &settings(&[(8, 1), (9, 0)])));
    let decoded = negotiated_settings(&same_frame);
    assert_eq!(decoded.is_extended_connect_protocol_enabled(), Some(true));
    assert_eq!(decoded.is_no_rfc7540_priorities(), Some(false));

    let mut connect_downgrade = frame(4, 0, 0, &settings(&[(8, 1)]));
    connect_downgrade.extend(frame(4, 0, 0, &settings(&[(8, 0)])));
    assert_kind(&connect_downgrade, DecodeErrorKind::SettingTransition);

    let mut priorities_change = frame(4, 0, 0, &settings(&[(9, 0)]));
    priorities_change.extend(frame(4, 0, 0, &settings(&[(9, 1)])));
    assert_kind(&priorities_change, DecodeErrorKind::SettingTransition);

    let mut priorities_change_after_omission = frame(4, 0, 0, &[]);
    priorities_change_after_omission.extend(frame(4, 0, 0, &settings(&[(9, 1)])));
    assert_kind(
        &priorities_change_after_omission,
        DecodeErrorKind::SettingTransition,
    );
}

#[test]
fn ignores_unknown_settings_frames_and_unused_flags() {
    let mut encoded = frame(0x10, 0xff, 17, b"extension");
    encoded.extend(frame(4, 0x80, 0x8000_0000, &settings(&[(0, 9), (10, 11)])));
    let decoded = decode_ok(Some(&encoded));
    assert_eq!(decoded.frame_count(), Some(2));
    assert_eq!(decoded.settings_frame_count(), Some(1));

    let extension_only = frame(0x10, 0, 0, &[]);
    let decoded = decode_ok(Some(&extension_only));
    assert_eq!(decoded.frame_count(), Some(1));
    assert_eq!(decoded.settings_frame_count(), Some(0));
    assert!(decoded.into_initial_settings().is_none());
}

#[test]
fn rejects_structurally_malformed_frame_sequences() {
    assert_kind(
        &vec![0; usize::from(u16::MAX) + 1],
        DecodeErrorKind::TotalLength,
    );
    assert_kind(&[0], DecodeErrorKind::TruncatedHeader);
    assert_kind(&[0; 8], DecodeErrorKind::TruncatedHeader);

    let truncated_payload = frame_header(1, 4, 0, 0);
    assert_kind(&truncated_payload, DecodeErrorKind::TruncatedPayload);

    let oversized = frame_header(16_385, 0x10, 0, 0);
    assert_kind(&oversized, DecodeErrorKind::FrameSize);
    assert_kind(&frame(0, 0, 0, &[]), DecodeErrorKind::CoreFrameType);
    assert_kind(&frame(4, 0, 1, &[]), DecodeErrorKind::SettingsStream);
    assert_kind(&frame(4, 1, 0, &[]), DecodeErrorKind::SettingsAck);
    assert_kind(&frame(4, 0, 0, &[0]), DecodeErrorKind::SettingsLength);
}

#[test]
fn rejects_invalid_known_setting_values() {
    for (id, value) in [
        (2, 1),
        (2, 2),
        (4, 0x8000_0000),
        (5, 16_383),
        (5, 16_777_216),
        (8, 2),
        (9, 2),
    ] {
        assert_kind(
            &frame(4, 0, 0, &settings(&[(id, value)])),
            DecodeErrorKind::SettingValue,
        );
    }
}

fn negotiated_settings(encoded: &[u8]) -> ::http2::frame::Settings {
    match decode_ok(Some(encoded)) {
        PeerApplicationSettings::Negotiated { settings, .. } => *settings,
        PeerApplicationSettings::Absent => panic!("encoded ALPS was treated as absent"),
    }
}

fn decode_ok(encoded: Option<&[u8]>) -> PeerApplicationSettings {
    match decode(encoded) {
        Ok(decoded) => decoded,
        Err(error) => panic!("peer settings were rejected: {error:?}"),
    }
}

fn assert_kind(encoded: &[u8], expected: DecodeErrorKind) {
    let error = match decode(Some(encoded)) {
        Ok(_) => panic!("malformed ALPS was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.kind, expected);
}

fn settings(values: &[(u16, u32)]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(values.len() * 6);
    for (id, value) in values {
        payload.extend(id.to_be_bytes());
        payload.extend(value.to_be_bytes());
    }
    payload
}

fn frame(kind: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut encoded = frame_header(payload.len(), kind, flags, stream_id);
    encoded.extend(payload);
    encoded
}

fn frame_header(length: usize, kind: u8, flags: u8, stream_id: u32) -> Vec<u8> {
    vec![
        ((length >> 16) & 0xff) as u8,
        ((length >> 8) & 0xff) as u8,
        (length & 0xff) as u8,
        kind,
        flags,
        ((stream_id >> 24) & 0xff) as u8,
        ((stream_id >> 16) & 0xff) as u8,
        ((stream_id >> 8) & 0xff) as u8,
        (stream_id & 0xff) as u8,
    ]
}
