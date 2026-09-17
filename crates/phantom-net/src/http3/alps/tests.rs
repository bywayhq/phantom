use super::{DecodeErrorKind, decode};

const ACCEPT_CH: u64 = 0x89;

#[test]
fn collects_accept_ch_across_frame_sequence_and_ignores_other_frames() {
    let mut encoded = frame(0x4, &[0, 1, 0]);
    encoded.extend(frame(
        ACCEPT_CH,
        &entries(&[
            (b"https://first.example", b"Sec-CH-UA"),
            (b"https://second.example", b"Sec-CH-UA-Platform"),
        ]),
    ));
    encoded.extend(frame(0x21, b"ignored extension payload"));

    let decoded = decode_ok(&encoded);
    assert_eq!(decoded.len(), 2);
    assert_eq!(
        decoded.for_origin("https://first.example"),
        Some(b"Sec-CH-UA".as_slice())
    );
    assert_eq!(
        decoded.for_origin("https://second.example"),
        Some(b"Sec-CH-UA-Platform".as_slice())
    );
    assert_eq!(decoded.for_origin("https://missing.example"), None);
}

#[test]
fn metadata_lookup_is_exact_and_first_duplicate_wins() {
    let mut encoded = frame(
        ACCEPT_CH,
        &entries(&[
            (b"https://example.test", b"first"),
            (b"https://example.test", b"same-frame-later"),
            (b"HTTPS://EXAMPLE.TEST", b"different-bytes"),
        ]),
    );
    encoded.extend(frame(
        ACCEPT_CH,
        &entries(&[(b"https://example.test", b"later-frame")]),
    ));

    let decoded = decode_ok(&encoded);
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded.ignored_len(), 1);
    assert_eq!(
        decoded.for_origin("https://example.test"),
        Some(&b"first"[..])
    );
    assert_eq!(decoded.for_origin("HTTPS://EXAMPLE.TEST"), None);
}

#[test]
fn accepts_empty_payload_and_empty_value() {
    assert_eq!(decode_ok(&[]).len(), 0);
    assert_eq!(decode_ok(&frame(ACCEPT_CH, &[])).len(), 0);

    let decoded = decode_ok(&frame(
        ACCEPT_CH,
        &entries(&[(b"", b"value"), (b"https://empty.test", b"")]),
    ));
    assert_eq!(decoded.for_origin(""), None);
    assert_eq!(decoded.for_origin("https://empty.test"), Some(&b""[..]));
    assert_eq!(decoded.ignored_len(), 1);
}

#[test]
fn rejects_truncated_frame_sequence() {
    assert_kind(&[0x40], DecodeErrorKind::TruncatedFrameType);
    assert_kind(&[0x01, 0x40], DecodeErrorKind::TruncatedFrameLength);
    assert_kind(&[0x01, 0x03, b'a'], DecodeErrorKind::TruncatedFramePayload);
}

#[test]
fn accepts_non_minimal_quic_varint_widths() {
    let origin = b"https://a.test";
    let mut payload = wide_varint(origin.len() as u64, 2);
    payload.extend_from_slice(origin);
    payload.extend(wide_varint(1, 4));
    payload.push(b'b');

    let mut encoded = wide_varint(ACCEPT_CH, 4);
    encoded.extend(wide_varint(payload.len() as u64, 2));
    encoded.extend(payload);

    let decoded = decode_ok(&encoded);
    assert_eq!(decoded.for_origin("https://a.test"), Some(&b"b"[..]));
}

#[test]
fn rejects_malformed_accept_ch_entries() {
    assert_payload_kind(&[0x40], DecodeErrorKind::TruncatedOriginLength);
    assert_payload_kind(&[2, b'a'], DecodeErrorKind::TruncatedOrigin);
    assert_payload_kind(&[1, b'a'], DecodeErrorKind::TruncatedValueLength);
    assert_payload_kind(&[1, b'a', 2, b'b'], DecodeErrorKind::TruncatedValue);
}

fn decode_ok(encoded: &[u8]) -> crate::accept_ch::AcceptCh {
    match decode(encoded) {
        Ok(decoded) => decoded,
        Err(error) => panic!("peer ALPS was rejected: {error}"),
    }
}

fn assert_payload_kind(payload: &[u8], expected: DecodeErrorKind) {
    assert_kind(&frame(ACCEPT_CH, payload), expected);
}

fn assert_kind(encoded: &[u8], expected: DecodeErrorKind) {
    let error = match decode(encoded) {
        Ok(_) => panic!("malformed peer ALPS was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.kind, expected);
}

fn entries(values: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut encoded = Vec::new();
    for (origin, value) in values {
        encoded.extend(varint(origin.len() as u64));
        encoded.extend_from_slice(origin);
        encoded.extend(varint(value.len() as u64));
        encoded.extend_from_slice(value);
    }
    encoded
}

fn frame(kind: u64, payload: &[u8]) -> Vec<u8> {
    let mut encoded = varint(kind);
    encoded.extend(varint(payload.len() as u64));
    encoded.extend_from_slice(payload);
    encoded
}

fn varint(value: u64) -> Vec<u8> {
    match value {
        0..=0x3f => vec![value as u8],
        0x40..=0x3fff => (value | 0x4000).to_be_bytes()[6..].to_vec(),
        0x4000..=0x3fff_ffff => (value | 0x8000_0000).to_be_bytes()[4..].to_vec(),
        _ => (value | 0xc000_0000_0000_0000).to_be_bytes().to_vec(),
    }
}

fn wide_varint(value: u64, width: usize) -> Vec<u8> {
    let prefix = match width {
        1 => 0,
        2 => 0x4000,
        4 => 0x8000_0000,
        8 => 0xc000_0000_0000_0000,
        _ => panic!("invalid QUIC varint width"),
    };
    (value | prefix).to_be_bytes()[8 - width..].to_vec()
}
