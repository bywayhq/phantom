use std::error::Error;

use phantom_profile::chromium;
use quinn_proto::{Side, transport_parameters::TransportParameters};

use super::{
    ENTROPY_LEN, ParsedTransportParameters, QuicTransportProfileError, TransportParameterProfile,
    WireEntropy, decode_varint,
};
use crate::QuicVersion;

const CAPTURED_PARAMETERS: &str = "070480600000050480600000110c00000001000000013a9acaca040480f00000080240647128044f52494709024067060480600000e1e690782fe06d0d0941dc5ee0276eeebb540f00030245c0200480010000010480007530";

#[test]
fn deterministic_entropy_reproduces_captured_parameters() -> Result<(), Box<dyn Error>> {
    let captured = decode_hex(CAPTURED_PARAMETERS)?;
    let params = TransportParameters::read(Side::Server, &mut captured.as_slice())?;
    let profile = TransportParameterProfile::new(chromium::v152_macos_quic())?;
    let mut entropy = fixture_entropy();

    let encoded = profile.encode_with_entropy(&params, QuicVersion::V1, &mut entropy)?;

    assert_eq!(encoded, captured);
    Ok(())
}

#[test]
fn entropy_changes_wire_shape_without_changing_parameter_set() -> Result<(), Box<dyn Error>> {
    let captured = decode_hex(CAPTURED_PARAMETERS)?;
    let params = TransportParameters::read(Side::Server, &mut captured.as_slice())?;
    let profile = TransportParameterProfile::new(chromium::v152_macos_quic())?;
    let mut first = WireEntropy::from_bytes([0; ENTROPY_LEN]);
    let mut second = WireEntropy::from_bytes([17; ENTROPY_LEN]);

    let first = profile.encode_with_entropy(&params, QuicVersion::V1, &mut first)?;
    let second = profile.encode_with_entropy(&params, QuicVersion::V1, &mut second)?;

    assert_ne!(first, second);
    let first_shape = parameter_shape(&first)?;
    let second_shape = parameter_shape(&second)?;
    assert_eq!(first_shape, second_shape);
    assert_eq!(first_shape.len(), 13);
    assert_eq!(first_shape.iter().filter(|entry| entry.0 == 27).count(), 1);
    validate_version_information(&first)?;
    validate_version_information(&second)?;
    Ok(())
}

#[test]
fn live_semantic_mismatch_fails_closed() -> Result<(), Box<dyn Error>> {
    let mut captured = decode_hex(CAPTURED_PARAMETERS)?;
    let max_data = captured
        .windows(4)
        .position(|window| window == [0x80, 0xf0, 0x00, 0x00])
        .ok_or("missing max-data fixture value")?;
    captured[max_data + 3] = 1;
    let params = TransportParameters::read(Side::Server, &mut captured.as_slice())?;
    let profile = TransportParameterProfile::new(chromium::v152_macos_quic())?;
    let mut entropy = fixture_entropy();

    let error = match profile.encode_with_entropy(&params, QuicVersion::V1, &mut entropy) {
        Ok(_) => return Err("mismatched live semantics were accepted".into()),
        Err(error) => error,
    };

    assert_eq!(error.field(), "initial_max_data");
    Ok(())
}

#[test]
fn unprofiled_live_parameter_fails_closed() -> Result<(), Box<dyn Error>> {
    let mut captured = decode_hex(CAPTURED_PARAMETERS)?;
    captured.extend_from_slice(&[0x0c, 0x00]);
    let params = TransportParameters::read(Side::Server, &mut captured.as_slice())?;
    let profile = TransportParameterProfile::new(chromium::v152_macos_quic())?;
    let mut entropy = fixture_entropy();

    let error = match profile.encode_with_entropy(&params, QuicVersion::V1, &mut entropy) {
        Ok(_) => return Err("unprofiled live state was accepted".into()),
        Err(error) => error,
    };

    assert_eq!(error.field(), "wire_parameters");
    Ok(())
}

#[test]
fn strict_parser_rejects_truncation_and_duplicates() {
    let truncated = ParsedTransportParameters::from_encoded(&[0x04, 0x02, 0x40]);
    assert!(truncated.is_err());

    let duplicate = ParsedTransportParameters::from_encoded(&[0x04, 0x01, 0x01, 0x04, 0x01, 0x02]);
    assert!(duplicate.is_err());
}

#[test]
fn constructor_rejects_quinn_incompatible_stream_windows() {
    let mut settings = chromium::v152_macos_quic();
    settings.initial_max_stream_data_bidi_remote -= 1;

    let error = match TransportParameterProfile::new(settings) {
        Ok(_) => panic!("Quinn-incompatible stream windows were accepted"),
        Err(error) => error,
    };

    assert_eq!(error.field(), "initial_max_stream_data");
}

#[test]
fn constructor_preserves_backend_neutral_validation_field() {
    let mut settings = chromium::v152_macos_quic();
    settings.max_udp_payload_size = 1_199;

    let error = match TransportParameterProfile::new(settings) {
        Ok(_) => panic!("invalid UDP payload size was accepted"),
        Err(error) => error,
    };

    assert_eq!(error.field(), "max_udp_payload_size");
}

fn fixture_entropy() -> WireEntropy {
    let mut bytes = [0; ENTROPY_LEN];
    bytes[..12].copy_from_slice(&[12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]);
    bytes[12..17].copy_from_slice(&[0x30, 0x90, 0xc0, 0xc0, 1]);
    bytes[17..25].copy_from_slice(&[0x01, 0x17, 0xf4, 0x24, 0xe8, 0xc5, 0x2c, 0xce]);
    bytes[25] = 9;
    bytes[26..35].copy_from_slice(&[0x41, 0xdc, 0x5e, 0xe0, 0x27, 0x6e, 0xee, 0xbb, 0x54]);
    WireEntropy::from_bytes(bytes)
}

fn parameter_shape(encoded: &[u8]) -> Result<Vec<(u64, usize, usize)>, QuicTransportProfileError> {
    let mut offset = 0;
    let mut shape = Vec::new();
    while offset < encoded.len() {
        let (identifier, id_width) = decode_varint(encoded, &mut offset)?;
        let (length, length_width) = decode_varint(encoded, &mut offset)?;
        let length = usize::try_from(length)
            .map_err(|_| super::profile_error("test", "length does not fit usize"))?;
        offset = offset
            .checked_add(length)
            .filter(|end| *end <= encoded.len())
            .ok_or_else(|| super::profile_error("test", "parameter is truncated"))?;
        let class = if identifier >= 27 && identifier % 31 == 27 {
            27
        } else {
            identifier
        };
        shape.push((class, id_width.encoded_len(), length_width.encoded_len()));
    }
    shape.sort_unstable();
    Ok(shape)
}

fn validate_version_information(encoded: &[u8]) -> Result<(), Box<dyn Error>> {
    let parsed = ParsedTransportParameters::from_encoded(encoded)?;
    let value = parsed.value(0x11)?;
    if value.len() != 12 || value[..4] != [0, 0, 0, 1] {
        return Err("version information has the wrong selected version or length".into());
    }
    let mut available = value[4..].chunks_exact(4);
    let first = u32::from_be_bytes(
        available
            .next()
            .ok_or("missing available version")?
            .try_into()?,
    );
    let second = u32::from_be_bytes(
        available
            .next()
            .ok_or("missing reserved version")?
            .try_into()?,
    );
    if available.next().is_some()
        || [first, second]
            .iter()
            .filter(|version| **version == 1)
            .count()
            != 1
    {
        return Err("version information must contain QUIC v1 exactly once".into());
    }
    let reserved = if first == 1 { second } else { first };
    if reserved & 0x0f0f_0f0f != 0x0a0a_0a0a {
        return Err("version information contains a non-reserved GREASE version".into());
    }
    Ok(())
}

fn decode_hex(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if input.len() % 2 != 0 {
        return Err("hex input has odd length".into());
    }
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect()
}
