use std::{collections::BTreeSet, error::Error, time::Duration};

use phantom_profile::{
    chromium,
    quic::{QuicTransportParameterKind, QuicTransportSettings},
};
use quinn_proto::{Side, transport_parameters::TransportParameters};

use super::{
    ENTROPY_LEN, ParsedTransportParameters, QuicTransportProfileError, TransportParameterProfile,
    WireEntropy, decode_varint, initial_max_streams_bidi,
};
use crate::QuicVersion;

/// The retained Chrome 154.0.8037.58 QUIC startup capture's
/// `transport_parameters_hex`, whose order the recipe carries as its
/// permutation template.
const CAPTURED_PARAMETERS: &str = "08024064070480600000110c000000019a7aaa7a00000001040480f00000090240670604806000000104800075307128044f524947200480010000c8200e4187dfa4b60190030245c00504806000000f00";

#[test]
fn deterministic_entropy_reproduces_captured_parameters() -> Result<(), Box<dyn Error>> {
    let captured = decode_hex(CAPTURED_PARAMETERS)?;
    let params = TransportParameters::read(Side::Server, &mut captured.as_slice())?;
    let profile = TransportParameterProfile::new(chromium::v154_quic())?;
    let mut entropy = fixture_entropy();

    let encoded = profile.encode_with_entropy(&params, QuicVersion::V1, None, &mut entropy)?;

    assert_eq!(encoded, captured);
    Ok(())
}

#[test]
fn reads_the_peer_s_bidirectional_stream_limit() -> Result<(), Box<dyn Error>> {
    // The captured Chrome parameters carry `initial_max_streams_bidi` 100.
    let captured = decode_hex(CAPTURED_PARAMETERS)?;
    assert_eq!(initial_max_streams_bidi(&captured), Some(100));
    // A two-byte varint of 1,000 among other parameters.
    assert_eq!(
        initial_max_streams_bidi(&[0x09, 0x01, 0x03, 0x08, 0x02, 0x43, 0xe8]),
        Some(1_000)
    );
    // RFC 9000, section 18.2: an absent parameter is 0.
    assert_eq!(initial_max_streams_bidi(&[0x09, 0x01, 0x03]), Some(0));
    assert_eq!(initial_max_streams_bidi(&[0x08, 0x02, 0x43]), None);
    assert_eq!(initial_max_streams_bidi(&[0x08, 0x02, 0x05, 0x06]), None);
    Ok(())
}

#[test]
fn entropy_changes_order_without_changing_profile_semantics() -> Result<(), Box<dyn Error>> {
    let captured = decode_hex(CAPTURED_PARAMETERS)?;
    let params = TransportParameters::read(Side::Server, &mut captured.as_slice())?;
    let settings = chromium::v154_quic();
    let profile = TransportParameterProfile::new(settings.clone())?;
    let expected_shape = parameter_shape(&captured)?;
    let captured = ParsedTransportParameters::from_encoded(&captured)?;
    let mut orders = BTreeSet::new();

    for seed in 0..16 {
        let mut entropy = seeded_entropy(seed);
        let encoded = profile.encode_with_entropy(&params, QuicVersion::V1, None, &mut entropy)?;

        assert_eq!(parameter_shape(&encoded)?, expected_shape);
        assert_profile_semantics(&encoded, &settings, &captured)?;
        orders.insert(parameter_order(&encoded)?);
    }

    assert!(orders.len() > 1, "transport-parameter order did not vary");
    Ok(())
}

#[test]
fn a_resumed_connection_adds_only_initial_rtt_as_a_minimal_varint() -> Result<(), Box<dyn Error>> {
    let captured = decode_hex(CAPTURED_PARAMETERS)?;
    let params = TransportParameters::read(Side::Server, &mut captured.as_slice())?;
    let profile = TransportParameterProfile::new(chromium::v154_quic())?;
    let mut fresh_shape = parameter_shape(&captured)?;
    // Loopback and 50 ms values from the resumption captures, and the
    // one-byte and eight-byte extremes.
    for (rtt, value) in [
        (Duration::from_micros(2_509), vec![0x49, 0xcd]),
        (Duration::from_micros(54_894), vec![0x80, 0x00, 0xd6, 0x6e]),
        (Duration::from_micros(63), vec![0x3f]),
        (
            Duration::from_secs(1_100),
            vec![0xc0, 0x00, 0x00, 0x00, 0x41, 0x90, 0xab, 0x00],
        ),
    ] {
        let mut orders = BTreeSet::new();
        for seed in 0..16 {
            let encoded = profile.encode_with_entropy(
                &params,
                QuicVersion::V1,
                Some(rtt),
                &mut seeded_entropy(seed),
            )?;
            let parsed = ParsedTransportParameters::from_encoded(&encoded)?;
            assert_eq!(parsed.value(0x3127)?, value.as_slice());
            let order = parameter_order(&encoded)?;
            orders.insert(order.iter().position(|id| *id == 0x3127));
            let mut expected = fresh_shape.clone();
            expected.push((0x3127, 2, 1, value.len()));
            expected.sort_unstable();
            assert_eq!(parameter_shape(&encoded)?, expected);
        }
        assert!(orders.len() > 1, "initial_rtt_us kept one position");
    }

    // A measurement below one microsecond has nothing to send.
    let encoded = profile.encode_with_entropy(
        &params,
        QuicVersion::V1,
        Some(Duration::from_nanos(900)),
        &mut fixture_entropy(),
    )?;
    assert_eq!(encoded, captured);
    fresh_shape.sort_unstable();
    assert_eq!(parameter_shape(&encoded)?, fresh_shape);
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
    let profile = TransportParameterProfile::new(chromium::v154_quic())?;
    let mut entropy = fixture_entropy();

    let error = match profile.encode_with_entropy(&params, QuicVersion::V1, None, &mut entropy) {
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
    let profile = TransportParameterProfile::new(chromium::v154_quic())?;
    let mut entropy = fixture_entropy();

    let error = match profile.encode_with_entropy(&params, QuicVersion::V1, None, &mut entropy) {
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
    let mut settings = chromium::v154_quic();
    settings.initial_max_stream_data_bidi_remote -= 1;

    let error = match TransportParameterProfile::new(settings) {
        Ok(_) => panic!("Quinn-incompatible stream windows were accepted"),
        Err(error) => error,
    };

    assert_eq!(error.field(), "initial_max_stream_data");
}

#[test]
fn constructor_preserves_backend_neutral_validation_field() {
    let mut settings = chromium::v154_quic();
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
    bytes[12..17].copy_from_slice(&[0x90, 0x70, 0xa0, 0x70, 0]);
    bytes[17..25].copy_from_slice(&[0x00, 0x43, 0x19, 0x3b, 0xeb, 0x9b, 0xdc, 0x05]);
    bytes[25] = 1;
    bytes[26] = 0x90;
    WireEntropy::from_bytes(bytes)
}

fn seeded_entropy(seed: u8) -> WireEntropy {
    let mut bytes = [0; ENTROPY_LEN];
    for (index, byte) in (0_u8..12).zip(&mut bytes[..12]) {
        *byte = seed.wrapping_mul(31).wrapping_add(index.wrapping_mul(17));
    }
    WireEntropy::from_bytes(bytes)
}

fn parameter_shape(
    encoded: &[u8],
) -> Result<Vec<(u64, usize, usize, usize)>, QuicTransportProfileError> {
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
        let stable_length = if class == 27 { 0 } else { length };
        shape.push((
            class,
            id_width.encoded_len(),
            length_width.encoded_len(),
            stable_length,
        ));
    }
    shape.sort_unstable();
    Ok(shape)
}

fn parameter_order(encoded: &[u8]) -> Result<Vec<u64>, QuicTransportProfileError> {
    let mut offset = 0;
    let mut order = Vec::new();
    while offset < encoded.len() {
        let (identifier, _) = decode_varint(encoded, &mut offset)?;
        let (length, _) = decode_varint(encoded, &mut offset)?;
        let length = usize::try_from(length)
            .map_err(|_| super::profile_error("test", "length does not fit usize"))?;
        offset = offset
            .checked_add(length)
            .filter(|end| *end <= encoded.len())
            .ok_or_else(|| super::profile_error("test", "parameter is truncated"))?;
        order.push(if identifier >= 27 && identifier % 31 == 27 {
            27
        } else {
            identifier
        });
    }
    Ok(order)
}

fn assert_profile_semantics(
    encoded: &[u8],
    settings: &QuicTransportSettings,
    captured: &ParsedTransportParameters,
) -> Result<(), Box<dyn Error>> {
    let parsed = ParsedTransportParameters::from_encoded(encoded)?;
    let expected_scalars = [
        (0x01, settings.max_idle_timeout_ms),
        (0x03, settings.max_udp_payload_size),
        (0x04, settings.initial_max_data),
        (0x05, settings.initial_max_stream_data_bidi_local),
        (0x06, settings.initial_max_stream_data_bidi_remote),
        (0x07, settings.initial_max_stream_data_uni),
        (0x08, settings.initial_max_streams_bidi),
        (0x09, settings.initial_max_streams_uni),
        (
            0x20,
            settings
                .max_datagram_frame_size
                .ok_or("Chrome profile omitted max_datagram_frame_size")?,
        ),
    ];
    for (identifier, expected) in expected_scalars {
        assert_eq!(parsed.scalar(identifier)?, expected);
    }
    assert_eq!(parsed.value(0x0f)?, captured.value(0x0f)?);
    assert_eq!(parsed.value(0x3128)?, b"ORIG");

    let grease = parsed
        .values
        .iter()
        .filter(|(identifier, _)| **identifier >= 27 && **identifier % 31 == 27)
        .collect::<Vec<_>>();
    assert_eq!(grease.len(), 1);
    assert!((0..=15).contains(&grease[0].1.len()));
    // A fresh connection omits `initial_rtt_us`.
    let fresh_parameters = settings
        .wire_parameters
        .iter()
        .filter(|parameter| parameter.kind != QuicTransportParameterKind::InitialRtt)
        .count();
    assert_eq!(parsed.values.len(), fresh_parameters);
    validate_version_information(encoded)?;
    Ok(())
}

fn validate_version_information(encoded: &[u8]) -> Result<(), Box<dyn Error>> {
    let parsed = ParsedTransportParameters::from_encoded(encoded)?;
    let value = parsed.value(0x11)?;
    if value.len() != 12 || value[..4] != [0, 0, 0, 1] {
        return Err("version information has the wrong selected version or length".into());
    }
    let mut available = value[4..].as_chunks::<4>().0.iter().copied();
    let first = u32::from_be_bytes(available.next().ok_or("missing available version")?);
    let second = u32::from_be_bytes(available.next().ok_or("missing reserved version")?);
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
    if !input.len().is_multiple_of(2) {
        return Err("hex input has odd length".into());
    }
    input
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect()
}
