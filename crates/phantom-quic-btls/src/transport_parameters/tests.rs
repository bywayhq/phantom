use std::{collections::BTreeSet, error::Error, time::Duration};

use phantom_profile::{
    QuicConnectionIdLength, QuicTransportParameterKind, QuicTransportParameterOrder,
    QuicTransportSettings, QuicVarIntWidth,
    browser::{chrome, firefox},
};
use quinn_proto::{Side, transport_parameters::TransportParameters};

use super::wire::encode_varint;
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
    let profile = TransportParameterProfile::new(chrome::v154_quic())?;
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
    let settings = chrome::v154_quic();
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
    let profile = TransportParameterProfile::new(chrome::v154_quic())?;
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
    let profile = TransportParameterProfile::new(chrome::v154_quic())?;
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
    let profile = TransportParameterProfile::new(chrome::v154_quic())?;
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
fn grease_identifiers_fit_every_configured_wire_width() -> Result<(), Box<dyn Error>> {
    let captured = decode_hex(CAPTURED_PARAMETERS)?;
    let params = TransportParameters::read(Side::Server, &mut captured.as_slice())?;
    for width in grease_widths() {
        let mut settings = chrome::v154_quic();
        settings.parameter_order = QuicTransportParameterOrder::Fixed;
        for parameter in &mut settings.wire_parameters {
            if matches!(parameter.kind, QuicTransportParameterKind::Grease(_)) {
                parameter.id_width = width;
            }
        }
        settings.validate()?;
        let profile = TransportParameterProfile::new(settings)?;
        for byte in [0, 1] {
            let mut entropy = WireEntropy::from_bytes([byte; ENTROPY_LEN]);
            let encoded =
                profile.encode_with_entropy(&params, QuicVersion::V1, None, &mut entropy)?;
            let mut offset = 0;
            let mut reserved = Vec::new();
            while offset < encoded.len() {
                let (identifier, encoded_width) = decode_varint(&encoded, &mut offset)?;
                let (len, _) = decode_varint(&encoded, &mut offset)?;
                offset += usize::try_from(len)?;
                assert!(offset <= encoded.len());
                if super::wire::is_reserved_transport_parameter(identifier) {
                    reserved.push((identifier, encoded_width));
                }
            }
            assert_eq!(reserved.len(), 1);
            let (identifier, encoded_width) = reserved[0];
            assert_eq!(encoded_width, width);
            assert!(width.can_encode(identifier));
            assert_eq!(identifier % 31, 27);
            assert!(identifier >= 27);
        }
    }
    Ok(())
}

#[test]
fn reserved_identifier_draws_include_both_bounds_and_reject_excess() -> Result<(), Box<dyn Error>> {
    for width in grease_widths() {
        let maximum_n = (width.maximum_value() - 27) / 31;
        let maximum_id = 31 * maximum_n + 27;
        for (first, second, expected) in [
            (0, 0, 27),
            (1, 0, 58),
            (maximum_n, 0, maximum_id),
            (u64::MAX, maximum_n, maximum_id),
        ] {
            let mut bytes = [0; ENTROPY_LEN];
            bytes[..8].copy_from_slice(&first.to_be_bytes());
            bytes[8..16].copy_from_slice(&second.to_be_bytes());
            let mut entropy = WireEntropy::from_bytes(bytes);
            let identifier = entropy.reserved_transport_parameter_id(width)?;
            assert_eq!(identifier, expected, "{width:?}, candidate {first}");
            assert!(width.can_encode(identifier));
            assert!(maximum_id <= width.maximum_value());
            assert!(maximum_id + 31 > width.maximum_value());
            let mut encoded = Vec::new();
            encode_varint(identifier, width, &mut encoded)?;
            assert_eq!(encoded.len(), width.encoded_len());
            assert_eq!(decode_varint(&encoded, &mut 0)?, (identifier, width));
        }
        if width != QuicVarIntWidth::One {
            let mut bytes = [0; ENTROPY_LEN];
            bytes[..8].copy_from_slice(&(maximum_n + 1).to_be_bytes());
            bytes[8..16].copy_from_slice(&1_u64.to_be_bytes());
            let mut entropy = WireEntropy::from_bytes(bytes);
            assert_eq!(entropy.reserved_transport_parameter_id(width)?, 58);
            let mut exhausted = WireEntropy::from_bytes([u8::MAX; ENTROPY_LEN]);
            let error = exhausted
                .reserved_transport_parameter_id(width)
                .err()
                .ok_or("exhausted entropy was accepted")?;
            assert!(error.is_entropy_failure());
        }
    }
    Ok(())
}

#[test]
fn small_identifier_ranges_assign_each_accepted_candidate_one_reserved_id()
-> Result<(), Box<dyn Error>> {
    for width in [QuicVarIntWidth::One, QuicVarIntWidth::Two] {
        let maximum_n = (width.maximum_value() - 27) / 31;
        let mut identifiers = BTreeSet::new();
        for candidate in 0..=maximum_n {
            let mut bytes = [0; ENTROPY_LEN];
            bytes[..8].copy_from_slice(&candidate.to_be_bytes());
            let identifier =
                WireEntropy::from_bytes(bytes).reserved_transport_parameter_id(width)?;
            assert_eq!(identifier, 31 * candidate + 27);
            assert!(identifiers.insert(identifier));
        }
        assert_eq!(u64::try_from(identifiers.len())?, maximum_n + 1);
    }
    Ok(())
}

fn grease_widths() -> [QuicVarIntWidth; 4] {
    [
        QuicVarIntWidth::One,
        QuicVarIntWidth::Two,
        QuicVarIntWidth::Four,
        QuicVarIntWidth::Eight,
    ]
}

#[test]
fn constructor_accepts_a_window_per_stream_class() -> Result<(), Box<dyn Error>> {
    let settings = firefox::v157_quic();
    assert_ne!(
        settings.initial_max_stream_data_bidi_local,
        settings.initial_max_stream_data_bidi_remote
    );
    TransportParameterProfile::new(settings)?;
    Ok(())
}

#[test]
fn constructor_rejects_a_min_ack_delay_the_runtime_cannot_honor() {
    let mut settings = firefox::v157_quic();
    settings.min_ack_delay_us = Some(2_000);

    let error = match TransportParameterProfile::new(settings) {
        Ok(_) => panic!("an unsupported min_ack_delay was accepted"),
        Err(error) => error,
    };

    assert_eq!(error.field(), "min_ack_delay_us");
    assert_eq!(
        error.kind(),
        crate::QuicTransportProfileErrorKind::InvalidProfile
    );
}

#[test]
fn exhausted_entropy_has_a_typed_category_without_field_matching() -> Result<(), Box<dyn Error>> {
    let mut entropy = WireEntropy::from_bytes([0; ENTROPY_LEN]);
    entropy.take(ENTROPY_LEN)?;
    let error = entropy
        .take(1)
        .err()
        .ok_or("exhausted entropy was accepted")?;
    assert_eq!(
        error.kind(),
        crate::QuicTransportProfileErrorKind::EntropyFailure
    );
    assert!(error.is_entropy_failure());
    assert_eq!(error.field(), "entropy");
    assert!(error.source().is_none());
    Ok(())
}

#[test]
fn version_information_lists_v2_then_v1_after_a_leading_reserved_version()
-> Result<(), Box<dyn Error>> {
    let profile = TransportParameterProfile::new(firefox::v157_quic())?;
    for (version, chosen) in [(QuicVersion::V1, 1_u32), (QuicVersion::V2, 0x6b33_43cf)] {
        let mut entropy = fixture_entropy();
        let value = profile.version_information(
            version,
            phantom_profile::QuicVersionGrease::First,
            2,
            &mut entropy,
        )?;
        let words = value
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_be_bytes(*word))
            .collect::<Vec<_>>();
        assert_eq!(words.len(), 4);
        assert_eq!(words[0], chosen);
        assert_eq!(words[1] & 0x0f0f_0f0f, 0x0a0a_0a0a);
        assert_eq!(words[2..], [0x6b33_43cf, 1]);
    }

    let chrome = TransportParameterProfile::new(chrome::v154_quic())?;
    let mut entropy = fixture_entropy();
    let error = match chrome.version_information(
        QuicVersion::V2,
        phantom_profile::QuicVersionGrease::Permuted,
        1,
        &mut entropy,
    ) {
        Ok(_) => panic!("a version the profile does not list was chosen"),
        Err(error) => error,
    };
    assert_eq!(error.field(), "version_information");
    Ok(())
}

#[test]
fn masked_random_destination_ids_favor_the_minimum_length() -> Result<(), Box<dyn Error>> {
    let profile = TransportParameterProfile::new(firefox::v157_quic())?;
    let provider = profile
        .initial_destination_connection_id()
        .ok_or("the Firefox recipe sets the Initial Destination Connection ID length")?;
    let mut shortest = 0;
    for _ in 0..2_000 {
        let length = provider().len();
        assert!((8..=20).contains(&length), "length {length}");
        shortest += usize::from(length == 8);
    }
    // The length is 8 when bits 2 and 3 of `b & (b >> 4)` are clear: (3/4)^2 = 0.5625.
    assert!(shortest > 1_000, "{shortest} of 2000 IDs had 8 bytes");

    let mut settings = firefox::v157_quic();
    settings.initial_destination_connection_id = Some(QuicConnectionIdLength::Fixed(12));
    let provider = TransportParameterProfile::new(settings)?
        .initial_destination_connection_id()
        .ok_or("a fixed length is a policy")?;
    assert_eq!(provider().len(), 12);
    assert!(
        TransportParameterProfile::new(chrome::v154_quic())?
            .initial_destination_connection_id()
            .is_none()
    );
    Ok(())
}

#[test]
fn constructor_preserves_backend_neutral_validation_field() {
    let mut settings = chrome::v154_quic();
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
