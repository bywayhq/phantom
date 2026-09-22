use std::collections::BTreeMap;

use super::{v152_quic, v153_quic};
use crate::quic::{
    GoogleConnectionOption, QuicTransportParameterKind, QuicTransportParameterOrder,
    QuicTransportSettings, QuicVarIntWidth, QuicVersionGrease,
};

const HTTP3_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/http3/chrome/152.0.7977.83/macos-15.5/client-startup.txt"
));
const WINDOWS_HTTP3_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/http3/chrome/152.0.7977.83/windows-11-26200/client-startup.txt"
));
const EDGE_153_WINDOWS_HTTP3_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/http3/edge/153.0.4234.48/windows-11-26200/client-startup.txt"
));
const V153_WINDOWS_HTTP3_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/http3/chrome/153.0.8010.48/windows-11-26200/client-startup.txt"
));

#[test]
fn chrome_152_macos_quic_settings_match_retained_startup_shape()
-> Result<(), Box<dyn std::error::Error>> {
    assert_quic_settings_match_startup(HTTP3_FIXTURE, &v152_quic())
}

#[test]
fn chrome_152_quic_recipe_matches_windows_chrome_for_testing_capture()
-> Result<(), Box<dyn std::error::Error>> {
    assert_quic_settings_match_startup(WINDOWS_HTTP3_FIXTURE, &v152_quic())
}

#[test]
fn chrome_153_quic_recipe_matches_windows_capture() -> Result<(), Box<dyn std::error::Error>> {
    assert!(V153_WINDOWS_HTTP3_FIXTURE.contains(
        "
client_version=153.0.8010.48
"
    ));
    assert_quic_settings_match_startup(V153_WINDOWS_HTTP3_FIXTURE, &v153_quic())?;
    assert_eq!(v153_quic(), v152_quic());
    Ok(())
}

#[test]
fn chrome_153_quic_recipe_matches_windows_edge_capture() -> Result<(), Box<dyn std::error::Error>> {
    assert!(EDGE_153_WINDOWS_HTTP3_FIXTURE.contains(
        "
client=Microsoft Edge
"
    ));
    assert!(EDGE_153_WINDOWS_HTTP3_FIXTURE.contains(
        "
client_version=153.0.4234.48
"
    ));
    assert_quic_settings_match_startup(EDGE_153_WINDOWS_HTTP3_FIXTURE, &v153_quic())
}

fn assert_quic_settings_match_startup(
    fixture: &str,
    settings: &QuicTransportSettings,
) -> Result<(), Box<dyn std::error::Error>> {
    settings.validate()?;
    let mut captured = parse_quic_transport_parameters(fixture)?;

    assert_eq!(captured.len(), settings.wire_parameters.len());
    assert_eq!(
        settings.parameter_order,
        QuicTransportParameterOrder::Permuted
    );

    use QuicTransportParameterKind as Kind;
    for parameter in &settings.wire_parameters {
        let observed_index = captured
            .iter()
            .position(|observed| parameter_matches(&parameter.kind, observed.id))
            .ok_or("captured transport parameters omitted a profile entry")?;
        let observed = captured.remove(observed_index);
        assert_eq!(parameter.id_width, observed.id_width);
        assert_eq!(parameter.length_width, observed.length_width);
        assert!(observed.id_width.can_encode(observed.id));
        assert!(
            observed
                .length_width
                .can_encode(u64::try_from(observed.value.len())?)
        );

        match &parameter.kind {
            Kind::InitialMaxStreamDataUni { value_width } => assert_quic_scalar(
                &observed,
                0x07,
                *value_width,
                settings.initial_max_stream_data_uni,
            )?,
            Kind::InitialMaxStreamDataBidiLocal { value_width } => assert_quic_scalar(
                &observed,
                0x05,
                *value_width,
                settings.initial_max_stream_data_bidi_local,
            )?,
            Kind::VersionInformation(version) => {
                assert_eq!(observed.id, 0x11);
                assert_eq!(version.grease, QuicVersionGrease::Permuted);
                let versions = decode_u32_words(&observed.value)?;
                assert_eq!(versions.first(), Some(&1));
                let available = &versions[1..];
                assert!(available.contains(&1));
                assert_eq!(
                    available
                        .iter()
                        .filter(|version| !is_reserved_version(**version))
                        .count(),
                    usize::from(version.available_version_count)
                );
                assert_eq!(
                    available
                        .iter()
                        .filter(|version| is_reserved_version(**version))
                        .count(),
                    1
                );
            }
            Kind::InitialMaxData { value_width } => {
                assert_quic_scalar(&observed, 0x04, *value_width, settings.initial_max_data)?;
            }
            Kind::InitialMaxStreamsBidi { value_width } => assert_quic_scalar(
                &observed,
                0x08,
                *value_width,
                settings.initial_max_streams_bidi,
            )?,
            Kind::GoogleConnectionOptions(options) => {
                assert_eq!(observed.id, 0x3128);
                assert_eq!(options, &[GoogleConnectionOption::RequestOriginFrame]);
                assert_eq!(observed.value, b"ORIG");
            }
            Kind::InitialMaxStreamsUni { value_width } => assert_quic_scalar(
                &observed,
                0x09,
                *value_width,
                settings.initial_max_streams_uni,
            )?,
            Kind::InitialMaxStreamDataBidiRemote { value_width } => assert_quic_scalar(
                &observed,
                0x06,
                *value_width,
                settings.initial_max_stream_data_bidi_remote,
            )?,
            Kind::Grease(grease) => {
                assert!(is_reserved_transport_parameter(observed.id));
                assert!(
                    (usize::from(grease.minimum_payload_length)
                        ..=usize::from(grease.maximum_payload_length))
                        .contains(&observed.value.len())
                );
            }
            Kind::InitialSourceConnectionId { length } => {
                assert_eq!(observed.id, 0x0f);
                assert_eq!(observed.value.len(), usize::from(*length));
            }
            Kind::MaxUdpPayloadSize { value_width } => {
                assert_quic_scalar(&observed, 0x03, *value_width, settings.max_udp_payload_size)?
            }
            Kind::MaxDatagramFrameSize { value_width } => assert_quic_scalar(
                &observed,
                0x20,
                *value_width,
                settings
                    .max_datagram_frame_size
                    .ok_or("captured DATAGRAM setting omitted its value")?,
            )?,
            Kind::MaxIdleTimeout { value_width } => {
                assert_quic_scalar(&observed, 0x01, *value_width, settings.max_idle_timeout_ms)?
            }
        }
    }
    assert!(captured.is_empty());
    Ok(())
}

fn parameter_matches(kind: &QuicTransportParameterKind, observed_id: u64) -> bool {
    use QuicTransportParameterKind as Kind;

    match kind {
        Kind::InitialMaxStreamDataUni { .. } => observed_id == 0x07,
        Kind::InitialMaxStreamDataBidiLocal { .. } => observed_id == 0x05,
        Kind::VersionInformation(_) => observed_id == 0x11,
        Kind::InitialMaxData { .. } => observed_id == 0x04,
        Kind::InitialMaxStreamsBidi { .. } => observed_id == 0x08,
        Kind::GoogleConnectionOptions(_) => observed_id == 0x3128,
        Kind::InitialMaxStreamsUni { .. } => observed_id == 0x09,
        Kind::InitialMaxStreamDataBidiRemote { .. } => observed_id == 0x06,
        Kind::Grease(_) => is_reserved_transport_parameter(observed_id),
        Kind::InitialSourceConnectionId { .. } => observed_id == 0x0f,
        Kind::MaxUdpPayloadSize { .. } => observed_id == 0x03,
        Kind::MaxDatagramFrameSize { .. } => observed_id == 0x20,
        Kind::MaxIdleTimeout { .. } => observed_id == 0x01,
    }
}

#[derive(Debug, Eq, PartialEq)]
struct CapturedQuicParameter {
    id: u64,
    id_width: QuicVarIntWidth,
    length_width: QuicVarIntWidth,
    value: Vec<u8>,
}

fn parse_quic_transport_parameters(
    fixture: &str,
) -> Result<Vec<CapturedQuicParameter>, Box<dyn std::error::Error>> {
    let count = fixture
        .lines()
        .find_map(|line| line.strip_prefix("transport_parameter_count="))
        .ok_or("HTTP/3 fixture omitted transport-parameter count")?
        .parse::<usize>()?;
    let mut annotated = Vec::with_capacity(count);

    for index in 0..count {
        let prefix = format!("transport_parameter_{index}=");
        let encoded = fixture
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .ok_or("HTTP/3 fixture omitted an indexed transport parameter")?;
        let mut fields = BTreeMap::new();
        for field in encoded.split(',') {
            let (name, value) = field
                .split_once(':')
                .ok_or("transport-parameter field omitted `:`")?;
            if fields.insert(name, value).is_some() {
                return Err("transport-parameter field repeated".into());
            }
        }
        if fields.keys().copied().collect::<Vec<_>>()
            != ["id", "id_width", "length_width", "value_hex"]
        {
            return Err("transport-parameter fields do not match the fixture schema".into());
        }
        annotated.push(CapturedQuicParameter {
            id: fields["id"].parse()?,
            id_width: parse_quic_width(fields["id_width"])?,
            length_width: parse_quic_width(fields["length_width"])?,
            value: decode_hex(fields["value_hex"])?,
        });
    }

    let wire = fixture
        .lines()
        .find_map(|line| line.strip_prefix("transport_parameters_hex="))
        .ok_or("HTTP/3 fixture omitted raw transport parameters")?;
    let decoded = decode_transport_parameter_bytes(&decode_hex(wire)?)?;
    if decoded != annotated || decoded.len() != count {
        return Err("raw transport parameters disagree with annotated fixture fields".into());
    }
    Ok(decoded)
}

fn decode_transport_parameter_bytes(
    encoded: &[u8],
) -> Result<Vec<CapturedQuicParameter>, Box<dyn std::error::Error>> {
    let mut remaining = encoded;
    let mut parameters = Vec::new();
    while !remaining.is_empty() {
        let (id, id_width, id_len) = decode_quic_varint_prefix(remaining)?;
        remaining = &remaining[id_len..];
        let (value_len, length_width, length_len) = decode_quic_varint_prefix(remaining)?;
        remaining = &remaining[length_len..];
        let value_len = usize::try_from(value_len)?;
        let value = remaining
            .get(..value_len)
            .ok_or("transport-parameter value exceeds the retained wire bytes")?;
        parameters.push(CapturedQuicParameter {
            id,
            id_width,
            length_width,
            value: value.to_vec(),
        });
        remaining = &remaining[value_len..];
    }
    Ok(parameters)
}

fn parse_quic_width(value: &str) -> Result<QuicVarIntWidth, Box<dyn std::error::Error>> {
    match value {
        "1" => Ok(QuicVarIntWidth::One),
        "2" => Ok(QuicVarIntWidth::Two),
        "4" => Ok(QuicVarIntWidth::Four),
        "8" => Ok(QuicVarIntWidth::Eight),
        _ => Err("invalid QUIC varint width".into()),
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !value.len().is_multiple_of(2) {
        return Err("hex value has odd length".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|offset| Ok(u8::from_str_radix(&value[offset..offset + 2], 16)?))
        .collect()
}

fn assert_quic_scalar(
    observed: &CapturedQuicParameter,
    expected_id: u64,
    expected_width: QuicVarIntWidth,
    expected_value: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(observed.id, expected_id);
    assert_eq!(observed.value.len(), expected_width.encoded_len());
    let (value, width) = decode_quic_varint(&observed.value)?;
    assert_eq!(width, expected_width);
    assert_eq!(value, expected_value);
    Ok(())
}

fn decode_quic_varint(
    encoded: &[u8],
) -> Result<(u64, QuicVarIntWidth), Box<dyn std::error::Error>> {
    let first = *encoded.first().ok_or("QUIC varint is empty")?;
    let width = match first >> 6 {
        0 => QuicVarIntWidth::One,
        1 => QuicVarIntWidth::Two,
        2 => QuicVarIntWidth::Four,
        3 => QuicVarIntWidth::Eight,
        _ => return Err("QUIC varint prefix is invalid".into()),
    };
    if encoded.len() != width.encoded_len() {
        return Err("QUIC varint length does not match its prefix".into());
    }
    let value = encoded
        .iter()
        .enumerate()
        .fold(0_u64, |value, (index, byte)| {
            (value << 8) | u64::from(if index == 0 { byte & 0x3f } else { *byte })
        });
    Ok((value, width))
}

fn decode_quic_varint_prefix(
    encoded: &[u8],
) -> Result<(u64, QuicVarIntWidth, usize), Box<dyn std::error::Error>> {
    let first = *encoded.first().ok_or("QUIC varint is empty")?;
    let encoded_len = 1_usize << usize::from(first >> 6);
    let encoded_value = encoded
        .get(..encoded_len)
        .ok_or("QUIC varint exceeds the retained wire bytes")?;
    let (value, width) = decode_quic_varint(encoded_value)?;
    Ok((value, width, encoded_len))
}

fn decode_u32_words(value: &[u8]) -> Result<Vec<u32>, Box<dyn std::error::Error>> {
    if !value.len().is_multiple_of(4) {
        return Err("version-information value is not a sequence of u32 values".into());
    }
    Ok(value
        .as_chunks::<4>()
        .0
        .iter()
        .map(|word| u32::from_be_bytes(*word))
        .collect())
}

fn is_reserved_version(version: u32) -> bool {
    version & 0x0f0f_0f0f == 0x0a0a_0a0a
}

fn is_reserved_transport_parameter(identifier: u64) -> bool {
    identifier >= 27 && (identifier - 27).is_multiple_of(31)
}
