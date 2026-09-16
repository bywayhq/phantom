use std::collections::BTreeMap;

use super::{v152_macos_http2, v152_macos_quic, v152_macos_tls};
use crate::http2::{Http2Priority, Http2PseudoHeader, Http2Setting, Http2Settings};
use crate::quic::{
    GoogleConnectionOption, QuicTransportParameterKind, QuicTransportParameterOrder,
    QuicVarIntWidth, QuicVersionGrease,
};

const PINGLY_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/http2/chrome/152.0.7977.83/macos-15.5/pingly-api-all.txt"
));
const INITIAL_CONNECTION_WINDOW: u32 = 65_535;

const HTTP3_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/http3/chrome/152.0.7977.83/macos-15.5/client-startup.txt"
));

#[test]
fn chrome_152_macos_tls_settings_are_valid() -> Result<(), Box<dyn std::error::Error>> {
    let settings = v152_macos_tls();
    settings.validate()?;
    let alps = settings.alps.ok_or("Chrome TLS profile omitted ALPS")?;
    assert_eq!(alps.protocol.as_ref(), b"h2");
    assert!(alps.settings.is_empty());
    assert!(alps.use_new_codepoint);
    Ok(())
}

#[test]
fn chrome_152_macos_http2_settings_match_retained_pingly_observation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = parse_fixture(PINGLY_FIXTURE)?;
    assert_fixture_metadata(&fixture)?;

    let initial_settings = parse_settings(required(&fixture, "settings")?)?;
    let window_increment = parse_u32(required(&fixture, "connection_window_update")?)?;
    let initial_connection_window_size = INITIAL_CONNECTION_WINDOW
        .checked_add(window_increment)
        .ok_or("connection window overflow")?;
    let pseudo_header_order = parse_pseudo_order(required(&fixture, "pseudo_header_order")?)?;
    let headers_priority = Http2Priority {
        dependency_stream_id: parse_u32(required(&fixture, "headers_priority_dependency")?)?,
        exclusive: parse_bool(required(&fixture, "headers_priority_exclusive")?)?,
        weight: required(&fixture, "headers_priority_weight")?.parse()?,
    };

    let observed = Http2Settings {
        initial_settings,
        initial_connection_window_size,
        pseudo_header_order,
        headers_priority: Some(headers_priority),
    };
    observed.validate()?;

    assert_eq!(v152_macos_http2(), observed);
    assert_eq!(window_increment, 15_663_105);
    assert_eq!(initial_connection_window_size, 15_728_640);
    assert_eq!(
        parse_u32(required(&fixture, "settings_frame_stream_id")?)?,
        0
    );
    assert_eq!(
        parse_u32(required(&fixture, "settings_frame_payload_length")?)?,
        u32::try_from(observed.initial_settings.len())? * 6
    );
    assert_eq!(
        parse_u32(required(&fixture, "headers_frame_stream_id")?)?,
        1
    );
    assert_eq!(
        parse_u32(required(&fixture, "headers_frame_flags")?)?,
        0x01 | 0x04 | 0x20
    );
    assert_eq!(
        required(&fixture, "notes")?,
        "Supplemental live endpoint observation; retain a local raw-frame fixture before making packet-parity claims."
    );
    assert_akamai_summary(&fixture, &observed, window_increment)?;

    Ok(())
}

#[test]
fn chrome_152_macos_quic_settings_match_retained_startup_shape()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = v152_macos_quic();
    settings.validate()?;
    let captured = parse_quic_transport_parameters(HTTP3_FIXTURE)?;

    assert_eq!(captured.len(), settings.wire_parameters.len());
    assert_eq!(
        settings.parameter_order,
        QuicTransportParameterOrder::Permuted
    );

    use QuicTransportParameterKind as Kind;
    for (parameter, observed) in settings.wire_parameters.iter().zip(&captured) {
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
                observed,
                0x07,
                *value_width,
                settings.initial_max_stream_data_uni,
            )?,
            Kind::InitialMaxStreamDataBidiLocal { value_width } => assert_quic_scalar(
                observed,
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
                assert_quic_scalar(observed, 0x04, *value_width, settings.initial_max_data)?;
            }
            Kind::InitialMaxStreamsBidi { value_width } => assert_quic_scalar(
                observed,
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
                observed,
                0x09,
                *value_width,
                settings.initial_max_streams_uni,
            )?,
            Kind::InitialMaxStreamDataBidiRemote { value_width } => assert_quic_scalar(
                observed,
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
                assert_quic_scalar(observed, 0x03, *value_width, settings.max_udp_payload_size)?
            }
            Kind::MaxDatagramFrameSize { value_width } => assert_quic_scalar(
                observed,
                0x20,
                *value_width,
                settings
                    .max_datagram_frame_size
                    .ok_or("captured DATAGRAM setting omitted its value")?,
            )?,
            Kind::MaxIdleTimeout { value_width } => {
                assert_quic_scalar(observed, 0x01, *value_width, settings.max_idle_timeout_ms)?
            }
        }
    }
    Ok(())
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
    if value.len() % 2 != 0 {
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
    if value.len() % 4 != 0 {
        return Err("version-information value is not a sequence of u32 values".into());
    }
    value
        .chunks_exact(4)
        .map(|word| {
            let bytes: [u8; 4] = word.try_into()?;
            Ok(u32::from_be_bytes(bytes))
        })
        .collect()
}

fn is_reserved_version(version: u32) -> bool {
    version & 0x0f0f_0f0f == 0x0a0a_0a0a
}

fn is_reserved_transport_parameter(identifier: u64) -> bool {
    identifier >= 27 && (identifier - 27) % 31 == 0
}

fn parse_fixture(input: &str) -> Result<BTreeMap<&str, &str>, Box<dyn std::error::Error>> {
    let mut fields = BTreeMap::new();
    for line in input.lines() {
        let (key, value) = line.split_once('=').ok_or("fixture line is missing `=`")?;
        if key.is_empty() || value.is_empty() || fields.insert(key, value).is_some() {
            return Err("fixture contains an empty or duplicate field".into());
        }
    }

    const EXPECTED_KEYS: [&str; 19] = [
        "akamai_fingerprint",
        "browser",
        "captured_at",
        "connection_window_update",
        "endpoint",
        "format",
        "headers_frame_flags",
        "headers_frame_stream_id",
        "headers_priority_dependency",
        "headers_priority_exclusive",
        "headers_priority_weight",
        "http_version",
        "mode",
        "notes",
        "os",
        "pseudo_header_order",
        "settings",
        "settings_frame_payload_length",
        "settings_frame_stream_id",
    ];
    if fields.keys().copied().collect::<Vec<_>>() != EXPECTED_KEYS {
        return Err("fixture keys do not match the versioned format".into());
    }
    Ok(fields)
}

fn assert_fixture_metadata(
    fixture: &BTreeMap<&str, &str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected = [
        ("format", "phantom-pingly-http2-v1"),
        ("captured_at", "2026-09-15"),
        ("browser", "Google Chrome 152.0.7977.83"),
        ("os", "macOS 15.5 (24F74)"),
        ("endpoint", "https://pingly.us.kg/api/all"),
        ("mode", "headless-new-isolated-profile"),
        ("http_version", "HTTP/2.0"),
    ];
    for (key, value) in expected {
        if required(fixture, key)? != value {
            return Err(format!("unexpected fixture {key}").into());
        }
    }
    Ok(())
}

fn parse_settings(value: &str) -> Result<Vec<Http2Setting>, Box<dyn std::error::Error>> {
    value
        .split(',')
        .map(|pair| {
            let (id, value) = pair.split_once(':').ok_or("invalid SETTINGS pair")?;
            let value = parse_u32(value)?;
            match id {
                "1" => Ok(Http2Setting::HeaderTableSize(value)),
                "2" => match value {
                    0 => Ok(Http2Setting::EnablePush(false)),
                    1 => Ok(Http2Setting::EnablePush(true)),
                    _ => Err("invalid SETTINGS_ENABLE_PUSH value".into()),
                },
                "3" => Ok(Http2Setting::MaxConcurrentStreams(value)),
                "4" => Ok(Http2Setting::InitialWindowSize(value)),
                "5" => Ok(Http2Setting::MaxFrameSize(value)),
                "6" => Ok(Http2Setting::MaxHeaderListSize(value)),
                "8" => match value {
                    0 => Ok(Http2Setting::EnableConnectProtocol(false)),
                    1 => Ok(Http2Setting::EnableConnectProtocol(true)),
                    _ => Err("invalid SETTINGS_ENABLE_CONNECT_PROTOCOL value".into()),
                },
                "9" => match value {
                    0 => Ok(Http2Setting::NoRfc7540Priorities(false)),
                    1 => Ok(Http2Setting::NoRfc7540Priorities(true)),
                    _ => Err("invalid SETTINGS_NO_RFC7540_PRIORITIES value".into()),
                },
                _ => Err(format!("unsupported SETTINGS identifier {id}").into()),
            }
        })
        .collect()
}

fn parse_pseudo_order(value: &str) -> Result<Vec<Http2PseudoHeader>, Box<dyn std::error::Error>> {
    value
        .split(',')
        .map(|header| match header {
            "method" => Ok(Http2PseudoHeader::Method),
            "authority" => Ok(Http2PseudoHeader::Authority),
            "scheme" => Ok(Http2PseudoHeader::Scheme),
            "path" => Ok(Http2PseudoHeader::Path),
            _ => Err(format!("unsupported pseudo-header {header}").into()),
        })
        .collect()
}

fn assert_akamai_summary(
    fixture: &BTreeMap<&str, &str>,
    observed: &Http2Settings,
    window_increment: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let parts = required(fixture, "akamai_fingerprint")?
        .split('|')
        .collect::<Vec<_>>();
    if parts.len() != 4 {
        return Err("invalid Akamai summary".into());
    }
    assert_eq!(
        parse_settings(&parts[0].replace(';', ","))?,
        observed.initial_settings
    );
    assert_eq!(parse_u32(parts[1])?, window_increment);
    assert_eq!(parts[2], "0");
    assert_eq!(parts[3], "m,a,s,p");
    Ok(())
}

fn required<'a>(
    fields: &'a BTreeMap<&str, &str>,
    key: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    fields
        .get(key)
        .copied()
        .ok_or_else(|| format!("missing fixture field {key}").into())
}

fn parse_u32(value: &str) -> Result<u32, Box<dyn std::error::Error>> {
    Ok(value.parse()?)
}

fn parse_bool(value: &str) -> Result<bool, Box<dyn std::error::Error>> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("invalid boolean {value}").into()),
    }
}
