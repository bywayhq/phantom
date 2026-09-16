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

    assert_eq!(settings.max_idle_timeout_ms, 30_000);
    assert_eq!(settings.max_udp_payload_size, 1_472);
    assert_eq!(settings.initial_max_data, 15_728_640);
    assert_eq!(settings.initial_max_stream_data_bidi_local, 6_291_456);
    assert_eq!(settings.initial_max_stream_data_bidi_remote, 6_291_456);
    assert_eq!(settings.initial_max_stream_data_uni, 6_291_456);
    assert_eq!(settings.initial_max_streams_bidi, 100);
    assert_eq!(settings.initial_max_streams_uni, 103);
    assert_eq!(settings.max_datagram_frame_size, Some(65_536));
    assert_eq!(
        settings.parameter_order,
        QuicTransportParameterOrder::Permuted
    );

    use QuicTransportParameterKind as Kind;
    use QuicVarIntWidth::{Eight, Four, One, Two};
    let expected = [
        ("initial_max_stream_data_uni", One, One, Some(Four)),
        ("initial_max_stream_data_bidi_local", One, One, Some(Four)),
        ("version_information_permuted_grease", One, One, None),
        ("initial_max_data", One, One, Some(Four)),
        ("initial_max_streams_bidi", One, One, Some(Two)),
        ("google_orig", Two, One, None),
        ("initial_max_streams_uni", One, One, Some(Two)),
        ("initial_max_stream_data_bidi_remote", One, One, Some(Four)),
        ("grease_0_15", Eight, One, None),
        ("initial_source_connection_id", One, One, None),
        ("max_udp_payload_size", One, One, Some(Two)),
        ("max_datagram_frame_size", One, One, Some(Four)),
        ("max_idle_timeout", One, One, Some(Four)),
    ];
    let actual = settings
        .wire_parameters
        .iter()
        .map(|parameter| {
            let (name, value_width) = match &parameter.kind {
                Kind::InitialMaxStreamDataUni { value_width } => {
                    ("initial_max_stream_data_uni", Some(*value_width))
                }
                Kind::InitialMaxStreamDataBidiLocal { value_width } => {
                    ("initial_max_stream_data_bidi_local", Some(*value_width))
                }
                Kind::VersionInformation(version)
                    if version.grease == QuicVersionGrease::Permuted =>
                {
                    ("version_information_permuted_grease", None)
                }
                Kind::InitialMaxData { value_width } => ("initial_max_data", Some(*value_width)),
                Kind::InitialMaxStreamsBidi { value_width } => {
                    ("initial_max_streams_bidi", Some(*value_width))
                }
                Kind::GoogleConnectionOptions(options)
                    if options == &[GoogleConnectionOption::RequestOriginFrame] =>
                {
                    ("google_orig", None)
                }
                Kind::InitialMaxStreamsUni { value_width } => {
                    ("initial_max_streams_uni", Some(*value_width))
                }
                Kind::InitialMaxStreamDataBidiRemote { value_width } => {
                    ("initial_max_stream_data_bidi_remote", Some(*value_width))
                }
                Kind::Grease(grease)
                    if grease.minimum_payload_length == 0
                        && grease.maximum_payload_length == 15 =>
                {
                    ("grease_0_15", None)
                }
                Kind::InitialSourceConnectionId => ("initial_source_connection_id", None),
                Kind::MaxUdpPayloadSize { value_width } => {
                    ("max_udp_payload_size", Some(*value_width))
                }
                Kind::MaxDatagramFrameSize { value_width } => {
                    ("max_datagram_frame_size", Some(*value_width))
                }
                Kind::MaxIdleTimeout { value_width } => ("max_idle_timeout", Some(*value_width)),
                _ => ("unexpected", None),
            };
            (
                name,
                parameter.id_width,
                parameter.length_width,
                value_width,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);

    assert!(HTTP3_FIXTURE.contains("transport_parameter_count=13\n"));
    assert!(
        HTTP3_FIXTURE.contains(
            "transport_parameter_5=id:12584,id_width:2,length_width:1,value_hex:4f524947\n"
        )
    );
    assert!(
        HTTP3_FIXTURE
            .contains("transport_parameter_8=id:2442798693768785165,id_width:8,length_width:1,")
    );
    Ok(())
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
