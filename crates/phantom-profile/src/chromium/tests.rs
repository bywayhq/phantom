use std::collections::BTreeMap;

use super::{v152_macos_client_hints, v152_macos_http2, v152_macos_http3_tls, v152_macos_tls};
use crate::client_hints::ClientHintDelivery;
use crate::http2::{Http2Priority, Http2PseudoHeader, Http2Setting, Http2Settings};

const PINGLY_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/http2/chrome/152.0.7977.83/macos-15.5/pingly-api-all.txt"
));
const INITIAL_CONNECTION_WINDOW: u32 = 65_535;
const CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/chrome/152.0.7977.83/macos-15.5/navigation.txt"
));

#[test]
fn chrome_152_macos_client_hints_match_isolated_navigation_capture()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = v152_macos_client_hints();
    settings.validate()?;
    let lines = CLIENT_HINT_FIXTURE.lines().collect::<Vec<_>>();
    assert_eq!(lines[0], "format=phantom-client-hints-v1");
    assert_eq!(lines[1], "captured_at=2026-09-16");
    assert_eq!(lines[2], "browser=Google Chrome 152.0.7977.83");
    assert_eq!(lines[3], "os=macOS 15.5 arm64");
    assert_eq!(lines[4], "transport=HTTP/1.1");
    assert_eq!(lines[5], "hint_count=11");

    let observed = lines[6..]
        .iter()
        .enumerate()
        .map(|(index, line)| {
            let prefix = format!("hint_{index}=");
            let value = line
                .strip_prefix(&prefix)
                .ok_or("client-hint fixture index is not canonical")?;
            let mut parts = value.splitn(3, '|');
            let delivery = match parts.next() {
                Some("default") => ClientHintDelivery::Default,
                Some("accept-ch") => ClientHintDelivery::AcceptCh,
                _ => return Err("client-hint fixture delivery is invalid"),
            };
            let name = parts.next().ok_or("client-hint fixture name is missing")?;
            let value = parts.next().ok_or("client-hint fixture value is missing")?;
            Ok((delivery, name, value.as_bytes()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let profile = settings
        .hints()
        .iter()
        .map(|hint| (hint.delivery(), hint.name(), hint.value()))
        .collect::<Vec<_>>();
    assert_eq!(profile, observed);
    Ok(())
}

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
fn chrome_152_macos_http3_tls_settings_are_valid() -> Result<(), Box<dyn std::error::Error>> {
    let settings = v152_macos_http3_tls();
    settings.validate()?;
    assert_eq!(settings.min_version, crate::tls::TlsVersion::Tls13);
    assert_eq!(settings.max_version, crate::tls::TlsVersion::Tls13);
    assert_eq!(settings.alpn_protocols, [Box::from(&b"h3"[..])]);
    assert!(!settings.session_tickets);

    let alps = settings
        .alps
        .ok_or("Chrome HTTP/3 TLS profile omitted ALPS")?;
    assert_eq!(alps.protocol.as_ref(), b"h3");
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
    assert_akamai_summary(&fixture, &observed, window_increment)?;

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

    const EXPECTED_KEYS: [&str; 18] = [
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
