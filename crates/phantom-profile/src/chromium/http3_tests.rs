use crate::{
    Http3PseudoHeader, Http3QpackDecoderStream, Http3QpackEncoding, Http3Setting, Http3SettingOrder,
};

use super::{v152_macos_http3, v152_macos_http3_request};

const FIXTURE: &str =
    include_str!("../../../../fixtures/http3/chrome/152.0.7977.83/macos-15.5/client-startup.txt");
const WINDOWS_FIXTURE: &str = include_str!(
    "../../../../fixtures/http3/chrome/152.0.7977.83/windows-11-26200/client-startup.txt"
);

#[test]
fn v152_http3_settings_match_retained_control_stream() -> Result<(), Box<dyn std::error::Error>> {
    assert_settings_match_control_stream(FIXTURE)
}

#[test]
fn chrome_152_http3_recipe_matches_windows_chrome_for_testing_capture()
-> Result<(), Box<dyn std::error::Error>> {
    assert_settings_match_control_stream(WINDOWS_FIXTURE)
}

/// The recipe models only the pseudo-header order; ordinary request fields
/// come from the caller. This compares the two captures directly instead.
#[test]
fn chrome_152_windows_h3_request_fields_match_macos_capture_except_persona_values()
-> Result<(), Box<dyn std::error::Error>> {
    const PERSONA_FIELDS: [&str; 4] = [
        "user-agent",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
    ];
    let macos = request_fields(FIXTURE)?;
    let windows = request_fields(WINDOWS_FIXTURE)?;
    assert_eq!(macos.len(), 17);
    assert_eq!(windows.len(), macos.len());
    for ((macos_name, macos_value), (windows_name, windows_value)) in macos.iter().zip(&windows) {
        assert_eq!(windows_name, macos_name);
        if windows_name == ":authority" || PERSONA_FIELDS.contains(&windows_name.as_str()) {
            continue;
        }
        assert_eq!(windows_value, macos_value, "{windows_name}");
    }
    Ok(())
}

fn request_fields(fixture: &str) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let count: usize = fixture
        .lines()
        .find_map(|line| line.strip_prefix("request_header_count="))
        .ok_or("fixture must contain request_header_count")?
        .parse()?;
    (0..count)
        .map(|index| {
            let prefix = format!("request_header_{index}=");
            let (name, value) = fixture
                .lines()
                .find_map(|line| line.strip_prefix(prefix.as_str()))
                .and_then(|field| field.split_once(':'))
                .ok_or("fixture request header must contain a name and value")?;
            Ok((decode_ascii_hex(name)?, decode_ascii_hex(value)?))
        })
        .collect()
}

fn decode_ascii_hex(encoded: &str) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect::<Result<Vec<u8>, Box<dyn std::error::Error>>>()?;
    Ok(String::from_utf8(bytes)?)
}

fn assert_settings_match_control_stream(fixture: &str) -> Result<(), Box<dyn std::error::Error>> {
    let profile = v152_macos_http3();
    assert_eq!(profile.setting_order, Http3SettingOrder::Ascending);
    assert_eq!(profile.qpack_encoding, Http3QpackEncoding::Dynamic);
    assert_eq!(
        profile.qpack_decoder_stream,
        Http3QpackDecoderStream::OnFeedback
    );
    assert_eq!(
        v152_macos_http3_request().pseudo_header_order,
        [
            Http3PseudoHeader::Method,
            Http3PseudoHeader::Authority,
            Http3PseudoHeader::Scheme,
            Http3PseudoHeader::Path,
        ]
    );
    assert_eq!(
        (0..4)
            .map(|index| fixture_request_name(fixture, index))
            .collect::<Result<Vec<_>, _>>()?,
        [":method", ":authority", ":scheme", ":path"]
    );
    assert_eq!(
        profile.initial_settings,
        [
            Http3Setting::QpackMaxTableCapacity(fixture_value(fixture, 0)),
            Http3Setting::MaxFieldSectionSize(fixture_value(fixture, 1)),
            Http3Setting::QpackBlockedStreams(fixture_value(fixture, 2)),
            Http3Setting::H3Datagram(fixture_value(fixture, 3) == 1),
            Http3Setting::RandomizedGrease,
        ]
    );
    Ok(())
}

fn fixture_request_name(fixture: &str, index: usize) -> Result<String, std::string::FromUtf8Error> {
    let prefix = format!("request_header_{index}=");
    let line = fixture
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("fixture must contain {prefix}"));
    let encoded = line[prefix.len()..]
        .split_once(':')
        .map(|(name, _)| name)
        .unwrap_or_else(|| panic!("fixture request header must contain a value"));
    let bytes = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|digits| u8::from_str_radix(digits, 16).ok())
                .unwrap_or_else(|| panic!("fixture request header name must be valid hex"))
        })
        .collect();
    String::from_utf8(bytes)
}

fn fixture_value(fixture: &str, index: usize) -> u64 {
    let prefix = format!("setting_{index}=");
    let line = fixture
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("fixture must contain {prefix}"));
    line.split(',')
        .find_map(|field| field.strip_prefix("value:"))
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("fixture setting value must be an integer"))
}

#[test]
fn named_http3_recipes_leave_extended_connect_order_unset() {
    assert_eq!(
        v152_macos_http3_request().extended_connect_pseudo_header_order,
        None
    );
}
