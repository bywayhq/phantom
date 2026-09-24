use crate::{
    Http3PseudoHeader, Http3QpackDecoderStream, Http3QpackEncoding, Http3RequestSettings,
    Http3Setting, Http3SettingOrder, Http3Settings,
};

use super::{v154_http3, v154_http3_request};

const EDGE_153_WINDOWS_FIXTURE: &str = include_str!(
    "../../../../fixtures/http3/edge/153.0.4234.48/windows-11-26200/client-startup.txt"
);
const V154_WINDOWS_FIXTURE: &str = include_str!(
    "../../../../fixtures/http3/chrome/154.0.8037.58/windows-11-26200/client-startup.txt"
);

#[test]
fn chrome_154_http3_recipe_matches_windows_capture() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        fixture_field(V154_WINDOWS_FIXTURE, "client")?,
        "Google Chrome"
    );
    assert_eq!(
        fixture_field(V154_WINDOWS_FIXTURE, "client_version")?,
        "154.0.8037.58"
    );
    assert_settings_match_control_stream(V154_WINDOWS_FIXTURE, v154_http3(), v154_http3_request())
}

/// Edge 153 shares the Chromium H3 control stream and request order; only
/// persona values differ.
#[test]
fn edge_153_h3_capture_matches_the_chromium_recipe() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        fixture_field(EDGE_153_WINDOWS_FIXTURE, "client")?,
        "Microsoft Edge"
    );
    assert_eq!(
        fixture_field(EDGE_153_WINDOWS_FIXTURE, "client_version")?,
        "153.0.4234.48"
    );
    assert_settings_match_control_stream(
        EDGE_153_WINDOWS_FIXTURE,
        v154_http3(),
        v154_http3_request(),
    )?;
    assert_request_fields_match_except_persona(V154_WINDOWS_FIXTURE, EDGE_153_WINDOWS_FIXTURE)
}

fn fixture_field<'a>(fixture: &'a str, key: &str) -> Result<&'a str, Box<dyn std::error::Error>> {
    let prefix = format!("{key}=");
    fixture
        .lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .ok_or_else(|| format!("fixture omitted {key}").into())
}

fn assert_request_fields_match_except_persona(
    reference: &str,
    candidate: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    const PERSONA_FIELDS: [&str; 4] = [
        "user-agent",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
    ];
    let macos = request_fields(reference)?;
    let windows = request_fields(candidate)?;
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
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect::<Result<Vec<u8>, Box<dyn std::error::Error>>>()?;
    Ok(String::from_utf8(bytes)?)
}

fn assert_settings_match_control_stream(
    fixture: &str,
    profile: Http3Settings,
    request: Http3RequestSettings,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(profile.setting_order, Http3SettingOrder::Ascending);
    assert_eq!(profile.qpack_encoding, Http3QpackEncoding::Dynamic);
    assert_eq!(
        profile.qpack_decoder_stream,
        Http3QpackDecoderStream::OnFeedback
    );
    assert_eq!(
        request.pseudo_header_order,
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
        .as_chunks::<2>()
        .0
        .iter()
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
        v154_http3_request().extended_connect_pseudo_header_order,
        None
    );
}
