use crate::{
    Http3PseudoHeader, Http3QpackDecoderStream, Http3QpackEncoding, Http3Setting, Http3SettingOrder,
};

use super::{v152_macos_http3, v152_macos_http3_request};

const FIXTURE: &str =
    include_str!("../../../../fixtures/http3/chrome/152.0.7977.83/macos-15.5/client-startup.txt");

#[test]
fn v152_http3_settings_match_retained_control_stream() -> Result<(), Box<dyn std::error::Error>> {
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
            .map(fixture_request_name)
            .collect::<Result<Vec<_>, _>>()?,
        [":method", ":authority", ":scheme", ":path"]
    );
    assert_eq!(
        profile.initial_settings,
        [
            Http3Setting::QpackMaxTableCapacity(fixture_value(0)),
            Http3Setting::MaxFieldSectionSize(fixture_value(1)),
            Http3Setting::QpackBlockedStreams(fixture_value(2)),
            Http3Setting::H3Datagram(fixture_value(3) == 1),
            Http3Setting::RandomizedGrease,
        ]
    );
    Ok(())
}

fn fixture_request_name(index: usize) -> Result<String, std::string::FromUtf8Error> {
    let prefix = format!("request_header_{index}=");
    let line = FIXTURE
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

fn fixture_value(index: usize) -> u64 {
    let prefix = format!("setting_{index}=");
    let line = FIXTURE
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("fixture must contain {prefix}"));
    line.split(',')
        .find_map(|field| field.strip_prefix("value:"))
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("fixture setting value must be an integer"))
}
