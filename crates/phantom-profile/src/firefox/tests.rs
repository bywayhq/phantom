use super::v154_macos_http2;
use crate::http2::{Http2Priority, Http2PseudoHeader, Http2Setting};

const LOCAL_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/http2/firefox/154.0/macos-15.5/client-startup.txt"
));
const PEET_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/http2/firefox/154.0/macos-15.5/peet-api-all.txt"
));
const PINGLY_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/http2/firefox/154.0/macos-15.5/pingly-api-all.txt"
));

#[test]
fn firefox_154_macos_http2_startup_matches_local_capture() -> Result<(), Box<dyn std::error::Error>>
{
    let settings = v154_macos_http2();
    settings.validate()?;

    assert_eq!(
        settings.initial_settings,
        [
            Http2Setting::HeaderTableSize(65_536),
            Http2Setting::EnablePush(false),
            Http2Setting::InitialWindowSize(131_072),
            Http2Setting::MaxFrameSize(16_384),
        ]
    );
    assert_eq!(settings.initial_connection_window_size, 12_582_912);
    assert_eq!(
        fixture_value(LOCAL_FIXTURE, "initial_settings")?,
        "0x0001:65536,0x0002:0,0x0004:131072,0x0005:16384"
    );
    assert_eq!(
        fixture_value(LOCAL_FIXTURE, "connection_window_update")?,
        "12517377"
    );
    assert_eq!(
        settings.initial_connection_window_size - 65_535,
        fixture_value(LOCAL_FIXTURE, "connection_window_update")?.parse()?
    );

    Ok(())
}

#[test]
fn firefox_154_macos_request_shape_matches_supplemental_observations()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = v154_macos_http2();
    let expected_order = [
        Http2PseudoHeader::Method,
        Http2PseudoHeader::Path,
        Http2PseudoHeader::Authority,
        Http2PseudoHeader::Scheme,
    ];
    let expected_priority = Http2Priority {
        dependency_stream_id: 0,
        weight: 42,
        exclusive: false,
    };

    assert_eq!(settings.pseudo_header_order, expected_order);
    assert_eq!(settings.headers_priority, Some(expected_priority));
    for fixture in [PEET_FIXTURE, PINGLY_FIXTURE] {
        assert_eq!(
            fixture_value(fixture, "evidence_role")?,
            "supplemental-live-not-regression-oracle"
        );
        assert_eq!(
            fixture_value(fixture, "pseudo_header_order")?,
            "method,path,authority,scheme"
        );
        assert_eq!(fixture_value(fixture, "headers_priority_dependency")?, "0");
        assert_eq!(fixture_value(fixture, "headers_priority_weight")?, "42");
        assert_eq!(
            fixture_value(fixture, "headers_priority_exclusive")?,
            "false"
        );
    }

    Ok(())
}

fn fixture_value<'a>(
    fixture: &'a str,
    expected_key: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    fixture
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key == expected_key).then_some(value)
        })
        .ok_or_else(|| format!("fixture omitted {expected_key}").into())
}
