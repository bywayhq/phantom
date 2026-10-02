use super::{v135_macos_client_hints, v136_http3_tls, v136_tls, v136_windows_client_hints};
use crate::chromium;
use crate::client_hints::navigation_capture::{NavigationCapture, profile_hints};
use crate::http2::{
    Http2HpackSettings, Http2Settings, Http2StreamSettings, session_capture::SessionCapture,
};

const CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/opera/136.0.6008.52/windows-11-26200/navigation.txt"
));
const MACOS_CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/opera/135.0.5973.92/macos-15.5-arm64/navigation.txt"
));
const SESSION_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/websocket/opera/136.0.6008.52/windows-11-26200/accept.txt"
));

#[test]
fn opera_136_windows_client_hints_match_navigation_capture()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = v136_windows_client_hints();
    settings.validate()?;
    let capture = NavigationCapture::parse(CLIENT_HINT_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Opera");
    assert_eq!(capture.value("client_version")?, "136.0.6008.52");
    assert_eq!(
        capture.value("operating_system")?,
        "Windows 11 Home 10.0.26200 x64"
    );
    assert_eq!(capture.value("launch_mode")?, "headless");
    assert_eq!(capture.value("repeat_count")?, "3");
    capture.assert_runs_agree()?;
    assert_eq!(profile_hints(&settings), capture.hints()?);
    Ok(())
}

#[test]
fn opera_client_hints_share_the_chromium_names_order_and_delivery() {
    let names = |settings: crate::ClientHintSettings| {
        settings
            .hints()
            .iter()
            .map(|hint| (hint.name().to_owned(), hint.delivery()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(v136_windows_client_hints()),
        names(chromium::v154_windows_client_hints())
    );
}

#[test]
fn opera_136_recipes_keep_the_backend_ech_grease_aead_policy() {
    for settings in [v136_tls(), v136_http3_tls()] {
        assert!(settings.ech_grease);
        assert!(settings.ech_grease_aeads.is_empty());
        assert!(settings.aes_hardware);
    }
}

/// Opera 136 sends the Chromium offers with its own 32 trust-anchor IDs, in
/// one order over TCP and QUIC.
#[test]
fn opera_136_tls_recipes_are_chromium_s_with_opera_trust_anchor_ids()
-> Result<(), Box<dyn std::error::Error>> {
    let opera = v136_tls();
    opera.validate()?;
    let ids = opera
        .requested_trust_anchor_ids
        .clone()
        .ok_or("Opera 136 recipe omitted trust-anchor IDs")?;
    assert_eq!(ids.len(), 32);
    let mut expected = chromium::v154_tls();
    let chrome_ids = expected
        .requested_trust_anchor_ids
        .clone()
        .ok_or("Chrome 154 recipe omitted trust-anchor IDs")?;
    assert!(chrome_ids.iter().all(|id| ids.contains(id)));
    let mut added = ids
        .iter()
        .filter(|id| !chrome_ids.contains(id))
        .map(|id| id.as_ref())
        .collect::<Vec<_>>();
    added.sort_unstable();
    assert_eq!(
        added,
        [
            &[0xd6, 0x79, 0x09, 0x02][..],
            &[0xd6, 0x79, 0x09, 0x03],
            &[0xd6, 0x79, 0x09, 0x09],
            &[0xd6, 0x79, 0x09, 0x0e],
        ]
    );
    expected.requested_trust_anchor_ids = Some(ids.clone());
    expected.ech_from_https_records = false;
    assert_eq!(opera, expected);

    let opera = v136_http3_tls();
    opera.validate()?;
    let mut expected = chromium::v154_http3_tls();
    expected.requested_trust_anchor_ids = Some(ids);
    expected.ech_from_https_records = false;
    assert_eq!(opera, expected);
    Ok(())
}

#[test]
fn opera_136_http2_session_capture_matches_the_chromium_recipe()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = SessionCapture::parse(SESSION_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Opera");
    assert_eq!(capture.value("client_version")?, "136.0.6008.52");
    assert_eq!(capture.value("scenario")?, "accept");
    let observed = capture.navigation_settings()?;
    assert_eq!(observed.len(), 3);
    let settings = chromium::v154_http2();
    let navigation = Http2Settings {
        extended_connect_pseudo_header_order: None,
        extended_connect_priority: None,
        hpack: Http2HpackSettings {
            static_name_index: settings.hpack.static_name_index,
            ..Http2HpackSettings::default()
        },
        // A capture shows the first stream ID but neither the assumed limit
        // nor the cap, and one navigation shows no preface PING.
        streams: Http2StreamSettings {
            assumed_max_concurrent_streams: None,
            max_concurrent_streams_cap: None,
            ..settings.streams
        },
        preface_ping_after: None,
        ping_timeout: None,
        ..settings
    };
    for run in observed {
        assert_eq!(run, navigation);
    }
    Ok(())
}

#[test]
fn opera_135_macos_client_hints_match_navigation_capture() -> Result<(), Box<dyn std::error::Error>>
{
    let settings = v135_macos_client_hints();
    settings.validate()?;
    let capture = NavigationCapture::parse(MACOS_CLIENT_HINT_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Opera");
    assert_eq!(capture.value("client_version")?, "135.0.5973.92");
    assert_eq!(
        capture.value("operating_system")?,
        "macOS 15.5 (24F74) arm64"
    );
    assert_eq!(capture.value("launch_mode")?, "headless");
    assert_eq!(capture.value("repeat_count")?, "3");
    capture.assert_runs_agree()?;
    assert_eq!(profile_hints(&settings), capture.hints()?);
    Ok(())
}

/// The macOS 15.5 arm64 page loads carry the same H2 settings as on Windows.
#[test]
fn opera_135_macos_http2_session_capture_matches_the_chromium_recipe()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = SessionCapture::parse(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/websocket/opera/135.0.5973.92/macos-15.5-arm64/accept.txt"
    )))?;
    assert_eq!(capture.value("client")?, "Opera");
    assert_eq!(
        capture.value("operating_system")?,
        "macOS 15.5 (24F74) arm64"
    );
    assert_eq!(capture.value("scenario")?, "accept");
    let settings = chromium::v154_http2();
    let navigation = Http2Settings {
        extended_connect_pseudo_header_order: None,
        extended_connect_priority: None,
        hpack: Http2HpackSettings {
            static_name_index: settings.hpack.static_name_index,
            ..Http2HpackSettings::default()
        },
        // A capture shows the first stream ID but neither the assumed limit
        // nor the cap, and one navigation shows no preface PING.
        streams: Http2StreamSettings {
            assumed_max_concurrent_streams: None,
            max_concurrent_streams_cap: None,
            ..settings.streams
        },
        preface_ping_after: None,
        ping_timeout: None,
        ..settings
    };
    let observed = capture.navigation_settings()?;
    assert_eq!(observed.len(), 3);
    for run in observed {
        assert_eq!(run, navigation);
    }
    Ok(())
}
