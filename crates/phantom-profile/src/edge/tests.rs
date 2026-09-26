use super::{v154_http3_tls, v154_macos_client_hints, v154_tls, v154_windows_client_hints};
use crate::chromium;
use crate::client_hints::navigation_capture::{NavigationCapture, changed_hints, profile_hints};
use crate::http2::{
    Http2HpackSettings, Http2Settings, Http2StreamSettings, session_capture::SessionCapture,
};

const CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/edge/154.0.4258.37/windows-11-26200/navigation.txt"
));
const MACOS_CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/edge/154.0.4258.37/macos-15.5-arm64/navigation.txt"
));
const SESSION_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/websocket/edge/154.0.4258.37/windows-11-26200/accept.txt"
));

#[test]
fn edge_154_windows_client_hints_match_navigation_capture() -> Result<(), Box<dyn std::error::Error>>
{
    let settings = v154_windows_client_hints();
    settings.validate()?;
    let capture = NavigationCapture::parse(CLIENT_HINT_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Microsoft Edge");
    assert_eq!(capture.value("client_version")?, "154.0.4258.37");
    assert_eq!(
        capture.value("operating_system")?,
        "Windows 11 Home 10.0.26200 x64"
    );
    assert_eq!(capture.value("launch_mode")?, "headless");
    assert_eq!(capture.value("repeat_count")?, "1");
    capture.assert_runs_agree()?;
    assert_eq!(profile_hints(&settings), capture.hints()?);
    Ok(())
}

#[test]
fn edge_154_client_hints_share_the_chromium_names_order_and_delivery() {
    let names = |settings: crate::ClientHintSettings| {
        settings
            .hints()
            .iter()
            .map(|hint| (hint.name().to_owned(), hint.delivery()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(v154_windows_client_hints()),
        names(chromium::v154_windows_client_hints())
    );
}

#[test]
fn edge_154_recipes_keep_the_backend_ech_grease_aead_policy() {
    // Edge advertises AES-128-GCM like Chrome; the backend default produces
    // that choice because `aes_hardware` is set.
    for settings in [v154_tls(), v154_http3_tls()] {
        assert!(settings.ech_grease);
        assert!(settings.ech_grease_aeads.is_empty());
        assert!(settings.aes_hardware);
    }
}

/// On the wire the Edge and Chrome ClientHellos differ only in the
/// trust-anchor IDs, with or without an HTTPS record's `ech`.
#[test]
fn edge_154_tls_recipes_remove_only_the_chromium_trust_anchor_ids()
-> Result<(), Box<dyn std::error::Error>> {
    for (edge, chrome) in [
        (v154_tls(), chromium::v154_tls()),
        (v154_http3_tls(), chromium::v154_http3_tls()),
    ] {
        edge.validate()?;
        assert!(chrome.requested_trust_anchor_ids.is_some());
        let mut expected = chrome;
        expected.requested_trust_anchor_ids = None;
        assert_eq!(edge, expected);
    }
    Ok(())
}

#[test]
fn edge_154_http2_session_capture_matches_the_chromium_recipe()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = SessionCapture::parse(SESSION_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Microsoft Edge");
    assert_eq!(capture.value("client_version")?, "154.0.4258.37");
    assert_eq!(capture.value("scenario")?, "accept");
    let observed = capture.navigation_settings()?;
    assert_eq!(observed.len(), 3);
    // One navigation block shows only the static-name choice; the WebSocket
    // recipe tests compare the whole encoder identity with every CONNECT.
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
fn edge_154_macos_client_hints_match_navigation_capture() -> Result<(), Box<dyn std::error::Error>>
{
    let settings = v154_macos_client_hints();
    settings.validate()?;
    let capture = NavigationCapture::parse(MACOS_CLIENT_HINT_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Microsoft Edge");
    assert_eq!(capture.value("client_version")?, "154.0.4258.37");
    assert_eq!(
        capture.value("operating_system")?,
        "macOS 15.5 (24F74) arm64"
    );
    assert_eq!(capture.value("launch_mode")?, "headless");
    assert_eq!(capture.value("repeat_count")?, "3");
    // On macOS Edge ignores `--lang`; the capture sets its languages.
    assert!(
        capture
            .value("launch_arguments")?
            .contains("--accept-lang=en-US")
    );
    capture.assert_runs_agree()?;
    assert_eq!(profile_hints(&settings), capture.hints()?);
    Ok(())
}

/// macOS changes only the platform hints.
#[test]
fn edge_154_macos_client_hints_differ_from_windows_only_in_platform_data() {
    let changed = changed_hints(&v154_windows_client_hints(), &v154_macos_client_hints());
    assert_eq!(
        changed,
        [
            ("sec-ch-ua-arch", r#""arm""#),
            ("sec-ch-ua-platform", r#""macOS""#),
            ("sec-ch-ua-platform-version", r#""15.5.0""#),
        ]
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
    );
}

/// The macOS 15.5 arm64 page loads carry the same H2 settings as on Windows.
#[test]
fn edge_154_macos_http2_session_capture_matches_the_chromium_recipe()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = SessionCapture::parse(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/websocket/edge/154.0.4258.37/macos-15.5-arm64/accept.txt"
    )))?;
    assert_eq!(capture.value("client")?, "Microsoft Edge");
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
