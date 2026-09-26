use super::{v154_http3_tls, v154_tls, v154_windows_client_hints};
use crate::chromium;
use crate::client_hints::navigation_capture::{NavigationCapture, profile_hints};
use crate::http2::{
    Http2HpackSettings, Http2Settings, Http2StreamSettings, session_capture::SessionCapture,
};

const CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/brave/154.1.96.59/windows-11-26200/navigation.txt"
));
const SESSION_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/websocket/brave/154.1.96.59/windows-11-26200/accept.txt"
));

#[test]
fn brave_154_windows_client_hints_match_navigation_capture()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = v154_windows_client_hints();
    settings.validate()?;
    let capture = NavigationCapture::parse(CLIENT_HINT_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Brave");
    assert_eq!(capture.value("client_version")?, "154.1.96.59");
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

/// Brave sends a subset of the Chromium hints in the Chromium order and
/// delivery: it never adds `sec-ch-ua-full-version` or
/// `sec-ch-ua-form-factors`.
#[test]
fn brave_154_client_hints_are_the_chromium_hints_without_two_names() {
    let names = |settings: crate::ClientHintSettings| {
        settings
            .hints()
            .iter()
            .map(|hint| (hint.name().to_owned(), hint.delivery()))
            .collect::<Vec<_>>()
    };
    let mut chromium = names(chromium::v154_windows_client_hints());
    chromium
        .retain(|(name, _)| name != "sec-ch-ua-full-version" && name != "sec-ch-ua-form-factors");
    assert_eq!(names(v154_windows_client_hints()), chromium);
}

#[test]
fn brave_154_recipes_keep_the_backend_ech_grease_aead_policy() {
    for settings in [v154_tls(), v154_http3_tls()] {
        assert!(settings.ech_grease);
        assert!(settings.ech_grease_aeads.is_empty());
        assert!(settings.aes_hardware);
    }
}

#[test]
fn brave_154_tls_recipes_remove_only_the_chromium_trust_anchor_ids()
-> Result<(), Box<dyn std::error::Error>> {
    for (brave, chrome) in [
        (v154_tls(), chromium::v154_tls()),
        (v154_http3_tls(), chromium::v154_http3_tls()),
    ] {
        brave.validate()?;
        assert!(chrome.requested_trust_anchor_ids.is_some());
        let mut expected = chrome;
        expected.requested_trust_anchor_ids = None;
        assert_eq!(brave, expected);
    }
    // Both recipes keep Chrome's ECH from HTTPS records, which the retained
    // Brave ECH captures over TCP and QUIC show.
    assert!(v154_tls().ech_from_https_records);
    assert!(v154_http3_tls().ech_from_https_records);
    Ok(())
}

#[test]
fn brave_154_http2_session_capture_matches_the_chromium_recipe()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = SessionCapture::parse(SESSION_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Brave");
    assert_eq!(capture.value("client_version")?, "154.1.96.59");
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
        // A capture shows the first stream ID but not the assumed limit.
        streams: Http2StreamSettings {
            assumed_max_concurrent_streams: None,
            ..settings.streams
        },
        ..settings
    };
    for run in observed {
        assert_eq!(run, navigation);
    }
    Ok(())
}
