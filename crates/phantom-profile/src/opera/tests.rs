use super::{v135_http3_tls, v135_tls, v135_windows_client_hints};
use crate::chromium;
use crate::client_hints::navigation_capture::{NavigationCapture, profile_hints};
use crate::http2::{Http2HpackSettings, Http2Settings, session_capture::SessionCapture};

const CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/opera/135.0.5973.92/windows-11-26200/navigation.txt"
));
const SESSION_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/websocket/opera/135.0.5973.92/windows-11-26200/accept.txt"
));

#[test]
fn opera_135_windows_client_hints_match_navigation_capture()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = v135_windows_client_hints();
    settings.validate()?;
    let capture = NavigationCapture::parse(CLIENT_HINT_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Opera");
    assert_eq!(capture.value("client_version")?, "135.0.5973.92");
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
fn opera_135_client_hints_share_the_chromium_names_order_and_delivery() {
    let names = |settings: crate::ClientHintSettings| {
        settings
            .hints()
            .iter()
            .map(|hint| (hint.name().to_owned(), hint.delivery()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(v135_windows_client_hints()),
        names(chromium::v154_windows_client_hints())
    );
}

#[test]
fn opera_135_recipes_keep_the_backend_ech_grease_aead_policy() {
    for settings in [v135_tls(), v135_http3_tls()] {
        assert!(settings.ech_grease);
        assert!(settings.ech_grease_aeads.is_empty());
        assert!(settings.aes_hardware);
    }
}

#[test]
fn opera_135_tls_recipes_differ_from_chromium_only_where_captured()
-> Result<(), Box<dyn std::error::Error>> {
    let opera = v135_tls();
    opera.validate()?;
    let mut expected = chromium::v154_tls();
    assert!(expected.requested_trust_anchor_ids.is_some());
    assert!(expected.grease_signature_algorithms);
    expected.requested_trust_anchor_ids = None;
    expected.grease_signature_algorithms = false;
    expected.ech_from_https_records = false;
    assert_eq!(opera, expected);

    let opera = v135_http3_tls();
    opera.validate()?;
    let mut expected = chromium::v154_http3_tls();
    assert!(!expected.grease_signature_algorithms);
    expected.requested_trust_anchor_ids = None;
    assert_eq!(opera, expected);
    Ok(())
}

#[test]
fn opera_135_http2_session_capture_matches_the_chromium_recipe()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = SessionCapture::parse(SESSION_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Opera");
    assert_eq!(capture.value("client_version")?, "135.0.5973.92");
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
        ..settings
    };
    for run in observed {
        assert_eq!(run, navigation);
    }
    Ok(())
}
