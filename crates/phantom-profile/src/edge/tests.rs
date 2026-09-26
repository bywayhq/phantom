use super::{v153_http3_tls, v153_macos_client_hints, v153_tls, v153_windows_client_hints};
use crate::chromium;
use crate::client_hints::navigation_capture::{NavigationCapture, profile_hints};
use crate::http2::{Http2HpackSettings, Http2Settings, session_capture::SessionCapture};

const CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/edge/153.0.4234.48/windows-11-26200/navigation.txt"
));
const MACOS_CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/edge/153.0.4234.48/macos-15.5-arm64/navigation.txt"
));
const SESSION_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/websocket/edge/153.0.4234.48/windows-11-26200/accept.txt"
));

#[test]
fn edge_153_windows_client_hints_match_navigation_capture() -> Result<(), Box<dyn std::error::Error>>
{
    let settings = v153_windows_client_hints();
    settings.validate()?;
    let capture = NavigationCapture::parse(CLIENT_HINT_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Microsoft Edge");
    assert_eq!(capture.value("client_version")?, "153.0.4234.48");
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
fn edge_153_client_hints_share_the_chromium_names_order_and_delivery() {
    let names = |settings: crate::ClientHintSettings| {
        settings
            .hints()
            .iter()
            .map(|hint| (hint.name().to_owned(), hint.delivery()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(v153_windows_client_hints()),
        names(chromium::v154_windows_client_hints())
    );
}

#[test]
fn edge_153_recipes_keep_the_backend_ech_grease_aead_policy() {
    // Edge advertises AES-128-GCM like Chrome; the backend default produces
    // that choice because `aes_hardware` is set.
    for settings in [v153_tls(), v153_http3_tls()] {
        assert!(settings.ech_grease);
        assert!(settings.ech_grease_aeads.is_empty());
        assert!(settings.aes_hardware);
    }
}

/// On the wire the Edge and Chrome ClientHellos differ only in the
/// trust-anchor IDs, with or without an HTTPS record's `ech`.
#[test]
fn edge_153_tls_recipes_remove_only_the_chromium_trust_anchor_ids()
-> Result<(), Box<dyn std::error::Error>> {
    for (edge, chrome) in [
        (v153_tls(), chromium::v154_tls()),
        (v153_http3_tls(), chromium::v154_http3_tls()),
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
fn edge_153_http2_session_capture_matches_the_chromium_recipe()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = SessionCapture::parse(SESSION_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Microsoft Edge");
    assert_eq!(capture.value("client_version")?, "153.0.4234.48");
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
        ..settings
    };
    for run in observed {
        assert_eq!(run, navigation);
    }
    Ok(())
}

#[test]
fn edge_153_macos_client_hints_match_navigation_capture() -> Result<(), Box<dyn std::error::Error>>
{
    let settings = v153_macos_client_hints();
    settings.validate()?;
    let capture = NavigationCapture::parse(MACOS_CLIENT_HINT_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Microsoft Edge");
    assert_eq!(capture.value("client_version")?, "153.0.4234.48");
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

/// Besides the build, macOS changes only the platform hints.
#[test]
fn edge_153_macos_client_hints_differ_from_windows_only_in_platform_data() {
    let differing = |settings: crate::ClientHintSettings| {
        settings
            .hints()
            .iter()
            .map(|hint| {
                (
                    hint.name().to_owned(),
                    String::from_utf8_lossy(hint.value()).into_owned(),
                )
            })
            .collect::<Vec<_>>()
    };
    let windows = differing(v153_windows_client_hints());
    let macos = differing(v153_macos_client_hints());
    let changed: Vec<_> = windows
        .iter()
        .zip(&macos)
        .filter(|(windows, macos)| windows != macos)
        .map(|(_, (name, value))| (name.as_str(), value.as_str()))
        .collect();
    assert_eq!(windows.len(), macos.len());
    assert_eq!(
        changed,
        [
            ("sec-ch-ua-arch", r#""arm""#),
            ("sec-ch-ua-platform", r#""macOS""#),
            ("sec-ch-ua-platform-version", r#""15.5.0""#),
        ]
    );
}
