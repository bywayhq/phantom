use super::{v135_http3_tls, v135_macos_client_hints, v135_tls, v135_windows_client_hints};
use crate::chromium;
use crate::client_hints::navigation_capture::{NavigationCapture, profile_hints};
use crate::http2::{Http2HpackSettings, Http2Settings, session_capture::SessionCapture};

const CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/opera/135.0.5973.92/windows-11-26200/navigation.txt"
));
const MACOS_CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/opera/135.0.5973.66/macos-15.5-arm64/navigation.txt"
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
fn opera_135_tls_recipes_drop_trust_anchor_ids_and_tcp_signature_algorithm_grease()
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
    expected.ech_from_https_records = false;
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

#[test]
fn opera_135_macos_client_hints_match_navigation_capture() -> Result<(), Box<dyn std::error::Error>>
{
    let settings = v135_macos_client_hints();
    settings.validate()?;
    let capture = NavigationCapture::parse(MACOS_CLIENT_HINT_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Opera");
    assert_eq!(capture.value("client_version")?, "135.0.5973.66");
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

/// Besides the build, macOS changes only the platform hints.
#[test]
fn opera_135_macos_client_hints_differ_from_windows_only_in_platform_data() {
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
    let windows = differing(v135_windows_client_hints());
    let macos = differing(v135_macos_client_hints());
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
            ("sec-ch-ua-full-version", r#""135.0.5973.66""#),
            ("sec-ch-ua-arch", r#""arm""#),
            ("sec-ch-ua-platform", r#""macOS""#),
            ("sec-ch-ua-platform-version", r#""15.5.0""#),
            (
                "sec-ch-ua-full-version-list",
                r#""Not=A?Brand";v="99.0.0.0", "Opera";v="135.0.5973.66", "Chromium";v="151.0.7922.176""#,
            ),
        ]
    );
}
