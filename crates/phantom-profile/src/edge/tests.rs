use super::{v153_http3_tls, v153_tls, v153_windows_client_hints};
use crate::chromium;
use crate::client_hints::navigation_capture::{NavigationCapture, profile_hints};
use crate::http2::session_capture::SessionCapture;

const CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/edge/153.0.4234.48/windows-11-26200/navigation.txt"
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
fn edge_153_client_hints_share_chrome_153_names_order_and_delivery() {
    let names = |settings: crate::ClientHintSettings| {
        settings
            .hints()
            .iter()
            .map(|hint| (hint.name().to_owned(), hint.delivery()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(v153_windows_client_hints()),
        names(chromium::v153_windows_client_hints())
    );
}

#[test]
fn edge_153_tls_recipes_remove_only_chrome_153_trust_anchor_ids()
-> Result<(), Box<dyn std::error::Error>> {
    for (edge, chrome) in [
        (v153_tls(), chromium::v153_tls()),
        (v153_http3_tls(), chromium::v153_http3_tls()),
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
fn edge_153_http2_session_capture_matches_chrome_153_recipe()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = SessionCapture::parse(SESSION_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Microsoft Edge");
    assert_eq!(capture.value("client_version")?, "153.0.4234.48");
    assert_eq!(capture.value("scenario")?, "accept");
    let observed = capture.navigation_settings()?;
    assert_eq!(observed.len(), 3);
    for run in observed {
        assert_eq!(run, chromium::v153_http2());
    }
    Ok(())
}
