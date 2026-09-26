use super::{
    v153_android_client_hints, v153_android_fetch_no_store_template,
    v153_android_navigation_template, v153_http2, v153_http3, v153_http3_request, v153_http3_tls,
    v153_quic, v153_tls, v153_websocket,
};
use crate::client_hints::navigation_capture::{NavigationCapture, profile_hints};
use crate::http2::{Http2HpackSettings, Http2Settings, session_capture::SessionCapture};
use crate::{RequestField, brave, chromium};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/brave-android/153.1.95.104/android-35-emulator/navigation.txt"
));
const SESSION_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/websocket/brave-android/153.1.95.104/android-35-emulator/accept.txt"
));

#[test]
fn brave_android_153_client_hints_match_navigation_capture() -> TestResult {
    let settings = v153_android_client_hints();
    settings.validate()?;
    let capture = NavigationCapture::parse(CLIENT_HINT_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Brave");
    assert_eq!(capture.value("client_version")?, "153.1.95.104");
    assert_eq!(capture.value("launch_mode")?, "android-typed");
    assert_eq!(capture.value("repeat_count")?, "3");
    capture.assert_runs_agree()?;
    assert_eq!(profile_hints(&settings), capture.hints()?);
    Ok(())
}

#[test]
fn brave_android_153_client_hints_share_the_desktop_brave_names_and_delivery() {
    let names = |settings: crate::ClientHintSettings| {
        settings
            .hints()
            .iter()
            .map(|hint| (hint.name().to_owned(), hint.delivery()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(v153_android_client_hints()),
        names(brave::v154_windows_client_hints())
    );
}

#[test]
fn brave_android_153_reuses_the_desktop_recipes() -> TestResult {
    let tls = v153_tls();
    tls.validate()?;
    let mut desktop = brave::v154_tls();
    desktop.ech_from_https_records = false;
    assert_eq!(tls, desktop);
    assert_eq!(v153_http3_tls(), brave::v154_http3_tls());
    assert_eq!(v153_http2(), chromium::v154_http2());
    assert_eq!(v153_quic(), chromium::v154_quic());
    assert_eq!(v153_http3(), chromium::v154_http3());
    assert_eq!(v153_http3_request(), chromium::v154_http3_request());
    assert_eq!(v153_websocket(), chromium::v154_websocket());
    Ok(())
}

/// The Android templates are the desktop Brave templates with the literal
/// Android `User-Agent` in place of the caller slot.
#[test]
fn brave_android_153_templates_change_only_the_user_agent() {
    let with_caller_agent = |template: crate::RequestTemplate| {
        let swap = |fields: Vec<RequestField>| {
            fields
                .into_iter()
                .map(|field| match field.name() {
                    Some(name) if name.eq_ignore_ascii_case("user-agent") => {
                        RequestField::required_caller(name)
                    }
                    _ => field,
                })
                .collect()
        };
        crate::RequestTemplate {
            http1_fields: swap(template.http1_fields),
            http2_fields: swap(template.http2_fields),
            http3_fields: template.http3_fields.map(swap),
            ..template
        }
    };
    for (android, desktop) in [
        (
            v153_android_navigation_template(),
            brave::v154_windows_navigation_template(),
        ),
        (
            v153_android_fetch_no_store_template(),
            brave::v154_windows_fetch_no_store_template(),
        ),
    ] {
        assert_eq!(android.validate(), Ok(()));
        assert_eq!(with_caller_agent(android), desktop);
    }
}

#[test]
fn brave_android_153_http2_session_capture_matches_the_chromium_recipe() -> TestResult {
    let capture = SessionCapture::parse(SESSION_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Brave");
    assert_eq!(capture.value("client_version")?, "153.1.95.104");
    let observed = capture.navigation_settings()?;
    assert_eq!(observed.len(), 3);
    let settings = v153_http2();
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
