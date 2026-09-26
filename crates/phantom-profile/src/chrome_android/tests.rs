use super::{
    v154_android_client_hints, v154_android_client_hints_for_model,
    v154_android_fetch_no_store_template, v154_android_navigation_template, v154_http2,
    v154_http3_tls, v154_tls, v154_websocket,
};
use crate::chromium;
use crate::client_hints::navigation_capture::{NavigationCapture, profile_hints};
use crate::http2::{Http2HpackSettings, Http2Settings, session_capture::SessionCapture};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/chrome-android/154.0.8037.57/android-17-pixel7-emulator/navigation.txt"
));
const SESSION_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/websocket/chrome-android/154.0.8037.57/android-17-pixel7-emulator/accept.txt"
));
const ANDROID_EMULATOR: &str =
    "Android 17 (API 37) x86_64 emulator reporting Pixel 7 CP3A.260905.009";

#[test]
fn chrome_android_154_client_hints_match_navigation_capture() -> TestResult {
    let settings = v154_android_client_hints();
    settings.validate()?;
    let capture = NavigationCapture::parse(CLIENT_HINT_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Google Chrome");
    assert_eq!(capture.value("client_version")?, "154.0.8037.57");
    assert_eq!(capture.value("operating_system")?, ANDROID_EMULATOR);
    assert_eq!(capture.value("launch_mode")?, "android-typed");
    assert_eq!(capture.value("repeat_count")?, "3");
    capture.assert_runs_agree()?;
    assert_eq!(profile_hints(&settings), capture.hints()?);
    Ok(())
}

#[test]
fn chrome_android_154_client_hints_share_the_chromium_names_order_and_delivery() {
    let names = |settings: crate::ClientHintSettings| {
        settings
            .hints()
            .iter()
            .map(|hint| (hint.name().to_owned(), hint.delivery()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(v154_android_client_hints()),
        names(chromium::v154_windows_client_hints())
    );
}

#[test]
fn chrome_android_154_reuses_the_desktop_http2_and_websocket_recipes() {
    assert_eq!(v154_http2(), chromium::v154_http2());
    assert_eq!(v154_websocket(), chromium::v154_websocket());
}

#[test]
fn chrome_android_154_templates_change_only_the_user_agent() {
    for (android, windows) in [
        (
            v154_android_navigation_template(),
            chromium::v154_windows_navigation_template(),
        ),
        (
            v154_android_fetch_no_store_template(),
            chromium::v154_windows_fetch_no_store_template(),
        ),
    ] {
        assert_eq!(android.validate(), Ok(()));
        let android_user_agent = user_agents(&android);
        assert_eq!(
            android_user_agent.len(),
            android.http3_fields.map_or(2, |_| 3)
        );
        assert!(
            android_user_agent
                .iter()
                .all(|value| value.contains("(Linux; Android 10; K)")
                    && value.ends_with("Chrome/154.0.0.0 Mobile Safari/537.36"))
        );
        assert_ne!(android_user_agent, user_agents(&windows));
    }
}

fn user_agents(template: &crate::RequestTemplate) -> Vec<String> {
    template
        .http1_fields
        .iter()
        .chain(&template.http2_fields)
        .chain(template.http3_fields.iter().flatten())
        .filter_map(|field| match field {
            crate::RequestField::Literal { name, value }
                if name.eq_ignore_ascii_case("user-agent") =>
            {
                Some(value.to_string())
            }
            _ => None,
        })
        .collect()
}

#[test]
fn chrome_android_154_http2_session_capture_matches_the_chromium_recipe() -> TestResult {
    let capture = SessionCapture::parse(SESSION_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Google Chrome");
    assert_eq!(capture.value("client_version")?, "154.0.8037.57");
    assert_eq!(capture.value("scenario")?, "accept");
    let observed = capture.navigation_settings()?;
    assert_eq!(observed.len(), 3);
    let settings = v154_http2();
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

/// Apart from the ECH lookup that no Android capture covers, the TLS recipes
/// are the desktop Chromium recipes, sorted trust-anchor IDs included.
#[test]
fn chrome_android_154_tls_recipes_differ_from_desktop_only_in_ech_lookup() -> TestResult {
    for (android, desktop) in [
        (v154_tls(), chromium::v154_tls()),
        (v154_http3_tls(), chromium::v154_http3_tls()),
    ] {
        android.validate()?;
        assert!(!android.ech_from_https_records);
        let mut expected = desktop;
        expected.ech_from_https_records = false;
        assert_eq!(android, expected);
    }
    Ok(())
}

/// The default model is the captured Pixel 7; an override changes only
/// `sec-ch-ua-model`, encoded as a structured-field string.
#[test]
fn chrome_android_154_client_hints_accept_another_model() -> TestResult {
    let model = |settings: &crate::ClientHintSettings| {
        settings
            .hints()
            .iter()
            .find(|hint| hint.name() == "sec-ch-ua-model")
            .map(|hint| hint.value().to_vec())
    };
    let captured = v154_android_client_hints();
    assert_eq!(model(&captured).as_deref(), Some(&br#""Pixel 7""#[..]));
    let other = v154_android_client_hints_for_model("Pixel 9");
    other.validate()?;
    assert_eq!(model(&other).as_deref(), Some(&br#""Pixel 9""#[..]));
    let without_model = |settings: &crate::ClientHintSettings| {
        settings
            .hints()
            .iter()
            .filter(|hint| hint.name() != "sec-ch-ua-model")
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(without_model(&captured), without_model(&other));
    assert_eq!(super::model_value(r#"a"b\c"#), r#""a\"b\\c""#);
    Ok(())
}
