use super::{
    v153_android_client_hints, v153_android_client_hints_for_model,
    v153_android_fetch_no_store_template, v153_android_navigation_template, v153_http2, v153_http3,
    v153_http3_request, v153_http3_tls, v153_quic, v153_tls,
};
use crate::client_hints::navigation_capture::{NavigationCapture, profile_hints};
use crate::http2::{
    Http2HpackSettings, Http2Settings, Http2StreamSettings, session_capture::SessionCapture,
};
use crate::{RequestField, chromium, edge};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/edge-android/153.0.4234.49/android-17-pixel7-emulator/navigation.txt"
));
const SESSION_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/websocket/edge-android/153.0.4234.49/android-17-pixel7-emulator/accept.txt"
));

#[test]
fn edge_android_153_client_hints_match_navigation_capture() -> TestResult {
    let settings = v153_android_client_hints();
    settings.validate()?;
    let capture = NavigationCapture::parse(CLIENT_HINT_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Microsoft Edge");
    assert_eq!(capture.value("client_version")?, "153.0.4234.49");
    assert_eq!(
        capture.value("operating_system")?,
        "Android 17 (API 37) arm64 emulator reporting Pixel 7 CP3A.260905.009"
    );
    assert_eq!(capture.value("launch_mode")?, "android-typed");
    assert_eq!(capture.value("repeat_count")?, "3");
    capture.assert_runs_agree()?;
    assert_eq!(profile_hints(&settings), capture.hints()?);
    Ok(())
}

/// Edge for Android sends the Chromium hint names in the Chromium order and
/// delivery, and the Edge 153 brand list it was captured with.
#[test]
fn edge_android_153_client_hints_share_desktop_edge_names_and_carry_the_edge_153_brands() {
    let names = |settings: &crate::ClientHintSettings| {
        settings
            .hints()
            .iter()
            .map(|hint| (hint.name().to_owned(), hint.delivery()))
            .collect::<Vec<_>>()
    };
    let android = v153_android_client_hints();
    let desktop = edge::v154_windows_client_hints();
    assert_eq!(names(&android), names(&desktop));
    let value = |settings: &crate::ClientHintSettings, name: &str| {
        settings
            .hints()
            .iter()
            .find(|hint| hint.name() == name)
            .map(|hint| hint.value().to_vec())
    };
    assert_eq!(
        value(&android, "sec-ch-ua").as_deref(),
        Some(&br#""Microsoft Edge";v="153", "Not_A Brand";v="8", "Chromium";v="153""#[..])
    );
    let other = v153_android_client_hints_for_model("Pixel 9");
    assert!(other.validate().is_ok());
    assert_eq!(
        value(&other, "sec-ch-ua-model").as_deref(),
        Some(&br#""Pixel 9""#[..])
    );
}

/// Apart from the ECH lookup that no Android capture covers, the TLS recipes
/// are desktop Edge's TLS recipes, which Edge 153 and 154 send alike, and the
/// other layers are the Chromium recipes.
#[test]
fn edge_android_153_reuses_the_desktop_edge_and_chromium_recipes() -> TestResult {
    let mut tls = edge::v154_tls();
    tls.ech_from_https_records = false;
    assert_eq!(v153_tls(), tls);
    let mut http3_tls = edge::v154_http3_tls();
    http3_tls.ech_from_https_records = false;
    assert_eq!(v153_http3_tls(), http3_tls);
    v153_tls().validate()?;
    v153_http3_tls().validate()?;
    assert_eq!(v153_http2(), chromium::v154_http2());
    assert_eq!(v153_quic(), chromium::v154_quic());
    assert_eq!(v153_http3(), chromium::v154_http3());
    assert_eq!(v153_http3_request(), chromium::v154_http3_request());
    Ok(())
}

/// The Android templates are the desktop Edge templates with the literal
/// Edge for Android `User-Agent` in place of the caller slot.
#[test]
fn edge_android_153_templates_change_only_the_user_agent() {
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
            edge::v154_windows_navigation_template(),
        ),
        (
            v153_android_fetch_no_store_template(),
            edge::v154_windows_fetch_no_store_template(),
        ),
    ] {
        assert_eq!(android.validate(), Ok(()));
        assert_eq!(with_caller_agent(android), desktop);
    }
}

#[test]
fn edge_android_153_http2_session_capture_matches_the_chromium_recipe() -> TestResult {
    let capture = SessionCapture::parse(SESSION_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Microsoft Edge");
    assert_eq!(capture.value("client_version")?, "153.0.4234.49");
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
        // A capture shows the first stream ID but neither the assumed limit
        // nor the cap, and one navigation shows no preface PING.
        streams: Http2StreamSettings {
            assumed_max_concurrent_streams: None,
            max_concurrent_streams_cap: None,
            ..settings.streams
        },
        preface_ping_after: None,
        ..settings
    };
    for run in observed {
        assert_eq!(run, navigation);
    }
    Ok(())
}
