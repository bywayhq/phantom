use super::{v102_android_client_hints, v102_android_client_hints_for_model, v102_android_tcp_tls};
use crate::client_hints::navigation_capture::{NavigationCapture, profile_hints};
use crate::{browser::chrome, browser::opera};

const CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/opera-android/102.1.5206.90382/android-17-pixel7-emulator/navigation.txt"
));

#[test]
fn opera_android_102_client_hints_match_navigation_capture()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = v102_android_client_hints();
    settings.validate()?;
    let capture = NavigationCapture::parse(CLIENT_HINT_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Opera");
    assert_eq!(capture.value("client_version")?, "102.1.5206.90382");
    assert_eq!(capture.value("launch_mode")?, "android-typed");
    assert_eq!(capture.value("repeat_count")?, "3");
    capture.assert_runs_agree()?;
    assert_eq!(profile_hints(&settings), capture.hints()?);
    Ok(())
}

#[test]
fn opera_android_102_client_hints_share_the_chromium_names_order_and_delivery() {
    let names = |settings: crate::ClientHintSettings| {
        settings
            .hints()
            .iter()
            .map(|hint| (hint.name().to_owned(), hint.delivery()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(v102_android_client_hints_for_model("Pixel 9")),
        names(chrome::v154_windows_client_hints())
    );
}

/// Opera for Android sends Chrome's ClientHello without trust-anchor IDs,
/// where desktop Opera 136 sends 32 of them.
#[test]
fn opera_android_102_tls_is_chrome_without_trust_anchor_ids()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = v102_android_tcp_tls();
    settings.validate()?;
    let mut chrome = chrome::v154_tcp_tls();
    chrome.requested_trust_anchor_ids = None;
    chrome.ech = crate::EchSettings::Grease(crate::EchGreaseSettings::backend_default());
    assert_eq!(settings, chrome);
    let mut desktop = opera::v136_tcp_tls();
    desktop.requested_trust_anchor_ids = None;
    desktop.ech = crate::EchSettings::Grease(crate::EchGreaseSettings::backend_default());
    assert_eq!(settings, desktop);
    Ok(())
}

/// Opera for Android sends Chrome's HTTP/1.1 navigation field order, before
/// and after `Accept-CH`. With no HTTP/2 or HTTP/3 capture it has no request
/// template; this records that the one captured protocol agrees.
#[test]
fn opera_android_102_navigation_field_order_equals_chrome_for_android()
-> Result<(), Box<dyn std::error::Error>> {
    let chrome = NavigationCapture::parse(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/client-hints/chrome-android/154.0.8037.57/android-17-pixel7-emulator/navigation.txt"
    )))?;
    let opera = NavigationCapture::parse(CLIENT_HINT_FIXTURE)?;
    for key in ["run_0_first_field_order", "run_0_second_field_order"] {
        assert_eq!(opera.value(key)?, chrome.value(key)?, "{key}");
    }
    Ok(())
}
