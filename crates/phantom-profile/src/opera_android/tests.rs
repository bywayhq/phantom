use super::{v102_android_client_hints, v102_tls};
use crate::client_hints::navigation_capture::{NavigationCapture, profile_hints};
use crate::{chromium, opera};

const CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/opera-android/102.1.5206.90382/android-35-emulator/navigation.txt"
));

#[test]
fn opera_android_102_client_hints_match_navigation_capture()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = v102_android_client_hints("sdk_gphone64_x86_64");
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
        names(v102_android_client_hints("sdk_gphone64_x86_64")),
        names(chromium::v154_windows_client_hints())
    );
}

/// Opera for Android keeps signature-algorithm GREASE, which desktop Opera
/// drops, so its ClientHello is Chrome's without trust-anchor IDs.
#[test]
fn opera_android_102_tls_is_desktop_opera_with_signature_algorithm_grease()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = v102_tls();
    settings.validate()?;
    let mut expected = opera::v135_tls();
    expected.grease_signature_algorithms = true;
    assert_eq!(settings, expected);
    let mut chrome = chromium::v154_tls();
    chrome.requested_trust_anchor_ids = None;
    chrome.ech_from_https_records = false;
    assert_eq!(settings, chrome);
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
        "/../../fixtures/client-hints/chrome-android/153.0.8010.52/android-35-emulator/navigation.txt"
    )))?;
    let opera = NavigationCapture::parse(CLIENT_HINT_FIXTURE)?;
    for key in ["run_0_first_field_order", "run_0_second_field_order"] {
        assert_eq!(opera.value(key)?, chrome.value(key)?, "{key}");
    }
    Ok(())
}
