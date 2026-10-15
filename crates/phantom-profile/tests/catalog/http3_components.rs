//! Stored HTTP/3 values pinned before component generation replaced literals.
//!
//! The baselines below were copied from the browser factories at
//! ae2aba3d42b29ddb881e119a4710c75dc757a66d, independently of declarations.
//! Firefox now intentionally uses mapping-time Alt-Used eligibility; all other
//! values retain that baseline.

use phantom_profile::{
    Http3AltUsed, Http3CookieCrumbs, Http3PseudoHeader, Http3QpackDecoderStream,
    Http3QpackEncoderStream, Http3QpackEncoding, Http3QpackStreamOrder, Http3RequestSettings,
    Http3Setting, Http3SettingOrder, Http3Settings, browser,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn browser_http3_factories_preserve_every_stored_field() -> TestResult {
    let chrome = chromium_settings();
    let chrome_request = chromium_request();
    let firefox = firefox_settings();
    let firefox_request = firefox_request();
    chrome.validate()?;
    chrome_request.validate()?;
    firefox.validate()?;
    firefox_request.validate()?;

    assert_eq!(browser::chrome::v154_http3(), chrome);
    assert_eq!(browser::chrome::v154_http3_request(), chrome_request);
    assert_eq!(browser::firefox::v157_http3(), firefox);
    assert_eq!(browser::firefox::v157_http3_request(), firefox_request);
    for (settings, request) in [
        (
            browser::chrome::v154_android_http3(),
            browser::chrome::v154_android_http3_request(),
        ),
        (
            browser::edge::v153_android_http3(),
            browser::edge::v153_android_http3_request(),
        ),
        (
            browser::brave::v153_android_http3(),
            browser::brave::v153_android_http3_request(),
        ),
    ] {
        assert_eq!(settings, chrome);
        assert_eq!(request, chrome_request);
    }
    Ok(())
}

#[test]
fn composed_recipes_preserve_http3_values_and_draw_policies() -> TestResult {
    for profile in [
        browser::chrome::v154_windows(),
        browser::chrome::v154_android(),
        browser::edge::v154_windows(),
        browser::edge::v153_android(),
        browser::brave::v154_windows(),
        browser::brave::v153_android(),
        browser::opera::v136_windows(),
    ] {
        let http3 = profile.http3().ok_or("composed recipe lost HTTP/3")?;
        assert_eq!(*http3.http3(), chromium_settings());
        assert_eq!(*http3.request(), chromium_request());
    }
    let firefox = browser::firefox::v157_windows();
    let http3 = firefox.http3().ok_or("Firefox recipe lost HTTP/3")?;
    assert_eq!(*http3.http3(), firefox_settings());
    assert_eq!(*http3.request(), firefox_request());

    let mut custom = browser::chrome::v154_http3();
    custom.initial_settings.clear();
    assert_eq!(browser::chrome::v154_http3(), chromium_settings());
    let mut custom_request = browser::firefox::v157_http3_request();
    custom_request.pseudo_header_order.reverse();
    assert_eq!(browser::firefox::v157_http3_request(), firefox_request());
    Ok(())
}

fn chromium_settings() -> Http3Settings {
    Http3Settings {
        initial_settings: vec![
            Http3Setting::QpackMaxTableCapacity(65_536),
            Http3Setting::MaxFieldSectionSize(262_144),
            Http3Setting::QpackBlockedStreams(100),
            Http3Setting::H3Datagram(true),
            Http3Setting::RandomizedGrease,
        ],
        setting_order: Http3SettingOrder::Ascending,
        qpack_encoding: Http3QpackEncoding::Dynamic,
        qpack_decoder_stream: Http3QpackDecoderStream::OnFeedback,
        qpack_encoder_stream: Http3QpackEncoderStream::OnFirstInstruction,
        qpack_stream_order: Http3QpackStreamOrder::DecoderFirst,
        reserved_frame_after_settings: false,
    }
}

fn chromium_request() -> Http3RequestSettings {
    Http3RequestSettings {
        pseudo_header_order: vec![
            Http3PseudoHeader::Method,
            Http3PseudoHeader::Authority,
            Http3PseudoHeader::Scheme,
            Http3PseudoHeader::Path,
        ],
        extended_connect_pseudo_header_order: None,
        cookie_crumbs: Http3CookieCrumbs::Split,
        alt_used: Http3AltUsed::Omit,
    }
}

fn firefox_settings() -> Http3Settings {
    Http3Settings {
        initial_settings: vec![
            Http3Setting::QpackMaxTableCapacity(65_536),
            Http3Setting::QpackBlockedStreams(20),
            Http3Setting::EnableWebTransportDraft02(false),
            Http3Setting::H3DatagramDraft04(true),
            Http3Setting::H3Datagram(true),
            Http3Setting::EnableConnectProtocol(true),
        ],
        setting_order: Http3SettingOrder::Fixed,
        qpack_encoding: Http3QpackEncoding::DynamicUnmatchedNames,
        qpack_decoder_stream: Http3QpackDecoderStream::Eager,
        qpack_encoder_stream: Http3QpackEncoderStream::Eager,
        qpack_stream_order: Http3QpackStreamOrder::EncoderFirst,
        reserved_frame_after_settings: true,
    }
}

fn firefox_request() -> Http3RequestSettings {
    Http3RequestSettings {
        pseudo_header_order: vec![
            Http3PseudoHeader::Method,
            Http3PseudoHeader::Scheme,
            Http3PseudoHeader::Authority,
            Http3PseudoHeader::Path,
        ],
        extended_connect_pseudo_header_order: None,
        cookie_crumbs: Http3CookieCrumbs::Whole,
        alt_used: Http3AltUsed::ValidatedMapping,
    }
}
