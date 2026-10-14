//! Original WebSocket values and unchanged composition at ff638d49.

use phantom_profile::{UrlTrust, WebSocketField, browser};

mod originals;
use originals::{chrome_original, firefox_original};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn browser_websocket_factories_preserve_every_ordered_field_and_policy() -> TestResult {
    for (actual, original) in [
        (browser::chrome::v154_websocket(), chrome_original()),
        (browser::firefox::v157_websocket(), firefox_original()),
    ] {
        actual.validate()?;
        original.validate()?;
        assert_eq!(actual, original);
    }
    assert_eq!(chrome_original().http1_fields.len(), 13);
    assert_eq!(chrome_original().http2_fields.len(), 9);
    assert_eq!(firefox_original().http1_fields.len(), 17);
    assert_eq!(firefox_original().http2_fields.len(), 14);
    Ok(())
}

#[test]
fn seven_composed_profiles_keep_websocket_and_three_android_profiles_keep_absence() -> TestResult {
    for profile in [
        browser::chrome::v154_windows(),
        browser::chrome::v154_android(),
        browser::edge::v154_windows(),
        browser::brave::v154_windows(),
        browser::brave::v153_android(),
        browser::opera::v136_windows(),
    ] {
        assert_eq!(
            profile.websocket().ok_or("lost WebSocket settings")?,
            &chrome_original()
        );
    }
    assert_eq!(
        browser::firefox::v157_windows()
            .websocket()
            .ok_or("lost Firefox WebSocket")?,
        &firefox_original()
    );
    assert_eq!(browser::chrome::v154_android_websocket(), chrome_original());
    assert_eq!(browser::brave::v153_android_websocket(), chrome_original());
    for profile in [
        browser::edge::v153_android(),
        browser::opera::v102_android(),
        browser::firefox::v156_android(),
    ] {
        assert!(profile.websocket().is_none());
    }
    Ok(())
}

#[test]
fn generated_websocket_fields_keep_both_trust_defaults_and_absence() {
    for (actual, original) in [
        (browser::chrome::v154_websocket(), chrome_original()),
        (browser::firefox::v157_websocket(), firefox_original()),
    ] {
        for (fields, original_fields) in [
            (&actual.http1_fields, &original.http1_fields),
            (&actual.http2_fields, &original.http2_fields),
        ] {
            for trust in [UrlTrust::PotentiallyTrustworthy, UrlTrust::Untrustworthy] {
                assert_eq!(
                    fields
                        .iter()
                        .map(|field| field.default_value(trust))
                        .collect::<Vec<_>>(),
                    original_fields
                        .iter()
                        .map(|field| field.default_value(trust))
                        .collect::<Vec<_>>()
                );
            }
        }
    }
}

#[test]
fn customized_websocket_values_remain_owned_and_keep_native_input_ranges() -> TestResult {
    for mut custom in [
        browser::chrome::v154_websocket(),
        browser::firefox::v157_websocket(),
    ] {
        custom
            .http1_fields
            .push(WebSocketField::literal("x".repeat(257), "v".repeat(4097)));
        custom.http2_fields.push(WebSocketField::ByTrust {
            name: "x-default".into(),
            trustworthy: Some("".into()),
            untrustworthy: None,
        });
        custom
            .connection
            .http1_alpn_protocols
            .push(Box::from(*b"http/1.1"));
        custom.validate()?;
        let field = custom.http2_fields.last().ok_or("missing custom field")?;
        assert_eq!(
            field.default_value(UrlTrust::PotentiallyTrustworthy),
            Some("")
        );
        assert_eq!(field.default_value(UrlTrust::Untrustworthy), None);
        custom.http1_fields.clear();
        custom.http2_fields.clear();
        custom.connection.http1_alpn_protocols[0][0] = 0;
        custom.permessage_deflate_offer.clear();
    }
    assert_eq!(browser::chrome::v154_websocket(), chrome_original());
    assert_eq!(browser::firefox::v157_websocket(), firefox_original());
    Ok(())
}
