//! Independent client-hint factory and model controls.

use phantom_profile::{
    ClientHintSettings, InvalidClientHintSettings, ValidationErrorKind, browser,
};

mod originals;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Factory = fn() -> ClientHintSettings;
type ModelFactory = fn(&str) -> Result<ClientHintSettings, InvalidClientHintSettings>;
type OriginalModelFactory = fn(&str) -> ClientHintSettings;

fn factories() -> [(Factory, Factory); 11] {
    [
        (
            browser::chrome::v154_windows_client_hints,
            originals::chrome_windows_original,
        ),
        (
            browser::chrome::v154_macos_client_hints,
            originals::chrome_macos_original,
        ),
        (
            browser::edge::v154_windows_client_hints,
            originals::edge_windows_original,
        ),
        (
            browser::edge::v154_macos_client_hints,
            originals::edge_macos_original,
        ),
        (
            browser::opera::v136_windows_client_hints,
            originals::opera_windows_original,
        ),
        (
            browser::opera::v136_macos_client_hints,
            originals::opera_macos_original,
        ),
        (
            browser::brave::v154_windows_client_hints,
            originals::brave_windows_original,
        ),
        (
            browser::chrome::v154_android_client_hints,
            originals::chrome_android_original,
        ),
        (
            browser::edge::v153_android_client_hints,
            originals::edge_android_original,
        ),
        (
            browser::opera::v102_android_client_hints,
            originals::opera_android_original,
        ),
        (
            browser::brave::v153_android_client_hints,
            originals::brave_android_original,
        ),
    ]
}

fn model_factories() -> [(ModelFactory, OriginalModelFactory, Factory); 3] {
    [
        (
            browser::chrome::v154_android_client_hints_for_model,
            originals::chrome_android_for_model_original,
            browser::chrome::v154_android_client_hints,
        ),
        (
            browser::edge::v153_android_client_hints_for_model,
            originals::edge_android_for_model_original,
            browser::edge::v153_android_client_hints,
        ),
        (
            browser::opera::v102_android_client_hints_for_model,
            originals::opera_android_for_model_original,
            browser::opera::v102_android_client_hints,
        ),
    ]
}

#[test]
fn all_client_hint_factories_preserve_original_values_order_and_delivery() -> TestResult {
    for (factory, original) in factories() {
        let actual = factory();
        actual.validate()?;
        assert_eq!(actual, original());
    }
    Ok(())
}

#[test]
fn client_hint_factories_return_independently_owned_name_and_value_bytes() {
    for (factory, _) in factories() {
        let first = factory();
        let second = factory();
        assert_eq!(first, second);
        assert_ne!(first.hints().as_ptr(), second.hints().as_ptr());
        for (left, right) in first.hints().iter().zip(second.hints()) {
            assert_ne!(left.name().as_ptr(), right.name().as_ptr());
            if !left.value().is_empty() {
                assert_ne!(left.value().as_ptr(), right.value().as_ptr());
            }
        }
    }
}

#[test]
fn model_adapters_preserve_original_escaping_and_accept_long_printable_models() -> TestResult {
    let models = [
        String::new(),
        " ~".to_owned(),
        r#"a"b\c"#.to_owned(),
        "Pixel 7".to_owned(),
        (b' '..=b'~').map(char::from).collect::<String>(),
        "x\"\\".repeat(4097),
    ];
    for model in &models {
        for (factory, original, captured) in model_factories() {
            let actual = factory(model)?;
            actual.validate()?;
            assert_eq!(actual, original(model));
            let captured = captured();
            assert_eq!(actual.hints().len(), captured.hints().len());
            for (changed, baseline) in actual.hints().iter().zip(captured.hints()) {
                assert_eq!(changed.name(), baseline.name());
                assert_eq!(changed.delivery(), baseline.delivery());
                if changed.name() != "sec-ch-ua-model" {
                    assert_eq!(changed, baseline);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn invalid_models_keep_recoverable_errors_without_disclosing_input() -> TestResult {
    let mut models = (0..=31_u8)
        .chain([127])
        .map(|byte| format!("sensitive{}model", char::from(byte)))
        .collect::<Vec<_>>();
    models.extend(
        [
            "sensitive\u{80}model",
            "sensitiveémodel",
            "sensitive🙂model",
        ]
        .map(str::to_owned),
    );
    for model in models {
        for (factory, _, _) in model_factories() {
            let error = factory(&model).err().ok_or("invalid model was accepted")?;
            assert_eq!(error.kind(), ValidationErrorKind::InvalidValue);
            assert_eq!(error.field(), "model");
            assert_eq!(
                error.reason(),
                "device model must contain only printable ASCII"
            );
            assert!(!error.to_string().contains(&model));
            assert!(!format!("{error:?}").contains(&model));
        }
    }
    Ok(())
}

#[test]
fn model_values_outlive_caller_input_and_stay_redacted() -> TestResult {
    for (factory, original, _) in model_factories() {
        let expected = original("sensitive model");
        let owned = {
            let model = "sensitive model".to_owned();
            factory(&model)?
        };
        assert_eq!(owned, expected);
        assert!(!format!("{owned:?}").contains("sensitive model"));
    }
    Ok(())
}

#[test]
fn composed_profiles_keep_their_exact_client_hints() -> TestResult {
    for (profile, original) in [
        (
            browser::chrome::v154_windows(),
            originals::chrome_windows_original(),
        ),
        (
            browser::edge::v154_windows(),
            originals::edge_windows_original(),
        ),
        (
            browser::opera::v136_windows(),
            originals::opera_windows_original(),
        ),
        (
            browser::brave::v154_windows(),
            originals::brave_windows_original(),
        ),
        (
            browser::chrome::v154_android(),
            originals::chrome_android_original(),
        ),
        (
            browser::edge::v153_android(),
            originals::edge_android_original(),
        ),
        (
            browser::opera::v102_android(),
            originals::opera_android_original(),
        ),
        (
            browser::brave::v153_android(),
            originals::brave_android_original(),
        ),
    ] {
        assert_eq!(profile.client_hints(), Some(&original));
        let custom = profile.with_client_hints(
            browser::chrome::v154_android_client_hints_for_model("Pixel 9")?,
        );
        assert_ne!(custom.client_hints(), Some(&original));
    }
    assert!(browser::firefox::v157_windows().client_hints().is_none());
    assert!(browser::firefox::v156_android().client_hints().is_none());
    Ok(())
}
