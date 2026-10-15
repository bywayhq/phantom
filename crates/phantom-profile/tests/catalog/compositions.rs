//! Full composition controls independent of the catalog declarations.

use std::convert::Infallible;

use phantom_profile::{
    ClientProfile,
    browser::{chrome, firefox},
    catalog::{LayerSupport, profile},
};

mod originals;

type TestResult = Result<(), Box<dyn std::error::Error>>;

// Keep the pre-migration oracle unchanged. Only these two compositions gain
// TCP; tcp_components independently checks every field of both new policies.
fn expected_profiles() -> [(&'static str, ClientProfile); 10] {
    originals::profiles().map(|(id, original)| {
        let expected = match id {
            "chrome/154.0.8037.57/android-17-pixel7-emulator/r1" => {
                original.with_tcp(chrome::v154_android_tcp())
            }
            "firefox/156.0.1/android-35-emulator/r1" => {
                original.with_tcp(firefox::v156_android_tcp())
            }
            _ => original,
        };
        (id, expected)
    })
}

#[test]
fn compositions_preserve_original_layers_and_add_only_declared_platform_tcp() -> TestResult {
    for (id, expected) in expected_profiles() {
        let definition = profile(id)?;
        let required: Vec<_> = definition
            .layers()
            .iter()
            .filter(|layer| layer.support() == LayerSupport::Configured)
            .map(|layer| layer.layer())
            .collect();
        let actual = definition.instantiate(&required)?;
        assert_eq!(actual, expected, "{id}");
        assert!(actual.request_template().is_none(), "{id}");
    }
    Ok(())
}

#[test]
fn composition_preserves_per_client_draw_counts_values_and_unsampled_definitions() -> TestResult {
    for draw in [0, 1, u64::MAX] {
        for (id, mut expected) in expected_profiles() {
            let definition = profile(id)?;
            let original = expected.clone();
            let mut actual = definition.instantiate(&[])?;
            let mut actual_draws = 0;
            let mut expected_draws = 0;
            actual.draw_per_client(|| {
                actual_draws += 1;
                Ok::<_, Infallible>(draw)
            })?;
            expected.draw_per_client(|| {
                expected_draws += 1;
                Ok::<_, Infallible>(draw)
            })?;
            assert_eq!(actual_draws, expected_draws, "{id}");
            assert_eq!(actual, expected, "{id}");
            assert_eq!(definition.instantiate(&[])?, original, "{id}");
        }
    }
    Ok(())
}

#[test]
fn customizing_a_composed_vector_leaves_other_instances_and_definition_unchanged() -> TestResult {
    for (id, expected) in expected_profiles() {
        let definition = profile(id)?;
        let actual = definition.instantiate(&[])?;
        if let Some(settings) = actual.http2() {
            let mut modified = settings.clone();
            assert!(!modified.initial_settings.is_empty(), "{id}");
            modified.initial_settings.clear();
            let customized = actual.with_http2(modified);
            assert_ne!(customized, expected, "{id}");
            assert_eq!(definition.instantiate(&[])?, expected, "{id}");
        }
    }
    Ok(())
}
