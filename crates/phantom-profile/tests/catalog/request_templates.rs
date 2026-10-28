//! Immutable template selection against frozen full values and original factories.

use phantom_profile::{
    RequestField, RequestTemplate, browser,
    catalog::{CatalogError, ProfileIdentity, RequestTemplateKind, profile, profiles},
};

mod originals;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const KINDS: [RequestTemplateKind; 4] = [
    RequestTemplateKind::Navigation,
    RequestTemplateKind::FetchNoStore,
    RequestTemplateKind::Fetch,
    RequestTemplateKind::FetchUpload,
];

fn original_factory(id: &str, kind: RequestTemplateKind) -> Option<RequestTemplate> {
    use RequestTemplateKind::{Fetch, FetchNoStore, FetchUpload, Navigation};

    let value = match (id, kind) {
        ("chrome/154.0.8037.95/macos-15.5-arm64/r1", Navigation) => {
            browser::chrome::v154_macos_navigation_template()
        }
        ("chrome/154.0.8037.95/macos-15.5-arm64/r1", FetchNoStore) => {
            browser::chrome::v154_macos_fetch_no_store_template()
        }
        ("chrome/154.0.8037.95/macos-15.5-arm64/r1", Fetch) => {
            browser::chrome::v154_macos_fetch_template()
        }
        ("chrome/154.0.8037.97/windows-11-26200/r1", Navigation) => {
            browser::chrome::v154_windows_navigation_template()
        }
        ("chrome/154.0.8037.97/windows-11-26200/r1", FetchNoStore) => {
            browser::chrome::v154_windows_fetch_no_store_template()
        }
        ("chrome/154.0.8037.97/windows-11-26200/r1", Fetch) => {
            browser::chrome::v154_windows_fetch_template()
        }
        ("chrome/154.0.8037.97/windows-11-26200/r1", FetchUpload) => {
            browser::chrome::v154_windows_fetch_upload_template()
        }
        ("chrome/154.0.8037.57/android-17-pixel7-emulator/r1", Navigation) => {
            browser::chrome::v154_android_navigation_template()
        }
        ("chrome/154.0.8037.57/android-17-pixel7-emulator/r1", FetchNoStore) => {
            browser::chrome::v154_android_fetch_no_store_template()
        }
        ("edge/154.0.4258.48/windows-11-26200/r1", Navigation) => {
            browser::edge::v154_windows_navigation_template()
        }
        ("edge/154.0.4258.48/windows-11-26200/r1", FetchNoStore) => {
            browser::edge::v154_windows_fetch_no_store_template()
        }
        ("edge/153.0.4234.48/windows-11-26200/r1", Navigation) => {
            browser::edge::v153_windows_navigation_template()
        }
        ("edge/153.0.4234.48/windows-11-26200/r1", FetchNoStore) => {
            browser::edge::v153_windows_fetch_no_store_template()
        }
        ("edge/153.0.4234.49/android-17-pixel7-emulator/r1", Navigation) => {
            browser::edge::v153_android_navigation_template()
        }
        ("edge/153.0.4234.49/android-17-pixel7-emulator/r1", FetchNoStore) => {
            browser::edge::v153_android_fetch_no_store_template()
        }
        ("brave/154.1.96.59/windows-11-26200/r1", Navigation) => {
            browser::brave::v154_windows_navigation_template()
        }
        ("brave/154.1.96.59/windows-11-26200/r1", FetchNoStore) => {
            browser::brave::v154_windows_fetch_no_store_template()
        }
        ("brave/153.1.95.104/android-17-pixel7-emulator/r1", Navigation) => {
            browser::brave::v153_android_navigation_template()
        }
        ("brave/153.1.95.104/android-17-pixel7-emulator/r1", FetchNoStore) => {
            browser::brave::v153_android_fetch_no_store_template()
        }
        ("firefox/157.0/windows-11-26200/r2", Navigation) => {
            browser::firefox::v157_windows_navigation_template()
        }
        ("firefox/157.0/windows-11-26200/r2", FetchNoStore) => {
            browser::firefox::v157_windows_fetch_no_store_template()
        }
        ("firefox/157.0/windows-11-26200/r2", Fetch) => {
            browser::firefox::v157_windows_fetch_template()
        }
        ("firefox/157.0/windows-11-26200/r2", FetchUpload) => {
            browser::firefox::v157_windows_fetch_upload_template()
        }
        ("opera/136.0.6008.52/windows-11-26200/r1", Navigation) => {
            browser::opera::v136_windows_navigation_template()
        }
        ("opera/136.0.6008.52/windows-11-26200/r1", FetchNoStore) => {
            browser::opera::v136_windows_fetch_no_store_template()
        }
        _ => return None,
    };
    Some(value)
}

fn all_expected_templates() -> Vec<(&'static str, RequestTemplateKind, RequestTemplate)> {
    let mut expected = originals::expected_templates();
    let historical = expected
        .iter()
        .filter(|(id, _, _)| *id == "edge/154.0.4258.48/windows-11-26200/r1")
        .map(|(_, kind, value)| {
            (
                "edge/153.0.4234.48/windows-11-26200/r1",
                *kind,
                value.clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(historical.len(), 2);
    expected.extend(historical);
    let firefox_r3 = expected
        .iter()
        .filter(|(id, _, _)| *id == "firefox/157.0/windows-11-26200/r2")
        .map(|(_, kind, value)| ("firefox/157.0/windows-11-26200/r3", *kind, value.clone()))
        .collect::<Vec<_>>();
    assert_eq!(firefox_r3.len(), 4);
    expected.extend(firefox_r3);
    for id in [
        "edge/154.0.4258.48/windows-11-26200/r1",
        "chrome/156.0.8078.48/macos-26.6.2-arm64/r1",
    ] {
        expected.push((
            id,
            RequestTemplateKind::Fetch,
            browser::chrome::v154_macos_fetch_template(),
        ));
    }
    let id = "chrome/154.0.8037.95/macos-15.5-arm64/r1";
    expected.extend([
        (
            id,
            RequestTemplateKind::Navigation,
            browser::chrome::v154_macos_navigation_template(),
        ),
        (
            id,
            RequestTemplateKind::FetchNoStore,
            browser::chrome::v154_macos_fetch_no_store_template(),
        ),
        (
            id,
            RequestTemplateKind::Fetch,
            browser::chrome::v154_macos_fetch_template(),
        ),
    ]);
    expected.push((
        "chrome/156.0.8078.48/windows-11-26200/r1",
        RequestTemplateKind::Navigation,
        super::chrome_windows156::expected_navigation(),
    ));
    expected.push((
        "chrome/156.0.8078.47/ubuntu-24.04.4-wsl2/r1",
        RequestTemplateKind::Navigation,
        super::chrome_linux156::navigation::expected_navigation(),
    ));
    for id in [
        "chrome/156.0.8078.48/macos-26.6.2-arm64/r1",
        "chrome/156.0.8078.48/macos-15.7.9-x86-64/r1",
    ] {
        expected.push((
            id,
            RequestTemplateKind::Navigation,
            super::chrome_macos156::navigation::expected_navigation(),
        ));
    }
    expected
}

#[test]
fn every_catalog_template_preserves_its_frozen_values_and_original_factory() -> TestResult {
    let expected = originals::expected_templates();
    assert_eq!(expected.len(), 20);
    for (id, kind, value) in expected {
        value.validate()?;
        assert_eq!(
            original_factory(id, kind),
            Some(value.clone()),
            "original {id} {kind:?}"
        );
        let selected = profile(id)?.request_template(kind)?;
        selected.validate()?;
        assert_eq!(selected, value, "catalog {id} {kind:?}");
    }
    Ok(())
}

#[test]
fn every_unsupported_kind_keeps_the_exact_selection_error() -> TestResult {
    let expected = all_expected_templates();
    let mut supported = 0;
    let mut unsupported = 0;
    for definition in profiles() {
        if !matches!(
            definition.metadata().identity(),
            ProfileIdentity::Observed { .. }
        ) {
            continue;
        }
        for kind in KINDS {
            let found = expected
                .iter()
                .find(|(id, candidate, _)| *id == definition.id().as_str() && *candidate == kind);
            match found {
                Some((_, _, value)) => {
                    assert_eq!(definition.request_template(kind)?, *value);
                    supported += 1;
                }
                None if matches!(
                    definition.selector(),
                    "brave-154-windows" | "opera-136-windows"
                ) && kind == RequestTemplateKind::Fetch =>
                {
                    definition.request_template(kind)?.validate()?;
                    supported += 1;
                }
                None if matches!(
                    definition.selector(),
                    "chrome-156-windows"
                        | "chrome-156-linux"
                        | "chrome-156-macos"
                        | "chrome-156-macos-intel"
                ) && kind == RequestTemplateKind::FetchNoStore =>
                {
                    definition.request_template(kind)?.validate()?;
                    supported += 1;
                }
                None => {
                    assert_eq!(
                        definition.request_template(kind),
                        Err(CatalogError::UnavailableTemplate {
                            profile: definition.id(),
                            kind
                        })
                    );
                    unsupported += 1;
                }
            }
        }
    }
    assert_eq!((supported, unsupported), (41, 27));
    Ok(())
}

#[test]
fn changing_an_owned_template_does_not_change_another_instance_or_definition() -> TestResult {
    for (id, kind, expected) in originals::expected_templates() {
        let definition = profile(id)?;
        let debug_before = format!("{definition:?}");
        let second = definition.request_template(kind)?;
        let mut first = definition.request_template(kind)?;
        for field in &mut first.http1_fields {
            if let RequestField::Literal { name, value } = field {
                name.make_ascii_uppercase();
                value.make_ascii_uppercase();
            }
        }
        first.http1_fields.clear();
        first.http2_fields.reverse();
        first.http3_fields = Some(Vec::new());
        first.http2_priority = None;
        first.requested_client_hint_placement = !first.requested_client_hint_placement;
        first.restarts_for_connection_accept_ch = !first.restarts_for_connection_accept_ch;
        assert_eq!(second, expected);
        assert_eq!(definition.request_template(kind)?, expected);
        assert_eq!(format!("{definition:?}"), debug_before);
    }
    Ok(())
}

#[test]
fn definition_debug_does_not_expose_template_field_values() {
    for definition in profiles() {
        let debug = format!("{definition:?}");
        for value in [
            "Mozilla/5.0",
            "gzip, deflate",
            "text/html,application",
            "en-US,en;q=0.9",
        ] {
            assert!(
                !debug.contains(value),
                "template value appeared in definition Debug"
            );
        }
    }
}
