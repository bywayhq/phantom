use std::error::Error;

use phantom_profile::{
    RequestField,
    browser::chrome,
    catalog::{self, RequestTemplateKind},
};
use serde_json::json;

use super::super::{
    FingerprintImportErrorKind as Kind, describe_profile, export_profile_json, import_profile_json,
};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn catalog_contexts_round_trip_as_owned_templates_with_exact_values() -> TestResult {
    for definition in catalog::profiles() {
        let profile = definition.instantiate(&[])?;
        let bytes = export_profile_json(&profile)?;
        let imported = import_profile_json(&bytes)?;
        assert!(imported.request_context_profile().is_none());
        let owned = imported.request_contexts().collect::<Vec<_>>();
        for kind in [
            RequestTemplateKind::Navigation,
            RequestTemplateKind::FetchNoStore,
            RequestTemplateKind::Fetch,
            RequestTemplateKind::FetchUpload,
            RequestTemplateKind::Script,
            RequestTemplateKind::Stylesheet,
            RequestTemplateKind::Image,
            RequestTemplateKind::Font,
        ] {
            let restored = owned.iter().find(|(candidate, _)| *candidate == kind);
            match definition.request_template(kind) {
                Ok(expected) => assert_eq!(
                    restored.map(|(_, template)| template.as_ref()),
                    Some(&expected)
                ),
                Err(catalog::CatalogError::UnavailableTemplate { .. }) => {
                    assert!(restored.is_none())
                }
                Err(error) => return Err(error.into()),
            }
        }
        assert_eq!(export_profile_json(&imported)?, bytes);
    }
    Ok(())
}

#[test]
fn edited_contexts_are_owned_and_do_not_restore_missing_catalog_contexts() -> TestResult {
    let original = chrome::v154_windows();
    let mut document = describe_profile(&original)?;
    let mut template = chrome::v154_windows_fetch_template();
    template
        .http2_fields
        .insert(0, RequestField::literal("x-custom-context", "edited"));
    let custom = original.with_request_contexts([(RequestTemplateKind::Fetch, template.clone())]);
    document["profile"]["request_contexts"] =
        describe_profile(&custom)?["profile"]["request_contexts"].clone();
    let mut bytes = serde_json::to_vec(&document)?;
    let imported = import_profile_json(&bytes)?;
    bytes.fill(0);
    drop(bytes);
    drop(document);
    let owned = imported.request_contexts().collect::<Vec<_>>();
    assert_eq!(owned.len(), 1);
    assert_eq!(owned[0].0, RequestTemplateKind::Fetch);
    assert_eq!(owned[0].1.as_ref(), &template);
    assert_eq!(imported.request_template(), custom.request_template());
    let client = crate::Client::builder(imported).build()?;
    client
        .get("https://example.test/")?
        .context(RequestTemplateKind::Fetch)?;
    let error = client
        .get("https://example.test/")?
        .context(RequestTemplateKind::Navigation)
        .err()
        .ok_or("catalog fallback restored")?;
    assert_eq!(error.kind(), crate::RequestErrorKind::RequestTemplate);
    Ok(())
}

#[test]
fn version_one_preserves_only_its_selected_template() -> TestResult {
    let profile =
        chrome::v154_windows().with_request_template(chrome::v154_windows_navigation_template());
    let mut document = describe_profile(&profile)?;
    document["version"] = 1.into();
    document["profile"]
        .as_object_mut()
        .ok_or("profile absent")?
        .remove("request_contexts");
    let imported = import_profile_json(&serde_json::to_vec(&document)?)?;
    assert_eq!(imported, profile);
    assert_eq!(imported.request_contexts().count(), 0);
    assert!(imported.request_context_profile().is_none());
    let client = crate::Client::builder(imported).build()?;
    assert!(
        client
            .get("https://example.test/")?
            .context(RequestTemplateKind::Navigation)
            .is_err()
    );
    Ok(())
}

#[test]
fn invalid_contexts_report_known_paths_and_retain_native_causes() -> TestResult {
    let base = describe_profile(&chrome::v154_windows())?;
    for contexts in [json!(null), json!([]), json!({"SECRET": {}})] {
        let mut document = base.clone();
        document["profile"]["request_contexts"] = contexts;
        let error = import_profile_json(&serde_json::to_vec(&document)?)
            .err()
            .ok_or("invalid contexts accepted")?;
        assert_eq!(error.field(), "request_contexts");
        assert!(!format!("{error} {error:?}").contains("SECRET"));
    }
    let mut document = base.clone();
    document["profile"]
        .as_object_mut()
        .ok_or("profile absent")?
        .remove("request_contexts");
    let missing = import_profile_json(&serde_json::to_vec(&document)?)
        .err()
        .ok_or("missing contexts accepted")?;
    assert_eq!(missing.kind(), Kind::MissingField);

    let mut document = base;
    document["profile"]["request_contexts"]["Fetch"]["http1_fields"] = json!([
        {"variant":"Literal", "name":"bad\r\nfield", "value":"SECRET"}
    ]);
    let invalid = import_profile_json(&serde_json::to_vec(&document)?)
        .err()
        .ok_or("invalid template accepted")?;
    assert_eq!(invalid.kind(), Kind::InvalidSettings);
    assert!(invalid.field().starts_with("request_contexts.Fetch"));
    assert!(invalid.source().is_some());
    assert!(!format!("{invalid} {invalid:?}").contains("SECRET"));
    Ok(())
}

#[test]
fn duplicate_context_names_and_more_than_eight_entries_are_rejected() -> TestResult {
    let document = describe_profile(&chrome::v154_windows())?;
    let encoded = serde_json::to_string(&document)?;
    let duplicated = encoded.replacen(
        "\"request_contexts\":{",
        "\"request_contexts\":{\"Fetch\":{},",
        1,
    );
    let error = import_profile_json(duplicated.as_bytes())
        .err()
        .ok_or("duplicate context accepted")?;
    assert_eq!(error.kind(), Kind::DuplicateField);
    let mut document = document;
    document["profile"]["request_contexts"] = json!({
        "Navigation":{}, "FetchNoStore":{}, "Fetch":{}, "FetchUpload":{},
        "Script":{}, "Stylesheet":{}, "Image":{}, "Font":{}, "extra":{}
    });
    let error = import_profile_json(&serde_json::to_vec(&document)?)
        .err()
        .ok_or("oversized contexts accepted")?;
    assert_eq!(error.kind(), Kind::TooLarge);
    assert_eq!(error.field(), "request_contexts");
    Ok(())
}
