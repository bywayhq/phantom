//! Owned request contexts in editable profiles.

use std::sync::Arc;

use phantom_profile::{
    ClientProfile, RequestTemplate,
    catalog::{self, CatalogError, RequestTemplateKind},
};

use super::{FingerprintImportError, FingerprintImportErrorKind as Kind, Result, json};

pub(super) const KINDS: [(&str, RequestTemplateKind); 8] = [
    ("Navigation", RequestTemplateKind::Navigation),
    ("FetchNoStore", RequestTemplateKind::FetchNoStore),
    ("Fetch", RequestTemplateKind::Fetch),
    ("FetchUpload", RequestTemplateKind::FetchUpload),
    ("Script", RequestTemplateKind::Script),
    ("Stylesheet", RequestTemplateKind::Stylesheet),
    ("Image", RequestTemplateKind::Image),
    ("Font", RequestTemplateKind::Font),
];

pub(super) fn parse(value: &json::Value) -> Result<Vec<(RequestTemplateKind, RequestTemplate)>> {
    let json::Value::Object(fields) = value else {
        return Err(FingerprintImportError::new(
            Kind::InvalidValue,
            "request_contexts",
        ));
    };
    if fields.len() > KINDS.len() {
        return Err(FingerprintImportError::new(
            Kind::TooLarge,
            "request_contexts",
        ));
    }

    fields
        .iter()
        .map(|(name, value)| {
            let &(token, kind) = KINDS
                .iter()
                .find(|(token, _)| *token == name.as_ref())
                .ok_or_else(|| {
                    FingerprintImportError::new(Kind::UnsupportedSetting, "request_contexts")
                })?;
            let template = super::request_template::parse(value).map_err(|mut error| {
                let suffix = error.field.strip_prefix("request_template").unwrap_or("");
                error.field = format!("request_contexts.{token}{suffix}").into();
                error
            })?;
            Ok((kind, template))
        })
        .collect()
}

pub(super) fn entries(
    profile: &ClientProfile,
) -> Result<Vec<(RequestTemplateKind, Arc<RequestTemplate>)>> {
    let Some(id) = profile.request_context_profile() else {
        return Ok(profile.request_contexts().collect());
    };
    let definition = catalog::profile(id.as_str())
        .map_err(|error| FingerprintImportError::native("request_contexts", error))?;
    let mut templates = Vec::new();
    for (_, kind) in KINDS {
        match definition.request_template(kind) {
            Ok(template) => templates.push((kind, Arc::new(template))),
            Err(CatalogError::UnavailableTemplate { .. }) => {}
            Err(error) => return Err(FingerprintImportError::native("request_contexts", error)),
        }
    }
    Ok(templates)
}
