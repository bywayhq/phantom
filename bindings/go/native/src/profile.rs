//! Caller-owned immutable profiles, independent of HTTP admission and handles.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};

use phantom::fingerprint::{self, FingerprintImportErrorKind};
use phantom_profile::{
    ClientProfile,
    catalog::{self, ProfileDefinition, RequestTemplateKind},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{error::Failure, operations};

pub(super) const MAX_DOCUMENT: usize = 16 * 1024 * 1024;

pub(super) struct ProfileState {
    settings: ClientProfile,
    definition: Option<&'static ProfileDefinition>,
}

impl ProfileState {
    fn catalog(identifier: &str, context: Option<&str>) -> Result<Self, Failure> {
        let definition =
            catalog::profile(identifier).map_err(|_| Failure::new("unknown_profile"))?;
        let mut settings = definition
            .instantiate(&[])
            .map_err(|_| Failure::new("invalid_profile"))?;
        if let Some(context) = context {
            settings = settings.with_request_template(catalog_template(definition, context)?);
        }
        Ok(Self {
            settings,
            definition: Some(definition),
        })
    }

    pub(super) fn selected(&self, context: Option<&str>) -> Result<ClientProfile, Failure> {
        let raw = self.settings.clone().without_request_template();
        match context.unwrap_or("raw") {
            "" | "raw" => Ok(raw),
            "profile" => self
                .settings
                .request_template()
                .cloned()
                .map(|template| raw.with_request_template(template))
                .ok_or_else(|| Failure::new("context_unavailable")),
            context => {
                template_kind(context)?;
                let definition = self
                    .definition
                    .ok_or_else(|| Failure::new("context_unavailable"))?;
                Ok(raw.with_request_template(catalog_template(definition, context)?))
            }
        }
    }
}

fn catalog_template(
    definition: &ProfileDefinition,
    context: &str,
) -> Result<phantom_profile::RequestTemplate, Failure> {
    definition
        .request_template(template_kind(context)?)
        .map_err(|_| Failure::new("context_unavailable"))
}

fn template_kind(context: &str) -> Result<RequestTemplateKind, Failure> {
    match context {
        "navigation" => Ok(RequestTemplateKind::Navigation),
        "fetch" => Ok(RequestTemplateKind::Fetch),
        "fetchNoStore" => Ok(RequestTemplateKind::FetchNoStore),
        "fetchUpload" => Ok(RequestTemplateKind::FetchUpload),
        _ => Err(Failure::new("invalid_context")),
    }
}

#[derive(Default)]
struct Registry {
    last: u64,
    owners: HashMap<u64, Arc<ProfileState>>,
}

impl Registry {
    fn insert(&mut self, owner: ProfileState) -> Result<Vec<u8>, Failure> {
        let id = self
            .last
            .checked_add(1)
            .ok_or_else(|| Failure::new("profile_id_exhausted"))?;
        let value = json!({"id": id, "catalog_id": owner.definition.map(|definition| definition.id().as_str())});
        // Serialize before publishing ownership: an ABI failure must not strand it.
        let reply = success(value)?;
        self.owners
            .try_reserve(1)
            .map_err(|_| Failure::new("profile_allocation"))?;
        self.owners.insert(id, Arc::new(owner));
        self.last = id;
        Ok(reply)
    }
}

static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();

fn registry() -> &'static Mutex<Registry> {
    REGISTRY.get_or_init(|| Mutex::new(Registry::default()))
}

pub(super) fn get(id: u64) -> Result<Arc<ProfileState>, Failure> {
    registry()
        .lock()
        .map_err(|_| Failure::new("internal"))?
        .owners
        .get(&id)
        .cloned()
        .ok_or_else(|| Failure::new("profile_closed"))
}

pub(super) fn named(identifier: &str, context: Option<&str>) -> Result<ClientProfile, Failure> {
    ProfileState::catalog(identifier, None)?.selected(context)
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Catalog {
        identifier: String,
        context: Option<String>,
    },
    Import {},
    Export {
        profile: u64,
    },
    Release {
        profile: u64,
    },
}

fn success(value: Value) -> Result<Vec<u8>, Failure> {
    serde_json::to_vec(&json!({"value": value}))
        .map_err(|_| Failure::new("internal"))
        .and_then(|bytes| {
            if bytes.len() <= operations::MAX_METADATA {
                Ok(bytes)
            } else {
                Err(Failure::new("metadata_limit"))
            }
        })
}

fn document_error(operation: &str, kind: FingerprintImportErrorKind, field: &str) -> Vec<u8> {
    let kind = match kind {
        FingerprintImportErrorKind::MalformedJson => "malformed_json",
        FingerprintImportErrorKind::MalformedDescription => "malformed_description",
        FingerprintImportErrorKind::TooLarge => "too_large",
        FingerprintImportErrorKind::MissingField => "missing_field",
        FingerprintImportErrorKind::DuplicateField => "duplicate_field",
        FingerprintImportErrorKind::UnsupportedFormat => "unsupported_format",
        FingerprintImportErrorKind::LossyDescription => "lossy_description",
        FingerprintImportErrorKind::UnsupportedSetting => "unsupported_setting",
        FingerprintImportErrorKind::InvalidValue => "invalid_value",
        FingerprintImportErrorKind::InvalidSettings => "invalid_settings",
        _ => "unknown",
    };
    serde_json::to_vec(
        &json!({"error": {"kind": format!("profile_{operation}_{kind}"), "field": field}}),
    )
    .unwrap_or_else(|_| operations::failure(Failure::new("internal")))
}

// Export is an immutable size probe or a complete copy, never a partial document.
// Registry guards end before parsing/exporting or building a client.
pub(super) fn dispatch(command: &[u8], input: &[u8], capacity: usize) -> (Vec<u8>, Vec<u8>) {
    let result = (|| {
        let command: Command =
            serde_json::from_slice(command).map_err(|_| Failure::new("invalid_command"))?;
        if !matches!(command, Command::Import {}) && !input.is_empty() {
            return Err(Failure::new("invalid_command"));
        }
        match command {
            Command::Catalog {
                identifier,
                context,
            } => {
                let owner = ProfileState::catalog(&identifier, context.as_deref())?;
                Ok((
                    registry()
                        .lock()
                        .map_err(|_| Failure::new("internal"))?
                        .insert(owner)?,
                    Vec::new(),
                ))
            }
            Command::Import {} => {
                let settings = match fingerprint::import_profile_json(input) {
                    Ok(settings) => settings,
                    Err(error) => {
                        return Ok((
                            document_error("import", error.kind(), error.field()),
                            Vec::new(),
                        ));
                    }
                };
                Ok((
                    registry()
                        .lock()
                        .map_err(|_| Failure::new("internal"))?
                        .insert(ProfileState {
                            settings,
                            definition: None,
                        })?,
                    Vec::new(),
                ))
            }
            Command::Export { profile } => {
                let owner = get(profile)?;
                let document = match fingerprint::export_profile_json(&owner.settings) {
                    Ok(document) => document,
                    Err(error) => {
                        return Ok((
                            document_error("export", error.kind(), error.field()),
                            Vec::new(),
                        ));
                    }
                };
                if document.len() > MAX_DOCUMENT {
                    return Err(Failure::new("profile_output_limit"));
                }
                let length = document.len();
                if capacity == 0 {
                    Ok((success(json!({"length": length}))?, Vec::new()))
                } else if capacity < length {
                    Err(Failure::new("profile_output_limit"))
                } else {
                    Ok((success(json!({"length": length}))?, document))
                }
            }
            Command::Release { profile } => {
                registry()
                    .lock()
                    .map_err(|_| Failure::new("internal"))?
                    .owners
                    .remove(&profile);
                Ok((success(json!({}))?, Vec::new()))
            }
        }
    })();
    result.unwrap_or_else(|error| (operations::failure(error), Vec::new()))
}

#[cfg(test)]
mod tests;
