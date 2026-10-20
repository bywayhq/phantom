//! Immutable profile settings and explicit request-template selection.

use std::{fmt, sync::Arc};

use napi::{Error, Result, Status};
use phantom::{PreparedRequestTemplate, fingerprint};
use phantom_profile::{
    ClientProfile,
    catalog::{self, ProfileDefinition, RequestTemplateKind},
};

use crate::error::failure;

pub(crate) const MAXIMUM_PROFILE_BYTES: usize = 16 * 1024 * 1024;

pub(crate) struct ProfileState {
    pub(crate) settings: ClientProfile,
    definition: Option<&'static ProfileDefinition>,
    attached: Option<PreparedRequestTemplate>,
}

impl fmt::Debug for ProfileState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProfileState")
            .field("catalog_id", &self.catalog_id())
            .field("attached_template", &self.attached.is_some())
            .finish_non_exhaustive()
    }
}

impl ProfileState {
    pub(crate) fn catalog(identifier: &str, context: Option<&str>) -> Result<Arc<Self>> {
        let definition = catalog::profile(identifier)
            .map_err(|_| failure("UnknownProfile", "unknown exact profile identifier"))?;
        let mut settings = definition
            .instantiate(&[])
            .map_err(|_| failure("InvalidProfile", "profile cannot be instantiated"))?;
        if let Some(context) = context {
            settings = settings.with_request_template(catalog_template(definition, context)?);
        }
        Self::new(settings, Some(definition))
    }

    pub(crate) fn import(input: &[u8]) -> Result<Arc<Self>> {
        let settings = fingerprint::import_profile_json(input)
            .map_err(|error| document_error("ProfileImport", error.kind(), error.field()))?;
        Self::new(settings, None)
    }

    fn new(
        settings: ClientProfile,
        definition: Option<&'static ProfileDefinition>,
    ) -> Result<Arc<Self>> {
        let attached = settings
            .request_template()
            .cloned()
            .map(PreparedRequestTemplate::new)
            .transpose()
            .map_err(|_| {
                document_error(
                    "ProfileImport",
                    fingerprint::FingerprintImportErrorKind::InvalidSettings,
                    "request_template",
                )
            })?;
        Ok(Arc::new(Self {
            settings,
            definition,
            attached,
        }))
    }

    pub(crate) fn export(&self) -> Result<Vec<u8>> {
        fingerprint::export_profile_json(&self.settings)
            .map_err(|error| document_error("ProfileExport", error.kind(), error.field()))
    }

    pub(crate) fn catalog_id(&self) -> Option<String> {
        self.definition
            .map(|definition| definition.id().as_str().to_owned())
    }

    pub(crate) fn contexts(&self) -> Vec<String> {
        let mut contexts = vec!["raw".to_owned()];
        if self.attached.is_some() {
            contexts.push("profile".to_owned());
        }
        if let Some(definition) = self.definition {
            for (context, kind) in [
                ("navigation", RequestTemplateKind::Navigation),
                ("fetch", RequestTemplateKind::Fetch),
                ("fetchNoStore", RequestTemplateKind::FetchNoStore),
                ("fetchUpload", RequestTemplateKind::FetchUpload),
            ] {
                if definition.request_template(kind).is_ok() {
                    contexts.push(context.to_owned());
                }
            }
        }
        contexts
    }

    pub(crate) fn template(&self, context: &str) -> Result<Option<PreparedRequestTemplate>> {
        match context {
            "raw" => Ok(None),
            "profile" => self.attached.clone().map(Some).ok_or_else(unavailable),
            _ => {
                let kind = template_kind(context)?;
                let definition = self.definition.ok_or_else(unavailable)?;
                let template = definition
                    .request_template(kind)
                    .map_err(|_| unavailable())?;
                PreparedRequestTemplate::new(template)
                    .map(Some)
                    .map_err(|_| failure("InvalidProfile", "request template is invalid"))
            }
        }
    }
}

fn unavailable() -> Error {
    failure(
        "UnavailableContext",
        "this profile has no template for the requested context",
    )
}

fn template_kind(context: &str) -> Result<RequestTemplateKind> {
    match context {
        "navigation" => Ok(RequestTemplateKind::Navigation),
        "fetch" => Ok(RequestTemplateKind::Fetch),
        "fetchNoStore" => Ok(RequestTemplateKind::FetchNoStore),
        "fetchUpload" => Ok(RequestTemplateKind::FetchUpload),
        _ => Err(failure("InvalidContext", "unknown named catalog context")),
    }
}

fn catalog_template(
    definition: &ProfileDefinition,
    context: &str,
) -> Result<phantom_profile::RequestTemplate> {
    definition
        .request_template(template_kind(context)?)
        .map_err(|_| unavailable())
}

fn document_error(
    operation: &str,
    kind: fingerprint::FingerprintImportErrorKind,
    field: &str,
) -> Error {
    Error::new(
        Status::GenericFailure,
        format!("PHANTOM_PROFILE:{operation}:{kind:?}:{field}:profile document rejected"),
    )
}
