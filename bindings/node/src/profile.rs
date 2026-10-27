//! Immutable profile settings and explicit request-template selection.

use std::{fmt, sync::Arc};

use napi::{Error, Result, Status};
use phantom::{PreparedRequestTemplate, RequestBuilder, fingerprint};
use phantom_profile::{
    ClientProfile,
    catalog::{self, ProfileDefinition, RequestTemplateKind},
};

use crate::error::failure;

pub(crate) const MAXIMUM_PROFILE_BYTES: usize = 16 * 1024 * 1024;

pub(crate) struct ProfileImport {
    pub(crate) state: Arc<ProfileState>,
    pub(crate) observed_fields: Vec<String>,
    pub(crate) supplemented_fields: Vec<String>,
}

impl ProfileImport {
    fn checked(
        result: std::result::Result<
            fingerprint::ImportedProfile,
            fingerprint::FingerprintImportError,
        >,
    ) -> Result<Self> {
        let imported =
            result.map_err(|error| document_error("ProfileImport", error.kind(), error.field()))?;
        let observed_fields = imported.observed_fields().map(str::to_owned).collect();
        let supplemented_fields = imported.supplemented_fields().map(str::to_owned).collect();
        Ok(Self {
            state: ProfileState::new(imported.into_profile(), None)?,
            observed_fields,
            supplemented_fields,
        })
    }
}

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
    pub(crate) fn import_ja3(&self, text: &str) -> Result<ProfileImport> {
        ProfileImport::checked(fingerprint::import_ja3_profile(text, &self.settings))
    }

    pub(crate) fn import_client_hello(&self, input: &[u8]) -> Result<ProfileImport> {
        ProfileImport::checked(fingerprint::import_client_hello_profile(
            input,
            &self.settings,
        ))
    }

    pub(crate) fn import_akamai(&self, text: &str) -> Result<ProfileImport> {
        ProfileImport::checked(fingerprint::import_akamai_profile(text, &self.settings))
    }

    pub(crate) fn import_ja4(&self, text: &str, format: &str) -> Result<ProfileImport> {
        let format = match format {
            "sorted" => fingerprint::Ja4RawFormat::Sorted,
            "original" => fingerprint::Ja4RawFormat::Original,
            _ => {
                return Err(document_error(
                    "ProfileImport",
                    fingerprint::FingerprintImportErrorKind::InvalidValue,
                    "ja4.format",
                ));
            }
        };
        ProfileImport::checked(fingerprint::import_ja4_profile(
            text,
            format,
            &self.settings,
        ))
    }

    pub(crate) fn import_quic_transport(&self, input: &[u8]) -> Result<ProfileImport> {
        ProfileImport::checked(fingerprint::import_quic_transport_profile(
            input,
            &self.settings,
        ))
    }

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
                ("script", RequestTemplateKind::Script),
                ("stylesheet", RequestTemplateKind::Stylesheet),
                ("image", RequestTemplateKind::Image),
                ("font", RequestTemplateKind::Font),
            ] {
                if definition.request_template(kind).is_ok() {
                    contexts.push(context.to_owned());
                }
            }
        }
        contexts
    }

    pub(crate) fn apply_context(
        &self,
        builder: RequestBuilder,
        context: &str,
    ) -> Result<RequestBuilder> {
        match context {
            "raw" => Ok(builder.without_template()),
            "profile" => self
                .attached
                .as_ref()
                .map(|template| builder.template(template))
                .ok_or_else(unavailable),
            _ => {
                let kind = template_kind(context)?;
                self.definition.ok_or_else(unavailable)?;
                builder.context(kind).map_err(|_| unavailable())
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
        "script" => Ok(RequestTemplateKind::Script),
        "stylesheet" => Ok(RequestTemplateKind::Stylesheet),
        "image" => Ok(RequestTemplateKind::Image),
        "font" => Ok(RequestTemplateKind::Font),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_handshake_import_owns_settings_without_catalog_evidence()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let base =
            ProfileState::catalog("chrome/154.0.8037.97/windows-11-26200/r1", Some("fetch"))?;
        let before = base.export()?;
        let fixture = include_str!(
            "../../../fixtures/tls/chrome/154.0.8037.58/windows-11-26200/client-hello.txt"
        );
        let hex = fixture
            .lines()
            .find_map(|line| line.strip_prefix("record_0_hex="))
            .ok_or("missing capture record")?;
        let record: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16))
            .collect::<std::result::Result<_, _>>()?;
        let imported = base.import_client_hello(&record[5..])?;
        assert!(
            imported
                .observed_fields
                .iter()
                .any(|path| path == "tls.versions")
        );
        assert!(
            imported
                .supplemented_fields
                .iter()
                .any(|path| path == "tls.requested_trust_anchor_ids")
        );
        assert_eq!(base.export()?, before);
        assert_eq!(imported.state.catalog_id(), None);
        assert_eq!(imported.state.contexts(), ["raw", "profile"]);
        drop(base);
        let exported = imported.state.export()?;
        assert!(!String::from_utf8_lossy(&exported).contains("server.phantom.test"));
        assert_eq!(ProfileState::import(&exported)?.export()?, exported);
        Ok(())
    }

    #[test]
    fn ja4_format_errors_are_canonical_and_redacted()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let base = ProfileState::catalog("chrome/154.0.8037.97/windows-11-26200/r1", None)?;
        let error = base
            .import_ja4("private-secret", "private-format")
            .err()
            .ok_or("accepted invalid format")?;
        assert!(error.reason.contains(":InvalidValue:ja4.format:"));
        assert!(!error.reason.contains("private"));
        Ok(())
    }
}
