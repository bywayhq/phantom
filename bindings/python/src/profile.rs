//! Owned profiles and strict authoring; imported settings carry no catalog claim.

use crate::error;
use phantom::fingerprint::{self, FingerprintImportErrorKind};
use phantom_profile::{
    ClientProfile,
    catalog::{self, ProfileDefinition, RequestTemplateKind},
};
use pyo3::{
    create_exception,
    exceptions::{PyException, PyTypeError},
    prelude::*,
    types::{PyBytes, PyBytesMethods},
};

create_exception!(_native, NativeProfileError, PyException);

fn document_error(kind: FingerprintImportErrorKind, field: &str) -> PyErr {
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
    NativeProfileError::new_err((kind, field.to_owned()))
}

fn template_kind(context: &str) -> PyResult<RequestTemplateKind> {
    match context {
        "navigation" => Ok(RequestTemplateKind::Navigation),
        "fetch" => Ok(RequestTemplateKind::Fetch),
        _ => Err(error::input("invalid_context")),
    }
}

#[pyclass(frozen)]
pub(super) struct NativeProfile {
    inner: ClientProfile,
    definition: Option<&'static ProfileDefinition>,
}

#[pymethods]
impl NativeProfile {
    #[staticmethod]
    #[pyo3(signature = (exact_id, context=None))]
    fn from_catalog(exact_id: &str, context: Option<&str>) -> PyResult<Self> {
        let definition = catalog::profile(exact_id).map_err(|_| error::input("unknown_profile"))?;
        let mut inner = definition
            .instantiate(&[])
            .map_err(|_| error::input("invalid_profile"))?
            .without_request_template();
        if let Some(context) = context {
            inner = inner.with_request_template(
                definition
                    .request_template(template_kind(context)?)
                    .map_err(|_| error::input("context_unavailable"))?,
            );
        }
        Ok(Self {
            inner,
            definition: Some(definition),
        })
    }

    #[staticmethod]
    fn import_json(py: Python<'_>, input: &Bound<'_, PyBytes>) -> PyResult<Self> {
        // PyBytes is immutable and remains owned by this call while Rust parses.
        let input = input.as_bytes();
        let inner = py
            .detach(|| fingerprint::import_profile_json(input))
            .map_err(|error| document_error(error.kind(), error.field()))?;
        Ok(Self {
            inner,
            definition: None,
        })
    }

    fn export_json(&self, py: Python<'_>) -> PyResult<Vec<u8>> {
        py.detach(|| fingerprint::export_profile_json(&self.inner))
            .map_err(|error| document_error(error.kind(), error.field()))
    }

    #[getter]
    fn catalog_id(&self) -> Option<&'static str> {
        self.definition.map(|definition| definition.id().as_str())
    }
}

impl NativeProfile {
    fn for_client(&self, context: Option<&str>) -> PyResult<ClientProfile> {
        match context {
            None | Some("raw") => Ok(self.inner.clone().without_request_template()),
            Some("profile") if self.inner.request_template().is_some() => Ok(self.inner.clone()),
            Some("profile") => Err(error::input("context_unavailable")),
            Some(context) => {
                let kind = template_kind(context)?;
                let definition = self
                    .definition
                    .ok_or_else(|| error::input("context_unavailable"))?;
                Ok(self.inner.clone().with_request_template(
                    definition
                        .request_template(kind)
                        .map_err(|_| error::input("context_unavailable"))?,
                ))
            }
        }
    }
}

pub(super) fn select(input: &Bound<'_, PyAny>, context: Option<&str>) -> PyResult<ClientProfile> {
    if let Ok(id) = input.extract::<&str>() {
        return NativeProfile::from_catalog(id, None)?.for_client(context);
    }
    let profile = input
        .extract::<PyRef<'_, NativeProfile>>()
        .map_err(|_| PyTypeError::new_err("profile must be an exact catalog ID or Profile"))?;
    profile.for_client(context)
}
