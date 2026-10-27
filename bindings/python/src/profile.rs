//! Owned profiles and validated custom settings.

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

pub(super) fn template_kind(context: &str) -> PyResult<RequestTemplateKind> {
    match context {
        "navigation" => Ok(RequestTemplateKind::Navigation),
        "fetch" => Ok(RequestTemplateKind::Fetch),
        "fetch_no_store" => Ok(RequestTemplateKind::FetchNoStore),
        "fetch_upload" => Ok(RequestTemplateKind::FetchUpload),
        "script" => Ok(RequestTemplateKind::Script),
        "stylesheet" => Ok(RequestTemplateKind::Stylesheet),
        "image" => Ok(RequestTemplateKind::Image),
        "font" => Ok(RequestTemplateKind::Font),
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

    #[staticmethod]
    fn import_ja3(py: Python<'_>, input: &str, base: &Self) -> PyResult<ImportResult> {
        py.detach(|| fingerprint::import_ja3_profile(input, &base.inner))
            .map(import_result)
            .map_err(|error| document_error(error.kind(), error.field()))
    }

    #[staticmethod]
    fn import_client_hello(
        py: Python<'_>,
        input: &Bound<'_, PyBytes>,
        base: &Self,
    ) -> PyResult<ImportResult> {
        let input = input.as_bytes();
        py.detach(|| fingerprint::import_client_hello_profile(input, &base.inner))
            .map(import_result)
            .map_err(|error| document_error(error.kind(), error.field()))
    }

    #[staticmethod]
    fn import_akamai(py: Python<'_>, input: &str, base: &Self) -> PyResult<ImportResult> {
        py.detach(|| fingerprint::import_akamai_profile(input, &base.inner))
            .map(import_result)
            .map_err(|error| document_error(error.kind(), error.field()))
    }

    #[staticmethod]
    fn import_ja4(
        py: Python<'_>,
        input: &str,
        format: &str,
        base: &Self,
    ) -> PyResult<ImportResult> {
        let format = match format {
            "sorted" => fingerprint::Ja4RawFormat::Sorted,
            "original" => fingerprint::Ja4RawFormat::Original,
            _ => {
                return Err(document_error(
                    FingerprintImportErrorKind::InvalidValue,
                    "ja4.format",
                ));
            }
        };
        py.detach(|| fingerprint::import_ja4_profile(input, format, &base.inner))
            .map(import_result)
            .map_err(|error| document_error(error.kind(), error.field()))
    }

    #[staticmethod]
    fn import_quic_transport(
        py: Python<'_>,
        input: &Bound<'_, PyBytes>,
        base: &Self,
    ) -> PyResult<ImportResult> {
        let input = input.as_bytes();
        py.detach(|| fingerprint::import_quic_transport_profile(input, &base.inner))
            .map(import_result)
            .map_err(|error| document_error(error.kind(), error.field()))
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

type ImportResult = (NativeProfile, Vec<String>, Vec<String>);

fn import_result(imported: fingerprint::ImportedProfile) -> ImportResult {
    let observed = imported.observed_fields().map(str::to_owned).collect();
    let supplemented = imported.supplemented_fields().map(str::to_owned).collect();
    (
        NativeProfile {
            inner: imported.into_profile(),
            definition: None,
        },
        observed,
        supplemented,
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_client_hello_reaches_owned_profile_without_capture_identity() -> PyResult<()> {
        let fixture = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/tls/chrome/154.0.8037.58/windows-11-26200/client-hello.txt"
        ));
        let record = fixture
            .lines()
            .find_map(|line| line.strip_prefix("record_0_hex="))
            .ok_or_else(|| error::input("test_capture_missing"))?;
        let bytes = record
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let value =
                    std::str::from_utf8(pair).map_err(|_| error::input("test_capture_hex"))?;
                u8::from_str_radix(value, 16).map_err(|_| error::input("test_capture_hex"))
            })
            .collect::<PyResult<Vec<_>>>()?;
        Python::initialize();
        Python::attach(|py| {
            let base = NativeProfile::from_catalog(
                "chrome/154.0.8037.97/windows-11-26200/r1",
                Some("fetch"),
            )?;
            let (profile, observed, supplemented) =
                NativeProfile::import_client_hello(py, &PyBytes::new(py, &bytes[5..]), &base)?;
            assert_eq!(profile.catalog_id(), None);
            assert!(observed.iter().any(|field| field == "tls.versions"));
            assert!(
                supplemented
                    .iter()
                    .any(|field| field == "tls.requested_trust_anchor_ids")
            );
            assert_eq!(profile.inner.http2(), base.inner.http2());
            assert_eq!(
                profile.inner.request_template(),
                base.inner.request_template()
            );
            let exported = profile.export_json(py)?;
            let restored = NativeProfile::import_json(py, &PyBytes::new(py, &exported))?;
            assert_eq!(restored.inner, profile.inner);
            assert!(
                !exported
                    .windows(b"server.phantom.test".len())
                    .any(|value| value == b"server.phantom.test")
            );
            Ok(())
        })
    }
}
