//! Parsed native identities; no Python key material survives construction.

use std::error::Error;

use phantom::{BuildError, ClientCertificate, ClientCertificateError, ClientCertificateErrorKind};
use pyo3::{
    prelude::*,
    types::{PyBytes, PyBytesMethods, PyTuple, PyTupleMethods},
};

use crate::error;

const MAXIMUM_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_CERTIFICATES: usize = 256;
const MAXIMUM_ORIGINS: usize = 256;
const MAXIMUM_ORIGIN_BYTES: usize = 64 * 1024;

pub(super) fn certificate_error(error: &ClientCertificateError) -> PyErr {
    let kind = match error.kind() {
        ClientCertificateErrorKind::Certificate => "certificate",
        ClientCertificateErrorKind::PrivateKey => "private_key",
        ClientCertificateErrorKind::KeyMismatch => "key_mismatch",
        ClientCertificateErrorKind::SignatureScheme => "signature_scheme",
        _ => "unsupported_certificate_error",
    };
    error::certificate(kind)
}

pub(super) fn build_error(error: BuildError) -> PyErr {
    if let Some(cause) = error.source().and_then(|cause| cause.downcast_ref()) {
        certificate_error(cause)
    } else {
        error::input("invalid_client_configuration")
    }
}

fn check_size(total: usize) -> PyResult<()> {
    if total > MAXIMUM_BYTES {
        return Err(error::certificate("too_large"));
    }
    Ok(())
}

#[pyclass(frozen)]
pub(super) struct NativeClientCertificate {
    pub(super) inner: ClientCertificate,
}

#[pymethods]
impl NativeClientCertificate {
    #[staticmethod]
    fn from_pem(
        py: Python<'_>,
        certificate_chain: &Bound<'_, PyBytes>,
        private_key: &Bound<'_, PyBytes>,
    ) -> PyResult<Self> {
        let chain = certificate_chain.as_bytes();
        let key = private_key.as_bytes();
        check_size(chain.len().saturating_add(key.len()))?;
        // Immutable PyBytes stay rooted by this synchronous call across detach.
        let inner = py
            .detach(|| ClientCertificate::from_pem(chain, key))
            .map_err(|error| certificate_error(&error))?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn from_der(
        py: Python<'_>,
        certificate_chain: &Bound<'_, PyTuple>,
        private_key: &Bound<'_, PyBytes>,
    ) -> PyResult<Self> {
        let chain = certificate_chain;
        let key = private_key;
        if chain.is_empty() || chain.len() > MAXIMUM_CERTIFICATES {
            return Err(error::certificate("invalid_chain_count"));
        }
        let mut total = key.as_bytes().len();
        // Inspect all input lengths before allocating even the borrowed list.
        for item in chain {
            let item = item
                .cast_into::<PyBytes>()
                .map_err(|_| error::certificate("invalid_certificate_bytes"))?;
            total = total.saturating_add(item.as_bytes().len());
        }
        check_size(total)?;
        let owners = chain
            .iter()
            .map(|item| {
                item.cast_into::<PyBytes>()
                    .map_err(|_| error::certificate("invalid_certificate_bytes"))
            })
            .collect::<PyResult<Vec<_>>>()?;
        let certificates: Vec<_> = owners.iter().map(|item| item.as_bytes()).collect();
        let key = key.as_bytes();
        let inner = py
            .detach(|| ClientCertificate::from_der(certificates, key))
            .map_err(|error| certificate_error(&error))?;
        Ok(Self { inner })
    }
}

pub(super) fn origins(
    values: Option<&Bound<'_, PyAny>>,
) -> PyResult<Vec<(String, ClientCertificate)>> {
    let Some(values) = values else {
        return Ok(Vec::new());
    };
    let values = values
        .cast::<PyTuple>()
        .map_err(|_| error::input("invalid_client_certificates_for"))?;
    if values.len() > MAXIMUM_ORIGINS {
        return Err(error::input("too_many_client_certificate_origins"));
    }
    // Validate the whole shape and aggregate bytes before cloning identities/URLs.
    let mut total = 0_usize;
    for value in values {
        let pair = value
            .cast_into::<PyTuple>()
            .map_err(|_| error::input("invalid_client_certificates_for"))?;
        if pair.len() != 2 {
            return Err(error::input("invalid_client_certificates_for"));
        }
        let origin = pair.get_item(0)?;
        let origin: &str = origin
            .extract()
            .map_err(|_| error::input("invalid_client_certificates_for"))?;
        total = total.saturating_add(origin.len());
        if origin.len() > MAXIMUM_ORIGIN_BYTES || total > MAXIMUM_BYTES {
            return Err(error::input("client_certificate_origins_too_large"));
        }
        let _: PyRef<'_, NativeClientCertificate> = pair
            .get_item(1)?
            .extract()
            .map_err(|_| error::input("invalid_client_certificates_for"))?;
    }
    values
        .iter()
        .map(|value| {
            let pair = value.cast_into::<PyTuple>()?;
            let origin: String = pair.get_item(0)?.extract()?;
            let owner = pair.get_item(1)?;
            let certificate: PyRef<'_, NativeClientCertificate> = owner.extract()?;
            Ok((origin, certificate.inner.clone()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsed_identity_and_direct_boundary_remain_bounded_and_redacted() -> PyResult<()> {
        Python::initialize();
        Python::attach(|py| {
            let pem = PyBytes::new(py, include_bytes!("../tests/fixtures/certificate.pem"));
            let key = PyBytes::new(py, include_bytes!("../tests/fixtures/key.pem"));
            let identity = NativeClientCertificate::from_pem(py, &pem, &key)?;
            let clone = identity.inner.clone();
            assert_eq!(
                identity
                    .inner
                    .certificate_chain_sha256()
                    .map_err(|cause| certificate_error(&cause))?,
                clone
                    .certificate_chain_sha256()
                    .map_err(|cause| certificate_error(&cause))?
            );
            let bad = PyBytes::new(py, b"private supplied input");
            for (chain, key, kind) in [(&bad, &key, "certificate"), (&pem, &bad, "private_key")] {
                let failure = NativeClientCertificate::from_pem(py, chain, key)
                    .err()
                    .ok_or_else(|| error::input("test_expected_certificate_error"))?;
                let fields: (String, String, Option<String>, Option<String>) =
                    failure.value(py).getattr("args")?.extract()?;
                assert_eq!(
                    fields,
                    ("client_certificate".into(), kind.into(), None, None)
                );
                assert!(!failure.to_string().contains("supplied"));
            }
            let empty = PyTuple::empty(py);
            assert!(NativeClientCertificate::from_der(py, &empty, &key).is_err());
            let over = PyTuple::new(py, (0..257).map(|_| &pem))?;
            assert!(NativeClientCertificate::from_der(py, &over, &key).is_err());
            let large = PyBytes::new(py, &vec![0; MAXIMUM_BYTES + 1]);
            let failure = NativeClientCertificate::from_pem(py, &large, &key)
                .err()
                .ok_or_else(|| error::input("test_expected_size_error"))?;
            assert!(failure.to_string().contains("too_large"));
            assert!(origins(Some(empty.as_any()))?.is_empty());
            let identity = Py::new(py, identity)?;
            let pair = PyTuple::new(
                py,
                [
                    "https://example.com".into_pyobject(py)?.as_any(),
                    identity.bind(py).as_any(),
                ],
            )?;
            let values = PyTuple::new(py, [&pair, &pair])?;
            let mapped = origins(Some(values.as_any()))?;
            assert_eq!(mapped.len(), 2);
            assert_eq!(mapped[0].0, "https://example.com");
            let over = PyTuple::new(py, (0..257).map(|_| &pair))?;
            assert!(origins(Some(over.as_any())).is_err());
            let oversized = PyTuple::new(
                py,
                [
                    "x".repeat(MAXIMUM_ORIGIN_BYTES + 1)
                        .into_pyobject(py)?
                        .as_any(),
                    identity.bind(py).as_any(),
                ],
            )?;
            let values = PyTuple::new(py, [&oversized])?;
            assert!(origins(Some(values.as_any())).is_err());
            Ok(())
        })
    }
}
