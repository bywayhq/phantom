//! Immutable replayable bodies encoded by the public core adapters.

use crate::error;
use phantom::{
    Bytes, MultipartPart, PreparedBodyError, PreparedBodyErrorKind, PreparedRequestBody,
};
use pyo3::{
    prelude::*,
    types::{PyBytes, PyInt, PyList, PyString},
};

#[pyclass(frozen)]
pub(super) struct NativePreparedBody {
    pub(super) inner: PreparedRequestBody,
}

fn failure(kind: &'static str) -> PyErr {
    error::NativeError::new_err(("prepared_body", kind, None::<String>, None::<String>))
}

fn prepared(error: PreparedBodyError) -> PyErr {
    failure(match error.kind() {
        PreparedBodyErrorKind::TooLarge => "too_large",
        PreparedBodyErrorKind::Allocation => "allocation",
        PreparedBodyErrorKind::InvalidName => "invalid_name",
        PreparedBodyErrorKind::InvalidFilename => "invalid_filename",
        PreparedBodyErrorKind::InvalidContentType => "invalid_content_type",
        PreparedBodyErrorKind::InvalidBoundary => "invalid_boundary",
        PreparedBodyErrorKind::BoundaryCollision => "boundary_collision",
        PreparedBodyErrorKind::TooManyParts => "too_many_parts",
        _ => "unknown",
    })
}

fn maximum(value: &Bound<'_, PyAny>) -> PyResult<usize> {
    value
        .cast_exact::<PyInt>()
        .map_err(|_| failure("invalid_maximum_bytes"))?
        .extract()
        .map_err(|_| failure("invalid_maximum_bytes"))
}

fn text<'a>(value: &'a Bound<'_, PyString>, limit: usize) -> PyResult<&'a str> {
    if value.len()? > limit {
        return Err(failure("too_large"));
    }
    let value = value.to_str().map_err(|_| failure("invalid_input"))?;
    if value.len() > limit {
        return Err(failure("too_large"));
    }
    Ok(value)
}

type Part<'py> = (
    Bound<'py, PyString>,
    Bound<'py, PyAny>,
    Option<Bound<'py, PyString>>,
    Option<Bound<'py, PyString>>,
);

#[pymethods]
impl NativePreparedBody {
    #[staticmethod]
    fn encoded(
        py: Python<'_>,
        input: &Bound<'_, PyBytes>,
        content_type: &Bound<'_, PyString>,
        maximum_bytes: &Bound<'_, PyAny>,
    ) -> PyResult<Self> {
        let maximum = maximum(maximum_bytes)?;
        let input = input.as_bytes();
        if input.len() > maximum {
            return Err(failure("too_large"));
        }
        let content_type = text(content_type, 4096)?;

        // Immutable Python bytes remain rooted until this synchronous copy finishes.
        py.detach(|| {
            PreparedRequestBody::encoded(Bytes::copy_from_slice(input), content_type, maximum)
        })
        .map(|inner| Self { inner })
        .map_err(prepared)
    }

    #[staticmethod]
    fn form(
        py: Python<'_>,
        pairs: &Bound<'_, PyList>,
        maximum_bytes: &Bound<'_, PyAny>,
    ) -> PyResult<Self> {
        let maximum = maximum(maximum_bytes)?;
        // Even an empty pair encodes at least '='. Bound metadata before allocation.
        if pairs.len() > maximum {
            return Err(failure("too_large"));
        }
        let pairs = pairs
            .iter()
            .map(|pair| {
                pair.extract::<(Bound<'_, PyString>, Bound<'_, PyString>)>()
                    .map_err(|_| failure("invalid_input"))
            })
            .collect::<PyResult<Vec<_>>>()?;
        let pairs = pairs
            .iter()
            .map(|(name, value)| Ok((text(name, maximum)?, text(value, maximum)?)))
            .collect::<PyResult<Vec<_>>>()?;
        // Rooted immutable strings outlive this synchronous detach. The closure
        // contains only Rust string borrows, never Python handles or callbacks.
        py.detach(|| PreparedRequestBody::form(pairs, maximum))
            .map(|inner| Self { inner })
            .map_err(prepared)
    }

    #[staticmethod]
    fn multipart(
        py: Python<'_>,
        boundary: &Bound<'_, PyString>,
        parts: &Bound<'_, PyList>,
        maximum_bytes: &Bound<'_, PyAny>,
    ) -> PyResult<Self> {
        let maximum = maximum(maximum_bytes)?;
        if parts.len() > 1024 {
            return Err(failure("too_many_parts"));
        }
        if boundary.len()? > 70 {
            return Err(failure("invalid_boundary"));
        }
        let boundary = boundary.to_str().map_err(|_| failure("invalid_boundary"))?;
        let parts = parts
            .iter()
            .map(|part| {
                part.extract::<Part<'_>>()
                    .map_err(|_| failure("invalid_input"))
            })
            .collect::<PyResult<Vec<_>>>()?;
        let parts = parts
            .iter()
            .map(|(name, value, filename, content_type)| {
                let name = text(name, 4096)?;
                let mut part = if let Ok(value) = value.cast::<PyBytes>() {
                    if value.as_bytes().len() > maximum {
                        return Err(failure("too_large"));
                    }
                    MultipartPart::bytes(name, value.as_bytes())
                } else if let Ok(value) = value.cast::<PyString>() {
                    MultipartPart::text(name, text(value, maximum)?)
                } else {
                    return Err(failure("invalid_input"));
                }
                .map_err(prepared)?;
                if let Some(filename) = filename {
                    part = part
                        .with_filename(text(filename, 4096)?)
                        .map_err(prepared)?;
                }
                if let Some(content_type) = content_type {
                    part = part
                        .with_content_type(text(content_type, 4096)?)
                        .map_err(prepared)?;
                }
                Ok(part)
            })
            .collect::<PyResult<Vec<_>>>()?;
        // Each borrowed payload is an immutable rooted str/bytes value.
        py.detach(|| PreparedRequestBody::multipart(boundary, parts, maximum))
            .map(|inner| Self { inner })
            .map_err(prepared)
    }

    #[getter]
    fn content_type(&self) -> &str {
        self.inner.content_type()
    }

    #[getter]
    fn length(&self) -> usize {
        self.inner.bytes().len()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.inner.bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_encoded_bytes_keep_order_and_validate_the_limit() -> PyResult<()> {
        Python::initialize();
        Python::attach(|py| {
            let input = PyBytes::new(py, br#"{"z":1,"a":2}"#);
            let content_type = PyString::new(py, "application/json");
            let cap = py.eval(c"13", None, None)?;
            let body = NativePreparedBody::encoded(py, &input, &content_type, &cap)?;
            assert_eq!(body.inner.bytes().as_ref(), br#"{"z":1,"a":2}"#);
            assert_eq!(body.inner.content_type(), "application/json");
            assert!(
                NativePreparedBody::encoded(
                    py,
                    &input,
                    &content_type,
                    &py.eval(c"12", None, None)?
                )
                .is_err()
            );
            assert!(
                NativePreparedBody::encoded(py, &input, &PyString::new(py, "bad\r\nvalue"), &cap)
                    .is_err()
            );
            Ok(())
        })
    }

    #[test]
    fn native_form_is_replayable_and_maximum_is_exact() -> PyResult<()> {
        Python::initialize();
        Python::attach(|py| {
            let pairs = py.eval(c"[('x', 'a b'), ('x', '+')]", None, None)?;
            let cap = py.eval(c"11", None, None)?;
            let body = NativePreparedBody::form(py, pairs.cast()?, &cap)?;
            assert_eq!(body.inner.bytes().as_ref(), b"x=a+b&x=%2B");
            assert_eq!(body.inner.clone(), body.inner);
            for invalid in [c"True", c"-1", c"1.0", c"1 << 100"] {
                assert!(
                    NativePreparedBody::form(py, pairs.cast()?, &py.eval(invalid, None, None)?)
                        .is_err()
                );
            }
            assert!(
                NativePreparedBody::form(py, pairs.cast()?, &py.eval(c"9", None, None)?).is_err()
            );
            Ok(())
        })
    }

    #[test]
    fn native_multipart_keeps_borrowed_order_and_precise_errors() -> PyResult<()> {
        Python::initialize();
        Python::attach(|py| {
            let boundary = pyo3::types::PyString::new(py, "B");
            let parts = py.eval(
                c"[('x', 'one\\ntwo', None, None), ('x', b'\\x00', 'data.bin', None)]",
                None,
                None,
            )?;
            let cap = py.eval(c"999", None, None)?;
            let body = NativePreparedBody::multipart(py, &boundary, parts.cast()?, &cap)?;
            assert!(
                body.inner
                    .bytes()
                    .windows(8)
                    .any(|bytes| bytes == b"one\r\ntwo")
            );
            assert!(
                body.inner
                    .bytes()
                    .windows(8)
                    .any(|bytes| bytes == b"data.bin")
            );
            let collision = py.eval(c"[('x', b'private--B', None, None)]", None, None)?;
            let failure = NativePreparedBody::multipart(py, &boundary, collision.cast()?, &cap)
                .err()
                .ok_or_else(|| error::input("expected_preparation_error"))?;
            let args: (String, String, Option<String>, Option<String>) =
                failure.value(py).getattr("args")?.extract()?;
            assert_eq!(
                (&*args.0, &*args.1),
                ("prepared_body", "boundary_collision")
            );
            assert!(!failure.to_string().contains("private"));
            Ok(())
        })
    }
}
