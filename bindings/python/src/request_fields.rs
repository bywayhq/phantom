//! Bounded owned request fields before scheduling native work.

use crate::error;
use phantom::RequestHeader;
use pyo3::{
    prelude::*,
    types::{PyBool, PyBytes, PyInt, PyList, PyString},
};
use std::time::Duration;

const MAXIMUM_FIELDS: usize = 256;
const MAXIMUM_BYTES: usize = 65536;

type Field<'py> = (
    Bound<'py, PyString>,
    Bound<'py, PyBytes>,
    Bound<'py, PyBool>,
);
fn field<'py>(value: &Bound<'py, PyAny>) -> PyResult<Field<'py>> {
    value
        .extract()
        .map_err(|_| error::input("invalid_request_field"))
}

pub(super) fn headers<'py>(
    headers: &Bound<'py, PyList>,
    trailers: Option<&Bound<'py, PyList>>,
) -> PyResult<(Vec<RequestHeader>, Vec<RequestHeader>)> {
    let count = headers
        .len()
        .checked_add(trailers.map_or(0, |list| list.len()))
        .ok_or_else(|| error::input("request_fields_limit"))?;
    if count > MAXIMUM_FIELDS {
        return Err(error::input("request_fields_limit"));
    }
    let mut remaining = MAXIMUM_BYTES;
    for fields in [Some(headers), trailers].into_iter().flatten() {
        for value in fields.iter() {
            let (name, value, _) = field(&value)?;
            if name.len()? > remaining || value.as_bytes().len() > remaining {
                return Err(error::input("request_fields_limit"));
            }
            remaining = remaining
                .checked_sub(
                    name.to_str()
                        .map_err(|_| error::input("invalid_request_field"))?
                        .len(),
                )
                .and_then(|remaining| remaining.checked_sub(value.as_bytes().len()))
                .ok_or_else(|| error::input("request_fields_limit"))?;
        }
    }
    let copy = |fields: Option<&Bound<'_, PyList>>| -> PyResult<Vec<RequestHeader>> {
        let Some(fields) = fields else {
            return Ok(Vec::new());
        };
        fields
            .iter()
            .map(|value| {
                let (name, value, sensitive) = field(&value)?;
                let header = RequestHeader::new(
                    name.to_str()
                        .map_err(|_| error::input("invalid_request_field"))?
                        .to_owned(),
                    value.as_bytes().to_vec(),
                );
                Ok(if sensitive.is_true() {
                    header.sensitive()
                } else {
                    header
                })
            })
            .collect()
    };
    Ok((copy(Some(headers))?, copy(trailers)?))
}

pub(super) fn expect_wait(value: Option<Bound<'_, PyAny>>) -> PyResult<Option<Duration>> {
    value
        .map(|value| {
            let value = value
                .cast_exact::<PyInt>()
                .map_err(|_| error::input("invalid_expect_continue_ms"))?
                .extract::<u64>()
                .map_err(|_| error::input("invalid_expect_continue_ms"))?;
            Ok(Duration::from_millis(value))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expect_wait_rejects_bool_and_preserves_zero_and_full_u64() -> PyResult<()> {
        Python::initialize();
        Python::attach(|py| {
            assert!(expect_wait(Some(PyBool::new(py, true).to_owned().into_any())).is_err());
            assert_eq!(expect_wait(None)?, None);
            for value in [
                py.eval(c"-1", None, None)?,
                py.eval(c"1 << 64", None, None)?,
                py.eval(c"0.5", None, None)?,
            ] {
                assert!(expect_wait(Some(value)).is_err());
            }
            for value in [0, u64::MAX] {
                assert_eq!(
                    expect_wait(Some(value.into_pyobject(py)?.into_any()))?,
                    Some(Duration::from_millis(value))
                );
            }
            Ok(())
        })
    }

    #[test]
    fn owned_trailers_keep_duplicates_order_and_sensitivity() -> PyResult<()> {
        Python::initialize();
        Python::attach(|py| {
            let empty = PyList::empty(py);
            let fields = PyList::new(
                py,
                [
                    ("X-Repeat", PyBytes::new(py, b"one"), true),
                    ("X-Middle", PyBytes::new(py, b"between"), false),
                    ("x-repeat", PyBytes::new(py, b"two"), false),
                ],
            )?;
            let (request, trailers) = headers(&empty, Some(&fields))?;
            assert!(request.is_empty());
            assert_eq!(
                trailers
                    .iter()
                    .map(|field| (field.name(), field.value(), field.is_sensitive()))
                    .collect::<Vec<_>>(),
                [
                    ("X-Repeat", b"one".as_slice(), true),
                    ("X-Middle", b"between".as_slice(), false),
                    ("x-repeat", b"two".as_slice(), false),
                ]
            );
            Ok(())
        })
    }

    #[test]
    fn field_limits_cover_headers_and_trailers_before_copying() -> PyResult<()> {
        Python::initialize();
        Python::attach(|py| {
            let header = ("X", PyBytes::new(py, b"a"), false);
            let request = PyList::new(py, std::iter::repeat_n(header, MAXIMUM_FIELDS))?;
            let trailer = PyList::new(py, [("Y", PyBytes::new(py, b"b"), true)])?;
            assert!(headers(&request, Some(&trailer)).is_err());
            let request = PyList::new(
                py,
                [("X", PyBytes::new(py, &vec![0; MAXIMUM_BYTES - 1]), false)],
            )?;
            assert!(headers(&request, None).is_ok());
            assert!(headers(&request, Some(&trailer)).is_err());
            Ok(())
        })
    }
}
