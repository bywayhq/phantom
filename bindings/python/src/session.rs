//! Typed state transfers retain the core's validation and atomic import semantics.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{configuration, error};
use phantom::{Client, SessionSnapshot, SessionSnapshotError, SessionSnapshotErrorKind};
use pyo3::{
    prelude::*,
    types::{PyBytes, PyBytesMethods, PyInt, PyList, PyString, PyTuple},
};
use zeroize::Zeroizing;

pub(super) type Routes = Vec<(Option<String>, Option<String>, Option<String>)>;

pub(super) mod alt_svc;
pub(super) mod cookies;
pub(super) mod tickets;

const MAXIMUM_TEXT: usize = 32 * 1024 * 1024;

fn transfer_failure(category: &'static str, kind: &'static str, index: Option<usize>) -> PyErr {
    let error = error::NativeError::new_err((category, kind, None::<String>, None::<String>));
    Python::attach(|py| {
        if let Err(failure) = error.value(py).setattr("entry_index", index) {
            return failure;
        }
        error
    })
}

fn account(value: &Bound<'_, PyAny>, remaining: &mut usize) -> PyResult<()> {
    let text = value
        .cast_exact::<PyString>()
        .map_err(|_| error::input("invalid_state_text"))?;
    if text.len()? > *remaining {
        return Err(error::input("state_transfer_limit"));
    }
    let size = text
        .to_str()
        .map_err(|_| error::input("invalid_state_text"))?
        .len();
    *remaining = remaining
        .checked_sub(size)
        .ok_or_else(|| error::input("state_transfer_limit"))?;
    Ok(())
}

fn timestamp(value: &Bound<'_, PyAny>) -> PyResult<SystemTime> {
    let nanos = value
        .cast_exact::<PyInt>()
        .map_err(|_| error::input("invalid_state_expiry"))?
        .extract::<i128>()
        .map_err(|_| error::input("invalid_state_expiry"))?;
    let magnitude = nanos.unsigned_abs();
    let seconds = u64::try_from(magnitude / 1_000_000_000)
        .map_err(|_| error::input("invalid_state_expiry"))?;
    let subsecond = u32::try_from(magnitude % 1_000_000_000)
        .map_err(|_| error::input("invalid_state_expiry"))?;
    let duration = Duration::new(seconds, subsecond);
    let time = if nanos < 0 {
        UNIX_EPOCH.checked_sub(duration)
    } else {
        UNIX_EPOCH.checked_add(duration)
    }
    .ok_or_else(|| error::input("invalid_state_expiry"))?;
    if unix_nanos(time)? != nanos {
        return Err(error::input("invalid_state_expiry"));
    }
    Ok(time)
}

fn unix_nanos(time: SystemTime) -> PyResult<i128> {
    let (duration, negative) = match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => (duration, false),
        Err(error) => (error.duration(), true),
    };
    let nanos =
        i128::try_from(duration.as_nanos()).map_err(|_| error::input("invalid_state_expiry"))?;
    Ok(if negative { -nanos } else { nanos })
}

fn validate_entries(
    entries: &Bound<'_, PyList>,
    maximum: usize,
    width: usize,
    text_fields: &[usize],
    optional_text_fields: &[usize],
    bool_fields: &[usize],
) -> PyResult<()> {
    if entries.len() > maximum {
        return Err(error::input("state_transfer_limit"));
    }
    let mut remaining = MAXIMUM_TEXT;
    for entry in entries.iter() {
        let entry = entry
            .cast_exact::<PyTuple>()
            .map_err(|_| error::input("invalid_state_entry"))?;
        if entry.len() != width {
            return Err(error::input("invalid_state_entry"));
        }
        for &field in text_fields {
            account(&entry.get_item(field)?, &mut remaining)?;
        }
        for &field in optional_text_fields {
            let value = entry.get_item(field)?;
            if !value.is_none() {
                account(&value, &mut remaining)?;
            }
        }
        for &field in bool_fields {
            entry
                .get_item(field)?
                .cast_exact::<pyo3::types::PyBool>()
                .map_err(|_| error::input("invalid_state_flag"))?;
        }
    }
    Ok(())
}

fn owned_text_size<'a>(
    text: impl IntoIterator<Item = &'a str>,
    remaining: &mut usize,
) -> PyResult<()> {
    for value in text {
        *remaining = remaining
            .checked_sub(value.len())
            .ok_or_else(|| error::input("state_transfer_limit"))?;
    }
    Ok(())
}

fn failure(kind: &'static str) -> PyErr {
    error::NativeError::new_err(("session_snapshot", kind, None::<String>, None::<String>))
}

fn snapshot_error(error: SessionSnapshotError) -> PyErr {
    let kind = match error.kind() {
        SessionSnapshotErrorKind::TooLarge => "too_large",
        SessionSnapshotErrorKind::Allocation => "allocation",
        SessionSnapshotErrorKind::InvalidSnapshot => "invalid_snapshot",
        SessionSnapshotErrorKind::Authentication => "authentication",
        SessionSnapshotErrorKind::Incompatible => "incompatible",
        SessionSnapshotErrorKind::Disabled => "disabled",
        SessionSnapshotErrorKind::Capacity => "capacity",
        SessionSnapshotErrorKind::Unsupported => "unsupported",
        SessionSnapshotErrorKind::Tickets => "tickets",
        SessionSnapshotErrorKind::Cookies => "cookies",
        SessionSnapshotErrorKind::AltSvc => "alt_svc",
        SessionSnapshotErrorKind::Backend => "backend",
        _ => "unknown",
    };
    failure(kind)
}

fn key(input: &Bound<'_, PyBytes>) -> PyResult<Zeroizing<[u8; 32]>> {
    let bytes = input.as_bytes();
    if bytes.len() != 32 {
        return Err(failure("invalid_key_length"));
    }
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(bytes);
    Ok(key)
}

pub(super) fn export(
    py: Python<'_>,
    client: &Client,
    input: &Bound<'_, PyBytes>,
) -> PyResult<Vec<u8>> {
    let key = key(input)?;
    py.detach(|| {
        let snapshot = client.export_session(&key).map_err(snapshot_error)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(snapshot.as_bytes().len())
            .map_err(|_| failure("allocation"))?;
        bytes.extend_from_slice(snapshot.as_bytes());
        Ok(bytes)
    })
}

pub(super) fn restore(
    py: Python<'_>,
    client: &Client,
    input: &Bound<'_, PyBytes>,
    secret: &Bound<'_, PyBytes>,
    routes: Routes,
) -> PyResult<Client> {
    let key = key(secret)?;
    let routes = routes
        .iter()
        .map(|(uri, username, password)| {
            configuration::route(uri.as_deref(), username.as_deref(), password.as_deref())
        })
        .collect::<PyResult<Vec<_>>>()?;
    // PyBytes remains immutable and owned by this synchronous call while detached.
    let input = input.as_bytes();
    py.detach(|| {
        let snapshot = SessionSnapshot::from_bytes(input).map_err(snapshot_error)?;
        client
            .restore_session(&snapshot, &key, &routes)
            .map_err(snapshot_error)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_conversion_preserves_representable_fractional_and_pre_epoch_times() -> PyResult<()> {
        Python::initialize();
        Python::attach(|py| {
            for value in [-1_000_000_100_i128, -100, 0, 100, 2_000_000_000_123_456_700] {
                let object = value.into_pyobject(py)?;
                assert_eq!(unix_nanos(timestamp(object.as_any())?)?, value);
            }
            for source in [c"True", c"1.5", c"2**128", c"'private'"] {
                let value = py.eval(source, None, None)?;
                let failure = timestamp(&value)
                    .err()
                    .ok_or_else(|| error::input("test_expected_expiry_error"))?;
                assert!(!failure.to_string().contains("private"));
            }
            Ok(())
        })
    }

    #[test]
    fn borrowed_state_validation_rejects_shapes_subclasses_flags_and_utf8_before_copy()
    -> PyResult<()> {
        Python::initialize();
        Python::attach(|py| {
            let scope = pyo3::types::PyDict::new(py);
            py.run(c"class Text(str): pass", Some(&scope), None)?;
            for source in [
                c"[('private',)]",
                c"[[None, None, None]]",
                c"[(Text('private'), None, None)]",
                c"[('private\\ud800', None, None)]",
                c"[(None, None, None)] * 257",
            ] {
                let value = py.eval(source, Some(&scope), None)?;
                let value = value.cast::<PyList>()?;
                assert!(validate_entries(value, 256, 3, &[], &[0, 1, 2], &[]).is_err());
            }
            let fields = py.eval(c"[('private', True)]", None, None)?;
            assert!(validate_entries(fields.cast::<PyList>()?, 1, 2, &[0], &[], &[1]).is_ok());
            let fields = py.eval(c"[('private', 1)]", None, None)?;
            assert!(validate_entries(fields.cast::<PyList>()?, 1, 2, &[0], &[], &[1]).is_err());
            let mut remaining = 3;
            assert!(owned_text_size(["é"], &mut remaining).is_ok());
            assert_eq!(remaining, 1);
            assert!(owned_text_size(["é"], &mut remaining).is_err());
            Ok(())
        })
    }
}
