//! Encrypted checkpoints reuse the core's bounded codec and configuration checks.

use crate::{configuration, error};
use phantom::{Client, SessionSnapshot, SessionSnapshotError, SessionSnapshotErrorKind};
use pyo3::{
    prelude::*,
    types::{PyBytes, PyBytesMethods},
};
use zeroize::Zeroizing;

pub(super) type Routes = Vec<(Option<String>, Option<String>, Option<String>)>;

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
