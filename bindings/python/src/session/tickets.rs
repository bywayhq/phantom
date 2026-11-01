//! Encrypted tickets use the core codec and explicit receiving-route validation.

use phantom::{Client, SessionTicketError, SessionTicketErrorKind, SessionTicketSnapshot};
use pyo3::{
    prelude::*,
    types::{PyBytes, PyBytesMethods, PyList},
};
use zeroize::Zeroizing;

use super::{Routes, transfer_failure, validate_entries};
use crate::configuration;

fn failure(error: SessionTicketError) -> PyErr {
    let kind = match error.kind() {
        SessionTicketErrorKind::TooLarge => "too_large",
        SessionTicketErrorKind::Allocation => "allocation",
        SessionTicketErrorKind::InvalidSnapshot => "invalid_snapshot",
        SessionTicketErrorKind::Authentication => "authentication",
        SessionTicketErrorKind::IncompatibleBackend => "incompatible_backend",
        SessionTicketErrorKind::Expired => "expired",
        SessionTicketErrorKind::Policy => "policy",
        SessionTicketErrorKind::Unsupported => "unsupported",
        SessionTicketErrorKind::Busy => "busy",
        SessionTicketErrorKind::Backend => "backend",
        _ => "unknown",
    };
    transfer_failure("session_tickets", kind, None)
}

fn key(input: &Bound<'_, PyBytes>) -> PyResult<Zeroizing<[u8; 32]>> {
    let mut secret = Zeroizing::new([0; 32]);
    if input.as_bytes().len() != secret.len() {
        return Err(transfer_failure(
            "session_tickets",
            "invalid_key_length",
            None,
        ));
    }
    secret.copy_from_slice(input.as_bytes());
    Ok(secret)
}

pub(crate) fn export(
    py: Python<'_>,
    client: &Client,
    input: &Bound<'_, PyBytes>,
) -> PyResult<Vec<u8>> {
    let key = key(input)?;
    py.detach(|| {
        let snapshot = client.export_session_tickets(&key).map_err(failure)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(snapshot.as_bytes().len())
            .map_err(|_| transfer_failure("session_tickets", "allocation", None))?;
        bytes.extend_from_slice(snapshot.as_bytes());
        Ok(bytes)
    })
}

pub(crate) fn import(
    py: Python<'_>,
    client: &Client,
    input: &Bound<'_, PyBytes>,
    secret: &Bound<'_, PyBytes>,
    routes: &Bound<'_, PyList>,
) -> PyResult<()> {
    let key = key(secret)?;
    if input.as_bytes().len() > 16 * 1024 * 1024 {
        return Err(transfer_failure("session_tickets", "too_large", None));
    }
    validate_entries(routes, 256, 3, &[], &[0, 1, 2], &[])?;
    let routes = routes
        .extract::<Routes>()?
        .iter()
        .map(|(uri, username, password)| {
            configuration::route(uri.as_deref(), username.as_deref(), password.as_deref())
        })
        .collect::<PyResult<Vec<_>>>()?;
    // Immutable PyBytes remains owned by this synchronous call while detached.
    let bytes = input.as_bytes();
    py.detach(|| {
        let snapshot = SessionTicketSnapshot::from_bytes(bytes).map_err(failure)?;
        client
            .import_session_tickets(&snapshot, &key, &routes)
            .map_err(failure)
    })
}
