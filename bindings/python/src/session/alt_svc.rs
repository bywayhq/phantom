//! Direct-route alternative metadata with exact absolute expiry conversion.

use phantom::{
    AltSvcSnapshot, AltSvcSnapshotEntry, AltSvcSnapshotError, AltSvcSnapshotErrorKind, Client,
};
use pyo3::{
    prelude::*,
    types::{PyInt, PyList, PyTuple},
};

use super::{
    MAXIMUM_TEXT, owned_text_size, timestamp, transfer_failure, unix_nanos, validate_entries,
};
use crate::error;

const MAXIMUM_ENTRIES: usize = 32768;
pub(crate) type Fields = (String, String, u16, i128);

fn failure(error: AltSvcSnapshotError) -> PyErr {
    let kind = match error.kind() {
        AltSvcSnapshotErrorKind::Disabled => "disabled",
        AltSvcSnapshotErrorKind::NoncanonicalOrigin => "noncanonical_origin",
        AltSvcSnapshotErrorKind::InvalidAlternative => "invalid_alternative",
        _ => "unknown",
    };
    transfer_failure("alt_svc_snapshot", kind, error.entry_index())
}

pub(crate) fn export(py: Python<'_>, client: &Client) -> PyResult<Option<Vec<Fields>>> {
    py.detach(|| {
        let Some(snapshot) = client.export_alt_svc() else {
            return Ok(None);
        };
        if snapshot.entries().len() > MAXIMUM_ENTRIES {
            return Err(error::input("state_transfer_limit"));
        }
        let mut remaining = MAXIMUM_TEXT;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(snapshot.entries().len())
            .map_err(|_| transfer_failure("alt_svc_snapshot", "allocation", None))?;
        for entry in snapshot.entries() {
            owned_text_size([entry.origin(), entry.alternative_host()], &mut remaining)?;
            entries.push((
                entry.origin().to_owned(),
                entry.alternative_host().to_owned(),
                entry.alternative_port(),
                unix_nanos(entry.expires_at())?,
            ));
        }
        Ok(Some(entries))
    })
}

pub(crate) fn import(py: Python<'_>, client: &Client, entries: &Bound<'_, PyList>) -> PyResult<()> {
    validate_entries(entries, MAXIMUM_ENTRIES, 4, &[0, 1], &[], &[])?;
    let mut snapshot = Vec::new();
    snapshot
        .try_reserve_exact(entries.len())
        .map_err(|_| transfer_failure("alt_svc_snapshot", "allocation", None))?;
    for value in entries.iter() {
        let value = value.cast_exact::<PyTuple>()?;
        value
            .get_item(2)?
            .cast_exact::<PyInt>()
            .map_err(|_| error::input("invalid_alternative_port"))?;
        let expiry = timestamp(&value.get_item(3)?)?;
        let (origin, host, port, _): Fields = value.extract()?;
        snapshot.push(AltSvcSnapshotEntry::new(origin, host, port, expiry));
    }
    py.detach(|| {
        client
            .import_alt_svc(&AltSvcSnapshot::new(snapshot))
            .map_err(failure)
    })
}
