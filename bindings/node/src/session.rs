//! Bounded encrypted checkpoints without JavaScript-owned CPU inputs.

use napi::{Error, Result, Status};
use phantom::{Client, Route, SessionSnapshot, SessionSnapshotError, SessionSnapshotErrorKind};
use zeroize::Zeroizing;

pub(crate) const MAXIMUM_BYTES: usize = 32 * 1024 * 1024;
pub(crate) const MAXIMUM_ROUTES: usize = 256;

pub(crate) fn failure(kind: &str) -> Error {
    Error::new(
        Status::GenericFailure,
        format!("PHANTOM_SNAPSHOT:{kind}:session checkpoint failed"),
    )
}

fn snapshot_error(error: SessionSnapshotError) -> Error {
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

pub(crate) fn key(bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<[u8; 32]>> {
    if bytes.len() != 32 {
        return Err(failure("invalid_key_length"));
    }
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

pub(crate) async fn export(client: Client, key: Zeroizing<[u8; 32]>) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        let snapshot = client.export_session(&key).map_err(snapshot_error)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(snapshot.as_bytes().len())
            .map_err(|_| failure("allocation"))?;
        bytes.extend_from_slice(snapshot.as_bytes());
        Ok(bytes)
    })
    .await
    .map_err(|_| failure("backend"))?
}

pub(crate) async fn restore(
    client: Client,
    bytes: Zeroizing<Vec<u8>>,
    key: Zeroizing<[u8; 32]>,
    routes: Vec<Route>,
) -> Result<Client> {
    // Dropping the awaiting future does not preempt this CPU work. Its owned
    // result is dropped if unpublished; no environment or JS buffer is retained.
    tokio::task::spawn_blocking(move || {
        let snapshot = SessionSnapshot::from_bytes(&bytes).map_err(snapshot_error)?;
        client
            .restore_session(&snapshot, &key, &routes)
            .map_err(snapshot_error)
    })
    .await
    .map_err(|_| failure("backend"))?
}
