//! Checkpoint CPU work uses ordinary operation admission and client ownership.

use super::*;
use phantom::SessionSnapshot;

pub(crate) struct SessionLease {
    pub(crate) source: NativeClient,
    id: u64,
    retained: bool,
    restored: Option<u64>,
}

impl SessionLease {
    pub(crate) fn new(client: u64) -> Result<Self, Failure> {
        let mut state = global()?.lock();
        if state.failed {
            return Err(Failure::new("internal"));
        }
        let source = state
            .clients
            .get(&client)
            .cloned()
            .ok_or_else(|| Failure::new("client_closed"))?;
        let (id, _) = state.reserve(Target::Session(client))?;
        Ok(Self {
            source,
            id,
            retained: false,
            restored: None,
        })
    }

    fn available(&self, state: &State) -> Result<(), Failure> {
        if state.failed {
            return Err(Failure::new("internal"));
        }
        if state.operations.get(&self.id).is_none_or(|op| op.abandoned) {
            return Err(Failure::new("client_closed"));
        }
        Ok(())
    }

    pub(crate) fn publish_snapshot(&self, snapshot: SessionSnapshot) -> Result<Value, Failure> {
        let mut state = global()?.lock();
        self.available(&state)?;
        let length = snapshot.as_bytes().len();
        let operation = state
            .operations
            .get_mut(&self.id)
            .ok_or_else(|| Failure::new("client_closed"))?;
        operation.snapshot = Some(snapshot);
        operation.finished = true;
        operation.cancel = None;
        Ok(json!({"operation": self.id, "length": length}))
    }

    pub(crate) fn publish_client(&mut self, client: NativeClient) -> Result<Value, Failure> {
        let mut state = global()?.lock();
        self.available(&state)?;
        if state.clients.len() >= MAX_HANDLES {
            return Err(Failure::new("capacity"));
        }
        let id = state.id()?;
        state.clients.insert(id, client);
        self.restored = Some(id);
        Ok(json!({"id": id}))
    }

    // Call only after encoding the complete successful reply. Until then Drop
    // rolls back any unpublished restored owner or prepared ciphertext.
    pub(crate) fn retain_snapshot(mut self) {
        self.retained = true;
    }

    pub(crate) fn accept_client(&mut self) {
        self.restored = None;
    }
}

impl Drop for SessionLease {
    fn drop(&mut self) {
        if let Ok(global) = global() {
            let mut state = global.lock();
            if let Some(client) = self.restored.take() {
                state.release_client(client);
            }
            if !self.retained {
                state.operations.remove(&self.id);
            }
        }
    }
}

pub(crate) fn take_snapshot(id: u64, capacity: usize) -> Result<SessionSnapshot, Failure> {
    let mut state = global()?.lock();
    if state.failed {
        return Err(Failure::new("internal"));
    }
    let operation = state
        .operations
        .get(&id)
        .ok_or_else(|| Failure::new("invalid_handle"))?;
    if !matches!(operation.target, Target::Session(_)) {
        return Err(Failure::new("invalid_handle"));
    }
    let snapshot = operation
        .snapshot
        .as_ref()
        .ok_or_else(|| Failure::new("operation_pending"))?;
    if snapshot.as_bytes().len() != capacity {
        return Err(Failure::new("snapshot_output_size"));
    }
    state
        .operations
        .remove(&id)
        .and_then(|operation| operation.snapshot)
        .ok_or_else(|| Failure::new("invalid_handle"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abandoned_codec_lease_drop_releases_reservation_and_unpublished_owner() -> Result<(), Failure>
    {
        let config = serde_json::from_value(json!({
            "profile": "chrome/154.0.8037.97/windows-11-26200/r1",
            "protocol": "h1",
            "cookies": true,
        }))
        .map_err(|_| Failure::new("internal"))?;
        let source = NativeClient::new(config)?;
        let source_id = {
            let mut state = global()?.lock();
            let id = state.id()?;
            state.clients.insert(id, source);
            id
        };
        let mut lease = SessionLease::new(source_id)?;
        let operation = lease.id;
        let restored = lease.source.fork(SessionSharing::default());
        let value = lease.publish_client(restored)?;
        let restored = value["id"]
            .as_u64()
            .ok_or_else(|| Failure::new("internal"))?;
        {
            let mut state = global()?.lock();
            state.release_client(source_id);
            assert!(state.clients.contains_key(&restored));
            assert!(
                state
                    .operations
                    .get(&operation)
                    .is_some_and(|op| op.abandoned)
            );
        }
        drop(lease);
        let state = global()?.lock();
        assert!(!state.clients.contains_key(&source_id));
        assert!(!state.clients.contains_key(&restored));
        assert!(!state.operations.contains_key(&operation));
        Ok(())
    }

    #[test]
    fn prepared_ciphertext_uses_ordinary_capacity_and_source_close_reclaims_it()
    -> Result<(), Failure> {
        let mut state = State::default();
        let id = state.reserve(Target::Session(1))?.0;
        let snapshot =
            SessionSnapshot::from_bytes(b"opaque").map_err(|_| Failure::new("internal"))?;
        let operation = state
            .operations
            .get_mut(&id)
            .ok_or_else(|| Failure::new("internal"))?;
        operation.snapshot = Some(snapshot);
        operation.finished = true;
        for _ in 1..MAX_HANDLES {
            state.reserve(Target::Request(2))?;
        }
        assert_eq!(
            state
                .reserve(Target::Session(2))
                .err()
                .map(|error| error.kind),
            Some("capacity")
        );
        state.release_client(1);
        assert!(!state.operations.contains_key(&id));
        assert_eq!(state.operations.len(), MAX_HANDLES - 1);
        assert!(state.reserve(Target::Request(2)).is_ok());
        Ok(())
    }

    #[test]
    fn source_close_keeps_cpu_reservation_until_native_owner_settles() -> Result<(), Failure> {
        let mut state = State::default();
        let id = state.reserve(Target::Session(1))?.0;
        for _ in 1..MAX_HANDLES {
            state.reserve(Target::Request(2))?;
        }
        state.release_client(1);
        assert!(
            state
                .operations
                .get(&id)
                .is_some_and(|operation| operation.abandoned)
        );
        assert_eq!(
            state
                .reserve(Target::Session(2))
                .err()
                .map(|error| error.kind),
            Some("capacity")
        );
        // SessionLease::drop removes the reservation only after codec work ends.
        state.operations.remove(&id);
        assert!(state.reserve(Target::Request(2)).is_ok());
        Ok(())
    }
}
