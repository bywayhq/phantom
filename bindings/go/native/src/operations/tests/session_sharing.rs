use super::*;

#[test]
fn fork_registration_preserves_client_capacity_and_released_owner_boundary() -> Result<(), Failure>
{
    let config = serde_json::from_value(json!({
        "profile": "chrome/154.0.8037.97/windows-11-26200/r1",
        "protocol": "h2", "cookies": true,
    }))
    .map_err(|_| Failure::new("test_config"))?;
    let source = NativeClient::new(config)?;
    let mut state = State::default();
    let id = state.id()?;
    state.clients.insert(id, source);
    let forked = state.fork_client(id, SessionSharing::default())?["id"]
        .as_u64()
        .ok_or_else(|| Failure::new("test_owner"))?;
    assert!(
        !state
            .clients
            .get(&forked)
            .ok_or_else(|| Failure::new("test_owner"))?
            .closing
    );
    for _ in 2..MAX_HANDLES {
        state.fork_client(id, SessionSharing::default())?;
    }
    let before = state.next;
    assert_eq!(
        state
            .fork_client(id, SessionSharing::default())
            .err()
            .map(|error| error.kind),
        Some("capacity")
    );
    assert_eq!(state.next, before);
    assert!(state.operations.is_empty());
    assert!(state.bodies.is_empty());
    state.release_client(id);
    assert_eq!(
        state
            .fork_client(id, SessionSharing::default())
            .err()
            .map(|error| error.kind),
        Some("client_closed")
    );
    assert!(state.clients.contains_key(&forked));
    Ok(())
}

#[test]
fn registered_closed_core_can_fork_into_open_independent_admission() -> Result<(), Failure> {
    let global = test_global()?;
    let config = serde_json::from_value(json!({
        "profile": "chrome/154.0.8037.97/windows-11-26200/r1",
        "protocol": "h1", "cookies": true,
    }))
    .map_err(|_| Failure::new("test_config"))?;
    let mut source = NativeClient::new(config)?;
    source.closing = true;
    global.runtime.block_on(source.client.shutdown());
    let fork = source.fork(SessionSharing::default());
    assert!(source.client.is_closed());
    assert!(!fork.client.is_closed());
    assert!(!fork.closing);
    Ok(())
}
