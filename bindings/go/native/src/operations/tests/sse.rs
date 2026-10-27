use super::*;

#[test]
fn terminal_event_releases_body_and_keeps_state_until_acknowledged() -> Result<(), Failure> {
    let global = test_global()?;
    let owner = empty_owner();
    let id = {
        let mut state = global.lock();
        state.bodies.insert(20, std::sync::Arc::clone(&owner));
        state.reserve(Target::Read(20))?.0
    };
    global.finish(
        id,
        Ok(Outcome::Event(crate::operations::sse::Read {
            event: None,
            last_event_id: "committed".to_owned(),
            retry: Some(std::time::Duration::from_millis(17)),
            error: Some(Failure::new("sse_line_too_long")),
            cause: None,
            trailers: None,
        })),
    );

    let mut state = global.lock();
    assert!(!state.bodies.contains_key(&20));
    assert!(owner.closed.load(Ordering::SeqCst));
    let read = state
        .operations
        .get(&id)
        .and_then(|operation| operation.event.as_ref())
        .ok_or_else(|| Failure::new("internal"))?;
    assert_eq!(read.id(), "committed");
    assert_eq!(read.retry, Some(std::time::Duration::from_millis(17)));
    assert!(matches!(
        state.ready.front().map(|queued| &queued.completion.result),
        Some(Ok(Completed::Complete))
    ));

    // An abandoned completed read must also release its retained event result.
    state.cancel(id);
    assert!(!state.operations.contains_key(&id));
    assert!(state.ready.is_empty());
    assert!(state.reserve(Target::Request(1)).is_ok());
    Ok(())
}
