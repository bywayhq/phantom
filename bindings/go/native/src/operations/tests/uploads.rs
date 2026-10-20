use super::*;

#[test]
fn bounded_upload_operations_do_not_reduce_request_capacity() -> Result<(), Failure> {
    let mut state = State::default();
    let mut cancellations = Vec::new();
    for owner in 0..MAX_HANDLES as u64 {
        cancellations.push(state.reserve(Target::UploadWrite(owner))?.1);
        cancellations.push(state.reserve(Target::UploadWait(owner))?.1);
        cancellations.push(state.reserve(Target::Request(1))?.1);
    }
    assert_eq!(
        state
            .reserve(Target::Request(1))
            .err()
            .map(|error| error.kind),
        Some("capacity")
    );
    assert_eq!(
        state
            .reserve(Target::UploadWrite(MAX_HANDLES as u64))
            .err()
            .map(|error| error.kind),
        Some("capacity")
    );
    assert_eq!(
        state
            .reserve(Target::UploadWait(MAX_HANDLES as u64))
            .err()
            .map(|error| error.kind),
        Some("capacity")
    );
    assert_eq!(cancellations.len(), 3 * MAX_HANDLES);
    Ok(())
}

#[test]
fn upload_operation_roles_are_exclusive_until_acknowledged() -> Result<(), Failure> {
    let mut state = State::default();
    let (_id, _cancel) = state.reserve(Target::UploadWrite(8))?;
    assert_eq!(
        state
            .reserve(Target::UploadWrite(8))
            .err()
            .map(|error| error.kind),
        Some("upload_operation_pending")
    );
    let (_id, _cancel) = state.reserve(Target::UploadWait(8))?;
    assert_eq!(
        state
            .reserve(Target::UploadWait(8))
            .err()
            .map(|error| error.kind),
        Some("upload_operation_pending")
    );
    Ok(())
}

#[tokio::test]
async fn release_closes_only_the_clients_uploads() -> Result<(), Failure> {
    let mut state = State::default();
    let first = Upload::new(1, None);
    let second = Upload::new(2, None);
    state.streams.insert(20, std::sync::Arc::clone(&first));
    state.streams.insert(21, std::sync::Arc::clone(&second));
    state.release_client(1);
    first.closed().await;
    assert!(!state.streams.contains_key(&20));
    assert!(state.streams.contains_key(&21));
    let _body = second.body()?;
    Ok(())
}
