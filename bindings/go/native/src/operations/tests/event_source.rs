use super::*;

#[test]
fn shutdown_retains_an_admitted_event_source_before_its_first_poll() -> Result<(), Failure> {
    let global = test_global()?;
    let config = serde_json::from_value(
        json!({"profile":"chrome-154-windows","protocol":"h1","cookies":false}),
    )
    .map_err(|_| Failure::new("test_config"))?;
    let entry = NativeClient::new(config)?;
    let native = entry.client.clone();
    global.lock().clients.insert(1, entry);
    let request = native
        .event_source(phantom::HttpProtocol::Http1, "http://127.0.0.1/")
        .map_err(Failure::from)?
        .headers(vec![phantom::SseHeader::field(
            phantom::RequestHeader::new("Last-Event-ID", "invalid-literal"),
        )]);
    let (operation, _cancel) = global.lock().reserve(Target::EventSourceOpen(1))?;
    global.runtime.block_on(async {
        let mut shutdown = Box::pin(global.shutdown(1, native.clone()));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(shutdown.as_mut().poll(&mut context).is_pending());
        assert!(!native.is_closed());
        let error = request
            .connect()
            .await
            .err()
            .ok_or_else(|| Failure::new("test_source_accepted"))?;
        assert_eq!(error.kind(), phantom::SseErrorKind::InvalidRequestHeader);
        global.finish(operation, Err(Failure::new("sse_invalid_request_header")));
        tokio::time::timeout(std::time::Duration::from_secs(5), shutdown)
            .await
            .map_err(|_| Failure::new("test_shutdown_stalled"))??;
        assert!(native.is_closed());
        Ok(())
    })
}

#[test]
fn source_reads_remain_admissible_when_new_requests_fill_capacity() -> Result<(), Failure> {
    let mut state = State::default();
    let mut cancelled = Vec::new();
    for _ in 0..MAX_HANDLES {
        cancelled.push(state.reserve(Target::Maintenance(1))?.1);
    }
    assert_eq!(
        state
            .reserve(Target::EventSourceOpen(1))
            .err()
            .map(|error| error.kind),
        Some("capacity")
    );
    assert!(state.reserve(Target::EventSourceRead(55)).is_ok());
    assert!(state.reserve(Target::Shutdown(1)).is_ok());
    Ok(())
}
