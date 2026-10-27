use super::*;

fn native_client() -> Result<NativeClient, Failure> {
    let config = serde_json::from_value(json!({
        "profile": "chrome-154-windows", "protocol": "h1", "cookies": false,
    }))
    .map_err(|_| Failure::new("test_config"))?;
    NativeClient::new(config)
}

#[test]
fn shutdown_retains_an_admitted_opening_before_its_first_poll() -> Result<(), Failure> {
    let global = test_global()?;
    let entry = native_client()?;
    let native = entry.client.clone();
    global.lock().clients.insert(1, entry);
    let request = native
        .websocket_with_protocol(phantom::HttpProtocol::Http1, "ws://127.0.0.1:1/socket")
        .map_err(|_| Failure::new("test_opening"))?
        // This fails locally after lifecycle admission; it performs no I/O.
        .handshake_timeout(Some(std::time::Duration::ZERO));
    let (opening, _cancel) = global.lock().reserve(Target::WebSocketOpen(1))?;
    global.runtime.block_on(async {
        let mut shutdown = Box::pin(global.shutdown(1, native.clone()));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(shutdown.as_mut().poll(&mut context).is_pending());
        assert!(!native.is_closed());

        let error = request
            .connect()
            .await
            .err()
            .ok_or_else(|| Failure::new("test_opening_accepted"))?;
        assert_eq!(error.kind(), phantom::WebSocketErrorKind::InvalidRequest);
        global.finish(opening, Err(Failure::new("invalid_websocket_request")));
        tokio::time::timeout(std::time::Duration::from_secs(5), shutdown)
            .await
            .map_err(|_| Failure::new("test_shutdown_stalled"))??;
        assert!(native.is_closed());
        Ok(())
    })
}

#[test]
fn cancelled_shutdown_wait_preserves_openings_and_retry_is_client_scoped() -> Result<(), Failure> {
    let global = test_global()?;
    let entry = native_client()?;
    let native = entry.client.clone();
    global.lock().clients.insert(1, entry);
    let (opening, _cancel) = global.lock().reserve(Target::WebSocketOpen(1))?;
    let (unrelated, _other_cancel) = global.lock().reserve(Target::WebSocketOpen(2))?;
    global.runtime.block_on(async {
        let mut shutdown = Box::pin(global.shutdown(1, native.clone()));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(shutdown.as_mut().poll(&mut context).is_pending());
        drop(shutdown);
        assert!(!native.is_closed());
        assert!(!global.lock().operations[&opening].abandoned);

        // A cancelled opening retains admission until its task has settled.
        global.lock().cancel(opening);
        let mut retry = Box::pin(global.shutdown(1, native.clone()));
        assert!(retry.as_mut().poll(&mut context).is_pending());
        global.finish(opening, Err(Failure::new("cancelled")));
        tokio::time::timeout(std::time::Duration::from_secs(5), retry)
            .await
            .map_err(|_| Failure::new("test_shutdown_retry_stalled"))??;
        assert!(native.is_closed());
        assert!(!global.lock().operations[&unrelated].abandoned);
        global.finish(unrelated, Err(Failure::new("cancelled")));
        Ok(())
    })
}

#[test]
fn independent_websocket_readers_do_not_spend_request_or_write_admission() -> Result<(), Failure> {
    let mut state = State::default();
    let mut receivers = Vec::new();
    for _ in 0..MAX_HANDLES {
        receivers.push(state.reserve(Target::Request(1))?.1);
    }
    for socket in [80, 81, 82, 83] {
        receivers.push(state.reserve(Target::WebSocketRead(socket))?.1);
        receivers.push(state.reserve(Target::WebSocketWrite(socket))?.1);
    }
    assert_eq!(
        state
            .reserve(Target::WebSocketRead(80))
            .err()
            .map(|error| error.kind),
        Some("websocket_read_pending")
    );
    assert_eq!(
        state
            .reserve(Target::WebSocketWrite(81))
            .err()
            .map(|error| error.kind),
        Some("websocket_write_pending")
    );
    assert!(state.reserve(Target::Shutdown(1)).is_ok());
    Ok(())
}

#[test]
fn websocket_opening_reserves_rejection_or_socket_custody_before_send() -> Result<(), Failure> {
    let mut state = State::default();
    for _ in 0..MAX_HANDLES - 1 {
        let id = state.id()?;
        state.bodies.insert(id, empty_owner());
    }
    let (id, _cancel) = state.reserve(Target::WebSocketOpen(1))?;
    assert!(
        state
            .operations
            .get(&id)
            .and_then(|operation| operation.reserved_response)
            .is_some()
    );
    assert_eq!(
        state
            .reserve(Target::Request(1))
            .err()
            .map(|error| error.kind),
        Some("capacity")
    );
    state.cancel(id);
    // Abandoned setup still owns its reservation until its task settles.
    assert_eq!(
        state
            .reserve(Target::WebSocketOpen(1))
            .err()
            .map(|error| error.kind),
        Some("capacity")
    );
    Ok(())
}
