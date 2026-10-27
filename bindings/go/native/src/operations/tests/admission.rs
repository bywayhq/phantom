use super::*;

#[test]
fn shutdown_retains_an_admitted_http_request_before_its_first_poll() -> Result<(), Failure> {
    let global = test_global()?;
    let config = serde_json::from_value(json!({
        "profile": "chrome-154-windows", "protocol": "h1", "cookies": false,
    }))
    .map_err(|_| Failure::new("test_config"))?;
    let entry = NativeClient::new(config)?;
    let native = entry.client.clone();
    global.lock().clients.insert(1, entry);
    let request = native
        .request_with_protocol(
            phantom::HttpProtocol::Http1,
            phantom::Method::GET,
            "http://127.0.0.1:1/",
        )
        .map_err(|_| Failure::new("test_request"))?
        .without_template()
        // Host is rejected locally after lifecycle admission, before I/O.
        .header(phantom::RequestHeader::new("Host", "invalid.test"));
    let (operation, _cancel) = global.lock().reserve(Target::Request(1))?;
    global.runtime.block_on(async {
        let mut shutdown = Box::pin(global.shutdown(1, native.clone()));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(shutdown.as_mut().poll(&mut context).is_pending());
        assert!(!native.is_closed());

        let error = request
            .send()
            .await
            .err()
            .ok_or_else(|| Failure::new("test_request_accepted"))?;
        assert_eq!(error.kind(), phantom::RequestErrorKind::InvalidHeader);
        global.finish(operation, Err(Failure::new("invalid_header")));
        tokio::time::timeout(std::time::Duration::from_secs(5), shutdown)
            .await
            .map_err(|_| Failure::new("test_shutdown_stalled"))??;
        assert!(native.is_closed());
        Ok(())
    })
}

#[test]
fn cancelled_shutdown_preserves_admitted_requests_until_their_tasks_settle() -> Result<(), Failure>
{
    let global = test_global()?;
    let config = serde_json::from_value(json!({
        "profile": "chrome-154-windows", "protocol": "h1", "cookies": false,
    }))
    .map_err(|_| Failure::new("test_config"))?;
    let entry = NativeClient::new(config)?;
    let native = entry.client.clone();
    let independent = entry.fork(SessionSharing::default());
    let other = independent.client.clone();
    global.lock().clients.insert(1, entry);
    global.lock().clients.insert(2, independent);
    let (request, _cancel) = global.lock().reserve(Target::Request(1))?;
    let (unrelated, _other_cancel) = global.lock().reserve(Target::Request(2))?;

    global.runtime.block_on(async {
        let mut shutdown = Box::pin(global.shutdown(1, native.clone()));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(shutdown.as_mut().poll(&mut context).is_pending());
        drop(shutdown);
        assert!(!native.is_closed());
        assert!(
            global
                .lock()
                .operations
                .get(&request)
                .is_some_and(|op| !op.abandoned)
        );

        global.lock().cancel(request);
        let mut retry = Box::pin(global.shutdown(1, native.clone()));
        assert!(retry.as_mut().poll(&mut context).is_pending());
        global.finish(request, Err(Failure::new("cancelled")));
        tokio::time::timeout(std::time::Duration::from_secs(5), retry)
            .await
            .map_err(|_| Failure::new("test_shutdown_retry_stalled"))??;
        assert!(native.is_closed());
        assert!(!other.is_closed());
        assert!(
            global
                .lock()
                .operations
                .get(&unrelated)
                .is_some_and(|op| !op.abandoned)
        );
        global.finish(unrelated, Err(Failure::new("cancelled")));
        Ok(())
    })
}

fn head(body: std::sync::Arc<BodyOwner>) -> Outcome {
    Outcome::Head(Head {
        status: 200,
        protocol: "h1",
        headers: Vec::new(),
        effective_url: "http://localhost/".to_owned(),
        redirects_followed: 0,
        connection_setup_retries: 0,
        decoded_content_codings: Vec::new(),
        redirect_history: None,
        body,
    })
}

fn fill_bodies(state: &mut State, count: usize) -> Result<(), Failure> {
    for _ in 0..count {
        let id = state.id()?;
        state.bodies.insert(id, empty_owner());
    }
    Ok(())
}

#[test]
fn response_custody_is_reserved_before_request_admission() -> Result<(), Failure> {
    let mut state = State::default();
    fill_bodies(&mut state, MAX_HANDLES - 1)?;
    let (request, _cancel) = state.reserve(Target::Request(1))?;
    assert!(state.operations[&request].reserved_response.is_some());
    assert_eq!(
        state
            .reserve(Target::Request(1))
            .err()
            .map(|error| error.kind),
        Some("capacity")
    );

    // Cancelling a task does not make its still-running work unaccounted for.
    state.cancel(request);
    assert_eq!(
        state
            .reserve(Target::Request(1))
            .err()
            .map(|error| error.kind),
        Some("capacity")
    );
    Ok(())
}

#[test]
fn response_completion_needs_no_new_id_or_body_slot() -> Result<(), Failure> {
    let global = test_global()?;
    let (request, body) = {
        let mut state = global.lock();
        fill_bodies(&mut state, MAX_HANDLES - 1)?;
        let (request, _) = state.reserve(Target::Request(1))?;
        let body = state.operations[&request]
            .reserved_response
            .ok_or_else(|| Failure::new("internal"))?;
        state.next = u64::MAX;
        (request, body)
    };
    global.finish(request, Ok(head(empty_owner())));

    let state = global.lock();
    assert_eq!(state.bodies.len(), MAX_HANDLES);
    assert!(state.bodies.contains_key(&body));
    assert!(state.operations[&request].reserved_response.is_none());
    assert_eq!(state.operations[&request].response, Some(body));
    assert!(matches!(
        state.ready.front().map(|queued| &queued.completion.result),
        Some(Ok(Completed::Head(completed))) if completed.body == body
    ));
    Ok(())
}

#[test]
fn failed_and_abandoned_requests_release_response_custody() -> Result<(), Failure> {
    for abandoned in [false, true] {
        let global = test_global()?;
        let request = {
            let mut state = global.lock();
            fill_bodies(&mut state, MAX_HANDLES - 1)?;
            let (request, _) = state.reserve(Target::Request(1))?;
            if abandoned {
                state.cancel(request);
            }
            request
        };
        global.finish(request, Err(Failure::new("cancelled")));

        let mut state = global.lock();
        assert_eq!(state.bodies.len(), MAX_HANDLES - 1);
        if abandoned {
            assert!(!state.operations.contains_key(&request));
        } else {
            assert!(state.operations[&request].reserved_response.is_none());
        }
        assert!(state.reserve(Target::Request(1)).is_ok());
    }
    Ok(())
}

#[test]
fn reads_have_service_capacity_during_maintenance_and_snapshot_work() -> Result<(), Failure> {
    let mut state = State::default();
    fill_bodies(&mut state, MAX_HANDLES)?;
    for index in 0..MAX_HANDLES {
        let target = if index % 2 == 0 {
            Target::Maintenance(1)
        } else {
            Target::Session(1)
        };
        state.reserve(target)?;
    }
    assert_eq!(
        state
            .reserve(Target::Maintenance(1))
            .err()
            .map(|error| error.kind),
        Some("capacity")
    );

    let bodies: Vec<_> = state.bodies.keys().copied().collect();
    for body in bodies {
        state.reserve(Target::Read(body))?;
    }
    assert_eq!(
        state.reserve(Target::Read(1)).err().map(|error| error.kind),
        Some("capacity")
    );
    assert!(state.reserve(Target::Shutdown(1)).is_ok());
    Ok(())
}
