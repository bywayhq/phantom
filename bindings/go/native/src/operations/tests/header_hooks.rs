use super::*;

type HookReply = oneshot::Receiver<Result<CallbackReply, header_hook::HostFailure>>;

fn pending_hook(global: &Global, owner: u64) -> Result<(u64, u64, HookReply), Failure> {
    let mut state = global.lock();
    let (operation, _cancel) = state.reserve(Target::Request(owner))?;
    let ticket = state.id()?;
    let (sender, receiver) = oneshot::channel();
    state
        .operations
        .get_mut(&operation)
        .ok_or_else(|| Failure::new("test_operation"))?
        .callback_call = Some(CallbackCall {
        ticket,
        invocation: CallbackInvocation::Header(std::sync::Arc::new(header_hook::Invocation {
            index: 0,
            method: "GET".to_owned(),
            uri: "http://127.0.0.1/".to_owned(),
            headers: Vec::new(),
        })),
        reply: Some(sender),
        host_owned: false,
    });
    state.ready.push_back(Queued {
        operation,
        completion: Completion {
            operation,
            result: Ok(Completed::HeaderHook(ticket)),
            data: Bytes::new(),
        },
    });
    Ok((operation, ticket, receiver))
}

#[test]
fn progress_keeps_terminal_failure_delivery_after_registry_poison() -> Result<(), Failure> {
    let global = test_global()?;
    let (operation, ticket, _reply) = pending_hook(global, 1)?;
    let progress = global.wait()?;
    assert!(matches!(progress.result, Ok(Completed::HeaderHook(value)) if value == ticket));
    assert!(!global.lock().operations[&operation].delivered);

    let _panic = std::panic::catch_unwind(|| {
        let _state = global
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        panic!("test registry poison");
    });
    // Recovery must enqueue a terminal failure even though progress was delivered.
    drop(global.lock());
    let terminal = global.wait()?;
    assert_eq!(terminal.operation, operation);
    assert!(matches!(
        terminal.result,
        Err(Failure {
            kind: "internal",
            ..
        })
    ));
    assert!(
        global.lock().operations[&operation]
            .callback_call
            .as_ref()
            .is_some_and(|call| call.host_owned)
    );
    global.reply_header_hook(operation, ticket, 2, Vec::new())?;
    Ok(())
}

#[test]
fn registry_failure_before_delivery_does_not_leave_unseen_host_custody() -> Result<(), Failure> {
    let mut closed_sources = Vec::new();
    let global = test_global()?;
    let (operation, _ticket, _reply) = pending_hook(global, 1)?;
    let _panic = std::panic::catch_unwind(|| {
        let _state = global
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        panic!("test registry poison before delivery");
    });
    drop(global.lock());
    let terminal = global.wait()?;
    assert_eq!(terminal.operation, operation);
    assert!(matches!(
        terminal.result,
        Err(Failure {
            kind: "internal",
            ..
        })
    ));
    assert!(global.lock().operations[&operation].callback_call.is_none());
    global.lock().cancel(operation, &mut closed_sources);
    assert!(!global.lock().operations.contains_key(&operation));
    Ok(())
}

#[test]
fn replies_are_single_use_and_cannot_release_another_request() -> Result<(), Failure> {
    let global = test_global()?;
    let (first, first_ticket, mut first_reply) = pending_hook(global, 1)?;
    let (second, second_ticket, mut second_reply) = pending_hook(global, 1)?;
    global.wait()?;
    global.wait()?;
    assert_eq!(
        global
            .reply_header_hook(first, second_ticket, 0, Vec::new())
            .err()
            .map(|error| error.kind),
        Some("header_hook_closed")
    );
    assert!(matches!(
        first_reply.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        second_reply.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    global.reply_header_hook(first, first_ticket, 0, Vec::new())?;
    assert!(
        matches!(first_reply.try_recv(), Ok(Ok(CallbackReply::Header(edits))) if edits.is_empty())
    );
    assert_eq!(
        global
            .reply_header_hook(first, first_ticket, 0, Vec::new())
            .err()
            .map(|error| error.kind),
        Some("header_hook_closed")
    );

    // Expiry drops the Rust receiver, while the host still owes handback.
    if let Some(call) = global
        .lock()
        .operations
        .get_mut(&second)
        .and_then(|op| op.callback_call.as_mut())
    {
        call.reply.take();
    }
    global.finish(second, Err(Failure::new("timeout")));
    assert_eq!(
        global
            .reply_header_hook(second, second_ticket, 0, Vec::new())
            .err()
            .map(|error| error.kind),
        Some("header_hook_closed")
    );
    assert!(
        !global.lock().operations[&second]
            .callback_call
            .as_ref()
            .is_some_and(|call| call.host_owned)
    );
    Ok(())
}

#[test]
fn abandoned_callback_retains_admission_until_actual_host_handback() -> Result<(), Failure> {
    let mut closed_sources = Vec::new();
    let global = test_global()?;
    let (operation, ticket, _reply) = pending_hook(global, 1)?;
    global.wait()?;
    for _ in 1..MAX_HANDLES {
        global.lock().reserve(Target::Request(2))?;
    }
    global.lock().cancel(operation, &mut closed_sources);
    global.finish(operation, Err(Failure::new("cancelled")));
    assert_eq!(
        global
            .lock()
            .reserve(Target::Request(2))
            .err()
            .map(|error| error.kind),
        Some("capacity")
    );
    global.reply_header_hook(operation, ticket, 2, Vec::new())?;
    assert!(!global.lock().operations.contains_key(&operation));
    assert!(global.lock().reserve(Target::Request(2)).is_ok());
    Ok(())
}

#[test]
fn shutdown_waits_for_cancelled_host_callback_after_native_send_finishes() -> Result<(), Failure> {
    let global = test_global()?;
    let config = serde_json::from_value(json!({
        "profile": "chrome-154-windows", "protocol": "h1", "cookies": false,
    }))
    .map_err(|_| Failure::new("test_config"))?;
    let entry = NativeClient::new(config)?;
    let native = entry.client.clone();
    global.lock().clients.insert(1, entry);
    let (operation, ticket, _reply) = pending_hook(global, 1)?;
    global.wait()?;
    global.cancel_header_request(operation)?;
    assert!(!global.lock().operations[&operation].abandoned);
    global.finish(operation, Err(Failure::new("cancelled")));

    global.runtime.block_on(async {
        let mut shutdown = Box::pin(global.shutdown(1, native.clone()));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(shutdown.as_mut().poll(&mut context).is_pending());
        assert!(!native.is_closed());
        global.reply_header_hook(operation, ticket, 2, Vec::new())?;
        tokio::time::timeout(std::time::Duration::from_secs(5), shutdown)
            .await
            .map_err(|_| Failure::new("test_shutdown_stalled"))??;
        assert!(native.is_closed());
        Ok(())
    })
}
