use super::*;

#[test]
fn logical_progress_is_not_terminal_and_reply_kind_is_checked() -> Result<(), Failure> {
    let global = test_global()?;
    let (operation, ticket, mut receiver) = {
        let mut state = global.lock();
        let (operation, _cancel) = state.reserve(Target::Request(1))?;
        let ticket = state.id()?;
        let (sender, receiver) = oneshot::channel();
        state
            .operations
            .get_mut(&operation)
            .ok_or_else(|| Failure::new("test_operation"))?
            .callback_call = Some(CallbackCall {
            ticket,
            invocation: CallbackInvocation::Logical(std::sync::Arc::new(
                super::super::logical_hooks::Invocation {
                    phase: 1,
                    cause_operation: 0,
                    method: "GET".into(),
                    uri: "http://127.0.0.1/".into(),
                    response: None,
                    error: None,
                },
            )),
            reply: Some(sender),
            host_owned: false,
        });
        state.ready.push_back(Queued {
            operation,
            completion: Completion {
                operation,
                result: Ok(Completed::LogicalHook(ticket)),
                data: Bytes::new(),
            },
        });
        (operation, ticket, receiver)
    };
    assert!(matches!(global.wait()?.result,Ok(Completed::LogicalHook(value)) if value==ticket));
    assert!(!global.lock().operations[&operation].delivered);
    assert!(
        global
            .reply_header_hook(operation, ticket, 0, Vec::new())
            .is_err()
    );
    assert!(matches!(
        receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    global.reply_callback(operation, ticket, 1, CallbackReply::Logical)?;
    assert!(matches!(receiver.try_recv(), Ok(Err(_))));
    assert!(!global.lock().operations[&operation].finished);
    assert!(
        global
            .reply_callback(operation, ticket, 0, CallbackReply::Logical)
            .is_err()
    );
    // A delivered failure leaves the request able to register its error phase.
    let next_ticket = {
        let mut state = global.lock();
        let next = state.id()?;
        let (sender, _) = oneshot::channel();
        state
            .operations
            .get_mut(&operation)
            .ok_or_else(|| Failure::new("test_operation"))?
            .callback_call = Some(CallbackCall {
            ticket: next,
            invocation: CallbackInvocation::Logical(std::sync::Arc::new(
                super::super::logical_hooks::Invocation {
                    phase: 4,
                    cause_operation: 0,
                    method: "GET".into(),
                    uri: "http://127.0.0.1/".into(),
                    response: None,
                    error: Some(Failure::new("request_hook")),
                },
            )),
            reply: Some(sender),
            host_owned: true,
        });
        next
    };
    global.reply_callback(operation, next_ticket, 0, CallbackReply::Logical)?;
    Ok(())
}

#[test]
fn cancelled_logical_callback_retains_actual_host_custody() -> Result<(), Failure> {
    let global = test_global()?;
    let config = serde_json::from_value(
        json!({"profile":"chrome-154-windows","protocol":"h1","cookies":false}),
    )
    .map_err(|_| Failure::new("test_config"))?;
    let entry = NativeClient::new(config)?;
    let native = entry.client.clone();
    global.lock().clients.insert(1, entry);
    let (operation, ticket) = {
        let mut state = global.lock();
        let (operation, _) = state.reserve(Target::Request(1))?;
        let ticket = state.id()?;
        let (sender, _) = oneshot::channel();
        state
            .operations
            .get_mut(&operation)
            .ok_or_else(|| Failure::new("test_operation"))?
            .callback_call = Some(CallbackCall {
            ticket,
            invocation: CallbackInvocation::Logical(std::sync::Arc::new(
                super::super::logical_hooks::Invocation {
                    phase: 2,
                    cause_operation: 0,
                    method: "GET".into(),
                    uri: "http://127.0.0.1/".into(),
                    response: None,
                    error: None,
                },
            )),
            reply: Some(sender),
            host_owned: true,
        });
        (operation, ticket)
    };
    global.cancel_header_request(operation)?;
    global.finish(operation, Err(Failure::new("timeout")));
    assert!(matches!(
        global.wait()?.result,
        Err(Failure {
            kind: "timeout",
            ..
        })
    ));
    global.runtime.block_on(async {
        let mut shutdown = Box::pin(global.shutdown(1, native.clone()));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(shutdown.as_mut().poll(&mut context).is_pending());
        global.reply_callback(operation, ticket, 2, CallbackReply::Logical)?;
        tokio::time::timeout(std::time::Duration::from_secs(5), shutdown)
            .await
            .map_err(|_| Failure::new("test_shutdown_stalled"))??;
        Ok(())
    })
}
