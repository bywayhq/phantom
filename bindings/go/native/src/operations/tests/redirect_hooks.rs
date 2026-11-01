use super::*;

#[test]
fn cancelled_redirect_retains_host_custody_and_rejects_another_reply_kind() -> Result<(), Failure> {
    let global = test_global()?;
    let config = serde_json::from_value(json!({
        "profile": "chrome-154-windows", "protocol": "h1", "cookies": false,
    }))
    .map_err(|_| Failure::new("test_config"))?;
    let entry = NativeClient::new(config)?;
    let native = entry.client.clone();
    global.lock().clients.insert(1, entry);
    let (operation, ticket, mut reply) = {
        let mut state = global.lock();
        let (operation, _cancel) = state.reserve(Target::Request(1))?;
        let ticket = state.id()?;
        let (sender, reply) = oneshot::channel();
        state
            .operations
            .get_mut(&operation)
            .ok_or_else(|| Failure::new("test_operation"))?
            .callback_call = Some(CallbackCall {
            ticket,
            invocation: CallbackInvocation::Redirect(std::sync::Arc::new(
                crate::redirect_hook::Invocation {
                    from: "http://127.0.0.1/start".into(),
                    to: "http://127.0.0.1/end".into(),
                    method: "POST".into(),
                    next_method: "GET".into(),
                    status: 303,
                    hop: 1,
                },
            )),
            reply: Some(sender),
            host_owned: false,
        });
        state.ready.push_back(Queued {
            operation,
            completion: Completion {
                operation,
                result: Ok(Completed::RedirectHook(ticket)),
                data: Bytes::new(),
            },
        });
        (operation, ticket, reply)
    };
    let progress = global.wait()?;
    assert!(matches!(progress.result, Ok(Completed::RedirectHook(value)) if value==ticket));
    assert!(!global.lock().operations[&operation].delivered);
    assert!(
        global
            .reply_header_hook(operation, ticket, 0, Vec::new())
            .is_err()
    );
    assert!(matches!(
        reply.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(
        global
            .reply_callback(
                operation,
                ticket + 1,
                0,
                CallbackReply::Redirect(phantom::RedirectDecision::Follow)
            )
            .is_err()
    );
    global.cancel_header_request(operation)?;
    assert!(!global.lock().operations[&operation].abandoned);
    global.finish(operation, Err(Failure::new("timeout")));
    let terminal = global.wait()?;
    assert!(matches!(
        terminal.result,
        Err(Failure {
            kind: "timeout",
            ..
        })
    ));
    global.runtime.block_on(async {
        let mut shutdown = Box::pin(global.shutdown(1, native.clone()));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(shutdown.as_mut().poll(&mut context).is_pending());
        global.reply_callback(
            operation,
            ticket,
            2,
            CallbackReply::Redirect(phantom::RedirectDecision::Reject),
        )?;
        assert!(
            global
                .reply_callback(
                    operation,
                    ticket,
                    2,
                    CallbackReply::Redirect(phantom::RedirectDecision::Reject)
                )
                .is_err()
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), shutdown)
            .await
            .map_err(|_| Failure::new("test_shutdown_stalled"))??;
        assert!(native.is_closed());
        Ok(())
    })
}
