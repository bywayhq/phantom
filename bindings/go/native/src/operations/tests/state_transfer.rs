use super::*;

#[test]
fn cancelled_state_work_keeps_shutdown_pending_until_actual_exit() -> Result<(), Failure> {
    let mut closed_sources = Vec::new();
    let global = test_global()?;
    let config = serde_json::from_value(json!({
        "profile": "chrome-154-windows", "protocol": "h1", "cookies": true,
    }))
    .map_err(|_| Failure::new("test_config"))?;
    let entry = NativeClient::new(config)?;
    let native = entry.client.clone();
    global.lock().clients.insert(1, entry);
    let (operation, _cancel) = global.lock().reserve(Target::StateTransfer(1))?;
    global.lock().cancel(operation, &mut closed_sources);
    assert!(global.lock().operations.contains_key(&operation));
    global.runtime.block_on(async {
        let mut shutdown = Box::pin(global.shutdown(1, native.clone()));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(shutdown.as_mut().poll(&mut context).is_pending());
        assert!(!native.is_closed());
        let result =
            crate::state_transfer::execute(&native, crate::state_transfer::Input::ExportCookies);
        global.finish(operation, Ok(Outcome::StateTransfer(result)));
        tokio::time::timeout(std::time::Duration::from_secs(5), shutdown)
            .await
            .map_err(|_| Failure::new("test_shutdown_stalled"))??;
        assert!(native.is_closed());
        assert!(!global.lock().operations.contains_key(&operation));
        assert!(global.lock().ready.is_empty());
        Ok(())
    })
}
