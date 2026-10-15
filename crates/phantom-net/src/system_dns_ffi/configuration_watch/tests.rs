//! Synthetic controls only: no registry, interface, route, or kernel event calls.
use super::*;
use std::future::Future;
use std::sync::atomic::AtomicUsize;
use std::task::{Context, Poll, Wake, Waker};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn missing_policy_watches_nearest_existing_ancestor_and_keeps_full_subtree_filter() -> TestResult {
    let mut attempted = Vec::new();
    let existing = nearest_existing(r"SOFTWARE\Policies\Microsoft\System\DNSClient", |path| {
        attempted.push(path.to_owned());
        Ok((path == r"SOFTWARE\Policies\Microsoft").then_some(path.to_owned()))
    })?;
    assert_eq!(existing, r"SOFTWARE\Policies\Microsoft");
    assert_eq!(
        attempted,
        [
            r"SOFTWARE\Policies\Microsoft\System\DNSClient",
            r"SOFTWARE\Policies\Microsoft\System",
            r"SOFTWARE\Policies\Microsoft",
        ]
    );
    assert_eq!(FILTER, 0x1000_000f);
    Ok(())
}

#[test]
fn missing_ancestors_are_bounded_at_hklm_and_access_errors_never_fall_back() -> TestResult {
    let mut attempts = 0;
    let result = nearest_existing::<()>(r"a\b", |_| {
        attempts += 1;
        Ok(None)
    });
    assert_eq!(attempts, 3);
    assert!(matches!(
        result,
        Err(WatchError {
            cause: WatchCause::Native {
                code: ERROR_PATH_NOT_FOUND,
                ..
            },
            ..
        })
    ));
    let denied = WatchError::native("RegOpenKeyExW", 5);
    let mut attempts = 0;
    assert_eq!(
        nearest_existing::<()>(r"a\b", |_| {
            attempts += 1;
            Err(denied)
        }),
        Err(denied)
    );
    assert_eq!(attempts, 1);
    Ok(())
}

#[test]
fn one_arm_exists_until_consumed_and_each_event_allows_exactly_one_rearm() -> TestResult {
    let mut arm = Arm::default();
    let mut calls = 0;
    arm.register(|| {
        calls += 1;
        Ok(())
    })?;
    assert!(
        arm.register(|| {
            calls += 1;
            Ok(())
        })
        .is_err()
    );
    assert_eq!(calls, 1);
    arm.consume()?;
    assert!(arm.consume().is_err());
    arm.register(|| {
        calls += 1;
        Ok(())
    })?;
    assert_eq!(calls, 2);
    assert!(arm.outstanding);
    Ok(())
}

#[test]
fn failed_registration_never_creates_a_phantom_outstanding_arm() -> TestResult {
    let mut arm = Arm::default();
    let failed = WatchError::native("RegNotifyChangeKeyValue", 5);
    assert_eq!(arm.register(|| Err(failed)), Err(failed));
    assert!(!arm.outstanding);
    assert!(arm.consume().is_err());
    arm.register(|| Ok(()))?;
    assert!(arm.outstanding);
    Ok(())
}

#[test]
fn failed_rearm_keeps_the_owner_ineligible_instead_of_claiming_it_is_armed() -> TestResult {
    let mut arm = Arm::default();
    arm.register(|| Ok(()))?;
    arm.consume()?;
    assert!(
        arm.register(|| Err(WatchError::native(
            "RegNotifyChangeKeyValue",
            ERROR_KEY_DELETED
        )))
        .is_err()
    );
    assert!(!arm.outstanding);
    Ok(())
}

#[test]
fn interface_and_route_callbacks_only_mark_the_same_generation_without_owner_lock() -> TestResult {
    let dirty = Arc::new(Dirty::new());
    let initial = dirty.observed()?;
    let terminal = dirty
        .terminal
        .lock()
        .map_err(|_| "poisoned test terminal")?;
    let context = Arc::as_ptr(&dirty).cast::<c_void>();
    // SAFETY: test Arc supplies stable live context. Null rows are deliberately
    // never read, freed, or retained, even while the owner terminal lock is held.
    unsafe {
        interface_changed(context, ptr::null(), 0);
        route_changed(context, ptr::null(), 0);
    }
    drop(terminal);
    assert_eq!(dirty.observed()?.sequence, initial.sequence + 2);
    Ok(())
}

#[test]
fn change_before_wait_is_observed_without_a_notification_permit() -> TestResult {
    let dirty = Dirty::new();
    let before = dirty.observed()?;
    dirty.mark();
    let wake = Arc::new(WakeCount::default());
    let waker = Waker::from(wake);
    let mut context = Context::from_waker(&waker);
    let mut changed = Box::pin(dirty.changed_since(before));
    assert_eq!(
        changed.as_mut().poll(&mut context),
        Poll::Ready(Ok(dirty.observed()?))
    );
    Ok(())
}

#[test]
fn installed_waiter_wakes_for_change_and_repeated_waits_do_not_lose_edges() -> TestResult {
    let dirty = Dirty::new();
    let wake = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&wake));
    let mut context = Context::from_waker(&waker);
    for _ in 0..3 {
        let previous = dirty.observed()?;
        let mut changed = Box::pin(dirty.changed_since(previous));
        assert!(changed.as_mut().poll(&mut context).is_pending());
        let before = wake.0.load(Ordering::Relaxed);
        dirty.mark();
        assert!(wake.0.load(Ordering::Relaxed) > before);
        assert_eq!(
            changed.as_mut().poll(&mut context),
            Poll::Ready(Ok(dirty.observed()?))
        );
    }
    Ok(())
}

#[test]
fn terminal_worker_failure_wakes_waiters_and_overrides_pending_dirty_generation() -> TestResult {
    let dirty = Dirty::new();
    let previous = dirty.observed()?;
    let wake = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&wake));
    let mut context = Context::from_waker(&waker);
    let mut changed = Box::pin(dirty.changed_since(previous));
    assert!(changed.as_mut().poll(&mut context).is_pending());
    dirty.mark();
    let error = WatchError::native("RegNotifyChangeKeyValue", 5);
    assert_eq!(dirty.finish(Err(error)), Err(error));
    assert_eq!(changed.as_mut().poll(&mut context), Poll::Ready(Err(error)));
    assert!(wake.0.load(Ordering::Relaxed) > 0);
    assert_eq!(dirty.observed(), Err(error));
    Ok(())
}

#[test]
fn orderly_shutdown_wakes_waiters_and_does_not_offer_a_new_valid_snapshot() -> TestResult {
    let dirty = Dirty::new();
    let previous = dirty.observed()?;
    let waker = Waker::from(Arc::new(WakeCount::default()));
    let mut context = Context::from_waker(&waker);
    let mut changed = Box::pin(dirty.changed_since(previous));
    assert!(changed.as_mut().poll(&mut context).is_pending());
    dirty.finish(Ok(()))?;
    assert!(matches!(
        changed.as_mut().poll(&mut context),
        Poll::Ready(Err(WatchError {
            cause: WatchCause::Stopped,
            ..
        }))
    ));
    Ok(())
}

#[test]
fn exhausted_generation_retires_without_wrapping_or_revalidating_old_tokens() -> TestResult {
    let dirty = Dirty::new();
    dirty.generation.store(u64::MAX, Ordering::Release);
    dirty.mark();
    assert_eq!(dirty.generation.load(Ordering::Acquire), u64::MAX);
    assert!(matches!(
        dirty.observed(),
        Err(WatchError {
            cause: WatchCause::GenerationExhausted,
            ..
        })
    ));
    dirty.mark();
    assert_eq!(dirty.generation.load(Ordering::Acquire), u64::MAX);
    Ok(())
}

fn cancel_with_last_callback(handle: HANDLE) -> u32 {
    // SAFETY: synthetic handle points to the stable test Dirty; no OS call.
    unsafe {
        (&*handle.cast::<Dirty>()).mark();
    }
    0
}

#[test]
fn callback_context_lives_through_successful_cancel_and_cancellation_is_idempotent() -> TestResult {
    let dirty = Arc::new(Dirty::new());
    let before = dirty.observed()?;
    let mut notification = Notification {
        handle: Arc::as_ptr(&dirty).cast_mut().cast(),
        context: Some(Arc::clone(&dirty)),
        slot: 0,
        cancel: cancel_with_last_callback,
    };
    assert_eq!(Arc::strong_count(&dirty), 2);
    notification.cancel();
    assert_eq!(dirty.observed()?.sequence, before.sequence + 1);
    assert_eq!(Arc::strong_count(&dirty), 1);
    notification.cancel();
    assert_eq!(dirty.observed()?.sequence, before.sequence + 1);
    Ok(())
}

fn fail_cancel(_handle: HANDLE) -> u32 {
    5
}

#[test]
fn cancellation_failure_retains_stable_state_and_reports_cleanup_with_original_error() -> TestResult
{
    let dirty = Arc::new(Dirty::new());
    let pointer = Arc::as_ptr(&dirty);
    let mut notification = Notification {
        handle: ptr::null_mut(),
        context: Some(Arc::clone(&dirty)),
        slot: 1,
        cancel: fail_cancel,
    };
    notification.cancel();
    assert_eq!(Arc::strong_count(&dirty), 2);
    // SAFETY: synthetic failed cancellation retained the Arc and never registered
    // with Windows. Simulate a final callback, then reclaim that test-only lease.
    unsafe {
        interface_changed(pointer.cast(), ptr::null(), 0);
    }
    let primary = WatchError::native("WaitForMultipleObjects", 6);
    let expected = WatchError {
        cause: primary.cause,
        cancellation_codes: [0, 5],
        worker_cause: None,
    };
    assert_eq!(dirty.finish(Err(primary)), Err(expected));
    assert_eq!(dirty.observed(), Err(expected));
    // SAFETY: one exact Arc::into_raw reference was quarantined by cancel();
    // no native registration exists in this synthetic control.
    drop(unsafe { Arc::from_raw(pointer) });
    assert_eq!(Arc::strong_count(&dirty), 1);
    Ok(())
}

#[test]
fn both_cancellation_errors_remain_reported_when_the_wait_itself_succeeded() -> TestResult {
    let dirty = Dirty::new();
    dirty.cancellation_codes[0].store(5, Ordering::Release);
    dirty.cancellation_codes[1].store(8, Ordering::Release);
    assert_eq!(
        dirty.finish(Ok(())),
        Err(WatchError {
            cause: WatchCause::Native {
                operation: "CancelMibChangeNotify2",
                code: 5
            },
            cancellation_codes: [5, 8],
            worker_cause: None,
        })
    );
    Ok(())
}

#[test]
fn debug_never_exposes_registry_paths_handles_or_generation_values() -> TestResult {
    let debug = format!(
        "{:?}",
        ConfigurationGeneration {
            owner: Arc::new(()),
            sequence: 42
        }
    );
    assert_eq!(debug, "ConfigurationGeneration(..)");
    assert!(!debug.contains("42"));
    assert_eq!(PATHS.len(), 9);
    assert!(PATHS.contains(&r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"));
    assert!(PATHS.contains(&r"SOFTWARE\Policies\Microsoft\System\DNSClient"));
    Ok(())
}

#[test]
fn tokens_from_another_owner_cannot_validate_a_new_owner_with_the_same_counter() -> TestResult {
    let first = Dirty::new();
    let second = Dirty::new();
    let previous = first.observed()?;
    assert_ne!(previous, second.observed()?);
    let waker = Waker::from(Arc::new(WakeCount::default()));
    let mut context = Context::from_waker(&waker);
    let mut changed = Box::pin(second.changed_since(previous));
    assert!(matches!(
        changed.as_mut().poll(&mut context),
        Poll::Ready(Err(WatchError {
            cause: WatchCause::ForeignGeneration,
            ..
        }))
    ));
    Ok(())
}

#[test]
fn shutdown_preserves_signal_worker_and_both_cancel_failures_together() -> TestResult {
    let signal = WatchError::native("SetEvent", 6);
    let mut worker = WatchError::native("WaitForMultipleObjects", 8);
    worker.cancellation_codes = [5, 87];
    let expected = WatchError {
        cause: signal.cause,
        cancellation_codes: [5, 87],
        worker_cause: Some(worker.cause),
    };
    assert_eq!(shutdown_result(Err(signal), Err(worker)), Err(expected));
    assert_eq!(shutdown_result(Ok(()), Err(worker)), Err(worker));
    assert_eq!(shutdown_result(Err(signal), Ok(())), Err(signal));
    assert_eq!(shutdown_result(Ok(()), Ok(())), Ok(()));
    Ok(())
}

struct CancelGate {
    entered: mpsc::SyncSender<()>,
    resume: Mutex<mpsc::Receiver<()>>,
}

fn blocked_successful_cancel(handle: HANDLE) -> u32 {
    // SAFETY: synthetic handle points to an Arc-owned gate retained by the
    // test and worker through its join. No native API or row is accessed.
    let gate = unsafe { &*handle.cast::<CancelGate>() };
    if gate.entered.send(()).is_err() {
        return 87;
    }
    match gate.resume.lock() {
        Ok(resume) => match resume.recv() {
            Ok(()) => 0,
            Err(_) => 87,
        },
        Err(_) => 6,
    }
}

fn panic_text(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(text) = payload.downcast_ref::<String>() {
        return text.clone();
    }
    if let Some(text) = payload.downcast_ref::<&str>() {
        return (*text).to_owned();
    }
    "non-string panic payload".to_owned()
}

fn terminal_before_blocked_cancel(unwind: bool) -> TestResult {
    let dirty = Arc::new(Dirty::new());
    let previous = dirty.observed()?;
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = mpsc::sync_channel(1);
    let gate = Arc::new(CancelGate {
        entered: entered_tx,
        resume: Mutex::new(resume_rx),
    });
    let expected = if unwind {
        WatchError::cause(WatchCause::WorkerPanicked)
    } else {
        WatchError::native("RegNotifyChangeKeyValue", 5)
    };
    let thread_dirty = Arc::clone(&dirty);
    let thread_gate = Arc::clone(&gate);
    let worker = thread::spawn(move || {
        // Lease is owned outside the caught operation, just like run().
        let mut notification = Notification {
            handle: Arc::as_ptr(&thread_gate).cast_mut().cast(),
            context: Some(Arc::clone(&thread_dirty)),
            slot: 0,
            cancel: blocked_successful_cancel,
        };
        finish_watch(
            &thread_dirty,
            || {
                if unwind {
                    panic!("synthetic watch body panic");
                }
                Err(expected)
            },
            || notification.cancel(),
        )
    });
    // Always release and join the worker, including assertion/error paths.
    let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> TestResult {
        entered_rx.recv()?;
        assert_eq!(dirty.observed(), Err(expected));
        let waker = Waker::from(Arc::new(WakeCount::default()));
        let mut context = Context::from_waker(&waker);
        let mut changed = Box::pin(dirty.changed_since(previous));
        assert_eq!(
            changed.as_mut().poll(&mut context),
            Poll::Ready(Err(expected))
        );
        // Both the worker owner and its still-blocked registration retain state.
        assert_eq!(Arc::strong_count(&dirty), 3);
        Ok(())
    }));
    let release = resume_tx.send(());
    let joined = worker.join();
    let mut failures = Vec::new();
    match body {
        Ok(Ok(())) => {}
        Ok(Err(error)) => failures.push(error.to_string()),
        Err(payload) => failures.push(panic_text(payload)),
    }
    if let Err(error) = release {
        failures.push(format!("cancel release: {error}"));
    }
    match joined {
        Ok(result) if result == Err(expected) => {}
        Ok(result) => failures.push(format!("worker result: {result:?}")),
        Err(payload) => failures.push(format!("worker panic: {}", panic_text(payload))),
    }
    if Arc::strong_count(&dirty) != 1 {
        failures.push("callback state retained after successful cancel".into());
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; ").into())
    }
}

#[test]
fn normal_watch_failure_is_terminal_while_cancellation_is_still_blocked() -> TestResult {
    terminal_before_blocked_cancel(false)
}

#[test]
fn caught_watch_unwind_is_terminal_while_cancellation_is_still_blocked() -> TestResult {
    terminal_before_blocked_cancel(true)
}

#[test]
fn final_cleanup_enriches_the_already_published_failure_with_cancel_status() -> TestResult {
    let dirty = Arc::new(Dirty::new());
    let pointer = Arc::as_ptr(&dirty);
    let primary = WatchError::native("WaitForMultipleObjects", 6);
    let mut notification = Notification {
        handle: ptr::null_mut(),
        context: Some(Arc::clone(&dirty)),
        slot: 1,
        cancel: fail_cancel,
    };
    let mut during_cleanup = None;
    let result = finish_watch(
        &dirty,
        || Err(primary),
        || {
            during_cleanup = Some(dirty.observed());
            notification.cancel();
        },
    );
    // SAFETY: fail_cancel is synthetic, with no native registration; reclaim
    // exactly the Arc::into_raw reference retained by this failed cancellation.
    drop(unsafe { Arc::from_raw(pointer) });
    let expected = WatchError {
        cause: primary.cause,
        cancellation_codes: [0, 5],
        worker_cause: None,
    };
    assert_eq!(during_cleanup, Some(Err(primary)));
    assert_eq!(result, Err(expected));
    assert_eq!(dirty.observed(), Err(expected));
    Ok(())
}

#[test]
fn concurrent_marks_keep_every_increment_without_losing_generation_updates() -> TestResult {
    let dirty = Arc::new(Dirty::new());
    let start = Arc::new(AtomicBool::new(false));
    let mut workers = Vec::new();
    let mut failures = Vec::new();
    for _ in 0..4 {
        let worker_dirty = Arc::clone(&dirty);
        let worker_start = Arc::clone(&start);
        match thread::Builder::new().spawn(move || {
            while !worker_start.load(Ordering::Acquire) {
                thread::yield_now();
            }
            for _ in 0..256 {
                worker_dirty.mark();
            }
        }) {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                failures.push(format!("worker start: {error}"));
                break;
            }
        }
    }
    // Even partial setup releases and joins every successfully started worker.
    start.store(true, Ordering::Release);
    for worker in workers {
        if let Err(payload) = worker.join() {
            failures.push(format!("worker panic: {}", panic_text(payload)));
        }
    }
    if !failures.is_empty() {
        return Err(failures.join("; ").into());
    }
    assert_eq!(dirty.observed()?.sequence, 1 + 4 * 256);
    assert!(!dirty.exhausted.load(Ordering::Acquire));
    Ok(())
}
