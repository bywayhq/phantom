//! One owned native notification thread. Start/check/shutdown are blocking.
//! Observer clones contain only invalidation state, never a native owner.
//! Hosts path/content and DNS/hostname notifications share this generation.
//! Checks sample actual hostname bytes; direct kernel hostname changes also
//! have a one-second idle sampling backup. Blocking native work may delay it;
//! neither synchronous OS delivery nor finite shutdown latency is promised.

use super::{
    OK, UNAVAILABLE, phantom_macos_dns_watch_check, phantom_macos_dns_watch_close,
    phantom_macos_dns_watch_start, phantom_macos_dns_watch_wait,
};
use std::{
    ffi::{CStr, CString, c_void},
    fmt,
    io::Write,
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    path::Path,
    ptr::{self, NonNull},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
};
use tokio::sync::Notify;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WatchCause {
    Native {
        operation: &'static str,
        status: u32,
        code: u32,
    },
    WitnessUnavailable,
    ThreadStart,
    ControlIo,
    InvalidControl,
    InvalidHostsPath,
    WorkerPanicked,
    StatePoisoned,
    GenerationExhausted,
    #[cfg(test)]
    ForeignGeneration,
    Stopped,
}

/// Fixed operation names/status codes only. A cancellation error may retain
/// at most this owner's two native registrations/descriptors until process exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WatchError {
    pub(crate) cause: WatchCause,
    pub(crate) cancellation: Option<(u32, u32)>,
}
impl WatchError {
    pub(super) fn cause(cause: WatchCause) -> Self {
        Self {
            cause,
            cancellation: None,
        }
    }

    fn native(operation: &'static str, status: u32, code: u32) -> Self {
        Self::cause(WatchCause::Native {
            operation,
            status,
            code,
        })
    }
}
impl fmt::Display for WatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "macOS DNS watch failed: {:?}", self.cause)
    }
}
impl std::error::Error for WatchError {}

#[derive(Clone)]
pub(crate) struct ConfigurationGeneration {
    owner: Arc<()>,
    sequence: u64,
}
impl PartialEq for ConfigurationGeneration {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.owner, &other.owner) && self.sequence == other.sequence
    }
}
impl Eq for ConfigurationGeneration {}
impl fmt::Debug for ConfigurationGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfigurationGeneration(..)")
    }
}

pub(super) struct Dirty {
    owner: Arc<()>,
    sequence: AtomicU64,
    exhausted: AtomicBool,
    terminal: Mutex<Option<Result<(), WatchError>>>,
    notify: Notify,
}
impl Dirty {
    pub(super) fn new() -> Self {
        Self {
            owner: Arc::new(()),
            sequence: AtomicU64::new(1),
            exhausted: AtomicBool::new(false),
            terminal: Mutex::new(None),
            notify: Notify::new(),
        }
    }

    pub(super) fn mark(&self) {
        let mut current = self.sequence.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(1) else {
                self.exhausted.store(true, Ordering::Release);
                break;
            };
            match self.sequence.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        self.notify.notify_waiters();
    }

    fn active(&self) -> Result<(), WatchError> {
        match *self
            .terminal
            .lock()
            .map_err(|_| WatchError::cause(WatchCause::StatePoisoned))?
        {
            Some(Ok(())) => Err(WatchError::cause(WatchCause::Stopped)),
            Some(Err(error)) => Err(error),
            None => Ok(()),
        }
    }

    pub(super) fn observed(&self) -> Result<ConfigurationGeneration, WatchError> {
        self.active()?;
        let sequence = self.sequence.load(Ordering::Acquire);
        if self.exhausted.load(Ordering::Acquire) {
            return Err(WatchError::cause(WatchCause::GenerationExhausted));
        }
        self.active()?;
        Ok(ConfigurationGeneration {
            owner: Arc::clone(&self.owner),
            sequence,
        })
    }

    pub(super) fn finish(&self, result: Result<(), WatchError>) -> Result<(), WatchError> {
        let result = match self.terminal.lock() {
            Ok(mut terminal) => {
                let result = match (*terminal, result) {
                    (Some(Err(mut previous)), Err(next)) => {
                        previous.cancellation = next.cancellation.or(previous.cancellation);
                        Err(previous)
                    }
                    (Some(Err(previous)), Ok(())) => Err(previous),
                    (_, result) => result,
                };
                *terminal = Some(result);
                result
            }
            Err(_) => Err(WatchError::cause(WatchCause::StatePoisoned)),
        };
        self.notify.notify_waiters();
        result
    }
}

/// Invalidation state only: does not keep the worker/registration alive.
#[derive(Clone)]
pub(crate) struct ConfigurationObserver {
    dirty: Arc<Dirty>,
}
impl fmt::Debug for ConfigurationObserver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfigurationObserver(..)")
    }
}
impl ConfigurationObserver {
    pub(crate) fn observed(&self) -> Result<ConfigurationGeneration, WatchError> {
        self.dirty.observed()
    }

    /// Waits for observed invalidation, not synchronous OS-wide linearization.
    #[cfg(test)]
    pub(crate) async fn changed_since(
        &self,
        previous: &ConfigurationGeneration,
    ) -> Result<ConfigurationGeneration, WatchError> {
        if !Arc::ptr_eq(&self.dirty.owner, &previous.owner) {
            return Err(WatchError::cause(WatchCause::ForeignGeneration));
        }
        loop {
            let notified = self.dirty.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let current = self.observed()?;
            if current != *previous {
                return Ok(current);
            }
            notified.await;
        }
    }
}

type Reply = mpsc::SyncSender<Result<ConfigurationGeneration, WatchError>>;

/// One joined thread. Ordinary Drop synchronously joins, so final owners must
/// be released outside async executors/cache locks; no bounded OS-cancel claim.
pub(crate) struct ConfigurationWatch {
    dirty: Arc<Dirty>,
    control: Mutex<Option<UnixStream>>,
    requests: mpsc::SyncSender<Reply>,
    worker: Option<JoinHandle<Result<(), WatchError>>>,
}
impl fmt::Debug for ConfigurationWatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigurationWatch")
            .field("running", &self.worker.is_some())
            .finish()
    }
}
impl ConfigurationWatch {
    /// Returns after DNS/hostname registration, hosts watches and checked baseline.
    /// The conventional path is resolved by the native owner, including symlinks.
    pub(crate) fn start() -> Result<Self, WatchError> {
        Self::start_path(Path::new("/etc/hosts"))
    }

    #[cfg(test)]
    pub(super) fn start_with_hosts(path: &Path) -> Result<Self, WatchError> {
        Self::start_path(path)
    }

    fn start_path(path: &Path) -> Result<Self, WatchError> {
        let bytes = path.as_os_str().as_bytes();
        if !path.is_absolute() || bytes.last() == Some(&b'/') || bytes.len() >= 1024 {
            return Err(WatchError::cause(WatchCause::InvalidHostsPath));
        }
        let hosts_path =
            CString::new(bytes).map_err(|_| WatchError::cause(WatchCause::InvalidHostsPath))?;
        let (control, receiver) =
            UnixStream::pair().map_err(|_| WatchError::cause(WatchCause::ControlIo))?;
        let dirty = Arc::new(Dirty::new());
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (requests, request_rx) = mpsc::sync_channel(1);
        let thread_dirty = Arc::clone(&dirty);
        let worker = thread::Builder::new()
            .name("phantom-macos-dns-watch".into())
            .spawn(move || run(receiver, request_rx, &thread_dirty, ready_tx, &hosts_path))
            .map_err(|_| WatchError::cause(WatchCause::ThreadStart))?;
        let mut watch = Self {
            dirty,
            control: Mutex::new(Some(control)),
            requests,
            worker: Some(worker),
        };
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(watch),
            Ok(Err(error)) => watch.stop_and_join().and(Err(error)),
            Err(_) => watch
                .stop_and_join()
                .and(Err(WatchError::cause(WatchCause::WorkerPanicked))),
        }
    }

    pub(crate) fn observer(&self) -> ConfigurationObserver {
        ConfigurationObserver {
            dirty: Arc::clone(&self.dirty),
        }
    }

    /// Blocking native check. Call around a refresh, without cache locks held.
    /// This serializes check callers and reserves only one bounded request.
    pub(crate) fn check(&self) -> Result<ConfigurationGeneration, WatchError> {
        let mut control = match self.control.lock() {
            Ok(control) => control,
            Err(_) => {
                let error = WatchError::cause(WatchCause::StatePoisoned);
                let _ = self.dirty.finish(Err(error));
                return Err(error);
            }
        };
        self.dirty.active()?;
        let (reply, response) = mpsc::sync_channel(1);
        self.requests.try_send(reply).map_err(|_| {
            let error = WatchError::cause(WatchCause::InvalidControl);
            self.dirty.finish(Err(error)).err().unwrap_or(error)
        })?;
        let written = control
            .as_mut()
            .ok_or_else(|| WatchError::cause(WatchCause::Stopped))?
            .write_all(&[1]);
        if written.is_err() {
            let error = WatchError::cause(WatchCause::ControlIo);
            let _ = self.dirty.finish(Err(error));
            // EOF is the stop signal. No duplicated writer can outlive it.
            drop(control.take());
            return Err(error);
        }
        response.recv().map_err(|_| {
            self.dirty
                .observed()
                .err()
                .unwrap_or_else(|| WatchError::cause(WatchCause::WorkerPanicked))
        })?
    }

    /// Blocking stop/join. A cancellation failure remains observable.
    pub(crate) fn shutdown(mut self) -> Result<(), WatchError> {
        self.stop_and_join()
    }

    fn stop_and_join(&mut self) -> Result<(), WatchError> {
        // get_mut is exclusive even on poison. Recover only to close the
        // owned wake endpoint and join; observer/check paths remain fail-closed.
        let control = match self.control.get_mut() {
            Ok(control) => control,
            Err(poisoned) => poisoned.into_inner(),
        };
        drop(control.take());
        let result = self.worker.take().map_or(Ok(()), |worker| {
            worker
                .join()
                .unwrap_or_else(|_| Err(WatchError::cause(WatchCause::WorkerPanicked)))
        });
        self.dirty.finish(result)
    }
}
impl Drop for ConfigurationWatch {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

struct NativeWatch(Option<NonNull<c_void>>);
impl NativeWatch {
    fn start(out: &mut Option<Self>, hosts_path: &CStr) -> Result<(), WatchError> {
        let mut owner = ptr::null_mut();
        let mut code = 0;
        // SAFETY: writable output slots; every non-null allocation is adopted
        // before inspecting status, including descriptor-setup failure. The
        // NUL-terminated path lives for this call; C copies it before returning.
        let status =
            unsafe { phantom_macos_dns_watch_start(hosts_path.as_ptr(), &mut owner, &mut code) };
        let watch = Self(NonNull::new(owner));
        let has_owner = watch.0.is_some();
        // The caller keeps this slot outside its caught body. Setup failure
        // must publish terminal state before a possibly blocking cancellation.
        *out = Some(watch);
        if status == UNAVAILABLE {
            return Err(WatchError::cause(WatchCause::WitnessUnavailable));
        }
        if status != OK {
            return Err(WatchError::native("watch_register/setup", status, code));
        }
        if !has_owner {
            return Err(WatchError::cause(WatchCause::InvalidControl));
        }
        Ok(())
    }

    fn pointer(&self) -> Result<*mut c_void, WatchError> {
        self.0
            .map(NonNull::as_ptr)
            .ok_or_else(|| WatchError::cause(WatchCause::Stopped))
    }

    fn check(&self) -> Result<bool, WatchError> {
        let owner = self.pointer()?;
        let mut changed = 0;
        let mut code = 0;
        // SAFETY: only the owned worker calls this, before close. Output slots
        // live for the synchronous call; C retains none of their pointers.
        let status = unsafe { phantom_macos_dns_watch_check(owner, &mut changed, &mut code) };
        if status != OK {
            return Err(WatchError::native("watch_check", status, code));
        }
        match changed {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(WatchError::cause(WatchCause::InvalidControl)),
        }
    }

    fn wait(&self, control: &UnixStream) -> Result<u32, WatchError> {
        let owner = self.pointer()?;
        let mut event = 0;
        let mut code = 0;
        // SAFETY: the worker exclusively owns the live C allocation and keeps
        // the control stream open through this blocking readiness/read call.
        let status = unsafe {
            phantom_macos_dns_watch_wait(owner, control.as_raw_fd(), &mut event, &mut code)
        };
        if status == OK {
            Ok(event)
        } else {
            Err(WatchError::native("watch_wait", status, code))
        }
    }

    fn close(&mut self) -> Result<(), WatchError> {
        let Some(owner) = self.0.take() else {
            return Ok(());
        };
        let mut code = 0;
        // SAFETY: taken exactly once, after wait/check have stopped. C frees its
        // allocation even on cancellation error; the library still owns any
        // failed native registration, which has no pointer into Rust or C owner.
        let status = unsafe { phantom_macos_dns_watch_close(owner.as_ptr(), &mut code) };
        if status == OK {
            Ok(())
        } else {
            let mut error = WatchError::native("watch_close", status, code);
            error.cancellation = Some((status, code));
            Err(error)
        }
    }
}
impl Drop for NativeWatch {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn run(
    control: UnixStream,
    requests: mpsc::Receiver<Reply>,
    dirty: &Arc<Dirty>,
    ready: mpsc::SyncSender<Result<(), WatchError>>,
    hosts_path: &CStr,
) -> Result<(), WatchError> {
    // Retain native ownership OUTSIDE the caught body: a setup/wait panic must
    // publish terminal invalidation before native cancellation can block.
    let mut native = None;
    let mut ready = Some(ready);
    let mut pending_reply = None;
    let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        NativeWatch::start(&mut native, hosts_path)?;
        let watch = native
            .as_ref()
            .ok_or_else(|| WatchError::cause(WatchCause::InvalidControl))?;
        let _ = watch.check()?; // Initial true is primed before baseline sampling.
        if let Some(ready) = ready.take() {
            ready
                .send(Ok(()))
                .map_err(|_| WatchError::cause(WatchCause::Stopped))?;
        }
        loop {
            match watch.wait(&control)? {
                0 => return Ok(()),
                1 => {
                    let _ = watch.check()?;
                    dirty.mark();
                }
                2 => {
                    pending_reply = Some(
                        requests
                            .try_recv()
                            .map_err(|_| WatchError::cause(WatchCause::InvalidControl))?,
                    );
                    if watch.check()? {
                        dirty.mark();
                    }
                    if let Some(reply) = pending_reply.take() {
                        let _ = reply.send(dirty.observed());
                    }
                }
                3 => {
                    if watch.check()? {
                        dirty.mark();
                    }
                }
                _ => return Err(WatchError::cause(WatchCause::InvalidControl)),
            }
        }
    }))
    .unwrap_or_else(|_| Err(WatchError::cause(WatchCause::WorkerPanicked)));
    finish_watch(dirty, body, ready, pending_reply, requests, || {
        native.as_mut().map_or(Ok(()), NativeWatch::close)
    })
}

fn finish_watch(
    dirty: &Dirty,
    body: Result<(), WatchError>,
    ready: Option<mpsc::SyncSender<Result<(), WatchError>>>,
    pending_reply: Option<Reply>,
    requests: mpsc::Receiver<Reply>,
    cleanup: impl FnOnce() -> Result<(), WatchError>,
) -> Result<(), WatchError> {
    let body = dirty.finish(body);
    let failure = dirty
        .observed()
        .err()
        .unwrap_or_else(|| WatchError::cause(WatchCause::Stopped));
    if let Some(ready) = ready {
        let _ = ready.send(Err(failure));
    }
    // Release check callers before cancellation, including queued requests.
    if let Some(reply) = pending_reply {
        let _ = reply.send(Err(failure));
    }
    for reply in requests.try_iter() {
        let _ = reply.send(Err(failure));
    }
    // A caller may have sampled active just before finish. Dropping the inbox
    // now closes that race without making it wait for native cancellation.
    drop(requests);
    let cleanup = cleanup();
    let result = match (body, cleanup) {
        (Err(mut primary), Err(cleanup)) => {
            primary.cancellation = cleanup.cancellation;
            Err(primary)
        }
        (Ok(()), result) | (result, Ok(())) => result,
    };
    dirty.finish(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::Future,
        io,
        task::{Context, Poll, Waker},
    };

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    #[test]
    fn generations_are_owner_qualified_and_marks_are_visible() -> TestResult {
        let first = Dirty::new();
        let second = Dirty::new();
        let before = first.observed()?;
        assert_ne!(before, second.observed()?);
        first.mark();
        assert_ne!(before, first.observed()?);
        Ok(())
    }

    #[test]
    fn registered_waiter_cannot_lose_invalidation_or_terminal_wakeup() -> TestResult {
        let dirty = Arc::new(Dirty::new());
        let observer = ConfigurationObserver {
            dirty: Arc::clone(&dirty),
        };
        let before = observer.observed()?;
        let changed = observer.changed_since(&before);
        tokio::pin!(changed);
        let mut context = Context::from_waker(Waker::noop());
        assert!(changed.as_mut().poll(&mut context).is_pending());
        dirty.mark();
        assert!(matches!(
            changed.as_mut().poll(&mut context),
            Poll::Ready(Ok(_))
        ));
        let before = observer.observed()?;
        let changed = observer.changed_since(&before);
        tokio::pin!(changed);
        assert!(changed.as_mut().poll(&mut context).is_pending());
        let failure = WatchError::cause(WatchCause::InvalidControl);
        assert_eq!(dirty.finish(Err(failure)), Err(failure));
        assert!(
            matches!(changed.as_mut().poll(&mut context), Poll::Ready(Err(error)) if error == failure)
        );
        Ok(())
    }

    #[test]
    fn observer_outlives_owner_state_without_owning_a_native_handle() -> TestResult {
        let dirty = Arc::new(Dirty::new());
        let observer = ConfigurationObserver {
            dirty: Arc::clone(&dirty),
        };
        dirty.finish(Ok(()))?;
        drop(dirty);
        assert_eq!(
            observer.observed().err().map(|error| error.cause),
            Some(WatchCause::Stopped)
        );
        Ok(())
    }

    #[test]
    fn terminal_error_is_visible_before_cleanup_and_enriched_afterward() {
        let dirty = Dirty::new();
        let failure = WatchError::cause(WatchCause::WorkerPanicked);
        assert_eq!(dirty.finish(Err(failure)), Err(failure));
        // This is the actual state transition used before native close; it
        // does not pretend that an OS cancellation succeeded or completed.
        assert_eq!(dirty.observed().err(), Some(failure));
        let mut cleanup = WatchError::native("notify_cancel", 3, 1000000);
        cleanup.cancellation = Some((3, 1000000));
        let enriched = dirty.finish(Err(cleanup));
        assert!(
            matches!(enriched, Err(error) if error.cause == failure.cause && error.cancellation == cleanup.cancellation)
        );
        assert_eq!(dirty.finish(Ok(())), enriched);
    }

    #[test]
    fn failed_or_panicked_body_releases_check_callers_before_blocked_cleanup() -> TestResult {
        for cause in [WatchCause::InvalidControl, WatchCause::WorkerPanicked] {
            let dirty = Arc::new(Dirty::new());
            let thread_dirty = Arc::clone(&dirty);
            let (requests, inbox) = mpsc::sync_channel(1);
            let (pending, pending_response) = mpsc::sync_channel(1);
            let (queued, queued_response) = mpsc::sync_channel(1);
            requests.try_send(queued)?;
            let (entered, entered_rx) = mpsc::sync_channel(1);
            let (release, release_rx) = mpsc::sync_channel(1);
            let failure = WatchError::cause(cause);
            let worker = thread::Builder::new().spawn(move || {
                finish_watch(
                    &thread_dirty,
                    Err(failure),
                    None,
                    Some(pending),
                    inbox,
                    || {
                        let entered = entered.send(());
                        let released = release_rx.recv();
                        if entered.is_err() || released.is_err() {
                            Err(WatchError::cause(WatchCause::ControlIo))
                        } else {
                            Ok(())
                        }
                    },
                )
            })?;
            let entered = entered_rx.recv_timeout(std::time::Duration::from_secs(1));
            let pending = pending_response.try_recv();
            let queued = queued_response.try_recv();
            let terminal = dirty.observed();
            let (late, _late_response) = mpsc::sync_channel(1);
            let late = requests.try_send(late);
            // Always release and join before asserting any observed result.
            let released = release.send(());
            let joined = worker.join();
            assert!(entered.is_ok());
            assert_eq!(pending?, Err(failure));
            assert_eq!(queued?, Err(failure));
            assert_eq!(terminal.err(), Some(failure));
            assert!(matches!(late, Err(mpsc::TrySendError::Disconnected(_))));
            released?;
            assert_eq!(
                joined.map_err(|_| io::Error::other("cleanup worker panicked"))?,
                Err(failure)
            );
        }
        Ok(())
    }

    #[test]
    fn generation_exhaustion_never_wraps_or_recovers() {
        let dirty = Dirty::new();
        dirty.sequence.store(u64::MAX, Ordering::Release);
        dirty.mark();
        dirty.mark();
        assert_eq!(dirty.sequence.load(Ordering::Acquire), u64::MAX);
        assert_eq!(
            dirty.observed().err().map(|error| error.cause),
            Some(WatchCause::GenerationExhausted)
        );
    }

    #[test]
    fn foreign_generation_wait_fails_without_waiting() -> TestResult {
        let dirty = Arc::new(Dirty::new());
        let observer = ConfigurationObserver { dirty };
        let foreign = Dirty::new().observed()?;
        let changed = observer.changed_since(&foreign);
        tokio::pin!(changed);
        let mut context = Context::from_waker(Waker::noop());
        assert!(
            matches!(changed.as_mut().poll(&mut context), Poll::Ready(Err(error)) if error.cause == WatchCause::ForeignGeneration)
        );
        Ok(())
    }

    #[test]
    fn concurrent_marks_are_counted_without_a_lost_increment() -> TestResult {
        let dirty = Dirty::new();
        thread::scope(|scope| -> TestResult {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        for _ in 0..256 {
                            dirty.mark();
                        }
                    })
                })
                .collect();
            for handle in handles {
                handle
                    .join()
                    .map_err(|_| io::Error::other("mark worker panicked"))?;
            }
            Ok(())
        })?;
        assert_eq!(dirty.observed()?.sequence, 1025);
        Ok(())
    }

    #[test]
    fn poisoned_terminal_state_fails_closed_and_wakes_no_false_success() {
        let dirty = Dirty::new();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = dirty.terminal.lock();
            panic!("synthetic poison");
        }));
        assert_eq!(
            dirty.observed().err().map(|error| error.cause),
            Some(WatchCause::StatePoisoned)
        );
        assert_eq!(
            dirty.finish(Ok(())).err().map(|error| error.cause),
            Some(WatchCause::StatePoisoned)
        );
    }
}
