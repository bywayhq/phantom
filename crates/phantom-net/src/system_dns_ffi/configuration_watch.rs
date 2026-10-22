//! Private Windows DNS invalidation owner. Register before reading settings.
//!
//! Start and shutdown run in blocking work. Shutdown signals the OS wait and
//! joins the owned thread. Settings reads and cache publication belong to the
//! caller.

use std::ffi::c_void;
use std::fmt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};

use tokio::sync::Notify;
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_KEY_DELETED, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, GetLastError,
    HANDLE, WAIT_FAILED, WAIT_OBJECT_0,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE,
    NotifyIpInterfaceChange, NotifyRouteChange2,
};
use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_NOTIFY, REG_NOTIFY_CHANGE_ATTRIBUTES, REG_NOTIFY_CHANGE_LAST_SET,
    REG_NOTIFY_CHANGE_NAME, REG_NOTIFY_CHANGE_SECURITY, REG_NOTIFY_THREAD_AGNOSTIC, RegCloseKey,
    RegNotifyChangeKeyValue, RegOpenKeyExW,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, INFINITE, SetEvent, WaitForMultipleObjects,
};

const PATHS: [&str; 9] = [
    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
    r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
    r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
    r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
    r"SOFTWARE\Policies\Microsoft\System\DNSClient",
    r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig",
    r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig",
    r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsConnections",
    r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsConnectionsProxies",
];
const FILTER: u32 = REG_NOTIFY_CHANGE_NAME
    | REG_NOTIFY_CHANGE_ATTRIBUTES
    | REG_NOTIFY_CHANGE_LAST_SET
    | REG_NOTIFY_CHANGE_SECURITY
    | REG_NOTIFY_THREAD_AGNOSTIC;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WatchCause {
    Native {
        operation: &'static str,
        code: u32,
    },
    ThreadStart,
    WorkerPanicked,
    GenerationExhausted,
    StatePoisoned,
    InvalidRegistrationState,
    #[cfg(test)]
    ForeignGeneration,
    Stopped,
}

/// Fixed operation names and status codes only; no registry or network values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WatchError {
    pub(crate) cause: WatchCause,
    /// Zero means cancellation succeeded or no registration was acquired.
    pub(crate) cancellation_codes: [u32; 2],
    pub(crate) worker_cause: Option<WatchCause>,
}

impl WatchError {
    fn cause(cause: WatchCause) -> Self {
        Self {
            cause,
            cancellation_codes: [0; 2],
            worker_cause: None,
        }
    }

    fn native(operation: &'static str, code: u32) -> Self {
        Self::cause(WatchCause::Native { operation, code })
    }
}

impl fmt::Display for WatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Windows DNS watch failed: {:?}", self.cause)
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

struct Dirty {
    owner: Arc<()>,
    generation: AtomicU64,
    exhausted: AtomicBool,
    notify: Notify,
    terminal: Mutex<Option<Result<(), WatchError>>>,
    cancellation_codes: [AtomicU32; 2],
}

impl Dirty {
    fn new() -> Self {
        Self {
            owner: Arc::new(()),
            generation: AtomicU64::new(1),
            exhausted: AtomicBool::new(false),
            notify: Notify::new(),
            terminal: Mutex::new(None),
            cancellation_codes: [AtomicU32::new(0), AtomicU32::new(0)],
        }
    }

    // Called from native callbacks: no owner lock, row reads or configuration I/O.
    fn mark(&self) {
        let mut current = self.generation.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(1) else {
                self.exhausted.store(true, Ordering::Release);
                break;
            };
            match self.generation.compare_exchange_weak(
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

    fn observed(&self) -> Result<ConfigurationGeneration, WatchError> {
        self.check_terminal()?;
        let generation = self.generation.load(Ordering::Acquire);
        if self.exhausted.load(Ordering::Acquire) {
            return Err(WatchError::cause(WatchCause::GenerationExhausted));
        }
        self.check_terminal()?;
        Ok(ConfigurationGeneration {
            owner: Arc::clone(&self.owner),
            sequence: generation,
        })
    }

    fn check_terminal(&self) -> Result<(), WatchError> {
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

    fn finish(&self, mut result: Result<(), WatchError>) -> Result<(), WatchError> {
        let codes = self
            .cancellation_codes
            .each_ref()
            .map(|code| code.load(Ordering::Acquire));
        if let Some(code) = codes.into_iter().find(|code| *code != 0) {
            let mut error = match result {
                Err(error) => error,
                Ok(()) => WatchError::native("CancelMibChangeNotify2", code),
            };
            error.cancellation_codes = codes;
            result = Err(error);
        }
        match self.terminal.lock() {
            Ok(mut terminal) => *terminal = Some(result),
            Err(_) => result = Err(WatchError::cause(WatchCause::StatePoisoned)),
        }
        self.notify.notify_waiters();
        result
    }

    #[cfg(test)]
    async fn changed_since(
        &self,
        previous: ConfigurationGeneration,
    ) -> Result<ConfigurationGeneration, WatchError> {
        if !Arc::ptr_eq(&self.owner, &previous.owner) {
            return Err(WatchError::cause(WatchCause::ForeignGeneration));
        }
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            // Install before the second observation, including notify_waiters.
            notified.as_mut().enable();
            let current = self.observed()?;
            if current != previous {
                return Ok(current);
            }
            notified.await;
        }
    }
}

/// Read-only invalidation state. This owns no native handle or worker.
#[derive(Clone)]
pub(crate) struct ConfigurationObserver {
    dirty: Arc<Dirty>,
}
impl ConfigurationObserver {
    pub(crate) fn observed(&self) -> Result<ConfigurationGeneration, WatchError> {
        self.dirty.observed()
    }
}

/// Exactly one joined thread; no native handles or atomic fields are exposed.
pub(crate) struct ConfigurationWatch {
    dirty: Arc<Dirty>,
    stop: OwnedHandle,
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
    /// Returns only after all registry and network registrations are installed.
    /// The caller takes a generation, reads settings, then checks it again.
    pub(crate) fn start() -> Result<Self, WatchError> {
        let dirty = Arc::new(Dirty::new());
        let stop = event(true)?;
        let thread_stop = stop.try_clone().map_err(|error| {
            WatchError::native("DuplicateHandle", error.raw_os_error().unwrap_or(0) as u32)
        })?;
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let thread_dirty = Arc::clone(&dirty);
        let worker = thread::Builder::new()
            .name("phantom-dns-watch".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run(thread_stop, &thread_dirty, ready_tx)
                }))
                .unwrap_or_else(|_| Err(WatchError::cause(WatchCause::WorkerPanicked)));
                thread_dirty.finish(result)
            })
            .map_err(|_| WatchError::cause(WatchCause::ThreadStart))?;
        let mut watch = Self {
            dirty,
            stop,
            worker: Some(worker),
        };
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(watch),
            Ok(Err(error)) => {
                let cleanup = watch.join();
                cleanup.and(Err(error))
            }
            Err(_) => watch
                .join()
                .and(Err(WatchError::cause(WatchCause::WorkerPanicked))),
        }
    }

    pub(crate) fn observer(&self) -> ConfigurationObserver {
        ConfigurationObserver {
            dirty: Arc::clone(&self.dirty),
        }
    }

    /// Call from blocking work, with no resolver/cache locks held.
    pub(crate) fn shutdown(mut self) -> Result<(), WatchError> {
        self.stop_and_join()
    }

    fn stop_and_join(&mut self) -> Result<(), WatchError> {
        if self.worker.is_none() {
            return Ok(());
        }
        // SAFETY: stop is owned through the completed join; only signals it.
        let signal = if unsafe { SetEvent(self.stop.as_raw_handle()) } == 0 {
            Err(last_error("SetEvent"))
        } else {
            Ok(())
        };
        // Never detach on a signal error. See the draft's OS-failure limitation.
        let joined = self.join();
        shutdown_result(signal, joined)
    }

    fn join(&mut self) -> Result<(), WatchError> {
        self.worker.take().map_or(Ok(()), |worker| {
            worker
                .join()
                .unwrap_or_else(|_| Err(WatchError::cause(WatchCause::WorkerPanicked)))
        })
    }
}

fn shutdown_result(
    signal: Result<(), WatchError>,
    joined: Result<(), WatchError>,
) -> Result<(), WatchError> {
    match (signal, joined) {
        (Err(mut signal), Err(worker)) => {
            signal.worker_cause = Some(worker.cause);
            signal.cancellation_codes = worker.cancellation_codes;
            Err(signal)
        }
        (Ok(()), result) | (result, Ok(())) => result,
    }
}

impl Drop for ConfigurationWatch {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

fn run(
    stop: OwnedHandle,
    dirty: &Arc<Dirty>,
    ready: mpsc::SyncSender<Result<(), WatchError>>,
) -> Result<(), WatchError> {
    let mut registry = Vec::with_capacity(PATHS.len());
    let mut notifications = Vec::with_capacity(2);
    // Owners stay outside both unwind-catching closures. A wait/setup panic
    // must publish terminal state before any notification lease starts cancel.
    let setup = catch_watch_result(|| {
        for path in PATHS {
            registry.push(RegistryWatch::new(path)?);
        }
        notifications.push(Notification::register(Arc::clone(dirty), 0)?);
        notifications.push(Notification::register(Arc::clone(dirty), 1)?);
        Ok(())
    });
    if let Err(error) = setup {
        let result = finish_watch(dirty, || Err(error), || drop(notifications));
        let _ = ready.send(result);
        return result;
    }
    if ready.send(Ok(())).is_err() {
        return finish_watch(dirty, || Ok(()), || drop(notifications));
    }
    finish_watch(
        dirty,
        || {
            loop {
                let mut handles = [ptr::null_mut(); PATHS.len() + 1];
                handles[0] = stop.as_raw_handle();
                for (slot, watch) in registry.iter().enumerate() {
                    handles[slot + 1] = watch.event.as_raw_handle();
                }
                // SAFETY: all ten handles stay owned and unchanged throughout this
                // wait. Auto-reset registry events consume exactly one outstanding arm.
                let status = unsafe {
                    WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, INFINITE)
                };
                if status == WAIT_FAILED {
                    return Err(last_error("WaitForMultipleObjects"));
                }
                if status == WAIT_OBJECT_0 {
                    return Ok(());
                }
                let index = status.wrapping_sub(WAIT_OBJECT_0 + 1) as usize;
                let Some(watch) = registry.get_mut(index) else {
                    return Err(WatchError::native("WaitForMultipleObjects status", status));
                };
                // Publish THIS registry invalidation after rearming. Independent
                // interface/route marks may interleave; OS delivery is not atomic.
                watch.signaled()?;
                dirty.mark();
            }
        },
        || drop(notifications),
    )
}

fn catch_watch_result(
    operation: impl FnOnce() -> Result<(), WatchError>,
) -> Result<(), WatchError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation))
        .unwrap_or_else(|_| Err(WatchError::cause(WatchCause::WorkerPanicked)))
}

fn finish_watch(
    dirty: &Dirty,
    operation: impl FnOnce() -> Result<(), WatchError>,
    cleanup: impl FnOnce(),
) -> Result<(), WatchError> {
    let result = catch_watch_result(operation);
    // Terminal publication precedes cancellation, including a caught unwind.
    // No terminal mutex guard survives this call into native cancellation.
    let published = dirty.finish(result);
    cleanup();
    // Enrich the already terminal failure with all cancellation statuses.
    dirty.finish(published)
}

fn event(manual_reset: bool) -> Result<OwnedHandle, WatchError> {
    // SAFETY: no inherited security/name; returned event is newly owned.
    let handle = unsafe { CreateEventW(ptr::null(), i32::from(manual_reset), 0, ptr::null()) };
    if handle.is_null() {
        return Err(last_error("CreateEventW"));
    }
    // SAFETY: non-null kernel event transferred exactly once to OwnedHandle.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn last_error(operation: &'static str) -> WatchError {
    // SAFETY: called immediately after the failing Windows operation.
    WatchError::native(operation, unsafe { GetLastError() })
}

struct RegistryKey(HKEY);
impl Drop for RegistryKey {
    fn drop(&mut self) {
        // SAFETY: key is opened by RegOpenKeyExW and never cloned/moved to a waiter.
        let _ = unsafe { RegCloseKey(self.0) };
    }
}

fn open_key(path: &str) -> Result<Option<RegistryKey>, WatchError> {
    // Opening an empty name on HKLM returns the shared predefined handle, not
    // a fresh owned key. Do not accidentally install multiple waits on it.
    if path.is_empty() {
        return Err(WatchError::native(
            "No owned registry ancestor",
            ERROR_PATH_NOT_FOUND,
        ));
    }
    let name: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let mut key = ptr::null_mut();
    // SAFETY: terminated bounded static path, writable output, read-only notify.
    let code = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, name.as_ptr(), 0, KEY_NOTIFY, &mut key) };
    match code {
        ERROR_SUCCESS => Ok(Some(RegistryKey(key))),
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(None),
        code => Err(WatchError::native("RegOpenKeyExW", code)),
    }
}

// A missing optional path watches its closest existing ancestor, including NAME.
// Keep that ancestor armed; subtree delivery covers later child installation.
fn nearest_existing<T>(
    mut path: &str,
    mut open: impl FnMut(&str) -> Result<Option<T>, WatchError>,
) -> Result<T, WatchError> {
    loop {
        if let Some(key) = open(path)? {
            return Ok(key);
        }
        if path.is_empty() {
            return Err(WatchError::native("HKLM watch root", ERROR_PATH_NOT_FOUND));
        }
        path = path.rsplit_once('\\').map_or("", |(parent, _)| parent);
    }
}

#[derive(Default)]
struct Arm {
    outstanding: bool,
}
impl Arm {
    fn register(&mut self, arm: impl FnOnce() -> Result<(), WatchError>) -> Result<(), WatchError> {
        if self.outstanding {
            return Err(WatchError::cause(WatchCause::InvalidRegistrationState));
        }
        arm()?;
        self.outstanding = true;
        Ok(())
    }
    fn consume(&mut self) -> Result<(), WatchError> {
        if !self.outstanding {
            return Err(WatchError::cause(WatchCause::InvalidRegistrationState));
        }
        self.outstanding = false;
        Ok(())
    }
}

struct RegistryWatch {
    // Close key before its event: closing a registered key signals the event.
    key: Option<RegistryKey>,
    event: OwnedHandle,
    target: &'static str,
    arm: Arm,
}
impl RegistryWatch {
    fn new(target: &'static str) -> Result<Self, WatchError> {
        let mut watch = Self {
            key: Some(nearest_existing(target, open_key)?),
            event: event(false)?,
            target,
            arm: Arm::default(),
        };
        watch.register()?;
        Ok(watch)
    }
    fn register(&mut self) -> Result<(), WatchError> {
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| WatchError::cause(WatchCause::InvalidRegistrationState))?
            .0;
        let event = self.event.as_raw_handle();
        self.arm.register(|| {
            // SAFETY: live key/event, constant filter and subtree/async settings.
            let code = unsafe { RegNotifyChangeKeyValue(key, 1, FILTER, event, 1) };
            if code == ERROR_SUCCESS {
                Ok(())
            } else {
                Err(WatchError::native("RegNotifyChangeKeyValue", code))
            }
        })
    }
    fn signaled(&mut self) -> Result<(), WatchError> {
        self.arm.consume()?;
        match self.register() {
            Ok(()) => Ok(()),
            Err(WatchError {
                cause:
                    WatchCause::Native {
                        code: ERROR_KEY_DELETED,
                        ..
                    },
                ..
            }) => {
                // No successful arm remains. Retire the deleted key/event pair;
                // a fresh event cannot consume the old key-close notification.
                drop(self.key.take());
                self.event = event(false)?;
                self.key = Some(nearest_existing(self.target, open_key)?);
                self.register() // one bounded reselection; repeated deletion fails closed
            }
            Err(error) => Err(error),
        }
    }
}

struct Notification {
    handle: HANDLE,
    context: Option<Arc<Dirty>>,
    slot: usize,
    cancel: fn(HANDLE) -> u32,
}
impl Notification {
    fn register(context: Arc<Dirty>, slot: usize) -> Result<Self, WatchError> {
        let pointer = Arc::as_ptr(&context).cast::<c_void>();
        let mut handle = ptr::null_mut();
        // SAFETY: context Arc remains stable until cancellation completes; the
        // callbacks ignore row pointers. No initial callback is requested.
        let code = unsafe {
            if slot == 0 {
                NotifyIpInterfaceChange(
                    AF_UNSPEC,
                    Some(interface_changed),
                    pointer,
                    false,
                    &mut handle,
                )
            } else {
                NotifyRouteChange2(AF_UNSPEC, Some(route_changed), pointer, false, &mut handle)
            }
        };
        if code != ERROR_SUCCESS {
            return Err(WatchError::native("Notify network change", code));
        }
        if handle.is_null() {
            // Broken native success contract: cannot cancel a null handle and
            // cannot prove the callback is inactive. Preserve its stable state.
            let _retained = Arc::into_raw(context);
            return Err(WatchError::native("Notify network change null handle", 6));
        }
        Ok(Self {
            handle,
            context: Some(context),
            slot,
            cancel: cancel_notification,
        })
    }
    fn cancel(&mut self) {
        let Some(context) = self.context.take() else {
            return;
        };
        let code = (self.cancel)(self.handle);
        if code != ERROR_SUCCESS {
            context.cancellation_codes[self.slot].store(code, Ordering::Release);
            // An arbitrary cancellation failure does not establish quiescence.
            // At most one strong state reference per failed registration is
            // quarantined per failed owner (not globally); never detach a worker
            // or free callback storage early.
            let _retained = Arc::into_raw(context);
        }
        // Successful return establishes quiescence before context is released.
    }
}
impl Drop for Notification {
    fn drop(&mut self) {
        self.cancel();
    }
}
fn cancel_notification(handle: HANDLE) -> u32 {
    // SAFETY: one acquired notification handle; called off-callback with no
    // resource/lock needed by either callback, context stays alive through return.
    unsafe { CancelMibChangeNotify2(handle) }
}
unsafe extern "system" fn interface_changed(
    context: *const c_void,
    _row: *const MIB_IPINTERFACE_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: installed only with a stable Arc<Dirty> retained by Notification;
    // cancellation retains custody until native callbacks have quiesced.
    unsafe {
        (&*context.cast::<Dirty>()).mark();
    }
}
unsafe extern "system" fn route_changed(
    context: *const c_void,
    _row: *const MIB_IPFORWARD_ROW2,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: identical stable callback custody; no row data is touched.
    unsafe {
        (&*context.cast::<Dirty>()).mark();
    }
}

#[cfg(test)]
mod tests;
