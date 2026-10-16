//! Owned inotify and route-netlink invalidation for one Linux DNS intake.
//!
//! Linux inotify(7)/netlink(7), and Linux v6.17 UAPI inotify.h, netlink.h and
//! rtnetlink.h define framing and subscriptions. Notification loss is terminal.
//! A drain fence covers delivered events, not an atomic OS configuration read.

use std::{
    ffi::CString,
    fmt,
    fs::File,
    io::{self, Read},
    mem::{size_of, zeroed},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicI32, AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const MAX_PATHS: usize = 128;
const MAX_PATH_BYTES: usize = 4095;
const MAX_DRAIN_READS: usize = 64;
const BUFFER_BYTES: usize = 64 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const STOPPED: i32 = -1;
const PANICKED: i32 = -2;
const INVALID_EVENT: i32 = -3;
const DRAIN_BUSY: i32 = -4;
const OTHER_FAILURE: i32 = -5;
const GENERATION_EXHAUSTED: i32 = -6;

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

struct Shared {
    owner: Arc<()>,
    sequence: AtomicU64,
    terminal: AtomicI32,
}

impl Shared {
    fn new() -> Self {
        Self {
            owner: Arc::new(()),
            sequence: AtomicU64::new(1),
            terminal: AtomicI32::new(0),
        }
    }

    fn observed(&self) -> io::Result<ConfigurationGeneration> {
        self.running()?;
        let sequence = self.sequence.load(Ordering::Acquire);
        self.running()?;
        Ok(ConfigurationGeneration {
            owner: Arc::clone(&self.owner),
            sequence,
        })
    }

    fn running(&self) -> io::Result<()> {
        let terminal = self.terminal.load(Ordering::Acquire);
        if terminal == 0 {
            Ok(())
        } else {
            Err(terminal_error(terminal))
        }
    }

    // Only the worker increments. Observers never perform I/O or acquire locks.
    fn mark(&self) -> io::Result<()> {
        let Some(next) = self.sequence.load(Ordering::Relaxed).checked_add(1) else {
            self.finish(GENERATION_EXHAUSTED);
            return Err(terminal_error(GENERATION_EXHAUSTED));
        };
        self.sequence.store(next, Ordering::Release);
        Ok(())
    }

    fn finish(&self, code: i32) {
        let _prior = self
            .terminal
            .compare_exchange(0, code, Ordering::AcqRel, Ordering::Acquire);
    }

    fn fail(&self, error: &io::Error) {
        let code = error
            .raw_os_error()
            .filter(|code| *code > 0)
            .unwrap_or(match error.kind() {
                io::ErrorKind::InvalidData => INVALID_EVENT,
                io::ErrorKind::WouldBlock => DRAIN_BUSY,
                _ => OTHER_FAILURE,
            });
        self.finish(code);
    }
}

fn terminal_error(code: i32) -> io::Error {
    if code > 0 {
        return io::Error::from_raw_os_error(code);
    }
    let (kind, message) = match code {
        STOPPED => (io::ErrorKind::BrokenPipe, "Linux DNS watch stopped"),
        PANICKED => (io::ErrorKind::Other, "Linux DNS watch worker panicked"),
        INVALID_EVENT => (
            io::ErrorKind::InvalidData,
            "Linux DNS watch lost valid notification state",
        ),
        DRAIN_BUSY => (
            io::ErrorKind::WouldBlock,
            "Linux DNS watch drain exceeds its work bound",
        ),
        GENERATION_EXHAUSTED => (io::ErrorKind::Other, "Linux DNS watch generation exhausted"),
        _ => (io::ErrorKind::Other, "Linux DNS watch worker failed"),
    };
    io::Error::new(kind, message)
}

#[derive(Clone)]
pub(crate) struct ConfigurationObserver {
    shared: Arc<Shared>,
}

impl ConfigurationObserver {
    /// Only processed notifications are reflected; use the owner fence at intake.
    pub(crate) fn observed(&self) -> io::Result<ConfigurationGeneration> {
        self.shared.observed()
    }
}

impl fmt::Debug for ConfigurationObserver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfigurationObserver(..)")
    }
}

enum Command {
    Check(SyncSender<io::Result<ConfigurationGeneration>>),
    Ensure(Vec<WatchPath>, SyncSender<io::Result<()>>),
}

pub(crate) struct ConfigurationWatch {
    shared: Arc<Shared>,
    commands: Option<SyncSender<Command>>,
    worker: Option<JoinHandle<()>>,
}

impl fmt::Debug for ConfigurationWatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigurationWatch")
            .field("joined", &self.worker.is_none())
            .finish()
    }
}

impl ConfigurationWatch {
    /// Registers every path and network subscription before acknowledging ready.
    /// Paths should include stable parents and resolved targets; no recursion.
    pub(crate) fn start(paths: &[PathBuf]) -> io::Result<Self> {
        let paths = prepare_paths(paths)?;
        if paths.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Linux DNS watch needs paths",
            ));
        }
        let shared = Arc::new(Shared::new());
        let worker_shared = Arc::clone(&shared);
        let (commands, receiver) = mpsc::sync_channel(1);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("phantom-linux-dns-watch".into())
            .spawn(move || {
                // This guard also publishes failure while unwinding, before reply
                // channels disappear; it owns no native resources itself.
                let completion = Completion(Arc::clone(&worker_shared));
                let result = run(paths, receiver, &worker_shared, ready_tx);
                match result {
                    Ok(()) => worker_shared.finish(STOPPED),
                    Err(error) => worker_shared.fail(&error),
                }
                drop(completion);
            })?;
        let mut watch = Self {
            shared,
            commands: Some(commands),
            worker: Some(worker),
        };
        if ready_rx.recv().is_err() {
            let result = watch.stop_and_join();
            return result.and(Err(io::Error::other(
                "Linux DNS watch did not become ready",
            )));
        }
        watch.shared.running()?;
        Ok(watch)
    }

    pub(crate) fn observer(&self) -> ConfigurationObserver {
        ConfigurationObserver {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Blocks on the owning worker, draining both native queues. No cache or
    /// resolver lock may be held. This is not an OS-wide linearization point.
    pub(crate) fn check(&self) -> io::Result<ConfigurationGeneration> {
        self.shared.running()?;
        let (reply, receiver) = mpsc::sync_channel(1);
        self.send(Command::Check(reply))?;
        receiver.recv().unwrap_or_else(|_| Err(self.disconnected()))
    }

    /// Adds bounded paths before resampling a changed symlink/target graph.
    /// Existing paths retain their watches. Worker registration/drain failures
    /// terminate the watch; rejected input does not change its registrations.
    pub(crate) fn ensure_paths(&self, paths: &[PathBuf]) -> io::Result<()> {
        self.shared.running()?;
        let paths = prepare_paths(paths)?;
        let (reply, receiver) = mpsc::sync_channel(1);
        self.send(Command::Ensure(paths, reply))?;
        receiver.recv().unwrap_or_else(|_| Err(self.disconnected()))
    }

    fn send(&self, command: Command) -> io::Result<()> {
        self.commands
            .as_ref()
            .ok_or_else(|| self.disconnected())?
            .send(command)
            .map_err(|_| self.disconnected())
    }

    fn disconnected(&self) -> io::Error {
        self.shared
            .running()
            .err()
            .unwrap_or_else(|| io::Error::other("Linux DNS watch channel closed"))
    }

    /// Joins the worker and releases both descriptors. Invoke from blocking work.
    /// Nonblocking native calls and bounded queue work do not promise finite OS
    /// syscall duration or a fixed scheduler/join completion time.
    pub(crate) fn shutdown(mut self) -> io::Result<()> {
        self.stop_and_join()
    }

    fn stop_and_join(&mut self) -> io::Result<()> {
        drop(self.commands.take());
        if let Some(worker) = self.worker.take()
            && worker.join().is_err()
        {
            self.shared.finish(PANICKED);
        }
        match self.shared.terminal.load(Ordering::Acquire) {
            STOPPED => Ok(()),
            code => Err(terminal_error(code)),
        }
    }
}

impl Drop for ConfigurationWatch {
    fn drop(&mut self) {
        // Drop cannot return cleanup errors; observers retain the terminal
        // result. Always join, including failed startup and owner cancellation.
        let _result = self.stop_and_join();
    }
}

struct Completion(Arc<Shared>);

impl Drop for Completion {
    fn drop(&mut self) {
        self.0.finish(PANICKED);
    }
}

struct WatchPath {
    path: PathBuf,
    native: CString,
}

fn prepare_paths(paths: &[PathBuf]) -> io::Result<Vec<WatchPath>> {
    if paths.len() > MAX_PATHS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many Linux DNS watch paths",
        ));
    }
    let mut result: Vec<WatchPath> = Vec::new();
    result
        .try_reserve_exact(paths.len())
        .map_err(io::Error::other)?;
    for path in paths {
        let bytes = path.as_os_str().as_bytes();
        if !path.is_absolute() || bytes.len() > MAX_PATH_BYTES || bytes.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Linux DNS watch path",
            ));
        }
        if result.iter().any(|prior| prior.path == *path) {
            continue;
        }
        let mut terminated = Vec::new();
        terminated
            .try_reserve_exact(bytes.len() + 1)
            .map_err(io::Error::other)?;
        terminated.extend_from_slice(bytes);
        terminated.push(0);
        let native = CString::from_vec_with_nul(terminated).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid Linux DNS watch path")
        })?;
        let mut owned = PathBuf::new();
        owned.try_reserve(bytes.len()).map_err(io::Error::other)?;
        owned.push(path);
        result.push(WatchPath {
            path: owned,
            native,
        });
    }
    Ok(result)
}

struct Worker {
    inotify: File,
    netlink: OwnedFd,
    paths: Vec<WatchPath>,
    hostname: String,
}

impl Worker {
    fn new(paths: Vec<WatchPath>) -> io::Result<Self> {
        // SAFETY: inotify_init1 has no pointer arguments. A successful fresh
        // descriptor is adopted exactly once below; flags prevent blocking and
        // exec inheritance. Partial startup drops both RAII owners.
        let descriptor = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: descriptor is the fresh owned result of successful init1.
        let inotify = File::from(unsafe { OwnedFd::from_raw_fd(descriptor) });
        let netlink = network_notifications()?;
        let mut worker = Self {
            inotify,
            netlink,
            paths: Vec::new(),
            hostname: super::hostname()?,
        };
        worker.ensure(paths)?;
        Ok(worker)
    }

    fn ensure(&mut self, paths: Vec<WatchPath>) -> io::Result<()> {
        let additions = paths
            .iter()
            .filter(|path| !self.paths.iter().any(|prior| prior.path == path.path))
            .count();
        if self
            .paths
            .len()
            .checked_add(additions)
            .is_none_or(|count| count > MAX_PATHS)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Linux DNS watch path roster is full",
            ));
        }
        self.paths
            .try_reserve(additions)
            .map_err(io::Error::other)?;
        for path in paths {
            if self.paths.iter().any(|prior| prior.path == path.path) {
                continue;
            }
            let mask = libc::IN_MODIFY
                | libc::IN_ATTRIB
                | libc::IN_CLOSE_WRITE
                | libc::IN_CREATE
                | libc::IN_DELETE
                | libc::IN_MOVED_FROM
                | libc::IN_MOVED_TO
                | libc::IN_DELETE_SELF
                | libc::IN_MOVE_SELF
                | libc::IN_MASK_ADD;
            // SAFETY: the owned inotify descriptor is live. CString is valid
            // and terminated throughout this synchronous call; kernel retains
            // the watch, not our pointer. Closing File removes every watch.
            let descriptor = unsafe {
                libc::inotify_add_watch(self.inotify.as_raw_fd(), path.native.as_ptr(), mask)
            };
            if descriptor < 0 {
                return Err(io::Error::last_os_error());
            }
            self.paths.push(path);
        }
        Ok(())
    }

    fn drain(&mut self, shared: &Shared) -> io::Result<()> {
        observe_hostname(&mut self.hostname, super::hostname()?, shared)?;
        let mut buffer = [0u8; BUFFER_BYTES];
        drain_reads(
            || {
                self.inotify.read(&mut buffer).and_then(|length| {
                    if length == 0 {
                        return Err(super::invalid("Linux DNS inotify reached EOF"));
                    }
                    inotify_events(&buffer[..length])
                })
            },
            shared,
        )?;
        drain_reads(
            || receive_network(self.netlink.as_raw_fd(), &mut buffer),
            shared,
        )
    }
}

fn observe_hostname(current: &mut String, next: String, shared: &Shared) -> io::Result<()> {
    if *current != next {
        *current = next;
        shared.mark()?;
    }
    Ok(())
}

fn run(
    paths: Vec<WatchPath>,
    commands: Receiver<Command>,
    shared: &Shared,
    ready: SyncSender<()>,
) -> io::Result<()> {
    let mut worker = Worker::new(paths)?;
    worker.drain(shared)?;
    if ready.send(()).is_err() {
        return Ok(());
    }
    loop {
        match commands.recv_timeout(POLL_INTERVAL) {
            Ok(Command::Check(reply)) => {
                let result = worker.drain(shared).and_then(|()| shared.observed());
                if let Err(error) = &result {
                    shared.fail(error);
                }
                let failed = result.is_err();
                // A cancelled caller owns no native operation; continue to
                // service the owner even when its reply receiver is gone.
                let _delivered = reply.send(result);
                if failed {
                    return Err(io::Error::other("Linux DNS watch check failed"));
                }
            }
            Ok(Command::Ensure(paths, reply)) => {
                let result = worker.ensure(paths).and_then(|()| worker.drain(shared));
                if let Err(error) = &result {
                    shared.fail(error);
                }
                let failed = result.is_err();
                let _delivered = reply.send(result);
                if failed {
                    return Err(io::Error::other("Linux DNS watch registration failed"));
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => worker.drain(shared)?,
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
        }
    }
}

fn drain_reads(mut receive: impl FnMut() -> io::Result<bool>, shared: &Shared) -> io::Result<()> {
    for _ in 0..MAX_DRAIN_READS {
        match receive() {
            Ok(changed) => {
                if changed {
                    shared.mark()?;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Err(terminal_error(DRAIN_BUSY))
}

fn inotify_events(mut bytes: &[u8]) -> io::Result<bool> {
    if bytes.is_empty() {
        return Err(super::invalid("empty Linux DNS inotify batch"));
    }
    while !bytes.is_empty() {
        if bytes.len() < 16 {
            return Err(super::invalid("truncated Linux DNS inotify header"));
        }
        let mask = u32::from_ne_bytes(
            bytes[4..8]
                .try_into()
                .map_err(|_| super::invalid("invalid inotify mask"))?,
        );
        let name_length = usize::try_from(u32::from_ne_bytes(
            bytes[12..16]
                .try_into()
                .map_err(|_| super::invalid("invalid inotify length"))?,
        ))
        .map_err(|_| super::invalid("invalid inotify length"))?;
        let end = 16usize
            .checked_add(name_length)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| super::invalid("truncated Linux DNS inotify name"))?;
        if name_length > 0 && !bytes[16..end].contains(&0) {
            return Err(super::invalid("unterminated Linux DNS inotify name"));
        }
        if mask
            & (libc::IN_Q_OVERFLOW
                | libc::IN_IGNORED
                | libc::IN_UNMOUNT
                | libc::IN_DELETE_SELF
                | libc::IN_MOVE_SELF)
            != 0
        {
            return Err(super::invalid("Linux DNS inotify notification state lost"));
        }
        bytes = &bytes[end..];
    }
    Ok(true)
}

fn network_notifications() -> io::Result<OwnedFd> {
    // SAFETY: socket has no pointer arguments. It subscribes locally to kernel
    // notifications only; no packet or configuration-changing request is sent.
    let descriptor = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful socket returned a fresh descriptor owned only here.
    let socket = unsafe { OwnedFd::from_raw_fd(descriptor) };
    // SAFETY: sockaddr_nl's integer fields/padding permit all-zero initialization.
    // Family/groups are filled before bind; pid zero requests a kernel ID.
    let mut address: libc::sockaddr_nl = unsafe { zeroed() };
    address.nl_family = libc::AF_NETLINK
        .try_into()
        .map_err(|_| super::invalid("invalid netlink family"))?;
    address.nl_groups = (libc::RTMGRP_LINK | libc::RTMGRP_IPV4_IFADDR | libc::RTMGRP_IPV6_IFADDR)
        .try_into()
        .map_err(|_| super::invalid("invalid netlink groups"))?;
    let length = size_of::<libc::sockaddr_nl>()
        .try_into()
        .map_err(|_| super::invalid("invalid netlink address size"))?;
    // SAFETY: socket is live; address has the correct ABI, family and byte
    // length, and remains readable through this synchronous call.
    let status = unsafe { libc::bind(socket.as_raw_fd(), (&raw const address).cast(), length) };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

fn receive_network(descriptor: libc::c_int, buffer: &mut [u8]) -> io::Result<bool> {
    // SAFETY: all-zero sockaddr_nl is a valid writable output structure.
    let mut address: libc::sockaddr_nl = unsafe { zeroed() };
    let mut length: libc::socklen_t = size_of::<libc::sockaddr_nl>()
        .try_into()
        .map_err(|_| super::invalid("invalid netlink address size"))?;
    // SAFETY: descriptor stays owned by the worker; buffer/address/length are
    // valid writable allocations for the supplied sizes. MSG_TRUNC exposes a
    // too-large datagram length, which is rejected before inspecting the data.
    let received = unsafe {
        libc::recvfrom(
            descriptor,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            (&raw mut address).cast(),
            &raw mut length,
        )
    };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    let received =
        usize::try_from(received).map_err(|_| super::invalid("invalid netlink receive length"))?;
    if received > buffer.len()
        || usize::try_from(length).ok() != Some(size_of::<libc::sockaddr_nl>())
        || i32::from(address.nl_family) != libc::AF_NETLINK
        || address.nl_pid != 0
    {
        return Err(super::invalid(
            "Linux DNS netlink datagram lost or untrusted",
        ));
    }
    netlink_events(&buffer[..received])
}

fn netlink_events(mut bytes: &[u8]) -> io::Result<bool> {
    if bytes.is_empty() {
        return Err(super::invalid("empty Linux DNS netlink datagram"));
    }
    let mut changed = false;
    while !bytes.is_empty() {
        if bytes.len() < 16 {
            return Err(super::invalid("truncated Linux DNS netlink header"));
        }
        let length = usize::try_from(u32::from_ne_bytes(
            bytes[..4]
                .try_into()
                .map_err(|_| super::invalid("invalid netlink length"))?,
        ))
        .map_err(|_| super::invalid("invalid netlink length"))?;
        if length < 16 || length > bytes.len() {
            return Err(super::invalid("invalid Linux DNS netlink frame"));
        }
        let kind = u16::from_ne_bytes(
            bytes[4..6]
                .try_into()
                .map_err(|_| super::invalid("invalid netlink type"))?,
        );
        match i32::from(kind) {
            libc::NLMSG_NOOP | libc::NLMSG_DONE => {}
            libc::NLMSG_OVERRUN => return Err(super::invalid("Linux DNS netlink overrun")),
            libc::NLMSG_ERROR => {
                if length < 36 {
                    return Err(super::invalid("truncated Linux DNS netlink error"));
                }
                let error = i32::from_ne_bytes(
                    bytes[16..20]
                        .try_into()
                        .map_err(|_| super::invalid("invalid netlink error"))?,
                );
                if error != 0 {
                    let error = error
                        .checked_neg()
                        .filter(|error| *error > 0)
                        .ok_or_else(|| super::invalid("invalid netlink errno"))?;
                    return Err(io::Error::from_raw_os_error(error));
                }
            }
            _ => changed = true,
        }
        let aligned = length
            .checked_add(3)
            .map(|length| length & !3)
            .ok_or_else(|| super::invalid("invalid netlink alignment"))?;
        if length == bytes.len() {
            break;
        }
        if aligned > bytes.len() {
            return Err(super::invalid("truncated Linux DNS netlink padding"));
        }
        bytes = &bytes[aligned..];
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generations_distinguish_owner_identity_and_checked_progress() -> io::Result<()> {
        let first = Shared::new();
        let second = Shared::new();
        let before = first.observed()?;
        assert_eq!(before, before.clone());
        assert_ne!(before, second.observed()?);
        first.mark()?;
        assert_ne!(before, first.observed()?);
        first.sequence.store(u64::MAX, Ordering::Relaxed);
        assert!(first.mark().is_err());
        first.finish(STOPPED);
        assert_eq!(first.terminal.load(Ordering::Acquire), GENERATION_EXHAUSTED);
        assert!(first.observed().is_err());
        Ok(())
    }

    #[test]
    fn native_terminal_errors_and_panics_remain_visible_without_io() {
        let native = Arc::new(Shared::new());
        let observer = ConfigurationObserver {
            shared: Arc::clone(&native),
        };
        native.fail(&io::Error::from_raw_os_error(libc::ENOBUFS));
        native.finish(STOPPED);
        assert_eq!(
            observer
                .observed()
                .err()
                .and_then(|error| error.raw_os_error()),
            Some(libc::ENOBUFS)
        );
        let panicked = Arc::new(Shared::new());
        drop(Completion(Arc::clone(&panicked)));
        assert_eq!(panicked.terminal.load(Ordering::Acquire), PANICKED);
    }

    #[test]
    fn hostname_changes_invalidate_without_file_or_adapter_events() -> io::Result<()> {
        let shared = Shared::new();
        let mut current = "first.example".to_owned();
        let before = shared.observed()?;
        observe_hostname(&mut current, "first.example".to_owned(), &shared)?;
        assert_eq!(before, shared.observed()?);
        observe_hostname(&mut current, "next.example".to_owned(), &shared)?;
        assert_ne!(before, shared.observed()?);
        assert_eq!(current, "next.example");
        Ok(())
    }

    fn inotify(mask: u32, name: &[u8]) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1i32.to_ne_bytes());
        bytes.extend_from_slice(&mask.to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        bytes.extend_from_slice(
            &u32::try_from(name.len())
                .map_err(io::Error::other)?
                .to_ne_bytes(),
        );
        bytes.extend_from_slice(name);
        Ok(bytes)
    }

    #[test]
    fn inotify_requires_complete_frames_and_rejects_lost_watches() -> io::Result<()> {
        let valid = inotify(libc::IN_MODIFY, b"resolv.conf\0")?;
        assert!(inotify_events(&valid)?);
        assert!(inotify_events(&inotify(libc::IN_DELETE, b"hosts\0")?)?);
        for mask in [
            libc::IN_Q_OVERFLOW,
            libc::IN_IGNORED,
            libc::IN_UNMOUNT,
            libc::IN_DELETE_SELF,
            libc::IN_MOVE_SELF,
        ] {
            assert!(inotify_events(&inotify(mask, b"")?).is_err());
        }
        assert!(inotify_events(&valid[..valid.len() - 1]).is_err());
        assert!(inotify_events(&inotify(libc::IN_MODIFY, b"missing-nul")?).is_err());
        assert!(inotify_events(&[]).is_err());
        Ok(())
    }

    fn netlink(kind: i32, payload: &[u8]) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &u32::try_from(16 + payload.len())
                .map_err(io::Error::other)?
                .to_ne_bytes(),
        );
        bytes.extend_from_slice(&u16::try_from(kind).map_err(io::Error::other)?.to_ne_bytes());
        bytes.extend_from_slice(&0u16.to_ne_bytes());
        bytes.extend_from_slice(&0u64.to_ne_bytes());
        bytes.extend_from_slice(payload);
        Ok(bytes)
    }

    #[test]
    fn netlink_validates_whole_datagrams_overrun_and_native_errors() -> io::Result<()> {
        let link = netlink(i32::from(libc::RTM_NEWLINK), &[0; 16])?;
        assert!(netlink_events(&link)?);
        assert!(!netlink_events(&netlink(libc::NLMSG_NOOP, b"")?)?);
        assert!(netlink_events(&netlink(libc::NLMSG_OVERRUN, b"")?).is_err());
        let mut error = vec![0; 20];
        error[..4].copy_from_slice(&(-libc::ENOBUFS).to_ne_bytes());
        assert_eq!(
            netlink_events(&netlink(libc::NLMSG_ERROR, &error)?)
                .err()
                .and_then(|error| error.raw_os_error()),
            Some(libc::ENOBUFS)
        );
        error[..4].copy_from_slice(&0i32.to_ne_bytes());
        assert!(!netlink_events(&netlink(libc::NLMSG_ERROR, &error)?)?);
        let mut invalid = link.clone();
        invalid.extend_from_slice(&[0]);
        assert!(netlink_events(&invalid).is_err());
        assert!(netlink_events(&link[..15]).is_err());
        assert!(netlink_events(&netlink(libc::NLMSG_ERROR, &[0; 4])?).is_err());
        assert!(netlink_events(&[]).is_err());
        Ok(())
    }

    #[test]
    fn drain_work_is_bounded_and_interrupts_do_not_fake_a_fence() -> io::Result<()> {
        let shared = Shared::new();
        let result = drain_reads(|| Ok(true), &shared);
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        let result = drain_reads(|| Err(io::Error::from_raw_os_error(libc::EINTR)), &shared);
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        drain_reads(|| Err(io::Error::from_raw_os_error(libc::EAGAIN)), &shared)?;
        Ok(())
    }

    #[test]
    fn bounded_path_preparation_deduplicates_without_logging_paths() -> io::Result<()> {
        let input = vec![PathBuf::from("/private-configuration"); MAX_PATHS];
        assert_eq!(prepare_paths(&input)?.len(), 1);
        assert!(prepare_paths(&[PathBuf::from("relative")]).is_err());
        assert!(prepare_paths(&[PathBuf::from("/bad\0name")]).is_err());
        assert!(prepare_paths(&vec![PathBuf::from("/x"); MAX_PATHS + 1]).is_err());
        Ok(())
    }
}
