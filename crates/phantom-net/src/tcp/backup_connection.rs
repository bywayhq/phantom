//! An IPv4 backup connection for a slow first attempt, the slower attempt's
//! connection a pool keeps, and the address family a pool entry remembers,
//! as [`TcpBackupConnection`](phantom_profile::TcpBackupConnection)
//! describes.

#![allow(
    dead_code,
    reason = "the HTTP connectors take the slower attempt from the next commit"
)]

use std::{
    collections::VecDeque,
    fmt,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use phantom_profile::TcpKeepaliveSchedule;
use tokio::net::TcpStream;

use super::{ProfileTcpStream, TcpKeepaliveControl, is_refusal_or_timeout, no_addresses};

/// An IP address family.
///
/// This is a seam for the facade's pools, not supported API.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AddressFamily {
    /// IPv4.
    Ipv4,
    /// IPv6.
    Ipv6,
}

impl AddressFamily {
    /// The family of `address`.
    #[must_use]
    pub const fn of(address: &SocketAddr) -> Self {
        match address {
            SocketAddr::V4(_) => Self::Ipv4,
            SocketAddr::V6(_) => Self::Ipv6,
        }
    }
}

/// The address family of an origin's connections, which a
/// [`TcpBackupConnection`](phantom_profile::TcpBackupConnection) resolves
/// alone once it is known.
///
/// A pool keeps one per origin and route, as Firefox keeps `mPreferIPv4`
/// and `mPreferIPv6` in its `ConnectionEntry`. The first connection that
/// succeeds sets the family and later ones leave it, unless their attempt
/// gave up on the remembered family; that attempt's family replaces it
/// (`netwerk/protocol/http/ConnectionEntry.cpp:125-149`,
/// `netwerk/protocol/http/DnsAndConnectSocket.cpp:1152-1165` at tag
/// `FIREFOX_157_0_RELEASE`). Clones share one memory.
///
/// This is a seam for the facade's pools, not supported API.
#[doc(hidden)]
#[derive(Clone, Default)]
pub struct AddressFamilyMemory {
    family: Arc<Mutex<Option<AddressFamily>>>,
}

impl AddressFamilyMemory {
    /// A memory with no family yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The remembered family, if any.
    #[must_use]
    pub fn family(&self) -> Option<AddressFamily> {
        *self.family.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Remembers `family` as the first successful connection would.
    pub fn remember(&self, family: AddressFamily) {
        self.record(family, true);
    }

    /// Forgets the family, as Firefox drops the connection entry of an
    /// origin with no connection left at its next prune
    /// (`netwerk/protocol/http/nsHttpConnectionMgr.cpp:2614-2618`).
    pub fn forget(&self) {
        *self.family.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Records the family of a connection to `address` that just
    /// succeeded.
    pub(super) fn record_connection(&self, address: &SocketAddr, switched_family: bool) {
        self.record(AddressFamily::of(address), switched_family);
    }

    fn record(&self, connected: AddressFamily, switched_family: bool) {
        let mut family = self.family.lock().unwrap_or_else(PoisonError::into_inner);
        if switched_family || family.is_none() {
            *family = Some(connected);
        }
    }
}

impl fmt::Debug for AddressFamilyMemory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AddressFamilyMemory")
            .field("family", &self.family())
            .finish()
    }
}

/// What a backup connection knows before it starts.
#[derive(Clone, Copy, Debug)]
pub(super) struct Plan {
    /// The family the origin's pool entry remembers, if any.
    pub(super) family: Option<AddressFamily>,
    /// Longest wait for each backup connect while the family is remembered.
    pub(super) known_family_backup_timeout: Option<Duration>,
}

/// A connection one attempt made.
pub(super) struct Connected<Stream> {
    pub(super) stream: Stream,
    /// When the attempt that made it began.
    pub(super) started: Instant,
    /// The address it connected to.
    pub(super) address: SocketAddr,
    /// Whether the attempt gave up on the remembered family for the other.
    pub(super) switched_family: bool,
}

/// The first connection, and the other attempt when it is still connecting.
pub(super) struct Won<Stream, Attempt, Dial> {
    pub(super) connected: Connected<Stream>,
    pub(super) slower: Option<Slower<Attempt, Dial>>,
}

/// Connects to one of `addresses` the way Firefox 157's `DnsAndConnectSocket`
/// does on release builds.
///
/// Line numbers are for Firefox tag `FIREFOX_157_0_RELEASE`:
///
/// - Without a remembered family, the primary attempt tries every address
///   in resolver order (`netwerk/dns/nsDNSService2.cpp:163-228`), and the
///   backup attempt the IPv4 addresses alone
///   (`netwerk/protocol/http/DnsAndConnectSocket.cpp:179-186`, `:222-225`).
/// - With one, both attempts try that family's addresses, the backup with
///   `known_family_backup_timeout` on each connect, and an attempt that runs
///   out of them tries the other family's (`DnsAndConnectSocket.cpp:167-178`,
///   `:1014-1046`, `:1063`, `:1295-1303`, `:1402-1412`).
/// - When `delay` completes while the primary attempt has not connected, the
///   backup attempt starts (`DnsAndConnectSocket.cpp:242-265`, `:286-290`).
/// - Each attempt moves to its next address only when a connect is refused,
///   finds no route, or times out
///   (`netwerk/base/nsSocketTransport2.cpp:169-200`, `:1747-1755`); any other
///   failure ends that attempt.
/// - The first connection wins. The other attempt, when the backup has
///   started and it has not failed, comes back as [`Won::slower`], which
///   keeps connecting while it is polled; dropping it closes its socket. A
///   primary attempt that ends before the backup starts cancels the backup
///   (`DnsAndConnectSocket.cpp:267-277`). When both attempts fail, the most
///   recent failure is returned.
///
/// `dial` gets each address and the timeout for that connect. `started` is
/// when the host lookup began: the primary attempt began then, and the
/// backup when `delay` ended.
pub(super) async fn connect<Dial, Attempt, Stream, Delay>(
    addresses: Vec<SocketAddr>,
    plan: Plan,
    delay: Delay,
    mut dial: Dial,
    started: Instant,
) -> io::Result<Won<Stream, Attempt, Dial>>
where
    Dial: FnMut(SocketAddr, Option<Duration>) -> Attempt,
    Attempt: Future<Output = io::Result<Stream>>,
    Delay: Future<Output = ()>,
{
    let (primary_addresses, backup_addresses) = match plan.family {
        None => {
            let ipv4 = Addresses {
                family: addresses
                    .iter()
                    .copied()
                    .filter(SocketAddr::is_ipv4)
                    .collect(),
                other_family: None,
                timeout: None,
                switched: false,
            };
            let all = Addresses {
                family: addresses.into(),
                other_family: None,
                timeout: None,
                switched: false,
            };
            (all, ipv4)
        }
        Some(family) => {
            let (known, other): (VecDeque<_>, VecDeque<_>) = addresses
                .into_iter()
                .partition(|address| AddressFamily::of(address) == family);
            let primary = Addresses {
                family: known,
                other_family: Some(other),
                timeout: None,
                switched: false,
            };
            let backup = Addresses {
                timeout: plan.known_family_backup_timeout,
                ..primary.clone()
            };
            (primary, backup)
        }
    };
    let mut primary = Walk::start(primary_addresses, &mut dial, started);
    let mut backup: Option<Walk<Attempt>> = None;
    let mut backup_pending = Some(backup_addresses);
    let mut delay = std::pin::pin!(delay);
    let mut last_error = None;

    loop {
        if primary.is_none() && backup.is_none() {
            return Err(last_error.unwrap_or_else(no_addresses));
        }
        tokio::select! {
            biased;
            result = Walk::finish(&mut primary), if primary.is_some() => {
                let Some(walk) = primary.take() else { continue };
                match result {
                    Ok(stream) => {
                        return Ok(Won {
                            connected: walk.connected(stream),
                            slower: backup.map(|walk| Slower { walk, dial }),
                        });
                    }
                    Err(error) => {
                        primary = walk.next(&error, &mut dial);
                        last_error = Some(error);
                    }
                }
                if primary.is_none() && backup.is_none() {
                    // No backup has started; the timer is cancelled.
                    backup_pending = None;
                }
            }
            result = Walk::finish(&mut backup), if backup.is_some() => {
                let Some(walk) = backup.take() else { continue };
                match result {
                    Ok(stream) => {
                        return Ok(Won {
                            connected: walk.connected(stream),
                            slower: primary.map(|walk| Slower { walk, dial }),
                        });
                    }
                    Err(error) => {
                        backup = walk.next(&error, &mut dial);
                        last_error = Some(error);
                    }
                }
            }
            () = &mut delay, if backup_pending.is_some() && primary.is_some() => {
                if let Some(addresses) = backup_pending.take() {
                    backup = Walk::start(addresses, &mut dial, Instant::now());
                }
            }
        }
    }
}

/// The addresses one attempt may try.
#[derive(Clone)]
struct Addresses {
    /// The remembered family's addresses, or every address it may try when
    /// no family is remembered.
    family: VecDeque<SocketAddr>,
    /// The other family's addresses, tried once `family` runs out, when a
    /// family is remembered.
    other_family: Option<VecDeque<SocketAddr>>,
    /// Longest wait for each connect to `family`.
    timeout: Option<Duration>,
    /// Whether `family` now holds the other family's addresses.
    switched: bool,
}

impl Addresses {
    /// The next address and its timeout, moving to the other family when
    /// this one has none left.
    fn pop(&mut self) -> Option<(SocketAddr, Option<Duration>)> {
        if let Some(address) = self.family.pop_front() {
            return Some((address, self.timeout));
        }
        // The other family is tried without the shorter timeout: Firefox
        // sets it only while it may still switch families
        // (`DnsAndConnectSocket.cpp:1295-1303`).
        self.family = self.other_family.take()?;
        self.timeout = None;
        self.switched = true;
        self.family.pop_front().map(|address| (address, None))
    }
}

/// One attempt: the address being connected and the ones it may try next.
struct Walk<Attempt> {
    connecting: Pin<Box<Attempt>>,
    address: SocketAddr,
    addresses: Addresses,
    started: Instant,
}

impl<Attempt> Walk<Attempt> {
    fn start<Dial>(mut addresses: Addresses, dial: &mut Dial, started: Instant) -> Option<Self>
    where
        Dial: FnMut(SocketAddr, Option<Duration>) -> Attempt,
    {
        let (address, timeout) = addresses.pop()?;
        Some(Self {
            connecting: Box::pin(dial(address, timeout)),
            address,
            addresses,
            started,
        })
    }

    /// The same attempt on its next address, when `error` lets it move on.
    fn next<Dial>(self, error: &io::Error, dial: &mut Dial) -> Option<Self>
    where
        Dial: FnMut(SocketAddr, Option<Duration>) -> Attempt,
    {
        if !is_refusal_or_timeout(error) {
            return None;
        }
        Self::start(self.addresses, dial, self.started)
    }

    fn connected<Stream>(self, stream: Stream) -> Connected<Stream> {
        Connected {
            stream,
            started: self.started,
            address: self.address,
            switched_family: self.addresses.switched,
        }
    }
}

impl<Attempt, Stream> Walk<Attempt>
where
    Attempt: Future<Output = io::Result<Stream>>,
{
    /// Waits for the attempt in `slot`; an empty slot never completes.
    async fn finish(slot: &mut Option<Self>) -> io::Result<Stream> {
        match slot {
            Some(walk) => walk.connecting.as_mut().await,
            None => std::future::pending().await,
        }
    }
}

/// The attempt that did not win, still connecting.
pub(super) struct Slower<Attempt, Dial> {
    walk: Walk<Attempt>,
    dial: Dial,
}

impl<Attempt, Dial, Stream> Slower<Attempt, Dial>
where
    Dial: FnMut(SocketAddr, Option<Duration>) -> Attempt,
    Attempt: Future<Output = io::Result<Stream>>,
{
    /// Connects the attempt, moving through its addresses as the race did.
    pub(super) async fn connect(self) -> io::Result<Connected<Stream>> {
        let Self { mut walk, mut dial } = self;
        loop {
            match walk.connecting.as_mut().await {
                Ok(stream) => return Ok(walk.connected(stream)),
                Err(error) => match walk.next(&error, &mut dial) {
                    Some(next) => walk = next,
                    None => return Err(error),
                },
            }
        }
    }
}

/// Whether the slower attempt of a backup connection has connected.
///
/// A pool counts the slower connection against the bound of the pool key
/// that adopted it from then on, as Firefox counts a connection that has
/// connected, idle or not, and no longer counts the attempt that made it
/// (`netwerk/protocol/http/ConnectionEntry.cpp:289-297`,
/// `netwerk/protocol/http/DnsAndConnectSocket.cpp:609-614`). Clones share one
/// flag.
///
/// This is a seam for the facade's pools, not supported API.
#[doc(hidden)]
#[derive(Clone, Debug, Default)]
pub struct SlowerProgress {
    connected: Arc<AtomicBool>,
}

impl SlowerProgress {
    /// Progress of an attempt that has not connected yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the attempt has connected.
    #[must_use]
    pub fn has_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    /// Records that the attempt connected.
    pub fn mark_connected(&self) {
        self.connected.store(true, Ordering::Release);
    }
}

/// The slower attempt of a backup connection, for a pool to keep.
///
/// It finishes when the attempt has connected and the connection has
/// finished any TLS handshake without a request, ready for one, as Firefox
/// drives the handshake of the slower attempt's connection with a null
/// transaction (`netwerk/protocol/http/DnsAndConnectSocket.cpp:683-743` at
/// tag `FIREFOX_157_0_RELEASE`). It ends with `None` when the attempt or
/// the handshake fails. It makes progress only while it is polled, and
/// dropping it closes its socket.
///
/// This is a seam for the facade's pools, not supported API.
#[doc(hidden)]
pub struct SlowerConnection<C> {
    progress: SlowerProgress,
    future: Pin<Box<dyn Future<Output = Option<C>> + Send>>,
}

impl<C> SlowerConnection<C> {
    /// The slower connection that `future` finishes, which reports its TCP
    /// connect to `progress`.
    pub fn new(
        progress: SlowerProgress,
        future: impl Future<Output = Option<C>> + Send + 'static,
    ) -> Self {
        Self {
            progress,
            future: Box::pin(future),
        }
    }

    /// The attempt's progress, which stays readable once [`Self::finish`]
    /// has taken the connection.
    #[must_use]
    pub fn progress(&self) -> SlowerProgress {
        self.progress.clone()
    }

    /// Connects the attempt and finishes the connection's handshake.
    pub async fn finish(self) -> Option<C> {
        self.future.await
    }
}

impl<C> fmt::Debug for SlowerConnection<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SlowerConnection")
            .field("connected", &self.progress.has_connected())
            .finish_non_exhaustive()
    }
}

/// When the slower attempt's connection starts its keepalive schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SlowerKeepalive {
    /// As it connects, before a TLS handshake: Firefox dispatches the null
    /// transaction that drives the handshake, which starts short-lived
    /// keepalive (`netwerk/protocol/http/nsHttpConnection.cpp:686`).
    BeforeTls,
    /// With its first request: a plaintext connection goes to the idle list
    /// with no transaction (`DnsAndConnectSocket.cpp:711-717`), and the hook
    /// logs show its first keepalive call as that request is dispatched.
    OnFirstRequest,
}

/// The TCP connection of a backup connection's slower attempt.
pub(crate) struct SlowerTcp {
    stream: TcpStream,
    /// The time from the attempt's start until it connected.
    setup: Duration,
    schedule: Option<TcpKeepaliveSchedule>,
}

impl SlowerTcp {
    /// The profile stream, with its keepalive schedule starting as `start`
    /// says.
    pub(crate) fn into_stream(self, start: SlowerKeepalive) -> ProfileTcpStream {
        let keepalive = self.schedule.map(|schedule| match start {
            SlowerKeepalive::BeforeTls => TcpKeepaliveControl::opened(schedule, self.setup),
            SlowerKeepalive::OnFirstRequest => {
                TcpKeepaliveControl::opened_idle(schedule, self.setup)
            }
        });
        ProfileTcpStream {
            stream: self.stream,
            keepalive,
        }
    }
}

type SlowerTcpFuture = Pin<Box<dyn Future<Output = io::Result<SlowerTcp>> + Send>>;

/// The slower attempt of a backup connection at the TCP layer.
pub(crate) struct SlowerAttempt {
    progress: SlowerProgress,
    state: SlowerState,
}

enum SlowerState {
    Connecting(SlowerTcpFuture),
    Connected(SlowerTcp),
    Failed,
}

impl SlowerAttempt {
    /// Wraps the attempt that lost the race, which records its family in
    /// `memory` when it connects.
    pub(super) fn new<Attempt, Dial>(
        slower: Slower<Attempt, Dial>,
        memory: AddressFamilyMemory,
        schedule: Option<TcpKeepaliveSchedule>,
    ) -> Self
    where
        Dial: FnMut(SocketAddr, Option<Duration>) -> Attempt + Send + 'static,
        Attempt: Future<Output = io::Result<TcpStream>> + Send + 'static,
    {
        Self::from_future(async move {
            let connected = slower.connect().await?;
            memory.record_connection(&connected.address, connected.switched_family);
            Ok(SlowerTcp {
                stream: connected.stream,
                setup: connected.started.elapsed(),
                schedule,
            })
        })
    }

    fn from_future(future: impl Future<Output = io::Result<SlowerTcp>> + Send + 'static) -> Self {
        Self {
            progress: SlowerProgress::new(),
            state: SlowerState::Connecting(Box::pin(future)),
        }
    }

    /// A slower attempt that `future` connects, for tests of the layers
    /// above.
    #[cfg(test)]
    pub(crate) fn scripted(
        future: impl Future<Output = io::Result<TcpStream>> + Send + 'static,
        setup: Duration,
        schedule: Option<TcpKeepaliveSchedule>,
    ) -> Self {
        Self::from_future(async move {
            Ok(SlowerTcp {
                stream: future.await?,
                setup,
                schedule,
            })
        })
    }

    /// Whether the attempt has connected, as of its last poll.
    pub(crate) fn has_connected(&self) -> bool {
        self.progress.has_connected()
    }

    pub(crate) fn progress(&self) -> SlowerProgress {
        self.progress.clone()
    }

    /// Runs `future` while the attempt keeps connecting, so it moves to its
    /// next address or connects meanwhile.
    pub(crate) async fn alongside<F: Future>(&mut self, future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        std::future::poll_fn(|context| {
            let _ = self.poll_connect(context);
            future.as_mut().poll(context)
        })
        .await
    }

    /// Waits until the attempt connects or fails.
    pub(crate) async fn connect(mut self) -> io::Result<SlowerTcp> {
        std::future::poll_fn(|context| self.poll_connect(context)).await;
        match self.state {
            SlowerState::Connected(tcp) => Ok(tcp),
            SlowerState::Connecting(_) | SlowerState::Failed => {
                Err(io::Error::other("the slower connection attempt failed"))
            }
        }
    }

    fn poll_connect(&mut self, context: &mut Context<'_>) -> Poll<()> {
        let SlowerState::Connecting(future) = &mut self.state else {
            return Poll::Ready(());
        };
        let Poll::Ready(result) = future.as_mut().poll(context) else {
            return Poll::Pending;
        };
        self.state = match result {
            Ok(tcp) => {
                self.progress.mark_connected();
                SlowerState::Connected(tcp)
            }
            Err(error) => {
                tracing::debug!(error = %error, "slower backup connection attempt failed");
                SlowerState::Failed
            }
        };
        Poll::Ready(())
    }
}

#[cfg(test)]
mod tests;
