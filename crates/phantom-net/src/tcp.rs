//! Profile TCP connections: socket options, address selection, and
//! keepalive.
//!
//! Outgoing TCP sockets are opened with a profile's [`TcpSettings`].
//! [`check_host_support`] reports, before any I/O, whether this host can apply
//! those settings exactly as written.

use std::{
    error::Error,
    fmt, io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use phantom_profile::{
    TcpAddressAdvance, TcpAddressSelection, TcpKeepalive, TcpKeepalivePolicy, TcpPortRandomization,
    TcpSettings,
};
use socket2::SockRef;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpSocket, TcpStream},
};

use crate::{host_resolver::HostResolver, source_binding::SourceBinding};

mod address_racing;
mod backup_connection;
mod keepalive_schedule;

pub use backup_connection::{AddressFamily, AddressFamilyMemory, SlowerConnection, SlowerProgress};
pub(crate) use backup_connection::{SlowerAttempt, SlowerKeepalive};
pub(crate) use keepalive_schedule::TcpKeepaliveControl;

/// A TCP connection opened with a profile's [`TcpSettings`].
///
/// With a [`TcpKeepalivePolicy::Schedule`], the HTTP layers report the
/// connection's life to it, and each read and write first brings the
/// socket's keepalive up to date, so a change always precedes the bytes
/// written after it.
pub(crate) struct ProfileTcpStream {
    stream: TcpStream,
    keepalive: Option<TcpKeepaliveControl>,
}

impl ProfileTcpStream {
    /// A stream without a keepalive schedule.
    pub(crate) fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            keepalive: None,
        }
    }

    /// Returns the remote address of the connection.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error when the socket has none.
    #[cfg(any(test, feature = "https-records"))]
    pub(crate) fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    /// Returns the local address of the connection.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error when the socket has none.
    #[cfg(test)]
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    #[cfg(test)]
    pub(crate) fn tcp_stream(&self) -> &TcpStream {
        &self.stream
    }

    /// The bare stream, without a keepalive schedule. A connection that
    /// carries no HTTP, such as a SOCKS5 UDP association's control
    /// connection, takes it before any I/O, so no keepalive is set on it;
    /// otherwise its keepalive stays as last applied.
    pub(crate) fn into_tcp_stream(self) -> TcpStream {
        self.stream
    }

    fn apply_keepalive(&self, context: &Context<'_>) -> io::Result<()> {
        match &self.keepalive {
            Some(keepalive) => keepalive.apply(&self.stream, context.waker()),
            None => Ok(()),
        }
    }
}

impl AsyncRead for ProfileTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.apply_keepalive(context)?;
        Pin::new(&mut this.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for ProfileTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.apply_keepalive(context)?;
        Pin::new(&mut this.stream).poll_write(context, buffer)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.apply_keepalive(context)?;
        Pin::new(&mut this.stream).poll_write_vectored(context, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
    }
}

/// A byte stream that may run over a [`ProfileTcpStream`], whose keepalive
/// schedule the HTTP layers on top of it then report to.
pub(crate) trait TcpKeepaliveSource {
    /// The schedule's control, when the TCP connection underneath has one.
    fn tcp_keepalive(&self) -> Option<TcpKeepaliveControl>;
}

impl TcpKeepaliveSource for ProfileTcpStream {
    fn tcp_keepalive(&self) -> Option<TcpKeepaliveControl> {
        self.keepalive.clone()
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsSocket for ProfileTcpStream {
    fn as_socket(&self) -> std::os::windows::io::BorrowedSocket<'_> {
        self.stream.as_socket()
    }
}

#[cfg(unix)]
impl std::os::fd::AsFd for ProfileTcpStream {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.stream.as_fd()
    }
}

impl fmt::Debug for ProfileTcpStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProfileTcpStream")
            .field("stream", &self.stream)
            .field("keepalive_schedule", &self.keepalive.is_some())
            .finish()
    }
}

/// Resolves `host`, through `resolver` when there is one, and connects to one
/// of its addresses.
///
/// Each attempt opens a fresh socket, applies `settings` when there are any,
/// and binds it as `source` says before connecting, as a browser applies its
/// options, so they already cover the TLS handshake. The addresses are tried
/// as [`TcpSettings::address_selection`] says; if every attempt fails, the
/// most recent failure is returned. A source binding with an address for
/// only one family skips the addresses of the other; see [`SourceBinding`].
///
/// For a [`TcpAddressSelection::Backup`], `family` is the origin's address
/// family, which the connection uses and updates, and the slower attempt
/// comes back when the backup started and that attempt is still connecting.
/// Without `family` the slower attempt is closed.
pub(crate) async fn connect_keeping_slower(
    host: &str,
    port: u16,
    settings: Option<TcpSettings>,
    source: Option<&SourceBinding>,
    resolver: Option<&HostResolver>,
    family: Option<&AddressFamilyMemory>,
) -> io::Result<(ProfileTcpStream, Option<SlowerAttempt>)> {
    check_settings(settings.as_ref(), source)?;
    let started = Instant::now();
    let addresses = crate::host_resolver::resolve(resolver, host, port).await?;
    connect_resolved_keeping_slower(addresses, settings, source, started, family).await
}

/// Connects as [`connect_keeping_slower`] does without a family, closing any
/// slower attempt.
#[cfg(test)]
pub(crate) async fn connect(
    host: &str,
    port: u16,
    settings: Option<TcpSettings>,
    source: Option<&SourceBinding>,
    resolver: Option<&HostResolver>,
) -> io::Result<ProfileTcpStream> {
    connect_keeping_slower(host, port, settings, source, resolver, None)
        .await
        .map(|(stream, _)| stream)
}

fn check_settings(
    settings: Option<&TcpSettings>,
    source: Option<&SourceBinding>,
) -> io::Result<()> {
    if let Some(source) = source {
        source
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    }
    let Some(settings) = settings else {
        return Ok(());
    };
    settings
        .validate()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    // A client built through the facade has already passed this check; a
    // connector used directly still must not drop an option silently.
    check_host_support(settings).map_err(|error| io::Error::new(io::ErrorKind::Unsupported, error))
}

/// Connects to one of `addresses`, already resolved, as
/// [`connect_keeping_slower`] does without a family, closing any slower
/// attempt.
///
/// `started` is when the host lookup began; a keepalive schedule takes its
/// probe interval from the time since then.
#[cfg(any(test, feature = "https-records"))]
pub(crate) async fn connect_resolved(
    addresses: Vec<SocketAddr>,
    settings: Option<TcpSettings>,
    source: Option<&SourceBinding>,
    started: Instant,
) -> io::Result<ProfileTcpStream> {
    connect_resolved_keeping_slower(addresses, settings, source, started, None)
        .await
        .map(|(stream, _)| stream)
}

/// Connects to one of `addresses`, already resolved, as
/// [`connect_keeping_slower`] does.
///
/// `started` is when the host lookup began; a keepalive schedule takes its
/// probe interval from the time since then.
pub(crate) async fn connect_resolved_keeping_slower(
    addresses: Vec<SocketAddr>,
    settings: Option<TcpSettings>,
    source: Option<&SourceBinding>,
    started: Instant,
    family: Option<&AddressFamilyMemory>,
) -> io::Result<(ProfileTcpStream, Option<SlowerAttempt>)> {
    check_settings(settings.as_ref(), source)?;
    // A schedule that could never switch would silently keep short-lived
    // keepalive; once the deadline service runs, it stays available.
    if settings
        .is_some_and(|settings| matches!(settings.keepalive, TcpKeepalivePolicy::Schedule(_)))
        && !crate::shutdown_timer::is_available()
    {
        return Err(io::Error::other(
            "could not start the keepalive schedule's timer",
        ));
    }
    let addresses = match source {
        Some(source) => source.usable_addresses(addresses)?,
        None => addresses,
    };
    let selection = settings.map_or_else(TcpAddressSelection::default, |settings| {
        settings.address_selection
    });
    let dial = |address| connect_address(address, settings, source);
    let schedule = match settings.map(|settings| settings.keepalive) {
        Some(TcpKeepalivePolicy::Schedule(schedule)) => Some(schedule),
        Some(TcpKeepalivePolicy::Unchanged | TcpKeepalivePolicy::Fixed(_)) | None => None,
        Some(_) => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                UnsupportedTcpSettings::unknown_policy("keepalive"),
            ));
        }
    };
    let (stream, attempt_started, slower) = match selection {
        TcpAddressSelection::Sequential(advance) => (
            connect_sequentially(addresses, advance, dial).await?,
            started,
            None,
        ),
        TcpAddressSelection::Racing(racing) => {
            let fallback = deadline(racing.fallback_delay)?;
            let stream = address_racing::race(addresses, fallback, dial).await?;
            (stream, started, None)
        }
        TcpAddressSelection::Backup(backup) => {
            let delay = deadline(backup.delay)?;
            let plan = backup_connection::Plan {
                family: family.and_then(AddressFamilyMemory::family),
                known_family_backup_timeout: backup.known_family_backup_timeout,
            };
            // The slower attempt outlives this call, so its dials own what
            // they use.
            let source = source.cloned();
            let dial = move |address, timeout| {
                let source = source.clone();
                async move { connect_address_within(address, settings, source.as_ref(), timeout).await }
            };
            let won = backup_connection::connect(addresses, plan, delay, dial, started).await?;
            let connected = won.connected;
            let slower = family.and_then(|memory| {
                memory.record_connection(&connected.address, connected.switched_family);
                won.slower
                    .map(|slower| SlowerAttempt::new(slower, memory.clone(), schedule))
            });
            (connected.stream, connected.started, slower)
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                UnsupportedTcpSettings::unknown_policy("address_selection"),
            ));
        }
    };
    let keepalive =
        schedule.map(|schedule| TcpKeepaliveControl::opened(schedule, attempt_started.elapsed()));
    Ok((ProfileTcpStream { stream, keepalive }, slower))
}

/// Tries `addresses` one at a time in resolver order, moving on after the
/// failures `advance` names and returning any other failure at once.
async fn connect_sequentially<Dial, Attempt, Stream>(
    addresses: Vec<SocketAddr>,
    advance: TcpAddressAdvance,
    mut dial: Dial,
) -> io::Result<Stream>
where
    Dial: FnMut(SocketAddr) -> Attempt,
    Attempt: std::future::Future<Output = io::Result<Stream>>,
{
    let stop_on_other_failure = match advance {
        TcpAddressAdvance::AfterAnyFailure => false,
        TcpAddressAdvance::AfterRefusalOrTimeout => true,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                UnsupportedTcpSettings::unknown_policy("address_selection.advance"),
            ));
        }
    };
    let mut last_error = None;
    for address in addresses {
        match dial(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => {
                if stop_on_other_failure && !is_refusal_or_timeout(&error) {
                    return Err(error);
                }
                last_error = Some(error);
            }
        }
    }
    Err(last_error.unwrap_or_else(no_addresses))
}

/// Whether Firefox tries the next address after this failure: a refused
/// connect, which it also reports for an unreachable network or host, an
/// unavailable address, and a denied connect, or a timeout
/// (`netwerk/base/nsSocketTransport2.cpp:169-200` at tag
/// `FIREFOX_157_0_RELEASE`).
fn is_refusal_or_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::TimedOut
    )
}

/// A delay from the deadline service.
fn deadline(delay: Duration) -> io::Result<impl std::future::Future<Output = ()>> {
    let deadline = crate::shutdown_timer::after(delay)
        .map_err(|_| io::Error::other("could not schedule the connection fallback timer"))?;
    // The deadline service never drops a pending deadline, so a receive
    // error cannot occur; treating one as expiry still keeps the second
    // attempt from being lost.
    Ok(async {
        let _ = deadline.await;
    })
}

fn no_addresses() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "could not resolve to any addresses",
    )
}

/// Connects as [`connect_address`] does, failing with
/// [`io::ErrorKind::TimedOut`] once `timeout` passes.
async fn connect_address_within(
    address: SocketAddr,
    settings: Option<TcpSettings>,
    source: Option<&SourceBinding>,
    timeout: Option<Duration>,
) -> io::Result<TcpStream> {
    within_connect_timeout(timeout, connect_address(address, settings, source)).await
}

/// Runs `connect`, failing with [`io::ErrorKind::TimedOut`] once `timeout`
/// passes, which moves a backup attempt to its next address.
async fn within_connect_timeout<T>(
    timeout: Option<Duration>,
    connect: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    let Some(timeout) = timeout else {
        return connect.await;
    };
    let expired = deadline(timeout)?;
    tokio::select! {
        biased;
        result = connect => result,
        () = expired => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the backup connect timed out",
        )),
    }
}

async fn connect_address(
    address: SocketAddr,
    settings: Option<TcpSettings>,
    source: Option<&SourceBinding>,
) -> io::Result<TcpStream> {
    if let Some(settings) = settings {
        check_policy_support(&settings)
            .map_err(|error| io::Error::new(io::ErrorKind::Unsupported, error))?;
    }
    let socket = match address {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    if let Some(settings) = settings {
        apply_options(&socket, settings)?;
    }
    if let Some(source) = source {
        source.bind_tcp(&socket, address)?;
    }
    socket.connect(address).await
}

/// Applies every option `settings` sets before `connect`, failing on the
/// first rejection.
///
/// Chromium ignores a failure to set these options
/// (`net/socket/tcp_socket_win.cc:70-71` at tag `154.0.8037.58`), and so does
/// Firefox (`netwerk/base/nsSocketTransport2.cpp:1449-1465` at tag
/// `FIREFOX_157_0_RELEASE`). Phantom fails the attempt instead, so a
/// connection never proceeds with socket options the profile did not ask
/// for. A keepalive schedule sets nothing here: it starts once the socket
/// has connected. Port randomization comes last, as in Chromium's call
/// order, and before a source binding binds the socket, which Windows
/// requires.
fn apply_options(socket: &TcpSocket, settings: TcpSettings) -> io::Result<()> {
    let fixed_keepalive = match settings.keepalive {
        TcpKeepalivePolicy::Fixed(keepalive) => Some(keepalive),
        TcpKeepalivePolicy::Unchanged | TcpKeepalivePolicy::Schedule(_) => None,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                UnsupportedTcpSettings::unknown_policy("keepalive"),
            ));
        }
    };
    let socket = SockRef::from(socket);
    if settings.nodelay {
        socket
            .set_tcp_nodelay(true)
            .map_err(|error| option_error("TCP_NODELAY", error))?;
    }
    if let Some(size) = settings.send_buffer_size {
        let size = usize::try_from(size.get())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        socket
            .set_send_buffer_size(size)
            .map_err(|error| option_error("SO_SNDBUF", error))?;
    }
    if let Some(keepalive) = fixed_keepalive {
        socket
            .set_tcp_keepalive(&keepalive_parameters(keepalive)?)
            .map_err(|error| option_error("TCP keepalive", error))?;
    }
    if let Some(randomization) = settings.port_randomization {
        randomize_port(&socket, randomization)?;
    }
    Ok(())
}

/// Sets `SO_RANDOMIZE_PORT` when this Windows is at least
/// `randomization.minimum_windows_build`.
#[cfg(windows)]
fn randomize_port(socket: &socket2::Socket, randomization: TcpPortRandomization) -> io::Result<()> {
    use std::os::windows::io::AsSocket;

    if !host_reaches_build(randomization.minimum_windows_build)? {
        return Ok(());
    }
    crate::socket_ffi::port_randomization::enable(socket.as_socket())
        .map_err(|error| option_error("SO_RANDOMIZE_PORT", error))
}

/// Only Windows has `SO_RANDOMIZE_PORT`; see [`TcpPortRandomization`].
#[cfg(not(windows))]
fn randomize_port(
    _socket: &socket2::Socket,
    _randomization: TcpPortRandomization,
) -> io::Result<()> {
    Ok(())
}

/// Whether the running Windows is version 10.0 at `minimum_build` or later,
/// or a later major version. The version is read once.
#[cfg(windows)]
fn host_reaches_build(minimum_build: u32) -> io::Result<bool> {
    use crate::socket_ffi::port_randomization::{WindowsVersion, windows_version};

    static HOST: std::sync::OnceLock<Option<WindowsVersion>> = std::sync::OnceLock::new();
    let version = HOST.get_or_init(windows_version).ok_or_else(|| {
        option_error(
            "SO_RANDOMIZE_PORT",
            io::Error::other("could not read the Windows version"),
        )
    })?;
    Ok(reaches_build(version.major, version.build, minimum_build))
}

#[cfg(any(windows, test))]
fn reaches_build(major: u32, build: u32, minimum_build: u32) -> bool {
    major > 10 || (major == 10 && build >= minimum_build)
}

/// Builds socket2 keepalive parameters for settings that
/// [`check_host_support`] accepted, so every requested value is applied.
fn keepalive_parameters(keepalive: TcpKeepalive) -> io::Result<socket2::TcpKeepalive> {
    let parameters = socket2::TcpKeepalive::new().with_time(keepalive.idle);
    match keepalive.interval {
        Some(interval) => with_interval(parameters, interval),
        None => Ok(parameters),
    }
}

// The targets of socket2 0.6.5's `TcpKeepalive::with_interval`, less Cygwin,
// a tier 3 target that Phantom does not build or test; an interval there is
// rejected by `check_host_support` instead of being applied unverified.
#[cfg(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "emscripten",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "illumos",
    target_os = "ios",
    target_os = "visionos",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "windows",
    target_os = "nuttx",
    all(target_os = "wasi", not(target_env = "p1")),
))]
fn with_interval(
    parameters: socket2::TcpKeepalive,
    interval: std::time::Duration,
) -> io::Result<socket2::TcpKeepalive> {
    Ok(parameters.with_interval(interval))
}

#[cfg(not(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "emscripten",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "illumos",
    target_os = "ios",
    target_os = "visionos",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "windows",
    target_os = "nuttx",
    all(target_os = "wasi", not(target_env = "p1")),
)))]
fn with_interval(
    _parameters: socket2::TcpKeepalive,
    _interval: std::time::Duration,
) -> io::Result<socket2::TcpKeepalive> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        UNSUPPORTED_INTERVAL,
    ))
}

/// Which keepalive values the host's socket API can apply.
#[derive(Clone, Copy, Debug)]
struct KeepaliveSupport {
    /// socket2 0.6.5 sets no idle time on OpenBSD, Haiku, or Vita (its
    /// `sys::unix::set_tcp_keepalive`), so a requested one would be dropped.
    idle: bool,
    /// The targets of socket2 0.6.5's `TcpKeepalive::with_interval`, less
    /// Cygwin (see `with_interval`).
    interval: bool,
    /// Windows applies both values through `SIO_KEEPALIVE_VALS`, where an
    /// unset interval becomes zero milliseconds rather than a system default.
    interval_required: bool,
}

const HOST_KEEPALIVE: KeepaliveSupport = KeepaliveSupport {
    idle: !cfg!(any(
        target_os = "openbsd",
        target_os = "haiku",
        target_os = "vita"
    )),
    interval: cfg!(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "emscripten",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "visionos",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "windows",
        target_os = "nuttx",
        all(target_os = "wasi", not(target_env = "p1")),
    )),
    interval_required: cfg!(windows),
};

const UNSUPPORTED_INTERVAL: &str = "this platform cannot set a TCP keepalive interval";

/// Checks that this host can apply `settings` exactly, without I/O.
///
/// Settings that pass [`TcpSettings::validate`] can still be impossible on a
/// particular operating system. They are rejected here rather than applied
/// partially; only a rejection by the operating system itself remains a
/// connection-time failure.
///
/// # Errors
///
/// Returns [`UnsupportedTcpSettings`] when this platform cannot set a
/// keepalive idle time, when an interval is requested where none can be set,
/// or when Windows would need an interval the settings leave unset. It also
/// rejects unknown keepalive, address-selection, and address-advance policies.
pub fn check_host_support(settings: &TcpSettings) -> Result<(), UnsupportedTcpSettings> {
    check_policy_support(settings)?;
    check_keepalive_support(settings, HOST_KEEPALIVE)
}

fn check_policy_support(settings: &TcpSettings) -> Result<(), UnsupportedTcpSettings> {
    match settings.keepalive {
        TcpKeepalivePolicy::Unchanged
        | TcpKeepalivePolicy::Fixed(_)
        | TcpKeepalivePolicy::Schedule(_) => {}
        _ => return Err(UnsupportedTcpSettings::unknown_policy("keepalive")),
    }
    match settings.address_selection {
        TcpAddressSelection::Sequential(advance) => match advance {
            TcpAddressAdvance::AfterAnyFailure | TcpAddressAdvance::AfterRefusalOrTimeout => {}
            _ => {
                return Err(UnsupportedTcpSettings::unknown_policy(
                    "address_selection.advance",
                ));
            }
        },
        TcpAddressSelection::Racing(_) | TcpAddressSelection::Backup(_) => {}
        _ => return Err(UnsupportedTcpSettings::unknown_policy("address_selection")),
    }
    Ok(())
}

fn check_keepalive_support(
    settings: &TcpSettings,
    support: KeepaliveSupport,
) -> Result<(), UnsupportedTcpSettings> {
    let keepalive = match settings.keepalive {
        TcpKeepalivePolicy::Unchanged => return Ok(()),
        TcpKeepalivePolicy::Fixed(keepalive) => keepalive,
        // A schedule always sets an interval, which Windows requires anyway.
        TcpKeepalivePolicy::Schedule(_) => {
            if !support.idle {
                return Err(UnsupportedTcpSettings {
                    field: "keepalive.short_lived_idle",
                    message: "this platform cannot set a TCP keepalive idle time",
                });
            }
            if !support.interval {
                return Err(UnsupportedTcpSettings {
                    field: "keepalive.minimum_interval",
                    message: UNSUPPORTED_INTERVAL,
                });
            }
            return Ok(());
        }
        _ => return Err(UnsupportedTcpSettings::unknown_policy("keepalive")),
    };
    if !support.idle {
        return Err(UnsupportedTcpSettings {
            field: "keepalive.idle",
            message: "this platform cannot set a TCP keepalive idle time",
        });
    }
    match keepalive.interval {
        Some(_) if !support.interval => Err(UnsupportedTcpSettings {
            field: "keepalive.interval",
            message: UNSUPPORTED_INTERVAL,
        }),
        None if support.interval_required => Err(UnsupportedTcpSettings {
            field: "keepalive.interval",
            message: "Windows requires a TCP keepalive interval with the idle time",
        }),
        _ => Ok(()),
    }
}

/// Error returned when this host cannot apply profile TCP settings as written.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsupportedTcpSettings {
    field: &'static str,
    message: &'static str,
}

impl UnsupportedTcpSettings {
    fn unknown_policy(field: &'static str) -> Self {
        Self {
            field,
            message: "the configured policy is not implemented",
        }
    }

    /// Returns the setting's field name.
    #[must_use]
    pub fn field(&self) -> &'static str {
        self.field
    }
}

impl fmt::Display for UnsupportedTcpSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unsupported TCP {} on this host: {}",
            self.field, self.message
        )
    }
}

impl Error for UnsupportedTcpSettings {}

fn option_error(option: &str, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("failed to set the profile's {option} socket option: {error}"),
    )
}

/// Socket options read back from each connected stream on the test thread.
#[cfg(test)]
pub(crate) mod observed {
    use std::cell::RefCell;

    use socket2::SockRef;
    use tokio::net::TcpStream;

    /// Options of one connected client socket, read back from the OS.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct ObservedSocket {
        pub(crate) nodelay: bool,
        pub(crate) keepalive: bool,
        /// `SO_RANDOMIZE_PORT`, always `false` off Windows.
        pub(crate) random_port: bool,
    }

    thread_local! {
        static SOCKETS: RefCell<Vec<ObservedSocket>> = const { RefCell::new(Vec::new()) };
    }

    pub(crate) fn record(stream: &TcpStream) {
        let socket = SockRef::from(stream);
        let observed = ObservedSocket {
            nodelay: socket.tcp_nodelay().unwrap_or(false),
            keepalive: socket.keepalive().unwrap_or(false),
            random_port: random_port(stream),
        };
        SOCKETS.with(|sockets| sockets.borrow_mut().push(observed));
    }

    #[cfg(windows)]
    fn random_port(stream: &TcpStream) -> bool {
        use std::os::windows::io::AsSocket;

        crate::socket_ffi::port_randomization::is_enabled(stream.as_socket()).unwrap_or(false)
    }

    #[cfg(not(windows))]
    fn random_port(_stream: &TcpStream) -> bool {
        false
    }

    /// Returns and clears the sockets connected on this thread.
    pub(crate) fn take() -> Vec<ObservedSocket> {
        SOCKETS.with(|sockets| std::mem::take(&mut *sockets.borrow_mut()))
    }
}

#[cfg(test)]
mod tests;
