//! Host support for profile TCP socket options.
//!
//! Outgoing TCP sockets are opened with a profile's [`TcpSettings`].
//! [`check_host_support`] reports, before any I/O, whether this host can apply
//! those settings exactly as written.

use std::{error::Error, fmt, io, net::SocketAddr};

use phantom_profile::{TcpKeepalive, TcpSettings};
use socket2::SockRef;
use tokio::net::{TcpSocket, TcpStream};

use crate::host_resolver::HostResolver;

mod address_racing;

/// Resolves `host`, through `resolver` when there is one, and connects to one
/// of its addresses.
///
/// Each attempt opens a fresh socket and applies `settings` before
/// connecting, as a browser does, so the options already cover the TLS
/// handshake. With [`TcpSettings::address_racing`] the addresses race as
/// [`address_racing::race`] describes; otherwise they are tried one at a time
/// in resolver order. Either way, if every attempt fails, the most recent
/// failure is returned.
pub(crate) async fn connect(
    host: &str,
    port: u16,
    settings: TcpSettings,
    resolver: Option<&HostResolver>,
) -> io::Result<TcpStream> {
    check_settings(&settings)?;
    let addresses = crate::host_resolver::resolve(resolver, host, port).await?;
    connect_resolved(addresses, settings).await
}

fn check_settings(settings: &TcpSettings) -> io::Result<()> {
    settings
        .validate()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    // A client built through the facade has already passed this check; a
    // connector used directly still must not drop an option silently.
    check_host_support(settings).map_err(|error| io::Error::new(io::ErrorKind::Unsupported, error))
}

/// Connects to one of `addresses`, already resolved, as [`connect`] does.
pub(crate) async fn connect_resolved(
    addresses: Vec<SocketAddr>,
    settings: TcpSettings,
) -> io::Result<TcpStream> {
    check_settings(&settings)?;
    match settings.address_racing {
        Some(racing) => {
            let fallback = crate::shutdown_timer::after(racing.fallback_delay).map_err(|_| {
                io::Error::other("could not schedule the connection fallback timer")
            })?;
            // The deadline service never drops a pending deadline, so a
            // receive error cannot occur; treating one as expiry still keeps
            // the second attempt from being lost.
            let fallback = async {
                let _ = fallback.await;
            };
            address_racing::race(addresses, fallback, |address| {
                connect_address(address, settings)
            })
            .await
        }
        None => {
            let mut last_error = None;
            for address in addresses {
                match connect_address(address, settings).await {
                    Ok(stream) => return Ok(stream),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(no_addresses))
        }
    }
}

fn no_addresses() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "could not resolve to any addresses",
    )
}

async fn connect_address(address: SocketAddr, settings: TcpSettings) -> io::Result<TcpStream> {
    let socket = match address {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    apply_options(&socket, settings)?;
    socket.connect(address).await
}

/// Applies every option `settings` asks for, failing on the first rejection.
///
/// Chromium ignores a failure to set these options
/// (`net/socket/tcp_socket_win.cc:70-71` at tag `154.0.8037.58`). Phantom
/// fails the attempt instead, so a connection never proceeds with socket
/// options the profile did not ask for.
fn apply_options(socket: &TcpSocket, settings: TcpSettings) -> io::Result<()> {
    let socket = SockRef::from(socket);
    if settings.nodelay {
        socket
            .set_tcp_nodelay(true)
            .map_err(|error| option_error("TCP_NODELAY", error))?;
    }
    if let Some(keepalive) = settings.keepalive {
        socket
            .set_tcp_keepalive(&keepalive_parameters(keepalive)?)
            .map_err(|error| option_error("TCP keepalive", error))?;
    }
    Ok(())
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
/// or when Windows would need an interval the settings leave unset.
pub fn check_host_support(settings: &TcpSettings) -> Result<(), UnsupportedTcpSettings> {
    check_keepalive_support(settings, HOST_KEEPALIVE)
}

fn check_keepalive_support(
    settings: &TcpSettings,
    support: KeepaliveSupport,
) -> Result<(), UnsupportedTcpSettings> {
    let Some(keepalive) = settings.keepalive else {
        return Ok(());
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
    }

    thread_local! {
        static SOCKETS: RefCell<Vec<ObservedSocket>> = const { RefCell::new(Vec::new()) };
    }

    pub(crate) fn record(stream: &TcpStream) {
        let socket = SockRef::from(stream);
        let observed = ObservedSocket {
            nodelay: socket.tcp_nodelay().unwrap_or(false),
            keepalive: socket.keepalive().unwrap_or(false),
        };
        SOCKETS.with(|sockets| sockets.borrow_mut().push(observed));
    }

    /// Returns and clears the sockets connected on this thread.
    pub(crate) fn take() -> Vec<ObservedSocket> {
        SOCKETS.with(|sockets| std::mem::take(&mut *sockets.borrow_mut()))
    }
}

#[cfg(test)]
mod tests;
