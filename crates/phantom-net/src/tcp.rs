//! Outgoing TCP sockets opened with a profile's socket options.

use std::{io, net::SocketAddr};

use phantom_profile::{TcpKeepalive, TcpSettings};
use socket2::SockRef;
use tokio::net::{TcpSocket, TcpStream};

/// Resolves `host` and connects to its addresses in resolver order.
///
/// Each attempt opens a fresh socket and applies `settings` before
/// connecting, as a browser does, so the options already cover the TLS
/// handshake. The first successful connection wins; if every address fails,
/// the last attempt's error is returned.
pub(crate) async fn connect(host: &str, port: u16, settings: TcpSettings) -> io::Result<TcpStream> {
    settings
        .validate()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut last_error = None;
    for address in tokio::net::lookup_host((host, port)).await? {
        match connect_address(address, settings).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "could not resolve to any addresses",
        )
    }))
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
/// (`net/socket/tcp_socket_win.cc:71-72` at tag `153.0.8010.48`). Phantom
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

fn keepalive_parameters(keepalive: TcpKeepalive) -> io::Result<socket2::TcpKeepalive> {
    let parameters = socket2::TcpKeepalive::new().with_time(keepalive.idle);
    match keepalive.interval {
        Some(interval) => with_interval(parameters, interval),
        // `SIO_KEEPALIVE_VALS` sets the idle time and the interval together;
        // socket2 would send an interval of zero milliseconds.
        None if cfg!(windows) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a TCP keepalive interval is required on Windows",
        )),
        None => Ok(parameters),
    }
}

#[cfg(any(
    target_os = "android",
    target_os = "freebsd",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "windows",
))]
fn with_interval(
    parameters: socket2::TcpKeepalive,
    interval: std::time::Duration,
) -> io::Result<socket2::TcpKeepalive> {
    Ok(parameters.with_interval(interval))
}

#[cfg(not(any(
    target_os = "android",
    target_os = "freebsd",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "windows",
)))]
fn with_interval(
    _parameters: socket2::TcpKeepalive,
    _interval: std::time::Duration,
) -> io::Result<socket2::TcpKeepalive> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "a TCP keepalive interval is not supported on this platform",
    ))
}

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
