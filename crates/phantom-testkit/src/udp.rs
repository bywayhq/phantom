//! UDP sockets for loopback test peers that survive a Windows reserved port
//! block.
//!
//! Windows hands out UDP ephemeral ports from one counter for the whole host.
//! When the counter reaches a block of reserved ports (`netsh int ipv4 show
//! excludedportrange protocol=udp`), a bind to port 0 can fail with
//! `WSAENOBUFS` (os error 10055, logged as Tcpip event 4266) instead of
//! skipping the block, and the counter moves past it, so the next bind gets a
//! port. These functions retry that bind as `phantom-net` does for its own
//! sockets; they repeat its rule here because `phantom-net` depends on this
//! crate for its tests.

use std::{io, net::SocketAddr};

/// `WSAENOBUFS`, Windows' "no buffer space available".
const WSAENOBUFS: i32 = 10_055;

/// How many times a refused bind to port 0 is retried.
const RESERVED_PORT_RETRIES: usize = 3;

/// Binds a UDP socket to `local`, as [`std::net::UdpSocket::bind`] does, and
/// retries a bind to port 0 that Windows refuses at a reserved port block.
///
/// # Errors
///
/// Returns the bind error.
pub fn bind(local: SocketAddr) -> io::Result<std::net::UdpSocket> {
    retry_past_reserved_ports(cfg!(windows), local.port(), || {
        std::net::UdpSocket::bind(local)
    })
}

/// Binds a Tokio UDP socket to `local` as [`bind`] does.
///
/// # Errors
///
/// Returns the bind error.
///
/// # Panics
///
/// Panics when called outside a Tokio runtime with I/O enabled, as
/// [`tokio::net::UdpSocket::from_std`] does.
pub fn bind_tokio(local: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
    let socket = bind(local)?;
    socket.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(socket)
}

/// Runs `bind`, and when `windows` is set and `port` is 0, runs it again
/// after each `WSAENOBUFS`, at most [`RESERVED_PORT_RETRIES`] times.
fn retry_past_reserved_ports<T>(
    windows: bool,
    port: u16,
    mut bind: impl FnMut() -> io::Result<T>,
) -> io::Result<T> {
    let mut retries = 0;
    loop {
        match bind() {
            Err(error)
                if windows
                    && port == 0
                    && retries < RESERVED_PORT_RETRIES
                    && error.raw_os_error() == Some(WSAENOBUFS) =>
            {
                retries += 1;
            }
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::{WSAENOBUFS, retry_past_reserved_ports};

    /// `WSAEADDRINUSE`.
    const WSAEADDRINUSE: i32 = 10_048;

    /// Returns the OS error of the retry's result over `outcomes`, if any, and
    /// how many binds it made.
    fn retry_over(windows: bool, port: u16, outcomes: &[Option<i32>]) -> (Option<i32>, usize) {
        let mut binds = 0;
        let result = retry_past_reserved_ports(windows, port, || {
            let outcome = outcomes.get(binds).copied().flatten();
            binds += 1;
            outcome.map_or(Ok(()), |code| Err(io::Error::from_raw_os_error(code)))
        });
        (result.err().and_then(|error| error.raw_os_error()), binds)
    }

    #[test]
    fn windows_retries_a_bind_to_port_zero_refused_at_a_reserved_block() {
        assert_eq!(retry_over(true, 0, &[Some(WSAENOBUFS), None]), (None, 2));
    }

    #[test]
    fn windows_returns_the_error_after_three_retries() {
        assert_eq!(
            retry_over(true, 0, &[Some(WSAENOBUFS); 5]),
            (Some(WSAENOBUFS), 4)
        );
    }

    #[test]
    fn other_bind_errors_are_not_retried() {
        assert_eq!(
            retry_over(true, 0, &[Some(WSAEADDRINUSE), None]),
            (Some(WSAEADDRINUSE), 1)
        );
    }

    #[test]
    fn explicit_ports_and_other_platforms_are_not_retried() {
        assert_eq!(
            retry_over(true, 443, &[Some(WSAENOBUFS), None]),
            (Some(WSAENOBUFS), 1)
        );
        assert_eq!(
            retry_over(false, 0, &[Some(WSAENOBUFS), None]),
            (Some(WSAENOBUFS), 1)
        );
    }
}
