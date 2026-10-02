//! Profile UDP sockets: the options a profile sets before a socket binds,
//! and a bind that survives a Windows reserved port block.
//!
//! Every UDP socket that carries QUIC opens here: the socket of a direct
//! QUIC connection, of the connection to a CONNECT-UDP proxy, and of a SOCKS5
//! UDP association.

use std::{io, net::SocketAddr};

use phantom_profile::UdpSettings;
use socket2::{Domain, Protocol, SockRef, Socket, Type};

use crate::source_binding::{SourceBinding, bind_error};

/// `WSAENOBUFS`, Windows' "no buffer space available".
const WSAENOBUFS: i32 = 10_055;

/// How many times a refused bind to port 0 is retried.
const RESERVED_PORT_RETRIES: usize = 3;

/// Opens a UDP socket that sends to `remote`, sets the options `settings`
/// asks for, and binds it.
///
/// The socket binds to `source`'s address for `remote`'s family, or to
/// `default_local` when there is no binding or it has no address of that
/// family. Chromium sets `SO_RANDOMIZE_PORT` right before the `connect` that
/// gives its UDP sockets their port (`net/socket/udp_socket_win.cc:563-575`
/// at tag `154.0.8037.58`); Phantom binds its sockets instead, and Windows
/// rejects the option once a socket is bound, so the options come first,
/// then the binding's interface, then the bind. A bind to port 0 that
/// Windows refuses at a reserved port block is retried.
pub(crate) fn bind_socket(
    remote: SocketAddr,
    default_local: SocketAddr,
    source: Option<&SourceBinding>,
    settings: Option<UdpSettings>,
) -> io::Result<std::net::UdpSocket> {
    let local = match source {
        Some(source) => source.udp_local_address(remote, default_local)?,
        None => default_local,
    };
    let socket = Socket::new(Domain::for_address(local), Type::DGRAM, Some(Protocol::UDP))?;
    if let Some(settings) = settings {
        apply_options(&socket, settings)?;
    }
    if let Some(source) = source {
        source.bind_interface(&SockRef::from(&socket))?;
    }
    // A socket whose bind failed is still unbound and keeps its options, so
    // the retry binds it again rather than opening another.
    retry_past_reserved_ports(cfg!(windows), local.port(), || socket.bind(&local.into())).map_err(
        |error| match source {
            Some(_) => bind_error("UDP", local.ip(), error),
            None => error,
        },
    )?;
    #[cfg(test)]
    observed::record(&socket);
    Ok(socket.into())
}

/// Applies every option `settings` sets before the bind, failing on the
/// first rejection.
///
/// Chromium ignores a failure to set `SO_RANDOMIZE_PORT`
/// (`net/socket/udp_socket_win.cc:564-568` at tag `154.0.8037.58`). Phantom
/// fails the socket instead, so a connection never proceeds with socket
/// options the profile did not ask for.
fn apply_options(socket: &Socket, settings: UdpSettings) -> io::Result<()> {
    if settings.port_randomization {
        randomize_port(socket)?;
    }
    Ok(())
}

#[cfg(windows)]
fn randomize_port(socket: &Socket) -> io::Result<()> {
    use std::os::windows::io::AsSocket;

    crate::windows_port_randomization::enable(socket.as_socket()).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("failed to set the profile's SO_RANDOMIZE_PORT UDP socket option: {error}"),
        )
    })
}

/// Only Windows has `SO_RANDOMIZE_PORT`; see [`UdpSettings`].
#[cfg(not(windows))]
fn randomize_port(_socket: &Socket) -> io::Result<()> {
    Ok(())
}

/// Runs `bind`, and when `windows` is set and `port` is 0, runs it again
/// after each `WSAENOBUFS`, at most [`RESERVED_PORT_RETRIES`] times.
///
/// Windows hands out UDP ephemeral ports from one counter for the whole host.
/// When the counter reaches a block of reserved ports (`netsh int ipv4 show
/// excludedportrange protocol=udp`), the bind to port 0 can fail with
/// `WSAENOBUFS` (os error 10055, logged as Tcpip event 4266) instead of
/// skipping the block, and the counter moves past it, so the next bind gets
/// a port. Any other error, an explicit port, or another platform returns the
/// first result.
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

/// Options read back from each UDP socket bound on the test thread.
#[cfg(test)]
pub(crate) mod observed {
    use std::cell::RefCell;

    use socket2::Socket;

    /// Options of one bound UDP socket, read back from the OS.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct ObservedSocket {
        /// `SO_RANDOMIZE_PORT`, always `false` off Windows.
        pub(crate) random_port: bool,
    }

    thread_local! {
        static SOCKETS: RefCell<Vec<ObservedSocket>> = const { RefCell::new(Vec::new()) };
    }

    pub(super) fn record(socket: &Socket) {
        let observed = ObservedSocket {
            random_port: random_port(socket),
        };
        SOCKETS.with(|sockets| sockets.borrow_mut().push(observed));
    }

    #[cfg(windows)]
    fn random_port(socket: &Socket) -> bool {
        use std::os::windows::io::AsSocket;

        crate::windows_port_randomization::is_enabled(socket.as_socket()).unwrap_or(false)
    }

    #[cfg(not(windows))]
    fn random_port(_socket: &Socket) -> bool {
        false
    }

    /// How many sockets have been bound on this thread since the last
    /// [`take`].
    pub(crate) fn count() -> usize {
        SOCKETS.with(|sockets| sockets.borrow().len())
    }

    /// Returns and clears the sockets bound on this thread.
    pub(crate) fn take() -> Vec<ObservedSocket> {
        SOCKETS.with(|sockets| std::mem::take(&mut *sockets.borrow_mut()))
    }
}

#[cfg(test)]
mod tests;
