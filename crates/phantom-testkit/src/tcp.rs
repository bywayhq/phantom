//! A loopback TCP port that refuses connections until a test listens on it.
//!
//! A test that wants a refused connect followed by a server at the same
//! address cannot close a probe listener and bind its address again later:
//! while the port is closed any socket on the host can take it, either a
//! listener in another test process or the ephemeral source port of an
//! outgoing connection. On Windows, which answers a refused loopback connect
//! after about two seconds and hands out ephemeral ports in sequence, that
//! surfaces as `AddrInUse` (10048) on the later bind, or as a stranger's
//! connection reaching the test's server.
//!
//! [`ReservedPort`](crate::tcp::ReservedPort) therefore keeps the port bound
//! without listening, which Linux and Windows refuse. macOS does not: XNU's
//! `tcp_input` silently drops a segment whose socket is bound but in the
//! `CLOSED` state (`DROP_REASON_TCP_CLOSED`, `bsd/netinet/tcp_input.c`), so
//! the client retransmits its SYN until the connect fails about eight seconds
//! later. On macOS the port is closed while the test waits for the refusal
//! and bound again by
//! [`ReservedPort::listen`](crate::tcp::ReservedPort::listen). macOS picks
//! ephemeral ports at random (`net.inet.ip.portrange.randomized`), so another
//! socket rarely lands on the port in that window.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
};

use tokio::net::{TcpListener, TcpSocket};

/// The accept backlog of [`ReservedPort::listen`].
const BACKLOG: u32 = 1024;

/// A loopback TCP port whose connects are refused until
/// [`ReservedPort::listen`] turns it into a listener at the same address.
///
/// On Linux and Windows the port stays bound, so no other socket can take it
/// while the test runs. On macOS it is released until `listen`; see the
/// [module documentation](self).
#[derive(Debug)]
pub struct ReservedPort {
    #[cfg(not(target_os = "macos"))]
    socket: TcpSocket,
    address: SocketAddr,
}

impl ReservedPort {
    /// Picks a free port on `127.0.0.1`.
    ///
    /// # Errors
    ///
    /// Returns the socket or bind error.
    pub fn bind() -> io::Result<Self> {
        let socket = TcpSocket::new_v4()?;
        socket.bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let address = socket.local_addr()?;
        // A bound socket that is not listening drops connects on macOS
        // instead of refusing them; only a free port refuses there.
        #[cfg(target_os = "macos")]
        drop(socket);
        Ok(Self {
            #[cfg(not(target_os = "macos"))]
            socket,
            address,
        })
    }

    /// Returns the reserved address.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Starts accepting on the reserved address.
    ///
    /// # Errors
    ///
    /// Returns the bind or listen error. On macOS the bind fails with
    /// `AddrInUse` when another socket took the port after [`Self::bind`].
    ///
    /// # Panics
    ///
    /// Panics when called outside a Tokio runtime with I/O enabled, as
    /// [`TcpSocket::listen`] does.
    pub fn listen(self) -> io::Result<TcpListener> {
        #[cfg(target_os = "macos")]
        let socket = {
            let socket = TcpSocket::new_v4()?;
            socket.set_reuseaddr(true)?;
            socket.bind(self.address)?;
            socket
        };
        #[cfg(not(target_os = "macos"))]
        let socket = self.socket;
        socket.listen(BACKLOG)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        time::{Duration, Instant},
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };

    use super::ReservedPort;

    /// Windows answers a refused loopback connect after about two seconds;
    /// a connect that macOS drops instead takes about eight.
    const REFUSAL_BOUND: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn a_connect_is_refused_until_the_port_listens() -> io::Result<()> {
        let reserved = ReservedPort::bind()?;
        let address = reserved.address();

        let started = Instant::now();
        let refused = TcpStream::connect(address).await;
        assert!(started.elapsed() < REFUSAL_BOUND, "{:?}", started.elapsed());
        assert_eq!(
            refused.map(drop).map_err(|error| error.kind()),
            Err(io::ErrorKind::ConnectionRefused)
        );

        let listener = reserved.listen()?;
        assert_eq!(listener.local_addr()?, address);
        let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        let mut client = client?;
        let (mut server, _) = accepted?;
        client.write_all(b"x").await?;
        let mut byte = [0; 1];
        server.read_exact(&mut byte).await?;
        assert_eq!(&byte, b"x");
        Ok(())
    }
}
