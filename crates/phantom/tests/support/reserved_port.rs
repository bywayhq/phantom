//! A loopback TCP port held for the whole test.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
};

use tokio::net::{TcpListener, TcpSocket};

/// A loopback TCP port that is bound but not listening.
///
/// Connects to it are refused, and since the socket stays bound, no other
/// socket on the host can take the port: not a listener in another test
/// process, and not the ephemeral source port of an outgoing connection.
/// Closing a probe listener and reusing its address leaves both of those
/// open, which surfaces as `AddrInUse` when the test later binds the address
/// or as a stranger's connection reaching the test's server.
pub(crate) struct ReservedPort {
    socket: TcpSocket,
    address: SocketAddr,
}

impl ReservedPort {
    pub(crate) fn bind() -> io::Result<Self> {
        let socket = TcpSocket::new_v4()?;
        socket.bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let address = socket.local_addr()?;
        Ok(Self { socket, address })
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    /// Starts accepting on the reserved address without releasing it.
    #[allow(dead_code)]
    pub(crate) fn listen(self) -> io::Result<TcpListener> {
        self.socket.listen(1024)
    }
}
