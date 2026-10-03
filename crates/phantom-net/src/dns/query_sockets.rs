//! The sockets Phantom's own DNS queries leave from.
//!
//! hickory opens one UDP socket per query through its `RuntimeProvider`.
//! [`QuerySockets`] opens each through [`crate::udp::bind_socket`], so a
//! query socket gets the profile's [`UdpSettings`] before it binds and
//! survives a Windows reserved port block as a QUIC socket does. TCP
//! connections, which carry a query only after a truncated UDP response, are
//! hickory's own.

use std::{future::Future, io, net::SocketAddr, pin::Pin, time::Duration};

use hickory_resolver::net::runtime::{RuntimeProvider, TokioRuntimeProvider};
use phantom_profile::UdpSettings;

/// A hickory runtime whose UDP sockets open with a profile's UDP settings.
#[derive(Clone, Default)]
pub(crate) struct QuerySockets {
    tokio: TokioRuntimeProvider,
    udp: Option<UdpSettings>,
}

impl QuerySockets {
    pub(crate) fn new(udp: Option<UdpSettings>) -> Self {
        Self {
            tokio: TokioRuntimeProvider::default(),
            udp,
        }
    }

    /// Whether hickory should bind port 0 and leave the port to the
    /// operating system rather than pick a random one itself.
    ///
    /// `SO_RANDOMIZE_PORT` changes only the port Windows picks, so it
    /// applies when the socket binds port 0. Chromium's built-in DNS client
    /// connects its UDP sockets through the path that sets the option
    /// (`net/dns/dns_transaction.cc:696-700`, `net/socket/udp_socket_win.cc:559-575`
    /// at tag `154.0.8037.58`). Elsewhere Chromium binds a random port itself
    /// (`net/socket/udp_socket_posix.cc:1564-1575`), as hickory does.
    pub(crate) fn leaves_port_to_the_os(&self) -> bool {
        cfg!(windows) && self.udp.is_some_and(|udp| udp.port_randomization)
    }
}

impl RuntimeProvider for QuerySockets {
    type Handle = <TokioRuntimeProvider as RuntimeProvider>::Handle;
    type Timer = <TokioRuntimeProvider as RuntimeProvider>::Timer;
    type Udp = <TokioRuntimeProvider as RuntimeProvider>::Udp;
    type Tcp = <TokioRuntimeProvider as RuntimeProvider>::Tcp;

    fn create_handle(&self) -> Self::Handle {
        self.tokio.create_handle()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        self.tokio.connect_tcp(server_addr, bind_addr, timeout)
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        let udp = self.udp;
        Box::pin(async move {
            let socket = crate::udp::bind_socket(server_addr, local_addr, None, udp)?;
            socket.set_nonblocking(true)?;
            tokio::net::UdpSocket::from_std(socket)
        })
    }
}
