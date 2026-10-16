//! The sockets Phantom's own DNS queries leave from.
//!
//! hickory opens one UDP socket per query through its `RuntimeProvider`.
//! [`QuerySockets`] opens each through [`crate::udp::bind_socket`], so a
//! query socket gets the profile's [`UdpSettings`] before it binds and
//! survives a Windows reserved port block as a QUIC socket does. TCP
//! connections, which carry a query only after a truncated UDP response, are
//! hickory's own.
//!
//! hickory sends a UDP query while the task that awaits the lookup polls
//! it. [`notify_sent_queries`] marks such a lookup, so its first sent
//! datagram can release another lookup that must go after it.

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use hickory_resolver::net::runtime::{
    DnsUdpSocket, RuntimeProvider, TokioRuntimeProvider, TokioTime,
};
use phantom_profile::UdpSettings;
use tokio::sync::Notify;

tokio::task_local! {
    /// Notified each time a query datagram of the marked lookup is sent.
    static SENT: Arc<Notify>;
}

/// Runs `lookup`, notifying `sent` each time it sends a UDP query datagram.
///
/// The notice comes from the socket's send, which runs inside the polls of
/// `lookup` on the task that awaits it.
pub(crate) async fn notify_sent_queries<F: Future>(sent: Arc<Notify>, lookup: F) -> F::Output {
    SENT.scope(sent, lookup).await
}

/// A hickory runtime whose UDP sockets open with a profile's UDP settings.
#[derive(Clone, Default)]
pub(crate) struct QuerySockets {
    tokio: TokioRuntimeProvider,
    udp: Option<UdpSettings>,
    scopes: Arc<[(SocketAddr, SocketAddr)]>,
}

impl QuerySockets {
    pub(crate) fn new(udp: Option<UdpSettings>) -> Self {
        Self {
            tokio: TokioRuntimeProvider::default(),
            udp,
            scopes: Arc::default(),
        }
    }

    pub(super) fn with_scopes(mut self, scopes: Arc<[(SocketAddr, SocketAddr)]>) -> Self {
        self.scopes = scopes;
        self
    }

    fn endpoint(&self, address: SocketAddr) -> SocketAddr {
        self.scopes
            .iter()
            .find_map(|(key, native)| (*key == address).then_some(*native))
            .unwrap_or(address)
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
    type Udp = QuerySocket;
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
        self.tokio
            .connect_tcp(self.endpoint(server_addr), bind_addr, timeout)
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        let udp = self.udp;
        let native_addr = self.endpoint(server_addr);
        Box::pin(async move {
            let socket = crate::udp::bind_socket(native_addr, local_addr, None, udp)?;
            socket.set_nonblocking(true)?;
            Ok(QuerySocket {
                socket: tokio::net::UdpSocket::from_std(socket)?,
                server_addr,
                native_addr,
            })
        })
    }
}

/// A query socket that reports each sent datagram to a marked lookup.
pub(crate) struct QuerySocket {
    socket: tokio::net::UdpSocket,
    server_addr: SocketAddr,
    native_addr: SocketAddr,
}

impl DnsUdpSocket for QuerySocket {
    type Time = TokioTime;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        match DnsUdpSocket::poll_recv_from(&self.socket, cx, buf) {
            Poll::Ready(Ok((size, source))) if self.server_addr != self.native_addr => {
                if !same_scoped_peer(source, self.native_addr) {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "DNS reply arrived from a different scoped endpoint",
                    )));
                }
                Poll::Ready(Ok((size, self.server_addr)))
            }
            received => received,
        }
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        let target = if target == self.server_addr {
            self.native_addr
        } else {
            target
        };
        let sent = DnsUdpSocket::poll_send_to(&self.socket, cx, buf, target);
        if let Poll::Ready(Ok(_)) = sent {
            let _ = SENT.try_with(|notify| notify.notify_one());
        }
        sent
    }
}

fn same_scoped_peer(source: SocketAddr, expected: SocketAddr) -> bool {
    source.ip() == expected.ip()
        && source.port() == expected.port()
        && match (source, expected) {
            (SocketAddr::V6(source), SocketAddr::V6(expected)) => {
                source.scope_id() == expected.scope_id()
            }
            _ => true,
        }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddrV6};

    #[test]
    fn a_scoped_dns_endpoint_is_restored_without_accepting_another_interface() {
        let ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 53);
        let plain = SocketAddr::new(ip.into(), 53);
        let scoped = SocketAddr::V6(SocketAddrV6::new(ip, 53, 0, 7));
        let sockets = QuerySockets::new(None).with_scopes(Arc::from([(plain, scoped)]));
        assert_eq!(sockets.endpoint(plain), scoped);
        assert!(same_scoped_peer(scoped, scoped));
        assert!(!same_scoped_peer(plain, scoped));
        assert!(!same_scoped_peer(
            SocketAddr::V6(SocketAddrV6::new(ip, 53, 0, 8)),
            scoped,
        ));
        assert!(same_scoped_peer(
            SocketAddr::V6(SocketAddrV6::new(ip, 53, 123, 7)),
            scoped,
        ));
    }
}
