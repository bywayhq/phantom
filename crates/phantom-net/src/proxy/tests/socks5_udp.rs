use std::{
    future::poll_fn,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use quinn::{AsyncUdpSocket, udp};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};

use super::super::{Socks5Auth, socks5_udp::associate_socks5_udp_local_with_auth};

use super::TestResult;

const TARGET_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const TARGET: SocketAddr = SocketAddr::new(IpAddr::V4(TARGET_IP), 443);
const RECEIVE_BUFFER_BYTES: usize = 1_500;
const RECEIVE_DEADLINE: Duration = Duration::from_secs(5);

#[tokio::test]
async fn oversized_relayed_datagram_is_dropped_and_later_datagrams_are_delivered() -> TestResult {
    let association = Association::open().await?;
    association
        .relay_to_client(&vec![0x5a; RECEIVE_BUFFER_BYTES + 1])
        .await?;
    association.relay_to_client(b"after").await?;

    assert_eq!(association.receive().await?, b"after");
    Ok(())
}

#[tokio::test]
async fn datagram_from_a_non_relay_source_is_dropped() -> TestResult {
    let association = Association::open().await?;
    let spoofer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    spoofer
        .send_to(&relayed(b"spoofed"), association.client)
        .await?;
    association.relay_to_client(b"relayed").await?;

    assert_eq!(association.receive().await?, b"relayed");
    Ok(())
}

struct Association {
    socket: Arc<dyn AsyncUdpSocket>,
    relay: UdpSocket,
    client: SocketAddr,
    _close_control: oneshot::Sender<()>,
    _proxy: JoinHandle<io::Result<()>>,
}

impl Association {
    async fn open() -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = listener.local_addr()?;
        let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let relay_address = relay.local_addr()?;
        let (close_control, closed) = oneshot::channel();
        let proxy = tokio::spawn(async move {
            let (control, _) = listener.accept().await?;
            serve_udp_associate(control, relay_address, closed).await
        });

        let association = associate_socks5_udp_local_with_auth(
            "127.0.0.1",
            proxy_address.port(),
            TARGET,
            Socks5Auth::None,
        )
        .await?;
        let (socket, _) = association.into_parts();
        let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), socket.local_addr()?.port());
        Ok(Self {
            socket,
            relay,
            client,
            _close_control: close_control,
            _proxy: proxy,
        })
    }

    async fn relay_to_client(&self, payload: &[u8]) -> io::Result<()> {
        self.relay
            .send_to(&relayed(payload), self.client)
            .await
            .map(drop)
    }

    async fn receive(&self) -> TestResult<Vec<u8>> {
        let mut buffer = vec![0; RECEIVE_BUFFER_BYTES];
        let mut meta = [udp::RecvMeta::default()];
        let received = timeout(
            RECEIVE_DEADLINE,
            poll_fn(|context| {
                let mut bufs = [IoSliceMut::new(&mut buffer)];
                self.socket.poll_recv(context, &mut bufs, &mut meta)
            }),
        )
        .await
        .map_err(|_| "SOCKS5 UDP socket received nothing")??;
        assert_eq!(received, 1);
        assert_eq!(meta[0].addr, TARGET);
        Ok(buffer[..meta[0].len].to_vec())
    }
}

async fn serve_udp_associate(
    mut control: TcpStream,
    relay: SocketAddr,
    closed: oneshot::Receiver<()>,
) -> io::Result<()> {
    let mut greeting = [0; 3];
    control.read_exact(&mut greeting).await?;
    control.write_all(&[5, 0]).await?;
    let mut request = [0; 10];
    control.read_exact(&mut request).await?;
    let IpAddr::V4(relay_ip) = relay.ip() else {
        return Err(io::Error::other("test relay must be IPv4"));
    };
    let mut reply = vec![5, 0, 0, 1];
    reply.extend_from_slice(&relay_ip.octets());
    reply.extend_from_slice(&relay.port().to_be_bytes());
    control.write_all(&reply).await?;
    let _ = closed.await;
    control.shutdown().await
}

fn relayed(payload: &[u8]) -> Vec<u8> {
    let mut datagram = vec![0, 0, 0, 1];
    datagram.extend_from_slice(&TARGET_IP.octets());
    datagram.extend_from_slice(&TARGET.port().to_be_bytes());
    datagram.extend_from_slice(payload);
    datagram
}
