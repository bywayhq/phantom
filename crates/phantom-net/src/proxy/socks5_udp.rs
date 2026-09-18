use std::{
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, ready},
};

use quinn::{AsyncUdpSocket, UdpPoller, udp};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

use super::socks5::{Socks5Auth, Socks5Error, Socks5ErrorKind, connect_proxy, trace_connect};

const VERSION: u8 = 5;
const NO_AUTHENTICATION: u8 = 0;
const USERNAME_PASSWORD: u8 = 2;
const NO_ACCEPTABLE_METHODS: u8 = 0xff;
const UDP_ASSOCIATE: u8 = 3;
const IPV4: u8 = 1;
const DOMAIN: u8 = 3;
const IPV6: u8 = 4;
const MAX_UDP_PACKET_BYTES: usize = 65_507;
const MAX_PACKETS_PER_POLL: usize = 32;

/// One local-DNS, single-target SOCKS5 UDP association.
///
/// The socket retains the TCP control connection for its complete lifetime.
/// Its Quinn-facing address is the fixed origin, while every physical datagram
/// is sent only to the relay selected by the SOCKS5 peer.
pub(crate) struct Socks5UdpAssociation {
    socket: Arc<Socks5UdpSocket>,
    target: SocketAddr,
}

impl Socks5UdpAssociation {
    pub(crate) fn into_parts(self) -> (Arc<dyn AsyncUdpSocket>, SocketAddr) {
        (self.socket, self.target)
    }
}

/// Opens one RFC 1928 UDP ASSOCIATE for a locally resolved, fixed IP target.
///
/// A concrete relay address is accepted as sent. For compatibility with
/// proxies that return an unspecified `BND.ADDR`, the established TCP peer's
/// IP address is substituted while preserving `BND.PORT`. Domain relay
/// addresses and a zero relay port are rejected; no non-proxy address is ever
/// inferred. The request advertises an unspecified client address and zero
/// port because a remote proxy, not Phantom, observes any external UDP tuple.
pub(crate) async fn associate_socks5_udp_local_with_auth(
    proxy_host: &str,
    proxy_port: u16,
    target: SocketAddr,
    auth: Socks5Auth<'_>,
) -> Result<Socks5UdpAssociation, Socks5Error> {
    trace_connect("local", async {
        let auth = auth.validate()?;
        if target.port() == 0 {
            return Err(Socks5Error::without_source(Socks5ErrorKind::InvalidTarget));
        }
        tokio::runtime::Handle::try_current()
            .map_err(|_| Socks5Error::without_source(Socks5ErrorKind::RuntimeUnavailable))?;

        let mut control = connect_proxy(proxy_host, proxy_port).await?;
        negotiate_authentication(&mut control, auth).await?;

        let control_local = control
            .local_addr()
            .map_err(|error| Socks5Error::io(Socks5ErrorKind::Negotiation, error))?;
        let control_peer = control
            .peer_addr()
            .map_err(|error| Socks5Error::io(Socks5ErrorKind::Negotiation, error))?;
        let mut client_bind = control_local;
        client_bind.set_port(0);
        let udp = UdpSocket::bind(client_bind)
            .await
            .map_err(|error| Socks5Error::io(Socks5ErrorKind::Connect, error))?;
        let client_udp = udp
            .local_addr()
            .map_err(|error| Socks5Error::io(Socks5ErrorKind::Negotiation, error))?;

        let association_client = SocketAddr::new(
            match client_udp.ip() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            },
            0,
        );
        write_udp_associate(&mut control, association_client).await?;
        let relay = read_udp_associate_reply(&mut control, control_peer).await?;
        if relay.is_ipv4() != client_udp.is_ipv4() {
            return Err(invalid_negotiation(
                "SOCKS5 UDP relay address family differs from the bound UDP socket",
            ));
        }

        let logical_local = SocketAddr::new(
            match target.ip() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            },
            client_udp.port(),
        );
        let target_header = encode_udp_target(target);
        let socket = Arc::new(Socks5UdpSocket {
            udp,
            _control: control,
            relay,
            target,
            logical_local,
            target_header,
            send_buffer: Mutex::new(Vec::with_capacity(MAX_UDP_PACKET_BYTES)),
            receive_buffer: Mutex::new(vec![0; MAX_UDP_PACKET_BYTES]),
        });
        Ok(Socks5UdpAssociation { socket, target })
    })
    .await
}

#[derive(Debug)]
struct Socks5UdpSocket {
    udp: UdpSocket,
    _control: TcpStream,
    relay: SocketAddr,
    target: SocketAddr,
    logical_local: SocketAddr,
    target_header: Vec<u8>,
    send_buffer: Mutex<Vec<u8>>,
    receive_buffer: Mutex<Vec<u8>>,
}

impl AsyncUdpSocket for Socks5UdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Socks5UdpPoller { socket: self })
    }

    fn try_send(&self, transmit: &udp::Transmit<'_>) -> io::Result<()> {
        if transmit.destination != self.target {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS5 UDP association received a different logical target",
            ));
        }
        if transmit.segment_size.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS5 UDP association does not support segmented sends",
            ));
        }
        let packet_len = self
            .target_header
            .len()
            .checked_add(transmit.contents.len())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "UDP packet is too large")
            })?;
        if packet_len > MAX_UDP_PACKET_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS5 UDP packet is too large",
            ));
        }

        let mut packet = lock(&self.send_buffer);
        packet.clear();
        packet.extend_from_slice(&self.target_header);
        packet.extend_from_slice(transmit.contents);
        let sent = self.udp.try_send_to(&packet, self.relay)?;
        if sent != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "SOCKS5 UDP relay accepted a partial datagram",
            ));
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        context: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }

        for _ in 0..MAX_PACKETS_PER_POLL {
            let mut packet = lock(&self.receive_buffer);
            let mut read = tokio::io::ReadBuf::new(&mut packet);
            let from = ready!(self.udp.poll_recv_from(context, &mut read))?;
            if from != self.relay {
                continue;
            }
            let received = read.filled();
            let Some((source, header_len)) = decode_udp_target(received) else {
                continue;
            };
            if source != self.target {
                continue;
            }
            let payload = &received[header_len..];
            if payload.len() > bufs[0].len() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SOCKS5 UDP payload exceeds the QUIC receive buffer",
                )));
            }
            bufs[0][..payload.len()].copy_from_slice(payload);
            meta[0] = udp::RecvMeta {
                addr: self.target,
                len: payload.len(),
                stride: payload.len(),
                ecn: None,
                dst_ip: None,
            };
            return Poll::Ready(Ok(1));
        }

        context.waker().wake_by_ref();
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.logical_local)
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

#[derive(Debug)]
struct Socks5UdpPoller {
    socket: Arc<Socks5UdpSocket>,
}

impl UdpPoller for Socks5UdpPoller {
    fn poll_writable(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.udp.poll_send_ready(context)
    }
}

async fn negotiate_authentication<S>(
    stream: &mut S,
    auth: Socks5Auth<'_>,
) -> Result<(), Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match auth {
        Socks5Auth::None => write_all(stream, &[VERSION, 1, NO_AUTHENTICATION]).await?,
        Socks5Auth::UsernamePassword { .. } => {
            write_all(stream, &[VERSION, 2, NO_AUTHENTICATION, USERNAME_PASSWORD]).await?;
        }
    }

    let mut selection = [0; 2];
    read_exact(stream, &mut selection).await?;
    if selection[0] != VERSION {
        return Err(invalid_negotiation(
            "SOCKS5 method selection used an invalid version",
        ));
    }
    match (selection[1], auth) {
        (NO_AUTHENTICATION, _) => Ok(()),
        (USERNAME_PASSWORD, Socks5Auth::UsernamePassword { username, password }) => {
            let mut request = Vec::with_capacity(3 + username.len() + password.len());
            request.push(1);
            request.push(username.len() as u8);
            request.extend_from_slice(username.as_bytes());
            request.push(password.len() as u8);
            request.extend_from_slice(password.as_bytes());
            write_all(stream, &request).await?;

            let mut response = [0; 2];
            read_exact(stream, &mut response).await?;
            if response[0] != 1 {
                return Err(invalid_negotiation(
                    "SOCKS5 authentication response used an invalid version",
                ));
            }
            if response[1] != 0 {
                return Err(Socks5Error::without_source(Socks5ErrorKind::Authentication));
            }
            Ok(())
        }
        (NO_ACCEPTABLE_METHODS | USERNAME_PASSWORD, _) => {
            Err(Socks5Error::without_source(Socks5ErrorKind::Authentication))
        }
        _ => Err(invalid_negotiation(
            "SOCKS5 proxy selected an unsupported authentication method",
        )),
    }
}

async fn write_udp_associate<S>(stream: &mut S, client: SocketAddr) -> Result<(), Socks5Error>
where
    S: AsyncWrite + Unpin,
{
    let mut request = Vec::with_capacity(4 + address_len(client.ip()) + 2);
    request.extend_from_slice(&[VERSION, UDP_ASSOCIATE, 0]);
    encode_address(client, &mut request);
    write_all(stream, &request).await
}

async fn read_udp_associate_reply<S>(
    stream: &mut S,
    proxy_peer: SocketAddr,
) -> Result<SocketAddr, Socks5Error>
where
    S: AsyncRead + Unpin,
{
    let mut head = [0; 4];
    read_exact(stream, &mut head).await?;
    if head[0] != VERSION || head[2] != 0 {
        return Err(invalid_negotiation("invalid SOCKS5 UDP ASSOCIATE reply"));
    }
    if head[1] != 0 {
        return Err(Socks5Error::without_source(Socks5ErrorKind::Rejected));
    }

    let address = match head[3] {
        IPV4 => {
            let mut bytes = [0; 4];
            read_exact(stream, &mut bytes).await?;
            IpAddr::V4(Ipv4Addr::from(bytes))
        }
        IPV6 => {
            let mut bytes = [0; 16];
            read_exact(stream, &mut bytes).await?;
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        DOMAIN => {
            let mut length = [0; 1];
            read_exact(stream, &mut length).await?;
            let mut discarded = vec![0; usize::from(length[0]) + 2];
            read_exact(stream, &mut discarded).await?;
            return Err(invalid_negotiation(
                "SOCKS5 UDP relay returned a domain address",
            ));
        }
        _ => return Err(invalid_negotiation("invalid SOCKS5 UDP relay address type")),
    };
    let mut port = [0; 2];
    read_exact(stream, &mut port).await?;
    let port = u16::from_be_bytes(port);
    if port == 0 {
        return Err(invalid_negotiation("SOCKS5 UDP relay returned a zero port"));
    }
    if address.is_unspecified() {
        let mut relay = proxy_peer;
        relay.set_port(port);
        Ok(relay)
    } else {
        Ok(SocketAddr::new(address, port))
    }
}

fn encode_udp_target(target: SocketAddr) -> Vec<u8> {
    let mut header = Vec::with_capacity(3 + 1 + address_len(target.ip()) + 2);
    header.extend_from_slice(&[0, 0, 0]);
    encode_address(target, &mut header);
    header
}

fn encode_address(address: SocketAddr, output: &mut Vec<u8>) {
    match address.ip() {
        IpAddr::V4(ip) => {
            output.push(IPV4);
            output.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            output.push(IPV6);
            output.extend_from_slice(&ip.octets());
        }
    }
    output.extend_from_slice(&address.port().to_be_bytes());
}

const fn address_len(address: IpAddr) -> usize {
    match address {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 16,
    }
}

fn decode_udp_target(packet: &[u8]) -> Option<(SocketAddr, usize)> {
    if packet.len() < 4 || packet[..3] != [0, 0, 0] {
        return None;
    }
    match packet[3] {
        IPV4 if packet.len() >= 10 => {
            let ip = Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]);
            let port = u16::from_be_bytes([packet[8], packet[9]]);
            Some((SocketAddr::new(IpAddr::V4(ip), port), 10))
        }
        IPV6 if packet.len() >= 22 => {
            let mut bytes = [0; 16];
            bytes.copy_from_slice(&packet[4..20]);
            let port = u16::from_be_bytes([packet[20], packet[21]]);
            Some((SocketAddr::new(IpAddr::V6(Ipv6Addr::from(bytes)), port), 22))
        }
        _ => None,
    }
}

async fn write_all<S>(stream: &mut S, bytes: &[u8]) -> Result<(), Socks5Error>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(bytes)
        .await
        .map_err(|error| Socks5Error::io(Socks5ErrorKind::Negotiation, error))?;
    stream
        .flush()
        .await
        .map_err(|error| Socks5Error::io(Socks5ErrorKind::Negotiation, error))
}

async fn read_exact<S>(stream: &mut S, bytes: &mut [u8]) -> Result<(), Socks5Error>
where
    S: AsyncRead + Unpin,
{
    stream
        .read_exact(bytes)
        .await
        .map(drop)
        .map_err(|error| Socks5Error::io(Socks5ErrorKind::Negotiation, error))
}

fn invalid_negotiation(message: &'static str) -> Socks5Error {
    Socks5Error::io(
        Socks5ErrorKind::Negotiation,
        io::Error::new(io::ErrorKind::InvalidData, message),
    )
}

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{
        Socks5Auth, Socks5ErrorKind, decode_udp_target, encode_udp_target,
        negotiate_authentication, read_udp_associate_reply, write_udp_associate,
    };

    type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

    #[test]
    fn udp_target_codec_preserves_fixed_ip_targets_and_rejects_fragments() -> TestResult<()> {
        for target in [
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 7), 443)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 8443)),
        ] {
            let encoded = encode_udp_target(target);
            assert_eq!(decode_udp_target(&encoded), Some((target, encoded.len())));

            let mut fragmented = encoded;
            fragmented[2] = 1;
            assert_eq!(decode_udp_target(&fragmented), None);
        }
        Ok(())
    }

    #[tokio::test]
    async fn no_authentication_emits_udp_associate_with_unknown_client_address() -> TestResult<()> {
        let (mut client, mut server) = tokio::io::duplex(64);
        let client_address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
        let peer = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 9), 1080));
        let server_task = tokio::spawn(async move {
            let mut greeting = [0; 3];
            server.read_exact(&mut greeting).await?;
            assert_eq!(greeting, [5, 1, 0]);
            server.write_all(&[5, 0]).await?;

            let mut request = [0; 10];
            server.read_exact(&mut request).await?;
            assert_eq!(request, [5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
            server
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0x9c, 0x40])
                .await?;
            Ok::<_, std::io::Error>(())
        });

        negotiate_authentication(&mut client, Socks5Auth::None).await?;
        write_udp_associate(&mut client, client_address).await?;
        let relay = read_udp_associate_reply(&mut client, peer).await?;

        server_task.await??;
        assert_eq!(relay, SocketAddr::new(peer.ip(), 40_000));
        Ok(())
    }

    #[tokio::test]
    async fn username_password_is_redacted_and_rejection_is_typed() -> TestResult<()> {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move {
            let mut greeting = [0; 4];
            server.read_exact(&mut greeting).await?;
            assert_eq!(greeting, [5, 2, 0, 2]);
            server.write_all(&[5, 2]).await?;

            let mut request = [0; 13];
            server.read_exact(&mut request).await?;
            assert_eq!(&request, b"\x01\x04user\x06secret");
            server.write_all(&[1, 1]).await?;
            Ok::<_, std::io::Error>(())
        });

        let auth = Socks5Auth::UsernamePassword {
            username: "user",
            password: "secret",
        };
        let error = match negotiate_authentication(&mut client, auth).await {
            Ok(()) => return Err("rejected authentication succeeded".into()),
            Err(error) => error,
        };

        server_task.await??;
        assert_eq!(error.kind(), Socks5ErrorKind::Authentication);
        assert!(!error.to_string().contains("secret"));
        Ok(())
    }

    #[tokio::test]
    async fn malformed_authentication_version_is_negotiation_failure() -> TestResult<()> {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move {
            let mut greeting = [0; 4];
            server.read_exact(&mut greeting).await?;
            server.write_all(&[5, 2]).await?;

            let mut request = [0; 13];
            server.read_exact(&mut request).await?;
            server.write_all(&[5, 0]).await?;
            Ok::<_, std::io::Error>(())
        });

        let error = match negotiate_authentication(
            &mut client,
            Socks5Auth::UsernamePassword {
                username: "user",
                password: "secret",
            },
        )
        .await
        {
            Ok(()) => return Err("malformed authentication response succeeded".into()),
            Err(error) => error,
        };

        server_task.await??;
        assert_eq!(error.kind(), Socks5ErrorKind::Negotiation);
        Ok(())
    }

    #[tokio::test]
    async fn domain_and_zero_port_relay_replies_are_rejected() -> TestResult<()> {
        for reply in [
            vec![5, 0, 0, 3, 3, b'f', b'o', b'o', 0, 53],
            vec![5, 0, 0, 1, 127, 0, 0, 1, 0, 0],
        ] {
            let (mut client, mut server) = tokio::io::duplex(64);
            let server_task = tokio::spawn(async move { server.write_all(&reply).await });
            let error = match read_udp_associate_reply(
                &mut client,
                SocketAddr::from((Ipv4Addr::LOCALHOST, 1080)),
            )
            .await
            {
                Ok(_) => return Err("invalid relay reply succeeded".into()),
                Err(error) => error,
            };
            server_task.await??;
            assert_eq!(error.kind(), Socks5ErrorKind::Negotiation);
        }
        Ok(())
    }
}
