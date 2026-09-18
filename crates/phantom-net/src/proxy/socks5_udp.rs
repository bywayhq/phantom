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
const REMOTE_VIRTUAL_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

/// One single-target SOCKS5 UDP association.
///
/// The socket retains the TCP control connection for its complete lifetime.
/// Its Quinn-facing address is a fixed logical target, while every physical
/// datagram is sent only to the relay selected by the SOCKS5 peer.
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
        let target_header = encode_udp_target(target);
        establish_udp_association(
            proxy_host,
            proxy_port,
            target,
            target_header,
            ReceiveTarget::ExactIp(target),
            auth,
        )
        .await
    })
    .await
}

/// A validated proxy-owned DNS target for a SOCKS5 UDP association.
#[derive(Debug)]
pub(crate) struct Socks5UdpRemoteTarget {
    target_header: Vec<u8>,
    receive_target: ReceiveTarget,
    port: u16,
}

/// Validates and prepares a remote-DNS UDP target without runtime or network I/O.
pub(crate) fn prepare_socks5_udp_remote_target(
    target_host: &str,
    target_port: u16,
) -> Result<Socks5UdpRemoteTarget, Socks5Error> {
    if target_port == 0 {
        return Err(Socks5Error::without_source(Socks5ErrorKind::InvalidTarget));
    }

    let (target_header, receive_target) = if let Ok(address) = target_host.parse::<IpAddr>() {
        let target = SocketAddr::new(address, target_port);
        (encode_udp_target(target), ReceiveTarget::ExactIp(target))
    } else {
        let domain = match url::Host::parse(target_host) {
            Ok(url::Host::Domain(domain)) if (1..=255).contains(&domain.len()) => domain,
            Ok(url::Host::Ipv4(address)) => {
                let target = SocketAddr::new(IpAddr::V4(address), target_port);
                return Ok(Socks5UdpRemoteTarget {
                    target_header: encode_udp_target(target),
                    receive_target: ReceiveTarget::ExactIp(target),
                    port: target_port,
                });
            }
            Ok(url::Host::Ipv6(address)) => {
                let target = SocketAddr::new(IpAddr::V6(address), target_port);
                return Ok(Socks5UdpRemoteTarget {
                    target_header: encode_udp_target(target),
                    receive_target: ReceiveTarget::ExactIp(target),
                    port: target_port,
                });
            }
            _ => return Err(Socks5Error::without_source(Socks5ErrorKind::InvalidTarget)),
        };
        (
            encode_udp_domain_target(domain.as_bytes(), target_port),
            ReceiveTarget::RemoteDomain {
                domain: domain.into_bytes().into_boxed_slice(),
                port: target_port,
            },
        )
    };
    Ok(Socks5UdpRemoteTarget {
        target_header,
        receive_target,
        port: target_port,
    })
}

/// Opens a remote-DNS UDP association from a synchronously prepared target.
///
/// Quinn sends to a stable documentation-range virtual peer. Domain targets
/// remain `DOMAIN` addresses on the wire. Replies may identify the exact domain
/// or an IP at the target port. Accepted replies remain mapped to the stable
/// logical peer, hiding physical target-address changes from Quinn while QUIC
/// authenticates the connection.
pub(crate) async fn associate_socks5_udp_remote_with_auth(
    proxy_host: &str,
    proxy_port: u16,
    target: Socks5UdpRemoteTarget,
    auth: Socks5Auth<'_>,
) -> Result<Socks5UdpAssociation, Socks5Error> {
    trace_connect("remote", async {
        let auth = auth.validate()?;
        let logical_target = SocketAddr::new(IpAddr::V4(REMOTE_VIRTUAL_IP), target.port);
        establish_udp_association(
            proxy_host,
            proxy_port,
            logical_target,
            target.target_header,
            target.receive_target,
            auth,
        )
        .await
    })
    .await
}

async fn establish_udp_association(
    proxy_host: &str,
    proxy_port: u16,
    logical_target: SocketAddr,
    target_header: Vec<u8>,
    receive_target: ReceiveTarget,
    auth: Socks5Auth<'_>,
) -> Result<Socks5UdpAssociation, Socks5Error> {
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
        match logical_target.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        },
        client_udp.port(),
    );
    let socket = Arc::new(Socks5UdpSocket {
        udp,
        _control: control,
        relay,
        logical_target,
        logical_local,
        target_header,
        receive_target,
        send_buffer: Mutex::new(Vec::with_capacity(MAX_UDP_PACKET_BYTES)),
        receive_buffer: Mutex::new(vec![0; MAX_UDP_PACKET_BYTES]),
    });
    Ok(Socks5UdpAssociation {
        socket,
        target: logical_target,
    })
}

#[derive(Debug)]
struct Socks5UdpSocket {
    udp: UdpSocket,
    _control: TcpStream,
    relay: SocketAddr,
    logical_target: SocketAddr,
    logical_local: SocketAddr,
    target_header: Vec<u8>,
    receive_target: ReceiveTarget,
    send_buffer: Mutex<Vec<u8>>,
    receive_buffer: Mutex<Vec<u8>>,
}

impl AsyncUdpSocket for Socks5UdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Socks5UdpPoller { socket: self })
    }

    fn try_send(&self, transmit: &udp::Transmit<'_>) -> io::Result<()> {
        if transmit.destination != self.logical_target {
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
            if !self.receive_target.accepts(source) {
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
                addr: self.logical_target,
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

fn encode_udp_domain_target(domain: &[u8], port: u16) -> Vec<u8> {
    let mut header = Vec::with_capacity(5 + domain.len() + 2);
    header.extend_from_slice(&[0, 0, 0, DOMAIN, domain.len() as u8]);
    header.extend_from_slice(domain);
    header.extend_from_slice(&port.to_be_bytes());
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DecodedUdpTarget<'a> {
    Ip(SocketAddr),
    Domain { domain: &'a [u8], port: u16 },
}

#[derive(Debug)]
enum ReceiveTarget {
    ExactIp(SocketAddr),
    RemoteDomain { domain: Box<[u8]>, port: u16 },
}

impl ReceiveTarget {
    fn accepts(&self, source: DecodedUdpTarget<'_>) -> bool {
        match (self, source) {
            (Self::ExactIp(expected), DecodedUdpTarget::Ip(actual)) => *expected == actual,
            (
                Self::RemoteDomain { domain, port, .. },
                DecodedUdpTarget::Domain {
                    domain: actual,
                    port: actual_port,
                },
            ) => domain.eq_ignore_ascii_case(actual) && *port == actual_port,
            (Self::RemoteDomain { port, .. }, DecodedUdpTarget::Ip(actual)) => {
                *port == actual.port()
            }
            _ => false,
        }
    }
}

fn decode_udp_target(packet: &[u8]) -> Option<(DecodedUdpTarget<'_>, usize)> {
    if packet.len() < 4 || packet[..3] != [0, 0, 0] {
        return None;
    }
    match packet[3] {
        IPV4 if packet.len() >= 10 => {
            let ip = Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]);
            let port = u16::from_be_bytes([packet[8], packet[9]]);
            Some((
                DecodedUdpTarget::Ip(SocketAddr::new(IpAddr::V4(ip), port)),
                10,
            ))
        }
        IPV6 if packet.len() >= 22 => {
            let mut bytes = [0; 16];
            bytes.copy_from_slice(&packet[4..20]);
            let port = u16::from_be_bytes([packet[20], packet[21]]);
            Some((
                DecodedUdpTarget::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(bytes)), port)),
                22,
            ))
        }
        DOMAIN if packet.len() >= 5 => {
            let length = usize::from(packet[4]);
            if length == 0 {
                return None;
            }
            let port_start = 5_usize.checked_add(length)?;
            let packet_end = port_start.checked_add(2)?;
            if packet.len() < packet_end {
                return None;
            }
            let port = u16::from_be_bytes([packet[port_start], packet[port_start + 1]]);
            Some((
                DecodedUdpTarget::Domain {
                    domain: &packet[5..port_start],
                    port,
                },
                packet_end,
            ))
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{
        DecodedUdpTarget, REMOTE_VIRTUAL_IP, ReceiveTarget, Socks5Auth, Socks5ErrorKind,
        decode_udp_target, encode_udp_target, negotiate_authentication,
        prepare_socks5_udp_remote_target, read_udp_associate_reply, write_udp_associate,
    };

    type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

    #[test]
    fn udp_target_codec_preserves_fixed_ip_targets_and_rejects_fragments() -> TestResult<()> {
        for target in [
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 7), 443)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 8443)),
        ] {
            let encoded = encode_udp_target(target);
            assert_eq!(
                decode_udp_target(&encoded),
                Some((DecodedUdpTarget::Ip(target), encoded.len()))
            );

            let mut fragmented = encoded;
            fragmented[2] = 1;
            assert_eq!(decode_udp_target(&fragmented), None);
        }
        Ok(())
    }

    #[test]
    fn remote_target_validation_canonicalizes_domains_and_literal_ips() -> TestResult<()> {
        let domain = prepare_socks5_udp_remote_target("origin.example", 443)?;
        assert_eq!(
            domain.target_header,
            b"\0\0\0\x03\x0eorigin.example\x01\xbb"
        );
        assert_eq!(
            SocketAddr::new(IpAddr::V4(REMOTE_VIRTUAL_IP), domain.port),
            SocketAddr::from((REMOTE_VIRTUAL_IP, 443))
        );

        let ipv4 = prepare_socks5_udp_remote_target("192.0.2.9", 8443)?;
        assert_eq!(ipv4.target_header, [0, 0, 0, 1, 192, 0, 2, 9, 0x20, 0xfb]);
        let ipv6 = prepare_socks5_udp_remote_target("2001:db8::9", 443)?;
        assert_eq!(ipv6.target_header[3], 4);
        let expanded_ipv6 =
            prepare_socks5_udp_remote_target("2001:0db8:0000:0000:0000:0000:0000:0009", 443)?;
        assert_eq!(expanded_ipv6.target_header, ipv6.target_header);
        let uppercase = prepare_socks5_udp_remote_target("Origin.Example", 443)?;
        assert_eq!(
            uppercase.target_header,
            b"\0\0\0\x03\x0eorigin.example\x01\xbb"
        );
        let unicode = prepare_socks5_udp_remote_target("bücher.example", 443)?;
        assert_eq!(
            unicode.target_header,
            b"\0\0\0\x03\x15xn--bcher-kva.example\x01\xbb"
        );
        Ok(())
    }

    #[test]
    fn remote_target_validation_rejects_unencodable_values() -> TestResult<()> {
        let too_long = "a".repeat(256);
        for (host, port) in [("", 443), (too_long.as_str(), 443), ("origin.example", 0)] {
            let error = match prepare_socks5_udp_remote_target(host, port) {
                Ok(_) => {
                    return Err(format!("invalid remote target {host:?}:{port} succeeded").into());
                }
                Err(error) => error,
            };
            assert_eq!(error.kind(), Socks5ErrorKind::InvalidTarget);
        }
        Ok(())
    }

    #[test]
    fn remote_domain_reply_accepts_exact_domain_and_same_port_ips() -> TestResult<()> {
        let target = prepare_socks5_udp_remote_target("origin.example", 443)?;
        assert!(target.receive_target.accepts(DecodedUdpTarget::Domain {
            domain: b"origin.example",
            port: 443,
        }));
        assert!(target.receive_target.accepts(DecodedUdpTarget::Domain {
            domain: b"ORIGIN.EXAMPLE",
            port: 443,
        }));
        assert!(!target.receive_target.accepts(DecodedUdpTarget::Domain {
            domain: b"other.example",
            port: 443,
        }));
        assert!(!target.receive_target.accepts(DecodedUdpTarget::Domain {
            domain: b"origin.example",
            port: 8443,
        }));

        let first_ip = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 7), 443));
        assert!(
            target
                .receive_target
                .accepts(DecodedUdpTarget::Ip(first_ip))
        );
        assert!(
            target
                .receive_target
                .accepts(DecodedUdpTarget::Ip(first_ip))
        );
        assert!(
            target
                .receive_target
                .accepts(DecodedUdpTarget::Ip(SocketAddr::from((
                    Ipv4Addr::new(198, 51, 100, 8),
                    443
                ))))
        );
        assert!(
            !target
                .receive_target
                .accepts(DecodedUdpTarget::Ip(SocketAddr::from((
                    Ipv4Addr::new(198, 51, 100, 7),
                    8443
                ))))
        );
        Ok(())
    }

    #[test]
    fn udp_domain_codec_rejects_fragments_and_truncation() -> TestResult<()> {
        let target = prepare_socks5_udp_remote_target("origin.example", 443)?;
        assert_eq!(
            decode_udp_target(&target.target_header),
            Some((
                DecodedUdpTarget::Domain {
                    domain: b"origin.example",
                    port: 443,
                },
                target.target_header.len(),
            ))
        );

        let mut fragmented = target.target_header.clone();
        fragmented[2] = 1;
        assert_eq!(decode_udp_target(&fragmented), None);
        assert_eq!(decode_udp_target(&target.target_header[..6]), None);
        assert_eq!(decode_udp_target(&[0, 0, 0, 3, 0, 0, 53]), None);
        Ok(())
    }

    #[test]
    fn local_receive_policy_remains_exact_ip() {
        let target = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 7), 443));
        let policy = ReceiveTarget::ExactIp(target);
        assert!(policy.accepts(DecodedUdpTarget::Ip(target)));
        assert!(!policy.accepts(DecodedUdpTarget::Ip(SocketAddr::from((
            Ipv4Addr::new(192, 0, 2, 8),
            443,
        )))));
        assert!(!policy.accepts(DecodedUdpTarget::Domain {
            domain: b"origin.example",
            port: 443,
        }));
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
