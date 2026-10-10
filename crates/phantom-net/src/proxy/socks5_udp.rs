use std::{
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::{Pin, pin},
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, ready},
    time::{Duration, Instant},
};

use quinn::{AsyncUdpSocket, UdpPoller, udp};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

use super::socks5::{Socks5Auth, Socks5Error, Socks5ErrorKind, connect_proxy, trace_connect};
use crate::direct::Dialer;

const VERSION: u8 = 5;
const NO_AUTHENTICATION: u8 = 0;
const USERNAME_PASSWORD: u8 = 2;
const NO_ACCEPTABLE_METHODS: u8 = 0xff;
const UDP_ASSOCIATE: u8 = 3;
const IPV4: u8 = 1;
const DOMAIN: u8 = 3;
const IPV6: u8 = 4;
const MAX_UDP_PACKET_BYTES: usize = 65_507;
// Large enough for any non-jumbogram IPv4 or IPv6 UDP payload, so a relayed
// datagram is never truncated and Windows never reports `WSAEMSGSIZE`.
const MAX_RECEIVED_DATAGRAM_BYTES: usize = 65_535;
const MAX_PACKETS_PER_POLL: usize = 32;
const REMOTE_VIRTUAL_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const SEND_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(60);
const MAX_CONTROL_READS_PER_POLL: usize = 16;

/// One single-target SOCKS5 UDP association.
///
/// The socket retains the TCP control connection for its complete lifetime;
/// when the proxy closes it, the association and its QUIC endpoint end.
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
    dialer: Dialer<'_>,
    proxy_host: &str,
    proxy_port: u16,
    target: SocketAddr,
    auth: Socks5Auth<'_>,
) -> Result<Socks5UdpAssociation, Socks5Error> {
    trace_connect(
        "local",
        pin!(async {
            let auth = auth.validate()?;
            if target.port() == 0 {
                return Err(Socks5Error::without_source(Socks5ErrorKind::InvalidTarget));
            }
            let target_header = encode_udp_target(target);
            establish_udp_association(
                dialer,
                proxy_host,
                proxy_port,
                target,
                target_header,
                ReceiveTarget::ExactIp(target),
                auth,
            )
            .await
        }),
    )
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
    dialer: Dialer<'_>,
    proxy_host: &str,
    proxy_port: u16,
    target: Socks5UdpRemoteTarget,
    auth: Socks5Auth<'_>,
) -> Result<Socks5UdpAssociation, Socks5Error> {
    trace_connect(
        "remote",
        pin!(async {
            let auth = auth.validate()?;
            let logical_target = SocketAddr::new(IpAddr::V4(REMOTE_VIRTUAL_IP), target.port);
            establish_udp_association(
                dialer,
                proxy_host,
                proxy_port,
                logical_target,
                target.target_header,
                target.receive_target,
                auth,
            )
            .await
        }),
    )
    .await
}

async fn establish_udp_association(
    dialer: Dialer<'_>,
    proxy_host: &str,
    proxy_port: u16,
    logical_target: SocketAddr,
    target_header: Vec<u8>,
    receive_target: ReceiveTarget,
    auth: Socks5Auth<'_>,
) -> Result<Socks5UdpAssociation, Socks5Error> {
    tokio::runtime::Handle::try_current()
        .map_err(|_| Socks5Error::without_source(Socks5ErrorKind::RuntimeUnavailable))?;

    // The control connection carries no HTTP, so no keepalive schedule.
    let mut control = connect_proxy(dialer, proxy_host, proxy_port)
        .await?
        .into_tcp_stream();
    negotiate_authentication(&mut control, auth).await?;

    let control_local = control
        .local_addr()
        .map_err(|error| Socks5Error::io(Socks5ErrorKind::Negotiation, error))?;
    let control_peer = control
        .peer_addr()
        .map_err(|error| Socks5Error::io(Socks5ErrorKind::Negotiation, error))?;
    let mut client_bind = control_local;
    client_bind.set_port(0);
    // A source binding gives the UDP socket its address for the proxy's
    // family, which the control connection already left from, and its
    // interface. Without one, the socket takes the control connection's
    // local address. The profile's UDP options are set before the bind.
    let udp = crate::udp::bind_socket(control_peer, client_bind, dialer.source, dialer.udp)
        .and_then(|socket| {
            socket.set_nonblocking(true)?;
            UdpSocket::from_std(socket)
        })
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
        control,
        relay,
        logical_target,
        logical_local,
        target_header,
        receive_target,
        send_buffer: Mutex::new(Vec::with_capacity(MAX_UDP_PACKET_BYTES)),
        last_send_error_log: Mutex::new(None),
        receive_buffer: Mutex::new(vec![0; MAX_RECEIVED_DATAGRAM_BYTES]),
    });
    Ok(Socks5UdpAssociation {
        socket,
        target: logical_target,
    })
}

#[derive(Debug)]
struct Socks5UdpSocket {
    udp: UdpSocket,
    control: TcpStream,
    relay: SocketAddr,
    logical_target: SocketAddr,
    logical_local: SocketAddr,
    target_header: Vec<u8>,
    receive_target: ReceiveTarget,
    send_buffer: Mutex<Vec<u8>>,
    last_send_error_log: Mutex<Option<Instant>>,
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
        let result = self.udp.try_send_to(&packet, self.relay);
        let expected = packet.len();
        drop(packet);
        match relay_send_outcome(result, expected)? {
            RelaySend::Sent => {}
            RelaySend::Dropped(error) => self.log_dropped_send(&error),
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
        if let Some(error) = self.poll_control_closed(context) {
            return Poll::Ready(Err(error));
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
            // Quinn ends its endpoint driver on any receive error other than
            // `ConnectionReset`, so an oversized relayed datagram is dropped
            // like any other datagram QUIC cannot accept.
            if payload.len() > bufs[0].len() {
                continue;
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

impl Socks5UdpSocket {
    /// Reports the end of the association's TCP control connection.
    ///
    /// RFC 1928 section 7 ends a UDP association when its TCP connection
    /// terminates. The returned error is not `ConnectionReset`, which Quinn
    /// ignores, so the endpoint stops and its connections are not reused.
    /// Bytes on the control connection have no meaning and are discarded.
    fn poll_control_closed(&self, context: &mut Context<'_>) -> Option<io::Error> {
        for _ in 0..MAX_CONTROL_READS_PER_POLL {
            match self.control.poll_read_ready(context) {
                Poll::Pending => return None,
                Poll::Ready(Err(error)) => return Some(control_closed(error)),
                Poll::Ready(Ok(())) => {}
            }
            let mut discarded = [0; 64];
            match self.control.try_read(&mut discarded) {
                Ok(0) => {
                    return Some(control_closed(io::Error::from(
                        io::ErrorKind::UnexpectedEof,
                    )));
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Some(control_closed(error)),
            }
        }
        context.waker().wake_by_ref();
        None
    }

    fn log_dropped_send(&self, error: &io::Error) {
        let now = Instant::now();
        let mut last = lock(&self.last_send_error_log);
        if last.is_some_and(|last| now.saturating_duration_since(last) < SEND_ERROR_LOG_INTERVAL) {
            return;
        }
        *last = Some(now);
        tracing::warn!(%error, "dropped a SOCKS5 UDP datagram after a relay send error");
    }
}

fn control_closed(source: io::Error) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        ControlConnectionClosed { source },
    )
}

#[derive(Debug)]
struct ControlConnectionClosed {
    source: io::Error,
}

impl std::fmt::Display for ControlConnectionClosed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SOCKS5 UDP association control connection closed")
    }
}

impl std::error::Error for ControlConnectionClosed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Debug)]
enum RelaySend {
    Sent,
    Dropped(io::Error),
}

/// Maps one relay send to Quinn's `AsyncUdpSocket::try_send` contract.
///
/// Like `quinn-udp`, only `WouldBlock` reaches Quinn. QUIC already recovers
/// lost datagrams, while any other error would end the connection driver.
fn relay_send_outcome(result: io::Result<usize>, expected: usize) -> io::Result<RelaySend> {
    match result {
        Ok(sent) if sent == expected => Ok(RelaySend::Sent),
        Ok(_) => Ok(RelaySend::Dropped(io::Error::new(
            io::ErrorKind::WriteZero,
            "SOCKS5 UDP relay accepted a partial datagram",
        ))),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Err(error),
        Err(error) => Ok(RelaySend::Dropped(error)),
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
mod tests;
