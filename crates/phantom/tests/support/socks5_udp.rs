use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

const MAX_UDP_PACKET_BYTES: usize = 65_507;
type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Socks5UdpAuthentication {
    None,
    UsernamePassword,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Socks5UdpAssociateReply {
    Success,
    Reject(u8),
    Malformed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Socks5UdpScript {
    pub(crate) authentication: Socks5UdpAuthentication,
    pub(crate) reply: Socks5UdpAssociateReply,
}

impl Socks5UdpScript {
    pub(crate) const fn no_auth() -> Self {
        Self {
            authentication: Socks5UdpAuthentication::None,
            reply: Socks5UdpAssociateReply::Success,
        }
    }

    pub(crate) const fn username_password() -> Self {
        Self {
            authentication: Socks5UdpAuthentication::UsernamePassword,
            reply: Socks5UdpAssociateReply::Success,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ObservedSocks5UdpAuthentication {
    pub(crate) username: String,
    pub(crate) password: String,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ObservedSocks5UdpAssociation {
    pub(crate) client_address: SocketAddr,
    pub(crate) relay_address: SocketAddr,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ObservedSocks5UdpRelay {
    pub(crate) authentication: Option<ObservedSocks5UdpAuthentication>,
    pub(crate) association: ObservedSocks5UdpAssociation,
    pub(crate) client_datagrams: usize,
    pub(crate) origin_datagrams: usize,
}

pub(crate) async fn forward_one_socks5_udp_associate(
    listener: TcpListener,
    origin: SocketAddr,
) -> TestResult<ObservedSocks5UdpRelay> {
    serve_one_socks5_udp_associate(listener, origin, Socks5UdpScript::no_auth()).await
}

pub(crate) async fn forward_one_authenticated_socks5_udp_associate(
    listener: TcpListener,
    origin: SocketAddr,
) -> TestResult<ObservedSocks5UdpRelay> {
    serve_one_socks5_udp_associate(listener, origin, Socks5UdpScript::username_password()).await
}

pub(crate) async fn serve_one_socks5_udp_associate(
    listener: TcpListener,
    origin: SocketAddr,
    script: Socks5UdpScript,
) -> TestResult<ObservedSocks5UdpRelay> {
    if !listener.local_addr()?.ip().is_loopback() || !origin.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKS5 UDP fixture requires loopback listener and origin addresses",
        )
        .into());
    }

    let (mut control, _) = listener.accept().await?;
    let authentication = match script.authentication {
        Socks5UdpAuthentication::None => {
            negotiate_no_auth(&mut control).await?;
            None
        }
        Socks5UdpAuthentication::UsernamePassword => {
            Some(negotiate_username_password(&mut control).await?)
        }
    };
    let client_address = read_udp_associate(&mut control).await?;
    let relay = UdpSocket::bind(SocketAddr::new(loopback_for(origin.ip()), 0)).await?;
    let relay_address = relay.local_addr()?;
    let association = ObservedSocks5UdpAssociation {
        client_address,
        relay_address,
    };

    match script.reply {
        Socks5UdpAssociateReply::Success => {
            write_associate_reply(&mut control, 0, relay_address).await?;
        }
        Socks5UdpAssociateReply::Reject(reply) => {
            if reply == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SOCKS5 rejection reply must be nonzero",
                )
                .into());
            }
            write_associate_reply(&mut control, reply, relay_address).await?;
            control.shutdown().await?;
            return Ok(ObservedSocks5UdpRelay {
                authentication,
                association,
                client_datagrams: 0,
                origin_datagrams: 0,
            });
        }
        Socks5UdpAssociateReply::Malformed => {
            control.write_all(&[5, 0, 0, 1, 127]).await?;
            control.shutdown().await?;
            return Ok(ObservedSocks5UdpRelay {
                authentication,
                association,
                client_datagrams: 0,
                origin_datagrams: 0,
            });
        }
    }

    relay_until_control_closes(control, relay, origin, authentication, association).await
}

async fn relay_until_control_closes(
    mut control: TcpStream,
    relay: UdpSocket,
    origin: SocketAddr,
    authentication: Option<ObservedSocks5UdpAuthentication>,
    association: ObservedSocks5UdpAssociation,
) -> TestResult<ObservedSocks5UdpRelay> {
    let mut packet = vec![0_u8; MAX_UDP_PACKET_BYTES];
    let mut control_byte = [0_u8; 1];
    let mut client_peer = None;
    let mut client_datagrams = 0_usize;
    let mut origin_datagrams = 0_usize;

    loop {
        tokio::select! {
            biased;
            read = control.read(&mut control_byte) => {
                match read? {
                    0 => break,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "SOCKS5 UDP control connection carried bytes after association",
                        ).into());
                    }
                }
            }
            received = relay.recv_from(&mut packet) => {
                let (length, peer) = received?;
                if peer == origin {
                    let client = client_peer.ok_or_else(|| io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SOCKS5 UDP origin replied before the client sent a datagram",
                    ))?;
                    let reply = encode_udp_packet(origin, &packet[..length])?;
                    let sent = relay.send_to(&reply, client).await?;
                    if sent != reply.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "SOCKS5 UDP relay sent a partial reply",
                        ).into());
                    }
                    origin_datagrams = increment(origin_datagrams)?;
                    continue;
                }

                match client_peer {
                    Some(client) if client != peer => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "SOCKS5 UDP association changed client address",
                        ).into());
                    }
                    None => client_peer = Some(peer),
                    Some(_) => {}
                }
                let request = parse_udp_packet(&packet[..length])?;
                if request.target != origin {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SOCKS5 UDP packet targeted an unexpected origin",
                    ).into());
                }
                let sent = relay.send_to(request.payload, origin).await?;
                if sent != request.payload.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "SOCKS5 UDP relay forwarded a partial datagram",
                    ).into());
                }
                client_datagrams = increment(client_datagrams)?;
            }
        }
    }

    Ok(ObservedSocks5UdpRelay {
        authentication,
        association,
        client_datagrams,
        origin_datagrams,
    })
}

async fn negotiate_no_auth(stream: &mut TcpStream) -> io::Result<()> {
    let mut greeting = [0_u8; 3];
    stream.read_exact(&mut greeting).await?;
    if greeting != [5, 1, 0] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected SOCKS5 UDP greeting",
        ));
    }
    stream.write_all(&[5, 0]).await?;
    stream.flush().await
}

async fn negotiate_username_password(
    stream: &mut TcpStream,
) -> io::Result<ObservedSocks5UdpAuthentication> {
    let mut greeting = [0_u8; 4];
    stream.read_exact(&mut greeting).await?;
    if greeting != [5, 2, 0, 2] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected authenticated SOCKS5 UDP greeting",
        ));
    }
    stream.write_all(&[5, 2]).await?;

    if stream.read_u8().await? != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected SOCKS5 UDP authentication version",
        ));
    }
    let username = read_nonempty_credential(stream, "username").await?;
    let password = read_nonempty_credential(stream, "password").await?;
    stream.write_all(&[1, 0]).await?;
    stream.flush().await?;
    Ok(ObservedSocks5UdpAuthentication { username, password })
}

async fn read_nonempty_credential(stream: &mut TcpStream, field: &str) -> io::Result<String> {
    let length = stream.read_u8().await?;
    if length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("SOCKS5 UDP {field} was empty"),
        ));
    }
    let mut value = vec![0_u8; usize::from(length)];
    stream.read_exact(&mut value).await?;
    String::from_utf8(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("SOCKS5 UDP {field} was not UTF-8"),
        )
    })
}

async fn read_udp_associate(stream: &mut TcpStream) -> io::Result<SocketAddr> {
    let mut head = [0_u8; 4];
    stream.read_exact(&mut head).await?;
    if head[..3] != [5, 3, 0] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected SOCKS5 UDP ASSOCIATE prefix",
        ));
    }
    let ip = match head[3] {
        1 => {
            let mut address = [0_u8; 4];
            stream.read_exact(&mut address).await?;
            IpAddr::V4(Ipv4Addr::from(address))
        }
        4 => {
            let mut address = [0_u8; 16];
            stream.read_exact(&mut address).await?;
            IpAddr::V6(Ipv6Addr::from(address))
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SOCKS5 UDP ASSOCIATE requires an IP client address",
            ));
        }
    };
    if !ip.is_unspecified() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 UDP ASSOCIATE client address was not unspecified",
        ));
    }
    let port = stream.read_u16().await?;
    if port != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 UDP ASSOCIATE client port was not zero",
        ));
    }
    Ok(SocketAddr::new(ip, port))
}

async fn write_associate_reply(
    stream: &mut TcpStream,
    reply: u8,
    address: SocketAddr,
) -> io::Result<()> {
    let mut wire = Vec::with_capacity(22);
    wire.extend_from_slice(&[5, reply, 0]);
    encode_address(address, &mut wire);
    stream.write_all(&wire).await?;
    stream.flush().await
}

struct ParsedUdpPacket<'a> {
    target: SocketAddr,
    payload: &'a [u8],
}

fn parse_udp_packet(packet: &[u8]) -> io::Result<ParsedUdpPacket<'_>> {
    if packet.len() < 4 || packet[..2] != [0, 0] || packet[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 UDP reserved or fragment field",
        ));
    }
    let (ip, port_index) = match packet[3] {
        1 if packet.len() >= 10 => (
            IpAddr::V4(Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7])),
            8,
        ),
        4 if packet.len() >= 22 => {
            let mut address = [0_u8; 16];
            address.copy_from_slice(&packet[4..20]);
            (IpAddr::V6(Ipv6Addr::from(address)), 20)
        }
        1 | 4 => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated SOCKS5 UDP target address",
            ));
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SOCKS5 UDP packet requires an IP target address",
            ));
        }
    };
    let port = u16::from_be_bytes([packet[port_index], packet[port_index + 1]]);
    Ok(ParsedUdpPacket {
        target: SocketAddr::new(ip, port),
        payload: &packet[port_index + 2..],
    })
}

fn encode_udp_packet(source: SocketAddr, payload: &[u8]) -> io::Result<Vec<u8>> {
    let header_length: usize = match source {
        SocketAddr::V4(_) => 10,
        SocketAddr::V6(_) => 22,
    };
    let packet_length = header_length.checked_add(payload.len()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 UDP reply length overflow",
        )
    })?;
    if packet_length > MAX_UDP_PACKET_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 UDP reply exceeds the fixture datagram bound",
        ));
    }
    let mut packet = Vec::with_capacity(packet_length);
    packet.extend_from_slice(&[0, 0, 0]);
    encode_address(source, &mut packet);
    packet.extend_from_slice(payload);
    Ok(packet)
}

fn encode_address(address: SocketAddr, wire: &mut Vec<u8>) {
    match address.ip() {
        IpAddr::V4(ip) => {
            wire.push(1);
            wire.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            wire.push(4);
            wire.extend_from_slice(&ip.octets());
        }
    }
    wire.extend_from_slice(&address.port().to_be_bytes());
}

const fn loopback_for(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
    }
}

fn increment(value: usize) -> io::Result<usize> {
    value.checked_add(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 UDP datagram count overflow",
        )
    })
}
