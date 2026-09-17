use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
};

use super::tls::TestResult;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ObservedSocks5Connect {
    pub(crate) host: String,
    pub(crate) port: u16,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ObservedSocks5Authentication {
    pub(crate) username: String,
    pub(crate) password: String,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ObservedAuthenticatedSocks5Connect {
    pub(crate) authentication: ObservedSocks5Authentication,
    pub(crate) connect: ObservedSocks5Connect,
}

pub(crate) async fn forward_one_socks5(
    listener: TcpListener,
    origin: SocketAddr,
) -> TestResult<ObservedSocks5Connect> {
    let (mut downstream, _) = listener.accept().await?;
    negotiate_no_auth(&mut downstream).await?;
    let request = read_connect(&mut downstream).await?;
    let mut upstream = TcpStream::connect(origin).await?;
    downstream
        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
        .await?;
    downstream.flush().await?;
    copy_bidirectional(&mut downstream, &mut upstream).await?;
    Ok(request)
}

pub(crate) async fn forward_one_authenticated_socks5(
    listener: TcpListener,
    origin: SocketAddr,
) -> TestResult<ObservedAuthenticatedSocks5Connect> {
    forward_next_authenticated_socks5(&listener, origin).await
}

pub(crate) async fn forward_next_authenticated_socks5(
    listener: &TcpListener,
    origin: SocketAddr,
) -> TestResult<ObservedAuthenticatedSocks5Connect> {
    let (mut downstream, _) = listener.accept().await?;
    let authentication = negotiate_username_password(&mut downstream, 0).await?;
    let connect = read_connect(&mut downstream).await?;
    let mut upstream = TcpStream::connect(origin).await?;
    downstream
        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
        .await?;
    downstream.flush().await?;
    copy_bidirectional(&mut downstream, &mut upstream).await?;
    Ok(ObservedAuthenticatedSocks5Connect {
        authentication,
        connect,
    })
}

pub(crate) async fn reject_one_socks5(
    listener: TcpListener,
    reply: u8,
) -> TestResult<ObservedSocks5Connect> {
    let (mut stream, _) = listener.accept().await?;
    negotiate_no_auth(&mut stream).await?;
    let request = read_connect(&mut stream).await?;
    stream
        .write_all(&[5, reply, 0, 1, 0, 0, 0, 0, 0, 0])
        .await?;
    stream.shutdown().await?;
    Ok(request)
}

pub(crate) async fn reject_one_socks5_authentication(
    listener: TcpListener,
    status: u8,
) -> TestResult<ObservedSocks5Authentication> {
    let (mut stream, _) = listener.accept().await?;
    let authentication = negotiate_username_password(&mut stream, status).await?;
    let mut remaining = Vec::new();
    stream.read_to_end(&mut remaining).await?;
    if !remaining.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 CONNECT followed rejected authentication",
        )
        .into());
    }
    Ok(authentication)
}

async fn negotiate_no_auth(stream: &mut TcpStream) -> io::Result<()> {
    let mut greeting = [0_u8; 3];
    stream.read_exact(&mut greeting).await?;
    if greeting != [5, 1, 0] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected SOCKS5 greeting",
        ));
    }
    stream.write_all(&[5, 0]).await?;
    stream.flush().await
}

async fn negotiate_username_password(
    stream: &mut TcpStream,
    status: u8,
) -> io::Result<ObservedSocks5Authentication> {
    let mut greeting = [0_u8; 4];
    stream.read_exact(&mut greeting).await?;
    if greeting != [5, 2, 0, 2] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected authenticated SOCKS5 greeting",
        ));
    }
    stream.write_all(&[5, 2]).await?;

    let version = stream.read_u8().await?;
    if version != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected SOCKS5 authentication version",
        ));
    }
    let username = read_nonempty_credential(stream, "username").await?;
    let password = read_nonempty_credential(stream, "password").await?;
    stream.write_all(&[1, status]).await?;
    stream.flush().await?;
    Ok(ObservedSocks5Authentication { username, password })
}

async fn read_nonempty_credential(stream: &mut TcpStream, field: &str) -> io::Result<String> {
    let length = stream.read_u8().await?;
    if length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("SOCKS5 {field} was empty"),
        ));
    }
    let mut value = vec![0_u8; usize::from(length)];
    stream.read_exact(&mut value).await?;
    String::from_utf8(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("SOCKS5 {field} was not UTF-8"),
        )
    })
}

async fn read_connect(stream: &mut TcpStream) -> io::Result<ObservedSocks5Connect> {
    let mut head = [0_u8; 4];
    stream.read_exact(&mut head).await?;
    if head[..3] != [5, 1, 0] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected SOCKS5 CONNECT prefix",
        ));
    }
    let host = match head[3] {
        1 => {
            let mut address = [0_u8; 4];
            stream.read_exact(&mut address).await?;
            IpAddr::V4(Ipv4Addr::from(address)).to_string()
        }
        3 => {
            let length = stream.read_u8().await?;
            if length == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SOCKS5 domain was empty",
                ));
            }
            let mut host = vec![0_u8; usize::from(length)];
            stream.read_exact(&mut host).await?;
            String::from_utf8(host).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "SOCKS5 domain was not UTF-8")
            })?
        }
        4 => {
            let mut address = [0_u8; 16];
            stream.read_exact(&mut address).await?;
            IpAddr::V6(Ipv6Addr::from(address)).to_string()
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported SOCKS5 target address type",
            ));
        }
    };
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(ObservedSocks5Connect {
        host,
        port: u16::from_be_bytes(port),
    })
}
