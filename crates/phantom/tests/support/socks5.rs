use std::{io, net::SocketAddr};

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

pub(crate) async fn forward_one_socks5(
    listener: TcpListener,
    origin: SocketAddr,
) -> TestResult<ObservedSocks5Connect> {
    let (mut downstream, _) = listener.accept().await?;
    negotiate_no_auth(&mut downstream).await?;
    let request = read_domain_connect(&mut downstream).await?;
    let mut upstream = TcpStream::connect(origin).await?;
    downstream
        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
        .await?;
    downstream.flush().await?;
    copy_bidirectional(&mut downstream, &mut upstream).await?;
    Ok(request)
}

pub(crate) async fn reject_one_socks5(
    listener: TcpListener,
    reply: u8,
) -> TestResult<ObservedSocks5Connect> {
    let (mut stream, _) = listener.accept().await?;
    negotiate_no_auth(&mut stream).await?;
    let request = read_domain_connect(&mut stream).await?;
    stream
        .write_all(&[5, reply, 0, 1, 0, 0, 0, 0, 0, 0])
        .await?;
    stream.shutdown().await?;
    Ok(request)
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

async fn read_domain_connect(stream: &mut TcpStream) -> io::Result<ObservedSocks5Connect> {
    let mut head = [0_u8; 5];
    stream.read_exact(&mut head).await?;
    if head[..4] != [5, 1, 0, 3] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 request was not a remote-DNS CONNECT",
        ));
    }
    let length = usize::from(head[4]);
    if length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 domain was empty",
        ));
    }
    let mut host = vec![0_u8; length];
    stream.read_exact(&mut host).await?;
    let host = String::from_utf8(host)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "SOCKS5 domain was not UTF-8"))?;
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(ObservedSocks5Connect {
        host,
        port: u16::from_be_bytes(port),
    })
}
