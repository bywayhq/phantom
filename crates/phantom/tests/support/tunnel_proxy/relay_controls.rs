use std::{io, net::Ipv4Addr, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use super::{TestResult, http1_connect};

const DEADLINE: Duration = Duration::from_secs(5);

#[tokio::test]
async fn dropping_an_established_tunnel_closes_its_actual_relay() -> TestResult<()> {
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy_address = proxy.local_addr()?;
    let origin_address = origin.local_addr()?;
    let launcher = tokio::spawn(http1_connect(proxy, origin_address));
    let mut client = TcpStream::connect(proxy_address).await?;
    client
        .write_all(b"CONNECT retained.test:443 HTTP/1.1\r\nHost: retained.test\r\n\r\n")
        .await?;
    let (mut upstream, _) = timeout(DEADLINE, origin.accept()).await??;
    let mut established = [0_u8; 39];
    timeout(DEADLINE, client.read_exact(&mut established)).await??;
    assert_eq!(&established, b"HTTP/1.1 200 Connection Established\r\n\r\n");
    let tunnel = timeout(DEADLINE, launcher).await???;

    client.write_all(b"ping").await?;
    let mut observed = [0_u8; 4];
    timeout(DEADLINE, upstream.read_exact(&mut observed)).await??;
    assert_eq!(&observed, b"ping");
    upstream.write_all(b"pong").await?;
    timeout(DEADLINE, client.read_exact(&mut observed)).await??;
    assert_eq!(&observed, b"pong");
    drop(tunnel);

    let closed = timeout(DEADLINE, upstream.read_u8()).await;
    client.shutdown().await?;
    upstream.shutdown().await?;
    drop(client);
    drop(upstream);

    assert!(matches!(closed, Ok(Err(ref error)) if error.kind() == io::ErrorKind::UnexpectedEof));
    Ok(())
}

#[tokio::test]
async fn a_connect_relay_forwards_nonzero_bytes_in_both_directions() -> TestResult<()> {
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = proxy.local_addr()?;
    let launcher = tokio::spawn(http1_connect(proxy, origin.local_addr()?));
    let mut client = TcpStream::connect(address).await?;
    client
        .write_all(b"CONNECT positive.test:443 HTTP/1.1\r\n\r\n")
        .await?;
    let (mut upstream, _) = timeout(DEADLINE, origin.accept()).await??;
    let mut established = [0_u8; 39];
    timeout(DEADLINE, client.read_exact(&mut established)).await??;
    assert_eq!(&established, b"HTTP/1.1 200 Connection Established\r\n\r\n");
    let tunnel = timeout(DEADLINE, launcher).await???;

    client.write_all(b"request bytes").await?;
    let mut request = [0_u8; 13];
    timeout(DEADLINE, upstream.read_exact(&mut request)).await??;
    assert_eq!(&request, b"request bytes");
    upstream.write_all(b"reply bytes").await?;
    let mut reply = [0_u8; 11];
    timeout(DEADLINE, client.read_exact(&mut reply)).await??;
    assert_eq!(&reply, b"reply bytes");

    client.shutdown().await?;
    upstream.shutdown().await?;
    assert_eq!(timeout(DEADLINE, client.read(&mut [0_u8; 1])).await??, 0);
    drop(tunnel);
    Ok(())
}
