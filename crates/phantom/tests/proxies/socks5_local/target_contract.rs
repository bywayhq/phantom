use std::net::{Ipv4Addr, SocketAddr};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use super::{ObservedSocks5Connect, TestResult, assert_local_target, bounded, forward_one_socks5};

async fn observe_literal_connect(connect: &[u8]) -> TestResult<(ObservedSocks5Connect, u16)> {
    let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let origin = origin_listener.local_addr()?;
    let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy = proxy_listener.local_addr()?;

    let origin_exchange = async {
        let (mut stream, _) = origin_listener.accept().await?;
        let mut request = [0_u8; 18];
        stream.read_exact(&mut request).await?;
        assert_eq!(&request, b"GET / HTTP/1.0\r\n\r\n");
        stream.write_all(b"HTTP/1.0 204\r\n\r\n").await?;
        stream.shutdown().await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    let proxy_exchange = forward_one_socks5(proxy_listener, origin);
    let client_exchange = exchange_literal_connect(proxy, connect);
    let (_, observation, ()) = tokio::try_join!(origin_exchange, proxy_exchange, client_exchange)?;
    Ok((observation, origin.port()))
}

async fn exchange_literal_connect(proxy: SocketAddr, connect: &[u8]) -> TestResult<()> {
    let mut client = TcpStream::connect(proxy).await?;
    client.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0_u8; 2];
    client.read_exact(&mut greeting).await?;
    assert_eq!(greeting, [5, 0]);

    client.write_all(connect).await?;
    let mut reply = [0_u8; 10];
    client.read_exact(&mut reply).await?;
    assert_eq!(reply, [5, 0, 0, 1, 127, 0, 0, 1, 0, 0]);

    client.write_all(b"GET / HTTP/1.0\r\n\r\n").await?;
    client.shutdown().await?;
    let mut response = Vec::new();
    client.read_to_end(&mut response).await?;
    assert_eq!(response, b"HTTP/1.0 204\r\n\r\n");
    Ok(())
}

async fn require_local(connect: &[u8]) -> TestResult<()> {
    let (observation, _) = observe_literal_connect(connect).await?;
    // The literal packet's port is 0x3039; forwarding deliberately uses its
    // separately held origin, so this check observes the requested wire target.
    assert_local_target(observation, 12_345)
}

async fn require_domain_rejected(connect: &[u8]) -> TestResult<()> {
    let (observation, _) = observe_literal_connect(connect).await?;
    assert!(
        assert_local_target(observation, 12_345).is_err(),
        "domain-form CONNECT counted as an IP literal"
    );
    Ok(())
}

#[tokio::test]
async fn a_numeric_ipv4_domain_is_not_a_local_ip_literal() -> TestResult<()> {
    bounded(require_domain_rejected(
        b"\x05\x01\x00\x03\x09127.0.0.1\x30\x39",
    ))
    .await
}

#[tokio::test]
async fn a_numeric_ipv6_domain_is_not_a_local_ip_literal() -> TestResult<()> {
    bounded(require_domain_rejected(b"\x05\x01\x00\x03\x03::1\x30\x39")).await
}

#[tokio::test]
async fn an_ordinary_domain_is_not_a_local_ip_literal() -> TestResult<()> {
    bounded(require_domain_rejected(
        b"\x05\x01\x00\x03\x09localhost\x30\x39",
    ))
    .await
}

#[tokio::test]
async fn an_ipv4_wire_literal_is_a_local_target() -> TestResult<()> {
    bounded(require_local(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x30\x39")).await
}

#[tokio::test]
async fn an_ipv6_wire_literal_is_a_local_target() -> TestResult<()> {
    bounded(require_local(
        b"\x05\x01\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x30\x39",
    ))
    .await
}
