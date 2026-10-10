use std::{net::Ipv4Addr, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use super::{ConnectionPeer, TestResult, http1_connect};

const DEADLINE: Duration = Duration::from_secs(5);

#[tokio::test]
async fn dropping_an_established_tunnel_closes_its_actual_relay() -> TestResult<()> {
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy_address = proxy.local_addr()?;
    let origin_address = origin.local_addr()?;
    let launcher = ConnectionPeer::spawn(http1_connect(proxy, origin_address));
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

    assert!(matches!(closed, Ok(Err(ref error)) if super::super::tls::is_peer_gone(error)));
    Ok(())
}

#[tokio::test]
async fn a_connect_relay_forwards_nonzero_bytes_in_both_directions() -> TestResult<()> {
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = proxy.local_addr()?;
    let launcher = ConnectionPeer::spawn(http1_connect(proxy, origin.local_addr()?));
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

#[tokio::test]
async fn dropping_an_http2_tunnel_closes_its_origin_connection_with_client_live() -> TestResult<()>
{
    use super::super::tls::{
        H1_ALPN, H2_ALPN, TestIdentity, accept_tls, client_builder, read_head,
    };
    use phantom::{HttpProtocol, HttpProxy, Route};

    let identity = TestIdentity::generate()?;
    let proxy_identity = TestIdentity::generate()?;
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let origin_address = origin.local_addr()?;
    let origin_acceptor = identity.acceptor(H1_ALPN)?;
    let mut origin_peer = ConnectionPeer::spawn(async move {
        let mut stream = accept_tls(origin, origin_acceptor).await?;
        let head = read_head(&mut stream).await?;
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await?;
        stream.flush().await?;
        TestResult::Ok((head, stream.read_u8().await))
    });
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy_address = listener.local_addr()?;
    let launcher = ConnectionPeer::spawn(super::http2_connect(
        listener,
        proxy_identity.acceptor(H2_ALPN)?,
        origin_address,
    ));
    let client = client_builder(&identity, true)
        .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
        .route(Route::http_proxy(
            HttpProxy::new(&format!("https://{proxy_address}"))?.with_http2_transport()?,
        ))
        .build()?;

    let response = timeout(
        DEADLINE,
        client
            .get(
                HttpProtocol::Http1,
                &format!("https://{origin_address}/ownership"),
            )?
            .send(),
    )
    .await??;
    assert_eq!(response.status(), phantom::StatusCode::NO_CONTENT);
    drop(response);
    let tunnel = timeout(DEADLINE, launcher).await???;
    drop(tunnel);

    let closed = timeout(DEADLINE, &mut origin_peer).await;
    if closed.is_err() {
        origin_peer.abort();
        let joined = timeout(DEADLINE, origin_peer).await?;
        assert!(matches!(joined, Err(ref error) if error.is_cancelled()));
    }
    let (head, read) = closed???;
    assert!(head.starts_with(b"GET /ownership HTTP/1.1\r\n"));
    assert!(matches!(read, Err(ref error) if super::super::tls::is_peer_gone(error)));
    let rebound = TcpListener::bind(origin_address).await?;
    assert_eq!(rebound.local_addr()?, origin_address);
    drop(client);
    Ok(())
}
