use tokio::{
    io::{AsyncWriteExt, copy_bidirectional},
    net::TcpStream,
};

use super::*;
use crate::support::tls::{H1_ALPN, accept_tls};

#[tokio::test]
async fn digest_connect_verifies_the_proxy_and_keeps_authorization_out_of_origin_tls() -> TestResult
{
    tokio::time::timeout(Duration::from_secs(15), async {
        let identity = TestIdentity::generate()?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let origin_acceptor = identity.acceptor(H1_ALPN)?;
        let origin = ConnectionPeer::spawn(async move {
            let mut stream = accept_tls(origin_listener, origin_acceptor).await?;
            let head = read_head(&mut stream).await?;
            assert!(authorization(&head)?.is_none());
            assert!(head.starts_with(b"GET /resource HTTP/1.1\r\n"));
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await?;
            Ok(())
        });
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let authority = origin_address.to_string();
        let peer = ConnectionPeer::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let anonymous = read_head(&mut stream).await?;
            assert!(authorization(&anonymous)?.is_none());
            stream.write_all(challenge("SHA-256", "first", false).as_bytes()).await?;
            let head = read_head(&mut stream).await?;
            assert!(head.starts_with(format!("CONNECT {authority} HTTP/1.1\r\n").as_bytes()));
            let value = authorization(&head)?.ok_or("CONNECT authorization missing")?;
            let proof = oracle::verify(&value, "CONNECT", &authority, "SHA-256", "first")?;
            stream.write_all(format!("HTTP/1.1 200 Connection Established\r\nProxy-Authentication-Info: {}\r\n\r\n", proof.information).as_bytes()).await?;
            let mut upstream = TcpStream::connect(origin_address).await?;
            copy_bidirectional(&mut stream, &mut upstream).await?;
            Ok(())
        });
        let operation = async {
            let route = Route::http_proxy(HttpProxy::new(&format!("http://{address}"))?.with_digest_auth("user", "password")?);
            let client = client_builder(&identity, false).route(route).build()?;
            let response = client.get_with_protocol(HttpProtocol::Http1, &format!("https://{origin_address}/resource"))?.send().await?;
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
            Ok(())
        }.await;
        let operation = finish_peer(operation, peer).await;
        finish_peer(operation, origin).await
    }).await.map_err(|_| "Digest origin isolation deadline")?
}
