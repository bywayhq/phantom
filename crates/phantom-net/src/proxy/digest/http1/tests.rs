use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use super::*;
use crate::proxy::{
    DigestPolicy, ProxyScheme,
    digest::tests::proxy_peer::{self, TestResult},
};

const AUTHORITY: &str = "origin.example:443";

#[tokio::test]
async fn every_digest_algorithm_handles_stale_nextnonce_and_origin_isolation() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
    for algorithm in proxy_peer::ALGORITHMS {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let peer = proxy_peer::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            assert!(
                proxy_peer::authorization(&proxy_peer::read_head(&mut stream).await?)?.is_none()
            );
            challenge(&mut stream, algorithm, "first", false).await?;
            let value = proxy_peer::authorization(&proxy_peer::read_head(&mut stream).await?)?
                .ok_or("missing first authorization")?;
            let first = proxy_peer::verify(&value, "CONNECT", AUTHORITY, algorithm, "first")?;
            assert_eq!(first.count, "00000001");
            challenge(&mut stream, algorithm, "second", true).await?;
            let value = proxy_peer::authorization(&proxy_peer::read_head(&mut stream).await?)?
                .ok_or("missing stale authorization")?;
            let second = proxy_peer::verify(&value, "CONNECT", AUTHORITY, algorithm, "second")?;
            assert_eq!(second.count, "00000001");
            assert_ne!(first.cnonce, second.cnonce);
            stream.write_all(format!("HTTP/1.1 200 Connection Established\r\nProxy-Authentication-Info: {}, nextnonce=\"third\"\r\n\r\nready", second.information).as_bytes()).await?;
            let origin = proxy_peer::read_head(&mut stream).await?;
            assert!(origin.starts_with(b"GET /resource HTTP/1.1\r\n"));
            assert!(proxy_peer::authorization(&origin)?.is_none());
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).await?, 0);
            let (mut stream, _) = listener.accept().await?;
            let value = proxy_peer::authorization(&proxy_peer::read_head(&mut stream).await?)?
                .ok_or("nextnonce was not preemptive")?;
            let third = proxy_peer::verify(&value, "CONNECT", AUTHORITY, algorithm, "third")?;
            assert_eq!(third.count, "00000001");
            stream.write_all(format!("HTTP/1.1 200 Connection Established\r\nProxy-Authentication-Info: {}\r\n\r\n", third.information).as_bytes()).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let credentials = HttpDigestCredentials::new("user", "password")?
            .with_policy(DigestPolicy::AllowLegacyMd5);
        let scope = DigestCacheKey::new(
            ProxyScheme::Http,
            "127.0.0.1",
            address.port(),
            None,
            credentials.policy(),
        );
        let headers = headers();
        let open = || async {
            TcpStream::connect(address)
                .await
                .map_err(HttpConnectError::Connect)
        };
        let mut tunnel = connect(&scope, &credentials, true, AUTHORITY, &headers, open).await?;
        let mut prefix = [0; 5];
        tunnel.read_exact(&mut prefix).await?;
        assert_eq!(&prefix, b"ready");
        tunnel
            .write_all(b"GET /resource HTTP/1.1\r\nHost: origin.example\r\n\r\n")
            .await?;
        drop(tunnel);
        drop(connect(&scope, &credentials, true, AUTHORITY, &headers, open).await?);
        peer.await??;
    }
    Ok(())
    }).await.map_err(|_| "Digest algorithm peer deadline")?
}

#[tokio::test]
async fn wrong_proxy_proof_never_accepts_or_remembers_the_tunnel() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let peer = proxy_peer::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        proxy_peer::read_head(&mut stream).await?;
        challenge(&mut stream, "SHA-256", "first", false).await?;
        let value = proxy_peer::authorization(&proxy_peer::read_head(&mut stream).await?)?
            .ok_or("authorization missing")?;
        let proof = proxy_peer::verify(&value, "CONNECT", AUTHORITY, "SHA-256", "first")?;
        stream.write_all(format!("HTTP/1.1 200 Connection Established\r\nProxy-Authentication-Info: {}, nextnonce=\"unsafe\"\r\n\r\n", proof.information.replacen("rspauth=\"", "rspauth=\"0", 1)).as_bytes()).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let credentials = HttpDigestCredentials::new("user", "password")?;
    let scope = DigestCacheKey::new(
        ProxyScheme::Http,
        "127.0.0.1",
        address.port(),
        None,
        credentials.policy(),
    );
    let outcome = connect(
        &scope,
        &credentials,
        true,
        AUTHORITY,
        &headers(),
        || async {
            TcpStream::connect(address)
                .await
                .map_err(HttpConnectError::Connect)
        },
    )
    .await;
    assert!(matches!(
        outcome,
        Err(HttpConnectError::Digest(
            super::super::DigestAuthError::InvalidResponseAuthentication
        ))
    ));
    assert!(credentials.remembered(&scope).is_none());
    peer.await??;
    Ok(())
    }).await.map_err(|_| "Digest proof peer deadline")?
}

fn headers() -> [HttpConnectHeader; 2] {
    [
        HttpConnectHeader::authority("Host"),
        HttpConnectHeader::proxy_authorization("Proxy-Authorization"),
    ]
}

#[tokio::test]
async fn redial_after_a_challenged_connection_closes_reserves_a_new_count() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let peer = proxy_peer::spawn(async move {
            let (mut first, _) = listener.accept().await?;
            proxy_peer::read_head(&mut first).await?;
            challenge(&mut first, "SHA-256", "first", false).await?;
            let value = proxy_peer::authorization(&proxy_peer::read_head(&mut first).await?)?.ok_or("first authorization missing")?;
            let first_proof = proxy_peer::verify(&value, "CONNECT", AUTHORITY, "SHA-256", "first")?;
            drop(first);
            let (mut second, _) = listener.accept().await?;
            let value = proxy_peer::authorization(&proxy_peer::read_head(&mut second).await?)?.ok_or("redial authorization missing")?;
            let second_proof = proxy_peer::verify(&value, "CONNECT", AUTHORITY, "SHA-256", "first")?;
            assert_eq!(first_proof.count, "00000001");
            assert_eq!(second_proof.count, "00000002");
            assert_eq!(first_proof.cnonce, second_proof.cnonce);
            second.write_all(format!("HTTP/1.1 200 Connection Established\r\nProxy-Authentication-Info: {}\r\n\r\n", second_proof.information).as_bytes()).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let credentials = HttpDigestCredentials::new("user", "password")?;
        let scope = DigestCacheKey::new(ProxyScheme::Http, "127.0.0.1", address.port(), None, credentials.policy());
        drop(connect(&scope, &credentials, false, AUTHORITY, &headers(), || async { TcpStream::connect(address).await.map_err(HttpConnectError::Connect) }).await?);
        peer.await??;
        Ok(())
    }).await.map_err(|_| "Digest redial peer deadline")?
}

async fn challenge(
    stream: &mut TcpStream,
    algorithm: &str,
    nonce: &str,
    stale: bool,
) -> TestResult {
    stream.write_all(format!("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: {}\r\nContent-Length: 0\r\n\r\n", proxy_peer::challenge(algorithm, nonce, stale)).as_bytes()).await?;
    Ok(())
}
