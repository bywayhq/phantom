use std::{pin::Pin, time::Duration};

use btls::ssl::Ssl;
use http::{Method, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::proxy_peer::{self, TestResult};
use crate::{
    proxy::{
        DigestPolicy, HttpConnectHeader, HttpDigestCredentials, HttpsProxyConnector,
        HttpsProxyProtocol, ProxyCredentialCache,
    },
    tls::test_support::{TEST_SERVER_NAME, TestIdentity, TestServerAlpn, loopback_listener},
};

const AUTHORITY: &str = "origin.example:443";

#[tokio::test]
async fn http2_wrong_proxy_proof_fails_without_accepting_nextnonce() -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), async {
        let identity = TestIdentity::generate()?;
        let connector = HttpsProxyConnector::new_with_additional_roots(
            &phantom_profile::browser::chrome::v154_tcp_tls(),
            [identity.root_der()],
        )?
        .with_http2_settings(&phantom_profile::browser::chrome::v154_http2())
        .with_protocol(HttpsProxyProtocol::Http2);
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let peer = proxy_peer::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut tls = tokio_btls::SslStream::new(Ssl::new(acceptor.context())?, tcp)?;
            Pin::new(&mut tls).accept().await?;
            let mut connection = ::http2::server::handshake(tls).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("anonymous CONNECT missing")??;
            assert!(!request.headers().contains_key("proxy-authorization"));
            respond.send_response(
                Response::builder()
                    .status(407)
                    .header(
                        "proxy-authenticate",
                        proxy_peer::challenge("SHA-256", "first", false),
                    )
                    .body(())?,
                true,
            )?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("authorized CONNECT missing")??;
            let value = request
                .headers()
                .get("proxy-authorization")
                .ok_or("authorization missing")?
                .to_str()?;
            let proof = proxy_peer::verify(value, "CONNECT", AUTHORITY, "SHA-256", "first")?;
            respond.send_response(
                Response::builder()
                    .header(
                        "proxy-authentication-info",
                        format!(
                            "{}, nextnonce=unsafe",
                            proof.information.replacen("rspauth=\"", "rspauth=\"0", 1)
                        ),
                    )
                    .body(())?,
                false,
            )?;
            while let Some(result) = connection.accept().await {
                result?;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let credentials = HttpDigestCredentials::new("user", "password")?;
        let headers = [
            HttpConnectHeader::authority("Host"),
            HttpConnectHeader::proxy_authorization("Proxy-Authorization"),
        ];
        let result = connector
            .connect_tunnel_with_digest_auth(
                "127.0.0.1",
                address.port(),
                TEST_SERVER_NAME,
                AUTHORITY,
                &headers,
                &credentials,
            )
            .await;
        assert!(matches!(
            result,
            Err(crate::proxy::HttpConnectError::Digest(
                crate::proxy::DigestAuthError::InvalidResponseAuthentication
            ))
        ));
        let scope = super::super::cache::DigestCacheKey::new(
            crate::proxy::ProxyScheme::Https,
            "127.0.0.1",
            address.port(),
            Some(connector.digest_settings()),
            credentials.policy(),
        )
        .with_server_name(TEST_SERVER_NAME);
        assert!(credentials.remembered(&scope).is_none());
        peer.await??;
        Ok(())
    })
    .await
    .map_err(|_| "Digest invalid proof deadline")?
}

#[tokio::test]
async fn all_digest_algorithms_use_exact_authority_stale_proof_and_nextnonce_on_http2() -> TestResult
{
    tokio::time::timeout(Duration::from_secs(30), async {
        for algorithm in proxy_peer::ALGORITHMS {
            let identity = TestIdentity::generate()?;
            let connector = HttpsProxyConnector::new_with_additional_roots(&phantom_profile::browser::chrome::v154_tcp_tls(), [identity.root_der()])?
                .with_http2_settings(&phantom_profile::browser::chrome::v154_http2())
                .with_protocol(HttpsProxyProtocol::Http2)
                .with_http2_proxy_pool(crate::proxy::Http2ProxyPool::new())
                .with_proxy_credential_cache(ProxyCredentialCache::new());
            let (address, listener) = loopback_listener().await?;
            let acceptor = identity.acceptor(TestServerAlpn::H2)?;
            let (done_tx, mut done_rx) = tokio::sync::oneshot::channel();
            let peer = proxy_peer::spawn(async move {
                let (tcp, _) = listener.accept().await?;
                let mut tls = tokio_btls::SslStream::new(Ssl::new(acceptor.context())?, tcp)?;
                Pin::new(&mut tls).accept().await?;
                let mut connection = ::http2::server::handshake(tls).await?;
                let mut held = Vec::new();
                let mut prior_cnonce = None;
                for index in 0..4 {
                    let (request, mut respond) = connection.accept().await.ok_or("CONNECT missing")??;
                    assert_eq!(request.method(), Method::CONNECT);
                    assert_eq!(request.uri().authority().map(|value| value.as_str()), Some(AUTHORITY));
                    let authorization = request.headers().get("proxy-authorization");
                    if index == 0 {
                        assert!(authorization.is_none());
                    } else {
                        let nonce = ["", "first", "second", "third"][index];
                        let proof = proxy_peer::verify(authorization.ok_or("authorization missing")?.to_str()?, "CONNECT", AUTHORITY, algorithm, nonce)?;
                        assert_eq!(proof.count, "00000001");
                        if let Some(prior) = prior_cnonce { assert_ne!(proof.cnonce, prior); }
                        prior_cnonce = Some(proof.cnonce);
                        if index >= 2 {
                            let information = if index == 2 { format!("{}, nextnonce=third", proof.information) } else { proof.information };
                            let mut send = respond.send_response(Response::builder().header("proxy-authentication-info", information).body(())?, false)?;
                            send.send_data(bytes::Bytes::from_static(b"ready"), false)?;
                            held.push(request);
                            continue;
                        }
                    }
                    let nonce = if index == 0 { "first" } else { "second" };
                    respond.send_response(Response::builder().status(407).header("proxy-authenticate", proxy_peer::challenge(algorithm, nonce, index == 1)).body(())?, true)?;
                    held.push(request);
                }
                tokio::select! {
                    _ = &mut done_rx => {},
                    result = connection.accept() => { if let Some(request) = result { request?; return Err("unexpected fifth CONNECT".into()); } }
                }
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            });
            let credentials = HttpDigestCredentials::new("user", "password")?.with_policy(DigestPolicy::AllowLegacyMd5);
            let headers = [HttpConnectHeader::authority("Host"), HttpConnectHeader::proxy_authorization("Proxy-Authorization")];
            for _ in 0..2 {
                let result = connector.connect_tunnel_with_digest_auth("127.0.0.1", address.port(), TEST_SERVER_NAME, AUTHORITY, &headers, &credentials).await;
                let mut tunnel = match result {
                    Ok(tunnel) => tunnel,
                    Err(error) => {
                        let peer_result = tokio::time::timeout(Duration::from_secs(5), &mut { peer }).await;
                        return Err(format!("client: {error:?}; peer: {peer_result:?}").into());
                    }
                };
                let mut prefix = [0; 5];
                tunnel.read_exact(&mut prefix).await?;
                assert_eq!(&prefix, b"ready");
                tunnel.write_all(b"GET /resource HTTP/1.1\r\nHost: origin.example\r\n\r\n").await?;
                drop(tunnel);
            }
            done_tx.send(()).map_err(|()| "peer exited early")?;
            peer.await??;
        }
        Ok(())
    }).await.map_err(|_| "Digest HTTP/2 peer deadline")?
}
