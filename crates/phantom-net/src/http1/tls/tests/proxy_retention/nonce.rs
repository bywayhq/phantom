//! A primed Digest cache makes premature nonce reservations observable.
use super::*;
use crate::proxy::{HttpConnectError, ProxyCredentialCache};

#[tokio::test]
async fn quiet_and_invalid_openings_do_not_advance_a_primed_digest_nonce() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(TestServerAlpn::Http1)?;
        let connector = test_connector(&identity)?.with_proxy_credential_cache(ProxyCredentialCache::new());
        let (address, listener) = loopback_listener().await?;
        let family = AddressFamilyMemory::default();
        let credentials = HttpDigestCredentials::new("user", "secret")?;
        let credentials = Some(HttpProxyAuthentication::Digest(&credentials));
        let current = fields("current", true);
        for second in [false, true] {
            if second {
                for invalid in [false, true] {
                    let route = route("127.0.0.1", address.port(), &current, credentials);
                    let (opening, _) = connector.open_http_connect_retaining(route, TEST_SERVER_NAME, &family).await?;
                    let (mut peer, _) = listener.accept().await?;
                    if invalid {
                        let invalid = fields("invalid\r\nfield", true);
                        let result = opening.finish(HttpConnectRoute { headers: &invalid, ..route }).await;
                        assert!(matches!(result, Err(Http1TlsError::Proxy(HttpConnectError::InvalidHeaderValue { .. }))));
                    } else { drop(opening); }
                    let mut bytes = Vec::new();
                    peer.read_to_end(&mut bytes).await?;
                    assert!(bytes.is_empty());
                }
            }
            let (opening, _) = connector.open_http_connect_retaining(route("127.0.0.1", address.port(), &current, credentials), TEST_SERVER_NAME, &family).await?;
            let (mut peer, _) = listener.accept().await?;
            let client = async {
                let connection = opening.finish(route("127.0.0.1", address.port(), &current, credentials)).await?;
                let response = connection.send_get(OriginForm::parse("/nonce")?, vec![RequestHeader::new("Host", TEST_SERVER_NAME)]).await?;
                assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
                TestResult::Ok(())
            };
            let server = async {
                let first = String::from_utf8(read_plaintext_head(&mut peer).await?)?;
                let authenticated = if second {
                    assert!(first.contains("Proxy-Authorization: Digest "), "accepted Digest session was not reused");
                    first
                } else {
                    assert!(!first.contains("Proxy-Authorization:"));
                    peer.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Digest realm=\"proxy\", nonce=\"one\", algorithm=SHA-256, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n").await?;
                    String::from_utf8(read_plaintext_head(&mut peer).await?)?
                };
                assert!(authenticated.contains(if second { "nc=00000002" } else { "nc=00000001" }));
                peer.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
                let ssl = btls::ssl::Ssl::new(acceptor.context())?;
                let mut tls = SslStream::new(ssl, peer)?;
                Pin::new(&mut tls).accept().await?;
                assert_eq!(read_plaintext_head(&mut tls).await?, b"GET /nonce HTTP/1.1\r\nHost: server.phantom.test\r\n\r\n");
                tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await?;
                TestResult::Ok(())
            };
            tokio::try_join!(client, server)?;
        }
        Ok(())
    }).await?
}
