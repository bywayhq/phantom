//! Digest routes against independent loopback proxy calculations.

use std::{net::Ipv4Addr, time::Duration};

use http_body_util::BodyExt;
use phantom::{DigestPolicy, HttpDigestCredentials, HttpProtocol, HttpProxy, Route};
use tokio::{io::AsyncWriteExt, net::TcpListener};

use crate::support::{
    tls::{H2_ALPN, TestIdentity, accept_tls_stream, client_builder, read_head},
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

mod connect;
mod oracle;
mod response_completion;
mod trailers;
use oracle::TestResult;

const URL: &str = "http://unresolvable.invalid:8080/a/%2e%2e/final?value=%2f";
const PATH: &str = "/a/%2e%2e/final?value=%2f";

#[tokio::test]
async fn digest_forwarding_hashes_absolute_form_and_reuses_the_connection_for_stale() -> TestResult
{
    tokio::time::timeout(Duration::from_secs(30), async {
        for algorithm in oracle::ALGORITHMS {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let peer = ConnectionPeer::spawn(async move {
                let (mut stream, _) = listener.accept().await?;
                let anonymous = read_head(&mut stream).await?;
                assert!(authorization(&anonymous)?.is_none());
                stream.write_all(challenge(algorithm, "first", false).as_bytes()).await?;
                let first = authorization(&read_head(&mut stream).await?)?.ok_or("missing authorization")?;
                let first = oracle::verify(&first, "GET", URL, algorithm, "first")?;
                stream.write_all(challenge(algorithm, "second", true).as_bytes()).await?;
                let second = authorization(&read_head(&mut stream).await?)?.ok_or("missing stale authorization")?;
                let second = oracle::verify(&second, "GET", URL, algorithm, "second")?;
                assert_eq!(first.count, "00000001");
                assert_eq!(second.count, "00000001");
                assert_ne!(first.cnonce, second.cnonce);
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nProxy-Authentication-Info: {}, nextnonce=third\r\n\r\nok", second.information).as_bytes()).await?;
                let third = authorization(&read_head(&mut stream).await?)?.ok_or("nextnonce not preemptive")?;
                let third = oracle::verify(&third, "GET", URL, algorithm, "third")?;
                assert_eq!(third.count, "00000001");
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nProxy-Authentication-Info: {}\r\n\r\nok", third.information).as_bytes()).await?;
                Ok(())
            });
            let operation = async {
                let identity = TestIdentity::generate()?;
                let credentials = HttpDigestCredentials::new("user", "password")?.with_policy(DigestPolicy::AllowLegacyMd5);
                let route = Route::http_proxy(HttpProxy::new(&format!("http://{address}"))?.with_digest_credentials(credentials));
                let client = client_builder(&identity, false).route(route).build()?;
                for _ in 0..2 {
                    let response = client.get(HttpProtocol::Http1, URL)?.send().await?;
                    assert_eq!(response.status(), http::StatusCode::OK);
                    assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
                }
                Ok(client)
            }.await;
            finish_peer(operation, peer).await?;
        }
        Ok(())
    }).await.map_err(|_| "Digest forwarding deadline")?
}

#[tokio::test]
async fn digest_http2_forwarding_hashes_the_encoded_path_and_verifies_proxy_proof() -> TestResult {
    tokio::time::timeout(Duration::from_secs(15), async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel();
        let peer = ConnectionPeer::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let stream = accept_tls_stream(tcp, acceptor).await?;
            let mut connection = http2::server::handshake(stream).await?;
            for index in 0..2 {
                let (request, mut respond) = connection.accept().await.ok_or("forwarded request missing")??;
                assert_eq!(request.method(), http::Method::GET);
                assert_eq!(request.uri().path_and_query().map(|value| value.as_str()), Some(PATH));
                assert_eq!(request.uri().authority().map(|value| value.as_str()), Some("unresolvable.invalid:8080"));
                if index == 0 {
                    assert!(!request.headers().contains_key("proxy-authorization"));
                    respond.send_response(http::Response::builder().status(407).header("proxy-authenticate", oracle::challenge("SHA-256", "first", false)).body(())?, true)?;
                } else {
                    let value = request.headers().get("proxy-authorization").ok_or("missing Digest")?.to_str()?;
                    let proof = oracle::verify(value, "GET", PATH, "SHA-256", "first")?;
                    assert_eq!(proof.count, "00000001");
                    let mut send = respond.send_response(http::Response::builder().header("proxy-authentication-info", proof.information).body(())?, false)?;
                    send.send_data(bytes::Bytes::from_static(b"ok"), true)?;
                }
            }
            tokio::select! {
                _ = &mut done_rx => {},
                request = connection.accept() => { if let Some(request) = request { request?; return Err("unexpected forwarded request".into()); } }
            }
            Ok(())
        });
        let operation = async {
            let route = Route::http_proxy(HttpProxy::new(&format!("https://{address}"))?.with_http2_transport()?.with_digest_auth("user", "password")?);
            let client = client_builder(&identity, true).add_proxy_root_certificate_der(identity.root_der.clone()).route(route).build()?;
            let response = client.get(HttpProtocol::Http2, URL)?.send().await?;
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
            done_tx.send(()).map_err(|()| "peer exited early")?;
            Ok(client)
        }.await;
        finish_peer(operation, peer).await?;
        Ok(())
    }).await.map_err(|_| "Digest HTTP/2 forwarding deadline")?
}

fn challenge(algorithm: &str, nonce: &str, stale: bool) -> String {
    format!(
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: {}\r\nContent-Length: 0\r\n\r\n",
        oracle::challenge(algorithm, nonce, stale)
    )
}

fn authorization(head: &[u8]) -> TestResult<Option<String>> {
    let head = std::str::from_utf8(head)?;
    let fields: Vec<_> = head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("proxy-authorization"))
        .collect();
    assert!(fields.len() <= 1);
    Ok(fields.first().map(|(_, value)| value.trim().to_owned()))
}

async fn finish_peer<T>(
    primary: TestResult<T>,
    mut peer: ConnectionPeer<TestResult>,
) -> TestResult<T> {
    let cleanup = if primary.is_ok() {
        match tokio::time::timeout(Duration::from_secs(5), peer.join()).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(error.into()),
            Err(error) => finish_with_cleanup(Err(error.into()), peer.shutdown().await),
        }
    } else {
        peer.shutdown().await
    };
    finish_with_cleanup(primary, cleanup)
}
