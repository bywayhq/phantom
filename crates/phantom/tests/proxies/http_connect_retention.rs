//! Public exact-H1 CONNECT controls for the connected-opening path.
use crate::support::tls::{
    H1_ALPN, TestIdentity, TestResult, accept_tls_stream, read_head, tls_settings,
};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, HttpProxy, RequestHeader, Route,
    profile::{ClientProfile, ProxyConnectField, browser::firefox},
};
use std::{net::Ipv4Addr, time::Duration};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

#[derive(Clone, Copy)]
enum Auth {
    None,
    Basic,
    Digest,
}

#[tokio::test]
async fn exact_h1_plain_proxy_connect_preserves_current_profile_order_and_origin_verification()
-> TestResult<()> {
    public_request(Auth::None).await
}
#[tokio::test]
async fn exact_h1_plain_proxy_connect_preserves_basic_challenge_and_same_socket_replay()
-> TestResult<()> {
    public_request(Auth::Basic).await
}
#[tokio::test]
async fn exact_h1_plain_proxy_connect_preserves_digest_nonce_and_same_socket_replay()
-> TestResult<()> {
    public_request(Auth::Digest).await
}

async fn public_request(auth: Auth) -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy = HttpProxy::new(&format!("http://{address}"))?;
        let proxy = match auth { Auth::None => proxy, Auth::Basic => proxy.with_basic_auth("user", "secret")?, Auth::Digest => proxy.with_digest_auth("user", "secret")? };
        let mut template = firefox::v157_proxy_connect();
        template.http1_fields = vec![ProxyConnectField::FromRequest { name: "X-Claim".into() }, ProxyConnectField::Authority { name: "host".into() }, ProxyConnectField::ProxyAuthorization { name: "Proxy-Authorization".into() }];
        let profile = ClientProfile::new(tls_settings()).with_tcp(firefox::v157_tcp()).with_proxy_connect(template);
        let client = Client::builder(profile).add_root_certificate_der(identity.root_der.clone()).route(Route::http_proxy(proxy)).build()?;
        let request = async {
            let response = client.get(HttpProtocol::Http1, "https://127.0.0.1/current")?.headers(vec![RequestHeader::new("X-Claim", "current")]).send().await?;
            assert_eq!(response.status(), 200);
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
            TestResult::Ok(())
        };
        let peer = async {
            let (mut stream, _) = listener.accept().await?;
            let anonymous = read_head(&mut stream).await?;
            assert_eq!(anonymous, b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nX-Claim: current\r\nhost: 127.0.0.1:443\r\n\r\n");
            if !matches!(auth, Auth::None) {
                let challenge = match auth { Auth::None => return Err("anonymous request challenged".into()), Auth::Basic => "Basic realm=\"proxy\"", Auth::Digest => "Digest realm=\"proxy\", nonce=\"one\", algorithm=SHA-256, qop=\"auth\"" };
                stream.write_all(format!("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: {challenge}\r\nContent-Length: 0\r\n\r\n").as_bytes()).await?;
                let authenticated = String::from_utf8(read_head(&mut stream).await?)?;
                assert!(authenticated.starts_with("CONNECT 127.0.0.1:443 HTTP/1.1\r\nX-Claim: current\r\nhost: 127.0.0.1:443\r\nProxy-Authorization: "));
                match auth {
                    Auth::Basic => assert!(authenticated.ends_with("Basic dXNlcjpzZWNyZXQ=\r\n\r\n")),
                    Auth::Digest => { assert!(authenticated.contains("Proxy-Authorization: Digest ")); assert!(authenticated.contains("nc=00000001")); },
                    Auth::None => return Err("anonymous credentials emitted".into()),
                }
            }
            stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
            let mut tls = accept_tls_stream(stream, acceptor).await?;
            let origin = read_head(&mut tls).await?;
            assert_eq!(origin, b"GET /current HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Claim: current\r\n\r\n");
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await?;
            TestResult::Ok(())
        };
        tokio::try_join!(request, peer)?;
        Ok(())
    }).await?
}

#[tokio::test]
async fn a_rejected_connect_keeps_its_typed_cause_without_tls_or_a_fallback_dial() -> TestResult<()>
{
    timeout(Duration::from_secs(10), async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let profile = ClientProfile::new(tls_settings()).with_tcp(firefox::v157_tcp());
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der)
            .route(Route::http_proxy(HttpProxy::new(&format!(
                "http://{address}"
            ))?))
            .build()?;
        let request = async {
            let result = client
                .get(HttpProtocol::Http1, "https://127.0.0.1:443/rejected")?
                .send()
                .await;
            let error = match result {
                Err(error) => error,
                Ok(_) => return Err("403 proxy rejection was accepted".into()),
            };
            let mut cause: &(dyn std::error::Error + 'static) = &error;
            loop {
                if matches!(
                    cause.downcast_ref::<phantom_net::proxy::HttpConnectError>(),
                    Some(phantom_net::proxy::HttpConnectError::Rejected { status: 403 })
                ) {
                    break;
                }
                cause = cause
                    .source()
                    .ok_or("typed proxy rejection cause was lost")?;
            }
            TestResult::Ok(())
        };
        let peer = async {
            use tokio::io::AsyncReadExt;
            let (mut stream, _) = listener.accept().await?;
            assert!(
                read_head(&mut stream)
                    .await?
                    .starts_with(b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n")
            );
            stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await?;
            let mut after = Vec::new();
            stream.read_to_end(&mut after).await?;
            assert!(
                after.is_empty(),
                "rejected CONNECT sent origin TLS or a request"
            );
            TestResult::Ok(())
        };
        tokio::try_join!(request, peer)?;
        assert!(
            std::future::poll_fn(|context| std::task::Poll::Ready(
                listener.poll_accept(context).is_pending()
            ))
            .await,
            "proxy rejection redialled"
        );
        Ok(())
    })
    .await?
}

mod https;
