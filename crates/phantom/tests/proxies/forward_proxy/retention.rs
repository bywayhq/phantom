//! Public forwarding consumers of the retained plaintext setup path.
use crate::support::tls::{TestIdentity, TestResult, read_head, tls_settings};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, HttpProxy, RequestHeader, Route,
    profile::{ClientProfile, browser::firefox},
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
async fn plaintext_forwarding_with_backup_selection_keeps_absolute_target_and_current_order()
-> TestResult<()> {
    forward(Auth::None).await
}

#[tokio::test]
async fn plaintext_forwarding_with_backup_selection_keeps_basic_challenge_replay() -> TestResult<()>
{
    forward(Auth::Basic).await
}

#[tokio::test]
async fn plaintext_forwarding_with_backup_selection_keeps_digest_challenge_replay() -> TestResult<()>
{
    forward(Auth::Digest).await
}

async fn forward(auth: Auth) -> TestResult<()> {
    timeout(Duration::from_secs(5), async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy = HttpProxy::new(&format!("http://{address}"))?;
        let proxy = match auth { Auth::None => proxy, Auth::Basic => proxy.with_basic_auth("user", "secret")?, Auth::Digest => proxy.with_digest_auth("user", "secret")? };
        let profile = ClientProfile::new(tls_settings()).with_tcp(firefox::v157_tcp());
        let client = Client::builder(profile).add_root_certificate_der(identity.root_der).route(Route::http_proxy(proxy)).build()?;
        let request = async {
            let response = client.get_with_protocol(HttpProtocol::Http1, "http://target.invalid/current")?.headers(vec![RequestHeader::new("X-First", "current"), RequestHeader::new("x-Second", "claim")]).send().await?;
            assert_eq!(response.status(), 200);
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
            TestResult::Ok(())
        };
        let proxy = async {
            let (mut stream, _) = listener.accept().await?;
            assert_eq!(read_head(&mut stream).await?, b"GET http://target.invalid/current HTTP/1.1\r\nHost: target.invalid\r\nX-First: current\r\nx-Second: claim\r\n\r\n");
            if !matches!(auth, Auth::None) {
                let challenge = match auth { Auth::None => return Err("anonymous request challenged".into()), Auth::Basic => "Basic realm=\"proxy\"", Auth::Digest => "Digest realm=\"proxy\", nonce=\"one\", algorithm=SHA-256, qop=\"auth\"" };
                stream.write_all(format!("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: {challenge}\r\nContent-Length: 0\r\n\r\n").as_bytes()).await?;
                let authenticated = String::from_utf8(read_head(&mut stream).await?)?;
                assert!(authenticated.starts_with("GET http://target.invalid/current HTTP/1.1\r\nHost: target.invalid\r\nX-First: current\r\nx-Second: claim\r\nProxy-Authorization: "));
                match auth { Auth::Basic => assert!(authenticated.ends_with("Basic dXNlcjpzZWNyZXQ=\r\n\r\n")), Auth::Digest => { assert!(authenticated.contains("Proxy-Authorization: Digest ")); assert!(authenticated.contains("nc=00000001")); }, Auth::None => return Err("anonymous credentials emitted".into()) }
            }
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await?;
            TestResult::Ok(())
        };
        tokio::try_join!(request, proxy)?;
        assert!(std::future::poll_fn(|cx| std::task::Poll::Ready(listener.poll_accept(cx).is_pending())).await, "forward authentication redialled");
        Ok(())
    }).await?
}
