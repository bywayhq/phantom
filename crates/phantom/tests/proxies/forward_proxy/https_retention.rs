//! Public consumers; deterministic spare selection is covered in pool controls.
use super::{H1_ALPN, TestIdentity, TestResult, accept_tls_stream, read_head, tls_settings};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, HttpProxy, RequestErrorKind, RequestHeader, RequestTimeoutOverrides,
    Route, TimeoutOverride,
    profile::{ClientProfile, browser::firefox},
};
use std::{net::Ipv4Addr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::timeout,
};

#[derive(Clone, Copy)]
enum Auth {
    None,
    Basic,
    Digest,
}

#[tokio::test]
async fn https_forward_backup_path_keeps_absolute_target_and_current_header_order() -> TestResult<()>
{
    forward(Auth::None).await
}
#[tokio::test]
async fn https_forward_backup_path_replays_basic_on_the_existing_outer_tls_socket() -> TestResult<()>
{
    forward(Auth::Basic).await
}
#[tokio::test]
async fn https_forward_backup_path_replays_digest_without_connect_or_origin_tls() -> TestResult<()>
{
    forward(Auth::Digest).await
}

async fn forward(auth: Auth) -> TestResult<()> {
    timeout(super::TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy = HttpProxy::new(&format!("https://{address}"))?;
        let proxy = match auth { Auth::None => proxy, Auth::Basic => proxy.with_basic_auth("user", "secret")?, Auth::Digest => proxy.with_digest_auth("user", "secret")? };
        let profile = ClientProfile::new(tls_settings()).with_tcp(firefox::v157_tcp());
        let client = Client::builder(profile).add_proxy_root_certificate_der(identity.root_der).route(Route::http_proxy(proxy)).build()?;
        let request = async {
            let response = client.get(HttpProtocol::Http1, "http://target.invalid/current")?.headers(vec![RequestHeader::new("X-First", "current"), RequestHeader::new("x-Second", "claim")]).send().await?;
            assert_eq!(response.status(), 200);
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
            TestResult::Ok(())
        };
        let server = async {
            let (stream, _) = listener.accept().await?;
            let mut tls = accept_tls_stream(stream, acceptor).await?;
            assert_eq!(tls.ssl().selected_alpn_protocol(), Some(b"http/1.1".as_slice()));
            assert_eq!(read_head(&mut tls).await?, b"GET http://target.invalid/current HTTP/1.1\r\nHost: target.invalid\r\nX-First: current\r\nx-Second: claim\r\n\r\n");
            if !matches!(auth, Auth::None) {
                let challenge = match auth { Auth::None => return Err("anonymous challenge".into()), Auth::Basic => "Basic realm=\"proxy\"", Auth::Digest => "Digest realm=\"proxy\", nonce=\"one\", algorithm=SHA-256, qop=\"auth\"" };
                tls.write_all(format!("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: {challenge}\r\nContent-Length: 0\r\n\r\n").as_bytes()).await?;
                let replay = String::from_utf8(read_head(&mut tls).await?)?;
                assert!(replay.starts_with("GET http://target.invalid/current HTTP/1.1\r\nHost: target.invalid\r\nX-First: current\r\nx-Second: claim\r\nProxy-Authorization: "));
                match auth {
                    Auth::Basic => assert!(replay.ends_with("Basic dXNlcjpzZWNyZXQ=\r\n\r\n")),
                    Auth::Digest => { assert!(replay.contains("Proxy-Authorization: Digest ")); assert!(replay.contains("uri=\"http://target.invalid/current\"")); assert!(replay.contains("nc=00000001")); },
                    Auth::None => return Err("anonymous replay".into()),
                }
            }
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await?;
            TestResult::Ok(())
        };
        tokio::try_join!(request, server)?;
        assert!(std::future::poll_fn(|cx| std::task::Poll::Ready(listener.poll_accept(cx).is_pending())).await, "forward replay redialled");
        Ok(())
    }).await?
}

#[cfg(feature = "cookies")]
#[tokio::test]
async fn https_forward_claim_reads_current_origin_cookie_and_ignores_proxy_challenge_cookie()
-> TestResult<()> {
    timeout(super::TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let route = Route::http_proxy(HttpProxy::new(&format!("https://{}", listener.local_addr()?))?.with_basic_auth("user", "secret")?);
        let profile = ClientProfile::new(tls_settings()).with_tcp(firefox::v157_tcp());
        let client = Client::builder(profile).add_proxy_root_certificate_der(identity.root_der).route(route).cookies().build()?;
        let request = async {
            for path in ["first", "current"] {
                client.get(HttpProtocol::Http1, &format!("http://target.invalid/{path}"))?.header(RequestHeader::new("X-Claim", path)).send().await?.into_body().collect().await?;
            }
            TestResult::Ok(())
        };
        let server = async {
            let (stream, _) = listener.accept().await?;
            let mut tls = accept_tls_stream(stream, acceptor).await?;
            assert_eq!(read_head(&mut tls).await?, b"GET http://target.invalid/first HTTP/1.1\r\nHost: target.invalid\r\nX-Claim: first\r\n\r\n");
            tls.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nSet-Cookie: poisoned=challenge; Path=/\r\nContent-Length: 0\r\n\r\n").await?;
            let replay = String::from_utf8(read_head(&mut tls).await?)?;
            assert!(replay.contains("Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n"));
            assert!(!replay.to_ascii_lowercase().contains("cookie:"));
            tls.write_all(b"HTTP/1.1 200 OK\r\nSet-Cookie: accepted=final; Path=/\r\nContent-Length: 0\r\n\r\n").await?;
            let current = String::from_utf8(read_head(&mut tls).await?)?;
            assert!(current.starts_with("GET http://target.invalid/current HTTP/1.1\r\nHost: target.invalid\r\nX-Claim: current\r\n"));
            assert!(current.to_ascii_lowercase().contains("cookie: accepted=final\r\n"));
            assert!(!current.contains("poisoned"));
            tls.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
            TestResult::Ok(())
        };
        tokio::try_join!(request, server)?;
        Ok(())
    }).await?
}

#[tokio::test]
async fn https_forward_total_deadline_cancels_outer_tls_without_request_or_redial() -> TestResult<()>
{
    timeout(super::TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let route = Route::http_proxy(
            HttpProxy::new(&format!("https://{}", listener.local_addr()?))?
                .with_basic_auth("user", "secret")?,
        );
        let profile = ClientProfile::new(tls_settings()).with_tcp(firefox::v157_tcp());
        let client = Client::builder(profile)
            .add_proxy_root_certificate_der(identity.root_der)
            .route(route)
            .build()?;
        let (start, started) = oneshot::channel();
        let request = async {
            started.await?;
            let error = client
                .get(HttpProtocol::Http1, "http://target.invalid/deadline")?
                .timeouts(
                    RequestTimeoutOverrides::disabled()
                        .total(TimeoutOverride::Limit(Duration::from_millis(250))),
                )
                .send()
                .await
                .err()
                .ok_or("withheld TLS finished")?;
            assert_eq!(error.kind(), RequestErrorKind::Timeout);
            TestResult::Ok(())
        };
        let server = async {
            start.send(()).map_err(|()| "request ended")?;
            let (mut stream, _) = listener.accept().await?;
            let mut record = [0; 5];
            stream.read_exact(&mut record).await?;
            assert_eq!(record[0], 22);
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).await?;
            assert!(
                !rest
                    .windows(b"CONNECT ".len())
                    .any(|bytes| bytes == b"CONNECT ")
            );
            assert!(
                !rest
                    .windows(b"Proxy-Authorization".len())
                    .any(|bytes| bytes == b"Proxy-Authorization")
            );
            TestResult::Ok(())
        };
        tokio::try_join!(request, server)?;
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(
                listener.poll_accept(cx).is_pending()
            ))
            .await
        );
        Ok(())
    })
    .await?
}
