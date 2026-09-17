use std::{net::Ipv4Addr, time::Duration};

use http::{Method, Response};
use http_body_util::BodyExt;
use phantom::{HttpConnectHeader, HttpProtocol, HttpProxy, RequestErrorKind, RequestHeader, Route};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    time::timeout,
};

use crate::{
    bounded, relay_until_terminal_close,
    tls_support::{
        H1_ALPN, H2_ALPN, TestIdentity, TestResult, accept_tls, accept_tls_stream, client_builder,
        read_head,
    },
};

#[tokio::test]
async fn basic_challenge_retries_plaintext_proxy_with_ordered_credentials() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let origin_acceptor = identity.acceptor(H1_ALPN)?;
        let origin = tokio::spawn(async move {
            let mut stream = accept_tls(origin_listener, origin_acceptor).await?;
            let request = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(request)
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(challenge_then_forward(proxy_listener, origin_address));
        let route = Route::http_connect(
            HttpProxy::new(&format!("http://{proxy_address}"))?
                .connect_headers(vec![
                    HttpConnectHeader::field(RequestHeader::new("X-Before", "one")),
                    HttpConnectHeader::proxy_authorization("proxy-authorization"),
                    HttpConnectHeader::authority("host"),
                    HttpConnectHeader::field(RequestHeader::new("X-After", "two")),
                ])
                .with_basic_auth("alice", "secret")?,
        );
        let client = client_builder(&identity, false).route(route).build()?;

        let response = client
            .get(HttpProtocol::Http1, &format!("https://{origin_address}/"))?
            .send()
            .await?;
        assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");

        let (anonymous, authorized) = proxy.await??;
        assert_eq!(
            anonymous,
            format!(
                "CONNECT {origin_address} HTTP/1.1\r\n\
                 X-Before: one\r\n\
                 host: {origin_address}\r\n\
                 X-After: two\r\n\r\n"
            )
            .as_bytes()
        );
        assert_eq!(
            authorized,
            format!(
                "CONNECT {origin_address} HTTP/1.1\r\n\
                 X-Before: one\r\n\
                 proxy-authorization: Basic YWxpY2U6c2VjcmV0\r\n\
                 host: {origin_address}\r\n\
                 X-After: two\r\n\r\n"
            )
            .as_bytes()
        );
        let origin_request = origin.await??;
        assert_eq!(
            origin_request,
            format!("GET / HTTP/1.1\r\nHost: {origin_address}\r\n\r\n").as_bytes()
        );
        assert!(!contains_ascii_case_insensitive(
            &origin_request,
            b"proxy-authorization"
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn second_basic_challenge_is_bounded_and_redacted() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(reject_credentials_twice(proxy_listener));
        let route = Route::http_connect(
            HttpProxy::new(&format!("http://{proxy_address}"))?
                .with_basic_auth("marker-user", "marker-password")?,
        );
        let client = client_builder(&identity, false).route(route).build()?;

        let result = client
            .get(HttpProtocol::Http1, "https://127.0.0.1:9/")?
            .send()
            .await;
        let error = match result {
            Ok(_) => return Err("a second proxy challenge was accepted".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        let diagnostic = format!("{error:?} {error}");
        for secret in ["marker-user", "marker-password", "private realm"] {
            assert!(!diagnostic.contains(secret));
        }

        let (anonymous, authorized, third_attempted) = proxy.await??;
        assert!(!contains_ascii_case_insensitive(
            &anonymous,
            b"proxy-authorization"
        ));
        assert!(contains_ascii_case_insensitive(
            &authorized,
            b"proxy-authorization: basic"
        ));
        assert!(!third_attempted);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn basic_challenge_reconnects_https_proxy_before_http2_origin() -> TestResult<()> {
    bounded(async {
        let origin_identity = TestIdentity::generate()?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let origin_acceptor = origin_identity.acceptor(H2_ALPN)?;
        let origin = tokio::spawn(async move {
            let stream = accept_tls(origin_listener, origin_acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before request")??;
            let method = request.method().clone();
            let response = Response::builder().status(204).body(())?;
            respond.send_response(response, true)?;
            drop(respond);
            std::future::poll_fn(|context| connection.poll_closed(context)).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(method)
        });

        let proxy_identity = TestIdentity::generate()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let first_acceptor = proxy_identity.acceptor(H1_ALPN)?;
        let second_acceptor = proxy_identity.acceptor(H1_ALPN)?;
        let proxy = tokio::spawn(challenge_then_forward_tls(
            proxy_listener,
            first_acceptor,
            second_acceptor,
            origin_address,
        ));
        let route = Route::http_connect(
            HttpProxy::new(&format!("https://{proxy_address}"))?
                .with_basic_auth("alice", "secret")?,
        );
        let client = client_builder(&origin_identity, true)
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .route(route)
            .build()?;

        let response = client
            .get(HttpProtocol::Http2, &format!("https://{origin_address}/"))?
            .send()
            .await?;
        assert_eq!(response.status(), 204);
        response.into_body().collect().await?;

        let (anonymous, authorized) = proxy.await??;
        assert!(!contains_ascii_case_insensitive(
            &anonymous,
            b"proxy-authorization"
        ));
        assert!(contains_ascii_case_insensitive(
            &authorized,
            b"proxy-authorization: basic ywxpy2u6c2vjcmv0"
        ));
        assert_eq!(origin.await??, Method::GET);
        Ok(())
    })
    .await
}

async fn challenge_then_forward(
    listener: TcpListener,
    origin: std::net::SocketAddr,
) -> TestResult<(Vec<u8>, Vec<u8>)> {
    let (mut first, _) = listener.accept().await?;
    let anonymous = read_head(&mut first).await?;
    first
        .write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
              Proxy-Authenticate: Digest realm=\"ignored\", Basic realm=\"proxy, one\", charset=\"UTF-8\"\r\n\
              Content-Length: 0\r\n\r\n",
        )
        .await?;
    first.shutdown().await?;

    let (mut second, _) = listener.accept().await?;
    let authorized = read_head(&mut second).await?;
    let mut upstream = TcpStream::connect(origin).await?;
    second
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    second.flush().await?;
    relay_until_terminal_close(&mut second, &mut upstream).await?;
    Ok((anonymous, authorized))
}

async fn reject_credentials_twice(listener: TcpListener) -> TestResult<(Vec<u8>, Vec<u8>, bool)> {
    let (mut first, _) = listener.accept().await?;
    let anonymous = read_head(&mut first).await?;
    first
        .write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
              Proxy-Authenticate: Basic realm=\"private realm\"\r\n\
              Content-Length: 0\r\n\r\n",
        )
        .await?;
    first.shutdown().await?;

    let (mut second, _) = listener.accept().await?;
    let authorized = read_head(&mut second).await?;
    second
        .write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
              Proxy-Authenticate: Basic realm=\"private realm\"\r\n\
              Content-Length: 0\r\n\r\n",
        )
        .await?;
    second.shutdown().await?;
    let third_attempted = timeout(Duration::from_millis(100), listener.accept())
        .await
        .is_ok();
    Ok((anonymous, authorized, third_attempted))
}

async fn challenge_then_forward_tls(
    listener: TcpListener,
    first_acceptor: btls::ssl::SslAcceptor,
    second_acceptor: btls::ssl::SslAcceptor,
    origin: std::net::SocketAddr,
) -> TestResult<(Vec<u8>, Vec<u8>)> {
    let (first_tcp, _) = listener.accept().await?;
    let mut first = accept_tls_stream(first_tcp, first_acceptor).await?;
    let anonymous = read_head(&mut first).await?;
    first
        .write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
              Proxy-Authenticate: Basic realm=proxy\r\n\
              Content-Length: 0\r\n\r\n",
        )
        .await?;
    first.shutdown().await?;

    let (second_tcp, _) = listener.accept().await?;
    let mut second = accept_tls_stream(second_tcp, second_acceptor).await?;
    let authorized = read_head(&mut second).await?;
    let mut upstream = TcpStream::connect(origin).await?;
    second
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    second.flush().await?;
    relay_until_terminal_close(&mut second, &mut upstream).await?;
    Ok((anonymous, authorized))
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}
