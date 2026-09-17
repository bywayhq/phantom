//! Public HTTP CONNECT route integration tests.

#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{
    future::Future,
    io,
    net::Ipv4Addr,
    task::{Context, Waker},
    time::Duration,
};

use bytes::Bytes;
use http::{HeaderMap, Method, Response};
use http_body_util::BodyExt;
use phantom::{HttpConnectHeader, HttpProtocol, HttpProxy, RequestErrorKind, RequestHeader, Route};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use tls_support::{
    H1_ALPN, H2_ALPN, TestIdentity, TestResult, accept_tls, client_builder, read_head, test_client,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const UNICODE_ORIGIN_NAME: &str = "bücher.example";
const ASCII_ORIGIN_NAME: &str = "xn--bcher-kva.example";

#[tokio::test]
async fn streams_http1_upload_through_ordered_connect_route() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let origin_acceptor = identity.acceptor(H1_ALPN)?;
        let origin = tokio::spawn(async move {
            let mut stream = accept_tls(origin_listener, origin_acceptor).await?;
            let request = read_head(&mut stream).await?;
            let mut body = [0_u8; 7];
            stream.read_exact(&mut body).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nthrough")
                .await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((request, body))
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(forward_one_connect(proxy_listener, origin_address));
        let route = Route::http_connect(
            HttpProxy::new(&format!("http://{proxy_address}"))?.connect_headers(vec![
                HttpConnectHeader::field(RequestHeader::new("User-Agent", "phantom-test")),
                HttpConnectHeader::authority("host"),
                HttpConnectHeader::field(RequestHeader::new("X-Proxy-Order", "last")),
            ]),
        );
        let client = client_builder(&identity, false).route(route).build()?;

        let response = client
            .request(
                HttpProtocol::Http1,
                Method::POST,
                &format!("https://{origin_address}/proxied"),
            )?
            .header(RequestHeader::new("X-Origin", "only"))
            .body(Bytes::from_static(b"payload"))
            .send()
            .await?;
        assert_eq!(response.status(), 200);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "through");

        let connect = proxy.await??;
        let expected_connect = format!(
            "CONNECT {origin_address} HTTP/1.1\r\n\
             User-Agent: phantom-test\r\n\
             host: {origin_address}\r\n\
             X-Proxy-Order: last\r\n\r\n"
        );
        assert_eq!(connect, expected_connect.as_bytes());

        let (request, body) = origin.await??;
        let expected_request = format!(
            "POST /proxied HTTP/1.1\r\nHost: {origin_address}\r\nX-Origin: only\r\nContent-Length: 7\r\n\r\n"
        );
        assert_eq!(request, expected_request.as_bytes());
        assert_eq!(&body, b"payload");
        assert!(!request.windows(12).any(|window| window == b"X-Proxy-Ord"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn unicode_origin_uses_one_canonical_connect_and_host_authority() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ASCII_ORIGIN_NAME)?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let origin_acceptor = identity.acceptor(H1_ALPN)?;
        let origin = tokio::spawn(async move {
            let mut stream = accept_tls(origin_listener, origin_acceptor).await?;
            let request = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(request)
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(forward_one_connect(proxy_listener, origin_address));
        let route = Route::http_connect(HttpProxy::new(&format!("http://{proxy_address}"))?);
        let client = client_builder(&identity, false).route(route).build()?;
        let origin_uri = format!(
            "https://{UNICODE_ORIGIN_NAME}:{}/resource",
            origin_address.port()
        );

        let response = client.get(HttpProtocol::Http1, &origin_uri)?.send().await?;
        assert_eq!(response.status(), 204);
        response.into_body().collect().await?;

        let authority = format!("{ASCII_ORIGIN_NAME}:{}", origin_address.port());
        assert_eq!(
            proxy.await??,
            format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes()
        );
        assert_eq!(
            origin.await??,
            format!("GET /resource HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes()
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn request_route_override_canonicalizes_http2_authority_and_streams_trailers()
-> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ASCII_ORIGIN_NAME)?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let origin_acceptor = identity.acceptor(H2_ALPN)?;
        let origin = tokio::spawn(async move {
            let stream = accept_tls(origin_listener, origin_acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before request")??;
            let response = Response::builder().status(200).body(())?;
            let mut send = respond.send_response(response, false)?;
            send.send_data(Bytes::from_static(b"h2-proxy"), false)?;
            let mut trailers = HeaderMap::new();
            trailers.insert("x-proxied", "yes".parse()?);
            send.send_trailers(trailers)?;
            let uri = request.uri().clone();
            drop(request);
            drop(send);
            drop(respond);
            std::future::poll_fn(|context| connection.poll_closed(context)).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(uri)
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(forward_one_connect(proxy_listener, origin_address));
        let route = Route::http_connect(HttpProxy::new(&format!("http://{proxy_address}"))?);
        let client = test_client(&identity, true)?;

        let response = client
            .get(
                HttpProtocol::Http2,
                &format!(
                    "https://{UNICODE_ORIGIN_NAME}:{}/h2-proxied",
                    origin_address.port()
                ),
            )?
            .route(route)
            .send()
            .await?;
        let collected = response.into_body().collect().await?;
        let trailer = collected
            .trailers()
            .and_then(|fields| fields.get("x-proxied"))
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        assert_eq!(collected.to_bytes(), "h2-proxy");
        assert_eq!(trailer.as_deref(), Some("yes"));

        let connect = proxy.await??;
        let authority = format!("{ASCII_ORIGIN_NAME}:{}", origin_address.port());
        assert_eq!(
            connect,
            format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes()
        );
        let uri = origin.await??;
        assert_eq!(
            uri.authority().map(|value| value.as_str()),
            Some(authority.as_str())
        );
        assert_eq!(uri.path(), "/h2-proxied");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn proxy_rejection_never_connects_direct() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = proxy_listener.accept().await?;
            let request = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, io::Error>(request)
        });
        let route = Route::http_connect(HttpProxy::new(&format!("http://{proxy_address}"))?);
        let client = client_builder(&identity, false).route(route).build()?;

        let error = match client
            .get(HttpProtocol::Http1, &format!("https://{origin_address}/"))?
            .send()
            .await
        {
            Ok(_) => return Err("rejected CONNECT request succeeded".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        assert!(matches!(
            origin.accept(),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        assert_eq!(
            proxy.await??,
            format!("CONNECT {origin_address} HTTP/1.1\r\nHost: {origin_address}\r\n\r\n")
                .as_bytes()
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn invalid_origin_and_connect_fields_fail_before_proxy_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let proxy = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    proxy.set_nonblocking(true)?;
    let proxy_address = proxy.local_addr()?;
    let origin = "https://origin.invalid/";

    let route = Route::http_connect(HttpProxy::new(&format!("http://{proxy_address}"))?);
    let client = client_builder(&identity, false)
        .route(route.clone())
        .build()?;
    let error = match client
        .get(HttpProtocol::Http1, origin)?
        .header(RequestHeader::new("Bad Header", "invalid"))
        .send()
        .await
    {
        Ok(_) => return Err("invalid HTTP/1 origin field touched the proxy".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::Http1);
    assert!(matches!(
        proxy.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));

    let client = client_builder(&identity, true).route(route).build()?;
    let error = match client
        .get(HttpProtocol::Http2, origin)?
        .header(RequestHeader::new("X-Uppercase", "invalid"))
        .send()
        .await
    {
        Ok(_) => return Err("invalid HTTP/2 origin field touched the proxy".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::Http2);
    assert!(matches!(
        proxy.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));

    let route = Route::http_connect(
        HttpProxy::new(&format!("http://{proxy_address}"))?.connect_headers(Vec::new()),
    );
    let client = client_builder(&identity, false).route(route).build()?;
    let error = match client.get(HttpProtocol::Http1, origin)?.send().await {
        Ok(_) => return Err("invalid CONNECT fields touched the proxy".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::Proxy);
    assert!(matches!(
        proxy.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    Ok(())
}

#[test]
fn polling_proxy_request_without_tokio_returns_runtime_error() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let route = Route::http_connect(HttpProxy::new("http://127.0.0.1:9")?);
    let client = client_builder(&identity, false).route(route).build()?;
    let request = client.get(HttpProtocol::Http1, "https://127.0.0.1:9/")?;
    let mut future = std::pin::pin!(request.send());
    let mut context = Context::from_waker(Waker::noop());

    let result = match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => {
            return Err("proxy request waited without a Tokio runtime".into());
        }
    };
    let error = match result {
        Ok(_) => return Err("proxy request completed outside a Tokio runtime".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::RuntimeUnavailable);
    Ok(())
}

async fn forward_one_connect(
    listener: TcpListener,
    origin: std::net::SocketAddr,
) -> TestResult<Vec<u8>> {
    let (mut downstream, _) = listener.accept().await?;
    let request = read_head(&mut downstream).await?;
    let mut upstream = TcpStream::connect(origin).await?;
    downstream
        .write_all(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    downstream.flush().await?;
    copy_bidirectional(&mut downstream, &mut upstream).await?;
    Ok(request)
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "proxy integration test exceeded its deadline")?
}
