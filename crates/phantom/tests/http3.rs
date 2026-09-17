//! Public HTTP/3 facade integration tests.

#[path = "support/h3.rs"]
mod h3_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{
    collections::VecDeque,
    convert::Infallible,
    future::Future,
    io,
    net::{Ipv4Addr, TcpListener as StdTcpListener, UdpSocket},
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::{Buf, Bytes};
use http::{HeaderMap, HeaderValue, Method, Response, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, HttpProxy, OrderedResponseHeaders, RequestErrorKind, RequestHeader,
    Route, Socks5Proxy, profile::ClientProfile,
};
use tokio::{sync::oneshot, time::timeout};

use h3_support::{accept_request, client_settings, server_endpoint};
use tls_support::{TestIdentity, TestResult, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn public_client_canonicalizes_host_and_streams_http3_data_and_trailers() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (release, released) = oneshot::channel();
        let (client_done, done_received) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (request, mut stream, _connection) = accept_request(&endpoint).await?;
            let authority = request
                .uri()
                .authority()
                .ok_or("HTTP/3 request omitted its authority")?
                .to_string();
            let target = request
                .uri()
                .path_and_query()
                .ok_or("HTTP/3 request omitted its target")?
                .to_string();
            let repeated = request
                .headers()
                .get_all("x-repeat")
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect::<Vec<_>>();

            let mut response = Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header("set-cookie", "first=1")
                .header("x-middle", "middle")
                .header("set-cookie", "second=2")
                .body(())?;
            response
                .extensions_mut()
                .insert(h3::ext::OrderedHeaders::new(vec![
                    ("set-cookie".parse()?, "first=1".parse()?),
                    ("x-middle".parse()?, "middle".parse()?),
                    ("set-cookie".parse()?, "second=2".parse()?),
                ]));
            stream.send_response(response).await?;
            stream.send_data(Bytes::from_static(b"first")).await?;
            released.await.map_err(io::Error::other)?;
            stream.send_data(Bytes::from_static(b"later")).await?;
            let mut trailers = HeaderMap::new();
            trailers.insert("x-finished", HeaderValue::from_static("yes"));
            stream.send_trailers(trailers).await?;
            stream.finish().await?;
            done_received.await.map_err(io::Error::other)?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((authority, target, repeated))
        });

        let client = test_client(&identity)?;
        let response = client
            .get(
                HttpProtocol::Http3,
                &format!(
                    "https://１２７．０．０．１:{}/resource?item=1",
                    address.port()
                ),
            )?
            .headers(vec![
                RequestHeader::new("x-first", "one"),
                RequestHeader::new("x-repeat", "alpha"),
                RequestHeader::new("x-repeat", "beta"),
            ])
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        let ordered = response
            .extensions()
            .get::<OrderedResponseHeaders>()
            .ok_or("HTTP/3 response omitted ordered fields")?;
        assert_eq!(
            ordered
                .iter()
                .map(|field| (field.name(), field.value()))
                .collect::<Vec<_>>(),
            [
                ("set-cookie", b"first=1".as_slice()),
                ("x-middle", b"middle".as_slice()),
                ("set-cookie", b"second=2".as_slice()),
            ]
        );

        let mut body = response.into_body();
        assert_eq!(next_data(&mut body).await?, "first");
        release
            .send(())
            .map_err(|_| "HTTP/3 server stopped before later body release")?;
        assert_eq!(next_data(&mut body).await?, "later");
        let trailers = next_trailers(&mut body).await?;
        assert_eq!(
            trailers
                .get("x-finished")
                .and_then(|value| value.to_str().ok()),
            Some("yes")
        );
        assert!(body.frame().await.is_none());

        client_done
            .send(())
            .map_err(|_| "HTTP/3 server stopped before client completion")?;
        let (authority, target, repeated) = server.await??;
        assert_eq!(authority, address.to_string());
        assert_eq!(target, "/resource?item=1");
        assert_eq!(repeated, [b"alpha".to_vec(), b"beta".to_vec()]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn public_client_sends_owned_http3_request_body() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (client_done, done_received) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (request, mut stream, _connection) = accept_request(&endpoint).await?;
            let method = request.method().clone();
            let length = request.headers().get("content-length").cloned();
            let mut body = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await? {
                let remaining = chunk.remaining();
                body.extend_from_slice(&chunk.copy_to_bytes(remaining));
            }
            stream
                .send_response(
                    Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .body(())?,
                )
                .await?;
            stream.finish().await?;
            done_received.await.map_err(io::Error::other)?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((method, length, body))
        });

        let client = test_client(&identity)?;
        let response = client
            .request(
                HttpProtocol::Http3,
                Method::POST,
                &format!("https://{address}/upload"),
            )?
            .body(Bytes::from_static(b"payload"))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;

        client_done
            .send(())
            .map_err(|_| "HTTP/3 server stopped before client completion")?;
        let (method, length, body) = server.await??;
        assert_eq!(method, Method::POST);
        assert_eq!(
            length.as_ref().and_then(|value| value.to_str().ok()),
            Some("7")
        );
        assert_eq!(body, b"payload");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn public_client_streams_unknown_length_http3_request_body() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (client_done, done_received) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (request, mut stream, _connection) = accept_request(&endpoint).await?;
            let length = request.headers().get("content-length").cloned();
            let mut body = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await? {
                let remaining = chunk.remaining();
                body.extend_from_slice(&chunk.copy_to_bytes(remaining));
            }
            stream
                .send_response(
                    Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .body(())?,
                )
                .await?;
            stream.finish().await?;
            done_received.await.map_err(io::Error::other)?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((length, body))
        });

        let client = test_client(&identity)?;
        let response = client
            .request(
                HttpProtocol::Http3,
                Method::POST,
                &format!("https://{address}/stream-upload"),
            )?
            .streaming_body(UnknownBody::new([b"alpha".as_slice(), b"beta".as_slice()]))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;

        client_done
            .send(())
            .map_err(|_| "HTTP/3 server stopped before client completion")?;
        let (length, body) = server.await??;
        assert!(length.is_none());
        assert_eq!(body, b"alphabeta");
        Ok(())
    })
    .await
}

#[test]
fn unavailable_http3_fails_before_network_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = tls_support::test_client(&identity, false)?;
    let origin = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    origin.set_nonblocking(true)?;
    let address = origin.local_addr()?;

    let error = match client.get(HttpProtocol::Http3, &format!("https://{address}/")) {
        Ok(_) => return Err("HTTP/3 unexpectedly available".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::ProtocolUnavailable);
    assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
    assert_udp_untouched(&origin)?;
    Ok(())
}

#[tokio::test]
async fn invalid_http3_field_fails_before_udp_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity)?;
    let origin = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    origin.set_nonblocking(true)?;
    let address = origin.local_addr()?;

    let result = client
        .get(HttpProtocol::Http3, &format!("https://{address}/"))?
        .header(RequestHeader::new("X-Uppercase", "rejected"))
        .send()
        .await;
    let error = match result {
        Ok(_) => return Err("invalid HTTP/3 field unexpectedly sent".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::Http3);
    assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
    assert_udp_untouched(&origin)?;
    Ok(())
}

#[tokio::test]
async fn certificate_failure_has_public_tls_category() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let server = tokio::spawn(async move {
            if let Some(incoming) = endpoint.accept().await {
                let _ = incoming.await;
            }
        });
        let mut tcp_tls = tls_settings();
        tcp_tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
        let profile = ClientProfile::new(tcp_tls).with_http3(client_settings());
        let client = Client::builder(profile).build()?;

        let error = client
            .get(HttpProtocol::Http3, &format!("https://{address}/"))?
            .send()
            .await
            .err()
            .ok_or("untrusted HTTP/3 certificate was accepted")?;

        server.abort();
        assert_eq!(error.kind(), RequestErrorKind::Tls);
        assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn tcp_proxy_routes_fail_before_proxy_or_origin_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let proxy = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    proxy.set_nonblocking(true)?;
    let proxy_address = proxy.local_addr()?;
    let origin = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    origin.set_nonblocking(true)?;
    let origin_address = origin.local_addr()?;
    let routes = [
        Route::http_connect(HttpProxy::new(&format!("http://{proxy_address}"))?),
        Route::http_connect(HttpProxy::new(&format!("https://{proxy_address}"))?),
        Route::socks5(Socks5Proxy::new(&format!("socks5h://{proxy_address}"))?),
    ];

    for route in routes {
        let default_route_client = client_builder(&identity).route(route.clone()).build()?;
        let error = match default_route_client
            .get(
                HttpProtocol::Http3,
                &format!("https://{origin_address}/default"),
            )?
            .send()
            .await
        {
            Ok(_) => return Err("HTTP/3 used a default TCP proxy route".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);
        assert_eq!(error.protocol(), Some(HttpProtocol::Http3));

        let override_client = test_client(&identity)?;
        let error = match override_client
            .get(
                HttpProtocol::Http3,
                &format!("https://{origin_address}/override"),
            )?
            .route(route)
            .send()
            .await
        {
            Ok(_) => return Err("HTTP/3 used a request TCP proxy override".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);
        assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
    }

    assert!(matches!(
        proxy.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    assert_udp_untouched(&origin)?;
    Ok(())
}

#[test]
fn polling_http3_request_without_tokio_returns_runtime_error() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity)?;
    let request = client.get(HttpProtocol::Http3, "https://127.0.0.1:9/")?;
    let mut future = std::pin::pin!(request.send());
    let mut context = Context::from_waker(Waker::noop());

    let result = match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => return Err("HTTP/3 request waited without Tokio".into()),
    };
    let error = match result {
        Ok(_) => return Err("HTTP/3 request completed outside Tokio".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::RuntimeUnavailable);
    assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
    Ok(())
}

fn client_builder(identity: &TestIdentity) -> phantom::ClientBuilder {
    let mut tcp_tls = tls_settings();
    tcp_tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    let profile = ClientProfile::new(tcp_tls).with_http3(client_settings());
    Client::builder(profile).add_root_certificate_der(identity.root_der.clone())
}

fn test_client(identity: &TestIdentity) -> TestResult<Client> {
    Ok(client_builder(identity).build()?)
}

struct UnknownBody {
    chunks: VecDeque<Bytes>,
}

impl UnknownBody {
    fn new<const N: usize>(chunks: [&'static [u8]; N]) -> Self {
        Self {
            chunks: chunks.into_iter().map(Bytes::from_static).collect(),
        }
    }
}

impl Body for UnknownBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.chunks.pop_front().map(Frame::data).map(Ok))
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

async fn next_data(body: &mut phantom::ResponseBody) -> TestResult<Bytes> {
    loop {
        let frame = body.frame().await.ok_or("response body ended")??;
        if let Ok(data) = frame.into_data() {
            if !data.is_empty() {
                return Ok(data);
            }
        }
    }
}

async fn next_trailers(body: &mut phantom::ResponseBody) -> TestResult<HeaderMap> {
    loop {
        let frame = body.frame().await.ok_or("response body ended")??;
        if let Ok(trailers) = frame.into_trailers() {
            return Ok(trailers);
        }
    }
}

fn assert_udp_untouched(socket: &UdpSocket) -> TestResult<()> {
    let mut byte = [0_u8; 1];
    assert!(matches!(
        socket.recv_from(&mut byte),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    Ok(())
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "HTTP/3 integration test exceeded its deadline")?
}
