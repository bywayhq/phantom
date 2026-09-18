//! Public direct plaintext HTTP/1.1 integration tests.

#[allow(dead_code)]
#[path = "support/h3.rs"]
mod h3_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{
    collections::VecDeque,
    convert::Infallible,
    future::Future,
    net::Ipv4Addr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, RequestErrorKind, RequestHeader, RequestTrailerName, ResponseInfo, Route,
    Socks5Proxy,
    profile::{ClientHint, ClientHintDelivery, ClientHintSettings, ClientProfile, chromium},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

use h3_support::client_settings;
use tls_support::{TestResult, read_head, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const NO_CONNECTION_WINDOW: Duration = Duration::from_millis(100);

#[tokio::test]
async fn direct_http1_preserves_origin_form_order_and_streaming_body() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let head = read_head(&mut stream).await?;
            let mut framed = Vec::new();
            while !framed.ends_with(b"0\r\n\r\n") {
                let mut byte = [0_u8; 1];
                stream.read_exact(&mut byte).await?;
                framed.push(byte[0]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\ndirect")
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((head, framed))
        });

        let client = http1_client()?;
        let response = client
            .request(
                HttpProtocol::Http1,
                Method::POST,
                &format!("http://{address}/a/%2e%2e/final?value=%2f"),
            )?
            .headers(vec![
                RequestHeader::new("X-First", "one"),
                RequestHeader::new("x-repeat", "alpha"),
                RequestHeader::new("X-Repeat", "beta"),
            ])
            .streaming_body(UnknownBody::new([
                b"alpha".as_slice(),
                b"beta".as_slice(),
            ]))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_protocol(&response)?, HttpProtocol::Http1);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "direct");

        let (head, framed) = server.await??;
        assert_eq!(
            head,
            format!(
                "POST /a/%2e%2e/final?value=%2f HTTP/1.1\r\nHost: {address}\r\nX-First: one\r\nx-repeat: alpha\r\nX-Repeat: beta\r\nTransfer-Encoding: chunked\r\n\r\n"
            )
            .as_bytes()
        );
        assert_eq!(framed, b"5\r\nalpha\r\n4\r\nbeta\r\n0\r\n\r\n");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn public_builder_sends_exact_ordered_dynamic_http1_request_trailers() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let head = read_head(&mut stream).await?;
            let mut framed = Vec::new();
            while !framed.ends_with(b"\r\n\r\n") {
                let mut byte = [0_u8; 1];
                stream.read_exact(&mut byte).await?;
                framed.push(byte[0]);
            }
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((head, framed))
        });

        let client = http1_client()?;
        let Err(conflict) = client
            .request(
                HttpProtocol::Http1,
                Method::POST,
                &format!("http://{address}/conflicting-trailers"),
            )?
            .streaming_body_with_trailers(trailer_body(), trailer_names())
            .trailers(vec![RequestHeader::new("X-Static", "value")])
            .send()
            .await
        else {
            return Err("static and dynamic trailers must conflict".into());
        };
        assert_eq!(conflict.kind(), RequestErrorKind::RequestBody);

        let response = client
            .request(
                HttpProtocol::Http1,
                Method::POST,
                &format!("http://{address}/trailers"),
            )?
            .header(RequestHeader::new("X-Before", "head"))
            .streaming_body_with_trailers(trailer_body(), trailer_names())
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;

        let (head, framed) = server.await??;
        assert_eq!(
            head,
            format!(
                "POST /trailers HTTP/1.1\r\nHost: {address}\r\nX-Before: head\r\nTransfer-Encoding: chunked\r\nTrailer: X-Repeat, X-Middle\r\n\r\n"
            )
            .as_bytes()
        );
        assert_eq!(
            framed,
            b"7\r\npayload\r\n0\r\nX-Repeat: alpha\r\nX-Middle: between\r\nX-Repeat: beta\r\n\r\n"
        );
        Ok(())
    })
    .await
}

fn trailer_names() -> Vec<RequestTrailerName> {
    vec![
        RequestTrailerName::new("X-Repeat"),
        RequestTrailerName::new("X-Middle"),
        RequestTrailerName::new("X-Repeat"),
    ]
}

fn trailer_body() -> TrailerBody {
    let mut trailers = HeaderMap::new();
    trailers.append("x-repeat", HeaderValue::from_static("alpha"));
    trailers.insert("x-middle", HeaderValue::from_static("between"));
    trailers.append("x-repeat", HeaderValue::from_static("beta"));
    TrailerBody {
        frames: [
            Frame::data(Bytes::from_static(b"payload")),
            Frame::trailers(trailers),
        ]
        .into(),
    }
}

struct TrailerBody {
    frames: VecDeque<Frame<Bytes>>,
}

impl Body for TrailerBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.frames.pop_front().map(Ok))
    }
}

#[tokio::test]
async fn direct_http1_reuses_same_origin_connection() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let first = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst")
                .await?;
            let second = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond")
                .await?;
            let opened_another = timeout(NO_CONNECTION_WINDOW, listener.accept())
                .await
                .is_ok();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((first, second, opened_another))
        });

        let client = http1_client()?;
        for (path, expected) in [("first", "first"), ("second", "second")] {
            let response = client
                .get(HttpProtocol::Http1, &format!("http://{address}/{path}"))?
                .send()
                .await?;
            assert_eq!(response_protocol(&response)?, HttpProtocol::Http1);
            assert_eq!(response.into_body().collect().await?.to_bytes(), expected);
        }

        let (first, second, opened_another) = server.await??;
        assert!(first.starts_with(b"GET /first HTTP/1.1\r\n"));
        assert!(second.starts_with(b"GET /second HTTP/1.1\r\n"));
        assert!(!opened_another);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn direct_plaintext_omits_client_hints() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let first = read_head(&mut stream).await?;
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nAccept-CH: Sec-CH-UA-Arch\r\nCritical-CH: Sec-CH-UA-Arch\r\nContent-Length: 0\r\n\r\n",
                )
                .await?;
            let second = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((first, second))
        });

        let hints = ClientHintSettings::new(vec![
            ClientHint::new("sec-ch-ua", "profile", ClientHintDelivery::Default),
            ClientHint::new(
                "sec-ch-ua-arch",
                "\"arm\"",
                ClientHintDelivery::AcceptCh,
            ),
        ]);
        let profile = ClientProfile::new(tls_settings()).with_client_hints(hints);
        let builder = Client::builder(profile);
        let session = builder.build()?;

        for path in ["first", "second"] {
            session
                .get(HttpProtocol::Http1, &format!("http://{address}/{path}"))?
                .send()
                .await?
                .into_body()
                .collect()
                .await?;
        }

        let (first, second) = server.await??;
        for request in [first, second] {
            let request = std::str::from_utf8(&request)?.to_ascii_lowercase();
            assert!(!request.contains("\r\nsec-ch-"));
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn non_http1_and_socks5_plaintext_fail_before_tcp_io() -> TestResult<()> {
    bounded(async {
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin.local_addr()?;
        let profile = ClientProfile::new(tls_settings())
            .with_http2(chromium::v152_macos_http2())
            .with_http3(client_settings());
        let client = Client::builder(profile).build()?;
        let target = format!("http://{origin_address}/unsupported");

        for protocol in [HttpProtocol::Http2, HttpProtocol::Http3] {
            let error = client
                .get(protocol, &target)?
                .send()
                .await
                .err()
                .ok_or("non-HTTP/1 plaintext request unexpectedly succeeded")?;
            assert_eq!(error.kind(), RequestErrorKind::UnsupportedScheme);
        }
        let negotiated_error = client
            .get_negotiated(&target)?
            .send()
            .await
            .err()
            .ok_or("negotiated plaintext request unexpectedly succeeded")?;
        assert_eq!(negotiated_error.kind(), RequestErrorKind::UnsupportedScheme);
        assert!(
            timeout(NO_CONNECTION_WINDOW, origin.accept())
                .await
                .is_err()
        );

        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy.local_addr()?;
        let route = Route::socks5(Socks5Proxy::new(&format!("socks5h://{proxy_address}"))?);
        let error = http1_client_with_route(route)?
            .get(HttpProtocol::Http1, "http://origin.test/unsupported")?
            .send()
            .await
            .err()
            .ok_or("SOCKS5 plaintext request unexpectedly succeeded")?;
        assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);
        assert!(timeout(NO_CONNECTION_WINDOW, proxy.accept()).await.is_err());
        Ok(())
    })
    .await
}

fn http1_client() -> TestResult<Client> {
    Ok(Client::builder(ClientProfile::new(tls_settings())).build()?)
}

fn http1_client_with_route(route: Route) -> TestResult<Client> {
    Ok(Client::builder(ClientProfile::new(tls_settings()))
        .route(route)
        .build()?)
}

fn response_protocol(response: &http::Response<phantom::ResponseBody>) -> TestResult<HttpProtocol> {
    response
        .extensions()
        .get::<ResponseInfo>()
        .map(ResponseInfo::protocol)
        .ok_or_else(|| "response omitted facade metadata".into())
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

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "direct HTTP test exceeded its deadline")?
}
