//! Direct HTTP/1.1-or-HTTP/2 ALPN negotiation tests.

#[allow(dead_code)]
#[path = "support/h2.rs"]
mod h2_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;
#[path = "support/tracing.rs"]
mod tracing_support;

use std::{
    collections::VecDeque,
    convert::Infallible,
    error::Error,
    future::{Future, poll_fn},
    io,
    net::{Ipv4Addr, TcpListener as StdTcpListener},
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::Bytes;
use http::{HeaderMap, Method, Response, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, Full};
use phantom::profile::{ClientProfile, chromium};
use phantom::{
    HttpProtocol, HttpProxy, RequestErrorKind, RequestHeader, RequestTrailerName, ResponseInfo,
    Route,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::timeout,
};
use tracing::instrument::WithSubscriber;

use h2_support::{accept_client_preface, read_request_headers, write_frame};
use tls_support::{
    H1_ALPN, H2_ALPN, TestIdentity, accept_tls_stream, client_builder, read_head, test_client,
};
use tracing_support::OutcomeSubscriber;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const SECOND_CONNECTION_WINDOW: Duration = Duration::from_millis(100);
type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[cfg(feature = "cookies")]
#[tokio::test]
async fn negotiated_http1_learns_and_sends_client_cookies() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let first_acceptor = identity.acceptor(H1_ALPN)?;
        let second_acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let (first, _) = listener.accept().await?;
            let mut first = accept_tls_stream(first, first_acceptor).await?;
            let first_head = read_head(&mut first).await?;
            first
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nSet-Cookie: learned=1; Secure; Path=/\r\nContent-Length: 0\r\n\r\n",
                )
                .await?;
            drop(first);

            let (second, _) = listener.accept().await?;
            let mut second = accept_tls_stream(second, second_acceptor).await?;
            let second_head = read_head(&mut second).await?;
            second
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((first_head, second_head))
        });

        let client = client_builder(&identity, true).cookies().build()?;
        for path in ["first", "second"] {
            client
                .get_negotiated(&format!("https://{address}/{path}"))?
                .send()
                .await?
                .into_body()
                .collect()
                .await?;
        }

        let (first, second) = server.await??;
        assert!(!first.windows(b"\r\nCookie:".len()).any(|part| part == b"\r\nCookie:"));
        assert!(
            second
                .windows(b"\r\nCookie: learned=1\r\n".len())
                .any(|part| part == b"\r\nCookie: learned=1\r\n")
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn negotiated_request_selects_http2_once() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let stream = accept_tls_stream(tcp, acceptor).await?;
            if stream.ssl().selected_alpn_protocol() != Some(b"h2") {
                return Err("server did not select h2".into());
            }
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before the negotiated request")??;
            respond.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
                true,
            )?;
            let uri = request.uri().clone();
            drop(request);
            drop(respond);
            poll_fn(|context| connection.poll_closed(context)).await?;
            let second = timeout(SECOND_CONNECTION_WINDOW, listener.accept()).await;
            Ok::<_, Box<dyn Error + Send + Sync>>((uri, second.is_err()))
        });

        let client = test_client(&identity, true)?;
        let response = client
            .get_negotiated(&format!("https://{address}/selected-h2"))?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response_protocol(&response)?, HttpProtocol::Http2);
        response.into_body().collect().await?;

        drop(client);
        let (uri, had_no_second_connection) = server.await??;
        assert_eq!(uri.path(), "/selected-h2");
        assert!(had_no_second_connection);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn negotiated_http1_sends_exact_dynamic_request_trailers() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, acceptor).await?;
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
            Ok::<_, Box<dyn Error + Send + Sync>>((head, framed))
        });

        let response = test_client(&identity, true)?
            .request_negotiated(Method::POST, &format!("https://{address}/trailers-h1"))?
            .streaming_body_with_trailers(dynamic_trailer_body(), dynamic_trailer_names())
            .send()
            .await?;
        assert_eq!(response_protocol(&response)?, HttpProtocol::Http1);
        response.into_body().collect().await?;

        let (head, framed) = server.await??;
        assert_eq!(
            head,
            format!(
                "POST /trailers-h1 HTTP/1.1\r\nHost: {address}\r\nTransfer-Encoding: chunked\r\nTrailer: x-repeat, x-middle\r\n\r\n"
            )
            .as_bytes()
        );
        assert_eq!(
            framed,
            b"7\r\npayload\r\n0\r\nx-repeat: alpha\r\nx-middle: between\r\nx-repeat: beta\r\n\r\n"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn negotiated_http2_sends_dynamic_request_trailers() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let stream = accept_tls_stream(tcp, acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before negotiated request")??;
            let mut incoming = request.into_body();
            let mut body = Vec::new();
            while let Some(chunk) = next_h2_request_data(&mut connection, &mut incoming).await? {
                body.extend_from_slice(&chunk);
                incoming.flow_control().release_capacity(chunk.len())?;
            }
            let trailers = next_h2_request_trailers(&mut connection, &mut incoming)
                .await?
                .ok_or("negotiated request omitted trailers")?;
            respond.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
                true,
            )?;
            poll_fn(|context| connection.poll_closed(context)).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((body, trailers))
        });

        let response = test_client(&identity, true)?
            .request_negotiated(Method::POST, &format!("https://{address}/trailers-h2"))?
            .streaming_body_with_trailers(dynamic_trailer_body(), dynamic_trailer_names())
            .send()
            .await?;
        assert_eq!(response_protocol(&response)?, HttpProtocol::Http2);
        response.into_body().collect().await?;

        let (body, trailers) = server.await??;
        assert_eq!(body, b"payload");
        assert_eq!(
            trailers
                .get_all("x-repeat")
                .iter()
                .map(http::HeaderValue::as_bytes)
                .collect::<Vec<_>>(),
            [b"alpha".as_slice(), b"beta".as_slice()]
        );
        assert_eq!(
            trailers
                .get("x-middle")
                .and_then(|value| value.to_str().ok()),
            Some("between")
        );
        Ok(())
    })
    .await
}

fn dynamic_trailer_names() -> Vec<RequestTrailerName> {
    vec![
        RequestTrailerName::new("x-repeat"),
        RequestTrailerName::new("x-middle"),
        RequestTrailerName::new("x-repeat"),
    ]
}

fn dynamic_trailer_body() -> DynamicTrailerBody {
    let mut trailers = HeaderMap::new();
    trailers.append("x-repeat", http::HeaderValue::from_static("alpha"));
    let mut middle = http::HeaderValue::from_static("between");
    middle.set_sensitive(true);
    trailers.insert("x-middle", middle);
    trailers.append("x-repeat", http::HeaderValue::from_static("beta"));
    DynamicTrailerBody {
        frames: [
            Frame::data(Bytes::from_static(b"payload")),
            Frame::trailers(trailers),
        ]
        .into(),
    }
}

struct DynamicTrailerBody {
    frames: VecDeque<Frame<Bytes>>,
}

impl Body for DynamicTrailerBody {
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
async fn concurrent_negotiated_http2_requests_share_one_tls_connection() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let stream = accept_tls_stream(tcp, acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let mut requests = Vec::with_capacity(2);
            let mut responders = Vec::with_capacity(2);
            for _ in 0..2 {
                let (request, respond) = connection
                    .accept()
                    .await
                    .ok_or("connection closed before both negotiated requests")??;
                requests.push((respond.stream_id().as_u32(), request.uri().path().to_owned()));
                responders.push(respond);
            }
            for mut respond in responders {
                respond.send_response(
                    Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .body(())?,
                    true,
                )?;
            }
            let had_no_second_connection = tokio::select! {
                closed = poll_fn(|context| connection.poll_closed(context)) => {
                    closed?;
                    return Err("negotiated HTTP/2 connection closed during reuse observation".into());
                }
                second = timeout(SECOND_CONNECTION_WINDOW, listener.accept()) => second.is_err(),
            };
            Ok::<_, Box<dyn Error + Send + Sync>>((requests, had_no_second_connection))
        });

        let client = test_client(&identity, true)?;
        let first_client = client.clone();
        let first = tokio::spawn(async move {
            let response = first_client
                .get_negotiated(&format!("https://{address}/first"))?
                .send()
                .await?;
            let protocol = response_protocol(&response)?;
            response.into_body().collect().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(protocol)
        });
        let second_client = client.clone();
        let second = tokio::spawn(async move {
            let response = second_client
                .get_negotiated(&format!("https://{address}/second"))?
                .send()
                .await?;
            let protocol = response_protocol(&response)?;
            response.into_body().collect().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(protocol)
        });

        assert_eq!(first.await??, HttpProtocol::Http2);
        assert_eq!(second.await??, HttpProtocol::Http2);
        let (requests, had_no_second_connection) = server.await??;
        let mut stream_ids = requests
            .iter()
            .map(|(stream_id, _)| *stream_id)
            .collect::<Vec<_>>();
        stream_ids.sort_unstable();
        let mut paths = requests
            .into_iter()
            .map(|(_, path)| path)
            .collect::<Vec<_>>();
        paths.sort_unstable();
        assert_eq!(stream_ids, [1, 3]);
        assert_eq!(paths, ["/first", "/second"]);
        assert!(had_no_second_connection);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn negotiated_http2_streams_unknown_length_request_body() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let stream = accept_tls_stream(tcp, acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before the negotiated request")??;
            let length = request.headers().get("content-length").cloned();
            let mut incoming = request.into_body();
            let mut body = Vec::new();
            while let Some(chunk) = next_h2_request_data(&mut connection, &mut incoming).await? {
                body.extend_from_slice(&chunk);
                incoming.flow_control().release_capacity(chunk.len())?;
            }
            respond.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
                true,
            )?;
            poll_fn(|context| connection.poll_closed(context)).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((length, body))
        });

        let client = test_client(&identity, true)?;
        let response = client
            .request_negotiated(Method::POST, &format!("https://{address}/stream-upload"))?
            .streaming_body(UnknownBody(Some(Bytes::from_static(b"payload"))))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response_protocol(&response)?, HttpProtocol::Http2);
        response.into_body().collect().await?;

        drop(client);
        let (length, body) = server.await??;
        assert!(length.is_none());
        assert_eq!(body, b"payload");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn negotiated_request_selects_http1_once() -> TestResult<()> {
    negotiated_http1_case(true).await
}

#[tokio::test]
async fn sequential_negotiated_http1_requests_reuse_one_tls_connection() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, acceptor).await?;
            let first = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst")
                .await?;
            let second = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            let replacement = timeout(SECOND_CONNECTION_WINDOW, listener.accept()).await;
            Ok::<_, Box<dyn Error + Send + Sync>>((first, second, replacement.is_err()))
        });

        let client = test_client(&identity, true)?;
        let first = client
            .get_negotiated(&format!("https://{address}/first"))?
            .send()
            .await?;
        assert_eq!(response_protocol(&first)?, HttpProtocol::Http1);
        assert_eq!(first.into_body().collect().await?.to_bytes(), "first");

        let second = client
            .get_negotiated(&format!("https://{address}/second"))?
            .send()
            .await?;
        assert_eq!(response_protocol(&second)?, HttpProtocol::Http1);
        assert!(second.into_body().collect().await?.to_bytes().is_empty());

        let (first, second, had_no_replacement) = server.await??;
        assert!(first.starts_with(b"GET /first HTTP/1.1\r\n"));
        assert!(second.starts_with(b"GET /second HTTP/1.1\r\n"));
        assert!(had_no_replacement);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn negotiated_http1_replaces_nonreusable_connection_without_replay() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let first_acceptor = identity.acceptor(H1_ALPN)?;
        let second_acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let (first_tcp, _) = listener.accept().await?;
            let mut first = accept_tls_stream(first_tcp, first_acceptor).await?;
            let first_head = read_head(&mut first).await?;
            first
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                .await?;
            drop(first);

            let (second_tcp, _) = listener.accept().await?;
            let mut second = accept_tls_stream(second_tcp, second_acceptor).await?;
            let second_head = read_head(&mut second).await?;
            second
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            let third = timeout(SECOND_CONNECTION_WINDOW, listener.accept()).await;
            Ok::<_, Box<dyn Error + Send + Sync>>((first_head, second_head, third.is_err()))
        });

        let client = test_client(&identity, true)?;
        for path in ["first", "second"] {
            let response = client
                .get_negotiated(&format!("https://{address}/{path}"))?
                .send()
                .await?;
            assert_eq!(response_protocol(&response)?, HttpProtocol::Http1);
            response.into_body().collect().await?;
        }

        let (first, second, had_no_third_connection) = server.await??;
        assert!(first.starts_with(b"GET /first HTTP/1.1\r\n"));
        assert!(second.starts_with(b"GET /second HTTP/1.1\r\n"));
        assert!(had_no_third_connection);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn negotiated_http1_sends_streaming_request_body() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, acceptor).await?;
            let head = read_head(&mut stream).await?;
            let mut body = [0_u8; 7];
            stream.read_exact(&mut body).await?;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((head, body))
        });

        let client = test_client(&identity, true)?;
        let response = client
            .request_negotiated(Method::POST, &format!("https://{address}/stream-upload"))?
            .streaming_body(Full::new(Bytes::from_static(b"payload")))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response_protocol(&response)?, HttpProtocol::Http1);
        response.into_body().collect().await?;

        let (head, body) = server.await??;
        assert!(head.starts_with(b"POST /stream-upload HTTP/1.1\r\n"));
        assert!(head.ends_with(b"Content-Length: 7\r\n\r\n"));
        assert_eq!(&body, b"payload");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn negotiated_request_uses_http1_when_alpn_is_absent() -> TestResult<()> {
    negotiated_http1_case(false).await
}

#[tokio::test]
async fn request_invalid_for_http2_fails_before_network_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity, true)?;
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;

    let result = client
        .get_negotiated(&format!("https://{address}/"))?
        .header(RequestHeader::new("X-Uppercase", "not-valid-in-h2"))
        .send()
        .await;
    let error = match result {
        Ok(_) => return Err("request invalid for HTTP/2 was sent".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::Http2);
    assert_eq!(error.protocol(), None);
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    Ok(())
}

#[tokio::test]
async fn request_invalid_for_http1_fails_before_network_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity, true)?;
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;

    let result = client
        .get_negotiated(&format!("https://{address}/"))?
        .header(RequestHeader::new("Transfer-Encoding", "chunked"))
        .send()
        .await;
    let error = match result {
        Ok(_) => return Err("request invalid for HTTP/1.1 was sent".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::Http1);
    assert_eq!(error.protocol(), None);
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    Ok(())
}

#[tokio::test]
async fn selected_protocol_is_recorded_on_post_alpn_failure() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let stream = accept_tls_stream(tcp, acceptor).await?;
            if stream.ssl().selected_alpn_protocol() != Some(b"http/1.1") {
                return Err("server did not select HTTP/1.1".into());
            }
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let client = test_client(&identity, true)?;
        let subscriber = OutcomeSubscriber::default();
        let result = client
            .get_negotiated(&format!("https://{address}/"))?
            .send()
            .with_subscriber(subscriber.dispatch())
            .await;
        let error = match result {
            Ok(_) => return Err("request succeeded after the peer closed".into()),
            Err(error) => error,
        };
        assert_eq!(error.protocol(), Some(HttpProtocol::Http1));
        assert_eq!(
            subscriber.selected_protocols_for("client.request"),
            ["http/1.1"]
        );
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn selected_protocol_is_recorded_when_request_is_cancelled() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let (request_seen, seen) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, acceptor).await?;
            let _request = read_head(&mut stream).await?;
            let _ = request_seen.send(());
            std::future::pending::<()>().await;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let client = test_client(&identity, true)?;
        let subscriber = OutcomeSubscriber::default();
        let request = client.get_negotiated(&format!("https://{address}/"))?;
        let task = tokio::spawn(request.send().with_subscriber(subscriber.dispatch()));
        seen.await?;
        task.abort();
        assert!(task.await.is_err());
        assert_eq!(
            subscriber.selected_protocols_for("client.request"),
            ["http/1.1"]
        );
        server.abort();
        assert!(server.await.is_err());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn negotiated_request_rejects_proxy_route_before_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let proxy_address = listener.local_addr()?;
    let proxy = HttpProxy::new(&format!("http://{proxy_address}"))?;
    let client = client_builder(&identity, true)
        .route(Route::http_connect(proxy))
        .build()?;

    let result = client.get_negotiated("https://example.test/")?.send().await;
    let error = match result {
        Ok(_) => return Err("negotiated request accepted an HTTP proxy".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);
    assert_eq!(error.protocol(), None);
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    Ok(())
}

#[tokio::test]
async fn unsupported_offered_alpn_sends_no_http_bytes() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(b"\x02h3")?;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, acceptor).await?;
            if stream.ssl().selected_alpn_protocol() != Some(b"h3") {
                return Err("server did not select the unsupported h3 ALPN".into());
            }
            // The client closes after rejecting the ALPN; the outer test
            // deadline bounds a client that never closes.
            let mut received = Vec::new();
            match stream.read_to_end(&mut received).await {
                Ok(_) => {}
                Err(error) if tls_support::is_peer_gone(&error) => {}
                Err(error) => return Err(error.into()),
            }
            Ok::<_, Box<dyn Error + Send + Sync>>(received.len())
        });

        let mut tls = tls_support::tls_settings();
        tls.alpn_protocols = vec![
            Box::from(&b"h3"[..]),
            Box::from(&b"h2"[..]),
            Box::from(&b"http/1.1"[..]),
        ];
        let client =
            phantom::Client::builder(ClientProfile::new(tls).with_http2(chromium::v154_http2()))
                .add_root_certificate_der(identity.root_der.clone())
                .build()?;
        let result = client
            .get_negotiated(&format!("https://{address}/"))?
            .send()
            .await;
        let error = match result {
            Ok(_) => return Err("negotiated request accepted h3 on its TCP path".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::Tls);
        assert_eq!(error.protocol(), None);
        assert_eq!(server.await??, 0);
        Ok(())
    })
    .await
}

#[test]
fn negotiated_request_requires_both_profile_capabilities() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity, false)?;

    let error = match client.get_negotiated("https://example.test/") {
        Ok(_) => return Err("HTTP/1-only profile exposed negotiation".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::ProtocolUnavailable);
    assert_eq!(error.protocol(), None);
    Ok(())
}

#[test]
fn polling_negotiated_request_without_tokio_returns_typed_error() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity, true)?;
    let request = client.get_negotiated("https://127.0.0.1:9/")?;
    let mut future = std::pin::pin!(request.send());
    let mut context = Context::from_waker(Waker::noop());

    let Poll::Ready(result) = future.as_mut().poll(&mut context) else {
        return Err("negotiated request waited without a Tokio runtime".into());
    };
    let error = match result {
        Ok(_) => return Err("negotiated request completed outside a Tokio runtime".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::RuntimeUnavailable);
    assert_eq!(error.protocol(), None);
    Ok(())
}

async fn negotiated_http1_case(select_alpn: bool) -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = if select_alpn {
            identity.acceptor(H1_ALPN)?
        } else {
            identity.acceptor_without_alpn()?
        };
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, acceptor).await?;
            let selected = stream.ssl().selected_alpn_protocol().map(Box::from);
            let request = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            stream.flush().await?;
            let second = timeout(SECOND_CONNECTION_WINDOW, listener.accept()).await;
            Ok::<_, Box<dyn Error + Send + Sync>>((selected, request, second.is_err()))
        });

        let client = test_client(&identity, true)?;
        let response = client
            .get_negotiated(&format!("https://{address}/selected-h1"))?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response_protocol(&response)?, HttpProtocol::Http1);
        response.into_body().collect().await?;

        let (selected, request, had_no_second_connection) = server.await??;
        let expected_alpn = select_alpn.then_some(b"http/1.1".as_slice());
        assert_eq!(selected.as_deref(), expected_alpn);
        assert_eq!(
            request,
            format!("GET /selected-h1 HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes()
        );
        assert!(had_no_second_connection);
        Ok(())
    })
    .await
}

fn response_protocol(response: &http::Response<phantom::ResponseBody>) -> TestResult<HttpProtocol> {
    response
        .extensions()
        .get::<ResponseInfo>()
        .map(ResponseInfo::protocol)
        .ok_or_else(|| "response omitted facade metadata".into())
}

struct UnknownBody(Option<Bytes>);

impl Body for UnknownBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.0.take().map(Frame::data).map(Ok))
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

async fn next_h2_request_data<T>(
    connection: &mut ::http2::server::Connection<T, Bytes>,
    body: &mut ::http2::RecvStream,
) -> TestResult<Option<Bytes>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    poll_fn(|context| {
        if let Poll::Ready(item) = body.poll_data(context) {
            return Poll::Ready(item.transpose());
        }
        match connection.poll_closed(context) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(None)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
    .map_err(Into::into)
}

async fn next_h2_request_trailers<T>(
    connection: &mut ::http2::server::Connection<T, Bytes>,
    body: &mut ::http2::RecvStream,
) -> TestResult<Option<HeaderMap>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    poll_fn(|context| {
        if let Poll::Ready(item) = body.poll_trailers(context) {
            return Poll::Ready(item);
        }
        match connection.poll_closed(context) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(None)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
    .map_err(Into::into)
}

#[tokio::test]
async fn negotiated_graceful_goaway_retries_a_bodyless_get_once_on_a_replacement() -> TestResult<()>
{
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let replacement_acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut first = accept_tls_stream(tcp, acceptor).await?;
            accept_client_preface(&mut first).await?;
            read_request_headers(&mut first, 1).await?;
            // GOAWAY(NO_ERROR) with last-stream-id 0: stream 1 was not processed.
            write_frame(&mut first, 0x7, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 0]).await?;
            first.flush().await?;
            first.shutdown().await?;

            let (tcp, _) = listener.accept().await?;
            let replacement = accept_tls_stream(tcp, replacement_acceptor).await?;
            let mut connection = ::http2::server::handshake(replacement).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("replacement closed before the retried request")??;
            respond.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
                true,
            )?;
            let path = request.uri().path().to_owned();
            drop(request);
            drop(respond);
            poll_fn(|context| connection.poll_closed(context)).await?;
            let third = timeout(SECOND_CONNECTION_WINDOW, listener.accept()).await;
            Ok::<_, Box<dyn Error + Send + Sync>>((path, third.is_err()))
        });

        let client = test_client(&identity, true)?;
        let response = client
            .get_negotiated(&format!("https://{address}/failed"))?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response_protocol(&response)?, HttpProtocol::Http2);
        let info = response
            .extensions()
            .get::<ResponseInfo>()
            .ok_or("response omitted metadata")?;
        assert_eq!(info.retries_performed(), 0);
        response.into_body().collect().await?;
        drop(client);

        let (path, had_no_third_connection) = server.await??;
        assert_eq!(path, "/failed");
        assert!(had_no_third_connection);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn negotiated_graceful_goaway_retry_is_bounded_to_one_replacement() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptors = [identity.acceptor(H2_ALPN)?, identity.acceptor(H2_ALPN)?];
        let (client_done_tx, client_done_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            for acceptor in acceptors {
                let (tcp, _) = listener.accept().await?;
                let mut stream = accept_tls_stream(tcp, acceptor).await?;
                accept_client_preface(&mut stream).await?;
                read_request_headers(&mut stream, 1).await?;
                write_frame(&mut stream, 0x7, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 0]).await?;
                stream.flush().await?;
                stream.shutdown().await?;
            }

            tokio::select! {
                biased;
                accepted = listener.accept() => {
                    accepted?;
                    Ok::<_, Box<dyn Error + Send + Sync>>(false)
                }
                completed = client_done_rx => {
                    completed.map_err(|_| "client stopped before reporting completion")?;
                    Ok(true)
                }
            }
        });

        let client = test_client(&identity, true)?;
        let result = client
            .get_negotiated(&format!("https://{address}/bounded"))?
            .send()
            .await;
        let error = match result {
            Ok(_) => return Err("request survived a second graceful GOAWAY".into()),
            Err(error) => error,
        };
        // The second GOAWAY surfaces as the selected protocol's typed error.
        assert_eq!(error.kind(), RequestErrorKind::Http2);
        assert_eq!(error.protocol(), Some(HttpProtocol::Http2));
        client_done_tx
            .send(())
            .map_err(|_| "server stopped before client completion")?;
        assert!(server.await??, "a second replay opened a third connection");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn negotiated_graceful_goaway_does_not_replay_another_method() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (client_done_tx, client_done_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, acceptor).await?;
            accept_client_preface(&mut stream).await?;
            read_request_headers(&mut stream, 1).await?;
            write_frame(&mut stream, 0x7, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 0]).await?;
            stream.flush().await?;
            stream.shutdown().await?;

            tokio::select! {
                biased;
                accepted = listener.accept() => {
                    accepted?;
                    Ok::<_, Box<dyn Error + Send + Sync>>(false)
                }
                completed = client_done_rx => {
                    completed.map_err(|_| "client stopped before reporting completion")?;
                    Ok(true)
                }
            }
        });

        let client = test_client(&identity, true)?;
        let result = client
            .request_negotiated(Method::POST, &format!("https://{address}/post"))?
            .send()
            .await;
        let error = match result {
            Ok(_) => return Err("POST was replayed after GOAWAY".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::Http2);
        client_done_tx
            .send(())
            .map_err(|_| "server stopped before client completion")?;
        assert!(
            server.await??,
            "ineligible replay opened a replacement connection"
        );
        Ok(())
    })
    .await
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "negotiated client test exceeded its deadline")?
}
