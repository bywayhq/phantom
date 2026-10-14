//! Direct HTTP/1.1-or-HTTP/2 ALPN negotiation tests.

use crate::support::h2 as h2_support;
use crate::support::tls as tls_support;
use crate::support::tracing as tracing_support;

use std::{
    collections::VecDeque,
    convert::Infallible,
    error::Error,
    future::poll_fn,
    io,
    net::{Ipv4Addr, TcpListener as StdTcpListener},
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::Bytes;
use http::{HeaderMap, Method, Response, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::Full;
use phantom::profile::{ClientProfile, browser::chrome};
use phantom::{
    HttpProtocol, HttpProxy, RequestErrorKind, RequestHeader, RequestTrailerName, ResponseInfo,
    Route,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
};
use tracing::instrument::WithSubscriber;

use h2_support::{accept_client_preface, read_request_headers, write_frame};
use tls_support::{
    H1_ALPN, H2_ALPN, TestIdentity, accept_tls_stream, client_builder, read_head, test_client,
};
use tracing_support::OutcomeSubscriber;

use body::{
    append_request_data, collect_response, next_h2_request_data, next_h2_request_trailers,
    read_framed_trailers,
};
use completion::{Peer, bounded, cancel, finish, finish_negative, join, no_connection};

mod body;
mod completion;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const SECOND_CONNECTION_WINDOW: Duration = Duration::from_millis(100);
type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[cfg(feature = "cookies")]
#[tokio::test]
async fn negotiated_http1_learns_and_sends_client_cookies() -> TestResult<()> {
    let mut server = None;
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let first_acceptor = identity.acceptor(H1_ALPN)?;
        let second_acceptor = identity.acceptor(H1_ALPN)?;
        server = Some(Peer::spawn(async move {
            let (first, _) = listener.accept().await?;
            let mut first = accept_tls_stream(first, first_acceptor).await?;
            let first_head = read_head(&mut first).await?;
            first
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nConnection: close\r\nSet-Cookie: learned=1; Secure; Path=/\r\nContent-Length: 0\r\n\r\n",
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
        }));

        let client = client_builder(&identity, true).cookies().build()?;
        for path in ["first", "second"] {
            let response = client
                .get_negotiated(&format!("https://{address}/{path}"))?
                .send()
                .await?;
            collect_response(response.into_body()).await?;
        }

        let (first, second) = join(&mut server).await?;
        assert!(!first.windows(b"\r\nCookie:".len()).any(|part| part == b"\r\nCookie:"));
        assert!(
            second
                .windows(b"\r\nCookie: learned=1\r\n".len())
                .any(|part| part == b"\r\nCookie: learned=1\r\n")
        );
        Ok(())
    })
    .await;
    finish(result, &mut server).await
}

#[tokio::test]
async fn negotiated_request_selects_http2_once() -> TestResult<()> {
    let mut server = None;
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        server = Some(Peer::spawn(async move {
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
            let had_no_second_connection = no_connection(listener.accept()).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((uri, had_no_second_connection))
        }));

        let client = test_client(&identity, true)?;
        let response = client
            .get_negotiated(&format!("https://{address}/selected-h2"))?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response_protocol(&response)?, HttpProtocol::Http2);
        collect_response(response.into_body()).await?;

        drop(client);
        let (uri, had_no_second_connection) = join(&mut server).await?;
        assert_eq!(uri.path(), "/selected-h2");
        assert!(had_no_second_connection);
        Ok(())
    })
    .await;
    finish(result, &mut server).await
}

#[tokio::test]
async fn negotiated_http1_sends_exact_dynamic_request_trailers() -> TestResult<()> {
    let mut server = None;
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        server = Some(Peer::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, acceptor).await?;
            let head = read_head(&mut stream).await?;
            let framed = read_framed_trailers(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((head, framed))
        }));

        let response = test_client(&identity, true)?
            .request_negotiated(Method::POST, &format!("https://{address}/trailers-h1"))?
            .streaming_body_with_trailers(dynamic_trailer_body(), dynamic_trailer_names())
            .send()
            .await?;
        assert_eq!(response_protocol(&response)?, HttpProtocol::Http1);
        collect_response(response.into_body()).await?;

        let (head, framed) = join(&mut server).await?;
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
    .await;
    finish(result, &mut server).await
}

#[tokio::test]
async fn negotiated_http2_sends_dynamic_request_trailers() -> TestResult<()> {
    let mut server = None;
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        server = Some(Peer::spawn(async move {
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
                append_request_data(&mut body, &chunk)?;
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
        }));

        let response = test_client(&identity, true)?
            .request_negotiated(Method::POST, &format!("https://{address}/trailers-h2"))?
            .streaming_body_with_trailers(dynamic_trailer_body(), dynamic_trailer_names())
            .send()
            .await?;
        assert_eq!(response_protocol(&response)?, HttpProtocol::Http2);
        collect_response(response.into_body()).await?;

        let (body, trailers) = join(&mut server).await?;
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
    .await;
    finish(result, &mut server).await
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
    let mut server = None;
    let mut first = None;
    let mut second = None;
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        server = Some(Peer::spawn(async move {
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
                second = no_connection(listener.accept()) => second?,
            };
            Ok::<_, Box<dyn Error + Send + Sync>>((requests, had_no_second_connection))
        }));

        let client = test_client(&identity, true)?;
        let first_client = client.clone();
        first = Some(Peer::spawn(async move {
            let response = first_client
                .get_negotiated(&format!("https://{address}/first"))?
                .send()
                .await?;
            let protocol = response_protocol(&response)?;
            collect_response(response.into_body()).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(protocol)
        }));
        let second_client = client.clone();
        second = Some(Peer::spawn(async move {
            let response = second_client
                .get_negotiated(&format!("https://{address}/second"))?
                .send()
                .await?;
            let protocol = response_protocol(&response)?;
            collect_response(response.into_body()).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(protocol)
        }));

        assert_eq!(join(&mut first).await?, HttpProtocol::Http2);
        assert_eq!(join(&mut second).await?, HttpProtocol::Http2);
        let (requests, had_no_second_connection) = join(&mut server).await?;
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
    .await;
    let result = finish(result, &mut server).await;
    let result = finish(result, &mut first).await;
    finish(result, &mut second).await
}

#[tokio::test]
async fn negotiated_http2_streams_unknown_length_request_body() -> TestResult<()> {
    let mut server = None;
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        server = Some(Peer::spawn(async move {
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
                append_request_data(&mut body, &chunk)?;
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
        }));

        let client = test_client(&identity, true)?;
        let response = client
            .request_negotiated(Method::POST, &format!("https://{address}/stream-upload"))?
            .streaming_body(UnknownBody(Some(Bytes::from_static(b"payload"))))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response_protocol(&response)?, HttpProtocol::Http2);
        collect_response(response.into_body()).await?;

        drop(client);
        let (length, body) = join(&mut server).await?;
        assert!(length.is_none());
        assert_eq!(body, b"payload");
        Ok(())
    })
    .await;
    finish(result, &mut server).await
}

#[tokio::test]
async fn negotiated_request_selects_http1_once() -> TestResult<()> {
    negotiated_http1_case(true).await
}

#[tokio::test]
async fn sequential_negotiated_http1_requests_reuse_one_tls_connection() -> TestResult<()> {
    let mut server = None;
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        server = Some(Peer::spawn(async move {
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
            let had_no_replacement = no_connection(listener.accept()).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((first, second, had_no_replacement))
        }));

        let client = test_client(&identity, true)?;
        let first = client
            .get_negotiated(&format!("https://{address}/first"))?
            .send()
            .await?;
        assert_eq!(response_protocol(&first)?, HttpProtocol::Http1);
        assert_eq!(collect_response(first.into_body()).await?, "first");

        let second = client
            .get_negotiated(&format!("https://{address}/second"))?
            .send()
            .await?;
        assert_eq!(response_protocol(&second)?, HttpProtocol::Http1);
        assert!(collect_response(second.into_body()).await?.is_empty());

        let (first, second, had_no_replacement) = join(&mut server).await?;
        assert!(first.starts_with(b"GET /first HTTP/1.1\r\n"));
        assert!(second.starts_with(b"GET /second HTTP/1.1\r\n"));
        assert!(had_no_replacement);
        Ok(())
    })
    .await;
    finish(result, &mut server).await
}

#[tokio::test]
async fn negotiated_http1_replaces_nonreusable_connection_without_replay() -> TestResult<()> {
    let mut server = None;
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let first_acceptor = identity.acceptor(H1_ALPN)?;
        let second_acceptor = identity.acceptor(H1_ALPN)?;
        server = Some(Peer::spawn(async move {
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
            let had_no_third_connection = no_connection(listener.accept()).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((
                first_head,
                second_head,
                had_no_third_connection,
            ))
        }));

        let client = test_client(&identity, true)?;
        for path in ["first", "second"] {
            let response = client
                .get_negotiated(&format!("https://{address}/{path}"))?
                .send()
                .await?;
            assert_eq!(response_protocol(&response)?, HttpProtocol::Http1);
            collect_response(response.into_body()).await?;
        }

        let (first, second, had_no_third_connection) = join(&mut server).await?;
        assert!(first.starts_with(b"GET /first HTTP/1.1\r\n"));
        assert!(second.starts_with(b"GET /second HTTP/1.1\r\n"));
        assert!(had_no_third_connection);
        Ok(())
    })
    .await;
    finish(result, &mut server).await
}

#[tokio::test]
async fn negotiated_http1_sends_streaming_request_body() -> TestResult<()> {
    let mut server = None;
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        server = Some(Peer::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, acceptor).await?;
            let head = read_head(&mut stream).await?;
            let mut body = [0_u8; 7];
            stream.read_exact(&mut body).await?;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((head, body))
        }));

        let client = test_client(&identity, true)?;
        let response = client
            .request_negotiated(Method::POST, &format!("https://{address}/stream-upload"))?
            .streaming_body(Full::new(Bytes::from_static(b"payload")))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response_protocol(&response)?, HttpProtocol::Http1);
        collect_response(response.into_body()).await?;

        let (head, body) = join(&mut server).await?;
        assert!(head.starts_with(b"POST /stream-upload HTTP/1.1\r\n"));
        assert!(head.ends_with(b"Content-Length: 7\r\n\r\n"));
        assert_eq!(&body, b"payload");
        Ok(())
    })
    .await;
    finish(result, &mut server).await
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
    let mut server = None;
    let mut client_error = None;
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        server = Some(Peer::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let stream = accept_tls_stream(tcp, acceptor).await?;
            if stream.ssl().selected_alpn_protocol() != Some(b"http/1.1") {
                return Err("server did not select HTTP/1.1".into());
            }
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }));

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
        client_error = Some(error);
        let error = client_error
            .as_ref()
            .ok_or("missing negative client outcome")?;
        assert_eq!(error.protocol(), Some(HttpProtocol::Http1));
        assert_eq!(
            subscriber.selected_protocols_for("client.request"),
            ["http/1.1"]
        );
        join(&mut server).await?;
        Ok(())
    })
    .await;
    let result = finish(result, &mut server).await;
    finish_negative(result, client_error)
}

#[tokio::test]
async fn selected_protocol_is_recorded_when_request_is_cancelled() -> TestResult<()> {
    let mut server = None;
    let mut task = None;
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let (request_seen, seen) = oneshot::channel();
        server = Some(Peer::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, acceptor).await?;
            let _request = read_head(&mut stream).await?;
            request_seen
                .send(())
                .map_err(|_| "client stopped before request observation")?;
            std::future::pending::<()>().await;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }));

        let client = test_client(&identity, true)?;
        let subscriber = OutcomeSubscriber::default();
        let request = client.get_negotiated(&format!("https://{address}/"))?;
        let dispatch = subscriber.dispatch();
        task = Some(Peer::spawn(async move {
            request.send().with_subscriber(dispatch).await?;
            TestResult::Ok(())
        }));
        seen.await?;
        cancel(&mut task).await?;
        assert_eq!(
            subscriber.selected_protocols_for("client.request"),
            ["http/1.1"]
        );
        cancel(&mut server).await?;
        Ok(())
    })
    .await;
    let result = finish(result, &mut server).await;
    finish(result, &mut task).await
}

#[tokio::test]
async fn negotiated_plaintext_request_uses_http1() -> TestResult<()> {
    let mut server = None;
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        server = Some(Peer::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let request = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nplain")
                .await?;
            stream.flush().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(request)
        }));

        let client = test_client(&identity, true)?;
        let response = client
            .get_negotiated(&format!("http://{address}/cleartext"))?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_protocol(&response)?, HttpProtocol::Http1);
        assert_eq!(collect_response(response.into_body()).await?, "plain");

        // The origin reads an HTTP/1.1 head in the clear: no TLS, no h2c.
        assert_eq!(
            join(&mut server).await?,
            format!("GET /cleartext HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes()
        );
        Ok(())
    })
    .await;
    finish(result, &mut server).await
}

#[tokio::test]
async fn negotiated_plaintext_request_is_forwarded_over_http1() -> TestResult<()> {
    let mut proxy = None;
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        proxy = Some(Peer::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let request = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            stream.flush().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(request)
        }));

        let route = Route::http_proxy(HttpProxy::new(&format!("http://{address}"))?);
        let client = client_builder(&identity, true).route(route).build()?;
        let response = client
            .get_negotiated("http://origin.test/forwarded")?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response_protocol(&response)?, HttpProtocol::Http1);
        collect_response(response.into_body()).await?;

        assert_eq!(
            join(&mut proxy).await?,
            b"GET http://origin.test/forwarded HTTP/1.1\r\nHost: origin.test\r\n\r\n"
        );
        Ok(())
    })
    .await;
    finish(result, &mut proxy).await
}

#[tokio::test]
async fn unsupported_offered_alpn_sends_no_http_bytes() -> TestResult<()> {
    let mut server = None;
    let mut client_error = None;
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(b"\x02h3")?;
        server = Some(Peer::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, acceptor).await?;
            if stream.ssl().selected_alpn_protocol() != Some(b"h3") {
                return Err("server did not select the unsupported h3 ALPN".into());
            }
            // The client closes after rejecting the ALPN; the outer test
            // deadline bounds a client that never closes.
            let mut received = [0_u8; 1];
            let count = match stream.read(&mut received).await {
                Ok(count) => count,
                Err(error) if tls_support::is_peer_gone(&error) => 0,
                Err(error) => return Err(error.into()),
            };
            Ok::<_, Box<dyn Error + Send + Sync>>(count)
        }));

        let mut tls = tls_support::tls_settings();
        tls.alpn_protocols = vec![
            Box::from(&b"h3"[..]),
            Box::from(&b"h2"[..]),
            Box::from(&b"http/1.1"[..]),
        ];
        let client =
            phantom::Client::builder(ClientProfile::new(tls).with_http2(chrome::v154_http2()))
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
        client_error = Some(error);
        let error = client_error
            .as_ref()
            .ok_or("missing negative client outcome")?;
        assert_eq!(error.kind(), RequestErrorKind::Tls);
        assert_eq!(error.protocol(), None);
        assert_eq!(join(&mut server).await?, 0);
        Ok(())
    })
    .await;
    let result = finish(result, &mut server).await;
    finish_negative(result, client_error)
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
    let mut server = None;
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = if select_alpn {
            identity.acceptor(H1_ALPN)?
        } else {
            identity.acceptor_without_alpn()?
        };
        server = Some(Peer::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, acceptor).await?;
            let selected = stream.ssl().selected_alpn_protocol().map(Box::from);
            let request = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            stream.flush().await?;
            let had_no_second_connection = no_connection(listener.accept()).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((selected, request, had_no_second_connection))
        }));

        let client = test_client(&identity, true)?;
        let response = client
            .get_negotiated(&format!("https://{address}/selected-h1"))?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response_protocol(&response)?, HttpProtocol::Http1);
        collect_response(response.into_body()).await?;

        let (selected, request, had_no_second_connection) = join(&mut server).await?;
        let expected_alpn = select_alpn.then_some(b"http/1.1".as_slice());
        assert_eq!(selected.as_deref(), expected_alpn);
        assert_eq!(
            request,
            format!("GET /selected-h1 HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes()
        );
        assert!(had_no_second_connection);
        Ok(())
    })
    .await;
    finish(result, &mut server).await
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

#[tokio::test]
async fn negotiated_graceful_goaway_retries_a_bodyless_get_once_on_a_replacement() -> TestResult<()>
{
    let mut server = None;
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let replacement_acceptor = identity.acceptor(H2_ALPN)?;
        server = Some(Peer::spawn(async move {
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
            let had_no_third_connection = no_connection(listener.accept()).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((path, had_no_third_connection))
        }));

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
        collect_response(response.into_body()).await?;
        drop(client);

        let (path, had_no_third_connection) = join(&mut server).await?;
        assert_eq!(path, "/failed");
        assert!(had_no_third_connection);
        Ok(())
    })
    .await;
    finish(result, &mut server).await
}

#[tokio::test]
async fn negotiated_graceful_goaway_replacement_may_select_http1() -> TestResult<()> {
    let mut server = None;
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let replacement_acceptor = identity.acceptor(H1_ALPN)?;
        server = Some(Peer::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut first = accept_tls_stream(tcp, acceptor).await?;
            accept_client_preface(&mut first).await?;
            read_request_headers(&mut first, 1).await?;
            // GOAWAY(NO_ERROR) with last-stream-id 0: stream 1 was not processed.
            write_frame(&mut first, 0x7, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 0]).await?;
            first.flush().await?;
            first.shutdown().await?;

            let (tcp, _) = listener.accept().await?;
            let mut replacement = accept_tls_stream(tcp, replacement_acceptor).await?;
            let head = read_head(&mut replacement).await?;
            replacement
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(head)
        }));

        let client = test_client(&identity, true)?;
        let response = client
            .get_negotiated(&format!("https://{address}/failed"))?
            .header(RequestHeader::new("x-trace", "1"))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response_protocol(&response)?, HttpProtocol::Http1);
        collect_response(response.into_body()).await?;
        drop(client);

        // The replacement carries the complete HTTP/1.1 field list.
        let head = join(&mut server).await?;
        assert_eq!(
            head,
            format!("GET /failed HTTP/1.1\r\nHost: {address}\r\nx-trace: 1\r\n\r\n").as_bytes()
        );
        Ok(())
    })
    .await;
    finish(result, &mut server).await
}

#[tokio::test]
async fn negotiated_graceful_goaway_retry_is_bounded_to_one_replacement() -> TestResult<()> {
    let mut server = None;
    let mut client_error = None;
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptors = [identity.acceptor(H2_ALPN)?, identity.acceptor(H2_ALPN)?];
        let (client_done_tx, client_done_rx) = oneshot::channel();
        server = Some(Peer::spawn(async move {
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
                    completed?;
                    Ok(true)
                }
            }
        }));

        let client = test_client(&identity, true)?;
        let result = client
            .get_negotiated(&format!("https://{address}/bounded"))?
            .send()
            .await;
        let error = match result {
            Ok(_) => return Err("request survived a second graceful GOAWAY".into()),
            Err(error) => error,
        };
        client_error = Some(error);
        let error = client_error
            .as_ref()
            .ok_or("missing negative client outcome")?;
        // The second GOAWAY surfaces as the selected protocol's typed error.
        assert_eq!(error.kind(), RequestErrorKind::Http2);
        assert_eq!(error.protocol(), Some(HttpProtocol::Http2));
        client_done_tx
            .send(())
            .map_err(|_| "server stopped before client completion")?;
        assert!(
            join(&mut server).await?,
            "a second replay opened a third connection"
        );
        Ok(())
    })
    .await;
    let result = finish(result, &mut server).await;
    finish_negative(result, client_error)
}

#[tokio::test]
async fn negotiated_graceful_goaway_does_not_replay_another_method() -> TestResult<()> {
    let mut server = None;
    let mut client_error = None;
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (client_done_tx, client_done_rx) = oneshot::channel();
        server = Some(Peer::spawn(async move {
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
                    completed?;
                    Ok(true)
                }
            }
        }));

        let client = test_client(&identity, true)?;
        let result = client
            .request_negotiated(Method::POST, &format!("https://{address}/post"))?
            .send()
            .await;
        let error = match result {
            Ok(_) => return Err("POST was replayed after GOAWAY".into()),
            Err(error) => error,
        };
        client_error = Some(error);
        let error = client_error
            .as_ref()
            .ok_or("missing negative client outcome")?;
        assert_eq!(error.kind(), RequestErrorKind::Http2);
        client_done_tx
            .send(())
            .map_err(|_| "server stopped before client completion")?;
        assert!(
            join(&mut server).await?,
            "ineligible replay opened a replacement connection"
        );
        Ok(())
    })
    .await;
    let result = finish(result, &mut server).await;
    finish_negative(result, client_error)
}
