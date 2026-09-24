//! Public-facade integration tests.

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
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::Bytes;
use http::{HeaderMap, Method, Response, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use phantom::{
    BuildErrorKind, Client, HttpProtocol, OrderedResponseHeaders, RedirectPolicy, RequestErrorKind,
    RequestHeader, RequestTimeouts, RequestTrailerName, ResponseInfo, ServerAuthentication,
    profile::{
        ClientHint, ClientHintDelivery, ClientHintSettings, ClientProfile, Http3ClientSettings,
        chromium,
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::timeout,
};
use tracing::instrument::WithSubscriber;

use h2_support::{read_frame as read_h2_frame, write_frame as write_h2_frame};
use tls_support::{
    H1_ALPN, H2_ALPN, TestIdentity, accept_tls, client_builder, read_head, test_client,
    tls_settings,
};
use tracing_support::OutcomeSubscriber;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[test]
fn request_debug_reports_shape_without_body_contents() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity, false)?;
    let request = client
        .request(HttpProtocol::Http1, Method::POST, "https://example.com/")?
        .body(Bytes::from_static(b"private-payload"));

    let debug = format!("{request:?}");
    assert!(debug.contains("POST"));
    assert!(debug.contains("body_len: 15"));
    assert!(!debug.contains("private-payload"));
    Ok(())
}

#[test]
fn runtime_without_io_returns_error_and_records_error_outcomes() -> TestResult<()> {
    let profile = ClientProfile::new(chromium::v154_tls());
    let client = Client::builder(profile).build()?;
    let request = client.get(HttpProtocol::Http1, "https://127.0.0.1:9/")?;
    let subscriber = OutcomeSubscriber::default();
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;

    let error = match runtime.block_on(request.send().with_subscriber(subscriber.dispatch())) {
        Ok(_) => return Err("request completed on a runtime without network I/O".into()),
        Err(error) => error,
    };

    assert_eq!(error.kind(), RequestErrorKind::RuntimeUnavailable);
    assert_eq!(subscriber.outcomes_for("client.request"), ["error"]);
    assert_eq!(
        subscriber.outcomes_for("http1.tls.connect"),
        ["runtime_unavailable"]
    );
    Ok(())
}

#[tokio::test]
async fn public_client_streams_http1_over_verified_tls() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let (release, released) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut stream = accept_tls(listener, acceptor).await?;
            let request = read_head(&mut stream).await?;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nSet-Cookie: first=1\r\nX-MiXeD: middle\r\nset-cookie: second=2\r\nContent-Length: 10\r\n\r\nfirst",
                )
                .await?;
            stream.flush().await?;
            released.await.map_err(io::Error::other)?;
            stream.write_all(b"later").await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(request)
        });

        let client = test_client(&identity, false)?;
        let response = client
            .get(
                HttpProtocol::Http1,
                &format!("https://{address}/resource?item=1"),
            )?
            .headers(vec![
                RequestHeader::new("X-First", "one"),
                RequestHeader::new("x-repeat", "alpha"),
                RequestHeader::new("X-Repeat", "beta"),
            ])
            .send()
            .await?;
        assert_eq!(response.status(), 200);
        assert_eq!(
            response
                .extensions()
                .get::<ResponseInfo>()
                .map(ResponseInfo::protocol),
            Some(HttpProtocol::Http1)
        );
        let ordered = response
            .extensions()
            .get::<OrderedResponseHeaders>()
            .ok_or("response did not expose ordered fields")?;
        let observed = ordered
            .iter()
            .map(|header| (header.name(), header.value()))
            .collect::<Vec<_>>();
        assert_eq!(
            observed,
            [
                ("Set-Cookie", b"first=1".as_slice()),
                ("X-MiXeD", b"middle".as_slice()),
                ("set-cookie", b"second=2".as_slice()),
                ("Content-Length", b"10".as_slice()),
            ]
        );

        let mut body = response.into_body();
        let first = next_data(&mut body).await?;
        assert_eq!(first, "first");
        release
            .send(())
            .map_err(|_| "server stopped before later body release")?;
        assert_eq!(body.collect().await?.to_bytes(), "later");

        let request = server.await??;
        let expected = format!(
            "GET /resource?item=1 HTTP/1.1\r\nHost: {address}\r\nX-First: one\r\nx-repeat: alpha\r\nX-Repeat: beta\r\n\r\n"
        );
        assert_eq!(request, expected.as_bytes());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn direct_request_canonicalizes_a_whatwg_ip_host_before_io() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_tls(listener, acceptor).await?;
            let request = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(request)
        });

        let client = test_client(&identity, false)?;
        let uri = format!("https://１２７．０．０．１:{}/idna", address.port());
        let response = client.get(HttpProtocol::Http1, &uri)?.send().await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;

        assert_eq!(
            server.await??,
            format!(
                "GET /idna HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                address.port()
            )
            .as_bytes()
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn public_client_sends_owned_http1_request_body() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_tls(listener, acceptor).await?;
            let head = read_head(&mut stream).await?;
            let mut body = [0_u8; 7];
            stream.read_exact(&mut body).await?;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((head, body))
        });

        let client = test_client(&identity, false)?;
        let response = client
            .request(
                HttpProtocol::Http1,
                Method::POST,
                &format!("https://{address}/upload"),
            )?
            .header(RequestHeader::new("X-Order", "first"))
            .body(Bytes::from_static(b"payload"))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;

        let (head, body) = server.await??;
        let expected = format!(
            "POST /upload HTTP/1.1\r\nHost: {address}\r\nX-Order: first\r\nContent-Length: 7\r\n\r\n"
        );
        assert_eq!(head, expected.as_bytes());
        assert_eq!(&body, b"payload");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn public_client_streams_unknown_length_http1_request_body() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_tls(listener, acceptor).await?;
            let head = read_head(&mut stream).await?;
            let mut framed = Vec::new();
            while !framed.ends_with(b"0\r\n\r\n") {
                let mut byte = [0_u8; 1];
                stream.read_exact(&mut byte).await?;
                framed.push(byte[0]);
            }
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((head, framed))
        });

        let client = test_client(&identity, false)?;
        let response = client
            .request(
                HttpProtocol::Http1,
                Method::POST,
                &format!("https://{address}/stream-upload"),
            )?
            .streaming_body(UnknownBody::new([b"alpha".as_slice(), b"beta".as_slice()]))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;

        let (head, framed) = server.await??;
        assert!(head.ends_with(b"Transfer-Encoding: chunked\r\n\r\n"));
        assert_eq!(framed, b"5\r\nalpha\r\n4\r\nbeta\r\n0\r\n\r\n");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn public_http1_body_source_error_has_request_body_category() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_tls(listener, acceptor).await?;
            let mut observed = Vec::new();
            stream.read_to_end(&mut observed).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(observed)
        });

        let client = test_client(&identity, false)?;
        let error = match client
            .request(
                HttpProtocol::Http1,
                Method::POST,
                &format!("https://{address}/failed-upload"),
            )?
            .streaming_body(ErrorBody::new())
            .send()
            .await
        {
            Ok(_) => return Err("failing HTTP/1 body source was accepted".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::RequestBody);
        assert_eq!(error.protocol(), Some(HttpProtocol::Http1));
        let _observed = server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn public_client_streams_http2_data_and_trailers() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (release, released) = oneshot::channel();
        let server = tokio::spawn(async move {
            let stream = accept_tls(listener, acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before request")??;
            let response = Response::builder()
                .status(206)
                .header("set-cookie", "first=1")
                .header("x-middle", "middle")
                .header("set-cookie", "second=2")
                .body(())?;
            let mut send = respond.send_response(response, false)?;
            send.send_data(Bytes::from_static(b"first"), false)?;

            tokio::pin!(released);
            tokio::select! {
                result = &mut released => result.map_err(io::Error::other)?,
                incoming = connection.accept() => {
                    if incoming.is_none() {
                        return Err("connection closed before later data release".into());
                    }
                    return Err("client sent an unexpected second request".into());
                }
            }

            send.send_data(Bytes::from_static(b"later"), false)?;
            let mut trailers = HeaderMap::new();
            trailers.insert("x-finished", "yes".parse()?);
            send.send_trailers(trailers)?;
            let uri = request.uri().clone();
            drop(request);
            drop(send);
            drop(respond);
            poll_fn(|context| connection.poll_closed(context)).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(uri)
        });

        let client = test_client(&identity, true)?;
        let response = client
            .get(
                HttpProtocol::Http2,
                &format!("https://{address}/resource?item=1"),
            )?
            .header(RequestHeader::new("x-repeat", "alpha"))
            .header(RequestHeader::new("x-repeat", "beta"))
            .send()
            .await?;
        assert_eq!(response.status(), 206);
        assert_eq!(
            response
                .extensions()
                .get::<ResponseInfo>()
                .map(ResponseInfo::protocol),
            Some(HttpProtocol::Http2)
        );
        let ordered = response
            .extensions()
            .get::<OrderedResponseHeaders>()
            .ok_or("HTTP/2 response omitted ordered fields")?;
        assert_eq!(
            ordered
                .iter()
                .map(|field| (field.name(), field.value()))
                .collect::<Vec<_>>(),
            [
                ("set-cookie", b"first=1".as_slice()),
                ("set-cookie", b"second=2".as_slice()),
                ("x-middle", b"middle".as_slice()),
            ]
        );

        let mut body = response.into_body();
        assert_eq!(next_data(&mut body).await?, "first");
        release
            .send(())
            .map_err(|_| "server stopped before later body release")?;

        let mut later = None;
        let mut trailer = None;
        while let Some(frame) = body.frame().await {
            let frame = frame?;
            match frame.into_data() {
                Ok(data) if !data.is_empty() => later = Some(data),
                Ok(_) => {}
                Err(frame) => {
                    if let Ok(fields) = frame.into_trailers() {
                        trailer = fields.get("x-finished").cloned();
                    }
                }
            }
        }
        assert_eq!(later.as_deref(), Some(&b"later"[..]));
        assert_eq!(
            trailer.as_ref().and_then(|value| value.to_str().ok()),
            Some("yes")
        );

        drop(client);
        let uri = server.await??;
        let expected_authority = address.to_string();
        assert_eq!(
            uri.authority().map(|value| value.as_str()),
            Some(expected_authority.as_str())
        );
        assert_eq!(
            uri.path_and_query().map(|value| value.as_str()),
            Some("/resource?item=1")
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn public_client_sends_owned_http2_request_body() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let stream = accept_tls(listener, acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before request")??;
            let method = request.method().clone();
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
            Ok::<_, Box<dyn Error + Send + Sync>>((method, length, Bytes::from(body)))
        });

        let client = test_client(&identity, true)?;
        let response = client
            .request(
                HttpProtocol::Http2,
                Method::POST,
                &format!("https://{address}/upload"),
            )?
            .body(Bytes::from_static(b"payload"))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;

        drop(client);
        let (method, length, body) = server.await??;
        assert_eq!(method, Method::POST);
        assert_eq!(
            length.as_ref().and_then(|value| value.to_str().ok()),
            Some("7")
        );
        assert_eq!(body, "payload");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn public_builder_sends_dynamic_http2_request_trailers_after_data() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let stream = accept_tls(listener, acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before request")??;
            let length = request.headers().get("content-length").cloned();
            let mut incoming = request.into_body();
            let mut body = Vec::new();
            while let Some(chunk) = next_h2_request_data(&mut connection, &mut incoming).await? {
                body.extend_from_slice(&chunk);
                incoming.flow_control().release_capacity(chunk.len())?;
            }
            let trailers = next_h2_request_trailers(&mut connection, &mut incoming)
                .await?
                .ok_or("request omitted trailers")?;
            respond.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
                true,
            )?;
            poll_fn(|context| connection.poll_closed(context)).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((length, Bytes::from(body), trailers))
        });

        let response = test_client(&identity, true)?
            .request(
                HttpProtocol::Http2,
                Method::POST,
                &format!("https://{address}/request-trailers"),
            )?
            .streaming_body_with_trailers(dynamic_trailer_body(), dynamic_trailer_names())
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;

        let (length, body, trailers) = server.await??;
        assert_eq!(length.as_ref().and_then(|value| value.to_str().ok()), None);
        assert_eq!(body, "payload");
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
async fn public_client_streams_unknown_length_http2_request_body() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let stream = accept_tls(listener, acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before request")??;
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
            .request(
                HttpProtocol::Http2,
                Method::POST,
                &format!("https://{address}/stream-upload"),
            )?
            .streaming_body(UnknownBody::new([b"alpha".as_slice(), b"beta".as_slice()]))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;

        drop(client);
        let (length, body) = server.await??;
        assert!(length.is_none());
        assert_eq!(body, b"alphabeta");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn upload_failure_after_early_http2_response_has_request_body_category() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (fail_upload, upload_failure) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let stream = accept_tls(listener, acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            if let Some(Ok((request, mut respond))) = connection.accept().await {
                // The response head arrives before the upload finishes, so the
                // client keeps uploading beside the response body.
                let _response =
                    respond.send_response(Response::builder().status(200).body(())?, false)?;
                let mut incoming = request.into_body();
                while let Ok(Some(chunk)) =
                    next_h2_request_data(&mut connection, &mut incoming).await
                {
                    incoming.flow_control().release_capacity(chunk.len())?;
                }
            }
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let client = test_client(&identity, true)?;
        let response = client
            .request(
                HttpProtocol::Http2,
                Method::POST,
                &format!("https://{address}/late-upload-failure"),
            )?
            .streaming_body(GatedErrorBody::new(upload_failure))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        // Fail the upload only after the client has returned the response head.
        let _ = fail_upload.send(());
        let error = match response.into_body().collect().await {
            Ok(_) => return Err("late request body failure was not reported".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::RequestBody);
        assert_eq!(error.protocol(), Some(HttpProtocol::Http2));
        drop(client);
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn public_http2_body_source_error_has_request_body_category() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let stream = accept_tls(listener, acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            if let Some(Ok((request, _respond))) = connection.accept().await {
                let mut incoming = request.into_body();
                while let Ok(Some(chunk)) =
                    next_h2_request_data(&mut connection, &mut incoming).await
                {
                    incoming.flow_control().release_capacity(chunk.len())?;
                }
            }
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let client = test_client(&identity, true)?;
        let error = match client
            .request(
                HttpProtocol::Http2,
                Method::POST,
                &format!("https://{address}/failed-upload"),
            )?
            .streaming_body(ErrorBody::new())
            .send()
            .await
        {
            Ok(_) => return Err("failing HTTP/2 body source was accepted".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::RequestBody);
        assert_eq!(error.protocol(), Some(HttpProtocol::Http2));
        drop(client);
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn public_http2_response_retains_interleaved_field_order() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (client_done, done_received) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut stream = accept_tls(listener, acceptor).await?;
            let mut preface = [0; 24];
            stream.read_exact(&mut preface).await?;
            if &preface != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
                return Err("client omitted the HTTP/2 preface".into());
            }

            loop {
                let frame = read_h2_frame(&mut stream).await?;
                if frame.kind == 0x4 && frame.stream_id == 0 && frame.flags & 0x1 == 0 {
                    break;
                }
            }
            write_h2_frame(&mut stream, 0x4, 0, 0, &[]).await?;
            write_h2_frame(&mut stream, 0x4, 0x1, 0, &[]).await?;

            loop {
                let frame = read_h2_frame(&mut stream).await?;
                if frame.kind == 0x1 && frame.stream_id == 1 {
                    if frame.flags & 0x4 == 0 {
                        return Err("test request HEADERS required CONTINUATION".into());
                    }
                    break;
                }
            }

            let block = interleaved_hpack_response();
            write_h2_frame(&mut stream, 0x1, 0x5, 1, &block).await?;
            stream.flush().await?;
            done_received.await.map_err(io::Error::other)?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let client = test_client(&identity, true)?;
        let response = client
            .get(HttpProtocol::Http2, &format!("https://{address}/ordered"))?
            .send()
            .await?;
        let ordered = response
            .extensions()
            .get::<OrderedResponseHeaders>()
            .ok_or("HTTP/2 response omitted ordered fields")?;
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
        assert!(response.into_body().collect().await?.to_bytes().is_empty());

        let _ = client_done.send(());
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn unavailable_protocol_fails_before_network_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity, false)?;
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;

    let error = match client.get(HttpProtocol::Http2, &format!("https://{address}/")) {
        Ok(_) => return Err("HTTP/2 unexpectedly available".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::ProtocolUnavailable);
    assert_eq!(error.protocol(), Some(HttpProtocol::Http2));
    assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    Ok(())
}

#[tokio::test]
async fn invalid_http2_field_fails_before_network_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity, true)?;
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;

    let result = client
        .get(HttpProtocol::Http2, &format!("https://{address}/"))?
        .header(RequestHeader::new("X-Uppercase", "rejected"))
        .send()
        .await;
    let error = match result {
        Ok(_) => return Err("invalid HTTP/2 field unexpectedly sent".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::Http2);
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    Ok(())
}

#[tokio::test]
async fn empty_host_fails_before_network_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity, false)?;
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();

    let error = match client.get(HttpProtocol::Http1, &format!("https://:{port}/")) {
        Ok(_) => return Err("empty request host was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::InvalidAuthority);
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    Ok(())
}

#[tokio::test]
async fn bracketed_ipv4_host_fails_before_network_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity, false)?;
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();

    let error = match client.get(HttpProtocol::Http1, &format!("https://[127.0.0.1]:{port}/")) {
        Ok(_) => return Err("bracketed IPv4 request host was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::InvalidAuthority);
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    Ok(())
}

#[tokio::test]
async fn invalid_idna_host_fails_before_network_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity, false)?;
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();

    let error = match client.get(
        HttpProtocol::Http1,
        &format!("https://\u{200d}.example:{port}/"),
    ) {
        Ok(_) => return Err("invalid IDNA request host was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::InvalidAuthority);
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    Ok(())
}

#[tokio::test]
async fn malformed_explicit_ports_fail_before_network_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity, false)?;
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;

    for (port, description) in [
        ("", "empty"),
        ("not-a-port", "nonnumeric"),
        ("65536", "overflow"),
    ] {
        let uri = format!("https://127.0.0.1:{port}/");
        let error = match client.get(HttpProtocol::Http1, &uri) {
            Ok(_) => return Err(format!("{description} request port was accepted").into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::InvalidAuthority);
        assert!(matches!(
            listener.accept(),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
    }
    Ok(())
}

#[test]
fn polling_direct_request_without_tokio_returns_error() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity, false)?;
    let request = client.get(HttpProtocol::Http1, "https://127.0.0.1:9/")?;
    let mut future = std::pin::pin!(request.send());
    let mut context = Context::from_waker(Waker::noop());

    let result = match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => return Err("request waited without a Tokio runtime".into()),
    };
    let error = match result {
        Ok(_) => return Err("request completed outside a Tokio runtime".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::RuntimeUnavailable);
    Ok(())
}

#[test]
fn polling_request_with_timeouts_without_tokio_returns_error() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity, false)?;
    let request = client
        .get(HttpProtocol::Http1, "https://127.0.0.1:9/")?
        .timeouts(RequestTimeouts::new().total(Duration::from_secs(1)));
    let mut future = std::pin::pin!(request.send());
    let mut context = Context::from_waker(Waker::noop());

    let result = match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => return Err("request waited without a Tokio runtime".into()),
    };
    let error = match result {
        Ok(_) => return Err("request completed outside a Tokio runtime".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::RuntimeUnavailable);
    Ok(())
}

#[test]
fn session_alt_svc_without_http3_fails_like_client_builder() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity, true)?;
    let error = match client.session_builder().alt_svc(NonZeroUsize::MIN).build() {
        Ok(_) => return Err("Alt-Svc session without an HTTP/3 connector was built".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);

    let error = match client_builder(&identity, true)
        .alt_svc(NonZeroUsize::MIN)
        .build()
    {
        Ok(_) => return Err("Alt-Svc client without an HTTP/3 connector was built".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);
    Ok(())
}

#[test]
fn invalid_http2_profile_has_stable_build_category() -> TestResult<()> {
    let mut tls = tls_settings();
    tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    let error =
        match Client::builder(ClientProfile::new(tls).with_http2(chromium::v154_http2())).build() {
            Ok(_) => return Err("HTTP/2 profile without h2 ALPN was accepted".into()),
            Err(error) => error,
        };
    assert_eq!(error.kind(), BuildErrorKind::InvalidProfile);

    let mut http2 = chromium::v154_http2();
    http2.initial_connection_window_size = 65_534;
    let error = match Client::builder(ClientProfile::new(tls_settings()).with_http2(http2)).build()
    {
        Ok(_) => return Err("invalid HTTP/2 settings were accepted".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), BuildErrorKind::InvalidProfile);
    Ok(())
}

#[test]
fn contradictory_server_authentication_policy_fails_during_build() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let error = match Client::builder(ClientProfile::new(tls_settings()))
        .server_authentication(ServerAuthentication::Disabled)
        .add_root_certificate_der(identity.root_der)
        .build()
    {
        Ok(_) => return Err("disabled authentication with extra roots was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);
    assert!(
        error
            .to_string()
            .contains("cannot be combined with additional roots")
    );
    Ok(())
}

#[test]
fn disabled_server_authentication_rejects_http3_during_build() -> TestResult<()> {
    let http3 = Http3ClientSettings::new(
        chromium::v154_http3_tls(),
        chromium::v154_quic(),
        chromium::v154_http3(),
        chromium::v154_http3_request(),
    );
    let error = match Client::builder(ClientProfile::new(tls_settings()).with_http3(http3))
        .server_authentication(ServerAuthentication::Disabled)
        .build()
    {
        Ok(_) => return Err("disabled authentication with HTTP/3 was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);
    assert!(error.to_string().contains("not supported for HTTP/3"));
    Ok(())
}

#[test]
fn client_builder_debug_reports_public_policy_without_secrets() {
    const SEVEN: NonZeroUsize = match NonZeroUsize::new(7) {
        Some(value) => value,
        None => NonZeroUsize::MIN,
    };
    let debug = format!(
        "{:?}",
        Client::builder(ClientProfile::new(tls_settings()))
            .server_authentication(ServerAuthentication::Disabled)
            .redirect_policy(RedirectPolicy::limited(SEVEN))
            .max_retained_http1_connections(SEVEN)
    );
    assert!(debug.contains("server_authentication: Disabled"));
    assert!(debug.contains("redirect_policy: RedirectPolicy { maximum: Some(7) }"));
    assert!(debug.contains("max_retained_http1_connections: 7"));
}

#[test]
fn invalid_client_hint_profile_has_stable_build_category() -> TestResult<()> {
    let hints = ClientHintSettings::new(vec![ClientHint::new(
        "Sec-CH-UA",
        "value",
        ClientHintDelivery::Default,
    )]);
    let error = match Client::builder(ClientProfile::new(tls_settings()).with_client_hints(hints))
        .build()
    {
        Ok(_) => return Err("invalid client-hint profile was accepted".into()),
        Err(error) => error,
    };

    assert_eq!(error.kind(), BuildErrorKind::InvalidProfile);
    assert!(
        error
            .to_string()
            .starts_with("invalid client-hint profile:")
    );
    Ok(())
}

#[test]
fn invalid_additional_root_has_stable_build_category() -> TestResult<()> {
    let mut tls = tls_settings();
    tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    let error = match Client::builder(ClientProfile::new(tls))
        .add_root_certificate_der([0_u8])
        .build()
    {
        Ok(_) => return Err("invalid additional trust root was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), BuildErrorKind::TrustStore);
    Ok(())
}

fn interleaved_hpack_response() -> Vec<u8> {
    let mut block = vec![0x88, 0x0f, 0x28, 7];
    block.extend_from_slice(b"first=1");
    block.extend_from_slice(&[0, 8]);
    block.extend_from_slice(b"x-middle");
    block.push(6);
    block.extend_from_slice(b"middle");
    block.extend_from_slice(&[0x0f, 0x28, 8]);
    block.extend_from_slice(b"second=2");
    block
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

/// Yields one chunk, then fails once the test signals that the response head
/// was returned.
struct GatedErrorBody {
    sent_prefix: bool,
    failure: oneshot::Receiver<()>,
}

impl GatedErrorBody {
    fn new(failure: oneshot::Receiver<()>) -> Self {
        Self {
            sent_prefix: false,
            failure,
        }
    }
}

impl Body for GatedErrorBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if !self.sent_prefix {
            self.sent_prefix = true;
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"prefix")))));
        }
        match Pin::new(&mut self.failure).poll(context) {
            Poll::Ready(_) => Poll::Ready(Some(Err(io::Error::other(
                "synthetic late request body failure",
            )))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

struct ErrorBody {
    frames: VecDeque<Result<Frame<Bytes>, io::Error>>,
}

impl ErrorBody {
    fn new() -> Self {
        Self {
            frames: [
                Ok(Frame::data(Bytes::from_static(b"prefix"))),
                Err(io::Error::other("synthetic request body failure")),
            ]
            .into(),
        }
    }
}

impl Body for ErrorBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.frames.pop_front())
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

async fn next_data(body: &mut phantom::ResponseBody) -> TestResult<Bytes> {
    loop {
        let frame = body.frame().await.ok_or("response body ended")??;
        if let Ok(data) = frame.into_data()
            && !data.is_empty()
        {
            return Ok(data);
        }
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

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "client test exceeded its deadline")?
}
