use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use http::Method;
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};
use tracing::{Dispatch, instrument::WithSubscriber};

use super::{TestResult, bounded_peer_test, host, read_head, target};
use crate::{
    OrderedResponseHeaders,
    http1::{
        AbsoluteForm, Http1Error, MAX_REQUEST_HEADER_BYTES, MAX_REQUEST_HEADERS,
        MAX_REQUEST_TRAILER_BYTES, MAX_REQUEST_TRAILERS, RequestHeader, send_forward_request,
        send_forward_request_body, send_get, send_request, send_request_body,
        send_request_body_with_trailers, validate_forward_request, validate_request,
        validate_request_body, validate_request_body_with_trailers,
    },
    request::RequestBody,
    tracing_test::{OutcomeSubscriber, poll_once_then_drop},
};

struct Chunks {
    chunks: std::collections::VecDeque<Bytes>,
    exact: Option<u64>,
}

impl Chunks {
    fn known(chunks: impl IntoIterator<Item = Bytes>) -> Self {
        let chunks = chunks
            .into_iter()
            .collect::<std::collections::VecDeque<_>>();
        let exact = chunks.iter().map(|chunk| chunk.len() as u64).sum();
        Self {
            chunks,
            exact: Some(exact),
        }
    }

    fn unknown(chunks: impl IntoIterator<Item = Bytes>) -> Self {
        Self {
            chunks: chunks.into_iter().collect(),
            exact: None,
        }
    }
}

impl Body for Chunks {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let chunk = self.chunks.pop_front();
        if let (Some(exact), Some(chunk)) = (self.exact.as_mut(), chunk.as_ref()) {
            *exact -= chunk.len() as u64;
        }
        Poll::Ready(chunk.map(Frame::data).map(Ok))
    }

    fn is_end_stream(&self) -> bool {
        self.chunks.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        match self.exact {
            Some(exact) => SizeHint::with_exact(exact),
            None => SizeHint::default(),
        }
    }
}

struct PollCountingBody(Arc<AtomicUsize>);

impl Body for PollCountingBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
}

#[tokio::test]
async fn cancelled_response_head_records_outcome_once() -> TestResult {
    let subscriber = OutcomeSubscriber::default();
    let (client, _server) = duplex(4096);
    let pending = poll_once_then_drop(
        send_get(client, target()?, vec![host()]),
        subscriber.clone(),
    )
    .await;
    if !pending {
        return Err("HTTP/1 response-head future completed before cancellation".into());
    }

    assert_eq!(
        subscriber.outcomes_for("http1.response_head"),
        ["cancelled"]
    );
    Ok(())
}

#[tokio::test]
async fn writes_exact_order_casing_and_duplicates() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let transaction = tokio::spawn(send_get(
            client,
            target()?,
            vec![
                host(),
                RequestHeader::new("X-First", "one"),
                RequestHeader::new("x-repeat", "alpha"),
                RequestHeader::new("X-Repeat", "beta"),
            ],
        ));

        let request = read_head(&mut server).await?;
        assert_eq!(
            request,
            b"GET /resource?item=1 HTTP/1.1\r\nHost: example.test\r\nX-First: one\r\nx-repeat: alpha\r\nX-Repeat: beta\r\n\r\n"
        );

        server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await?;
        let response = transaction.await??;
        response.into_body().collect().await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn writes_method_body_and_generated_content_length() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let transaction = tokio::spawn(send_request(
            client,
            Method::POST,
            target()?,
            vec![host(), RequestHeader::new("X-Order", "before-length")],
            Some(Bytes::from_static(b"payload")),
        ));

        let head = read_head(&mut server).await?;
        assert_eq!(
            head,
            b"POST /resource?item=1 HTTP/1.1\r\nHost: example.test\r\nX-Order: before-length\r\nContent-Length: 7\r\n\r\n"
        );
        let mut body = [0_u8; 7];
        server.read_exact(&mut body).await?;
        assert_eq!(&body, b"payload");

        server
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await?;
        transaction.await??.into_body().collect().await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn known_stream_preserves_generated_content_length_order() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let body = RequestBody::streaming(Chunks::known([
            Bytes::from_static(b"pay"),
            Bytes::from_static(b"load"),
        ]));
        let transaction = tokio::spawn(send_request_body(
            client,
            Method::POST,
            target()?,
            vec![host(), RequestHeader::new("X-Order", "before-length")],
            Some(body),
        ));

        let head = read_head(&mut server).await?;
        assert_eq!(
            head,
            b"POST /resource?item=1 HTTP/1.1\r\nHost: example.test\r\nX-Order: before-length\r\nContent-Length: 7\r\n\r\n"
        );
        let mut body = [0_u8; 7];
        server.read_exact(&mut body).await?;
        assert_eq!(&body, b"payload");
        server
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await?;
        transaction.await??.into_body().collect().await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn unknown_stream_preserves_generated_chunked_framing_order() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let body = RequestBody::streaming(Chunks::unknown([
            Bytes::from_static(b"pay"),
            Bytes::from_static(b"load"),
        ]));
        let transaction = tokio::spawn(send_request_body(
            client,
            Method::POST,
            target()?,
            vec![host(), RequestHeader::new("X-Order", "before-framing")],
            Some(body),
        ));

        let head = read_head(&mut server).await?;
        assert_eq!(
            head,
            b"POST /resource?item=1 HTTP/1.1\r\nHost: example.test\r\nX-Order: before-framing\r\nTransfer-Encoding: chunked\r\n\r\n"
        );
        let mut body = [0_u8; 22];
        server.read_exact(&mut body).await?;
        assert_eq!(&body, b"3\r\npay\r\n4\r\nload\r\n0\r\n\r\n");
        server
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await?;
        transaction.await??.into_body().collect().await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn writes_exact_order_casing_and_interleaved_duplicate_trailers() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let transaction = tokio::spawn(send_request_body_with_trailers(
            client,
            Method::POST,
            target()?,
            vec![host(), RequestHeader::new("X-Order", "before-framing")],
            Some(RequestBody::from_bytes(Bytes::from_static(b"payload"))),
            vec![
                RequestHeader::new("X-Repeat", "alpha"),
                RequestHeader::new("X-Middle", "between"),
                RequestHeader::new("x-repeat", "omega"),
            ],
        ));

        let head = read_head(&mut server).await?;
        assert_eq!(
            head,
            b"POST /resource?item=1 HTTP/1.1\r\nHost: example.test\r\nX-Order: before-framing\r\nTransfer-Encoding: chunked\r\nTrailer: X-Repeat, X-Middle\r\n\r\n"
        );
        let expected = b"7\r\npayload\r\n0\r\nX-Repeat: alpha\r\nX-Middle: between\r\nx-repeat: omega\r\n\r\n";
        let mut body = vec![0_u8; expected.len()];
        server.read_exact(&mut body).await?;
        assert_eq!(body, expected);
        server
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await?;
        transaction.await??.into_body().collect().await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn trailer_only_request_still_uses_chunked_framing() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let transaction = tokio::spawn(send_request_body_with_trailers(
            client,
            Method::POST,
            target()?,
            vec![host()],
            None,
            vec![RequestHeader::new("X-Final", "yes")],
        ));

        let head = read_head(&mut server).await?;
        assert_eq!(
            head,
            b"POST /resource?item=1 HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nTrailer: X-Final\r\n\r\n"
        );
        let expected = b"0\r\nX-Final: yes\r\n\r\n";
        let mut body = vec![0_u8; expected.len()];
        server.read_exact(&mut body).await?;
        assert_eq!(body, expected);
        server
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await?;
        transaction.await??.into_body().collect().await?;
        Ok(())
    })
    .await
}

#[test]
fn validates_trailer_fields_declaration_and_limits() -> TestResult {
    let target = target()?;
    let metadata = RequestBody::from_bytes(Bytes::new()).metadata();
    let trailer = RequestHeader::new("x-final", "yes");
    assert!(matches!(
        validate_request_body_with_trailers(
            &Method::POST,
            &target,
            &[host(), RequestHeader::new("Content-Length", "0")],
            Some(metadata),
            std::slice::from_ref(&trailer),
        ),
        Err(Http1Error::RequestTrailersWithContentLength { index: 1 })
    ));
    assert!(matches!(
        validate_request_body_with_trailers(
            &Method::POST,
            &target,
            &[host(), RequestHeader::new("Trailer", "x-other")],
            Some(metadata),
            std::slice::from_ref(&trailer),
        ),
        Err(Http1Error::InvalidTrailerDeclaration { index: 1 })
    ));
    assert!(matches!(
        validate_request_body_with_trailers(
            &Method::POST,
            &target,
            &[host()],
            Some(metadata),
            &[RequestHeader::new("Content-Type", "text/plain")],
        ),
        Err(Http1Error::ForbiddenTrailer { index: 0, .. })
    ));
    for name in ["connection", "upgrade", "keep-alive", "proxy-connection"] {
        assert!(matches!(
            validate_request_body_with_trailers(
                &Method::POST,
                &target,
                &[host()],
                Some(metadata),
                &[RequestHeader::new(name, "value")],
            ),
            Err(Http1Error::ForbiddenTrailer { index: 0, .. })
        ));
    }
    assert!(matches!(
        validate_request_body_with_trailers(
            &Method::POST,
            &target,
            &[host()],
            Some(metadata),
            &[RequestHeader::new("bad name", "value")],
        ),
        Err(Http1Error::InvalidTrailerName { index: 0 })
    ));
    assert!(matches!(
        validate_request_body_with_trailers(
            &Method::POST,
            &target,
            &[host()],
            Some(metadata),
            &vec![RequestHeader::new("x-many", "value"); MAX_REQUEST_TRAILERS + 1],
        ),
        Err(Http1Error::TooManyTrailers { .. })
    ));
    assert!(matches!(
        validate_request_body_with_trailers(
            &Method::POST,
            &target,
            &[host()],
            Some(metadata),
            &[RequestHeader::new(
                "x-large",
                vec![b'a'; MAX_REQUEST_TRAILER_BYTES]
            )],
        ),
        Err(Http1Error::TrailersTooLarge { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn forwarding_writes_exact_absolute_target_and_ordered_fields() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let transaction = tokio::spawn(send_forward_request(
            client,
            Method::POST,
            AbsoluteForm::parse("http://example.test:8080/resource?item=1")?,
            vec![
                RequestHeader::new("Host", "example.test:8080"),
                RequestHeader::new("X-First", "one"),
                RequestHeader::new("x-repeat", "alpha"),
                RequestHeader::new("X-Repeat", "beta"),
            ],
            Some(Bytes::from_static(b"payload")),
        ));

        let head = read_head(&mut server).await?;
        assert_eq!(
            head,
            b"POST http://example.test:8080/resource?item=1 HTTP/1.1\r\nHost: example.test:8080\r\nX-First: one\r\nx-repeat: alpha\r\nX-Repeat: beta\r\nContent-Length: 7\r\n\r\n"
        );
        let mut body = [0_u8; 7];
        server.read_exact(&mut body).await?;
        assert_eq!(&body, b"payload");

        server
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await?;
        transaction.await??.into_body().collect().await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn forward_proxy_streams_unknown_body_with_absolute_form() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let body = RequestBody::streaming(Chunks::unknown([Bytes::from_static(b"proxy")]));
        let transaction = tokio::spawn(send_forward_request_body(
            client,
            Method::POST,
            AbsoluteForm::parse("http://example.test:8080/upload")?,
            vec![
                RequestHeader::new("Host", "example.test:8080"),
                RequestHeader::new("X-Order", "before-framing"),
            ],
            Some(body),
        ));

        let head = read_head(&mut server).await?;
        assert_eq!(
            head,
            b"POST http://example.test:8080/upload HTTP/1.1\r\nHost: example.test:8080\r\nX-Order: before-framing\r\nTransfer-Encoding: chunked\r\n\r\n"
        );
        let mut body = [0_u8; 15];
        server.read_exact(&mut body).await?;
        assert_eq!(&body, b"5\r\nproxy\r\n0\r\n\r\n");
        server
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await?;
        transaction.await??.into_body().collect().await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn preserves_explicit_content_length_spelling_and_position() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let transaction = tokio::spawn(send_request(
            client,
            Method::PUT,
            target()?,
            vec![
                host(),
                RequestHeader::new("cOnTeNt-LeNgTh", "4"),
                RequestHeader::new("X-After", "yes"),
            ],
            Some(Bytes::from_static(b"data")),
        ));

        let head = read_head(&mut server).await?;
        assert_eq!(
            head,
            b"PUT /resource?item=1 HTTP/1.1\r\nHost: example.test\r\ncOnTeNt-LeNgTh: 4\r\nX-After: yes\r\n\r\n"
        );
        let mut body = [0_u8; 4];
        server.read_exact(&mut body).await?;
        assert_eq!(&body, b"data");

        server
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await?;
        transaction.await??.into_body().collect().await?;
        Ok(())
    })
    .await
}

#[test]
fn validates_content_length_and_transfer_framing() -> TestResult {
    let request_target = target()?;
    let body = Bytes::from_static(b"data");

    assert!(matches!(
        validate_request(
            &Method::POST,
            &request_target,
            &[host(), RequestHeader::new("Content-Length", "3")],
            Some(&body),
        ),
        Err(Http1Error::InvalidContentLength { index: 1 })
    ));
    assert!(matches!(
        validate_request(
            &Method::POST,
            &request_target,
            &[
                host(),
                RequestHeader::new("Content-Length", "4"),
                RequestHeader::new("content-length", "4"),
            ],
            Some(&body),
        ),
        Err(Http1Error::DuplicateContentLength { index: 2 })
    ));
    assert!(matches!(
        validate_request(
            &Method::POST,
            &request_target,
            &[host(), RequestHeader::new("Content-Length", "04")],
            Some(&body),
        ),
        Err(Http1Error::InvalidContentLength { index: 1 })
    ));
    assert!(matches!(
        validate_request(
            &Method::POST,
            &request_target,
            &[host(), RequestHeader::new("Transfer-Encoding", "chunked")],
            Some(&body),
        ),
        Err(Http1Error::RequestFramingHeader { .. })
    ));
    assert!(matches!(
        validate_request(&Method::CONNECT, &request_target, &[host()], None),
        Err(Http1Error::ConnectUnsupported)
    ));
    for value in ["host", "Content-Length", "transfer-encoding"] {
        assert!(matches!(
            validate_request(
                &Method::GET,
                &request_target,
                &[host(), RequestHeader::new("Connection", value)],
                None,
            ),
            Err(Http1Error::ConnectionNominatesCriticalField { index: 1 })
        ));
    }
    assert!(matches!(
        validate_request(
            &Method::GET,
            &request_target,
            &[
                host(),
                RequestHeader::new("Connection", b"content-length,\xff"),
            ],
            None,
        ),
        Err(Http1Error::ConnectionNominatesCriticalField { index: 1 })
    ));
    validate_request(
        &Method::POST,
        &request_target,
        &[host(), RequestHeader::new("Content-Length", "0")],
        None,
    )?;
    validate_request_body(
        &Method::POST,
        &request_target,
        &[host(), RequestHeader::new("Content-Length", "0")],
        None,
    )?;
    Ok(())
}

#[test]
fn sensitive_fields_reach_semantic_input() -> TestResult {
    let prepared = crate::http1::request::PreparedRequest::new(
        Method::POST,
        target()?,
        vec![
            host(),
            RequestHeader::new("Cookie", "secret=value").sensitive(),
        ],
        Some(Bytes::from_static(b"body")),
    )?;
    let request = prepared.into_request();
    assert!(request.headers()["cookie"].is_sensitive());
    Ok(())
}

#[tokio::test]
async fn invalid_content_length_never_touches_the_stream() -> TestResult {
    let writes = Arc::new(AtomicUsize::new(0));
    let (client, _server) = duplex(128);
    let result = send_request(
        WriteCountingStream {
            inner: client,
            writes: Arc::clone(&writes),
        },
        Method::POST,
        target()?,
        vec![host(), RequestHeader::new("Content-Length", "3")],
        Some(Bytes::from_static(b"data")),
    )
    .await;

    assert!(matches!(
        result,
        Err(Http1Error::InvalidContentLength { .. })
    ));
    assert_eq!(writes.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn unknown_stream_framing_error_never_polls_body_or_touches_stream() -> TestResult {
    let writes = Arc::new(AtomicUsize::new(0));
    let polls = Arc::new(AtomicUsize::new(0));
    let (client, _server) = duplex(128);
    let body = RequestBody::streaming(PollCountingBody(Arc::clone(&polls)));
    let result = send_request_body(
        WriteCountingStream {
            inner: client,
            writes: Arc::clone(&writes),
        },
        Method::POST,
        target()?,
        vec![host(), RequestHeader::new("Content-Length", "1")],
        Some(body),
    )
    .await;

    assert!(matches!(
        result,
        Err(Http1Error::RequestFramingHeader { .. })
    ));
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(writes.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn invalid_trailer_never_polls_body_or_touches_stream() -> TestResult {
    let writes = Arc::new(AtomicUsize::new(0));
    let polls = Arc::new(AtomicUsize::new(0));
    let (client, _server) = duplex(128);
    let body = RequestBody::streaming(PollCountingBody(Arc::clone(&polls)));
    let result = send_request_body_with_trailers(
        WriteCountingStream {
            inner: client,
            writes: Arc::clone(&writes),
        },
        Method::POST,
        target()?,
        vec![host()],
        Some(body),
        vec![RequestHeader::new("X-Bad", b"ok\r\nInjected: yes")],
    )
    .await;

    assert!(matches!(
        result,
        Err(Http1Error::InvalidTrailerValue { index: 0, .. })
    ));
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(writes.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn mismatched_forward_host_never_touches_the_stream() -> TestResult {
    let writes = Arc::new(AtomicUsize::new(0));
    let (client, _server) = duplex(128);
    let target = AbsoluteForm::parse("http://example.test/resource")?;
    assert!(matches!(
        validate_forward_request(
            &Method::GET,
            &target,
            &[RequestHeader::new("Host", "other.test")],
            None,
        ),
        Err(Http1Error::MismatchedHost { index: 0 })
    ));

    let result = send_forward_request(
        WriteCountingStream {
            inner: client,
            writes: Arc::clone(&writes),
        },
        Method::GET,
        target,
        vec![RequestHeader::new("Host", "other.test")],
        None,
    )
    .await;
    assert!(matches!(
        result,
        Err(Http1Error::MismatchedHost { index: 0 })
    ));
    assert_eq!(writes.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn rejects_ambiguous_response_framing() -> TestResult {
    bounded_peer_test(async {
        let subscriber = OutcomeSubscriber::default();
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
                )
                .await
        });

        let result = send_get(client, target()?, vec![host()])
            .with_subscriber(Dispatch::new(subscriber.clone()))
            .await;
        assert!(matches!(result, Err(Http1Error::AmbiguousResponseFraming)));
        assert_eq!(
            subscriber.outcomes_for("http1.response_head"),
            ["invalid_response"]
        );
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn accepts_interim_response_across_one_byte_reads() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(
                    b"HTTP/1.1 100 Continue\r\nX-Interim: ignored\r\n\r\n\
                      HTTP/1.1 200 OK\r\nX-Final: kept\r\nContent-Length: 5\r\n\r\nhello",
                )
                .await
        });

        let response =
            send_get(OneByteReadStream { inner: client }, target()?, vec![host()]).await?;
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers().get("x-final"), Some(&"kept".parse()?));
        assert!(response.headers().get("x-interim").is_none());
        assert_eq!(response.into_body().collect().await?.to_bytes(), "hello");
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn response_extension_retains_global_order_duplicates_and_casing() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(
                    b"HTTP/1.1 103 Early Hints\r\nX-Ignored: interim\r\n\r\n\
                      HTTP/1.1 200 OK\r\nSet-Cookie: first=1\r\nX-MiXeD: middle\r\nset-cookie: second=2\r\nX-OWS:\t value \t\r\nContent-Length: 0\r\n\r\n",
                )
                .await
        });

        let response =
            send_get(OneByteReadStream { inner: client }, target()?, vec![host()]).await?;
        let ordered = response
            .extensions()
            .get::<OrderedResponseHeaders>()
            .ok_or("response omitted ordered headers")?;
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
                ("X-OWS", b"value".as_slice()),
                ("Content-Length", b"0".as_slice()),
            ]
        );
        assert_eq!(
            ordered.as_slice()[3].value(),
            response.headers()["x-ows"].as_bytes()
        );
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn accepts_multiple_distinct_interim_responses() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(
                    b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n\
                      HTTP/1.1 100 Continue\r\n\r\n\
                      HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                )
                .await
        });

        let response =
            send_get(OneByteReadStream { inner: client }, target()?, vec![host()]).await?;
        assert_eq!(response.status(), 200);
        assert!(response.headers().get("link").is_none());
        assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn protocol_failure_has_specific_response_head_outcome() -> TestResult {
    bounded_peer_test(async {
        let subscriber = OutcomeSubscriber::default();
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server.write_all(b"not an HTTP response\r\n\r\n").await?;
            server.shutdown().await
        });

        let result = send_get(client, target()?, vec![host()])
            .with_subscriber(Dispatch::new(subscriber.clone()))
            .await;
        assert!(matches!(result, Err(Http1Error::Protocol(_))));
        assert_eq!(
            subscriber.outcomes_for("http1.response_head"),
            ["protocol_error"]
        );
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn invalid_request_is_traced_before_stream_io() -> TestResult {
    let subscriber = OutcomeSubscriber::default();
    let writes = Arc::new(AtomicUsize::new(0));
    let (client, _server) = duplex(128);
    let result = send_get(
        WriteCountingStream {
            inner: client,
            writes: Arc::clone(&writes),
        },
        target()?,
        Vec::new(),
    )
    .with_subscriber(Dispatch::new(subscriber.clone()))
    .await;

    assert!(matches!(result, Err(Http1Error::MissingHost)));
    assert_eq!(writes.load(Ordering::SeqCst), 0);
    assert_eq!(subscriber.outcomes_for("http1.request.prepare"), ["error"]);
    assert_eq!(
        subscriber.error_kinds_for("http1.request.prepare"),
        ["missing_host"]
    );
    assert!(subscriber.outcomes_for("http1.response_head").is_empty());
    Ok(())
}

#[tokio::test]
async fn invalid_headers_never_touch_the_stream() -> TestResult {
    bounded_peer_test(async {
        let mut cases = vec![
            vec![],
            vec![host(), host()],
            vec![host(), RequestHeader::new("Transfer-Encoding", "chunked")],
            vec![host(), RequestHeader::new("bad name", "value")],
            vec![host(), RequestHeader::new("X-Bad", b"ok\r\nInjected: yes")],
        ];
        let mut too_many = Vec::with_capacity(MAX_REQUEST_HEADERS + 1);
        too_many.push(host());
        for index in 0..MAX_REQUEST_HEADERS {
            too_many.push(RequestHeader::new(format!("x-{index}"), "value"));
        }
        cases.push(too_many);
        cases.push(vec![
            host(),
            RequestHeader::new("X-Large", vec![b'a'; MAX_REQUEST_HEADER_BYTES]),
        ]);

        for headers in cases {
            let writes = Arc::new(AtomicUsize::new(0));
            let (client, _server) = duplex(128);
            let stream = WriteCountingStream {
                inner: client,
                writes: Arc::clone(&writes),
            };
            let result = send_get(stream, target()?, headers).await;
            assert!(result.is_err());
            assert_eq!(writes.load(Ordering::SeqCst), 0);
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn canceling_request_closes_stream() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let transaction = tokio::spawn(send_get(client, target()?, vec![host()]));
        read_head(&mut server).await?;

        transaction.abort();
        let join_error = match transaction.await {
            Ok(_) => return Err("request task completed after cancellation".into()),
            Err(error) => error,
        };
        assert!(join_error.is_cancelled());
        let mut byte = [0_u8; 1];
        let count = server.read(&mut byte).await?;
        assert_eq!(count, 0);
        Ok(())
    })
    .await
}

struct WriteCountingStream {
    inner: DuplexStream,
    writes: Arc<AtomicUsize>,
}

struct OneByteReadStream {
    inner: DuplexStream,
}

impl AsyncRead for OneByteReadStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let mut byte = [0_u8; 1];
        let mut limited = ReadBuf::new(&mut byte);
        match Pin::new(&mut self.inner).poll_read(context, &mut limited) {
            Poll::Ready(Ok(())) => {
                buffer.put_slice(limited.filled());
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for OneByteReadStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

impl AsyncRead for WriteCountingStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for WriteCountingStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.writes.fetch_add(buffer.len(), Ordering::SeqCst);
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}
