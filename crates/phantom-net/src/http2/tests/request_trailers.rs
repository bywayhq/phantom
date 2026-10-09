use std::{
    collections::VecDeque,
    convert::Infallible,
    future::poll_fn,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Response};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt as _;
use phantom_profile::{Http2HuffmanCoding, browser::chrome::v154_http2};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::{TestResult, bounded_peer_test};
use crate::{
    http2::{Http2Connection, Http2Error, validate_request_body_with_trailers},
    request::{OriginForm, RequestBody, RequestBodyErrorKind, RequestHeader, RequestTrailerName},
};

#[tokio::test]
async fn static_trailers_follow_trailer_only_owned_and_streaming_bodies() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let peer = tokio::spawn(run_static_trailer_peer(server));
        let connection = Http2Connection::connect(client, &v154_http2()).await?;

        let trailer_only = connection
            .send_request_body_with_trailers(
                Method::POST,
                "example.test",
                OriginForm::parse("/trailer-only")?,
                Vec::new(),
                None,
                ordered_trailers(),
            )
            .await?;
        trailer_only.into_body().collect().await?;

        let owned = connection
            .send_request_with_trailers(
                Method::POST,
                "example.test",
                OriginForm::parse("/owned")?,
                Vec::new(),
                Some(Bytes::from_static(b"payload")),
                ordered_trailers(),
            )
            .await?;
        owned.into_body().collect().await?;

        let streaming = connection
            .send_request_body_with_trailers(
                Method::POST,
                "example.test",
                OriginForm::parse("/streaming")?,
                Vec::new(),
                Some(RequestBody::streaming(ChunkBody::new([
                    Bytes::from_static(b"alpha"),
                    Bytes::from_static(b"beta"),
                ]))),
                ordered_trailers(),
            )
            .await?;
        streaming.into_body().collect().await?;

        drop(connection);
        peer.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn body_produced_trailers_preserve_values_and_per_name_duplicates() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let peer = tokio::spawn(run_dynamic_trailer_peer(server));
        let connection = Http2Connection::connect(client, &v154_http2()).await?;
        let response = connection
            .send_request_body(
                Method::POST,
                "example.test",
                OriginForm::parse("/dynamic-trailers")?,
                Vec::new(),
                Some(dynamic_trailer_body(false)),
            )
            .await?;
        response.into_body().collect().await?;

        drop(connection);
        peer.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn static_trailers_preserve_cross_name_order_and_never_indexed_wire_marker() -> TestResult<()>
{
    bounded_peer_test(check_trailer_wire(false)).await
}

#[tokio::test]
async fn body_produced_trailers_preserve_cross_name_order_and_never_indexed_wire_marker()
-> TestResult<()> {
    bounded_peer_test(check_trailer_wire(true)).await
}

async fn check_trailer_wire(body_produced: bool) -> TestResult<()> {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let peer = tokio::spawn(run_trailer_wire_peer(server));
    let mut settings = v154_http2();
    // One-byte strings are Huffman ties, so this profile sends them raw.
    settings.hpack.huffman_coding = Http2HuffmanCoding::WhenShorter;
    let connection = Http2Connection::connect(client, &settings).await?;
    let body = if body_produced {
        let mut trailers = HeaderMap::new();
        let mut sensitive = HeaderValue::from_static("2");
        sensitive.set_sensitive(true);
        trailers.append("a", HeaderValue::from_static("1"));
        trailers.insert("b", sensitive);
        trailers.append("a", HeaderValue::from_static("3"));
        RequestBody::streaming_with_trailers(
            ChunkAndTrailerBody::new(Bytes::from_static(b"data"), trailers),
            vec![
                RequestTrailerName::new("a"),
                RequestTrailerName::new("b"),
                RequestTrailerName::new("a"),
            ],
        )
    } else {
        RequestBody::streaming(ChunkBody::new([Bytes::from_static(b"data")]))
    };
    let trailers = if body_produced {
        Vec::new()
    } else {
        vec![
            RequestHeader::new("a", "1"),
            RequestHeader::new("b", "2").sensitive(),
            RequestHeader::new("a", "3"),
        ]
    };
    let response = connection
        .send_request_body_with_trailers(
            Method::POST,
            "example.test",
            OriginForm::parse("/")?,
            Vec::new(),
            Some(body),
            trailers,
        )
        .await?;
    assert_eq!(response.status(), http::StatusCode::NO_CONTENT);
    response.into_body().collect().await?;
    drop(connection);
    peer.await??;
    Ok(())
}

async fn run_trailer_wire_peer(mut stream: DuplexStream) -> TestResult<()> {
    let mut preface = [0; 24];
    stream.read_exact(&mut preface).await?;
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    stream.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await?;
    let mut initial_headers = false;
    let mut data = Vec::new();
    loop {
        let mut header = [0; 9];
        stream.read_exact(&mut header).await?;
        let length =
            (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
        assert!(length <= 16_384, "unexpected oversized test frame");
        let mut payload = vec![0; length];
        stream.read_exact(&mut payload).await?;
        let stream_id = u32::from_be_bytes(header[5..9].try_into()?) & 0x7fff_ffff;
        if header[3] == 1 {
            assert_eq!(stream_id, 1);
            assert_ne!(header[4] & 4, 0, "small HEADERS must be complete");
            if !initial_headers {
                assert_eq!(header[4] & 1, 0, "initial HEADERS ended the upload");
                initial_headers = true;
                continue;
            }
            assert_eq!(header[4], 5, "trailer HEADERS must end the stream");
            assert_eq!(data, b"data");
            // RFC 7541 sections 6.2.1/6.2.3: insert a:1, never-index b:2,
            // then insert a:3 using the newest dynamic name (index 62).
            // The peer decoder loses the never-indexed marker, so compare bytes.
            assert_eq!(
                payload,
                [
                    0x40, 1, b'a', 1, b'1', 0x10, 1, b'b', 1, b'2', 0x7e, 1, b'3'
                ]
            );
            break;
        }
        if header[3] == 0 {
            assert!(initial_headers);
            assert_eq!(stream_id, 1);
            assert_eq!(header[4], 0, "DATA must leave the stream open for trailers");
            data.extend_from_slice(&payload);
        }
        assert_ne!(header[3], 3, "upload reset before its trailer HEADERS");
    }
    // END_STREAM response HEADERS with the static :status 204 index.
    stream.write_all(&[0, 0, 1, 1, 5, 0, 0, 0, 1, 0x89]).await?;
    stream.read_to_end(&mut Vec::new()).await?;
    Ok(())
}

#[tokio::test]
async fn body_produced_trailer_failures_are_request_local() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let peer = tokio::spawn(run_body_trailer_peer(server));
        let connection = Http2Connection::connect(client, &v154_http2()).await?;

        for (path, body, expected_kind) in [
            (
                "/undeclared-trailers",
                RequestBody::streaming(BodyTrailer::new(body_trailers())),
                RequestBodyErrorKind::TrailersUnsupported,
            ),
            (
                "/mismatched-trailers",
                dynamic_trailer_body(true),
                RequestBodyErrorKind::TrailersMismatch,
            ),
        ] {
            let Err(error) = connection
                .send_request_body(
                    Method::POST,
                    "example.test",
                    OriginForm::parse(path)?,
                    Vec::new(),
                    Some(body),
                )
                .await
            else {
                return Err("invalid body-produced trailers were accepted".into());
            };
            assert!(matches!(
                error,
                Http2Error::RequestBody(ref error) if error.kind() == expected_kind
            ));
        }

        let followup = connection
            .send_get(
                "example.test",
                OriginForm::parse("/after-body-trailers")?,
                Vec::new(),
            )
            .await?;
        followup.into_body().collect().await?;
        drop(connection);
        peer.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn invalid_dynamic_trailer_plans_fail_before_opening_a_stream() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let peer = tokio::spawn(run_prevalidation_peer(server));
        let connection = Http2Connection::connect(client, &v154_http2()).await?;

        let metadata_only = dynamic_trailer_body(false);
        assert!(matches!(
            validate_request_body_with_trailers(
                &Method::POST,
                "example.test",
                &OriginForm::parse("/metadata-only")?,
                &[],
                Some(metadata_only.metadata()),
                &[],
            ),
            Err(Http2Error::BodyTrailerPlanRequired)
        ));

        let invalid_name = RequestBody::streaming_with_trailers(
            BodyTrailer::new(body_trailers()),
            vec![RequestTrailerName::new("X-Upper")],
        );
        assert!(matches!(
            connection
                .send_request_body(
                    Method::POST,
                    "example.test",
                    OriginForm::parse("/invalid-name")?,
                    Vec::new(),
                    Some(invalid_name),
                )
                .await,
            Err(Http2Error::InvalidTrailerName { index: 0 })
        ));

        assert!(matches!(
            connection
                .send_request_body_with_trailers(
                    Method::POST,
                    "example.test",
                    OriginForm::parse("/conflicting-trailers")?,
                    Vec::new(),
                    Some(dynamic_trailer_body(false)),
                    vec![RequestHeader::new("x-static", "value")],
                )
                .await,
            Err(Http2Error::ConflictingRequestTrailers)
        ));

        let followup = connection
            .send_get(
                "example.test",
                OriginForm::parse("/after-prevalidation")?,
                Vec::new(),
            )
            .await?;
        followup.into_body().collect().await?;
        drop(connection);
        peer.await??;
        Ok(())
    })
    .await
}

fn ordered_trailers() -> Vec<RequestHeader> {
    vec![
        RequestHeader::new("x-repeat", "first"),
        RequestHeader::new("x-middle", "between").sensitive(),
        RequestHeader::new("x-repeat", "second"),
    ]
}

async fn run_static_trailer_peer(stream: tokio::io::DuplexStream) -> TestResult<()> {
    let mut connection = ::http2::server::handshake(stream).await?;
    for (path, expected_data, expected_length) in [
        ("/trailer-only", b"".as_slice(), None),
        ("/owned", b"payload".as_slice(), Some("7")),
        ("/streaming", b"alphabeta".as_slice(), None),
    ] {
        let (request, mut respond) = connection
            .accept()
            .await
            .ok_or("connection closed before request trailers")??;
        assert_eq!(request.uri().path(), path);
        assert_eq!(
            request
                .headers()
                .get("content-length")
                .and_then(|value| value.to_str().ok()),
            expected_length
        );
        let mut body = request.into_body();
        let mut data = Vec::new();
        while let Some(chunk) = poll_fn(|context| {
            if let Poll::Ready(item) = body.poll_data(context) {
                return Poll::Ready(Ok(item));
            }
            match connection.poll_closed(context) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(None)),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?
        {
            data.extend_from_slice(&chunk?);
        }
        assert_eq!(data, expected_data);
        let trailers = poll_fn(|context| {
            if let Poll::Ready(result) = body.poll_trailers(context) {
                return Poll::Ready(result);
            }
            match connection.poll_closed(context) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(None)),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?
        .ok_or("request ended without static trailers")?;
        assert_eq!(
            trailers
                .get_all("x-repeat")
                .iter()
                .map(|value| value.as_bytes())
                .collect::<Vec<_>>(),
            [b"first".as_slice(), b"second".as_slice()]
        );
        assert_eq!(
            trailers
                .get("x-middle")
                .and_then(|value| value.to_str().ok()),
            Some("between")
        );
        respond.send_response(Response::builder().status(204).body(())?, true)?;
    }
    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok(())
}

async fn run_body_trailer_peer(stream: tokio::io::DuplexStream) -> TestResult<()> {
    let mut connection = ::http2::server::handshake(stream).await?;
    for path in ["/undeclared-trailers", "/mismatched-trailers"] {
        let (request, _respond) = connection
            .accept()
            .await
            .ok_or("connection closed before body-produced trailers")??;
        assert_eq!(request.uri().path(), path);
        let mut body = request.into_body();
        loop {
            let item = poll_fn(|context| {
                if let Poll::Ready(item) = body.poll_data(context) {
                    return Poll::Ready(Ok(item));
                }
                match connection.poll_closed(context) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(None)),
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await?;
            match item {
                Some(Ok(_)) => {}
                Some(Err(error)) => {
                    assert!(error.is_reset());
                    assert_eq!(error.reason(), Some(::http2::Reason::CANCEL));
                    break;
                }
                None => return Err("invalid body-produced trailers completed normally".into()),
            }
        }
    }

    let (followup, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before follow-up")??;
    assert_eq!(followup.uri().path(), "/after-body-trailers");
    respond.send_response(Response::builder().status(204).body(())?, true)?;
    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok(())
}

async fn run_dynamic_trailer_peer(stream: tokio::io::DuplexStream) -> TestResult<()> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before dynamic trailers")??;
    assert_eq!(request.uri().path(), "/dynamic-trailers");
    let mut body = request.into_body();
    let data = poll_fn(|context| {
        if let Poll::Ready(item) = body.poll_data(context) {
            return Poll::Ready(Ok(item));
        }
        match connection.poll_closed(context) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(None)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await?
    .transpose()?;
    assert_eq!(data, Some(Bytes::from_static(b"data")));
    assert!(
        poll_fn(|context| {
            if let Poll::Ready(item) = body.poll_data(context) {
                return Poll::Ready(Ok(item));
            }
            match connection.poll_closed(context) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(None)),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?
        .is_none()
    );
    let trailers = poll_fn(|context| {
        if let Poll::Ready(result) = body.poll_trailers(context) {
            return Poll::Ready(result);
        }
        match connection.poll_closed(context) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(None)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await?
    .ok_or("request ended without dynamic trailers")?;
    assert_eq!(
        trailers
            .get_all("x-repeat")
            .iter()
            .map(HeaderValue::as_bytes)
            .collect::<Vec<_>>(),
        [b"first".as_slice(), b"second".as_slice()]
    );
    assert_eq!(
        trailers
            .get("x-middle")
            .and_then(|value| value.to_str().ok()),
        Some("between")
    );
    respond.send_response(Response::builder().status(204).body(())?, true)?;
    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok(())
}

async fn run_prevalidation_peer(stream: tokio::io::DuplexStream) -> TestResult<()> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before valid follow-up")??;
    assert_eq!(request.uri().path(), "/after-prevalidation");
    respond.send_response(Response::builder().status(204).body(())?, true)?;
    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok(())
}

struct ChunkBody {
    chunks: VecDeque<Bytes>,
}

impl ChunkBody {
    fn new(chunks: impl IntoIterator<Item = Bytes>) -> Self {
        Self {
            chunks: chunks.into_iter().collect(),
        }
    }
}

impl Body for ChunkBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.chunks.pop_front().map(|chunk| Ok(Frame::data(chunk))))
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

struct BodyTrailer(Option<HeaderMap>);

impl BodyTrailer {
    fn new(trailers: HeaderMap) -> Self {
        Self(Some(trailers))
    }
}

impl Body for BodyTrailer {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.0.take().map(|trailers| Ok(Frame::trailers(trailers))))
    }
}

fn body_trailers() -> HeaderMap {
    let mut trailers = HeaderMap::new();
    let mut middle = HeaderValue::from_static("between");
    middle.set_sensitive(true);
    trailers.append("x-repeat", HeaderValue::from_static("first"));
    trailers.insert("x-middle", middle);
    trailers.append("x-repeat", HeaderValue::from_static("second"));
    trailers
}

fn dynamic_trailer_body(mismatch: bool) -> RequestBody {
    let mut trailers = body_trailers();
    if mismatch {
        trailers.remove("x-middle");
        trailers.insert("x-other", HeaderValue::from_static("between"));
    }
    RequestBody::streaming_with_trailers(
        ChunkAndTrailerBody::new(Bytes::from_static(b"data"), trailers),
        vec![
            RequestTrailerName::new("x-repeat"),
            RequestTrailerName::new("x-middle"),
            RequestTrailerName::new("x-repeat"),
        ],
    )
}

struct ChunkAndTrailerBody {
    data: Option<Bytes>,
    trailers: Option<HeaderMap>,
}

impl ChunkAndTrailerBody {
    fn new(data: Bytes, trailers: HeaderMap) -> Self {
        Self {
            data: Some(data),
            trailers: Some(trailers),
        }
    }
}

impl Body for ChunkAndTrailerBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(
            self.data
                .take()
                .map(Frame::data)
                .or_else(|| self.trailers.take().map(Frame::trailers))
                .map(Ok),
        )
    }
}
