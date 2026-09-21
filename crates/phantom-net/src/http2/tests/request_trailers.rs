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
use phantom_profile::chromium::v152_http2;

use super::{TestResult, bounded_peer_test};
use crate::{
    http2::{
        Http2Connection, Http2Error, OriginForm, RequestBody, RequestHeader,
        validate_request_body_with_trailers,
    },
    request::{RequestBodyErrorKind, RequestTrailerName},
};

#[tokio::test]
async fn static_trailers_follow_trailer_only_owned_and_streaming_bodies() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let peer = tokio::spawn(run_static_trailer_peer(server));
        let connection = Http2Connection::connect(client, &v152_http2()).await?;

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
async fn body_produced_trailers_follow_the_declared_order_and_sensitivity() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let peer = tokio::spawn(run_dynamic_trailer_peer(server));
        let connection = Http2Connection::connect(client, &v152_http2()).await?;
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
async fn body_produced_trailer_failures_are_request_local() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let peer = tokio::spawn(run_body_trailer_peer(server));
        let connection = Http2Connection::connect(client, &v152_http2()).await?;

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
        let connection = Http2Connection::connect(client, &v152_http2()).await?;

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
