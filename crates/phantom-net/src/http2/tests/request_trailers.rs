use std::{
    collections::VecDeque,
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http::{HeaderMap, Method, Response};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt as _;
use phantom_profile::chromium::v152_macos_http2;

use super::{TestResult, bounded_peer_test};
use crate::{
    http2::{Http2Connection, Http2Error, OriginForm, RequestBody, RequestHeader},
    request::RequestBodyErrorKind,
};

#[tokio::test]
async fn static_trailers_follow_trailer_only_owned_and_streaming_bodies() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let peer = tokio::spawn(run_static_trailer_peer(server));
        let connection = Http2Connection::connect(client, &v152_macos_http2()).await?;

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
async fn body_produced_trailers_fail_before_static_trailers_and_preserve_connection()
-> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let peer = tokio::spawn(run_body_trailer_peer(server));
        let connection = Http2Connection::connect(client, &v152_macos_http2()).await?;

        let error = connection
            .send_request_body_with_trailers(
                Method::POST,
                "example.test",
                OriginForm::parse("/body-trailers")?,
                Vec::new(),
                Some(RequestBody::streaming(BodyTrailer)),
                vec![RequestHeader::new("x-must-not-arrive", "static")],
            )
            .await
            .expect_err("body-produced trailers were accepted");
        assert!(matches!(
            error,
            Http2Error::RequestBody(ref error)
                if error.kind() == RequestBodyErrorKind::TrailersUnsupported
        ));

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
        while let Some(chunk) = body.data().await {
            data.extend_from_slice(&chunk?);
        }
        assert_eq!(data, expected_data);
        let trailers = body
            .trailers()
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
        assert!(
            trailers
                .get("x-middle")
                .is_some_and(http::HeaderValue::is_sensitive)
        );
        respond.send_response(Response::builder().status(204).body(())?, true)?;
    }
    std::future::poll_fn(|context| connection.poll_closed(context)).await?;
    Ok(())
}

async fn run_body_trailer_peer(stream: tokio::io::DuplexStream) -> TestResult<()> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, _respond) = connection
        .accept()
        .await
        .ok_or("connection closed before body-produced trailers")??;
    let mut body = request.into_body();
    let error = body
        .data()
        .await
        .ok_or("body-produced trailers ended without a reset")?
        .expect_err("body-produced trailers emitted DATA");
    assert!(error.is_reset());
    assert_eq!(error.reason(), Some(::http2::Reason::CANCEL));

    let (followup, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before follow-up")??;
    assert_eq!(followup.uri().path(), "/after-body-trailers");
    respond.send_response(Response::builder().status(204).body(())?, true)?;
    std::future::poll_fn(|context| connection.poll_closed(context)).await?;
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

struct BodyTrailer;

impl Body for BodyTrailer {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut trailers = HeaderMap::new();
        trailers.insert("x-from-body", "unsupported".parse().expect("valid value"));
        Poll::Ready(Some(Ok(Frame::trailers(trailers))))
    }
}
