use std::{
    future::poll_fn,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http::{Method, Response};
use http_body::{Body, Frame};
use http_body_util::BodyExt as _;
use phantom_profile::chromium::v152_macos_http2;
use tokio::time::timeout;

use super::{PEER_TEST_TIMEOUT, TestResult, bounded_peer_test};
use crate::{
    http2::{Http2Connection, Http2Error, OriginForm, RequestBody, RequestHeader},
    request::RequestBodyErrorKind,
};

struct FailingBody;

impl Body for FailingBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(Some(Err(io::Error::other("producer failed"))))
    }
}

#[tokio::test]
async fn request_body_error_resets_only_that_stream_and_preserves_connection() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let peer = tokio::spawn(run_peer(server));
        let connection = Http2Connection::connect(client, &v152_macos_http2()).await?;

        let error = match connection
            .send_request_body_with_trailers(
                Method::POST,
                "example.test",
                OriginForm::parse("/failing-upload")?,
                Vec::new(),
                Some(RequestBody::streaming(FailingBody)),
                vec![RequestHeader::new("x-must-not-arrive", "trailer")],
            )
            .await
        {
            Ok(_) => return Err("failing producer completed the request".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            Http2Error::RequestBody(ref error)
                if error.kind() == RequestBodyErrorKind::Source
        ));

        let followup = connection
            .send_get(
                "example.test",
                OriginForm::parse("/after-body-error")?,
                Vec::new(),
            )
            .await?;
        assert_eq!(followup.status(), 204);
        followup.into_body().collect().await?;
        drop(connection);
        peer.await??;
        Ok(())
    })
    .await
}

async fn run_peer(stream: tokio::io::DuplexStream) -> TestResult<()> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, _respond) = connection
        .accept()
        .await
        .ok_or("connection closed before failing upload")??;
    assert_eq!(request.uri().path(), "/failing-upload");
    let mut body = request.into_body();
    let observed = timeout(
        PEER_TEST_TIMEOUT,
        poll_fn(|context| {
            if let Poll::Ready(item) = body.poll_data(context) {
                return Poll::Ready(item);
            }
            match connection.poll_closed(context) {
                Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
                Poll::Ready(Ok(())) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            }
        }),
    )
    .await
    .map_err(|_| "request-body failure did not reset the stream")?
    .ok_or("request-body failure ended without a reset")?;
    let error = match observed {
        Ok(_) => return Err("failed request body unexpectedly emitted DATA".into()),
        Err(error) => error,
    };
    assert!(error.is_reset());
    assert_eq!(error.reason(), Some(::http2::Reason::CANCEL));

    let (followup, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before follow-up")??;
    assert_eq!(followup.uri().path(), "/after-body-error");
    respond.send_response(Response::builder().status(204).body(())?, true)?;
    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok(())
}
