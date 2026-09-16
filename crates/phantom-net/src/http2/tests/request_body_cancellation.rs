use std::{future::poll_fn, task::Poll};

use bytes::Bytes;
use http::{Method, Response};
use http_body_util::BodyExt;
use phantom_profile::chromium::v152_macos_http2;
use tokio::{io::DuplexStream, sync::oneshot, time::timeout};

use super::{PEER_TEST_TIMEOUT, TestResult, bounded_peer_test};
use crate::http2::{Http2Connection, OriginForm};

const BODY_LEN: usize = 70_000;

#[tokio::test]
async fn cancelling_a_stalled_upload_resets_only_that_stream() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let peer = tokio::spawn(run_peer(server, accepted_tx));
        let connection = Http2Connection::connect(client, &v152_macos_http2()).await?;

        let root = connection
            .send_get("example.test", OriginForm::parse("/")?, Vec::new())
            .await?;
        root.into_body().collect().await?;

        let request_connection = connection.clone();
        let upload = tokio::spawn(async move {
            let target = OriginForm::parse("/cancel-upload").map_err(|error| error.to_string())?;
            request_connection
                .send_request(
                    Method::POST,
                    "example.test",
                    target,
                    Vec::new(),
                    Some(Bytes::from(vec![b'R'; BODY_LEN])),
                )
                .await
                .map_err(|error| error.to_string())
        });
        accepted_rx
            .await
            .map_err(|_| "peer stopped before accepting the upload")?;
        upload.abort();
        let cancellation = match upload.await {
            Ok(_) => return Err("stalled upload completed after cancellation".into()),
            Err(cancellation) => cancellation,
        };
        assert!(cancellation.is_cancelled());

        let followup = connection
            .send_get(
                "example.test",
                OriginForm::parse("/after-cancel")?,
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

async fn run_peer(stream: DuplexStream, accepted: oneshot::Sender<()>) -> TestResult<()> {
    let mut builder = ::http2::server::Builder::new();
    builder.initial_window_size(0);
    let mut connection = builder.handshake::<_, Bytes>(stream).await?;

    let (_root, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before the root request")??;
    respond.send_response(Response::builder().status(204).body(())?, true)?;

    let (request, _respond) = connection
        .accept()
        .await
        .ok_or("connection closed before the cancellable upload")??;
    assert_eq!(request.method(), Method::POST);
    let mut body = request.into_body();
    accepted
        .send(())
        .map_err(|_| "client stopped before cancelling the upload")?;
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
    .map_err(|_| "cancelled upload did not reset the stream")?
    .ok_or("cancelled upload ended without a reset")?;
    let error = match observed {
        Ok(_) => return Err("cancelled upload produced DATA instead of a reset".into()),
        Err(error) => error,
    };
    assert!(error.is_reset());
    assert_eq!(error.reason(), Some(::http2::Reason::CANCEL));

    let (followup, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before the post-cancellation request")??;
    assert_eq!(followup.uri().path(), "/after-cancel");
    respond.send_response(Response::builder().status(204).body(())?, true)?;
    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok(())
}
