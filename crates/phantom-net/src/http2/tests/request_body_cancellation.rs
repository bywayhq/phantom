use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    task::Poll,
};

use bytes::Bytes;
use http::{Method, Response};
use http_body_util::BodyExt;
use phantom_profile::browser::chrome::v154_http2;
use tokio::{io::DuplexStream, sync::oneshot, time::timeout};

use super::{
    PEER_TEST_TIMEOUT, PeerDeadline, TestResult, bounded_peer_test, driver_shutdown::ShutdownPeer,
};
use crate::{
    http2::{Http2Body, Http2Connection},
    request::{OriginForm, RequestBody},
};

const BODY_LEN: usize = 70_000;

mod completion_controls;
mod teardown_characterization;

#[tokio::test]
async fn cancelling_a_stalled_upload_resets_only_that_stream() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let peer = ShutdownPeer::spawn(run_peer(server, accepted_tx));
        let connection = match Http2Connection::connect(client, &v154_http2()).await {
            Ok(connection) => connection,
            Err(error) => return complete_upload(Err(error.into()), peer.stop().await),
        };

        let upload = match start_stalled_upload(&connection).await {
            Ok((_, upload)) => upload,
            Err(error) => {
                drop(connection);
                return complete_upload(Err(error), peer.stop().await);
            }
        };
        finish_cancelled_upload(connection, peer, upload, accepted_rx).await
    })
    .await
}

type UploadTask = ShutdownPeer<Response<Http2Body>>;

async fn start_stalled_upload(
    connection: &Http2Connection,
) -> TestResult<(http::StatusCode, UploadTask)> {
    let root = connection
        .send_get("example.test", OriginForm::parse("/")?, Vec::new())
        .await?;
    let status = root.status();
    root.into_body().collect().await?;

    let request_connection = connection.clone();
    let upload = ShutdownPeer::spawn(async move {
        let target = OriginForm::parse("/cancel-upload")?;
        let response = request_connection
            .send_request_body(
                Method::POST,
                "example.test",
                target,
                Vec::new(),
                Some(RequestBody::streaming(http_body_util::Full::new(
                    Bytes::from(vec![b'R'; BODY_LEN]),
                ))),
            )
            .await?;
        Ok(response)
    });

    Ok((status, upload))
}

fn finish_cancelled_upload(
    connection: Http2Connection,
    peer: impl Into<ShutdownPeer<()>>,
    mut upload: UploadTask,
    accepted_rx: oneshot::Receiver<()>,
) -> impl Future<Output = TestResult<()>> {
    let mut peer = peer.into();

    async move {
        let accepted = accepted_rx
            .await
            .map_err(|cause| UploadAcceptanceFailure { cause });
        if let Err(error) = accepted {
            let upload_cleanup = upload.stop().await;
            drop(connection);
            let peer_cleanup = peer.stop().await;
            return complete_upload(
                Err(error.into()),
                complete_upload(upload_cleanup, peer_cleanup),
            );
        }

        upload.abort_handle().abort();
        let cancellation = timeout(PEER_TEST_TIMEOUT, &mut upload).await;
        let primary = match cancellation {
            Ok(Err(error)) if error.is_cancelled() => Ok(()),
            Ok(Err(error)) => Err(error.into()),
            Ok(Ok(Err(error))) => Err(error),
            Ok(Ok(Ok(_))) => Err("stalled upload completed after cancellation".into()),
            Err(cause) => complete_upload(
                Err(PeerDeadline {
                    context: "cancelled upload task did not finish",
                    cause,
                }
                .into()),
                upload.stop().await,
            ),
        };

        let primary = match primary {
            Err(error) => Err(error),
            Ok(()) => {
                async {
                    let followup = connection
                        .send_get(
                            "example.test",
                            OriginForm::parse("/after-cancel")?,
                            Vec::new(),
                        )
                        .await?;
                    assert_eq!(followup.status(), 204);
                    followup.into_body().collect().await?;
                    Ok(())
                }
                .await
            }
        };
        drop(connection);

        let cleanup = if primary.is_err() {
            peer.stop().await
        } else {
            match timeout(PEER_TEST_TIMEOUT, &mut peer).await {
                Ok(Ok(result)) => result,
                Ok(Err(error)) => Err(error.into()),
                Err(cause) => complete_upload(
                    Err(PeerDeadline {
                        context: "upload peer did not finish",
                        cause,
                    }
                    .into()),
                    peer.stop().await,
                ),
            }
        };
        complete_upload(primary, cleanup)
    }
}

async fn run_peer(stream: DuplexStream, accepted: oneshot::Sender<()>) -> TestResult<()> {
    let mut builder = ::http2::server::Builder::new();
    builder.initial_window_size(0);
    let mut connection = builder.handshake::<_, Bytes>(stream).await?;
    let mut upload = accept_stalled_upload(&mut connection, accepted).await?;
    observe_upload_reset(&mut connection, &mut upload.body).await?;

    let (followup, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before the post-cancellation request")??;
    assert_eq!(followup.uri().path(), "/after-cancel");
    respond.send_response(Response::builder().status(204).body(())?, true)?;
    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok(())
}

struct AcceptedUpload {
    body: ::http2::RecvStream,
    _upload_response: ::http2::server::SendResponse<Bytes>,
    _root_response: ::http2::server::SendResponse<Bytes>,
    _root: http::Request<::http2::RecvStream>,
}

async fn accept_stalled_upload(
    connection: &mut ::http2::server::Connection<DuplexStream, Bytes>,
    accepted: oneshot::Sender<()>,
) -> TestResult<AcceptedUpload> {
    let (root, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before the root request")??;
    respond.send_response(Response::builder().status(204).body(())?, true)?;

    let (request, upload_response) = connection
        .accept()
        .await
        .ok_or("connection closed before the cancellable upload")??;
    assert_eq!(request.method(), Method::POST);
    let body = request.into_body();
    accepted
        .send(())
        .map_err(|_| "client stopped before cancelling the upload")?;

    Ok(AcceptedUpload {
        body,
        _upload_response: upload_response,
        _root_response: respond,
        _root: root,
    })
}

async fn observe_upload_reset(
    connection: &mut ::http2::server::Connection<DuplexStream, Bytes>,
    body: &mut ::http2::RecvStream,
) -> TestResult<()> {
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
    .map_err(|cause| PeerDeadline {
        context: "cancelled upload did not reset the stream",
        cause,
    })?
    .ok_or("cancelled upload ended without a reset")?;
    let error = match observed {
        Ok(_) => return Err("cancelled upload produced DATA instead of a reset".into()),
        Err(error) => error,
    };
    assert!(error.is_reset());
    assert_eq!(error.reason(), Some(::http2::Reason::CANCEL));

    Ok(())
}

fn complete_upload(primary: TestResult<()>, cleanup: TestResult<()>) -> TestResult<()> {
    match (primary, cleanup) {
        (Ok(()), result) | (result, Ok(())) => result,
        (Err(primary), Err(cleanup)) => Err(UploadCleanupFailure { primary, cleanup }.into()),
    }
}

#[derive(Debug)]
struct UploadAcceptanceFailure {
    cause: oneshot::error::RecvError,
}

impl fmt::Display for UploadAcceptanceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "peer stopped before accepting the upload: {}",
            self.cause
        )
    }
}

impl Error for UploadAcceptanceFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.cause)
    }
}

#[derive(Debug)]
struct UploadCleanupFailure {
    primary: Box<dyn Error + Send + Sync>,
    cleanup: Box<dyn Error + Send + Sync>,
}

impl fmt::Display for UploadCleanupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; upload peer cleanup also failed: {}",
            self.primary, self.cleanup
        )
    }
}

impl Error for UploadCleanupFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.primary.as_ref())
    }
}
