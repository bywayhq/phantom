use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    time::Duration,
};

use bytes::Bytes;
use http::{Method, Response, StatusCode};
use http_body_util::BodyExt;
use phantom_profile::browser::chrome::v154_http2;
use tokio::time::timeout;

use super::{PEER_TEST_TIMEOUT, TestResult, bounded_peer_test};
use crate::{
    http2::Http2Connection,
    request::{OriginForm, RequestBody},
};

mod peer_ownership;

#[tokio::test]
async fn early_final_response_cancels_upload_and_preserves_connection() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let peer = spawn_early_peer(run_peer(server));
        let result: TestResult<()> = async {
            let connection = Http2Connection::connect(client, &v154_http2()).await?;

            let response = timeout(
                Duration::from_secs(1),
                connection.send_request_body(
                    Method::POST,
                    "example.test",
                    OriginForm::parse("/upload")?,
                    Vec::new(),
                    Some(RequestBody::streaming(http_body_util::Full::new(
                        Bytes::from(vec![b'R'; 70_000]),
                    ))),
                ),
            )
            .await
            .map_err(|_| "early final response was blocked behind the upload")?
            .map_err(|error| format!("initial request failed: {error:?}"))?;
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
            response
                .into_body()
                .collect()
                .await
                .map_err(|error| format!("early response body failed: {error:?}"))?;

            let followup = connection
                .send_get(
                    "example.test",
                    OriginForm::parse("/after-early-response")?,
                    Vec::new(),
                )
                .await
                .map_err(|error| format!("follow-up request failed: {error:?}"))?;
            assert_eq!(followup.status(), StatusCode::NO_CONTENT);
            followup.into_body().collect().await?;
            drop(connection);
            Ok(())
        }
        .await;
        peer.complete(result, PeerOutcome::FinalResponse).await
    })
    .await
}

#[tokio::test]
async fn early_incomplete_response_keeps_uploading_until_the_body_is_sent() -> TestResult<()> {
    const UPLOAD_BYTES: usize = 200_000;
    bounded_peer_test(async {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let mut peer = spawn_early_peer(run_streaming_peer(server, UPLOAD_BYTES));
        let result: TestResult<()> = async {
            let connection = Http2Connection::connect(client, &v154_http2()).await?;

            let response = connection
                .send_request_body(
                    Method::POST,
                    "example.test",
                    OriginForm::parse("/duplex")?,
                    Vec::new(),
                    Some(RequestBody::streaming(http_body_util::Full::new(
                        Bytes::from(vec![b'U'; UPLOAD_BYTES]),
                    ))),
                )
                .await
                .map_err(|error| format!("request failed: {error:?}"))?;
            assert_eq!(response.status(), StatusCode::OK);
            let body = response
                .into_body()
                .collect()
                .await
                .map_err(|error| format!("response body failed: {error:?}"))?
                .to_bytes();

            assert_eq!(body, UPLOAD_BYTES.to_string());

            if let Ok(result) = timeout(Duration::from_millis(100), &mut peer.task).await {
                peer.joined = true;
                let received = result??;
                return Err(format!(
                    "peer completed with {received:?} while the connection was still live"
                )
                .into());
            }

            drop(connection);
            Ok(())
        }
        .await;
        peer.complete(result, PeerOutcome::Uploaded(UPLOAD_BYTES))
            .await
    })
    .await
}

#[derive(Debug, Eq, PartialEq)]
enum PeerOutcome {
    FinalResponse,
    Uploaded(usize),
}

fn spawn_early_peer(
    peer: impl Future<Output = TestResult<PeerOutcome>> + Send + 'static,
) -> EarlyResponsePeer {
    EarlyResponsePeer {
        task: tokio::spawn(peer),
        joined: false,
    }
}

struct EarlyResponsePeer {
    task: tokio::task::JoinHandle<TestResult<PeerOutcome>>,
    joined: bool,
}

#[derive(Debug)]
struct EarlyResponsePeerFailure {
    context: &'static str,
    primary: Box<dyn Error + Send + Sync>,
    cleanup: Option<Box<dyn Error + Send + Sync>>,
}

impl fmt::Display for EarlyResponsePeerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.context, self.primary)?;
        if let Some(cleanup) = &self.cleanup {
            write!(formatter, "; peer cleanup failed: {cleanup}")?;
        }
        Ok(())
    }
}

impl Error for EarlyResponsePeerFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&*self.primary)
    }
}

impl EarlyResponsePeer {
    async fn complete(self, result: TestResult<()>, expected: PeerOutcome) -> TestResult<()> {
        match result {
            Ok(()) => {
                assert_eq!(self.finish().await?, expected);
                Ok(())
            }
            Err(error) => match self.abort_and_join().await {
                Ok(()) => Err(error),
                Err(cleanup) => Err(EarlyResponsePeerFailure {
                    context: "early-response test failed",
                    primary: error,
                    cleanup: Some(cleanup),
                }
                .into()),
            },
        }
    }

    async fn finish(mut self) -> TestResult<PeerOutcome> {
        // The owner keeps the handle during awaits, so dropping the enclosing
        // test or this join future still aborts the peer.
        match timeout(PEER_TEST_TIMEOUT, &mut self.task).await {
            Ok(result) => {
                self.joined = true;
                result?
            }
            Err(error) => {
                let cleanup = self.abort_and_join().await.err();
                Err(EarlyResponsePeerFailure {
                    context: "early-response peer did not finish",
                    primary: error.into(),
                    cleanup,
                }
                .into())
            }
        }
    }

    async fn abort_and_join(mut self) -> TestResult<()> {
        if self.joined {
            return Ok(());
        }
        self.task.abort();
        match timeout(PEER_TEST_TIMEOUT, &mut self.task).await {
            Ok(result) => {
                self.joined = true;
                match result {
                    Err(error) if error.is_cancelled() => Ok(()),
                    result => result?.map(|_| ()),
                }
            }
            Err(error) => Err(EarlyResponsePeerFailure {
                context: "early-response peer did not stop after abort",
                primary: error.into(),
                cleanup: None,
            }
            .into()),
        }
    }
}

impl Drop for EarlyResponsePeer {
    fn drop(&mut self) {
        if !self.joined {
            self.task.abort();
        }
    }
}

/// Answers with headers first, then responds only after the whole request
/// body arrives, like a streaming or full-duplex endpoint.
async fn run_streaming_peer(
    stream: tokio::io::DuplexStream,
    expected: usize,
) -> TestResult<PeerOutcome> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before the upload")??;
    let mut response =
        respond.send_response(Response::builder().status(StatusCode::OK).body(())?, false)?;

    let mut incoming = request.into_body();
    let mut received = 0;
    let body_finished = poll_fn(|context| {
        loop {
            match incoming.poll_data(context) {
                std::task::Poll::Ready(Some(Ok(data))) => {
                    received += data.len();
                    if let Err(error) = incoming.flow_control().release_capacity(data.len()) {
                        return std::task::Poll::Ready(Err(error));
                    }
                }
                std::task::Poll::Ready(Some(Err(error))) => {
                    return std::task::Poll::Ready(Err(error));
                }
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(Ok(())),
                std::task::Poll::Pending => break,
            }
        }
        match connection.poll_closed(context) {
            std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Err(error)),
            std::task::Poll::Ready(Ok(())) | std::task::Poll::Pending => std::task::Poll::Pending,
        }
    });
    timeout(PEER_TEST_TIMEOUT, body_finished)
        .await
        .map_err(|_| "client stopped uploading after the early response head")??;
    assert_eq!(received, expected);

    response.send_data(Bytes::from(received.to_string()), true)?;
    drop(incoming);
    drop(response);
    drop(respond);

    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok(PeerOutcome::Uploaded(received))
}

async fn run_peer(stream: tokio::io::DuplexStream) -> TestResult<PeerOutcome> {
    let mut builder = ::http2::server::Builder::new();
    builder.initial_window_size(0);
    let mut connection = builder.handshake::<_, Bytes>(stream).await?;

    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before the upload")??;
    assert_eq!(request.method(), Method::POST);
    assert_eq!(request.uri().path(), "/upload");
    let mut response = respond.send_response(
        Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .body(())?,
        true,
    )?;
    let reset = timeout(
        PEER_TEST_TIMEOUT,
        poll_fn(|context| {
            if let std::task::Poll::Ready(result) = response.poll_reset(context) {
                return std::task::Poll::Ready(result);
            }
            match connection.poll_closed(context) {
                std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Err(error)),
                std::task::Poll::Ready(Ok(())) | std::task::Poll::Pending => {
                    std::task::Poll::Pending
                }
            }
        }),
    )
    .await
    .map_err(|_| "early final response did not cancel the upload")??;
    assert_eq!(reset, ::http2::Reason::CANCEL);
    drop(request);
    drop(response);
    drop(respond);

    let (followup, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before the follow-up request")??;
    assert_eq!(followup.uri().path(), "/after-early-response");
    respond.send_response(
        Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(())?,
        true,
    )?;
    drop(followup);
    drop(respond);
    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok(PeerOutcome::FinalResponse)
}
