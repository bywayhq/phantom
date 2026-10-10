use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    task::Poll,
    time::Duration,
};

use bytes::Bytes;
use http::{Method, Response, StatusCode};
use phantom_profile::browser::chrome::v154_http2;
use tokio::{
    io::{DuplexStream, duplex},
    sync::oneshot,
    task::AbortHandle,
    time::timeout,
};

use super::{
    accept_stalled_upload, finish_cancelled_upload, observe_upload_reset, run_peer,
    start_stalled_upload,
};
use crate::http2::tests::TestResult;
use crate::http2::tests::driver_shutdown::ShutdownPeer;
use crate::http2::{Http2Connection, Http2Error};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
const QUIET_WINDOW: Duration = Duration::from_millis(100);

#[tokio::test]
async fn accepted_channel_failure_keeps_recv_error_and_completed_peer_failure() -> TestResult<()> {
    let (client, server) = duplex(64 * 1024);
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let (post_tx, post_rx) = oneshot::channel();
    let peer = tokio::spawn(fail_before_accepted(server, accepted_tx, post_tx));
    let mut cleanup = UploadCleanup::new(peer.abort_handle());

    let observed: TestResult<Box<dyn Error + Send + Sync>> = async {
        let connection = Http2Connection::connect(client, &v154_http2()).await?;
        let (status, upload) = start_stalled_upload(&connection).await?;
        cleanup.upload = Some(upload.abort_handle());
        assert_eq!(status, StatusCode::NO_CONTENT);
        timeout(CONTROL_TIMEOUT, post_rx).await??;
        timeout(CONTROL_TIMEOUT, until_finished(&cleanup.peer)).await?;
        timeout(
            CONTROL_TIMEOUT,
            until_finished(
                cleanup
                    .upload
                    .as_ref()
                    .ok_or("upload abort handle missing")?,
            ),
        )
        .await?;

        let result = finish_cancelled_upload(connection.clone(), peer, upload, accepted_rx).await;
        drop(connection);
        result
            .err()
            .ok_or_else(|| "failed peer was accepted as a completed exchange".into())
    }
    .await;
    let error = complete_control(observed, cleanup.stop().await)?;

    assert!(has_cause::<oneshot::error::RecvError>(&*error));
    assert!(error.to_string().contains("peer marker 913"));
    Ok(())
}

#[tokio::test]
async fn a_reset_upload_keeps_the_original_http2_error() -> TestResult<()> {
    let (client, server) = duplex(64 * 1024);
    let (post_tx, post_rx) = oneshot::channel();
    let peer = ShutdownPeer::spawn(reset_upload(server, post_tx));
    let connection = Http2Connection::connect(client, &v154_http2()).await?;
    let (status, upload) = start_stalled_upload(&connection).await?;
    let upload_abort = UploadAbort(upload.abort_handle());
    assert_eq!(status, StatusCode::NO_CONTENT);

    let observed: TestResult<Box<dyn Error + Send + Sync>> = async {
        timeout(CONTROL_TIMEOUT, post_rx).await??;
        match timeout(CONTROL_TIMEOUT, upload).await?? {
            Ok(_) => Err("reset upload returned a response".into()),
            Err(error) => Ok(error.into()),
        }
    }
    .await;
    upload_abort.0.abort();
    timeout(CONTROL_TIMEOUT, until_finished(&upload_abort.0)).await?;
    drop(connection);
    let error = complete_control(observed, peer.stop().await)?;

    assert!(has_cause::<Http2Error>(&*error));
    let h2 = h2_cause(&*error).ok_or("original reset cause was lost")?;
    assert!(h2.is_remote());
    assert!(h2.is_reset());
    assert_eq!(h2.reason(), Some(::http2::Reason::INTERNAL_ERROR));
    Ok(())
}

#[tokio::test]
async fn an_unreset_upload_keeps_the_actual_elapsed_cause() -> TestResult<()> {
    let (client, server) = duplex(64 * 1024);
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let (deadline_tx, deadline_rx) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let peer = ShutdownPeer::spawn(hold_unreset_upload(
        server,
        accepted_tx,
        deadline_tx,
        released,
    ));
    let mut cleanup = UploadCleanup::new(peer.abort_handle());

    let observed: TestResult<Box<dyn Error + Send + Sync>> = async {
        let connection = Http2Connection::connect(client, &v154_http2()).await?;
        let (status, upload) = start_stalled_upload(&connection).await?;
        cleanup.upload = Some(upload.abort_handle());
        assert_eq!(status, StatusCode::NO_CONTENT);
        timeout(CONTROL_TIMEOUT, accepted_rx).await??;
        assert!(!upload.is_finished());

        let result = timeout(CONTROL_TIMEOUT, deadline_rx).await??;

        cleanup
            .upload
            .as_ref()
            .ok_or("upload abort handle missing")?
            .abort();
        let upload_cleanup = match timeout(CONTROL_TIMEOUT, upload).await? {
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error.into()),
            Ok(Err(error)) => Err(error.into()),
            Ok(Ok(_)) => Err("zero-window upload completed without cancellation".into()),
        };
        let release_result = release
            .send(())
            .map_err(|_| "unreset peer cleanup gate stopped".into());
        let peer_cleanup = match timeout(CONTROL_TIMEOUT, peer).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(error.into()),
            Err(error) => Err(error.into()),
        };
        drop(connection);
        let cleanup_result = complete_control(
            upload_cleanup,
            complete_control(release_result, peer_cleanup),
        );
        complete_control(result, cleanup_result)
            .err()
            .ok_or_else(|| "unreset upload completed without its deadline".into())
    }
    .await;
    let error = complete_control(observed, cleanup.stop().await)?;

    assert!(has_cause::<tokio::time::error::Elapsed>(&*error));
    Ok(())
}

#[tokio::test]
async fn dropping_the_upload_observation_stops_both_driven_tasks() -> TestResult<()> {
    let (client, server) = duplex(64 * 1024);
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let peer = tokio::spawn(run_peer(server, accepted_tx));
    let mut cleanup = UploadCleanup::new(peer.abort_handle());

    let observed: TestResult<bool> = async {
        let connection = Http2Connection::connect(client, &v154_http2()).await?;
        let (status, upload) = start_stalled_upload(&connection).await?;
        cleanup.upload = Some(upload.abort_handle());
        assert_eq!(status, StatusCode::NO_CONTENT);
        timeout(CONTROL_TIMEOUT, accepted_rx).await??;
        assert!(!upload.is_finished());

        // Keep accepted publication closed while the actual tail owns its tasks.
        let (publish, held_accept) = oneshot::channel();
        let mut observation = Box::pin(finish_cancelled_upload(
            connection.clone(),
            peer,
            upload,
            held_accept,
        ));
        poll_fn(|context| match observation.as_mut().poll(context) {
            Poll::Pending => Poll::Ready(Ok(())),
            Poll::Ready(result) => Poll::Ready(match result {
                Err(error) => Err(error),
                Ok(()) => Err("held publication did not keep the observation pending".into()),
            }),
        })
        .await?;
        drop(observation);

        let stopped = timeout(QUIET_WINDOW, cleanup.wait()).await.is_ok();
        cleanup.abort();
        timeout(CONTROL_TIMEOUT, cleanup.wait()).await?;
        drop(publish);
        drop(connection);
        Ok(stopped)
    }
    .await;
    let stopped = complete_control(observed, cleanup.stop().await)?;

    assert!(
        stopped,
        "driven peer or upload outlived its observation boundary"
    );
    Ok(())
}

async fn fail_before_accepted(
    stream: DuplexStream,
    accepted: oneshot::Sender<()>,
    observed_post: oneshot::Sender<()>,
) -> TestResult<()> {
    let mut builder = ::http2::server::Builder::new();
    builder.initial_window_size(0);
    let mut connection = builder.handshake::<_, Bytes>(stream).await?;
    let (root, mut respond) = connection.accept().await.ok_or("root request absent")??;
    assert_eq!(root.uri().path(), "/");
    respond.send_response(Response::builder().status(204).body(())?, true)?;

    let (post, upload_response) = connection.accept().await.ok_or("upload request absent")??;
    assert_eq!(post.method(), Method::POST);
    assert_eq!(post.uri().path(), "/cancel-upload");
    observed_post
        .send(())
        .map_err(|_| "POST observer stopped")?;

    drop(root);
    drop(respond);
    drop(post);
    drop(upload_response);
    connection.abrupt_shutdown(::http2::Reason::NO_ERROR);
    timeout(
        CONTROL_TIMEOUT,
        poll_fn(|context| connection.poll_closed(context)),
    )
    .await??;

    drop(accepted);
    Err(CompletedPeerFault {
        cause: ::http2::Error::from(::http2::Reason::INTERNAL_ERROR),
    }
    .into())
}

async fn reset_upload(stream: DuplexStream, observed_post: oneshot::Sender<()>) -> TestResult<()> {
    let mut builder = ::http2::server::Builder::new();
    builder.initial_window_size(0);
    let mut connection = builder.handshake::<_, Bytes>(stream).await?;
    let (root, mut respond) = connection.accept().await.ok_or("root request absent")??;
    assert_eq!(root.uri().path(), "/");
    respond.send_response(Response::builder().status(204).body(())?, true)?;

    let (post, mut respond) = connection.accept().await.ok_or("upload request absent")??;
    assert_eq!(post.method(), Method::POST);
    assert_eq!(post.uri().path(), "/cancel-upload");
    respond.send_reset(::http2::Reason::INTERNAL_ERROR);
    observed_post
        .send(())
        .map_err(|_| "POST observer stopped")?;
    drop(root);
    drop(post);
    drop(respond);
    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok(())
}

async fn hold_unreset_upload(
    stream: DuplexStream,
    accepted: oneshot::Sender<()>,
    deadline: oneshot::Sender<TestResult<()>>,
    released: oneshot::Receiver<()>,
) -> TestResult<()> {
    let mut builder = ::http2::server::Builder::new();
    builder.initial_window_size(0);
    let mut connection = builder.handshake::<_, Bytes>(stream).await?;
    let mut upload = accept_stalled_upload(&mut connection, accepted).await?;

    let result = observe_upload_reset(&mut connection, &mut upload.body).await;
    if let Err(result) = deadline.send(result) {
        return complete_control(result, Err("reset deadline observer stopped".into()));
    }

    tokio::select! {
        result = released => result?,
        result = poll_fn(|context| connection.poll_closed(context)) => {
            result?;
            return Err("unreset peer closed before its cleanup gate".into());
        }
    }

    drop(upload);
    connection.abrupt_shutdown(::http2::Reason::NO_ERROR);
    timeout(
        CONTROL_TIMEOUT,
        poll_fn(|context| connection.poll_closed(context)),
    )
    .await??;
    Ok(())
}

struct UploadAbort(AbortHandle);

impl Drop for UploadAbort {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct UploadCleanup {
    peer: AbortHandle,
    upload: Option<AbortHandle>,
}

impl UploadCleanup {
    fn new(peer: AbortHandle) -> Self {
        Self { peer, upload: None }
    }

    fn abort(&self) {
        self.peer.abort();
        if let Some(upload) = &self.upload {
            upload.abort();
        }
    }

    async fn wait(&self) {
        until_finished(&self.peer).await;
        if let Some(upload) = &self.upload {
            until_finished(upload).await;
        }
    }

    async fn stop(self) -> TestResult<()> {
        self.abort();
        timeout(CONTROL_TIMEOUT, self.wait()).await?;
        Ok(())
    }
}

impl Drop for UploadCleanup {
    fn drop(&mut self) {
        self.abort();
    }
}

async fn until_finished(handle: &AbortHandle) {
    while !handle.is_finished() {
        tokio::task::yield_now().await;
    }
}

fn has_cause<E: Error + 'static>(mut error: &(dyn Error + 'static)) -> bool {
    loop {
        if error.is::<E>() {
            return true;
        }
        let Some(source) = error.source() else {
            return false;
        };
        error = source;
    }
}

fn h2_cause<'a>(mut error: &'a (dyn Error + 'static)) -> Option<&'a ::http2::Error> {
    loop {
        if let Some(cause) = error.downcast_ref::<::http2::Error>() {
            return Some(cause);
        }
        error = error.source()?;
    }
}

fn complete_control<T>(result: TestResult<T>, cleanup: TestResult<()>) -> TestResult<T> {
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(ControlFailures { primary, cleanup }.into()),
    }
}

#[derive(Debug)]
struct ControlFailures {
    primary: Box<dyn Error + Send + Sync>,
    cleanup: Box<dyn Error + Send + Sync>,
}

impl fmt::Display for ControlFailures {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; upload control cleanup failed: {}",
            self.primary, self.cleanup
        )
    }
}

impl Error for ControlFailures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&*self.primary)
    }
}

#[derive(Debug)]
struct CompletedPeerFault {
    cause: ::http2::Error,
}

impl fmt::Display for CompletedPeerFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "completed peer marker 913: {:?}",
            self.cause.reason()
        )
    }
}

impl Error for CompletedPeerFault {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.cause)
    }
}
