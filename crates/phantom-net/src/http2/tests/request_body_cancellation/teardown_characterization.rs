use std::{error::Error, fmt, future::poll_fn, io, task::Poll, time::Duration};

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use tokio::{io::DuplexStream, sync::oneshot, time::timeout};

use super::BODY_LEN;
use crate::http2::tests::{TestResult, driver_shutdown::ShutdownPeer};

const DEADLINE: Duration = Duration::from_secs(5);

#[tokio::test]
async fn a_closed_backend_upload_drops_without_another_reset() -> TestResult<()> {
    close_stalled_upload(StreamRelease::Drop).await
}

#[tokio::test]
async fn a_closed_backend_upload_accepts_cancel_before_drop() -> TestResult<()> {
    close_stalled_upload(StreamRelease::Cancel).await
}

enum StreamRelease {
    Drop,
    Cancel,
}

async fn close_stalled_upload(release: StreamRelease) -> TestResult<()> {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let (posted, post) = oneshot::channel();
    let (close, closed) = oneshot::channel();
    let peer = ShutdownPeer::spawn(close_after_post(server, posted, closed));
    let (mut sender, connection) = timeout(DEADLINE, ::http2::client::handshake(client)).await??;
    let driver = ShutdownPeer::spawn(async move { connection.await.map_err(Into::into) });

    let operation: TestResult<::http2::SendStream<Bytes>> = async {
        let root = Request::builder().uri("https://example.test/").body(())?;
        let (response, root_send) = sender.send_request(root, true)?;
        let response = timeout(DEADLINE, response).await??;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let mut body = response.into_body();
        match timeout(DEADLINE, body.data()).await? {
            None => {}
            Some(Err(error)) => return Err(error.into()),
            Some(Ok(_)) => return Err("terminal 204 carried DATA".into()),
        }
        drop(body);
        drop(root_send);

        let request = Request::builder()
            .method(Method::POST)
            .uri("https://example.test/cancel-upload")
            .body(())?;
        let (response, mut upload) = sender.send_request(request, false)?;
        timeout(DEADLINE, post).await??;
        upload.reserve_capacity(BODY_LEN);
        assert_eq!(upload.capacity(), 0);
        poll_fn(|context| match upload.poll_capacity(context) {
            Poll::Pending => Poll::Ready(Ok::<_, Box<dyn Error + Send + Sync>>(())),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(error.into())),
            Poll::Ready(_) => Poll::Ready(Err("zero-window upload did not remain pending".into())),
        })
        .await?;

        close
            .send(())
            .map_err(|_| "backend peer stopped before its close gate")?;
        let failure = timeout(DEADLINE, response)
            .await?
            .err()
            .ok_or("closed backend upload returned a response")?;
        if !failure.is_io() {
            return Err(failure.into());
        }
        assert!(matches!(
            failure.get_io().map(io::Error::kind),
            Some(io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof)
        ));
        Ok(upload)
    }
    .await;

    let peer_result = join_backend_task(peer).await;
    let driver_result = join_backend_task(driver).await;
    let mut upload = finish_backend_operation(
        operation,
        finish_backend_operation(peer_result, driver_result),
    )?;

    // Both drivers are joined; this isolates a reset after terminal I/O.
    if matches!(release, StreamRelease::Cancel) {
        upload.send_reset(::http2::Reason::CANCEL);
    }
    drop(upload);
    drop(sender);
    Ok(())
}

async fn close_after_post(
    stream: DuplexStream,
    posted: oneshot::Sender<()>,
    closed: oneshot::Receiver<()>,
) -> TestResult<()> {
    let mut builder = ::http2::server::Builder::new();
    builder.initial_window_size(0);
    let mut connection = builder.handshake::<_, Bytes>(stream).await?;
    let (root, mut respond) = connection.accept().await.ok_or("root request absent")??;
    assert_eq!(root.method(), Method::GET);
    assert_eq!(root.uri().path(), "/");
    respond.send_response(Response::builder().status(204).body(())?, true)?;

    let (post, upload_response) = connection.accept().await.ok_or("upload request absent")??;
    assert_eq!(post.method(), Method::POST);
    assert_eq!(post.uri().path(), "/cancel-upload");
    posted.send(()).map_err(|_| "POST observer stopped")?;
    tokio::select! {
        result = closed => result?,
        result = poll_fn(|context| connection.poll_closed(context)) => {
            result?;
            return Err("backend closed before its explicit gate".into());
        }
    }

    drop(root);
    drop(respond);
    drop(post);
    drop(upload_response);
    connection.abrupt_shutdown(::http2::Reason::NO_ERROR);
    timeout(DEADLINE, poll_fn(|context| connection.poll_closed(context))).await??;
    Ok(())
}

async fn join_backend_task(mut task: ShutdownPeer<()>) -> TestResult<()> {
    match timeout(DEADLINE, &mut task).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(error.into()),
        Err(error) => finish_backend_operation(Err(error.into()), task.stop().await),
    }
}

fn finish_backend_operation<T>(result: TestResult<T>, cleanup: TestResult<()>) -> TestResult<T> {
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(BackendFailures { primary, cleanup }.into()),
    }
}

#[derive(Debug)]
struct BackendFailures {
    primary: Box<dyn Error + Send + Sync>,
    cleanup: Box<dyn Error + Send + Sync>,
}

impl fmt::Display for BackendFailures {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; backend teardown failed: {}",
            self.primary, self.cleanup
        )
    }
}

impl Error for BackendFailures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&*self.primary)
    }
}
