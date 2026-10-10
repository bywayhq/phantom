use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    net::Ipv4Addr,
    task::Poll,
    time::Duration,
};

use http_body_util::BodyExt;
use phantom::{RequestError, RequestErrorKind};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::oneshot,
    task::AbortHandle,
    time::timeout,
};

use super::{BUDGET, Client, HttpProtocol, Method, PreparedRequestBody, StatusCode, TestResult};
use super::{Observed, collect_upload, read_upload, tls_settings};
use crate::support::tunnel_proxy::{connection_peer::FixtureFailures, finish_with_cleanup};

const QUIET: Duration = Duration::from_millis(100);
const COMPLETE: &[u8] = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
const TRUNCATED: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nab";

struct AbortBackup(AbortHandle);

impl Drop for AbortBackup {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Destroyed(Option<oneshot::Sender<()>>);

impl Drop for Destroyed {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            // An already-failed observer does not change task destruction.
            let _ = sender.send(());
        }
    }
}

#[derive(Debug)]
struct RecorderFailure;

impl fmt::Display for RecorderFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("upload recorder failed after its response write")
    }
}

impl Error for RecorderFailure {}

async fn cancelled_collection(polled: bool) -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let url = format!("http://{}/upload", listener.local_addr()?);
    let (release, held) = oneshot::channel();
    let (destroyed, mut destruction) = oneshot::channel();
    let mut server = tokio::spawn(async move {
        let _destroyed = Destroyed(Some(destroyed));
        let (stream, _) = listener.accept().await?;
        let mut stream = BufReader::new(stream);
        let observed = read_upload(&mut stream).await?;
        assert_eq!(observed.method, b"POST");
        assert_eq!(observed.body, b"a=b");
        assert_eq!(observed.value("content-length"), Some(&b"3"[..]));

        stream.get_mut().write_all(COMPLETE).await?;
        // Controls hold the real recorder after its successful wire exchange.
        held.await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(observed)
    });
    let backup = AbortBackup(server.abort_handle());
    let client = Client::builder(phantom::profile::ClientProfile::new(tls_settings())).build();
    let preparation = async {
        let client = client?;
        let response = client
            .request(HttpProtocol::Http1, Method::POST, &url)?
            .prepared_body(PreparedRequestBody::form([("a", "b")], 128)?)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(client)
    }
    .await;

    let client = match preparation {
        Ok(client) => client,
        Err(primary) => {
            server.abort();
            let cleanup = match timeout(BUDGET, &mut server).await {
                Ok(Err(error)) if error.is_cancelled() => Ok(()),
                Ok(Err(error)) => Err(error.into()),
                Ok(Ok(result)) => result.map(|_| ()),
                Err(error) => Err(error.into()),
            };
            return finish_with_cleanup(Err(primary), cleanup);
        }
    };

    let (stop, _stopped) = oneshot::channel();
    let mut collection = Box::pin(collect_upload(async { Ok(()) }, stop, server));
    let pending = if polled {
        poll_fn(|cx| Poll::Ready(matches!(collection.as_mut().poll(cx), Poll::Pending))).await
    } else {
        true
    };
    drop(collection);
    let observed = timeout(QUIET, &mut destruction).await;
    let closed_before_backup = match &observed {
        Ok(Ok(())) => true,
        Ok(Err(_)) | Err(_) => false,
    };

    backup.0.abort();
    // The backup releases the injected hold after taking the lifetime snapshot.
    let _ = release.send(());
    let cleanup = if observed.is_ok() {
        observed
            .map_err(Into::into)
            .and_then(|result| result.map_err(Into::into))
    } else {
        timeout(BUDGET, destruction)
            .await
            .map_err(Into::into)
            .and_then(|result| result.map_err(Into::into))
    };
    drop(client);
    finish_with_cleanup(Ok(()), cleanup)?;

    assert!(
        pending,
        "collection unexpectedly completed while recorder was held"
    );
    assert!(
        closed_before_backup,
        "dropped upload collection left its recorder alive"
    );
    Ok(())
}

async fn completed_collection(failed_recorder: bool, truncated: bool) -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let url = format!("http://{}/upload", listener.local_addr()?);
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut stream = BufReader::new(stream);
        let observed = read_upload(&mut stream).await?;
        assert_eq!(observed.method, b"POST");
        assert_eq!(observed.body, b"a=b");

        stream
            .get_mut()
            .write_all(if truncated { TRUNCATED } else { COMPLETE })
            .await?;
        if failed_recorder {
            return Err(RecorderFailure.into());
        }
        Ok::<Observed, Box<dyn Error + Send + Sync>>(observed)
    });
    let _backup = AbortBackup(server.abort_handle());
    let client = Client::builder(phantom::profile::ClientProfile::new(tls_settings())).build()?;
    let operation = async {
        let response = client
            .request(HttpProtocol::Http1, Method::POST, &url)?
            .prepared_body(PreparedRequestBody::form([("a", "b")], 128)?)
            .send()
            .await?;
        assert_eq!(
            response.status(),
            if truncated {
                StatusCode::OK
            } else {
                StatusCode::NO_CONTENT
            }
        );
        response.into_body().collect().await?;
        Ok(())
    }
    .await;
    timeout(BUDGET, async {
        while !server.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await?;

    let (stop, _stopped) = oneshot::channel();
    let result = collect_upload(async { operation }, stop, server).await;
    if truncated {
        let error = result.err().ok_or("truncated upload response succeeded")?;
        let mut cause: &(dyn Error + 'static) = error.as_ref();
        let request = loop {
            if let Some(request) = cause.downcast_ref::<RequestError>() {
                break request;
            }
            cause = cause
                .source()
                .ok_or("truncated upload lost its request cause")?;
        };
        assert_eq!(request.kind(), RequestErrorKind::Http1);
        let mut cause: &(dyn Error + 'static) = request;
        loop {
            if let Some(error) = cause.downcast_ref::<io::Error>() {
                assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
                break;
            }
            cause = cause
                .source()
                .ok_or("truncated upload lost its I/O cause")?;
        }

        if failed_recorder {
            let failures = error
                .downcast_ref::<FixtureFailures>()
                .ok_or("collection discarded its completed recorder failure")?;
            assert!(failures.cleanup.downcast_ref::<RecorderFailure>().is_some());
        }
    } else {
        let observed = result?;
        assert_eq!(observed.method, b"POST");
        assert_eq!(observed.body, b"a=b");
    }
    Ok(())
}

#[tokio::test]
async fn dropping_an_unpolled_collection_destroys_its_exchanged_recorder() -> TestResult<()> {
    timeout(BUDGET, cancelled_collection(false)).await?
}

#[tokio::test]
async fn cancelling_a_pending_collection_destroys_its_exchanged_recorder() -> TestResult<()> {
    timeout(BUDGET, cancelled_collection(true)).await?
}

#[tokio::test]
async fn a_truncated_response_keeps_its_completed_recorder_failure() -> TestResult<()> {
    timeout(BUDGET, completed_collection(true, true)).await?
}

#[tokio::test]
async fn a_truncated_response_with_a_clean_recorder_keeps_its_body_cause() -> TestResult<()> {
    timeout(BUDGET, completed_collection(false, true)).await?
}

#[tokio::test]
async fn a_complete_upload_collects_literal_body_and_peer_result() -> TestResult<()> {
    timeout(BUDGET, completed_collection(false, false)).await?
}
