use std::{
    error::Error,
    future::{Future, poll_fn},
    net::Ipv4Addr,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use phantom::{Client, HttpProtocol, RequestBuilder, RequestError, RequestErrorKind, ResponseBody};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::{oneshot, watch},
    task::{AbortHandle, JoinError},
    time::timeout,
};

use crate::support::tunnel_proxy::{
    ConnectionPeer, connection_peer::FixtureFailures, finish_with_cleanup,
};

use super::{
    Event, Server, TEST_TIMEOUT, TestResult, builder, finish, hold, profile, read_head,
    request_path,
};

const OBSERVATION_LIMIT: Duration = Duration::from_secs(2);
const BACKUP_LIMIT: Duration = Duration::from_secs(5);

type RequestResult = Result<http::Response<ResponseBody>, RequestError>;

#[derive(Default)]
pub(super) struct RequestTask {
    task: Option<ConnectionPeer<RequestResult>>,
    cancellation_requested: bool,
}

pub(super) fn spawn_request(
    request: RequestBuilder,
    pending: Option<watch::Sender<bool>>,
) -> RequestTask {
    let task = match pending {
        None => ConnectionPeer::spawn(request.send()),
        Some(pending) => ConnectionPeer::spawn(async move {
            let mut send = std::pin::pin!(request.send());
            poll_fn(|context| {
                let result = send.as_mut().poll(context);
                if result.is_pending() {
                    pending.send_replace(true);
                }
                result
            })
            .await
        }),
    };

    RequestTask {
        task: Some(task),
        cancellation_requested: false,
    }
}

impl RequestTask {
    fn abort(&mut self) {
        if let Some(task) = &self.task
            && !task.is_finished()
        {
            self.cancellation_requested = true;
            task.abort();
        }
    }

    fn abort_handle(&self) -> Option<AbortHandle> {
        self.task.as_ref().map(ConnectionPeer::abort_handle)
    }

    fn is_finished(&self) -> bool {
        self.task.as_ref().is_none_or(ConnectionPeer::is_finished)
    }

    async fn stop(&mut self) -> TestResult {
        if self.task.is_none() {
            return Ok(());
        }

        self.abort();

        match timeout(BACKUP_LIMIT, &mut *self).await? {
            Ok(Ok(response)) => finish(response).await,
            Ok(Err(error)) => Err(error.into()),
            Err(error)
                if self.cancellation_requested
                    && error
                        .downcast_ref::<JoinError>()
                        .is_some_and(JoinError::is_cancelled) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

impl Future for RequestTask {
    type Output = TestResult<RequestResult>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let Some(task) = this.task.as_mut() else {
            return Poll::Ready(Err("queued request owner has no pending task".into()));
        };

        match Pin::new(task).poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                this.task.take();
                Poll::Ready(result.map_err(Into::into))
            }
        }
    }
}

pub(super) async fn finish_request(primary: TestResult, request: &mut RequestTask) -> TestResult {
    finish_with_cleanup(primary, request.stop().await)
}

struct RequestBackup {
    server: Option<Server>,
    client: Option<Client>,
    held: Option<http::Response<ResponseBody>>,
    task: Option<RequestTask>,
    completion: Option<AbortHandle>,
    pending: watch::Receiver<bool>,
}

impl RequestBackup {
    async fn start(&mut self) -> TestResult {
        self.server = Some(Server::start().await?);
        self.client = Some(
            builder(profile())
                .max_concurrent_http1_requests_per_origin(NonZeroUsize::MIN)
                .max_pending_http1_requests_per_origin(NonZeroUsize::MIN)
                .build()?,
        );
        let server = self.server.as_mut().ok_or("request server missing")?;
        let client = self.client.as_ref().ok_or("request client missing")?;
        self.held = Some(hold(client, &server.uri("held")).await?);
        if server.next().await? != Event::Accepted(0)
            || server.next_request().await? != (0, "held".to_owned())
        {
            return Err("the actual held request was not admitted and recorded".into());
        }

        let request = client.get(HttpProtocol::Http1, &server.uri("queued"))?;
        let (pending, receiver) = watch::channel(false);
        self.pending = receiver;
        let task = spawn_request(request, Some(pending));
        self.completion = task.abort_handle();
        self.task = Some(task);
        timeout(OBSERVATION_LIMIT, self.pending.wait_for(|pending| *pending)).await??;
        server.assert_quiet().await?;
        if self
            .task
            .as_ref()
            .ok_or("queued request missing")?
            .is_finished()
        {
            return Err("queued request completed while the first response was held".into());
        }
        Ok(())
    }

    async fn joined(&mut self) -> TestResult<TestResult<RequestResult>> {
        let task = self.task.as_mut().ok_or("queued request missing")?;
        let result = timeout(OBSERVATION_LIMIT, task).await?;
        self.task.take();
        Ok(result)
    }

    async fn completed(&self, limit: Duration) -> TestResult {
        let completion = self
            .completion
            .as_ref()
            .ok_or("request completion witness missing")?;
        timeout(limit, async {
            while !completion.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }

    async fn stop(&mut self) -> TestResult {
        let request = if let Some(task) = self.task.as_mut() {
            let result = task.stop().await;
            if task.task.is_none() {
                self.task.take();
            }
            result
        } else if let Some(completion) = &self.completion {
            completion.abort();
            self.completed(BACKUP_LIMIT).await
        } else {
            Ok(())
        };

        self.held.take();
        let server = match self.server.take() {
            Some(server) => server.shutdown().await,
            None => Ok(()),
        };
        self.client.take();
        finish_with_cleanup(request, server)
    }
}

impl Default for RequestBackup {
    fn default() -> Self {
        let (_, pending) = watch::channel(false);
        Self {
            server: None,
            client: None,
            held: None,
            task: None,
            completion: None,
            pending,
        }
    }
}

impl Drop for RequestBackup {
    fn drop(&mut self) {
        if let Some(completion) = &self.completion {
            completion.abort();
        }
    }
}

#[tokio::test]
async fn releasing_the_held_response_completes_the_actual_queued_request() -> TestResult {
    let mut backup = RequestBackup::default();
    let primary = async {
        backup.start().await?;
        finish(backup.held.take().ok_or("held response missing")?).await?;
        let response = backup.joined().await???;
        if response.status() != http::StatusCode::OK {
            return finish_with_cleanup(
                Err("queued request response status changed".into()),
                finish(response).await,
            );
        }
        finish(response).await?;
        let server = backup.server.as_mut().ok_or("request server missing")?;
        if server.next_request().await? != (0, "queued".to_owned()) {
            return Err("queued request did not reuse the admitted connection".into());
        }
        server.assert_quiet().await?;
        backup.completed(OBSERVATION_LIMIT).await
    }
    .await;

    let cleanup = backup.stop().await;
    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn explicit_abort_and_join_destroys_the_actual_queued_send() -> TestResult {
    let mut backup = RequestBackup::default();
    let primary = async {
        backup.start().await?;
        backup
            .task
            .as_mut()
            .ok_or("queued request missing")?
            .abort();
        match backup.joined().await? {
            Err(error)
                if error
                    .downcast_ref::<JoinError>()
                    .is_some_and(JoinError::is_cancelled) => {}
            Err(error) => return Err(error),
            Ok(Err(error)) => return Err(error.into()),
            Ok(Ok(response)) => {
                return finish_with_cleanup(
                    Err("explicit abort did not cancel the queued request".into()),
                    finish(response).await,
                );
            }
        }
        backup.completed(OBSERVATION_LIMIT).await
    }
    .await;

    let cleanup = backup.stop().await;
    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn dropping_queued_request_destroys_the_actual_pending_send() -> TestResult {
    let mut backup = RequestBackup::default();
    let primary = async {
        backup.start().await?;
        backup.task.take();
        // Task completion follows destruction of its original send future.
        backup.completed(OBSERVATION_LIMIT).await
    }
    .await;

    let cleanup = backup.stop().await;
    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn stopping_a_completed_request_keeps_its_actual_capacity_error() -> TestResult {
    let mut backup = RequestBackup::default();
    let mut overflow = RequestTask::default();
    let primary = async {
        backup.start().await?;
        let client = backup.client.as_ref().ok_or("request client missing")?;
        let server = backup.server.as_ref().ok_or("request server missing")?;
        overflow = spawn_request(
            client.get(HttpProtocol::Http1, &server.uri("overflow"))?,
            None,
        );
        wait_finished(&overflow).await?;

        let observed = match overflow.stop().await {
            Err(error) => error,
            Ok(()) => return Err("request shutdown discarded its completed capacity error".into()),
        };
        let Some(error) = observed.downcast_ref::<RequestError>() else {
            return Err(observed);
        };

        if error.kind() != RequestErrorKind::Capacity
            || error.protocol() != Some(HttpProtocol::Http1)
            || error.origin().is_none()
        {
            return Err(observed);
        }
        overflow.stop().await
    }
    .await;

    let request_cleanup = overflow.stop().await;
    let backup_cleanup = backup.stop().await;
    finish_with_cleanup(
        primary,
        finish_with_cleanup(request_cleanup, backup_cleanup),
    )
}

#[tokio::test]
async fn stopping_a_completed_queued_request_collects_its_actual_normal_response() -> TestResult {
    let mut backup = RequestBackup::default();
    let primary = async {
        backup.start().await?;
        finish(backup.held.take().ok_or("held response missing")?).await?;
        backup.completed(OBSERVATION_LIMIT).await?;
        backup
            .task
            .as_mut()
            .ok_or("queued request missing")?
            .stop()
            .await?;

        let client = backup.client.as_ref().ok_or("request client missing")?;
        let server = backup.server.as_mut().ok_or("request server missing")?;
        finish(hold(client, &server.uri("after-cleanup")).await?).await?;
        if server.next_request().await? != (0, "queued".to_owned())
            || server.next_request().await? != (0, "after-cleanup".to_owned())
        {
            return Err(
                "request shutdown did not leave the literal response connection reusable".into(),
            );
        }
        server.assert_quiet().await
    }
    .await;

    let cleanup = backup.stop().await;
    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn stopping_a_completed_response_keeps_the_actual_body_deadline() -> TestResult {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let (release_body, released) = oneshot::channel::<()>();
    let peer = ConnectionPeer::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let head = read_head(&mut stream).await?;
        if request_path(&head) != "withheld-body" {
            return Err("the body deadline peer received a different request".into());
        }

        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n")
            .await?;
        released.await?;
        stream.write_all(b"done").await?;
        TestResult::Ok(())
    });
    let mut client = None;
    let mut request = RequestTask::default();
    let primary = async {
        client = Some(builder(profile()).build()?);
        let client = client.as_ref().ok_or("body deadline client missing")?;
        request = spawn_request(
            client.get(
                HttpProtocol::Http1,
                &format!("http://{address}/withheld-body"),
            )?,
            None,
        );
        wait_finished(&request).await?;
        if peer.is_finished() {
            return Err("the body deadline peer ended before request cleanup".into());
        }

        let observed = match timeout(TEST_TIMEOUT + OBSERVATION_LIMIT, request.stop()).await? {
            Err(error) => error,
            Ok(()) => return Err("request cleanup discarded the withheld body's deadline".into()),
        };
        if !observed.is::<tokio::time::error::Elapsed>() {
            return Err(observed);
        }

        if peer.is_finished() {
            return Err("the body deadline peer ended before the timeout was observed".into());
        }
        Ok(())
    }
    .await;

    let request_cleanup = request.stop().await;
    let peer_cleanup = peer.stop().await;
    drop(release_body);
    drop(client);
    finish_with_cleanup(primary, finish_with_cleanup(request_cleanup, peer_cleanup))
}

#[tokio::test]
async fn caller_failure_and_completed_request_cleanup_keep_both_actual_causes() -> TestResult {
    let mut backup = RequestBackup::default();
    let mut overflow = RequestTask::default();
    let primary = async {
        backup.start().await?;
        let client = backup.client.as_ref().ok_or("request client missing")?;
        let server = backup.server.as_ref().ok_or("request server missing")?;
        overflow = spawn_request(
            client.get(HttpProtocol::Http1, &server.uri("overflow"))?,
            None,
        );
        wait_finished(&overflow).await?;

        let caller: TestResult = match client.get(HttpProtocol::Http1, "http://owner.test/\n") {
            Err(error) => Err(error.into()),
            Ok(_) => return Err("invalid caller URI was accepted".into()),
        };
        let observed = match finish_request(caller, &mut overflow).await {
            Err(error) => error,
            Ok(()) => {
                return Err("caller and completed request cleanup failures were discarded".into());
            }
        };
        let Some(causes) = observed.downcast_ref::<FixtureFailures>() else {
            return Err(observed);
        };

        let Some(caller) = causes.primary.downcast_ref::<RequestError>() else {
            return Err(observed);
        };

        let Some(cleanup) = causes.cleanup.downcast_ref::<RequestError>() else {
            return Err(observed);
        };

        if caller.kind() != RequestErrorKind::InvalidUri
            || !caller
                .source()
                .is_some_and(|cause| cause.is::<http::uri::InvalidUri>())
            || cleanup.kind() != RequestErrorKind::Capacity
            || cleanup.protocol() != Some(HttpProtocol::Http1)
            || cleanup.origin().is_none()
        {
            return Err(observed);
        }
        Ok(())
    }
    .await;

    let request_cleanup = overflow.stop().await;
    let backup_cleanup = backup.stop().await;
    finish_with_cleanup(
        primary,
        finish_with_cleanup(request_cleanup, backup_cleanup),
    )
}

#[tokio::test]
async fn shutdown_keeps_a_completed_cancellation_it_did_not_request() -> TestResult {
    let mut backup = RequestBackup::default();
    let primary = async {
        backup.start().await?;
        backup
            .completion
            .as_ref()
            .ok_or("request completion witness missing")?
            .abort();
        backup.completed(OBSERVATION_LIMIT).await?;

        let observed = match backup
            .task
            .as_mut()
            .ok_or("queued request missing")?
            .stop()
            .await
        {
            Err(error) => error,
            Ok(()) => {
                return Err("request shutdown accepted a cancellation it did not request".into());
            }
        };
        if !observed
            .downcast_ref::<JoinError>()
            .is_some_and(JoinError::is_cancelled)
        {
            return Err(observed);
        }
        Ok(())
    }
    .await;

    let cleanup = backup.stop().await;
    finish_with_cleanup(primary, cleanup)
}

async fn wait_finished(request: &RequestTask) -> TestResult {
    timeout(OBSERVATION_LIMIT, async {
        while !request.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}
