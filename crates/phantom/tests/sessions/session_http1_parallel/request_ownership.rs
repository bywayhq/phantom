use std::{future::Future, future::poll_fn, num::NonZeroUsize, time::Duration};

use phantom::{Client, HttpProtocol, RequestBuilder, RequestError, ResponseBody};
use tokio::{
    sync::watch,
    task::{AbortHandle, JoinError, JoinHandle},
    time::timeout,
};

use crate::support::tunnel_proxy::finish_with_cleanup;

use super::{Event, Server, TestResult, builder, finish, hold, profile};

const OBSERVATION_LIMIT: Duration = Duration::from_secs(2);
const BACKUP_LIMIT: Duration = Duration::from_secs(5);

type RequestResult = Result<http::Response<ResponseBody>, RequestError>;

pub(super) fn spawn_request(
    request: RequestBuilder,
    pending: Option<watch::Sender<bool>>,
) -> JoinHandle<RequestResult> {
    match pending {
        None => tokio::spawn(request.send()),
        Some(pending) => tokio::spawn(async move {
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
    }
}

struct RequestBackup {
    server: Option<Server>,
    client: Option<Client>,
    held: Option<http::Response<ResponseBody>>,
    task: Option<JoinHandle<RequestResult>>,
    completion: Option<AbortHandle>,
    pending: watch::Receiver<bool>,
}

impl RequestBackup {
    async fn start(&mut self) -> TestResult {
        self.server = Some(Server::start().await?);
        self.client = Some(
            builder(profile())
                .max_concurrent_http1_requests_per_origin(NonZeroUsize::MIN)
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
        self.completion = Some(task.abort_handle());
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

    async fn joined(&mut self) -> TestResult<Result<RequestResult, JoinError>> {
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
        if let Some(completion) = &self.completion {
            completion.abort();
        }
        let request = if let Some(task) = self.task.as_mut() {
            match timeout(BACKUP_LIMIT, task).await {
                Ok(result) => {
                    self.task.take();
                    match result {
                        Ok(Ok(response)) => finish(response).await,
                        Ok(Err(error)) => Err(error.into()),
                        Err(error) if error.is_cancelled() => Ok(()),
                        Err(error) => Err(error.into()),
                    }
                }
                Err(error) => Err(error.into()),
            }
        } else if self.completion.is_some() {
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
            .as_ref()
            .ok_or("queued request missing")?
            .abort();
        match backup.joined().await? {
            Err(error) if error.is_cancelled() => {}
            Err(error) => return Err(error.into()),
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
