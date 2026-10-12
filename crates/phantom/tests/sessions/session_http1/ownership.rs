use std::{
    error::Error,
    future::{Future, poll_fn},
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
};

use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, RequestBuilder, RequestError, RequestErrorKind, Response, ResponseBody,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{oneshot, watch},
    task::{AbortHandle, JoinHandle},
};

use super::tls_support::client_builder;
use super::{
    H1_ALPN, TestIdentity, TestResult, accept_one, accept_one_observed, bounded, read_head,
    test_client,
};

#[derive(Clone, Debug, Default)]
struct State {
    address: Option<SocketAddr>,
    server: Option<AbortHandle>,
    accepted: bool,
    handshake_pending: bool,
    caller_pending: bool,
    destroyed: bool,
    completed_tls_error: Option<String>,
}

#[derive(Clone, Debug)]
pub(super) struct Observation(watch::Sender<State>);

impl Observation {
    pub(super) fn accepted(&self) {
        self.0.send_modify(|state| state.accepted = true);
    }

    pub(super) fn handshake_pending(&self) {
        self.0.send_modify(|state| state.handshake_pending = true);
    }

    fn completed(&self, result: &TestResult) {
        if let Err(error) = result
            && let Some(error) = error.downcast_ref::<btls::ssl::Error>()
        {
            self.0
                .send_modify(|state| state.completed_tls_error = Some(error.to_string()));
        }
    }
}

struct PeerLife(Option<Observation>);

impl Drop for PeerLife {
    fn drop(&mut self) {
        if let Some(observed) = &self.0 {
            observed.0.send_modify(|state| state.destroyed = true);
        }
    }
}

pub(super) struct Control {
    observed: Observation,
    start: oneshot::Receiver<()>,
    first_target: Option<String>,
}

pub(super) async fn reuse_requests(control: Option<Control>) -> TestResult {
    let (observed, start, mut first_target) = match control {
        Some(control) => (
            Some(control.observed),
            Some(control.start),
            control.first_target,
        ),
        None => (None, None, None),
    };

    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let peer_observed = observed.clone();
        let server = tokio::spawn(async move {
            let _life = PeerLife(peer_observed.clone());

            let result: TestResult = async {
                let mut stream =
                    accept_one_observed(&listener, &acceptor, peer_observed.as_ref()).await?;

                for _ in 0..2 {
                    read_head(&mut stream).await?;
                    stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .await?;
                }

                Ok::<_, Box<dyn Error + Send + Sync>>(())
            }
            .await;

            if let Some(observed) = peer_observed {
                observed.completed(&result);
            }

            result
        });

        if let Some(observed) = &observed {
            observed.0.send_modify(|state| {
                state.address = Some(address);
                state.server = Some(server.abort_handle());
            });
        }

        if let Some(start) = start {
            start.await?;
        }

        let client = test_client(&identity, false)?;
        for path in ["first", "second"] {
            let target = first_target
                .take()
                .unwrap_or_else(|| format!("https://{address}/{path}"));
            let sending = client.get(HttpProtocol::Http1, &target)?.send();

            let response = if let Some(observed) = &observed {
                tokio::pin!(sending);
                poll_fn(|context| {
                    let result = sending.as_mut().poll(context);
                    if result.is_pending() {
                        observed.0.send_modify(|state| state.caller_pending = true);
                    }

                    result
                })
                .await?
            } else {
                sending.await?
            };

            response.into_body().collect().await?;
        }

        server.await??;
        Ok(())
    })
    .await
}

pub(super) struct ActiveBody {
    pub(super) session: Client,
    pub(super) active: Response<ResponseBody>,
    pub(super) address: SocketAddr,
    pub(super) server: JoinHandle<TestResult>,
}

#[derive(Clone, Debug, Default)]
struct QueuedState {
    pending: [bool; 2],
    ready: [bool; 2],
    kinds: [Option<RequestErrorKind>; 2],
    destroyed: [bool; 2],
    tasks: [Option<AbortHandle>; 2],
    joined: [bool; 2],
    selected: Option<usize>,
    stop_requested: [bool; 2],
    peer_pending: bool,
    peer_closed: bool,
    peer_destroyed: bool,
}

#[derive(Clone, Debug)]
pub(super) struct QueuedObservation(watch::Sender<QueuedState>);

struct QueuedPeerLife(Option<QueuedObservation>);

impl Drop for QueuedPeerLife {
    fn drop(&mut self) {
        if let Some(observed) = &self.0 {
            observed.0.send_modify(|state| state.peer_destroyed = true);
        }
    }
}

pub(super) async fn active_body(observed: Option<QueuedObservation>) -> TestResult<ActiveBody> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let server = tokio::spawn(async move {
        let _life = QueuedPeerLife(observed.clone());

        let mut stream = accept_one(&listener, &acceptor).await?;
        read_head(&mut stream).await?;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nfirst")
            .await?;

        let mut remaining = Vec::new();
        if let Some(observed) = observed {
            let reading = stream.read_to_end(&mut remaining);
            tokio::pin!(reading);
            let result = poll_fn(|context| {
                let result = reading.as_mut().poll(context);
                if result.is_pending() {
                    observed.0.send_modify(|state| state.peer_pending = true);
                }

                result
            })
            .await;

            if result.is_ok() {
                observed.0.send_modify(|state| state.peer_closed = true);
            }

            result?;
        } else {
            stream.read_to_end(&mut remaining).await?;
        }

        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });

    let session = client_builder(&identity, false)
        .max_pending_http1_requests_per_origin(NonZeroUsize::MIN)
        .build()?;
    let active = session
        .get(HttpProtocol::Http1, &format!("https://{address}/active"))?
        .send()
        .await?;

    Ok(ActiveBody {
        session,
        active,
        address,
        server,
    })
}

pub(super) struct QueuedControl {
    observed: QueuedObservation,
    collect_after: oneshot::Receiver<()>,
    return_after: oneshot::Receiver<()>,
}

struct QueuedLife {
    observed: QueuedObservation,
    index: usize,
}

impl Drop for QueuedLife {
    fn drop(&mut self) {
        self.observed
            .0
            .send_modify(|state| state.destroyed[self.index] = true);
    }
}

fn spawn_waiter(
    request: RequestBuilder,
    observed: Option<QueuedObservation>,
    index: usize,
) -> JoinHandle<Result<Response<ResponseBody>, RequestError>> {
    let Some(observed) = observed else {
        return tokio::spawn(request.send());
    };
    let task_observed = observed.clone();
    let task = tokio::spawn(async move {
        let _life = QueuedLife {
            observed: task_observed.clone(),
            index,
        };

        let sending = request.send();
        tokio::pin!(sending);

        let result = poll_fn(|context| {
            let result = sending.as_mut().poll(context);
            if result.is_pending() {
                task_observed
                    .0
                    .send_modify(|state| state.pending[index] = true);
            }

            result
        })
        .await;

        task_observed.0.send_modify(|state| {
            state.ready[index] = true;
            if let Err(error) = &result {
                state.kinds[index] = Some(error.kind());
            }
        });

        result
    });

    observed
        .0
        .send_modify(|state| state.tasks[index] = Some(task.abort_handle()));

    task
}

pub(super) async fn queued_requests(
    first_waiter: RequestBuilder,
    second_waiter: RequestBuilder,
    control: Option<QueuedControl>,
) -> TestResult {
    let (observed, collect_after, return_after) = match control {
        Some(control) => (
            Some(control.observed),
            Some(control.collect_after),
            Some(control.return_after),
        ),
        None => (None, None, None),
    };

    let mut first_waiter = spawn_waiter(first_waiter, observed.clone(), 0);
    let mut second_waiter = spawn_waiter(second_waiter, observed.clone(), 1);

    if let Some(collect_after) = collect_after {
        collect_after.await?;
    }

    let rejected = tokio::select! {
        result = &mut first_waiter => {
            second_waiter.abort();
            if let Some(observed) = &observed {
                observed.0.send_modify(|state| {
                    state.joined[0] = true;
                    state.selected = Some(0);
                    state.stop_requested[1] = true;
                });
            }

            result?
        }
        result = &mut second_waiter => {
            first_waiter.abort();
            if let Some(observed) = &observed {
                observed.0.send_modify(|state| {
                    state.joined[1] = true;
                    state.selected = Some(1);
                    state.stop_requested[0] = true;
                });
            }

            result?
        }
    };

    if let Some(return_after) = return_after {
        return_after.await?;
    }

    let error = match rejected {
        Ok(_) => return Err("excess HTTP/1 waiter was admitted".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::Capacity);
    Ok(())
}

#[cfg(test)]
mod tests;
