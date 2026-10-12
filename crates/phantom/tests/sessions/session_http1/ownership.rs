use std::{
    error::Error,
    future::{Future, poll_fn},
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};

use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, RequestBuilder, RequestError, RequestErrorKind, Response, ResponseBody,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{oneshot, watch},
    task::{AbortHandle, JoinError, JoinHandle},
    time::timeout,
};

use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

use super::tls_support::client_builder;
use super::{
    H1_ALPN, TEST_TIMEOUT, TestIdentity, TestResult, accept_one, accept_one_observed, bounded,
    read_head, test_client,
};

pub(super) type Server<T = ()> = ConnectionPeer<TestResult<T>>;

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

    let mut server = None;
    let caller = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let peer_observed = observed.clone();
        server = Some(ConnectionPeer::spawn(async move {
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
        }));

        if let Some(observed) = &observed {
            let peer = server
                .as_ref()
                .ok_or("original HTTP/1 peer missing after spawn")?;

            observed.0.send_modify(|state| {
                state.address = Some(address);
                state.server = Some(peer.abort_handle());
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

        join_peer(&mut server).await?;
        Ok(())
    })
    .await;

    collect_peer(caller, server).await
}

pub(super) struct ActiveBody {
    pub(super) session: Client,
    pub(super) active: Response<ResponseBody>,
    pub(super) address: SocketAddr,
    pub(super) server: Server,
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

pub(super) async fn active_body(
    observed: Option<QueuedObservation>,
    server: &mut Option<Server>,
) -> TestResult<ActiveBody> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    *server = Some(ConnectionPeer::spawn(async move {
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
    }));

    let session = client_builder(&identity, false)
        .max_pending_http1_requests_per_origin(NonZeroUsize::MIN)
        .build()?;
    let active = session
        .get(HttpProtocol::Http1, &format!("https://{address}/active"))?
        .send()
        .await?;
    let server = server
        .take()
        .ok_or("original active-body HTTP/1 peer missing after setup")?;

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
    let observed = control.as_ref().map(|control| control.observed.clone());
    let mut requests = QueuedPair::new(first_waiter, second_waiter, observed);
    let caller = requests.drive(control).await;

    requests.finish(caller).await
}

type SendOutcome = Result<Response<ResponseBody>, RequestError>;
type JoinedOutcome = Result<SendOutcome, JoinError>;

enum QueuedSlot {
    Pending(ConnectionPeer<SendOutcome>),
    Ready(JoinedOutcome),
    Consumed,
}

impl QueuedSlot {
    fn poll_join(
        &mut self,
        context: &mut Context<'_>,
        observed: Option<&QueuedObservation>,
        index: usize,
    ) -> Poll<()> {
        let Self::Pending(task) = self else {
            return Poll::Ready(());
        };

        let result = match Pin::new(task).poll(context) {
            Poll::Ready(result) => result,
            Poll::Pending => return Poll::Pending,
        };

        *self = Self::Ready(result);
        if let Some(observed) = observed {
            observed.0.send_modify(|state| state.joined[index] = true);
        }

        Poll::Ready(())
    }

    fn outcome(&mut self, requested: bool) -> TestResult {
        let Self::Ready(_) = self else {
            return Ok(());
        };

        let Self::Ready(result) = std::mem::replace(self, Self::Consumed) else {
            return Err("original HTTP/1 queued result missing after join".into());
        };

        match result {
            Ok(Err(error)) if error.kind() == RequestErrorKind::Capacity => Ok(()),
            Ok(Err(error)) => Err(error.into()),
            Ok(Ok(_)) => Err("excess HTTP/1 waiter was admitted".into()),
            Err(error) if requested && error.is_cancelled() => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

pub(super) struct QueuedPair {
    slots: [QueuedSlot; 2],
    requested: [bool; 2],
    selected: Option<usize>,
    observed: Option<QueuedObservation>,
}

impl Drop for QueuedPair {
    fn drop(&mut self) {
        // Abort both tasks before dropping a ready response can release capacity.
        for slot in &self.slots {
            if let QueuedSlot::Pending(task) = slot {
                task.abort();
            }
        }
    }
}

impl QueuedPair {
    pub(super) fn new(
        first: RequestBuilder,
        second: RequestBuilder,
        observed: Option<QueuedObservation>,
    ) -> Self {
        let first = ConnectionPeer::from_task(spawn_waiter(first, observed.clone(), 0));
        let second = ConnectionPeer::from_task(spawn_waiter(second, observed.clone(), 1));

        Self {
            slots: [QueuedSlot::Pending(first), QueuedSlot::Pending(second)],
            requested: [false; 2],
            selected: None,
            observed,
        }
    }

    pub(super) async fn drive(&mut self, control: Option<QueuedControl>) -> TestResult {
        let (collect_after, return_after) = match control {
            Some(control) => (Some(control.collect_after), Some(control.return_after)),
            None => (None, None),
        };

        if let Some(collect_after) = collect_after {
            collect_after.await?;
        }

        let [first, second] = &mut self.slots;
        let observed = self.observed.as_ref();
        let selected = tokio::select! {
            () = poll_fn(|context| first.poll_join(context, observed, 0)) => 0,
            () = poll_fn(|context| second.poll_join(context, observed, 1)) => 1,
        };

        self.selected = Some(selected);
        if let Some(observed) = &self.observed {
            observed
                .0
                .send_modify(|state| state.selected = Some(selected));
        }

        self.poll_ready().await;
        self.abort_pending();

        timeout(TEST_TIMEOUT, self.join_all())
            .await
            .map_err(|elapsed| {
                FixtureDeadline::new("HTTP/1 queued request cleanup exceeded deadline", elapsed)
            })?;

        if let Some(return_after) = return_after {
            return_after.await?;
        }

        self.outcomes()
    }

    async fn poll_ready(&mut self) {
        poll_fn(|context| {
            for (index, slot) in self.slots.iter_mut().enumerate() {
                // The actual result stays in the slot even though this poll never waits.
                match slot.poll_join(context, self.observed.as_ref(), index) {
                    Poll::Ready(()) | Poll::Pending => {}
                }
            }

            Poll::Ready(())
        })
        .await;
    }

    fn abort_pending(&mut self) {
        for (index, slot) in self.slots.iter().enumerate() {
            if let QueuedSlot::Pending(task) = slot
                && !task.is_finished()
            {
                self.requested[index] = true;
                task.abort();
                if let Some(observed) = &self.observed {
                    observed
                        .0
                        .send_modify(|state| state.stop_requested[index] = true);
                }
            }
        }
    }

    async fn join_all(&mut self) {
        poll_fn(|context| {
            let mut pending = false;
            for (index, slot) in self.slots.iter_mut().enumerate() {
                pending |= slot
                    .poll_join(context, self.observed.as_ref(), index)
                    .is_pending();
            }

            if pending {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
    }

    fn outcomes(&mut self) -> TestResult {
        let first = self.selected.unwrap_or(0);
        let second = 1 - first;
        let primary = self.slots[first].outcome(self.requested[first]);
        let sibling = self.slots[second].outcome(self.requested[second]);

        finish_with_cleanup(primary, sibling)
    }

    pub(super) async fn finish(&mut self, caller: TestResult) -> TestResult {
        self.poll_ready().await;
        self.abort_pending();

        let joining = timeout(TEST_TIMEOUT, self.join_all())
            .await
            .map_err(|elapsed| {
                FixtureDeadline::new("HTTP/1 queued request cleanup exceeded deadline", elapsed)
                    .into()
            });
        let requests = finish_with_cleanup(self.outcomes(), joining);

        finish_with_cleanup(caller, requests)
    }
}

pub(super) async fn join_peer<T>(server: &mut Option<Server<T>>) -> TestResult<T> {
    let peer = server
        .as_mut()
        .ok_or("original HTTP/1 peer missing before join")?;

    let joined = peer.await;
    drop(server.take());

    joined?
}

pub(super) async fn collect_peer<T: Send + 'static, O>(
    caller: TestResult<O>,
    server: Option<Server<T>>,
) -> TestResult<O> {
    let Some(mut server) = server else {
        return caller;
    };

    let ready = poll_fn(|context| match Pin::new(&mut server).poll(context) {
        Poll::Ready(result) => Poll::Ready(Some(result)),
        Poll::Pending => Poll::Ready(None),
    })
    .await;

    let requested = ready.is_none() && !server.is_finished();
    if requested {
        server.abort();
    }

    let joined = match ready {
        Some(result) => Ok(result),
        None => timeout(TEST_TIMEOUT, &mut server).await.map_err(|elapsed| {
            FixtureDeadline::new("HTTP/1 peer cleanup exceeded deadline", elapsed)
        }),
    };

    let cleanup = match joined {
        Ok(Ok(result)) => result.map(|_| ()),
        Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
        Ok(Err(error)) => Err(error.into()),
        Err(error) => Err(error.into()),
    };

    finish_with_cleanup(caller, cleanup)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod queued_tests;

#[cfg(test)]
mod budget_tests;
