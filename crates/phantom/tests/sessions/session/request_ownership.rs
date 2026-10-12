use std::{
    error::Error,
    future::{Future, poll_fn},
    io,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

use phantom::{Client, RequestError, RequestErrorKind};
use tokio::{
    net::TcpListener,
    sync::{Barrier, oneshot, watch},
    task::{AbortHandle, JoinHandle},
    time::{Instant, timeout_at},
};

use crate::support::deadline::FixtureDeadline;

use super::{
    H2_ALPN, TEST_TIMEOUT, TestIdentity, TestResult, bounded, reuse_ownership, send,
    send_after_barrier, test_client,
};

#[derive(Clone, Debug, Default)]
struct HeldState {
    requests: Vec<(u32, String)>,
    read_pending: bool,
    driver_pending: bool,
    destroyed: bool,
    closed: bool,
    completed_error: Option<(io::ErrorKind, String)>,
}

#[derive(Clone, Debug)]
pub(super) struct HoldObservation(watch::Sender<HeldState>);

impl HoldObservation {
    pub(super) fn read_pending(&self) {
        self.0.send_modify(|state| state.read_pending = true);
    }

    pub(super) fn destroyed(&self) {
        self.0.send_modify(|state| state.destroyed = true);
    }

    pub(super) fn closed(&self) {
        self.0.send_modify(|state| state.closed = true);
    }

    pub(super) fn completed(&self, result: &TestResult<reuse_ownership::Requests>) {
        if let Err(error) = result
            && let Some(error) = error.downcast_ref::<::http2::Error>()
            && let Some(error) = error.get_io()
        {
            self.0.send_modify(|state| {
                state.completed_error = Some((error.kind(), error.to_string()));
            });
        }
    }
}

pub(super) struct ResponseHold {
    release: oneshot::Receiver<()>,
    observed: HoldObservation,
}

impl ResponseHold {
    pub(super) fn observation(&self) -> HoldObservation {
        self.observed.clone()
    }

    pub(super) fn accepted(&self, requests: &[(u32, String)]) {
        self.observed.0.send_modify(|state| {
            state.requests = requests.to_vec();
            state.read_pending = false;
        });
    }

    pub(super) fn driver_pending(&self) {
        self.observed.0.send_modify(|state| state.driver_pending = true);
    }

    pub(super) fn poll_release(&mut self, context: &mut Context<'_>) -> Poll<TestResult<()>> {
        Pin::new(&mut self.release).poll(context).map(|result| result.map_err(Into::into))
    }
}

#[derive(Clone, Debug, Default)]
struct RequestState {
    pending: [bool; 2],
    ready: [bool; 2],
    kinds: [Option<RequestErrorKind>; 2],
    syntax_sources: [bool; 2],
    destroyed: [bool; 2],
    tasks: Vec<AbortHandle>,
}

#[derive(Clone, Debug)]
struct RequestObservation(watch::Sender<RequestState>);

struct RequestLife {
    observed: RequestObservation,
    index: usize,
}

impl Drop for RequestLife {
    fn drop(&mut self) {
        self.observed.0.send_modify(|state| state.destroyed[self.index] = true);
    }
}

struct RequestControl {
    observed: RequestObservation,
    collect_after: oneshot::Receiver<()>,
    targets: Option<[String; 2]>,
}

struct RequestInputs {
    targets: [String; 2],
    observed: Option<RequestObservation>,
    collect_after: Option<oneshot::Receiver<()>>,
}

fn spawn_request(
    request: impl Future<Output = TestResult<()>> + Send + 'static,
    observed: Option<RequestObservation>,
    index: usize,
) -> JoinHandle<TestResult<()>> {
    let Some(observed) = observed else {
        return tokio::spawn(request);
    };

    let task_observed = observed.clone();
    let task = tokio::spawn(async move {
        let _life = RequestLife { observed: task_observed.clone(), index };
        let mut request = Box::pin(request);
        let result = poll_fn(|context| {
            let result = request.as_mut().poll(context);
            if result.is_pending() {
                task_observed.0.send_modify(|state| state.pending[index] = true);
            }
            result
        }).await;
        task_observed.0.send_modify(|state| {
            state.ready[index] = true;
            if let Err(error) = &result
                && let Some(original) = error.downcast_ref::<RequestError>()
            {
                state.kinds[index] = Some(original.kind());
                state.syntax_sources[index] = original.source()
                    .is_some_and(|source| source.is::<http::uri::InvalidUri>());
            }
        });
        result
    });
    observed.0.send_modify(|state| state.tasks.push(task.abort_handle()));
    task
}

async fn cold_requests(
    session: &Client,
    address: SocketAddr,
    control: Option<RequestControl>,
) -> TestResult<()> {
    let RequestInputs { targets, observed, collect_after } = request_inputs(address, control);
    let start = std::sync::Arc::new(Barrier::new(3));
    let [first_target, second_target] = targets;
    let first = spawn_request(
        send_after_barrier(session.clone(), first_target, start.clone()),
        observed.clone(),
        0,
    );
    let second = spawn_request(
        send_after_barrier(session.clone(), second_target, start.clone()),
        observed,
        1,
    );
    start.wait().await;

    if let Some(collect_after) = collect_after {
        collect_after.await?;
    }
    first.await??;
    second.await??;
    Ok(())
}

async fn independent_requests(
    first_client: Client,
    second_client: Client,
    address: SocketAddr,
    control: Option<RequestControl>,
) -> TestResult<()> {
    let RequestInputs { targets, observed, collect_after } = request_inputs(address, control);
    let [first_target, second_target] = targets;
    let first = spawn_request(send(first_client, first_target), observed.clone(), 0);
    let second = spawn_request(send(second_client, second_target), observed, 1);

    if let Some(collect_after) = collect_after {
        collect_after.await?;
    }
    first.await??;
    second.await??;
    Ok(())
}

fn request_inputs(
    address: SocketAddr,
    control: Option<RequestControl>,
) -> RequestInputs {
    let defaults = [format!("https://{address}/first"), format!("https://{address}/second")];
    match control {
        Some(control) => RequestInputs {
            targets: control.targets.unwrap_or(defaults),
            observed: Some(control.observed),
            collect_after: Some(control.collect_after),
        },
        None => RequestInputs { targets: defaults, observed: None, collect_after: None },
    }
}

async fn finish_cold(caller: TestResult<()>, server: reuse_ownership::Server) -> TestResult<reuse_ownership::Requests> {
    caller?;
    Ok(server.await??)
}

pub(super) async fn cold() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = reuse_ownership::spawn_server(listener, acceptor, 2, None);

        let session = test_client(&identity, true)?;
        let caller = cold_requests(&session, address, None).await;
        drop(session);

        let requests = finish_cold(caller, server).await?;
        let mut stream_ids = requests
            .iter()
            .map(|(stream_id, _)| *stream_id)
            .collect::<Vec<_>>();
        stream_ids.sort_unstable();
        let mut paths = requests
            .into_iter()
            .map(|(_, path)| path)
            .collect::<Vec<_>>();
        paths.sort_unstable();
        assert_eq!(stream_ids, [1, 3]);
        assert_eq!(paths, vec!["/first".to_owned(), "/second".to_owned()]);
        Ok(())
    })
    .await
}

pub(super) async fn independent() -> TestResult<()> {
    let deadline = Instant::now() + TEST_TIMEOUT;
    let (identity, address, server) = timeout_at(deadline, async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = reuse_ownership::spawn_independent(listener, acceptor, None);
        Ok::<_, Box<dyn Error + Send + Sync>>((identity, address, server))
    })
    .await
    .map_err(|elapsed| FixtureDeadline::new("session test exceeded its deadline", elapsed))??;

    let caller = match timeout_at(deadline, async {
        let first_client = test_client(&identity, true)?;
        let second_client = test_client(&identity, true)?;
        independent_requests(first_client, second_client, address, None).await
    })
    .await
    {
        Ok(result) => result,
        Err(elapsed) => Err(FixtureDeadline::new("session test exceeded its deadline", elapsed).into()),
    };

    let mut connections = reuse_ownership::collect_independent(caller, server).await?;
    connections.sort_unstable();
    assert_eq!(
        connections,
        [
            vec![(1, "/first".to_owned())],
            vec![(1, "/second".to_owned())]
        ]
    );
    Ok(())
}

mod tests;
