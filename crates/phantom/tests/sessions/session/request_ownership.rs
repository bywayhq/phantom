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
    time::{Instant, timeout_at},
};

use crate::support::{deadline::FixtureDeadline, tunnel_proxy::finish_with_cleanup};

use super::{
    H2_ALPN, TEST_TIMEOUT, TestIdentity, TestResult, reuse_ownership, send, send_after_barrier,
    test_client,
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
        self.observed
            .0
            .send_modify(|state| state.driver_pending = true);
    }

    pub(super) fn poll_release(&mut self, context: &mut Context<'_>) -> Poll<TestResult<()>> {
        Pin::new(&mut self.release)
            .poll(context)
            .map(|result| result.map_err(Into::into))
    }
}

#[derive(Clone, Debug, Default)]
struct RequestState {
    entered: [bool; 2],
    pending: [bool; 2],
    ready: [bool; 2],
    kinds: [Option<RequestErrorKind>; 2],
    syntax_sources: [bool; 2],
    destroyed: [bool; 2],
}

#[derive(Clone, Debug)]
struct RequestObservation(watch::Sender<RequestState>);

struct RequestLife {
    observed: RequestObservation,
    index: usize,
}

impl Drop for RequestLife {
    fn drop(&mut self) {
        self.observed
            .0
            .send_modify(|state| state.destroyed[self.index] = true);
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

type RequestResults = [Option<TestResult<()>>; 2];

async fn observe_request(
    request: impl Future<Output = TestResult<()>>,
    observed: Option<RequestObservation>,
    index: usize,
) -> TestResult<()> {
    let Some(observed) = observed else {
        return request.await;
    };

    observed.0.send_modify(|state| state.entered[index] = true);
    let _life = RequestLife {
        observed: observed.clone(),
        index,
    };
    tokio::pin!(request);

    let result = poll_fn(|context| {
        let result = request.as_mut().poll(context);
        if result.is_pending() {
            observed.0.send_modify(|state| state.pending[index] = true);
        }

        result
    })
    .await;

    observed.0.send_modify(|state| {
        state.ready[index] = true;
        if let Err(error) = &result
            && let Some(original) = error.downcast_ref::<RequestError>()
        {
            state.kinds[index] = Some(original.kind());
            state.syntax_sources[index] = original
                .source()
                .is_some_and(|source| source.is::<http::uri::InvalidUri>());
        }
    });

    result
}

async fn cold_requests(
    session: &Client,
    address: SocketAddr,
    control: Option<RequestControl>,
) -> TestResult<()> {
    let mut results = [None, None];
    let operation = drive_cold(session, address, control, &mut results).await;

    finish_requests(operation, results)
}

async fn timed_cold_requests(
    deadline: Instant,
    session: &Client,
    address: SocketAddr,
    control: Option<RequestControl>,
) -> TestResult<()> {
    let mut results = [None, None];
    let operation = match timeout_at(
        deadline,
        drive_cold(session, address, control, &mut results),
    )
    .await
    {
        Ok(operation) => operation,
        Err(elapsed) => {
            Err(FixtureDeadline::new("session test exceeded its deadline", elapsed).into())
        }
    };

    finish_requests(operation, results)
}

async fn drive_cold(
    session: &Client,
    address: SocketAddr,
    control: Option<RequestControl>,
    results: &mut RequestResults,
) -> TestResult<()> {
    let RequestInputs {
        targets,
        observed,
        collect_after,
    } = request_inputs(address, control);
    let start = std::sync::Arc::new(Barrier::new(3));
    let [first_target, second_target] = targets;
    let first = observe_request(
        send_after_barrier(session.clone(), first_target, start.clone()),
        observed.clone(),
        0,
    );
    let second = observe_request(
        send_after_barrier(session.clone(), second_target, start.clone()),
        observed,
        1,
    );

    drive_pair(first, second, Some(&start), collect_after, results).await
}

async fn independent_requests(
    first_client: Client,
    second_client: Client,
    address: SocketAddr,
    control: Option<RequestControl>,
) -> TestResult<()> {
    let mut results = [None, None];
    let operation =
        drive_independent(first_client, second_client, address, control, &mut results).await;

    finish_requests(operation, results)
}

async fn drive_independent(
    first_client: Client,
    second_client: Client,
    address: SocketAddr,
    control: Option<RequestControl>,
    results: &mut RequestResults,
) -> TestResult<()> {
    let RequestInputs {
        targets,
        observed,
        collect_after,
    } = request_inputs(address, control);
    let [first_target, second_target] = targets;
    let first = observe_request(send(first_client, first_target), observed.clone(), 0);
    let second = observe_request(send(second_client, second_target), observed, 1);

    drive_pair(first, second, None, collect_after, results).await
}

async fn drive_pair(
    first: impl Future<Output = TestResult<()>>,
    second: impl Future<Output = TestResult<()>>,
    start: Option<&Barrier>,
    mut collect_after: Option<oneshot::Receiver<()>>,
    results: &mut RequestResults,
) -> TestResult<()> {
    let mut started = start.is_none();
    let starting = async {
        if let Some(start) = start {
            start.wait().await;
        }
    };
    tokio::pin!(first, second, starting);

    poll_fn(|context| {
        if results[0].is_none()
            && let Poll::Ready(result) = first.as_mut().poll(context)
        {
            results[0] = Some(result);
        }

        if results[1].is_none()
            && let Poll::Ready(result) = second.as_mut().poll(context)
        {
            results[1] = Some(result);
        }

        if !started {
            started = starting.as_mut().poll(context).is_ready();
            if !started {
                return Poll::Pending;
            }
        }

        if let Some(released) = &mut collect_after {
            match Pin::new(released).poll(context) {
                Poll::Ready(Ok(())) => collect_after = None,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Pending => return Poll::Pending,
            }
        }

        if results.iter().flatten().any(Result::is_err) || results.iter().all(Option::is_some) {
            return Poll::Ready(Ok(()));
        }

        Poll::Pending
    })
    .await
}

fn finish_requests(operation: TestResult<()>, results: RequestResults) -> TestResult<()> {
    let complete = results.iter().all(Option::is_some);
    let [first, second] = results;
    let first = first.and_then(Result::err);
    let second = second.and_then(Result::err);

    let requests = match (first, second) {
        (Some(first), Some(second)) => Some(finish_with_cleanup::<()>(Err(first), Err(second))),
        (Some(error), None) | (None, Some(error)) => Some(Err(error)),
        (None, None) => None,
    };

    match requests {
        Some(requests) => finish_with_cleanup(requests, operation),
        None if operation.is_err() || complete => operation,
        None => Err("request pair ended without both original outcomes".into()),
    }
}

fn request_inputs(address: SocketAddr, control: Option<RequestControl>) -> RequestInputs {
    let defaults = [
        format!("https://{address}/first"),
        format!("https://{address}/second"),
    ];
    match control {
        Some(control) => RequestInputs {
            targets: control.targets.unwrap_or(defaults),
            observed: Some(control.observed),
            collect_after: Some(control.collect_after),
        },
        None => RequestInputs {
            targets: defaults,
            observed: None,
            collect_after: None,
        },
    }
}

async fn finish_cold(
    caller: TestResult<()>,
    server: reuse_ownership::Server,
) -> TestResult<reuse_ownership::Requests> {
    reuse_ownership::collect(caller, server).await
}

pub(super) async fn cold() -> TestResult<()> {
    let deadline = Instant::now() + TEST_TIMEOUT;
    let (identity, address, server) = timeout_at(deadline, async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = reuse_ownership::spawn_server(listener, acceptor, 2, None);
        Ok::<_, Box<dyn Error + Send + Sync>>((identity, address, server))
    })
    .await
    .map_err(|elapsed| FixtureDeadline::new("session test exceeded its deadline", elapsed))??;

    let caller = match test_client(&identity, true) {
        Ok(session) => {
            let result = timed_cold_requests(deadline, &session, address, None).await;
            drop(session);
            result
        }
        Err(error) => Err(error),
    };

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

    let mut results = [None, None];
    let operation = match timeout_at(deadline, async {
        let first_client = test_client(&identity, true)?;
        let second_client = test_client(&identity, true)?;
        drive_independent(first_client, second_client, address, None, &mut results).await
    })
    .await
    {
        Ok(result) => result,
        Err(elapsed) => {
            Err(FixtureDeadline::new("session test exceeded its deadline", elapsed).into())
        }
    };

    let caller = finish_requests(operation, results);

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
