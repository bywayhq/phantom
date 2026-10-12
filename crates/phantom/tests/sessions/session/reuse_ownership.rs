use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    task::{Context, Poll},
};

use btls::ssl::SslAcceptor;
use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{oneshot, watch},
    task::{AbortHandle, JoinError},
    time::{error::Elapsed, timeout},
};
use tokio_btls::SslStream;

use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{ConnectionPeer, connection_peer::FixtureFailures, finish_with_cleanup},
};

use super::{TEST_TIMEOUT, TestResult, accept_tls, request_ownership, serve_requests, serve_requests_held};

pub(super) type Requests = Vec<(u32, String)>;
pub(super) type Server = ConnectionPeer<TestResult<Requests>>;
type ServerJoin = Result<Result<TestResult<Requests>, JoinError>, Elapsed>;

struct ReuseChild {
    server: Server,
    requested: bool,
}

impl ReuseChild {
    fn new(server: Server) -> Self {
        Self {
            server,
            requested: false,
        }
    }

    fn request_stop(&mut self) {
        request_stop(&self.server.abort_handle(), &mut self.requested);
    }
}

pub(super) struct IndependentServer {
    task: ConnectionPeer<TestResult<Option<[Requests; 2]>>>,
    stop: Option<oneshot::Sender<()>>,
}

impl IndependentServer {
    pub(super) fn abort_handle(&self) -> AbortHandle {
        self.task.abort_handle()
    }

    pub(super) fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    fn request_shutdown(&mut self) {
        if !self.is_finished()
            && let Some(stop) = self.stop.take()
        {
            // A receiver that already ended is still observed by the original join.
            let _ = stop.send(());
        }
    }
}

impl Future for IndependentServer {
    type Output = Result<TestResult<Option<[Requests; 2]>>, JoinError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.get_mut().task).poll(context)
    }
}

#[derive(Clone, Debug, Default)]
struct State {
    closed_pending: bool,
    fault_taken: bool,
    destroyed: bool,
    children: Vec<AbortHandle>,
    second_accept_pending: bool,
    second_accept_failed: bool,
    second_accept_held: bool,
    second_accept_error_and_shutdown_ready: bool,
    coordinator_destroyed: bool,
}

#[derive(Clone, Debug)]
pub(super) struct Observation(watch::Sender<State>);

pub(super) struct Control {
    observed: Observation,
    fault: Option<io::Error>,
    armed: oneshot::Receiver<()>,
}

pub(super) struct Stream {
    stream: SslStream<TcpStream>,
    control: Option<Control>,
    held: Option<request_ownership::HoldObservation>,
}

impl Stream {
    fn new(stream: SslStream<TcpStream>, control: Option<Control>) -> Self {
        Self { stream, control, held: None }
    }

    fn holding(mut self, hold: Option<&request_ownership::ResponseHold>) -> Self {
        self.held = hold.map(request_ownership::ResponseHold::observation);
        self
    }

    pub(super) fn observation(&self) -> Option<Observation> {
        self.control
            .as_ref()
            .map(|control| control.observed.clone())
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        if let Some(control) = &self.control {
            control
                .observed
                .0
                .send_modify(|state| state.destroyed = true);
        }
        if let Some(held) = &self.held {
            held.destroyed();
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        let can_read = buffer.remaining() != 0;
        let result = Pin::new(&mut this.stream).poll_read(context, buffer);
        if let Some(held) = &this.held {
            match &result {
                Poll::Pending => held.read_pending(),
                Poll::Ready(Ok(())) if can_read && before == buffer.filled().len() => held.closed(),
                _ => {}
            }
        }
        if result.is_pending()
            && let Some(control) = &mut this.control
            && control.fault.is_some()
            && matches!(
                Pin::new(&mut control.armed).poll(context),
                Poll::Ready(Ok(()))
            )
            && let Some(error) = control.fault.take()
        {
            control
                .observed
                .0
                .send_modify(|state| state.fault_taken = true);
            return Poll::Ready(Err(error));
        }

        result
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(context, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
    }
}

pub(super) fn poll_closed(
    connection: &mut ::http2::server::Connection<Stream, Bytes>,
    observed: Option<&Observation>,
    context: &mut Context<'_>,
) -> Poll<Result<(), ::http2::Error>> {
    let result = connection.poll_closed(context);
    if result.is_pending()
        && let Some(observed) = observed
    {
        observed.0.send_modify(|state| state.closed_pending = true);
    }

    result
}

pub(super) fn spawn_server(
    listener: TcpListener,
    acceptor: SslAcceptor,
    count: usize,
    control: Option<Control>,
) -> Server {
    spawn_server_held(listener, acceptor, count, control, None)
}

pub(super) fn spawn_server_held(
    listener: TcpListener,
    acceptor: SslAcceptor,
    count: usize,
    control: Option<Control>,
    hold: Option<request_ownership::ResponseHold>,
) -> Server {
    ConnectionPeer::spawn(async move {
        let stream = accept_tls(&listener, &acceptor).await?;
        serve_held(stream, count, control, hold).await
    })
}

async fn serve_held(
    stream: SslStream<TcpStream>,
    count: usize,
    control: Option<Control>,
    hold: Option<request_ownership::ResponseHold>,
) -> TestResult<Requests> {
    let observed = hold.as_ref().map(request_ownership::ResponseHold::observation);
    let stream = Stream::new(stream, control).holding(hold.as_ref());
    let result = match hold {
        Some(hold) => serve_requests_held(stream, count, Some(hold)).await,
        None => serve_requests(stream, count).await,
    };
    if let Some(observed) = observed {
        observed.completed(&result);
    }
    result
}

pub(super) fn request_fault_control(fault: io::Error, armed: oneshot::Receiver<()>) -> Control {
    let (state, _) = watch::channel(State::default());
    Control { observed: Observation(state), fault: Some(fault), armed }
}

pub(super) async fn collect(caller: TestResult<()>, server: Server) -> TestResult<Requests> {
    let mut child = ReuseChild::new(server);
    if caller.is_err() {
        child.request_stop();
    }

    let joined = timeout(TEST_TIMEOUT, &mut child.server).await;
    let result = complete_server_join(&mut child, joined).await;
    let mut requests = None;
    let cleanup = match result {
        Ok(value) => {
            requests = value;
            Ok(())
        }
        Err(error) => Err(error),
    };
    finish_with_cleanup(caller, cleanup)?;

    requests.ok_or_else(|| "reuse server cancelled without a failure".into())
}

struct CoordinatorLife(Option<Observation>);

impl Drop for CoordinatorLife {
    fn drop(&mut self) {
        if let Some(observed) = &self.0 {
            observed
                .0
                .send_modify(|state| state.coordinator_destroyed = true);
        }
    }
}

pub(super) fn spawn_independent(
    listener: TcpListener,
    acceptor: SslAcceptor,
    control: Option<Control>,
) -> IndependentServer {
    spawn_independent_observed(listener, acceptor, control, None, None, None)
}

pub(super) fn spawn_independent_held(
    listener: TcpListener,
    acceptor: SslAcceptor,
    holds: [request_ownership::ResponseHold; 2],
) -> IndependentServer {
    spawn_independent_controlled(listener, acceptor, None, None, None, None, holds.map(Some))
}

fn spawn_independent_observed(
    listener: TcpListener,
    acceptor: SslAcceptor,
    control: Option<Control>,
    second_control: Option<Control>,
    collect_after: Option<oneshot::Receiver<()>>,
    second_accept_after: Option<oneshot::Receiver<()>>,
) -> IndependentServer {
    spawn_independent_controlled(listener, acceptor, control, second_control, collect_after,
        second_accept_after, [None, None])
}

fn spawn_independent_controlled(
    listener: TcpListener,
    acceptor: SslAcceptor,
    control: Option<Control>,
    second_control: Option<Control>,
    collect_after: Option<oneshot::Receiver<()>>,
    second_accept_after: Option<oneshot::Receiver<()>>,
    holds: [Option<request_ownership::ResponseHold>; 2],
) -> IndependentServer {
    let [first_hold, second_hold] = holds;
    let (shutdown, mut stop) = oneshot::channel();
    let task = ConnectionPeer::spawn(async move {
        let observed = control.as_ref().map(|control| control.observed.clone());
        let _life = CoordinatorLife(observed.clone());
        let first = tokio::select! {
            biased;
            result = accept_tls(&listener, &acceptor) => result?,
            _ = &mut stop => return Ok(None),
        };
        let mut first = ReuseChild::new(ConnectionPeer::spawn(serve_held(first, 1, control, first_hold)));
        if let Some(observed) = &observed {
            observed
                .0
                .send_modify(|state| state.children.push(first.server.abort_handle()));
        }

        let accepting = accept_tls(&listener, &acceptor);
        tokio::pin!(accepting);
        let second = poll_fn(|context| {
            let result = accepting.as_mut().poll(context);
            if let Some(observed) = &observed {
                if result.is_pending() {
                    observed
                        .0
                        .send_modify(|state| state.second_accept_pending = true);
                } else if matches!(&result, Poll::Ready(Err(_))) {
                    observed
                        .0
                        .send_modify(|state| state.second_accept_failed = true);
                }
            }

            result
        });
        tokio::pin!(second);
        let mut held = None;
        if let Some(released) = second_accept_after {
            // Retain the sole actual accept result before controls queue shutdown.
            held = Some(second.as_mut().await);
            if let Some(observed) = &observed {
                observed
                    .0
                    .send_modify(|state| state.second_accept_held = true);
            }
            if let Err(error) = released.await {
                first.request_stop();
                let joined = timeout(TEST_TIMEOUT, &mut first.server).await;
                let cleanup = complete_server_join(&mut first, joined).await.map(|_| ());
                let acquisition = match held.take() {
                    Some(Err(error)) => Err(error),
                    Some(Ok(_)) => Ok(None),
                    None => Err("original second accept result missing".into()),
                };
                let primary = finish_with_cleanup(acquisition, Err(error.into()));
                return finish_with_cleanup(primary, cleanup);
            }

            if let Some(observed) = &observed {
                let ready = held.as_ref().is_some_and(Result::is_err) && !stop.is_empty();
                observed
                    .0
                    .send_modify(|state| state.second_accept_error_and_shutdown_ready = ready);
            }
        }

        let second = tokio::select! {
            biased;
            result = async {
                match held {
                    Some(result) => result,
                    None => second.as_mut().await,
                }
            } => result.map(Some),
            _ = &mut stop => Ok(None),
        };
        let second = match second {
            Ok(Some(stream)) => stream,
            Ok(None) => {
                first.request_stop();
                let joined = timeout(TEST_TIMEOUT, &mut first.server).await;
                return complete_server_join(&mut first, joined).await.map(|_| None);
            }
            Err(error) => {
                first.request_stop();
                let joined = timeout(TEST_TIMEOUT, &mut first.server).await;
                let cleanup = complete_server_join(&mut first, joined).await.map(|_| ());
                return finish_with_cleanup(Err(error), cleanup);
            }
        };
        let mut second = ReuseChild::new(ConnectionPeer::spawn(serve_held(second, 1, second_control, second_hold)));
        if let Some(observed) = &observed {
            observed
                .0
                .send_modify(|state| state.children.push(second.server.abort_handle()));
        }

        // Controls can hold these original child results until both are observable.
        let mut stopped = false;
        if let Some(collect_after) = collect_after {
            let released = tokio::select! {
                biased;
                released = collect_after => released,
                _ = &mut stop => {
                    stopped = true;
                    Ok(())
                }
            };
            if let Err(error) = released {
                first.request_stop();
                second.request_stop();
                let cleanup = collect_children(first, second, &mut stop, stopped)
                    .await
                    .map(|_| ());
                return finish_with_cleanup(Err(error.into()), cleanup);
            }
        }

        if stopped {
            first.request_stop();
            second.request_stop();
        }
        let [first, second] = collect_children(first, second, &mut stop, stopped).await?;
        if stopped || first.is_none() || second.is_none() {
            return Ok(None);
        }

        Ok(Some([
            first.ok_or("first reuse child cancelled without a failure")?,
            second.ok_or("second reuse child cancelled without a failure")?,
        ]))
    });
    IndependentServer {
        task,
        stop: Some(shutdown),
    }
}

pub(super) async fn collect_independent(
    caller: TestResult<()>,
    mut server: IndependentServer,
) -> TestResult<[Requests; 2]> {
    if caller.is_err() {
        server.request_shutdown();
    }

    let mut requested = false;
    let result = match timeout(TEST_TIMEOUT, &mut server).await {
        Ok(joined) => coordinator_outcome(joined, requested),
        Err(elapsed) => {
            request_stop(&server.abort_handle(), &mut requested);
            let cleanup = match timeout(TEST_TIMEOUT, &mut server).await {
                Ok(joined) => coordinator_outcome(joined, requested).map(|_| ()),
                Err(elapsed) => {
                    Err(FixtureDeadline::new("reuse coordinator did not finish", elapsed).into())
                }
            };
            finish_with_cleanup(
                Err(FixtureDeadline::new("reuse coordinator did not finish", elapsed).into()),
                cleanup,
            )
        }
    };

    let mut requests = None;
    let cleanup = match result {
        Ok(value) => {
            requests = value;
            Ok(())
        }
        Err(error) => Err(error),
    };
    finish_with_cleanup(caller, cleanup)?;

    requests.ok_or_else(|| "reuse coordinator cancelled without a failure".into())
}

async fn collect_children(
    mut first: ReuseChild,
    mut second: ReuseChild,
    stop: &mut oneshot::Receiver<()>,
    mut stopped: bool,
) -> TestResult<[Option<Requests>; 2]> {
    let first_abort = first.server.abort_handle();
    let second_abort = second.server.abort_handle();
    let (first_joined, second_joined) = {
        let first_join = timeout(TEST_TIMEOUT, &mut first.server);
        let second_join = timeout(TEST_TIMEOUT, &mut second.server);
        tokio::pin!(first_join, second_join);
        let mut first_joined = None;
        let mut second_joined = None;
        while first_joined.is_none() || second_joined.is_none() {
            tokio::select! {
                joined = &mut first_join, if first_joined.is_none() => {
                    if !matches!(&joined, Ok(Ok(Ok(_)))) {
                        request_stop(&first_abort, &mut first.requested);
                        request_stop(&second_abort, &mut second.requested);
                    }
                    first_joined = Some(joined);
                }
                joined = &mut second_join, if second_joined.is_none() => {
                    if !matches!(&joined, Ok(Ok(Ok(_)))) {
                        request_stop(&first_abort, &mut first.requested);
                        request_stop(&second_abort, &mut second.requested);
                    }
                    second_joined = Some(joined);
                }
                _ = &mut *stop, if !stopped => {
                    stopped = true;
                    request_stop(&first_abort, &mut first.requested);
                    request_stop(&second_abort, &mut second.requested);
                }
            }
        }
        first_joined
            .zip(second_joined)
            .ok_or("original reuse child joins missing")?
    };

    if !matches!(&first_joined, Ok(Ok(Ok(_)))) || !matches!(&second_joined, Ok(Ok(Ok(_)))) {
        first.request_stop();
        second.request_stop();
    }

    let first_result = complete_server_join(&mut first, first_joined).await;
    let second_result = complete_server_join(&mut second, second_joined).await;
    match (first_result, second_result) {
        (Ok(first), Ok(second)) => Ok([first, second]),
        (Err(primary), Err(cleanup)) => Err(Box::new(FixtureFailures { primary, cleanup })),
        (Err(error), Ok(_)) | (Ok(_), Err(error)) => Err(error),
    }
}

fn request_stop(abort: &AbortHandle, requested: &mut bool) {
    if !abort.is_finished() {
        *requested = true;
        abort.abort();
    }
}

async fn complete_server_join(
    child: &mut ReuseChild,
    joined: ServerJoin,
) -> TestResult<Option<Requests>> {
    match joined {
        Ok(joined) => server_outcome(joined, child.requested),
        Err(elapsed) => {
            child.request_stop();
            let cleanup = match timeout(TEST_TIMEOUT, &mut child.server).await {
                Ok(joined) => server_outcome(joined, child.requested).map(|_| ()),
                Err(elapsed) => {
                    Err(FixtureDeadline::new("reuse server did not finish", elapsed).into())
                }
            };
            finish_with_cleanup(
                Err(FixtureDeadline::new("reuse server did not finish", elapsed).into()),
                cleanup,
            )
        }
    }
}

fn server_outcome(
    joined: Result<TestResult<Requests>, JoinError>,
    requested: bool,
) -> TestResult<Option<Requests>> {
    match joined {
        Ok(result) => result.map(Some),
        Err(error) if requested && error.is_cancelled() => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn coordinator_outcome(
    joined: Result<TestResult<Option<[Requests; 2]>>, JoinError>,
    requested: bool,
) -> TestResult<Option<[Requests; 2]>> {
    match joined {
        Ok(result) => result,
        Err(error) if requested && error.is_cancelled() => Ok(None),
        Err(error) => Err(error.into()),
    }
}

mod tests;
