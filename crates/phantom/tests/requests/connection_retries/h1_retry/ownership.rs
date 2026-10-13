use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};

use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, RequestError, ResponseInfo, RetryPolicy, profile::ClientProfile,
};
use phantom_testkit::tcp::ReservedPort;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::{oneshot, watch},
    task::AbortHandle,
    time::timeout,
};

use crate::support::tunnel_proxy::finish_with_cleanup;

use super::{Exchange, OutcomeSubscriber, RequestResult, ServerOutput, TestResult};

const LIMIT: Duration = Duration::from_secs(5);
const OBSERVATION_LIMIT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, Default)]
struct State {
    request_pending_after_body: bool,
    request_destroyed: bool,
    server_pending: bool,
    server_destroyed: bool,
    body_read: bool,
    head: Vec<u8>,
    framed: Vec<u8>,
    flushed: bool,
    fault_taken: bool,
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Healthy,
    HoldResponse,
    FailWrite,
    FailFlush,
}

#[derive(Debug)]
struct FailureIdentity;

#[derive(Debug)]
struct ServingFailure(Arc<FailureIdentity>);

impl fmt::Display for ServingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected retry server write failure")
    }
}

impl Error for ServingFailure {}

pub(in super::super) struct RequestControl {
    state: watch::Sender<State>,
    body_notice: oneshot::Receiver<()>,
}

struct RequestLife(watch::Sender<State>);

impl Drop for RequestLife {
    fn drop(&mut self) {
        self.0.send_modify(|state| state.request_destroyed = true);
    }
}

pub(super) async fn observe_request(
    request: impl Future<Output = RequestResult>,
    control: Option<RequestControl>,
) -> RequestResult {
    let Some(control) = control else {
        return request.await;
    };
    let _life = RequestLife(control.state.clone());
    tokio::pin!(request);
    let observed = poll_fn(|context| {
        let result = request.as_mut().poll(context);
        let body_read = control.state.borrow().body_read;
        if result.is_pending() && body_read {
            control
                .state
                .send_modify(|state| state.request_pending_after_body = true);
        }
        result
    });
    tokio::pin!(observed);

    // The server's actual body read wakes this wrapper for a fresh original poll.
    // Channel cancellation is only a wake hint; the original result still wins.
    tokio::select! {
        result = &mut observed => result,
        _notice = control.body_notice => observed.await,
    }
}

pub(in super::super) struct Control {
    state: watch::Sender<State>,
    mode: Mode,
    body_notice: Option<oneshot::Sender<()>>,
    release: oneshot::Receiver<()>,
    released: bool,
    fault: Option<io::Error>,
}

impl Control {
    fn wait(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.released {
            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut self.release).poll(context) {
            Poll::Pending => {
                self.state.send_modify(|state| state.server_pending = true);
                Poll::Pending
            }
            Poll::Ready(Ok(())) => {
                self.released = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(io::Error::other(error))),
        }
    }

    fn failure(&mut self) -> io::Result<io::Error> {
        let error = self
            .fault
            .take()
            .ok_or_else(|| io::Error::other("configured original write fault missing"))?;
        self.state.send_modify(|state| state.fault_taken = true);
        Ok(error)
    }
}

pub(super) struct ObservedStream {
    stream: TcpStream,
    control: Option<Control>,
}

impl ObservedStream {
    pub(super) fn new(stream: TcpStream, control: Option<Control>) -> Self {
        Self { stream, control }
    }

    pub(super) fn body_read(&mut self, head: &[u8], framed: &[u8]) {
        if let Some(control) = &mut self.control {
            control.state.send_modify(|state| {
                state.body_read = true;
                state.head = head.to_vec();
                state.framed = framed.to_vec();
            });
            if let Some(notice) = control.body_notice.take() {
                // A finished original request no longer needs the poll wake hint.
                let _ = notice.send(());
            }
        }
    }
}

impl Drop for ObservedStream {
    fn drop(&mut self) {
        if let Some(control) = &self.control {
            control
                .state
                .send_modify(|state| state.server_destroyed = true);
        }
    }
}

impl AsyncRead for ObservedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for ObservedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(control) = &mut this.control {
            match control.mode {
                Mode::HoldResponse => ready!(control.wait(context))?,
                Mode::FailWrite => return Poll::Ready(Err(control.failure()?)),
                Mode::Healthy | Mode::FailFlush => {}
            }
        }
        Pin::new(&mut this.stream).poll_write(context, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(Pin::new(&mut this.stream).poll_flush(context))?;
        if let Some(control) = &mut this.control {
            control.state.send_modify(|state| state.flushed = true);
            if matches!(control.mode, Mode::FailFlush) {
                ready!(control.wait(context))?;
                return Poll::Ready(Err(control.failure()?));
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
    }
}

struct Backup {
    exchange: Option<Exchange>,
    request_abort: Option<AbortHandle>,
    server_abort: Option<AbortHandle>,
    client: Option<Client>,
    state: watch::Receiver<State>,
    release: Option<oneshot::Sender<()>>,
    address: Option<SocketAddr>,
    subscriber: OutcomeSubscriber,
}

impl Drop for Backup {
    fn drop(&mut self) {
        if let Some(abort) = &self.request_abort {
            abort.abort();
        }
        if let Some(abort) = &self.server_abort {
            abort.abort();
        }
    }
}

impl Backup {
    fn prepare(mode: Mode) -> (Self, RequestControl, Control, Arc<FailureIdentity>) {
        let identity = Arc::new(FailureIdentity);
        let fault = matches!(mode, Mode::FailWrite | Mode::FailFlush).then(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                ServingFailure(Arc::clone(&identity)),
            )
        });
        let (state, observed) = watch::channel(State::default());
        let (body_notice, notice) = oneshot::channel();
        let (release, released) = oneshot::channel();
        (
            Self {
                exchange: None,
                request_abort: None,
                server_abort: None,
                client: None,
                state: observed,
                release: Some(release),
                address: None,
                subscriber: OutcomeSubscriber::default(),
            },
            RequestControl {
                state: state.clone(),
                body_notice: notice,
            },
            Control {
                state,
                mode,
                body_notice: Some(body_notice),
                release: released,
                released: false,
                fault,
            },
            identity,
        )
    }

    async fn start(&mut self, request: RequestControl, server: Control) -> TestResult<()> {
        let reserved = ReservedPort::bind()?;
        let address = reserved.address();
        self.address = Some(address);
        self.client = Some(
            Client::builder(ClientProfile::new(super::super::tls_settings()))
                .retry_policy(RetryPolicy::none())
                .build()?,
        );
        self.exchange = Some(super::start(
            address,
            self.client.as_ref().ok_or("actual retry client missing")?,
            &self.subscriber,
            Some(request),
        )?);
        self.request_abort = Some(
            self.exchange
                .as_ref()
                .ok_or("original exchange missing")?
                .request
                .as_ref()
                .ok_or("original request missing")?
                .abort_handle(),
        );

        super::super::wait_for_retry_reason(&self.subscriber).await?;
        let listener = reserved.listen()?;
        let exchange = self.exchange.as_mut().ok_or("original exchange missing")?;
        exchange.listen(listener, Some(server));
        self.server_abort = Some(
            exchange
                .server
                .as_ref()
                .ok_or("original server missing")?
                .abort_handle(),
        );
        Ok(())
    }

    async fn pending(&mut self) -> TestResult<()> {
        timeout(
            LIMIT,
            self.state.wait_for(|state| {
                state.body_read && state.server_pending && state.request_pending_after_body
            }),
        )
        .await??;
        if self
            .request_abort
            .as_ref()
            .ok_or("original request witness missing")?
            .is_finished()
            || self
                .server_abort
                .as_ref()
                .ok_or("original server witness missing")?
                .is_finished()
        {
            return Err("original retry task completed before its pending operation".into());
        }
        Ok(())
    }

    async fn caller(&mut self) -> TestResult<()> {
        let response = timeout(
            LIMIT,
            self.exchange
                .as_mut()
                .ok_or("original exchange missing")?
                .response(),
        )
        .await??;
        assert_eq!(response.status(), http::StatusCode::NO_CONTENT);
        let info = response
            .extensions()
            .get::<ResponseInfo>()
            .ok_or("response omitted retry metadata")?;
        assert_eq!(info.protocol(), HttpProtocol::Http1);
        assert_eq!(info.retries_performed(), 1);
        timeout(LIMIT, response.into_body().collect()).await??;
        Ok(())
    }

    fn release(&mut self) -> TestResult<()> {
        self.release
            .take()
            .ok_or("original response release missing")?
            .send(())
            .map_err(|_| "original server stopped before response release".into())
    }

    async fn server_finished(&mut self) -> TestResult<()> {
        timeout(
            OBSERVATION_LIMIT,
            self.state.wait_for(|state| state.server_destroyed),
        )
        .await??;
        wait_finished(
            self.server_abort
                .as_ref()
                .ok_or("original server witness missing")?,
        )
        .await
    }

    async fn destroyed(&mut self) -> TestResult<()> {
        timeout(
            OBSERVATION_LIMIT,
            self.state
                .wait_for(|state| state.request_destroyed && state.server_destroyed),
        )
        .await??;
        wait_finished(
            self.request_abort
                .as_ref()
                .ok_or("original request witness missing")?,
        )
        .await?;
        wait_finished(
            self.server_abort
                .as_ref()
                .ok_or("original server witness missing")?,
        )
        .await?;
        let address = self.address.ok_or("original retry address missing")?;
        // A closed connection can leave its port in TIME_WAIT after task teardown.
        let refused = timeout(LIMIT, TcpStream::connect(address))
            .await?
            .err()
            .ok_or("original retry listener still accepts connections")?;
        if refused.kind() != io::ErrorKind::ConnectionRefused {
            return Err(refused.into());
        }
        Ok(())
    }

    async fn collect(&mut self, caller: TestResult<()>) -> TestResult<ServerOutput> {
        let exchange = self.exchange.take().ok_or("original exchange missing")?;
        let ((), output) = timeout(LIMIT, exchange.finish(caller)).await??;
        Ok(output)
    }

    async fn stop(&mut self) -> TestResult<()> {
        let mut result = Ok(());
        if let Some(mut exchange) = self.exchange.take() {
            if let Some(mut request) = exchange.request.take() {
                let requested = !request.is_finished();
                if requested {
                    request.abort();
                }
                let joined = match timeout(LIMIT, &mut request).await {
                    Ok(Ok(outcome)) => outcome.map(|_| ()).map_err(Into::into),
                    Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
                    Ok(Err(error)) => Err(error.into()),
                    Err(error) => Err(error.into()),
                };
                result = finish_with_cleanup(result, joined);
            }
            if let Some(mut server) = exchange.server.take() {
                let requested = !server.is_finished();
                if requested {
                    server.abort();
                }
                let joined = match timeout(LIMIT, &mut server).await {
                    Ok(Ok(outcome)) => outcome.map(|_| ()),
                    Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
                    Ok(Err(error)) => Err(error.into()),
                    Err(error) => Err(error.into()),
                };
                result = finish_with_cleanup(result, joined);
            }
        }
        for abort in [&self.request_abort, &self.server_abort]
            .into_iter()
            .flatten()
        {
            if !abort.is_finished() {
                abort.abort();
            }
            result = finish_with_cleanup(result, wait_finished(abort).await);
        }
        drop(self.client.take());
        result
    }
}

async fn wait_finished(abort: &AbortHandle) -> TestResult<()> {
    timeout(LIMIT, async {
        while !abort.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}

fn retains_fault(error: &(dyn Error + 'static), identity: &Arc<FailureIdentity>) -> TestResult<()> {
    let original = error
        .downcast_ref::<io::Error>()
        .ok_or("original retry write error was discarded")?;
    if original.kind() != io::ErrorKind::PermissionDenied {
        return Err("original retry write error kind changed".into());
    }
    let cause = original
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<ServingFailure>())
        .ok_or("original retry write cause was discarded")?;
    if !Arc::ptr_eq(&cause.0, identity) {
        return Err("original retry write cause identity changed".into());
    }
    Ok(())
}

mod tests;
