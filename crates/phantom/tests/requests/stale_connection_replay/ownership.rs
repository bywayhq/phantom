use std::{
    error::Error,
    fmt, io,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::AbortHandle,
    time::{Instant, timeout, timeout_at},
};

use super::{
    EXTRA_CONNECTION_WINDOW, PRIMING_RESPONSE, ReceivedRequest, TEST_TIMEOUT, TestResult,
    is_peer_gone, read_head, read_request,
};
use crate::support::deadline::FixtureDeadline;
use crate::support::tunnel_proxy::connection_peer::ConnectionPeer;
use crate::support::tunnel_proxy::finish_with_cleanup;

pub(super) type Server = ConnectionPeer<TestResult<(ReceivedRequest, bool)>>;

pub(super) async fn complete<T: Send + 'static>(
    server: &mut Option<ConnectionPeer<TestResult<T>>>,
    caller: TestResult,
    deadline: Instant,
) -> TestResult<T> {
    let Some(mut server) = server.take() else {
        return match caller {
            Ok(()) => Err("original stale server missing".into()),
            Err(error) => Err(error),
        };
    };

    // A finished foreign cancellation stays an error. Concurrent aborts of an
    // unfinished task cannot identify which cancellation request won.
    let mut requested = caller.is_err() && !server.is_finished();
    if requested {
        server.abort();
    }

    let join_deadline = if caller.is_ok() {
        deadline
    } else {
        Instant::now() + TEST_TIMEOUT
    };

    match timeout_at(join_deadline, &mut server).await {
        Ok(Ok(result)) => match caller {
            Ok(()) => result,
            Err(primary) => finish_with_cleanup(Err(primary), result.map(|_| ())),
        },
        Ok(Err(error)) => match caller {
            Ok(()) => Err(error.into()),
            Err(primary) => {
                let cleanup = if requested && error.is_cancelled() {
                    Ok(())
                } else {
                    Err(error.into())
                };

                finish_with_cleanup(Err(primary), cleanup)
            }
        },
        Err(elapsed) => {
            let purpose = if caller.is_ok() {
                "stale-connection replay test exceeded its deadline"
            } else {
                "stale-replay original worker completion exceeded its deadline"
            };
            let deadline_error = FixtureDeadline::new(purpose, elapsed).into();
            let failure = match caller {
                Ok(()) => Err(deadline_error),
                Err(primary) => finish_with_cleanup(Err(primary), Err(deadline_error)),
            };

            if !server.is_finished() {
                requested = true;
                server.abort();
            }

            let cleanup = match timeout(TEST_TIMEOUT, &mut server).await {
                Ok(Ok(result)) => result.map(|_| ()),
                Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
                Ok(Err(error)) => Err(error.into()),
                Err(elapsed) => Err(FixtureDeadline::new(
                    "stale-replay original worker final cleanup exceeded its deadline",
                    elapsed,
                )
                .into()),
            };

            finish_with_cleanup(failure, cleanup)
        }
    }
}

pub(super) async fn spawn_single_stale_server(
    control: Option<Control>,
) -> TestResult<(SocketAddr, Server)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let state = control.as_ref().map(|control| control.state.clone());
    let server = ConnectionPeer::from_task(tokio::spawn(async move {
        let _lifetime = control
            .as_ref()
            .map(|control| Lifetime(control.state.clone()));

        let stale = serve_stale_connection(&listener, control).await?;
        let extra = timeout(EXTRA_CONNECTION_WINDOW, listener.accept()).await;
        Ok((stale, extra.is_err()))
    }));

    if let Some(state) = state {
        state.send_modify(|state| state.abort = Some(server.abort_handle()));
    }

    Ok((address, server))
}

/// Answers the priming request, then reads the next request on the same
/// connection and closes it without any response byte.
pub(super) async fn serve_stale_connection(
    listener: &TcpListener,
    control: Option<Control>,
) -> TestResult<ReceivedRequest> {
    let (stream, _) = listener.accept().await?;
    let mut stream = ObservedStream { stream, control };
    let priming = read_request(&mut stream).await?;
    assert!(priming.head.starts_with(b"GET /prime HTTP/1.1\r\n"));

    stream.write_all(PRIMING_RESPONSE).await?;
    stream.flush().await?;

    let stale = read_request(&mut stream).await?;
    // Every request byte was read, so dropping the socket sends FIN, not RST.
    drop(stream);
    Ok(stale)
}

#[derive(Clone, Default)]
struct State {
    abort: Option<AbortHandle>,
    primed: bool,
    stale_read_pending: bool,
    fault_taken: bool,
    destroyed: bool,
    backup_requested: Arc<AtomicBool>,
}

#[derive(Debug)]
struct ServingFailure(Arc<()>);

impl fmt::Display for ServingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected stale-replay serving failure")
    }
}

impl Error for ServingFailure {}

#[derive(Clone, Copy)]
enum Mode {
    Healthy,
    FailPrimeFlush,
}

pub(super) struct Control {
    state: watch::Sender<State>,
    fault: Option<io::Error>,
}

impl Control {
    pub(super) fn lifetime(&self) -> Lifetime {
        Lifetime(self.state.clone())
    }

    pub(super) fn abort_registration(&self) -> impl FnOnce(AbortHandle) + use<> {
        let state = self.state.clone();

        move |abort| state.send_modify(|state| state.abort = Some(abort))
    }
}

pub(super) struct Lifetime(watch::Sender<State>);

impl Drop for Lifetime {
    fn drop(&mut self) {
        self.0.send_modify(|state| state.destroyed = true);
    }
}

pub(super) struct ObservedStream<S> {
    stream: S,
    control: Option<Control>,
}

impl<S> ObservedStream<S> {
    pub(super) fn new(stream: S, control: Option<Control>) -> Self {
        Self { stream, control }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ObservedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.stream).poll_read(context, buffer);
        if result.is_pending()
            && let Some(control) = &this.control
        {
            control.state.send_modify(|state| {
                if state.primed {
                    state.stale_read_pending = true;
                }
            });
        }

        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ObservedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(context, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(Pin::new(&mut this.stream).poll_flush(context))?;

        if let Some(control) = &mut this.control {
            control.state.send_modify(|state| state.primed = true);

            if let Some(error) = control.fault.take() {
                // The real priming response has been flushed before this fault.
                control.state.send_modify(|state| state.fault_taken = true);
                return Poll::Ready(Err(error));
            }
        }

        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
    }
}

struct Observation {
    state: watch::Receiver<State>,
    marker: Arc<()>,
}

impl Drop for Observation {
    fn drop(&mut self) {
        if let Some(abort) = &self.state.borrow().abort {
            abort.abort();
        }
    }
}

impl Observation {
    fn control(mode: Mode) -> (Control, Self) {
        let (state, received) = watch::channel(State::default());
        let marker = Arc::new(());
        let fault = match mode {
            Mode::Healthy => None,
            Mode::FailPrimeFlush => Some(io::Error::new(
                io::ErrorKind::PermissionDenied,
                ServingFailure(Arc::clone(&marker)),
            )),
        };

        (
            Control { state, fault },
            Self {
                state: received,
                marker,
            },
        )
    }

    async fn wait(
        &mut self,
        purpose: &'static str,
        predicate: impl Fn(&State) -> bool,
    ) -> TestResult {
        timeout(TEST_TIMEOUT, async {
            loop {
                if predicate(&self.state.borrow()) {
                    return TestResult::Ok(());
                }

                self.state.changed().await?;
            }
        })
        .await
        .map_err(|elapsed| FixtureDeadline::new(purpose, elapsed))?
    }

    async fn closed<S: AsyncRead + Unpin>(
        &mut self,
        stream: &mut S,
        destruction_purpose: &'static str,
        socket_purpose: &'static str,
    ) -> TestResult {
        self.wait(destruction_purpose, |state| state.destroyed)
            .await?;

        let read = timeout(TEST_TIMEOUT, stream.read(&mut [0_u8; 1]))
            .await
            .map_err(|elapsed| FixtureDeadline::new(socket_purpose, elapsed))?;

        match read {
            Ok(0) => Ok(()),
            Err(error) if is_peer_gone(&error) => Ok(()),
            Err(error) => Err(error.into()),
            Ok(_) => Err("stale-replay target socket returned bytes instead of closing".into()),
        }
    }

    fn no_backup(&self) -> TestResult {
        if self.state.borrow().backup_requested.load(Ordering::Acquire) {
            return Err("stale-replay target observation occurred after backup".into());
        }

        Ok(())
    }

    async fn backup(
        &mut self,
        server: &mut Option<Server>,
        stream: Option<&mut TcpStream>,
    ) -> TestResult {
        let abort = self
            .state
            .borrow()
            .abort
            .clone()
            .ok_or("original stale server abort handle missing")?;

        // Marks the explicit backup call, not an observed target shutdown.
        self.state
            .borrow()
            .backup_requested
            .store(true, Ordering::Release);
        abort.abort();

        let joined = if let Some(server) = server.take() {
            match timeout(TEST_TIMEOUT, server).await {
                Ok(Ok(result)) => result.map(|_| ()),
                Ok(Err(error)) if error.is_cancelled() => Ok(()),
                Ok(Err(error)) => Err(error.into()),
                Err(elapsed) => Err(FixtureDeadline::new(
                    "stale-replay backup original join exceeded its deadline",
                    elapsed,
                )
                .into()),
            }
        } else {
            Ok(())
        };

        let closed = match stream {
            Some(stream) => {
                self.closed(
                    stream,
                    "stale-replay backup destruction exceeded its deadline",
                    "stale-replay backup socket closure exceeded its deadline",
                )
                .await
            }
            None => {
                self.wait(
                    "stale-replay backup destruction exceeded its deadline",
                    |state| state.destroyed,
                )
                .await
            }
        };
        finish_with_cleanup(joined, closed)
    }

    fn serving_cause(&self, error: &(dyn Error + Send + Sync + 'static)) -> TestResult {
        let io = error
            .downcast_ref::<io::Error>()
            .ok_or("original stale serving I/O type lost")?;

        if io.kind() != io::ErrorKind::PermissionDenied {
            return Err("original stale serving I/O kind changed".into());
        }

        let marker = io
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<ServingFailure>())
            .ok_or("original stale serving payload lost")?;

        if !Arc::ptr_eq(&marker.0, &self.marker) {
            return Err("original stale serving payload identity changed".into());
        }

        Ok(())
    }
}

async fn pending() -> TestResult<(SocketAddr, Option<Server>, TcpStream, Observation)> {
    let (control, mut observation) = Observation::control(Mode::Healthy);
    let (address, server) = spawn_single_stale_server(Some(control)).await?;
    let mut server = Some(server);

    let setup = async {
        let mut stream = TcpStream::connect(address).await?;
        stream
            .write_all(b"GET /prime HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await?;
        let response = timeout(TEST_TIMEOUT, read_head(&mut stream))
            .await
            .map_err(|elapsed| {
                FixtureDeadline::new(
                    "stale-replay actual priming response exceeded its deadline",
                    elapsed,
                )
            })??;

        if response != b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n" {
            return Err("actual stale-replay priming response changed".into());
        }

        observation
            .wait(
                "stale-replay actual post-prime read Pending prerequisite exceeded its deadline",
                |state| state.primed && state.stale_read_pending && state.abort.is_some(),
            )
            .await?;
        TestResult::Ok(stream)
    }
    .await;

    match setup {
        Ok(stream) => Ok((address, server, stream, observation)),
        Err(error) => {
            let cleanup = observation.backup(&mut server, None).await;
            finish_with_cleanup(Err(error), cleanup)
        }
    }
}

#[cfg(test)]
mod mixed_deadline_tests;

#[cfg(test)]
mod raw_fixture;

#[cfg(test)]
mod raw_tests;

#[cfg(test)]
mod tests;
