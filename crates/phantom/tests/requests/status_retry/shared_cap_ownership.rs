use std::{
    error::Error,
    fmt,
    future::Future,
    io,
    net::SocketAddr,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};

use http::StatusCode;
use http_body_util::BodyExt;
use phantom::{HttpProtocol, RedirectPolicy, ResponseInfo, RetryPolicy};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::{AbortHandle, JoinError},
    time::{Instant, timeout, timeout_at},
};

use super::{
    OK, ReceivedRequest, TestResult, UNAVAILABLE, is_peer_gone, plain_builder, read_request,
    request_lines, status_retry,
};
use crate::support::deadline::FixtureDeadline;
use crate::support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup};

const OBSERVATION_LIMIT: Duration = Duration::from_secs(2);

type Records = [ReceivedRequest; 5];
type Peer = ConnectionPeer<TestResult<Records>>;

pub(super) async fn exchange() -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(10);
    let (address, server) = timeout_at(deadline, start_server(None)).await??;
    let records = complete(deadline, server, request(address)).await?;

    assert_eq!(
        request_lines(&records),
        [
            "GET /prime HTTP/1.1",
            "GET /start HTTP/1.1",
            "GET /start HTTP/1.1",
            "GET /start HTTP/1.1",
            "GET /final HTTP/1.1",
        ]
    );
    Ok(())
}

async fn complete(
    deadline: Instant,
    mut server: Peer,
    caller: impl Future<Output = TestResult>,
) -> TestResult<Records> {
    let mut serving = None;
    let operation = timeout_at(deadline, async {
        caller.await?;
        serving = Some((&mut server).await);
        TestResult::Ok(())
    })
    .await;

    let caller = match operation {
        Ok(result) => result,
        Err(elapsed) => Err(elapsed.into()),
    };

    let serving = match serving {
        Some(joined) => serving_outcome(joined, false),
        None => collect_server(&mut server, caller.is_err()).await,
    };
    let (records, cleanup) = match serving {
        Ok(records) => (records, Ok(())),
        Err(error) => (None, Err(error)),
    };

    finish_with_cleanup(caller, cleanup)?;
    records.ok_or_else(|| "shared-cap original request records missing".into())
}

async fn collect_server(server: &mut Peer, stop: bool) -> TestResult<Option<Records>> {
    let mut requested = stop && !server.is_finished();
    if requested {
        server.abort();
    }

    match timeout(OBSERVATION_LIMIT, &mut *server).await {
        Ok(joined) => serving_outcome(joined, requested),
        Err(elapsed) => {
            if !server.is_finished() {
                server.abort();
                requested = true;
            }

            let cleanup = match timeout(OBSERVATION_LIMIT, server).await {
                Ok(joined) => serving_outcome(joined, requested).map(|_| ()),
                Err(elapsed) => Err(FixtureDeadline::new(
                    "shared-cap backup task collection exceeded its deadline",
                    elapsed,
                )
                .into()),
            };

            finish_with_cleanup(
                Err(FixtureDeadline::new(
                    "shared-cap task collection exceeded its deadline",
                    elapsed,
                )
                .into()),
                cleanup,
            )
        }
    }
}

fn serving_outcome(
    joined: Result<TestResult<Records>, JoinError>,
    requested: bool,
) -> TestResult<Option<Records>> {
    match joined {
        Ok(result) => result.map(Some),
        Err(error) if requested && error.is_cancelled() => Ok(None),
        Err(error) => Err(error.into()),
    }
}

async fn start_server(control: Option<Control>) -> TestResult<(SocketAddr, Peer)> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let state = control.as_ref().map(|control| control.state.clone());
    let server = ConnectionPeer::spawn(async move {
        let _lifetime = control
            .as_ref()
            .map(|control| Lifetime(control.state.clone()));

        let (first, _) = listener.accept().await?;
        let mut first = ObservedStream {
            stream: first,
            control,
        };
        let prime = read_request(&mut first).await?;
        first.write_all(OK.as_bytes()).await?;
        first.flush().await?;

        let stale = read_request(&mut first).await?;
        drop(first);

        let (mut second, _) = listener.accept().await?;
        let replayed = read_request(&mut second).await?;
        second.write_all(UNAVAILABLE.as_bytes()).await?;
        second.flush().await?;

        let status_retried = read_request(&mut second).await?;
        second
            .write_all(b"HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\n\r\n")
            .await?;
        second.flush().await?;

        let redirected = read_request(&mut second).await?;
        second.write_all(UNAVAILABLE.as_bytes()).await?;
        second.flush().await?;
        Ok([prime, stale, replayed, status_retried, redirected])
    });

    if let Some(state) = state {
        state.send_modify(|state| state.abort = Some(server.abort_handle()));
    }

    Ok((address, server))
}

async fn request(address: SocketAddr) -> TestResult {
    let client = plain_builder()
        .redirect_policy(RedirectPolicy::limited(
            NonZeroUsize::new(5).ok_or("redirect limit is zero")?,
        ))
        .retry_policy(
            RetryPolicy::none()
                .with_reused_connection_replay(true)
                .with_status_retry(status_retry(3, Duration::ZERO)?)
                .with_max_retries(Some(2)),
        )
        .build()?;

    client
        .get_with_protocol(HttpProtocol::Http1, &format!("http://{address}/prime"))?
        .send()
        .await?
        .into_body()
        .collect()
        .await?;

    let response = client
        .get_with_protocol(HttpProtocol::Http1, &format!("http://{address}/start"))?
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let info = response
        .extensions()
        .get::<ResponseInfo>()
        .ok_or("response omitted metadata")?;
    assert_eq!(info.retries_performed(), 0);
    response.into_body().collect().await?;
    Ok(())
}

#[derive(Clone, Default)]
struct State {
    abort: Option<AbortHandle>,
    read_pending: bool,
    flushed: bool,
    fault_taken: bool,
    destroyed: bool,
    backup_requested: Arc<AtomicBool>,
}

#[derive(Debug)]
struct ServingFailure(Arc<()>);

impl fmt::Display for ServingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected shared-cap serving failure")
    }
}

impl Error for ServingFailure {}

enum Mode {
    Healthy,
    FailPrimeFlush,
}

struct Control {
    state: watch::Sender<State>,
    fault: Option<io::Error>,
}

struct Lifetime(watch::Sender<State>);

impl Drop for Lifetime {
    fn drop(&mut self) {
        self.0.send_modify(|state| state.destroyed = true);
    }
}

struct ObservedStream {
    stream: TcpStream,
    control: Option<Control>,
}

impl AsyncRead for ObservedStream {
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
            control.state.send_modify(|state| state.read_pending = true);
        }

        result
    }
}

impl AsyncWrite for ObservedStream {
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
            control.state.send_modify(|state| state.flushed = true);

            if let Some(error) = control.fault.take() {
                // The actual prime response has been flushed before this fault.
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
        timeout(OBSERVATION_LIMIT, async {
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

    async fn closed(
        &mut self,
        stream: &mut TcpStream,
        destruction_purpose: &'static str,
        socket_purpose: &'static str,
    ) -> TestResult {
        self.wait(destruction_purpose, |state| state.destroyed)
            .await?;

        let read = timeout(OBSERVATION_LIMIT, stream.read(&mut [0_u8; 1]))
            .await
            .map_err(|elapsed| FixtureDeadline::new(socket_purpose, elapsed))?;

        match read {
            Ok(0) => Ok(()),
            Err(error) if is_peer_gone(&error) => Ok(()),
            Err(error) => Err(error.into()),
            Ok(_) => Err("shared-cap socket returned bytes instead of closing".into()),
        }
    }

    async fn backup_stop(&mut self, stream: &mut TcpStream) -> TestResult {
        let abort = self
            .state
            .borrow()
            .abort
            .clone()
            .ok_or("shared-cap server abort handle was not published")?;

        // This marks the explicit backup abort, not target completion.
        self.state
            .borrow()
            .backup_requested
            .store(true, Ordering::Release);
        abort.abort();

        self.closed(
            stream,
            "shared-cap backup server destruction exceeded its deadline",
            "shared-cap backup socket closure exceeded its deadline",
        )
        .await
    }

    fn serving_cause(&self, error: &(dyn Error + Send + Sync + 'static)) -> TestResult {
        let io = error
            .downcast_ref::<io::Error>()
            .ok_or("shared-cap original serving I/O cause was lost")?;

        if io.kind() != io::ErrorKind::PermissionDenied {
            return Err("shared-cap original serving I/O kind changed".into());
        }

        let failure = io
            .get_ref()
            .and_then(|error| error.downcast_ref::<ServingFailure>())
            .ok_or("shared-cap original serving payload was lost")?;

        if !Arc::ptr_eq(&failure.0, &self.marker) {
            return Err("shared-cap original serving payload identity changed".into());
        }

        Ok(())
    }
}

async fn pending() -> TestResult<(SocketAddr, Peer, TcpStream, Observation)> {
    let (control, mut observation) = Observation::control(Mode::Healthy);
    let (address, server) = start_server(Some(control)).await?;
    let stream = TcpStream::connect(address).await?;

    observation
        .wait(
            "shared-cap accepted TCP read pending prerequisite exceeded its deadline",
            |state| state.abort.is_some() && state.read_pending,
        )
        .await?;
    Ok((address, server, stream, observation))
}

#[cfg(test)]
mod tests;
