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
    task::{AbortHandle, JoinHandle},
    time::timeout,
};

use super::{
    OK, ReceivedRequest, TestResult, UNAVAILABLE, is_peer_gone, plain_builder, read_request,
    request_lines, status_retry,
};
use crate::support::deadline::FixtureDeadline;

const OBSERVATION_LIMIT: Duration = Duration::from_secs(2);

type Records = [ReceivedRequest; 5];

pub(super) async fn exchange() -> TestResult {
    bounded(async {
        let (address, server) = start_server(None).await?;
        let records = complete(server, request(address)).await?;

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
    })
    .await
}

async fn bounded<T>(future: impl Future<Output = TestResult<T>>) -> TestResult<T> {
    timeout(Duration::from_secs(10), future).await?
}

async fn complete(
    server: JoinHandle<TestResult<Records>>,
    caller: impl Future<Output = TestResult>,
) -> TestResult<Records> {
    caller.await?;
    server.await?
}

async fn start_server(
    control: Option<Control>,
) -> TestResult<(SocketAddr, JoinHandle<TestResult<Records>>)> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let state = control.as_ref().map(|control| control.state.clone());
    let server = tokio::spawn(async move {
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
        .get(HttpProtocol::Http1, &format!("http://{address}/prime"))?
        .send()
        .await?
        .into_body()
        .collect()
        .await?;

    let response = client
        .get(HttpProtocol::Http1, &format!("http://{address}/start"))?
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
        assert!(matches!(read, Ok(0)) || matches!(read, Err(ref error) if is_peer_gone(error)));
        Ok(())
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
        assert_eq!(io.kind(), io::ErrorKind::PermissionDenied);

        let failure = io
            .get_ref()
            .and_then(|error| error.downcast_ref::<ServingFailure>())
            .ok_or("shared-cap original serving payload was lost")?;
        assert!(Arc::ptr_eq(&failure.0, &self.marker));
        Ok(())
    }
}

async fn pending() -> TestResult<(
    SocketAddr,
    JoinHandle<TestResult<Records>>,
    TcpStream,
    Observation,
)> {
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
mod tests {
    use std::{error::Error, sync::atomic::Ordering};

    use http::StatusCode;
    use http_body_util::BodyExt;
    use phantom::{HttpProtocol, RequestError, RequestErrorKind};
    use tokio::{
        task::yield_now,
        time::{error::Elapsed, timeout},
    };

    use super::{
        Mode, OBSERVATION_LIMIT, Observation, TestResult, bounded, complete, pending,
        plain_builder, start_server,
    };
    use crate::support::deadline::FixtureDeadline;
    use crate::support::tunnel_proxy::connection_peer::FixtureFailures;
    use crate::support::tunnel_proxy::finish_with_cleanup;

    #[tokio::test]
    async fn handle_drop_closes_the_actual_pending_shared_cap_socket() -> TestResult {
        let (_, server, mut stream, mut observation) = pending().await?;

        drop(server);
        let observed = observation
            .closed(
                &mut stream,
                "shared-cap server destruction after handle Drop exceeded its deadline",
                "shared-cap socket closure after handle Drop exceeded its deadline",
            )
            .await;
        assert!(
            !observation
                .state
                .borrow()
                .backup_requested
                .load(Ordering::Acquire)
        );

        let backup = observation.backup_stop(&mut stream).await;
        finish_with_cleanup(observed, backup)
    }

    #[tokio::test]
    async fn caller_failure_closes_the_actual_pending_shared_cap_socket() -> TestResult {
        let (_, server, mut stream, mut observation) = pending().await?;

        let error = complete(server, invalid_uri())
            .await
            .err()
            .ok_or("invalid URI succeeded")?;
        caller_cause(error.as_ref())?;

        let observed = observation
            .closed(
                &mut stream,
                "shared-cap server destruction after caller failure exceeded its deadline",
                "shared-cap socket closure after caller failure exceeded its deadline",
            )
            .await;
        assert!(
            !observation
                .state
                .borrow()
                .backup_requested
                .load(Ordering::Acquire)
        );

        let backup = observation.backup_stop(&mut stream).await;
        finish_with_cleanup(observed, backup)
    }

    #[tokio::test]
    async fn completion_retains_the_actual_shared_cap_prime_flush_error() -> TestResult {
        let (control, mut observation) = Observation::control(Mode::FailPrimeFlush);
        let (address, server) = start_server(Some(control)).await?;

        let result = complete(server, prime_request(address)).await;
        observation
            .wait(
                "shared-cap prime flush fault consumption and destruction exceeded its deadline",
                |state| state.flushed && state.fault_taken && state.destroyed,
            )
            .await?;

        let error = result
            .err()
            .ok_or("shared-cap prime flush error was discarded")?;
        observation.serving_cause(error.as_ref())
    }

    #[tokio::test]
    async fn explicit_backup_abort_closes_the_actual_pending_shared_cap_socket() -> TestResult {
        let (_, server, mut stream, mut observation) = pending().await?;

        observation.backup_stop(&mut stream).await?;
        assert!(
            observation
                .state
                .borrow()
                .backup_requested
                .load(Ordering::Acquire)
        );

        let result = timeout(OBSERVATION_LIMIT, server)
            .await
            .map_err(|elapsed| {
                FixtureDeadline::new("shared-cap backup join exceeded its deadline", elapsed)
            })?;
        assert!(matches!(result, Err(error) if error.is_cancelled()));
        Ok(())
    }

    #[tokio::test]
    async fn completion_retains_the_actual_caller_and_completed_shared_cap_errors() -> TestResult {
        let (control, mut observation) = Observation::control(Mode::FailPrimeFlush);
        let (address, server) = start_server(Some(control)).await?;

        prime_request(address).await?;
        observation
            .wait(
                "shared-cap completed prime flush fault prerequisite exceeded its deadline",
                |state| state.flushed && state.fault_taken && state.destroyed,
            )
            .await?;

        timeout(OBSERVATION_LIMIT, async {
            while !server.is_finished() {
                yield_now().await;
            }
        })
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new(
                "shared-cap original server completion prerequisite exceeded its deadline",
                elapsed,
            )
        })?;

        let error = complete(server, invalid_uri())
            .await
            .err()
            .ok_or("invalid URI succeeded")?;

        let caller = match error.downcast_ref::<FixtureFailures>() {
            Some(failures) => failures.primary.as_ref(),
            None => error.as_ref(),
        };
        caller_cause(caller)?;

        let failures = error
            .downcast_ref::<FixtureFailures>()
            .ok_or("shared-cap caller and completed serving failure were not both retained")?;
        observation.serving_cause(failures.cleanup.as_ref())
    }

    #[tokio::test]
    async fn exchange_deadline_closes_the_actual_pending_shared_cap_socket() -> TestResult {
        let (address, server, mut stream, mut observation) = pending().await?;

        let error = bounded(complete(server, prime_request(address)))
            .await
            .err()
            .ok_or("blocked shared-cap exchange succeeded")?;
        error
            .downcast_ref::<Elapsed>()
            .ok_or("original shared-cap exchange deadline was lost")?;

        let observed = observation
            .closed(
                &mut stream,
                "shared-cap server destruction after exchange deadline exceeded its deadline",
                "shared-cap socket closure after exchange deadline exceeded its deadline",
            )
            .await;
        assert!(
            !observation
                .state
                .borrow()
                .backup_requested
                .load(Ordering::Acquire)
        );

        let backup = observation.backup_stop(&mut stream).await;
        finish_with_cleanup(observed, backup)
    }

    async fn invalid_uri() -> TestResult {
        let client = plain_builder().build()?;

        let _response = client
            .get(HttpProtocol::Http1, "http://127.0.0.1/invalid uri")?
            .send()
            .await?;
        Ok(())
    }

    fn caller_cause(error: &(dyn Error + Send + Sync + 'static)) -> TestResult {
        let request = error
            .downcast_ref::<RequestError>()
            .ok_or("original caller type changed")?;
        assert_eq!(request.kind(), RequestErrorKind::InvalidUri);
        assert!(
            request
                .source()
                .is_some_and(|source| source.is::<http::uri::InvalidUri>())
        );
        Ok(())
    }

    async fn prime_request(address: std::net::SocketAddr) -> TestResult {
        let client = plain_builder().build()?;

        let response = client
            .get(HttpProtocol::Http1, &format!("http://{address}/prime"))?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await?.to_bytes().as_ref(),
            b"ok"
        );
        Ok(())
    }
}
