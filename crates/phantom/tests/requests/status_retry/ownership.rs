use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};

use btls::ssl::SslAcceptor;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::watch,
    task::AbortHandle,
    time::timeout,
};
use tokio_btls::SslStream;

use crate::support::deadline::FixtureDeadline;
use super::{ScriptedServer, TestResult, accept_tls_stream, is_peer_gone};

const LIMIT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, Default)]
pub(super) struct State {
    pub(super) abort: Option<AbortHandle>,
    read_pending: bool,
    tls_pending: bool,
    flushed: bool,
    fault_taken: bool,
    destroyed: bool,
}

#[derive(Debug)]
struct ServingFailure(Arc<()>);

impl fmt::Display for ServingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected status-retry serving failure")
    }
}

impl Error for ServingFailure {}

enum Mode {
    Healthy,
    FailFlush,
}

pub(super) struct Control {
    state: watch::Sender<State>,
    flush_failure: Option<io::Error>,
}

pub(super) struct Lifetime(watch::Sender<State>);

impl Drop for Lifetime {
    fn drop(&mut self) {
        self.0.send_modify(|state| state.destroyed = true);
    }
}

impl Control {
    pub(super) fn state(&self) -> watch::Sender<State> {
        self.state.clone()
    }

    pub(super) fn lifetime(&self) -> Lifetime {
        Lifetime(self.state.clone())
    }
}

pub(super) async fn accept_tls(
    tcp: TcpStream,
    acceptor: SslAcceptor,
    control: &mut Option<Control>,
) -> TestResult<SslStream<TcpStream>> {
    let accepted = accept_tls_stream(tcp, acceptor);
    tokio::pin!(accepted);

    poll_fn(|context| {
        let result = accepted.as_mut().poll(context);
        if result.is_pending()
            && let Some(control) = &*control
        {
            control.state.send_modify(|state| state.tls_pending = true);
        }

        result
    })
    .await
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
            control.state.send_modify(|state| state.read_pending = true);
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
            control.state.send_modify(|state| state.flushed = true);

            if let Some(error) = control.flush_failure.take() {
                // The real response bytes were flushed before this fault.
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
        let flush_failure = matches!(mode, Mode::FailFlush).then(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                ServingFailure(Arc::clone(&marker)),
            )
        });

        (
            Control {
                state,
                flush_failure,
            },
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
        timeout(LIMIT, async {
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

        let read = timeout(LIMIT, stream.read(&mut [0_u8; 1]))
            .await
            .map_err(|elapsed| FixtureDeadline::new(socket_purpose, elapsed))?;
        assert!(matches!(read, Ok(0)) || matches!(read, Err(ref error) if is_peer_gone(error)));
        Ok(())
    }

    async fn backup_stop(&mut self) -> TestResult {
        let abort = self
            .state
            .borrow()
            .abort
            .clone()
            .ok_or("child was not accepted")?;

        abort.abort();

        self.wait(
            "status retry backup child destruction exceeded its deadline",
            |state| state.destroyed,
        )
        .await
    }

    fn serving_error(&self, result: TestResult) -> TestResult {
        let error = result
            .err()
            .ok_or("status-retry serving failure was discarded")?;

        let io = error
            .downcast_ref::<io::Error>()
            .ok_or("missing original serving I/O cause")?;
        assert_eq!(io.kind(), io::ErrorKind::PermissionDenied);

        let failure = io
            .get_ref()
            .and_then(|error| error.downcast_ref::<ServingFailure>())
            .ok_or("missing original serving payload")?;
        assert!(Arc::ptr_eq(&failure.0, &self.marker));
        Ok(())
    }
}

async fn pending(
    acceptor: Option<SslAcceptor>,
) -> TestResult<(ScriptedServer, TcpStream, Observation)> {
    let (control, mut observation) = Observation::control(Mode::Healthy);
    let tls = acceptor.is_some();
    let server = ScriptedServer::start_observed(&[super::OK], acceptor, Some(control)).await?;
    let stream = TcpStream::connect(server.address).await?;

    observation
        .wait(
            if tls {
                "status retry accepted TLS child pending prerequisite exceeded its deadline"
            } else {
                "status retry accepted TCP child pending prerequisite exceeded its deadline"
            },
            |state| {
                state.abort.is_some()
                    && if tls {
                        state.tls_pending
                    } else {
                        state.read_pending
                    }
            },
        )
        .await?;

    Ok((server, stream, observation))
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use btls::ssl::SslAcceptor;
    use http::StatusCode;
    use http_body_util::BodyExt;
    use phantom::{HttpProtocol, RequestError, RequestErrorKind};

    use super::super::{H1_ALPN, OK, TestIdentity, plain_builder, request_lines};
    use super::{Mode, Observation, ScriptedServer, TestResult, pending};
    use crate::support::tunnel_proxy::finish_with_cleanup;

    #[tokio::test]
    async fn server_drop_closes_an_actual_pending_tcp_child() -> TestResult {
        drop_pending(None).await
    }

    #[tokio::test]
    async fn server_drop_closes_an_actual_pending_tls_child() -> TestResult {
        let identity = TestIdentity::generate()?;
        drop_pending(Some(identity.acceptor(H1_ALPN)?)).await
    }

    #[tokio::test]
    async fn caller_failure_closes_an_actual_pending_tcp_child() -> TestResult {
        caller_failure(None).await
    }

    #[tokio::test]
    async fn caller_failure_closes_an_actual_pending_tls_child() -> TestResult {
        let identity = TestIdentity::generate()?;
        caller_failure(Some(identity.acceptor(H1_ALPN)?)).await
    }

    #[tokio::test]
    async fn explicit_backup_abort_destroys_the_actual_pending_child() -> TestResult {
        let (server, mut stream, mut observation) = pending(None).await?;

        observation.backup_stop().await?;
        observation
            .closed(
                &mut stream,
                "status retry backup child destruction observation exceeded its deadline",
                "status retry backup socket closure exceeded its deadline",
            )
            .await?;
        server.finish(Ok(())).await
    }

    #[tokio::test]
    async fn an_observed_actual_response_keeps_its_original_request_and_body() -> TestResult {
        let (control, mut observation) = Observation::control(Mode::Healthy);
        let server = ScriptedServer::start_observed(&[OK], None, Some(control)).await?;

        let caller = exchange(&server).await;
        observation
            .wait(
                "status retry healthy child completion exceeded its deadline",
                |state| state.destroyed,
            )
            .await?;
        assert!(observation.state.borrow().flushed);
        assert!(!observation.state.borrow().fault_taken);

        server.finish(caller).await
    }

    #[tokio::test]
    async fn completion_retains_the_actual_post_flush_serving_failure() -> TestResult {
        let (control, mut observation) = Observation::control(Mode::FailFlush);
        let server = ScriptedServer::start_observed(&[OK], None, Some(control)).await?;

        let caller = exchange(&server).await;
        assert!(
            caller.is_ok(),
            "the actual response failed before completion: {caller:?}"
        );

        observation
            .wait(
                "status retry flush fault consumption and child completion exceeded its deadline",
                |state| state.fault_taken && state.destroyed,
            )
            .await?;
        assert!(observation.state.borrow().flushed);

        observation.serving_error(server.finish(caller).await)
    }

    async fn drop_pending(acceptor: Option<SslAcceptor>) -> TestResult {
        let (server, mut stream, mut observation) = pending(acceptor).await?;

        drop(server);

        let observed = observation
            .closed(
                &mut stream,
                "status retry child destruction after server drop exceeded its deadline",
                "status retry socket closure after server drop exceeded its deadline",
            )
            .await;
        let backup = observation.backup_stop().await;
        finish_with_cleanup(observed, backup)
    }

    async fn caller_failure(acceptor: Option<SslAcceptor>) -> TestResult {
        let (server, mut stream, mut observation) = pending(acceptor).await?;

        let caller: TestResult = async {
            let client = plain_builder().build()?;

            let _response = client
                .get(HttpProtocol::Http1, "http://127.0.0.1/invalid uri")?
                .send()
                .await?;
            Ok(())
        }
        .await;

        let error = server
            .finish(caller)
            .await
            .err()
            .ok_or("invalid caller URI succeeded")?;

        let request = error
            .downcast_ref::<RequestError>()
            .ok_or("original caller type changed")?;
        assert_eq!(request.kind(), RequestErrorKind::InvalidUri);
        assert!(
            request
                .source()
                .is_some_and(|source| source.is::<http::uri::InvalidUri>())
        );

        let observed = observation
            .closed(
                &mut stream,
                "status retry child destruction after caller failure exceeded its deadline",
                "status retry socket closure after caller failure exceeded its deadline",
            )
            .await;
        let backup = observation.backup_stop().await;
        finish_with_cleanup(observed, backup)
    }

    async fn exchange(server: &ScriptedServer) -> TestResult {
        let client = plain_builder().build()?;

        let response = client
            .get(HttpProtocol::Http1, &server.url("http", "/observed"))?
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");

        assert_eq!(
            request_lines(&server.received()),
            ["GET /observed HTTP/1.1"]
        );
        Ok(())
    }
}
