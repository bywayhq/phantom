use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    net::Ipv4Addr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use btls::ssl::SslAcceptor;
use bytes::Bytes;
use http_body::Body;
use http_body_util::{BodyExt, Collected};
use phantom::{Client, HttpProtocol, RequestError, RequestErrorKind, ResponseBody};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::{AbortHandle, yield_now},
    time::timeout,
};
use tokio_btls::SslStream;

use super::{TEST_TIMEOUT, TestResult};
use crate::support::deadline::FixtureDeadline;
use crate::support::tls::{H1_ALPN, TestIdentity, accept_tls, client_builder, read_head};
use crate::support::tunnel_proxy::connection_peer::ConnectionPeer;
use crate::support::tunnel_proxy::finish_with_cleanup;

pub(super) type Server = ConnectionPeer<TestResult>;

pub(super) fn spawn(
    listener: TcpListener,
    acceptor: SslAcceptor,
    control: Option<Control>,
) -> Server {
    let state = control.as_ref().map(|control| control.state.clone());
    let server = ConnectionPeer::from_task(tokio::spawn(async move {
        let _lifetime = control
            .as_ref()
            .map(|control| Lifetime(control.state.clone()));
        let stream = accept_tls(listener, acceptor).await?;
        let mut stream = ObservedStream { stream, control };
        read_head(&mut stream).await?;

        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx")
            .await?;

        std::future::pending::<()>().await;
        TestResult::Ok(())
    }));

    if let Some(state) = state {
        state.send_modify(|state| state.abort = Some(server.abort_handle()));
    }

    server
}

pub(super) async fn complete(
    server: &mut Option<Server>,
    caller: impl Future<Output = TestResult>,
) -> TestResult {
    let mut server = server.take().ok_or("original total-body server missing")?;

    let caller = caller.await;

    let requested = !server.is_finished();
    if requested {
        server.abort();
    }

    let cleanup = match timeout(TEST_TIMEOUT, &mut server).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
        Ok(Err(error)) => Err(error.into()),
        Err(elapsed) => Err(FixtureDeadline::new(
            "total-body original worker completion exceeded its deadline",
            elapsed,
        )
        .into()),
    };

    finish_with_cleanup(caller, cleanup)
}

pub(super) async fn collect_body(
    body: ResponseBody,
    observation: Option<&Observation>,
) -> TestResult<Result<Collected<Bytes>, RequestError>> {
    if let Some(observation) = observation {
        observation.collect_pending.store(false, Ordering::Release);
    }

    let mut collection = std::pin::pin!(body.collect());
    let collection = poll_fn(|context| {
        let result = collection.as_mut().poll(context);

        if result.is_pending()
            && let Some(observation) = observation
        {
            observation.collect_pending.store(true, Ordering::Release);
        }

        result
    });

    timeout(TEST_TIMEOUT, collection).await.map_err(|elapsed| {
        FixtureDeadline::new("response body did not observe its total deadline", elapsed).into()
    })
}

#[derive(Clone, Default)]
struct State {
    abort: Option<AbortHandle>,
    partial_written: bool,
    fault_taken: bool,
    destroyed: bool,
    backup_requested: Arc<AtomicBool>,
}

#[derive(Debug)]
struct ServingFailure(Arc<()>);

impl fmt::Display for ServingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected total-body response write failure")
    }
}

impl Error for ServingFailure {}

#[derive(Clone, Copy)]
enum Mode {
    Healthy,
    FailPartialWrite,
}

pub(super) struct Control {
    state: watch::Sender<State>,
    fault: Option<io::Error>,
    written: usize,
}

struct Lifetime(watch::Sender<State>);

impl Drop for Lifetime {
    fn drop(&mut self) {
        self.0.send_modify(|state| state.destroyed = true);
    }
}

struct ObservedStream {
    stream: SslStream<TcpStream>,
    control: Option<Control>,
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
        let result = Pin::new(&mut this.stream).poll_write(context, bytes);

        if let Poll::Ready(Ok(written)) = result
            && let Some(control) = &mut this.control
        {
            control.written += written;
            if control.written == b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx".len() {
                control
                    .state
                    .send_modify(|state| state.partial_written = true);

                if let Some(error) = control.fault.take() {
                    // The original partial response was written by the real TLS stream.
                    control.state.send_modify(|state| state.fault_taken = true);
                    return Poll::Ready(Err(error));
                }
            }
        }

        result
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
    }
}

pub(super) struct Observation {
    state: watch::Receiver<State>,
    marker: Arc<()>,
    collect_pending: AtomicBool,
    peer_closed: bool,
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
            Mode::FailPartialWrite => Some(io::Error::new(
                io::ErrorKind::PermissionDenied,
                ServingFailure(Arc::clone(&marker)),
            )),
        };

        (
            Control {
                state,
                fault,
                written: 0,
            },
            Self {
                state: received,
                marker,
                collect_pending: AtomicBool::new(false),
                peer_closed: false,
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

    async fn closed(
        &mut self,
        body: &mut ResponseBody,
        destruction_purpose: &'static str,
        body_purpose: &'static str,
    ) -> TestResult {
        self.wait(destruction_purpose, |state| state.destroyed)
            .await?;

        if self.peer_closed {
            return Ok(());
        }

        let frame = timeout(TEST_TIMEOUT, body.frame())
            .await
            .map_err(|elapsed| FixtureDeadline::new(body_purpose, elapsed))?;

        match frame {
            Some(Err(error)) if error.kind() == RequestErrorKind::Http1 => {
                self.peer_closed = true;
                Ok(())
            }
            Some(Err(error)) => Err(error.into()),
            _ => Err("actual incomplete total body did not report peer closure".into()),
        }
    }

    fn no_backup(&self) -> TestResult {
        if self.state.borrow().backup_requested.load(Ordering::Acquire) {
            return Err("total-body target observation occurred after backup".into());
        }

        Ok(())
    }

    async fn backup(
        &mut self,
        server: &mut Option<Server>,
        body: Option<&mut ResponseBody>,
    ) -> TestResult {
        let abort = self
            .state
            .borrow()
            .abort
            .clone()
            .ok_or("original total-body server abort handle missing")?;

        // Marks the explicit backup call, not observed target completion.
        self.state
            .borrow()
            .backup_requested
            .store(true, Ordering::Release);
        let requested = !abort.is_finished();
        if requested {
            abort.abort();
        }

        let joined = if let Some(server) = server.take() {
            match timeout(TEST_TIMEOUT, server).await {
                Ok(Ok(result)) => result,
                Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
                Ok(Err(error)) => Err(error.into()),
                Err(elapsed) => Err(FixtureDeadline::new(
                    "total-body backup original join exceeded its deadline",
                    elapsed,
                )
                .into()),
            }
        } else {
            Ok(())
        };

        let closed = match body {
            Some(body) => {
                self.closed(
                    body,
                    "total-body backup destruction exceeded its deadline",
                    "total-body backup peer closure exceeded its deadline",
                )
                .await
            }
            None => {
                self.wait(
                    "total-body backup destruction exceeded its deadline",
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
            .ok_or("original total-body serving I/O type lost")?;

        if io.kind() != io::ErrorKind::PermissionDenied {
            return Err("original total-body serving I/O kind changed".into());
        }

        let marker = io
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<ServingFailure>())
            .ok_or("original total-body serving payload lost")?;

        if !Arc::ptr_eq(&marker.0, &self.marker) {
            return Err("original total-body serving payload identity changed".into());
        }

        Ok(())
    }
}

async fn partial_response(
    mode: Mode,
) -> TestResult<(Option<Server>, Client, ResponseBody, Observation)> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let (control, mut observation) = Observation::control(mode);
    let mut server = Some(spawn(listener, acceptor, Some(control)));

    let setup = async {
        let client = client_builder(&identity, false).build()?;
        let response = timeout(
            TEST_TIMEOUT,
            client
                .get(HttpProtocol::Http1, &format!("https://{address}/stalled"))?
                .send(),
        )
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new("actual total-body response head timed out", elapsed)
        })??;

        if response.status() != http::StatusCode::OK
            || !response
                .headers()
                .get("content-length")
                .is_some_and(|value| value == "2")
        {
            return Err("actual total-body response head changed".into());
        }

        let mut body = response.into_body();
        let frame = timeout(TEST_TIMEOUT, body.frame())
            .await
            .map_err(|elapsed| {
                FixtureDeadline::new("actual total-body first frame timed out", elapsed)
            })?
            .ok_or("actual total-body first frame missing")??;

        let bytes = frame
            .into_data()
            .map_err(|_| "actual total-body first frame was not data")?;

        if bytes.as_ref() != b"x" {
            return Err("actual total-body first byte changed".into());
        }

        observation
            .wait(
                "actual total-body partial write prerequisite timed out",
                |state| state.partial_written && state.abort.is_some(),
            )
            .await?;

        if matches!(mode, Mode::Healthy) {
            poll_fn(|context| match Pin::new(&mut body).poll_frame(context) {
                Poll::Pending => Poll::Ready(TestResult::Ok(())),
                Poll::Ready(Some(Err(error))) => Poll::Ready(Err(error.into())),
                Poll::Ready(_) => Poll::Ready(Err("actual total body was not Pending".into())),
            })
            .await?;
        }

        TestResult::Ok((client, body))
    }
    .await;

    match setup {
        Ok((client, body)) => Ok((server, client, body, observation)),
        Err(error) => {
            let cleanup = observation.backup(&mut server, None).await;
            finish_with_cleanup(Err(error), cleanup)
        }
    }
}

async fn completed(server: &Option<Server>, purpose: &'static str) -> TestResult {
    timeout(TEST_TIMEOUT, async {
        while !server
            .as_ref()
            .ok_or("original total-body task missing")?
            .is_finished()
        {
            yield_now().await;
        }

        TestResult::Ok(())
    })
    .await
    .map_err(|elapsed| FixtureDeadline::new(purpose, elapsed))?
}

#[cfg(test)]
mod tests;
