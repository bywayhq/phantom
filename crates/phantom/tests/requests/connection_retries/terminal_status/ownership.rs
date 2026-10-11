use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};

use phantom::{Client, RequestError, RequestErrorKind, RetryPolicy, profile::ClientProfile};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::AbortHandle,
    time::timeout,
};

use crate::support::{tls::is_peer_gone, tunnel_proxy::finish_with_cleanup};

use super::{OutcomeSubscriber, Output, Peer, RESPONSE, TestResult, caller, collect, spawn};

const LIMIT: Duration = Duration::from_secs(5);
const OBSERVATION_LIMIT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, Default)]
struct State {
    read_pending: bool,
    flushed: bool,
    accept_pending: bool,
    fault_taken: bool,
    destroyed: bool,
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Healthy,
    FailFlush,
    FailAccept,
}

#[derive(Debug)]
struct ServingFailure(Arc<()>);

impl fmt::Display for ServingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected terminal-status serving failure")
    }
}

impl Error for ServingFailure {}

pub(in super::super) struct Control {
    state: watch::Sender<State>,
    mode: Mode,
    fault: Option<io::Error>,
}

pub(super) struct Lifetime(watch::Sender<State>);

impl Drop for Lifetime {
    fn drop(&mut self) {
        self.0.send_modify(|state| state.destroyed = true);
    }
}

impl Control {
    pub(super) fn lifetime(&self) -> Lifetime {
        Lifetime(self.state.clone())
    }

    fn failure(&mut self) -> io::Result<io::Error> {
        let error = self
            .fault
            .take()
            .ok_or_else(|| io::Error::other("configured terminal-status serving fault missing"))?;
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

    pub(super) async fn second_accept(
        &mut self,
        listener: &TcpListener,
    ) -> io::Result<(TcpStream, SocketAddr)> {
        let accepted = listener.accept();
        tokio::pin!(accepted);
        poll_fn(|context| {
            let result = accepted.as_mut().poll(context);
            if result.is_pending()
                && let Some(control) = &mut self.control
            {
                control
                    .state
                    .send_modify(|state| state.accept_pending = true);
                if matches!(control.mode, Mode::FailAccept) {
                    return Poll::Ready(Err(control.failure()?));
                }
            }
            result
        })
        .await
    }
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
            && let Some(control) = &mut this.control
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
            if matches!(control.mode, Mode::FailFlush) {
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
    peer: Option<Peer>,
    abort: AbortHandle,
    client: Client,
    stream: Option<TcpStream>,
    state: watch::Receiver<State>,
    address: SocketAddr,
    subscriber: OutcomeSubscriber,
    marker: Arc<()>,
}

impl Drop for Backup {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

impl Backup {
    async fn prepare(mode: Mode) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let client = Client::builder(ClientProfile::new(super::super::tls_settings()))
            .retry_policy(RetryPolicy::connection_failures(
                NonZeroUsize::MIN,
                super::super::RETRY_DELAY,
            ))
            .build()?;
        let marker = Arc::new(());
        let fault = matches!(mode, Mode::FailFlush | Mode::FailAccept).then(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                ServingFailure(Arc::clone(&marker)),
            )
        });
        let (state, observed) = watch::channel(State::default());
        let peer = spawn(listener, Some(Control { state, mode, fault }));
        let abort = peer.abort_handle();
        Ok(Self {
            peer: Some(peer),
            abort,
            client,
            stream: None,
            state: observed,
            address,
            subscriber: OutcomeSubscriber::default(),
            marker,
        })
    }

    async fn pending(&mut self) -> TestResult<()> {
        self.stream = Some(timeout(LIMIT, TcpStream::connect(self.address)).await??);
        timeout(LIMIT, self.state.wait_for(|state| state.read_pending)).await??;
        assert!(
            !self.abort.is_finished(),
            "original terminal peer finished before its read Pending"
        );
        Ok(())
    }

    async fn response(&mut self) -> TestResult<()> {
        let head = format!("GET /terminal HTTP/1.1\r\nHost: {}\r\n\r\n", self.address);
        let stream = self
            .stream
            .as_mut()
            .ok_or("original terminal client socket missing")?;
        timeout(LIMIT, stream.write_all(head.as_bytes())).await??;
        let mut response = vec![0_u8; RESPONSE.len()];
        timeout(LIMIT, stream.read_exact(&mut response)).await??;
        assert_eq!(response, RESPONSE);
        Ok(())
    }

    async fn completed(&mut self) -> TestResult<()> {
        timeout(LIMIT, self.state.wait_for(|state| state.destroyed)).await??;
        wait_finished(&self.abort).await
    }

    async fn destroyed(&mut self) -> TestResult<()> {
        timeout(
            OBSERVATION_LIMIT,
            self.state.wait_for(|state| state.destroyed),
        )
        .await??;
        wait_finished(&self.abort).await?;
        if let Some(stream) = &mut self.stream {
            match timeout(LIMIT, stream.read(&mut [0_u8; 1])).await? {
                Ok(0) => {}
                Err(error) if is_peer_gone(&error) => {}
                Err(error) => return Err(error.into()),
                Ok(_) => return Err("original terminal peer returned unexpected extra data".into()),
            }
        }

        // A closed connection may retain its local port in TIME_WAIT.
        match timeout(LIMIT, TcpStream::connect(self.address)).await? {
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => Ok(()),
            Err(error) => Err(error.into()),
            Ok(_) => Err("original terminal listener still accepts connections".into()),
        }
    }

    fn take_peer(&mut self) -> TestResult<Peer> {
        self.peer
            .take()
            .ok_or_else(|| "original terminal peer missing".into())
    }

    async fn collect<T>(&mut self, caller: TestResult<T>) -> TestResult<(T, Output)> {
        let peer = self.take_peer()?;
        timeout(LIMIT, collect(caller, peer)).await?
    }

    async fn rejected_caller(&self) -> TestResult<phantom::ResponseBody> {
        let result = caller(&self.client, "http://[", &self.subscriber).await;
        let error = result
            .err()
            .ok_or("terminal caller accepted an invalid URI")?;
        let original = error
            .downcast_ref::<RequestError>()
            .ok_or("original terminal caller type changed")?;
        assert_eq!(original.kind(), RequestErrorKind::InvalidUri);
        assert!(
            original
                .source()
                .is_some_and(|source| source.is::<http::uri::InvalidUri>())
        );
        Err(error)
    }

    async fn stop(&mut self) -> TestResult<()> {
        let mut result = Ok(());
        if let Some(mut peer) = self.peer.take() {
            let requested = !peer.is_finished();
            if requested {
                peer.abort();
            }
            let joined = match timeout(LIMIT, &mut peer).await {
                Ok(Ok(outcome)) => outcome.map(|_| ()),
                Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
            };
            result = finish_with_cleanup(result, joined);
        }
        if !self.abort.is_finished() {
            self.abort.abort();
        }
        finish_with_cleanup(result, wait_finished(&self.abort).await)
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

fn retains_fault(error: &(dyn Error + 'static), marker: &Arc<()>) -> TestResult<()> {
    let original = error
        .downcast_ref::<io::Error>()
        .ok_or("original terminal serving I/O cause missing")?;
    assert_eq!(original.kind(), io::ErrorKind::PermissionDenied);
    let cause = original
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<ServingFailure>())
        .ok_or("original terminal serving cause identity missing")?;
    assert!(Arc::ptr_eq(&cause.0, marker));
    Ok(())
}

mod tests;
