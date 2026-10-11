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
    task::{AbortHandle, JoinHandle},
};
use tokio_btls::SslStream;

use super::{TestResult, accept_tls, serve_requests};

pub(super) type Requests = Vec<(u32, String)>;
pub(super) type Server = JoinHandle<TestResult<Requests>>;
pub(super) type IndependentServer = JoinHandle<TestResult<[Requests; 2]>>;

#[derive(Clone, Debug, Default)]
struct State {
    closed_pending: bool,
    fault_taken: bool,
    destroyed: bool,
    children: Vec<AbortHandle>,
    second_accept_pending: bool,
    second_accept_failed: bool,
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
}

impl Stream {
    fn new(stream: SslStream<TcpStream>, control: Option<Control>) -> Self {
        Self { stream, control }
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
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.stream).poll_read(context, buffer);
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
    tokio::spawn(async move {
        let stream = accept_tls(&listener, &acceptor).await?;
        serve_requests(Stream::new(stream, control), count).await
    })
}

pub(super) async fn collect(caller: TestResult<()>, server: Server) -> TestResult<Requests> {
    caller?;
    server.await?
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
    tokio::spawn(async move {
        let observed = control.as_ref().map(|control| control.observed.clone());
        let _life = CoordinatorLife(observed.clone());
        let first = accept_tls(&listener, &acceptor).await?;
        let first = tokio::spawn(serve_requests(Stream::new(first, control), 1));
        if let Some(observed) = &observed {
            observed
                .0
                .send_modify(|state| state.children.push(first.abort_handle()));
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
        })
        .await?;
        let second = tokio::spawn(serve_requests(Stream::new(second, None), 1));
        if let Some(observed) = &observed {
            observed
                .0
                .send_modify(|state| state.children.push(second.abort_handle()));
        }

        Ok([first.await??, second.await??])
    })
}

pub(super) async fn collect_independent(
    caller: TestResult<()>,
    server: IndependentServer,
) -> TestResult<[Requests; 2]> {
    caller?;
    server.await?
}

mod tests;
