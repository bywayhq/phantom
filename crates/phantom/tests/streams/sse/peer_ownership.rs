//! Controls retain the original fixed-response worker's resource witnesses.
//! Injected shutdown errors follow real TLS response writes and shutdown.

use std::{
    error::Error,
    fmt, io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use btls::{
    ssl::{SslConnector, SslMethod, SslVerifyMode},
    x509::X509,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{oneshot, watch},
    task::AbortHandle,
    time::timeout,
};
use tokio_btls::SslStream;

use crate::support::{
    tls::is_peer_gone,
    tunnel_proxy::{connection_peer::FixtureFailures, finish_with_cleanup},
};

use super::{TestResult, fixed_response_observed, tls_support::TestIdentity};

const CONTROL_LIMIT: Duration = Duration::from_secs(5);
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 13\r\nConnection: close\r\n\r\ndata: owner\n\n";
const INVALID_TARGET: &str = "https://owner.test/\n";

#[derive(Clone, Debug, Default)]
struct WorkerState {
    head_pending: bool,
    written: usize,
    shutdown: bool,
    injected: Option<io::ErrorKind>,
    dropped: bool,
}

#[derive(Debug)]
struct WorkerWitness {
    address: SocketAddr,
    abort: AbortHandle,
}

#[derive(Debug)]
pub(super) struct Observation {
    worker: Option<WorkerObservation>,
    attached: oneshot::Sender<WorkerWitness>,
    before_client: oneshot::Receiver<Option<&'static str>>,
}

impl Observation {
    fn pair(fault: Option<io::Error>) -> (Self, Backup, oneshot::Sender<Option<&'static str>>) {
        let (state, observed) = watch::channel(WorkerState::default());
        let (attached, attachment) = oneshot::channel();
        let (release, before_client) = oneshot::channel();
        let observation = Self {
            worker: Some(WorkerObservation { state, fault }),
            attached,
            before_client,
        };
        let backup = Backup {
            attachment: Some(attachment),
            witness: None,
            state: observed,
            client: None,
        };
        (observation, backup, release)
    }

    pub(super) fn take_worker(&mut self) -> Option<WorkerObservation> {
        self.worker.take()
    }

    pub(super) async fn before_client(
        self,
        address: SocketAddr,
        abort: AbortHandle,
    ) -> TestResult<Option<&'static str>> {
        self.attached
            .send(WorkerWitness { address, abort })
            .map_err(|witness| {
                witness.abort.abort();
                "fixed-response observer stopped before worker attachment"
            })?;
        Ok(self.before_client.await?)
    }
}

#[derive(Debug)]
pub(super) struct WorkerObservation {
    state: watch::Sender<WorkerState>,
    fault: Option<io::Error>,
}

impl WorkerObservation {
    pub(super) fn lifetime(&self) -> WorkerLifetime {
        WorkerLifetime(self.state.clone())
    }
}

#[derive(Debug)]
pub(super) struct WorkerLifetime(watch::Sender<WorkerState>);

impl Drop for WorkerLifetime {
    fn drop(&mut self) {
        self.0.send_modify(|state| state.dropped = true);
    }
}

#[derive(Debug)]
pub(super) struct ObservedStream {
    stream: SslStream<TcpStream>,
    observation: Option<WorkerObservation>,
}

impl ObservedStream {
    pub(super) fn new(
        stream: SslStream<TcpStream>,
        observation: Option<WorkerObservation>,
    ) -> Self {
        Self { stream, observation }
    }
}

impl AsyncRead for ObservedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.stream).poll_read(context, output);
        if result.is_pending()
            && let Some(observation) = &this.observation
        {
            observation
                .state
                .send_modify(|state| state.head_pending = true);
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
        let this = self.get_mut();
        let result = Pin::new(&mut this.stream).poll_write(context, bytes);
        if let Poll::Ready(Ok(written)) = &result
            && let Some(observation) = &this.observation
        {
            observation
                .state
                .send_modify(|state| state.written += *written);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.stream).poll_shutdown(context);
        if let Poll::Ready(Ok(())) = &result
            && let Some(observation) = &mut this.observation
        {
            observation
                .state
                .send_modify(|state| state.shutdown = true);
            if let Some(fault) = observation.fault.take() {
                observation
                    .state
                    .send_modify(|state| state.injected = Some(fault.kind()));
                return Poll::Ready(Err(fault));
            }
        }
        result
    }
}

#[derive(Debug)]
struct Backup {
    attachment: Option<oneshot::Receiver<WorkerWitness>>,
    witness: Option<WorkerWitness>,
    state: watch::Receiver<WorkerState>,
    client: Option<SslStream<TcpStream>>,
}

impl Backup {
    async fn attached(&mut self) -> TestResult<()> {
        let attachment = self
            .attachment
            .as_mut()
            .ok_or("worker attachment already taken")?;
        self.witness = Some(timeout(CONTROL_LIMIT, attachment).await??);
        drop(self.attachment.take());
        Ok(())
    }

    fn witness(&self) -> TestResult<&WorkerWitness> {
        self.witness
            .as_ref()
            .ok_or_else(|| "original worker witness missing".into())
    }

    async fn connect(&mut self, identity: &TestIdentity) -> TestResult<()> {
        let mut connector = SslConnector::bare_builder(SslMethod::tls())?;
        connector.set_verify(SslVerifyMode::PEER);
        connector
            .cert_store_mut()
            .add_cert(X509::from_der(&identity.root_der)?)?;
        connector.set_alpn_protos(super::tls_support::H1_ALPN)?;
        let ssl = connector.build().configure()?.into_ssl("127.0.0.1")?;
        let socket = timeout(
            CONTROL_LIMIT,
            TcpStream::connect(self.witness()?.address),
        )
        .await??;
        self.client = Some(SslStream::new(ssl, socket)?);
        let client = self.client.as_mut().ok_or("control TLS client missing")?;
        timeout(CONTROL_LIMIT, Pin::new(&mut *client).connect()).await??;
        assert_eq!(
            client.ssl().selected_alpn_protocol(),
            Some(&b"http/1.1"[..])
        );
        timeout(
            CONTROL_LIMIT,
            self.state.wait_for(|state| state.head_pending),
        )
        .await??;
        assert!(!self.witness()?.abort.is_finished());
        Ok(())
    }

    async fn response(&mut self) -> TestResult<()> {
        let client = self.client.as_mut().ok_or("control TLS client missing")?;
        timeout(
            CONTROL_LIMIT,
            client.write_all(b"GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"),
        )
        .await??;
        let mut response = vec![0_u8; RESPONSE.len()];
        timeout(CONTROL_LIMIT, client.read_exact(&mut response)).await??;
        assert_eq!(response, RESPONSE);
        Ok(())
    }

    async fn destroyed(&mut self) -> TestResult<()> {
        timeout(CONTROL_LIMIT, self.state.wait_for(|state| state.dropped)).await??;
        let abort = &self.witness()?.abort;
        timeout(CONTROL_LIMIT, async {
            while !abort.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        if let Some(client) = &mut self.client {
            match timeout(CONTROL_LIMIT, client.read(&mut [0_u8; 1])).await? {
                Ok(0) => {}
                Err(error) if is_peer_gone(&error) => {}
                Err(error) => return Err(error.into()),
                Ok(_) => return Err("original worker left unexpected response bytes".into()),
            }
        }
        let rebound = TcpListener::bind(self.witness()?.address).await?;
        assert_eq!(rebound.local_addr()?, self.witness()?.address);
        Ok(())
    }

    async fn stop(mut self) -> TestResult<()> {
        self.harvest_attachment();
        if let Some(witness) = &self.witness {
            witness.abort.abort();
            timeout(CONTROL_LIMIT, async {
                while !witness.abort.is_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await?;
        }
        drop(self.client.take());
        Ok(())
    }

    fn harvest_attachment(&mut self) {
        if self.witness.is_none()
            && let Some(attachment) = &mut self.attachment
            && let Ok(witness) = attachment.try_recv()
        {
            self.witness = Some(witness);
        }
    }
}

impl Drop for Backup {
    fn drop(&mut self) {
        self.harvest_attachment();
        if let Some(witness) = &self.witness {
            witness.abort.abort();
        }
    }
}

#[derive(Debug)]
struct ShutdownFailure(Arc<()>);

impl fmt::Display for ShutdownFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected original SSE peer shutdown failure")
    }
}

impl Error for ShutdownFailure {}

mod tests;
