//! Controls observe the original cross-origin workers before backup cleanup.

use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use btls::{
    ssl::{SslConnector, SslMethod, SslVerifyMode},
    x509::X509,
};
use phantom::{HttpProtocol, RequestErrorKind};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::AbortHandle,
    time::timeout,
};
use tokio_btls::SslStream;

use crate::support::{
    tls::{TestIdentity, is_peer_gone},
    tunnel_proxy::{connection_peer::FixtureFailures, finish_with_cleanup},
};

use super::{
    CrossOriginCaller, CrossOriginPeer, TestResult, cross_origin_peers, finish_cross_origin,
};

const LIMIT: Duration = Duration::from_secs(5);
const HEAD: &[u8] = b"GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
const ORIGIN_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nAccept-CH: last-event-id\r\nContent-Length: 21\r\nConnection: close\r\n\r\nid: first\ndata: one\n\n";
const DESTINATION_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nAccept-CH: last-event-id\r\nContent-Length: 15\r\nConnection: close\r\n\r\nid:\ndata: two\n\n";
const STOP_RESPONSE: &[u8] = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";

#[derive(Clone, Debug, Default)]
struct State {
    pending: usize,
    heads: usize,
    written: usize,
    shutdowns: usize,
    fault_taken: bool,
    dropped: bool,
}

#[derive(Debug)]
struct ServingFailure(Arc<()>);

impl fmt::Display for ServingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected original cross-origin shutdown failure")
    }
}

impl Error for ServingFailure {}

pub(super) struct Observation {
    pub(super) origin: Control,
    pub(super) destination: Control,
}

pub(super) struct Control {
    state: watch::Sender<State>,
    fault: Option<io::Error>,
}

pub(super) struct Lifetime(watch::Sender<State>);

impl Drop for Lifetime {
    fn drop(&mut self) {
        self.0.send_modify(|state| state.dropped = true);
    }
}

impl Control {
    pub(super) fn lifetime(&self) -> Lifetime {
        Lifetime(self.state.clone())
    }
}

pub(super) async fn observe_head(
    stream: &mut SslStream<TcpStream>,
    control: Option<&Control>,
) -> io::Result<Vec<u8>> {
    let Some(control) = control else {
        return super::read_head(stream).await;
    };

    let reading = super::read_head(stream);
    tokio::pin!(reading);
    let head = poll_fn(|context| {
        let result = reading.as_mut().poll(context);
        if result.is_pending() {
            control.state.send_modify(|state| state.pending += 1);
        }
        result
    })
    .await?;
    control.state.send_modify(|state| state.heads += 1);
    Ok(head)
}

pub(super) fn written(control: Option<&Control>, count: usize) {
    if let Some(control) = control {
        control.state.send_modify(|state| state.written += count);
    }
}

pub(super) fn after_shutdown(control: Option<&mut Control>) -> io::Result<()> {
    let Some(control) = control else {
        return Ok(());
    };

    control.state.send_modify(|state| state.shutdowns += 1);
    if let Some(fault) = control.fault.take() {
        control.state.send_modify(|state| state.fault_taken = true);
        return Err(fault);
    }

    Ok(())
}

#[derive(Clone, Copy)]
enum Faults {
    None,
    Origin,
    Both,
}

struct PeerBackup {
    peer: Option<CrossOriginPeer>,
    abort: AbortHandle,
    address: SocketAddr,
    state: watch::Receiver<State>,
    client: Option<SslStream<TcpStream>>,
    marker: Arc<()>,
}

impl Drop for PeerBackup {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

impl PeerBackup {
    async fn pending(&mut self, identity: &TestIdentity) -> TestResult<()> {
        let pending_before = self.state.borrow().pending;
        let mut connector = SslConnector::bare_builder(SslMethod::tls())?;
        connector.set_verify(SslVerifyMode::PEER);
        connector
            .cert_store_mut()
            .add_cert(X509::from_der(&identity.root_der)?)?;
        connector.set_alpn_protos(super::super::tls_support::H1_ALPN)?;
        let ssl = connector.build().configure()?.into_ssl("127.0.0.1")?;
        let socket = timeout(LIMIT, TcpStream::connect(self.address)).await??;
        self.client = Some(SslStream::new(ssl, socket)?);
        let client = self
            .client
            .as_mut()
            .ok_or("original control client missing")?;
        timeout(LIMIT, Pin::new(&mut *client).connect()).await??;
        assert_eq!(
            client.ssl().selected_alpn_protocol(),
            Some(&b"http/1.1"[..])
        );
        timeout(
            LIMIT,
            self.state.wait_for(|state| state.pending > pending_before),
        )
        .await??;
        assert!(
            !self.abort.is_finished(),
            "original worker finished before its pending read"
        );
        Ok(())
    }

    async fn response(&mut self, expected: &[u8]) -> TestResult<()> {
        let client = self
            .client
            .as_mut()
            .ok_or("original control client missing")?;
        timeout(LIMIT, client.write_all(HEAD)).await??;
        let mut response = vec![0_u8; expected.len()];
        timeout(LIMIT, client.read_exact(&mut response)).await??;
        assert_eq!(response, expected);
        Ok(())
    }

    async fn connection_closed(&mut self) -> TestResult<()> {
        let client = self
            .client
            .as_mut()
            .ok_or("original control client missing")?;
        match timeout(LIMIT, client.read(&mut [0_u8; 1])).await? {
            Ok(0) => Ok(()),
            Err(error) if is_peer_gone(&error) => Ok(()),
            Err(error) => Err(error.into()),
            Ok(_) => Err("original cross-origin worker wrote extra response bytes".into()),
        }
    }

    async fn destroyed(&mut self) -> TestResult<()> {
        timeout(LIMIT, self.state.wait_for(|state| state.dropped)).await??;
        timeout(LIMIT, async {
            while !self.abort.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        self.connection_closed().await?;
        let rebound = TcpListener::bind(self.address).await?;
        assert_eq!(rebound.local_addr()?, self.address);
        Ok(())
    }

    async fn fault_completed(&mut self, expected: &[u8]) -> TestResult<()> {
        self.response(expected).await?;
        self.destroyed().await?;
        let state = self.state.borrow().clone();
        assert_eq!(state.heads, 1);
        assert_eq!(state.written, expected.len());
        assert_eq!(state.shutdowns, 1);
        assert!(state.fault_taken);
        Ok(())
    }

    async fn stop(&mut self) -> TestResult<()> {
        let result = if let Some(mut peer) = self.peer.take() {
            let requested = !peer.is_finished();
            if requested {
                peer.abort();
            }
            match timeout(LIMIT, &mut peer).await {
                Ok(Ok(result)) => result.map(|_| ()),
                Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
            }
        } else {
            self.abort.abort();
            timeout(LIMIT, async {
                while !self.abort.is_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .map_err(Into::into)
        };
        drop(self.client.take());
        result
    }

    async fn cancelled(&mut self) -> TestResult<()> {
        let mut peer = self
            .peer
            .take()
            .ok_or("original cancelled worker missing")?;
        match timeout(LIMIT, &mut peer).await? {
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error.into()),
            Ok(Err(error)) => Err(error),
            Ok(Ok(_)) => Err("original aborted worker returned success".into()),
        }
    }
}

struct Backup {
    origin: PeerBackup,
    destination: PeerBackup,
}

impl Backup {
    async fn prepare(identity: &TestIdentity, faults: Faults) -> TestResult<Self> {
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin.local_addr()?;
        let destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let destination_address = destination.local_addr()?;
        let origin_acceptor = identity.acceptor(super::super::tls_support::H1_ALPN)?;
        let destination_acceptor = identity.acceptor(super::super::tls_support::H1_ALPN)?;
        let (origin_control, origin_state, origin_marker) =
            control(!matches!(faults, Faults::None));
        let (destination_control, destination_state, destination_marker) =
            control(matches!(faults, Faults::Both));
        let observation = Observation {
            origin: origin_control,
            destination: destination_control,
        };
        let (origin_peer, destination_peer) = cross_origin_peers(
            origin,
            destination,
            origin_acceptor,
            destination_acceptor,
            destination_address,
            Some(observation),
        );
        let origin_abort = origin_peer.abort_handle();
        let destination_abort = destination_peer.abort_handle();
        Ok(Self {
            origin: PeerBackup {
                peer: Some(origin_peer),
                abort: origin_abort,
                address: origin_address,
                state: origin_state,
                client: None,
                marker: origin_marker,
            },
            destination: PeerBackup {
                peer: Some(destination_peer),
                abort: destination_abort,
                address: destination_address,
                state: destination_state,
                client: None,
                marker: destination_marker,
            },
        })
    }

    async fn pending(&mut self, identity: &TestIdentity) -> TestResult<()> {
        self.origin.pending(identity).await?;
        self.destination.pending(identity).await
    }

    async fn collect(
        &mut self,
        caller: TestResult<CrossOriginCaller>,
    ) -> TestResult<(Vec<String>, Vec<String>)> {
        let origin = self
            .origin
            .peer
            .take()
            .ok_or("original origin worker missing")?;
        let destination = self
            .destination
            .peer
            .take()
            .ok_or("original destination worker missing")?;
        let (_caller, origin, destination) =
            timeout(LIMIT, finish_cross_origin(caller, origin, destination)).await??;
        Ok((origin, destination))
    }

    async fn healthy_destination(&mut self, identity: &TestIdentity) -> TestResult<()> {
        self.destination.response(DESTINATION_RESPONSE).await?;
        self.destination.connection_closed().await?;
        drop(self.destination.client.take());
        self.destination.pending(identity).await?;
        self.destination.response(STOP_RESPONSE).await?;
        self.destination.destroyed().await
    }

    async fn stop(&mut self) -> TestResult<()> {
        let origin = self.origin.stop().await;
        let destination = self.destination.stop().await;
        finish_with_cleanup(origin, destination)
    }
}

fn control(failing: bool) -> (Control, watch::Receiver<State>, Arc<()>) {
    let marker = Arc::new(());
    let fault = failing.then(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            ServingFailure(Arc::clone(&marker)),
        )
    });
    let (state, observed) = watch::channel(State::default());
    (Control { state, fault }, observed, marker)
}

fn rejected_caller(identity: &TestIdentity) -> TestResult<CrossOriginCaller> {
    let client = super::test_client(identity, false)?;
    let error = client
        .event_source(HttpProtocol::Http1, "https://owner.test/\n")
        .err()
        .ok_or("cross-origin caller accepted an invalid target")?;
    assert_eq!(error.kind(), RequestErrorKind::InvalidUri);
    assert!(
        error
            .source()
            .is_some_and(|source| source.is::<http::uri::InvalidUri>())
    );
    Err(error.into())
}

fn retains_fault(error: &(dyn Error + 'static), marker: &Arc<()>) -> TestResult<()> {
    let original = error
        .downcast_ref::<io::Error>()
        .ok_or("original serving I/O error missing")?;
    assert_eq!(original.kind(), io::ErrorKind::PermissionDenied);

    let source = original
        .get_ref()
        .and_then(|source| source.downcast_ref::<ServingFailure>())
        .ok_or("original serving cause missing")?;

    assert!(Arc::ptr_eq(&source.0, marker));
    Ok(())
}

fn retains_pair(error: &(dyn Error + 'static), backup: &Backup) -> TestResult<()> {
    let failures = error
        .downcast_ref::<FixtureFailures>()
        .ok_or("first cross-origin failure discarded the second completed cause")?;
    retains_fault(failures.primary.as_ref(), &backup.origin.marker)?;
    retains_fault(failures.cleanup.as_ref(), &backup.destination.marker)
}

mod tests;
