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
    tls::{H1_ALPN, TestIdentity, is_peer_gone, test_client},
    tunnel_proxy::finish_with_cleanup,
};

use super::{Caller, Peer, TestResult, collect, spawn};

const LIMIT: Duration = Duration::from_secs(5);
const HEAD: &[u8] = b"GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
const FIRST_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nAccept-CH: last-event-id\r\nCritical-CH: last-event-id\r\nContent-Length: 21\r\n\r\nid: first\ndata: one\n\n";
const RESET_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nAccept-CH: last-event-id\r\nCritical-CH: last-event-id\r\nContent-Length: 15\r\n\r\nid:\ndata: two\n\n";
const STOP_RESPONSE: &[u8] = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";

#[derive(Clone, Debug, Default)]
struct State {
    pending: bool,
    heads: usize,
    written: usize,
    shutdown: bool,
    fault_taken: bool,
    destroyed: bool,
}

#[derive(Debug)]
struct ServingFailure(Arc<()>);

impl fmt::Display for ServingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected managed-ID terminal shutdown failure")
    }
}

impl Error for ServingFailure {}

pub(in super::super) struct Control {
    state: watch::Sender<State>,
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
}

pub(super) async fn read_head(
    stream: &mut SslStream<TcpStream>,
    control: Option<&Control>,
) -> io::Result<Vec<u8>> {
    let Some(control) = control else {
        return super::super::read_head(stream).await;
    };

    let reading = super::super::read_head(stream);
    tokio::pin!(reading);
    let head = poll_fn(|context| {
        let result = reading.as_mut().poll(context);
        if result.is_pending() {
            control.state.send_modify(|state| state.pending = true);
        }
        result
    })
    .await?;
    control.state.send_modify(|state| state.heads += 1);
    Ok(head)
}

pub(super) fn written(control: Option<&Control>) {
    if let Some(control) = control {
        control.state.send_modify(|state| state.written += 1);
    }
}

pub(super) fn after_shutdown(control: Option<&mut Control>) -> io::Result<()> {
    let Some(control) = control else {
        return Ok(());
    };

    control.state.send_modify(|state| state.shutdown = true);
    if let Some(error) = control.fault.take() {
        control.state.send_modify(|state| state.fault_taken = true);
        return Err(error);
    }

    Ok(())
}

struct Backup {
    peer: Option<Peer>,
    abort: AbortHandle,
    address: SocketAddr,
    state: watch::Receiver<State>,
    client: Option<SslStream<TcpStream>>,
    marker: Arc<()>,
}

impl Drop for Backup {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

impl Backup {
    async fn prepare(identity: &TestIdentity, failing: bool) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let marker = Arc::new(());
        let fault = failing.then(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                ServingFailure(Arc::clone(&marker)),
            )
        });
        let (state, observed) = watch::channel(State::default());
        let peer = spawn(listener, acceptor, Some(Control { state, fault }));
        let abort = peer.abort_handle();
        Ok(Self {
            peer: Some(peer),
            abort,
            address,
            state: observed,
            client: None,
            marker,
        })
    }

    async fn pending(&mut self, identity: &TestIdentity) -> TestResult<()> {
        let mut connector = SslConnector::bare_builder(SslMethod::tls())?;
        connector.set_verify(SslVerifyMode::PEER);
        connector
            .cert_store_mut()
            .add_cert(X509::from_der(&identity.root_der)?)?;
        connector.set_alpn_protos(H1_ALPN)?;
        let ssl = connector.build().configure()?.into_ssl("127.0.0.1")?;
        let socket = timeout(LIMIT, TcpStream::connect(self.address)).await??;
        self.client = Some(SslStream::new(ssl, socket)?);
        let client = self.client.as_mut().ok_or("original control client missing")?;
        timeout(LIMIT, Pin::new(&mut *client).connect()).await??;
        assert_eq!(client.ssl().selected_alpn_protocol(), Some(&b"http/1.1"[..]));
        timeout(LIMIT, self.state.wait_for(|state| state.pending)).await??;
        assert!(!self.abort.is_finished(), "original worker finished before its pending read");
        Ok(())
    }

    async fn responses(&mut self) -> TestResult<()> {
        let client = self.client.as_mut().ok_or("original control client missing")?;
        for expected in [FIRST_RESPONSE, RESET_RESPONSE, STOP_RESPONSE] {
            timeout(LIMIT, client.write_all(HEAD)).await??;
            let mut response = vec![0_u8; expected.len()];
            timeout(LIMIT, client.read_exact(&mut response)).await??;
            assert_eq!(response, expected);
        }
        self.destroyed().await?;
        let state = self.state.borrow().clone();
        assert_eq!(state.heads, 3);
        assert_eq!(state.written, 2);
        assert!(state.shutdown);
        Ok(())
    }

    async fn destroyed(&mut self) -> TestResult<()> {
        timeout(LIMIT, self.state.wait_for(|state| state.destroyed)).await??;
        timeout(LIMIT, async {
            while !self.abort.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let client = self.client.as_mut().ok_or("original control client missing")?;
        match timeout(LIMIT, client.read(&mut [0_u8; 1])).await? {
            Ok(0) => Ok(()),
            Err(error) if is_peer_gone(&error) => Ok(()),
            Err(error) => Err(error.into()),
            Ok(_) => Err("original managed-ID worker wrote extra bytes before closure".into()),
        }
    }

    fn take_peer(&mut self) -> TestResult<Peer> {
        self.peer.take().ok_or_else(|| "original managed-ID worker missing".into())
    }

    async fn collect(&mut self, caller: TestResult<Caller>) -> TestResult<Vec<String>> {
        let peer = self.take_peer()?;
        let (_caller, heads) = timeout(LIMIT, collect(caller, peer)).await??;
        Ok(heads)
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
}

fn rejected_caller(identity: &TestIdentity) -> TestResult<Caller> {
    let client = test_client(identity, false)?;
    let error = client
        .event_source(HttpProtocol::Http1, "https://owner.test/\n")
        .err()
        .ok_or("managed-ID caller accepted an invalid target")?;
    assert_eq!(error.kind(), RequestErrorKind::InvalidUri);
    assert!(error.source().is_some_and(|source| source.is::<http::uri::InvalidUri>()));
    Err(error.into())
}

fn retains_fault(error: &(dyn Error + 'static), marker: &Arc<()>) -> TestResult<()> {
    let original = error.downcast_ref::<io::Error>()
        .ok_or("original managed-ID serving I/O type missing")?;
    assert_eq!(original.kind(), io::ErrorKind::PermissionDenied);

    let cause = original.get_ref()
        .and_then(|cause| cause.downcast_ref::<ServingFailure>())
        .ok_or("original managed-ID serving cause missing")?;
    assert!(Arc::ptr_eq(&cause.0, marker));
    Ok(())
}

mod tests;
