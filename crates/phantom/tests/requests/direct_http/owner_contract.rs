use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::AbortHandle,
    time::timeout,
};

use crate::support::tls::is_peer_gone;

use super::{Client, HttpProtocol, Peer, TestResult, finish_peer};

const LIMIT: Duration = Duration::from_secs(5);
const OBSERVATION_LIMIT: Duration = Duration::from_secs(2);
const REQUEST_HEAD: &[u8] =
    b"POST /ownership HTTP/1.1\r\nHost: origin.phantom.test\r\nTransfer-Encoding: chunked\r\n\r\n";
const FRAMED_BODY: &[u8] = b"5\r\nalpha\r\n4\r\nbeta\r\n0\r\n\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\ndirect";
type Output = (Vec<u8>, Vec<u8>);

#[derive(Clone, Debug, Default)]
struct State {
    pending: bool,
    waiting: bool,
    read: bool,
    fault_taken: bool,
    destroyed: bool,
}

#[derive(Debug)]
struct FailureIdentity;

#[derive(Debug)]
struct ServingFailure(Arc<FailureIdentity>);

impl fmt::Display for ServingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected direct-request peer serving failure")
    }
}

impl Error for ServingFailure {}

pub(super) struct Control {
    state: watch::Sender<State>,
    fault: Option<io::Error>,
}

pub(super) struct Life(watch::Sender<State>);

impl Drop for Life {
    fn drop(&mut self) {
        self.0.send_modify(|state| state.destroyed = true);
    }
}

impl Control {
    pub(super) fn life(&self) -> Life {
        Life(self.state.clone())
    }
}

pub(super) async fn observe_head(
    stream: &mut TcpStream,
    control: &mut Option<Control>,
) -> io::Result<Vec<u8>> {
    let Some(control) = control.as_mut() else {
        return super::read_head(stream).await;
    };
    let reading = super::read_head(stream);
    tokio::pin!(reading);
    let head = poll_fn(|context| {
        let result = reading.as_mut().poll(context);
        if result.is_pending() {
            control.state.send_modify(|state| state.pending = true);
        }
        result
    })
    .await?;
    if !head.is_empty() {
        control.state.send_modify(|state| state.read = true);
        if let Some(error) = control.fault.take() {
            control.state.send_modify(|state| state.fault_taken = true);
            return Err(error);
        }
    }
    Ok(head)
}

pub(super) async fn observe_byte(
    stream: &mut TcpStream,
    byte: &mut [u8; 1],
    control: Option<&Control>,
) -> io::Result<()> {
    let Some(control) = control else {
        return stream.read_exact(byte).await.map(|_| ());
    };
    let reading = stream.read_exact(byte);
    tokio::pin!(reading);
    poll_fn(|context| {
        let result = reading.as_mut().poll(context);
        if result.is_pending() {
            control.state.send_modify(|state| state.waiting = true);
        }
        result
    })
    .await
    .map(|_| ())
}

struct Backup {
    peer: Option<Peer<Output>>,
    abort: Option<AbortHandle>,
    raw_client: Option<TcpStream>,
    client: Option<Client>,
    state: watch::Receiver<State>,
}

impl Drop for Backup {
    fn drop(&mut self) {
        if let Some(abort) = &self.abort {
            abort.abort();
        }
    }
}

impl Backup {
    fn prepare(failing: bool) -> (Self, Control, Arc<FailureIdentity>) {
        let identity = Arc::new(FailureIdentity);
        let fault = failing.then(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                ServingFailure(Arc::clone(&identity)),
            )
        });
        let (state, observed) = watch::channel(State::default());
        (
            Self {
                peer: None,
                abort: None,
                raw_client: None,
                client: None,
                state: observed,
            },
            Control { state, fault },
            identity,
        )
    }

    async fn bind(&mut self, control: Control) -> TestResult<SocketAddr> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        self.peer = Some(super::streaming_origin(listener, Some(control)));
        self.abort = Some(self.peer.as_ref().ok_or("original peer missing")?.abort_handle());
        Ok(address)
    }

    async fn pending(&mut self, control: Control) -> TestResult<()> {
        let address = self.bind(control).await?;
        self.raw_client = Some(timeout(LIMIT, TcpStream::connect(address)).await??);
        timeout(LIMIT, self.state.wait_for(|state| state.pending)).await??;
        let client = self.raw_client.as_mut().ok_or("raw client missing")?;
        timeout(LIMIT, client.write_all(REQUEST_HEAD)).await??;
        timeout(LIMIT, self.state.wait_for(|state| state.waiting)).await??;
        if self.abort.as_ref().ok_or("original peer witness missing")?.is_finished() {
            return Err("original peer completed before the waiting operation".into());
        }
        Ok(())
    }

    async fn finished(&mut self) -> TestResult<()> {
        timeout(OBSERVATION_LIMIT, self.state.wait_for(|state| state.destroyed)).await??;
        let abort = self.abort.as_ref().ok_or("original peer witness missing")?;
        timeout(LIMIT, async {
            while !abort.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }

    async fn closed(&mut self) -> TestResult<()> {
        self.finished().await?;
        let client = self.raw_client.as_mut().ok_or("raw client missing")?;
        match timeout(LIMIT, client.read(&mut [0_u8; 1])).await? {
            Ok(0) => Ok(()),
            Err(error) if is_peer_gone(&error) => Ok(()),
            Err(error) => Err(error.into()),
            Ok(_) => Err("original peer wrote unexpected bytes before closing".into()),
        }
    }

    async fn collect(&mut self, caller: TestResult<Option<Client>>) -> TestResult<Output> {
        let peer = self.peer.take().ok_or("original peer missing")?;
        let (_client, observed) = timeout(LIMIT, finish_peer(caller, peer)).await??;
        Ok(observed)
    }

    async fn caller_failure(
        &mut self,
        control: Control,
    ) -> TestResult<(Box<dyn Error + Send + Sync>, phantom::RequestErrorKind)> {
        let address = self.bind(control).await?;
        self.client = Some(super::http1_client()?);
        let client = self.client.as_ref().ok_or("actual client missing")?;
        let error = timeout(
            LIMIT,
            client.request(HttpProtocol::Http1, http::Method::POST, &format!("http://{address}/ownership"))?
                .streaming_body(super::UnknownBody::new([b"alpha".as_slice(), b"beta".as_slice()]))
                .send(),
        ).await?.err().ok_or("faulted origin unexpectedly answered the actual caller")?;

        let kind = error.kind();
        timeout(LIMIT, self.state.wait_for(|state| state.read && state.fault_taken)).await??;
        self.finished().await?;
        Ok((Box::new(error), kind))
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
        } else if let Some(abort) = &self.abort {
            if !abort.is_finished() {
                abort.abort();
            }
            timeout(LIMIT, async {
                while !abort.is_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .map_err(Into::into)
        } else {
            Ok(())
        };
        drop(self.raw_client.take());
        drop(self.client.take());
        result
    }
}

fn retains_fault(error: &(dyn Error + 'static), identity: &Arc<FailureIdentity>) -> TestResult<()> {
    let original = error.downcast_ref::<io::Error>().ok_or("original serving I/O error was discarded")?;
    if original.kind() != io::ErrorKind::PermissionDenied {
        return Err("original serving I/O error kind changed".into());
    }
    let cause = original.get_ref()
        .and_then(|cause| cause.downcast_ref::<ServingFailure>())
        .ok_or("original typed serving cause was discarded")?;
    if !Arc::ptr_eq(&cause.0, identity) {
        return Err("original typed serving identity changed".into());
    }
    Ok(())
}

mod tests;
