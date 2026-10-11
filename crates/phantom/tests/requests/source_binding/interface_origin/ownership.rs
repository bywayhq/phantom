use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    sync::watch,
    task::AbortHandle,
    time::timeout,
};

use crate::support::tls::is_peer_gone;

use super::{Outcome, Peer, TestResult, collect};

const LIMIT: Duration = Duration::from_secs(5);
const OBSERVATION_LIMIT: Duration = Duration::from_secs(2);
const REQUEST: &[u8] = b"GET /ownership HTTP/1.1\r\nHost: origin.phantom.test\r\n\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 204 No Content\r\n\r\n";

#[derive(Clone, Debug, Default)]
struct State {
    pending: bool,
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
        formatter.write_str("injected source-binding origin serving failure")
    }
}

impl Error for ServingFailure {}

#[derive(Debug)]
pub(in super::super) struct Control {
    state: watch::Sender<State>,
    fault: Option<io::Error>,
}

#[derive(Debug)]
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

pub(super) async fn read_head(
    stream: &mut TcpStream,
    control: &mut Option<Control>,
) -> io::Result<Vec<u8>> {
    let Some(control) = control.as_mut() else {
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

    control.state.send_modify(|state| state.read = true);
    if let Some(error) = control.fault.take() {
        control.state.send_modify(|state| state.fault_taken = true);
        return Err(error);
    }

    Ok(head)
}

struct Backup {
    peer: Option<Peer>,
    abort: Option<AbortHandle>,
    client: Option<TcpStream>,
    request_client: Option<super::super::Client>,
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
                client: None,
                request_client: None,
                state: observed,
            },
            Control { state, fault },
            identity,
        )
    }

    async fn bind(&mut self, control: Control) -> TestResult<SocketAddr> {
        let listener = TcpListener::bind((super::super::IPV4_LOOPBACK, 0)).await?;
        let address = listener.local_addr()?;
        self.peer = Some(super::spawn(listener, Some(control)));
        self.abort = Some(
            self.peer
                .as_ref()
                .ok_or("original interface-origin peer missing")?
                .abort_handle(),
        );
        Ok(address)
    }

    async fn pending(&mut self, control: Control) -> TestResult<()> {
        let address = self.bind(control).await?;
        self.client = Some(timeout(LIMIT, TcpStream::connect(address)).await??);
        timeout(LIMIT, self.state.wait_for(|state| state.pending)).await??;
        if self
            .abort
            .as_ref()
            .ok_or("original interface-origin witness missing")?
            .is_finished()
        {
            return Err("original interface-origin completed before its pending read".into());
        }

        Ok(())
    }

    async fn finished(&mut self) -> TestResult<()> {
        timeout(
            OBSERVATION_LIMIT,
            self.state.wait_for(|state| state.destroyed),
        )
        .await??;
        let abort = self
            .abort
            .as_ref()
            .ok_or("original interface-origin witness missing")?;
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
        let client = self.client.as_mut().ok_or("original raw client missing")?;
        match timeout(LIMIT, client.read(&mut [0_u8; 1])).await? {
            Ok(0) => Ok(()),
            Err(error) if is_peer_gone(&error) => Ok(()),
            Err(error) => Err(error.into()),
            Ok(_) => Err("interface-origin wrote unexpected bytes before closure".into()),
        }
    }

    async fn collect(&mut self, caller: TestResult<Outcome>) -> TestResult<Option<SocketAddr>> {
        let peer = self
            .peer
            .take()
            .ok_or("original interface-origin peer missing")?;
        collect(caller, peer).await
    }

    async fn caller_failure(
        &mut self,
        control: Control,
    ) -> TestResult<(Box<dyn Error + Send + Sync>, super::super::RequestErrorKind)> {
        let address = self.bind(control).await?;
        self.request_client = Some(super::super::Client::builder(super::super::profile()).build()?);
        let client = self
            .request_client
            .as_ref()
            .ok_or("actual request client missing")?;
        let error = timeout(
            LIMIT,
            super::super::get(client, format!("http://{address}/ownership")),
        )
        .await?
        .err()
        .ok_or("faulted original interface-origin answered its actual caller")?;
        let kind = error.kind();
        timeout(
            LIMIT,
            self.state.wait_for(|state| state.read && state.fault_taken),
        )
        .await??;
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
                Ok(Ok(result)) => result.map(|_| ()).map_err(Into::into),
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
        drop(self.client.take());
        drop(self.request_client.take());
        result
    }
}

fn retains_fault(error: &(dyn Error + 'static), identity: &Arc<FailureIdentity>) -> TestResult<()> {
    let original = error
        .downcast_ref::<io::Error>()
        .ok_or("original interface-origin I/O type was discarded")?;
    if original.kind() != io::ErrorKind::PermissionDenied {
        return Err("original interface-origin I/O kind changed".into());
    }

    let cause = original
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<ServingFailure>())
        .ok_or("original interface-origin typed cause was discarded")?;

    if !Arc::ptr_eq(&cause.0, identity) {
        return Err("original interface-origin cause identity changed".into());
    }

    Ok(())
}

mod tests;
