//! Read-policy controls use real TCP reads through the canonical close helper.
//! Injected errors follow byte progress; they do not model a TLS backend fault.

use std::{
    error::Error,
    fmt, io,
    net::Ipv4Addr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::watch,
    time::timeout,
};

use crate::support::{
    tls::is_peer_gone,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

use super::{TestResult, await_peer_close};

const DEADLINE: Duration = Duration::from_secs(5);
const CLIENT_BYTE: u8 = b'!';

#[derive(Clone, Debug, Default)]
struct ReadState {
    pending: bool,
    byte: Option<u8>,
    eof: bool,
    injected: Option<io::ErrorKind>,
    dropped: bool,
}

#[derive(Debug)]
struct ObservedRead {
    socket: TcpStream,
    fault: Option<io::Error>,
    state: watch::Sender<ReadState>,
}

impl AsyncRead for ObservedRead {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        let mut byte = [0_u8; 1];
        let mut actual = ReadBuf::new(&mut byte);
        match Pin::new(&mut this.socket).poll_read(context, &mut actual) {
            Poll::Pending => {
                this.state.send_modify(|state| state.pending = true);
                Poll::Pending
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) if actual.filled().is_empty() => {
                this.state.send_modify(|state| state.eof = true);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(())) => {
                this.state
                    .send_modify(|state| state.byte = Some(actual.filled()[0]));
                if let Some(error) = this.fault.take() {
                    this.state
                        .send_modify(|state| state.injected = Some(error.kind()));
                    return Poll::Ready(Err(error));
                }
                output.put_slice(actual.filled());
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl Drop for ObservedRead {
    fn drop(&mut self) {
        self.state.send_modify(|state| state.dropped = true);
    }
}

#[derive(Debug)]
struct ReadPeer {
    worker: Option<ConnectionPeer<TestResult<()>>>,
    client: Option<TcpStream>,
    state: watch::Receiver<ReadState>,
}

impl ReadPeer {
    fn new() -> Self {
        let (_, state) = watch::channel(ReadState::default());
        Self {
            worker: None,
            client: None,
            state,
        }
    }

    async fn start(&mut self, fault: Option<io::Error>) -> TestResult<()> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (state, observed) = watch::channel(ReadState::default());
        self.state = observed;
        self.worker = Some(ConnectionPeer::spawn(async move {
            let (socket, _) = listener.accept().await?;
            drop(listener);
            let mut stream = ObservedRead {
                socket,
                fault,
                state,
            };
            await_peer_close(&mut stream).await
        }));
        self.client = Some(timeout(DEADLINE, TcpStream::connect(address)).await??);
        timeout(DEADLINE, self.state.wait_for(|state| state.pending)).await??;
        if self
            .worker
            .as_ref()
            .ok_or("read worker missing")?
            .is_finished()
        {
            return Err("idle close helper completed before client progress".into());
        }
        Ok(())
    }

    async fn send_byte(&mut self) -> TestResult<()> {
        let client = self.client.as_mut().ok_or("client socket missing")?;
        timeout(DEADLINE, client.write_all(&[CLIENT_BYTE])).await??;
        Ok(())
    }

    async fn send_eof(&mut self) -> TestResult<()> {
        let client = self.client.as_mut().ok_or("client socket missing")?;
        timeout(DEADLINE, client.shutdown()).await??;
        Ok(())
    }

    async fn observe(&mut self) -> TestResult<TestResult<()>> {
        let worker = self.worker.as_mut().ok_or("read worker missing")?;
        let joined = timeout(DEADLINE, worker).await?;
        drop(self.worker.take());
        Ok(joined?)
    }

    async fn witness(&mut self) -> TestResult<ReadState> {
        let state = self.state.borrow().clone();
        if !state.pending || !state.dropped || self.worker.is_some() {
            return Err("original pending read worker was not joined and dropped".into());
        }
        let client = self.client.as_mut().ok_or("client socket missing")?;
        match timeout(DEADLINE, client.read(&mut [0_u8; 1])).await? {
            Ok(0) => Ok(state),
            Err(error) if is_peer_gone(&error) => Ok(state),
            Err(error) => Err(error.into()),
            Ok(_) => Err("read worker wrote unexpected response bytes".into()),
        }
    }

    async fn stop(mut self) -> TestResult<()> {
        let cleanup = match self.worker.take() {
            Some(worker) => worker.stop().await,
            None => Ok(()),
        };
        drop(self.client.take());
        cleanup
    }
}

#[derive(Debug)]
struct ReadFailure(Arc<()>);

impl fmt::Display for ReadFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected idle close read failure")
    }
}

impl Error for ReadFailure {}

fn original_fault(kind: io::ErrorKind, identity: &Arc<()>) -> io::Error {
    io::Error::new(kind, ReadFailure(Arc::clone(identity)))
}

mod tests;
