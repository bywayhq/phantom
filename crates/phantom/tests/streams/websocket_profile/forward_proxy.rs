//! The one plaintext CONNECT relay used by the profile and trust scripts.

use std::{net::{Ipv4Addr, SocketAddr}, time::Duration};

use tokio::{net::TcpListener, sync::watch, time::timeout};

use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::ConnectionPeer,
    websocket::forward_one_connect,
};

use super::TestResult;
use super::server::retain_failure;

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub(crate) struct ForwardProxy {
    pub(crate) address: SocketAddr,
    task: Option<ConnectionPeer<TestResult<Option<Vec<u8>>>>>,
    stop: watch::Sender<bool>,
    failure: Option<Box<dyn std::error::Error + Send + Sync>>,
    incomplete_shutdown: bool,
}

impl ForwardProxy {
    pub(crate) async fn start(origin: SocketAddr) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (stop, mut stopped) = watch::channel(false);
        let task = ConnectionPeer::spawn(async move {
            tokio::select! {
                biased;
                result = forward_one_connect(listener, origin) => result.map(Some),
                result = stopped.changed() => { result?; Ok(None) }
            }
        });
        Ok(Self { address, task: Some(task), stop, failure: None, incomplete_shutdown: false })
    }

    pub(crate) async fn head(&mut self) -> TestResult<Vec<u8>> {
        let task = self.task.as_mut().ok_or("CONNECT proxy was already observed")?;
        let joined = task.await;
        self.task.take();
        joined??.ok_or_else(|| "CONNECT proxy stopped before its request was observed".into())
    }

    pub(crate) async fn finish<T>(&mut self, caller: TestResult<T>) -> TestResult<T> {
        let value = match caller {
            Ok(value) => Some(value),
            Err(error) => { self.retain(error); None }
        };
        self.stop.send_replace(true);
        if let Some(task) = self.task.as_mut() {
            let joined = match timeout(CLEANUP_TIMEOUT, &mut *task).await {
                Ok(joined) => Some(joined),
                Err(elapsed) => {
                    retain_failure(&mut self.failure, FixtureDeadline::new("CONNECT proxy cleanup exceeded its deadline", elapsed).into());
                    task.abort();
                    let joined = timeout(CLEANUP_TIMEOUT, &mut *task).await;
                    match joined {
                        Ok(joined) => Some(joined),
                        Err(elapsed) => {
                            retain_failure(&mut self.failure, FixtureDeadline::new("CONNECT proxy abort exceeded its deadline", elapsed).into());
                            self.incomplete_shutdown = true;
                            None
                        }
                    }
                }
            };
            if let Some(joined) = joined {
                self.task.take();
                match joined {
                    Ok(Ok(_)) => {}
                    Ok(Err(error)) => self.retain(error),
                    Err(error) => self.retain(error.into()),
                }
            }
        }
        if let Some(error) = self.failure.take() { return Err(error); }
        if self.incomplete_shutdown { return Err("an earlier CONNECT proxy shutdown returned before collection completed".into()); }
        value.ok_or_else(|| "CONNECT proxy caller completed without a value".into())
    }

    fn retain(&mut self, error: Box<dyn std::error::Error + Send + Sync>) {
        retain_failure(&mut self.failure, error);
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};

    use super::{CLEANUP_TIMEOUT, ForwardProxy, Ipv4Addr, TcpListener, TestResult, timeout};
    use crate::support::tls::{is_peer_gone, read_head};

    #[tokio::test]
    async fn caller_failure_collects_the_original_accepted_connect_relay() -> TestResult<()> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin = listener.local_addr()?;
        let mut proxy = ForwardProxy::start(origin).await?;
        let address = proxy.address;
        let mut client = TcpStream::connect(address).await?;
        client.write_all(format!("CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n").as_bytes()).await?;
        let (mut accepted, _) = timeout(CLEANUP_TIMEOUT, listener.accept()).await??;
        assert_eq!(timeout(CLEANUP_TIMEOUT, read_head(&mut client)).await??,
            b"HTTP/1.1 200 Connection Established\r\n\r\n");
        client.write_all(b"ping").await?;
        let mut incoming = [0_u8; 4];
        timeout(CLEANUP_TIMEOUT, accepted.read_exact(&mut incoming)).await??;
        assert_eq!(&incoming, b"ping");

        let error = proxy.finish::<()>(Err(io::Error::new(io::ErrorKind::PermissionDenied,
            "original CONNECT caller failure").into())).await.err()
            .ok_or("caller failure was discarded")?;
        let cause = error.downcast_ref::<io::Error>().ok_or("original caller cause was replaced")?;
        assert_eq!(cause.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(cause.to_string(), "original CONNECT caller failure");
        assert!(proxy.task.is_none(), "original relay outcome was not collected");
        for stream in [&mut client, &mut accepted] {
            let closed = timeout(CLEANUP_TIMEOUT, stream.read(&mut [0_u8; 1])).await?;
            assert!(matches!(closed, Ok(0)) || matches!(closed, Err(ref error) if is_peer_gone(error)));
        }
        let rebound = TcpListener::bind(address).await?;
        assert_eq!(rebound.local_addr()?, address);
        Ok(())
    }
}
