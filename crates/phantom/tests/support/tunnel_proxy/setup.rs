use std::{error::Error, fmt, future::Future, sync::Arc, time::Duration};

use tokio::{sync::oneshot, time::timeout};

use super::{ConnectionPeer, EstablishedTunnel, TestResult, finish_with_cleanup};
use crate::support::deadline::FixtureDeadline;

const SETUP_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

enum SetupOutcome<T> {
    Finished(TestResult<EstablishedTunnel<T>>),
    Stopped,
}

/// Retains a CONNECT coordinator and its returned tunnel outside caller deadlines.
pub(crate) struct TunnelSetup<T> {
    task: Option<ConnectionPeer<SetupOutcome<T>>>,
    stop: Option<oneshot::Sender<()>>,
    tunnel: Option<EstablishedTunnel<T>>,
    failure: Option<SetupFailure>,
}

impl<T: Send + 'static> TunnelSetup<T> {
    pub(crate) fn spawn(
        setup: impl Future<Output = TestResult<EstablishedTunnel<T>>> + Send + 'static,
    ) -> Self {
        let (stop, stopped) = oneshot::channel();
        let task = ConnectionPeer::spawn(async move {
            tokio::select! {
                biased;
                result = setup => SetupOutcome::Finished(result),
                signal = stopped => match signal {
                    Ok(()) => SetupOutcome::Stopped,
                    Err(error) => SetupOutcome::Finished(Err(error.into())),
                },
            }
        });
        Self {
            task: Some(task),
            stop: Some(stop),
            tunnel: None,
            failure: None,
        }
    }

    pub(crate) async fn establish(&mut self) -> TestResult<&T> {
        if let Some(task) = self.task.as_mut() {
            let joined = task.await;
            self.task = None;
            self.stop = None;
            self.accept_outcome(joined);
        }

        if let Some(failure) = &self.failure {
            return Err(Box::new(failure.clone()));
        }
        self.tunnel
            .as_ref()
            .map(|tunnel| &tunnel.observed)
            .ok_or_else(|| "tunnel setup stopped before establishment".into())
    }

    pub(crate) async fn finish(&mut self, primary: TestResult<()>) -> TestResult<()> {
        self.retain_failure(primary);
        if let Some(stop) = self.stop.take() {
            // A completed coordinator already dropped its receiver. Join its
            // original result rather than inferring cancellation from this send.
            let _ = stop.send(());
        }
        if let Some(task) = self.task.as_mut() {
            match timeout(SETUP_CLEANUP_TIMEOUT, task).await {
                Ok(joined) => {
                    self.task = None;
                    self.accept_outcome(joined);
                }
                Err(elapsed) => self.retain_failure(Err(
                    FixtureDeadline::new("tunnel setup cleanup exceeded five seconds", elapsed)
                        .into(),
                )),
            }
        }

        let cleanup = match self.tunnel.as_mut() {
            Some(tunnel) => tunnel.finish(Ok(())).await,
            None => Ok(()),
        };
        let primary = match &self.failure {
            Some(failure) => Err(Box::new(failure.clone()) as Box<dyn Error + Send + Sync>),
            None => Ok(()),
        };
        finish_with_cleanup(primary, cleanup)
    }

    fn accept_outcome(&mut self, joined: Result<SetupOutcome<T>, tokio::task::JoinError>) {
        match joined {
            Ok(SetupOutcome::Finished(Ok(tunnel))) => self.tunnel = Some(tunnel),
            Ok(SetupOutcome::Finished(Err(error))) => self.retain_failure(Err(error)),
            Ok(SetupOutcome::Stopped) => (),
            Err(error) => self.retain_failure(Err(error.into())),
        }
    }

    fn retain_failure(&mut self, result: TestResult<()>) {
        let Err(error) = result else {
            return;
        };
        if let (Some(previous), Some(returned)) = (
            self.failure.as_ref(),
            error.downcast_ref::<SetupFailure>(),
        ) {
            if Arc::ptr_eq(&previous.0, &returned.0) {
                return;
            }
        }
        let combined = match self.failure.take() {
            Some(previous) => finish_with_cleanup::<()>(Err(Box::new(previous)), Err(error)),
            None => Err(error),
        };
        self.failure = combined.err().map(|error| SetupFailure(Arc::from(error)));
    }
}

#[derive(Clone, Debug)]
struct SetupFailure(Arc<dyn Error + Send + Sync>);

impl fmt::Display for SetupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.0.as_ref(), formatter)
    }
}

impl Error for SetupFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error, io, net::Ipv4Addr, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        task::JoinError,
        time::timeout,
    };

    use super::{EstablishedTunnel, TestResult, TunnelSetup};
    use crate::support::tunnel_proxy::{connection_peer::FixtureFailures, http1_connect};

    const DEADLINE: Duration = Duration::from_secs(5);

    fn cause<'a, E: Error + 'static>(error: &'a (dyn Error + 'static)) -> Option<&'a E> {
        if let Some(found) = error.downcast_ref::<E>() {
            return Some(found);
        }
        if let Some(failures) = error.downcast_ref::<FixtureFailures>() {
            return cause(failures.primary.as_ref()).or_else(|| cause(failures.cleanup.as_ref()));
        }
        error.source().and_then(cause::<E>)
    }

    async fn closed(stream: &mut TcpStream) -> TestResult<()> {
        let result = timeout(DEADLINE, stream.read(&mut [0_u8; 1])).await?;
        assert!(
            matches!(result, Ok(0))
                || matches!(result, Err(ref error) if crate::support::tls::is_peer_gone(error))
        );
        Ok(())
    }

    async fn pending_setup() -> TestResult<(TunnelSetup<Vec<u8>>, TcpStream)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let owner = TunnelSetup::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            stream.write_all(b"ready").await?;
            stream.read_u8().await?;
            TestResult::<EstablishedTunnel<Vec<u8>>>::Err("unexpected setup input".into())
        });
        let mut client = TcpStream::connect(address).await?;
        let mut ready = [0_u8; 5];
        timeout(DEADLINE, client.read_exact(&mut ready)).await??;
        assert_eq!(&ready, b"ready");
        Ok((owner, client))
    }

    #[tokio::test]
    async fn setup_shutdown_retains_a_pending_external_cancellation() -> TestResult<()> {
        let (mut owner, mut client) = pending_setup().await?;
        let task = owner
            .task
            .as_ref()
            .ok_or("setup task missing")?
            .abort_handle();
        let id = task.id();
        task.abort();

        let error = owner
            .finish(Ok(()))
            .await
            .err()
            .ok_or("external abort was discarded")?;
        let joined = cause::<JoinError>(error.as_ref()).ok_or("original JoinError missing")?;
        assert!(joined.is_cancelled());
        assert_eq!(joined.id(), id);
        assert!(owner.task.is_none());
        assert!(task.is_finished());
        closed(&mut client).await?;
        Ok(())
    }

    #[tokio::test]
    async fn a_caller_deadline_retains_and_stops_its_pending_setup() -> TestResult<()> {
        let (mut owner, mut client) = pending_setup().await?;
        let task = owner
            .task
            .as_ref()
            .ok_or("setup task missing")?
            .abort_handle();
        let elapsed = timeout(Duration::from_millis(10), owner.establish())
            .await
            .err()
            .ok_or("silent setup completed")?;
        assert!(owner.task.is_some());

        let error = owner
            .finish(Err(elapsed.into()))
            .await
            .err()
            .ok_or("caller deadline was discarded")?;
        assert!(cause::<tokio::time::error::Elapsed>(error.as_ref()).is_some());
        assert!(owner.task.is_none());
        assert!(task.is_finished());
        closed(&mut client).await?;
        Ok(())
    }

    #[tokio::test]
    async fn an_interrupted_finish_retains_the_established_tunnel_and_original_cause()
    -> TestResult<()> {
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = proxy.local_addr()?;
        let mut owner = TunnelSetup::spawn(http1_connect(proxy, origin.local_addr()?));
        let mut client = TcpStream::connect(address).await?;
        client
            .write_all(b"CONNECT retained.test:443 HTTP/1.1\r\n\r\n")
            .await?;
        let (mut upstream, _) = timeout(DEADLINE, origin.accept()).await??;
        let mut response = [0_u8; 39];
        timeout(DEADLINE, client.read_exact(&mut response)).await??;
        assert_eq!(&response, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        assert_eq!(
            timeout(DEADLINE, owner.establish()).await??,
            b"CONNECT retained.test:443 HTTP/1.1\r\n\r\n"
        );
        assert!(owner.task.is_none());
        assert!(owner.tunnel.is_some());

        let original = Box::new(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "caller after CONNECT",
        ));
        let original_pointer = original.as_ref() as *const io::Error;
        {
            let finish = owner.finish(Err(original));
            tokio::pin!(finish);
            assert!(futures_util::poll!(&mut finish).is_pending());
        }
        assert!(owner.tunnel.is_some());
        let error = owner
            .finish(Ok(()))
            .await
            .err()
            .ok_or("original caller failure missing")?;
        let retained = cause::<io::Error>(error.as_ref()).ok_or("original I/O cause missing")?;
        assert_eq!(retained.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(retained as *const io::Error, original_pointer);
        closed(&mut client).await?;
        closed(&mut upstream).await?;
        Ok(())
    }
}
