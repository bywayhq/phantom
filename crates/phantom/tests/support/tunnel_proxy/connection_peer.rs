use std::{
    error::Error,
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    task::{JoinError, JoinHandle},
    time::timeout,
};

use super::TestResult;

#[derive(Debug)]
pub(crate) struct ConnectionPeer<T> {
    task: JoinHandle<T>,
}

impl<T> Drop for ConnectionPeer<T> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl<T: Send + 'static> ConnectionPeer<T> {
    pub(crate) fn from_task(task: JoinHandle<T>) -> Self {
        Self { task }
    }

    pub(crate) fn spawn(future: impl Future<Output = T> + Send + 'static) -> Self {
        Self::from_task(tokio::spawn(future))
    }

    pub(crate) fn abort(&self) {
        self.task.abort();
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

impl<T: Send + 'static> From<JoinHandle<T>> for ConnectionPeer<T> {
    fn from(task: JoinHandle<T>) -> Self {
        Self::from_task(task)
    }
}

impl<T> Future for ConnectionPeer<T> {
    type Output = Result<T, JoinError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.get_mut().task).poll(context)
    }
}

impl<T: Send + 'static> ConnectionPeer<TestResult<T>> {
    pub(crate) async fn stop(mut self) -> TestResult<()> {
        self.abort();

        match timeout(Duration::from_secs(5), &mut self).await? {
            Ok(result) => result.map(|_| ()),
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

/// Retains both outcomes when explicit fixture shutdown also fails.
#[derive(Debug)]
pub(crate) struct FixtureFailures {
    pub(crate) primary: Box<dyn Error + Send + Sync>,
    pub(crate) cleanup: Box<dyn Error + Send + Sync>,
}

impl fmt::Display for FixtureFailures {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; fixture cleanup also failed: {}",
            self.primary, self.cleanup
        )
    }
}

impl Error for FixtureFailures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.primary.as_ref())
    }
}

pub(crate) fn finish_with_cleanup<T>(
    primary: TestResult<T>,
    cleanup: TestResult<()>,
) -> TestResult<T> {
    match (primary, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(Box::new(FixtureFailures { primary, cleanup })),
    }
}

#[cfg(test)]
mod tests {
    use std::{io, net::Ipv4Addr, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::timeout,
    };

    use super::{ConnectionPeer, FixtureFailures, TestResult, finish_with_cleanup};

    const DEADLINE: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn dropping_an_accepted_peer_closes_its_socket_with_runtime_live() -> TestResult<()> {
        let (peer, mut client, address) = ready_peer().await?;
        drop(peer);

        let closed = timeout(DEADLINE, client.read_u8()).await;
        client.shutdown().await?;
        drop(client);

        assert!(
            matches!(closed, Ok(Err(ref error)) if super::super::super::tls::is_peer_gone(error))
        );
        let rebound = TcpListener::bind(address).await?;
        assert_eq!(rebound.local_addr()?, address);
        Ok(())
    }

    #[tokio::test]
    async fn explicit_abort_and_join_closes_an_accepted_peer() -> TestResult<()> {
        let (peer, mut client, address) = ready_peer().await?;
        peer.abort();
        let joined = timeout(DEADLINE, peer).await?;
        assert!(matches!(joined, Err(ref error) if error.is_cancelled()));

        let closed = timeout(DEADLINE, client.read(&mut [0_u8; 1])).await?;
        assert!(
            matches!(closed, Ok(0))
                || matches!(closed, Err(ref error) if super::super::super::tls::is_peer_gone(error))
        );
        let rebound = TcpListener::bind(address).await?;
        assert_eq!(rebound.local_addr()?, address);
        Ok(())
    }

    #[tokio::test]
    async fn stopping_a_completed_peer_keeps_its_typed_failure() -> TestResult<()> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let peer = ConnectionPeer::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            assert_eq!(stream.read_u8().await?, b'!');
            stream.write_all(b"ready").await?;
            TestResult::<()>::Err(
                io::Error::new(io::ErrorKind::PermissionDenied, LateFailure).into(),
            )
        });
        let mut client = TcpStream::connect(address).await?;
        client.write_all(b"!").await?;
        let mut ready = [0_u8; 5];
        timeout(DEADLINE, client.read_exact(&mut ready)).await??;
        assert_eq!(&ready, b"ready");

        timeout(DEADLINE, async {
            while !peer.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let Err(error) = peer.stop().await else {
            return Err("late peer failure was discarded".into());
        };

        let io = error
            .downcast_ref::<io::Error>()
            .ok_or("missing original I/O cause")?;
        assert_eq!(io.kind(), io::ErrorKind::PermissionDenied);
        assert!(io.get_ref().is_some_and(|cause| cause.is::<LateFailure>()));
        Ok(())
    }

    #[tokio::test]
    async fn a_primary_failure_and_late_peer_failure_keep_both_typed_causes() -> TestResult<()> {
        let primary: TestResult<()> =
            Err(io::Error::new(io::ErrorKind::InvalidInput, "primary request failure").into());
        let peer = ConnectionPeer::spawn(async {
            TestResult::<()>::Err(
                io::Error::new(io::ErrorKind::PermissionDenied, LateFailure).into(),
            )
        });
        timeout(DEADLINE, async {
            while !peer.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;

        let error = finish_with_cleanup(primary, peer.stop().await)
            .err()
            .ok_or("both failures were discarded")?;
        let causes = error
            .downcast_ref::<FixtureFailures>()
            .ok_or("missing simultaneous causes")?;
        let primary = causes
            .primary
            .downcast_ref::<io::Error>()
            .ok_or("missing primary I/O cause")?;
        let cleanup = causes
            .cleanup
            .downcast_ref::<io::Error>()
            .ok_or("missing cleanup I/O cause")?;
        assert_eq!(primary.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(cleanup.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            cleanup
                .get_ref()
                .is_some_and(|cause| cause.is::<LateFailure>())
        );
        Ok(())
    }

    async fn ready_peer() -> TestResult<(
        ConnectionPeer<TestResult<()>>,
        TcpStream,
        std::net::SocketAddr,
    )> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let peer = ConnectionPeer::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await?;
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await?;
            stream.read_u8().await?;
            TestResult::Ok(())
        });
        let mut client = TcpStream::connect(address).await?;
        client.write_all(b"ping").await?;
        let mut reply = [0_u8; 4];
        timeout(DEADLINE, client.read_exact(&mut reply)).await??;
        assert_eq!(&reply, b"pong");
        Ok((peer, client, address))
    }

    #[derive(Debug)]
    struct LateFailure;

    impl std::fmt::Display for LateFailure {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("injected late connection failure")
        }
    }

    impl std::error::Error for LateFailure {}
}
