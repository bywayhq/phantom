use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::task::{JoinError, JoinHandle};

use super::TestResult;

pub(crate) struct ConnectionPeer<T> {
    task: JoinHandle<T>,
}

impl<T: Send + 'static> ConnectionPeer<T> {
    pub(crate) fn spawn(future: impl Future<Output = T> + Send + 'static) -> Self {
        Self {
            task: tokio::spawn(future),
        }
    }

    pub(crate) fn abort(&self) {
        self.task.abort();
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

impl<T> Future for ConnectionPeer<T> {
    type Output = Result<T, JoinError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.get_mut().task).poll(context)
    }
}

impl<T: Send + 'static> ConnectionPeer<TestResult<T>> {
    pub(crate) async fn stop(self) -> TestResult<()> {
        self.abort();
        Ok(())
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

    use super::{ConnectionPeer, TestResult};

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
