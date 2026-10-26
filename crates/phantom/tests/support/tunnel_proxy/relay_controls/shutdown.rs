use std::{
    error::Error,
    future::{Future, poll_fn},
    io,
    net::Ipv4Addr,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    task::JoinError,
    time::timeout,
};

use super::super::{EstablishedTunnel, connection_peer::FixtureFailures, spawn_relay};
use super::{ConnectionPeer, DEADLINE, TestResult, http1_connect};

async fn ready_tunnel() -> TestResult<(EstablishedTunnel<Vec<u8>>, TcpStream, TcpStream)> {
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = proxy.local_addr()?;
    let launcher = ConnectionPeer::spawn(http1_connect(proxy, origin.local_addr()?));
    let mut client = timeout(DEADLINE, TcpStream::connect(address)).await??;
    client
        .write_all(b"CONNECT shutdown.test:443 HTTP/1.1\r\n\r\n")
        .await?;
    let (mut upstream, _) = timeout(DEADLINE, origin.accept()).await??;
    let mut established = [0_u8; 39];
    timeout(DEADLINE, client.read_exact(&mut established)).await??;
    assert_eq!(&established, b"HTTP/1.1 200 Connection Established\r\n\r\n");
    let tunnel = timeout(DEADLINE, launcher).await???;

    client.write_all(b"ping").await?;
    let mut observed = [0_u8; 4];
    timeout(DEADLINE, upstream.read_exact(&mut observed)).await??;
    assert_eq!(&observed, b"ping");
    Ok((tunnel, client, upstream))
}

async fn assert_closed(stream: &mut TcpStream) -> TestResult<()> {
    let closed = timeout(DEADLINE, stream.read(&mut [0_u8; 1])).await?;
    assert!(
        matches!(closed, Ok(0))
            || matches!(closed, Err(ref error) if crate::support::tls::is_peer_gone(error))
    );
    Ok(())
}

fn cause<'a, E: Error + 'static>(error: &'a (dyn Error + 'static)) -> Option<&'a E> {
    if let Some(found) = error.downcast_ref::<E>() {
        return Some(found);
    }
    if let Some(failures) = error.downcast_ref::<FixtureFailures>() {
        return cause(failures.primary.as_ref()).or_else(|| cause(failures.cleanup.as_ref()));
    }
    error.source().and_then(cause::<E>)
}

fn caller_failure() -> TestResult<Box<dyn Error + Send + Sync>> {
    use phantom::{
        Client, HttpProtocol, RequestErrorKind,
        profile::{ClientProfile, browser::chrome},
    };

    let client = Client::builder(ClientProfile::new(chrome::v154_tcp_tls())).build()?;
    let error = client
        .get_with_protocol(HttpProtocol::Http1, "https://[invalid/")
        .err()
        .ok_or("malformed authority was accepted")?;
    assert_eq!(error.kind(), RequestErrorKind::InvalidAuthority);
    Ok(Box::new(error))
}

#[tokio::test]
async fn tunnel_shutdown_distinguishes_local_stop_from_pending_external_abort() -> TestResult<()> {
    for external in [false, true] {
        let (mut tunnel, mut client, mut upstream) = ready_tunnel().await?;
        let task = tunnel.peers[0]
            .abort_handle()
            .ok_or("relay was not owned")?;
        let task_id = task.id();
        if external {
            task.abort();
        }

        // Do not wait for is_finished: foreign cancellation can still be pending
        // when the local shutdown signal is sent.
        let result = tunnel.finish(Ok(())).await;
        assert!(tunnel.peers.is_empty());
        if external {
            let error = result.err().ok_or("external cancellation was discarded")?;
            let joined = cause::<JoinError>(error.as_ref()).ok_or("original JoinError was lost")?;
            assert!(joined.is_cancelled());
            assert_eq!(joined.id(), task_id);
        } else {
            result?;
        }
        assert!(task.is_finished());
        assert_closed(&mut upstream).await?;
        assert_closed(&mut client).await?;
    }
    Ok(())
}

#[tokio::test]
async fn interrupted_tunnel_finish_retains_the_caller_failure_and_original_relay() -> TestResult<()>
{
    let (mut tunnel, mut client, mut upstream) = ready_tunnel().await?;
    let task = tunnel.peers[0]
        .abort_handle()
        .ok_or("relay was not owned")?;
    let primary = caller_failure()?;
    let original = primary
        .downcast_ref::<phantom::RequestError>()
        .ok_or("caller did not return its original request error")?
        as *const phantom::RequestError;
    {
        let finish = tunnel.finish(Err(primary));
        tokio::pin!(finish);
        poll_fn(|context| {
            assert!(finish.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        // Dropping this borrowed cleanup future leaves its actual worker and the
        // initiating error on the outer owner for a later cleanup attempt.
    }

    let error = tunnel
        .finish(Ok(()))
        .await
        .err()
        .ok_or("caller failure was discarded")?;
    let retained =
        cause::<phantom::RequestError>(error.as_ref()).ok_or("original caller error was lost")?;
    assert!(std::ptr::eq(retained, original));
    assert!(tunnel.peers.is_empty());
    assert!(task.is_finished());
    assert_closed(&mut upstream).await?;
    assert_closed(&mut client).await?;
    Ok(())
}

struct FailedRead(TcpStream);

impl AsyncRead for FailedRead {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "original relay read failure",
        )))
    }
}

impl AsyncWrite for FailedRead {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(context, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(context)
    }
}

#[tokio::test]
async fn completed_relay_failure_and_caller_failure_collect_later_tunnel_owners() -> TestResult<()>
{
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let mut client = timeout(DEADLINE, TcpStream::connect(listener.local_addr()?)).await??;
    let (downstream, _) = timeout(DEADLINE, listener.accept()).await??;
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream = timeout(DEADLINE, TcpStream::connect(origin.local_addr()?)).await??;
    let (mut origin_client, _) = timeout(DEADLINE, origin.accept()).await??;
    let failed = EstablishedTunnel::new((), spawn_relay(FailedRead(downstream), upstream));
    timeout(DEADLINE, async {
        while !failed.peers[0].is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let (later, mut later_client, mut later_origin) = ready_tunnel().await?;
    let later_task = later.peers[0]
        .abort_handle()
        .ok_or("later relay was not owned")?;
    let mut tunnel = failed.combine(later).map(|(_, head)| head);

    let error = tunnel
        .finish(Err(caller_failure()?))
        .await
        .err()
        .ok_or("both failures were discarded")?;
    let worker = cause::<io::Error>(error.as_ref()).ok_or("original worker I/O error was lost")?;
    assert_eq!(worker.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(worker.to_string(), "original relay read failure");
    assert!(cause::<phantom::RequestError>(error.as_ref()).is_some());
    assert!(tunnel.peers.is_empty());
    assert!(later_task.is_finished());
    assert_closed(&mut client).await?;
    assert_closed(&mut origin_client).await?;
    assert_closed(&mut later_client).await?;
    assert_closed(&mut later_origin).await?;
    Ok(())
}
