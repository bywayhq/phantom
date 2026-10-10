use std::{error::Error, fmt, net::Ipv4Addr, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};

use super::PlaintextPeer;
use crate::support::tls::{TestResult, is_peer_gone, read_head};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);
const HEAD: &[u8] = b"GET /ownership HTTP/1.1\r\nHost: loopback.test\r\n\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";

struct PeerDestroyed(Option<oneshot::Sender<()>>);

impl Drop for PeerDestroyed {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            // The observation may already be cancelled with its enclosing test.
            let _ = sender.send(());
        }
    }
}

#[derive(Debug)]
struct PeerFailure;

impl fmt::Display for PeerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("plaintext persistence peer failed")
    }
}

impl Error for PeerFailure {}

#[tokio::test]
async fn cancelling_a_driven_plaintext_owner_closes_the_retained_client_socket() -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut client = TcpStream::connect(listener.local_addr()?).await?;
        let (destroyed, mut destruction) = oneshot::channel();
        let server = PlaintextPeer::spawn(async move {
            let _destroyed = PeerDestroyed(Some(destroyed));
            let (mut stream, _) = listener.accept().await?;
            assert_eq!(read_head(&mut stream).await?, HEAD);
            stream.write_all(RESPONSE).await?;
            let mut byte = [0_u8; 1];
            assert_eq!(stream.read(&mut byte).await?, 0);
            Ok(())
        });
        let abort = server.task.abort_handle();
        client.write_all(HEAD).await?;
        assert_eq!(read_head(&mut client).await?, RESPONSE);

        drop(server);
        let mut byte = [0_u8; 1];
        let closed = timeout(CONTROL_TIMEOUT, client.read(&mut byte)).await;
        let peer_closed = match &closed {
            Ok(Ok(0)) => true,
            Ok(Err(error)) => is_peer_gone(error),
            _ => false,
        };
        let destroyed_before_client_close = destruction.try_recv().is_ok();

        if !destroyed_before_client_close {
            // Reap the intentionally defective baseline while the client is retained.
            abort.abort();
            timeout(CONTROL_TIMEOUT, &mut destruction).await??;
        }

        assert!(
            peer_closed,
            "peer remained open after cancellation: {closed:?}"
        );
        assert!(destroyed_before_client_close);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn a_completed_plaintext_failure_retains_its_original_type() -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut client = TcpStream::connect(listener.local_addr()?).await?;
        let server = PlaintextPeer::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            assert_eq!(read_head(&mut stream).await?, HEAD);
            stream.write_all(RESPONSE).await?;
            Err(Box::new(PeerFailure) as Box<dyn Error + Send + Sync>)
        });
        client.write_all(HEAD).await?;
        assert_eq!(read_head(&mut client).await?, RESPONSE);

        let error = timeout(CONTROL_TIMEOUT, server.finish())
            .await?
            .err()
            .ok_or("failed plaintext peer was accepted")?;
        assert!(error.downcast_ref::<PeerFailure>().is_some());
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn a_successful_plaintext_peer_keeps_literal_exchange_bytes() -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut client = TcpStream::connect(listener.local_addr()?).await?;
        let server = PlaintextPeer::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            assert_eq!(read_head(&mut stream).await?, HEAD);
            stream.write_all(RESPONSE).await?;
            Ok(())
        });
        client.write_all(HEAD).await?;
        assert_eq!(read_head(&mut client).await?, RESPONSE);
        timeout(CONTROL_TIMEOUT, server.finish()).await??;
        Ok(())
    })
    .await?
}
