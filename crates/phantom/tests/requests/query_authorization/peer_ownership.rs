use std::{error::Error, fmt, future::pending, net::Ipv4Addr, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};

use super::{bounded, exchange, serve_continue};
use crate::support::tls::{TestResult, is_peer_gone, read_head};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);
const HEAD: &[u8] = b"POST /ownership HTTP/1.1\r\nHost: loopback.test\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n";
const CONTINUE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";
const FINAL: &[u8] = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";

struct PeerDestroyed(Option<oneshot::Sender<()>>);

impl Drop for PeerDestroyed {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            // A cancelled outer test may no longer observe the signal.
            let _ = sender.send(());
        }
    }
}

#[derive(Debug)]
struct PeerFailure;

impl fmt::Display for PeerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("driven query peer failed")
    }
}

impl Error for PeerFailure {}

#[tokio::test]
async fn owner_cancellation_closes_a_driven_continue_peer() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut client = TcpStream::connect(listener.local_addr()?).await?;
        let (destroyed, mut destruction) = oneshot::channel();
        let peer = async move {
            let _destroyed = PeerDestroyed(Some(destroyed));
            serve_continue(listener).await
        };
        let mut owner = Box::pin(exchange(peer, pending::<TestResult<()>>()));
        client.write_all(HEAD).await?;

        let response = tokio::select! {
            response = read_head(&mut client) => response?,
            result = &mut owner => {
                result?;
                return Err("peer owner ended before the readiness response".into());
            }
        };
        assert_eq!(response, CONTINUE);

        drop(owner);
        let mut byte = [0_u8; 1];
        let closed = timeout(CONTROL_TIMEOUT, client.read(&mut byte)).await;
        let peer_closed = match &closed {
            Ok(Ok(0)) => true,
            Ok(Err(error)) => is_peer_gone(error),
            _ => false,
        };
        let destroyed_before_client_close = destruction.try_recv().is_ok();

        if !destroyed_before_client_close {
            // Reap the defective baseline peer before reporting its failure.
            client.shutdown().await?;
            drop(client);
            timeout(CONTROL_TIMEOUT, &mut destruction).await??;
        }

        assert!(
            peer_closed,
            "peer stayed open after owner cancellation: {closed:?}"
        );
        assert!(destroyed_before_client_close);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn completed_continue_peer_failure_is_returned_with_its_type() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut client = TcpStream::connect(listener.local_addr()?).await?;
        let (destroyed, destruction) = oneshot::channel();
        let peer = async move {
            let _destroyed = PeerDestroyed(Some(destroyed));
            let (head, body) = serve_continue(listener).await?;
            assert_eq!(head.as_bytes(), HEAD);
            assert_eq!(&body, b"data");
            Err::<(String, [u8; 4]), _>(Box::new(PeerFailure) as Box<dyn Error + Send + Sync>)
        };
        let owner = exchange(peer, pending::<TestResult<()>>());
        client.write_all(HEAD).await?;
        let response = async {
            assert_eq!(read_head(&mut client).await?, CONTINUE);
            client.write_all(b"data").await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(read_head(&mut client).await?)
        };

        let (result, response) = tokio::join!(timeout(CONTROL_TIMEOUT, owner), response);
        assert_eq!(response?, FINAL);
        timeout(CONTROL_TIMEOUT, destruction).await??;

        let error: Box<dyn Error + Send + Sync> = match result {
            Ok(Err(error)) => error,
            Ok(Ok(_)) => return Err("failed peer was accepted".into()),
            Err(error) => Box::new(error),
        };
        assert!(error.downcast_ref::<PeerFailure>().is_some(), "{error}");
        Ok(())
    })
    .await
}
