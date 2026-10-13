use std::{error::Error, fmt, future::pending, net::Ipv4Addr, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};

use super::{bounded, no_content, receive_heads, serve};
use crate::support::tls::{TestResult, is_peer_gone, read_head};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);
const HEAD: &[u8] = b"GET /ownership HTTP/1.1\r\nHost: loopback.test\r\n\r\n";

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
        formatter.write_str("driven plaintext peer failed")
    }
}

impl Error for PeerFailure {}

#[tokio::test]
async fn owner_cancellation_closes_a_driven_plaintext_peer() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut client = TcpStream::connect(listener.local_addr()?).await?;
        let (destroyed, mut destruction) = oneshot::channel();
        let peer = async move {
            let _destroyed = PeerDestroyed(Some(destroyed));
            serve(listener, vec![no_content(), no_content()]).await
        };
        let mut owner = Box::pin(receive_heads(peer, pending::<TestResult<()>>()));
        client.write_all(HEAD).await?;

        let response = tokio::select! {
            response = read_head(&mut client) => response?,
            result = &mut owner => {
                result?;
                return Err("peer owner ended before the readiness response".into());
            }
        };
        assert_eq!(response, no_content());

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
async fn completed_plaintext_peer_failure_is_returned_with_its_type() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut client = TcpStream::connect(listener.local_addr()?).await?;
        let (destroyed, destruction) = oneshot::channel();
        let peer = async move {
            let _destroyed = PeerDestroyed(Some(destroyed));
            let heads = serve(listener, vec![no_content()]).await?;
            assert_eq!(heads, [String::from_utf8(HEAD.to_vec())?]);
            Err::<Vec<String>, _>(Box::new(PeerFailure) as Box<dyn Error + Send + Sync>)
        };
        let owner = receive_heads(peer, pending::<TestResult<()>>());
        client.write_all(HEAD).await?;

        let (result, response) =
            tokio::join!(timeout(CONTROL_TIMEOUT, owner), read_head(&mut client),);
        assert_eq!(response?, no_content());
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
