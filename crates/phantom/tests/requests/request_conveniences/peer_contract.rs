use std::{error::Error, fmt, future::pending, net::Ipv4Addr, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};

use super::exchange_peer;
use crate::support::tls::{TestResult, is_peer_gone, read_head};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);
const HEAD: &[u8] = b"GET /ownership HTTP/1.1\r\nHost: loopback.test\r\n\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";

struct PeerDestroyed(Option<oneshot::Sender<()>>);

impl Drop for PeerDestroyed {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            // A cancelled enclosing test may no longer observe the signal.
            let _ = sender.send(());
        }
    }
}

#[derive(Debug)]
struct PeerFailure;

impl fmt::Display for PeerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("driven request conveniences peer failed")
    }
}

impl Error for PeerFailure {}

#[tokio::test]
async fn successful_peer_exchange_keeps_literal_request_and_response_bytes() -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut client = TcpStream::connect(listener.local_addr()?).await?;
        let peer = async move {
            let (mut stream, _) = listener.accept().await?;
            let head = read_head(&mut stream).await?;
            stream.write_all(RESPONSE).await?;
            Ok(head)
        };
        let request = async {
            client.write_all(HEAD).await?;
            Ok(read_head(&mut client).await?)
        };

        let (head, response) = exchange_peer(peer, request).await?;
        assert_eq!(head, HEAD);
        assert_eq!(response, RESPONSE);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn owner_cancellation_closes_a_driven_peer_with_client_retained() -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut client = TcpStream::connect(listener.local_addr()?).await?;
        let (destroyed, mut destruction) = oneshot::channel();
        let peer = async move {
            let _destroyed = PeerDestroyed(Some(destroyed));
            let (mut stream, _) = listener.accept().await?;
            assert_eq!(read_head(&mut stream).await?, HEAD);
            stream.write_all(RESPONSE).await?;
            let mut byte = [0_u8; 1];
            assert_eq!(stream.read(&mut byte).await?, 0);
            Ok(())
        };
        let mut owner = Box::pin(exchange_peer(peer, pending::<TestResult<()>>()));
        client.write_all(HEAD).await?;

        let response = tokio::select! {
            response = read_head(&mut client) => response?,
            result = &mut owner => {
                result?;
                return Err("peer owner ended before its readiness response".into());
            }
        };
        assert_eq!(response, RESPONSE);

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
            // Close the client after recording peer state, then await destruction.
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
    .await?
}

#[tokio::test]
async fn a_completed_driven_peer_failure_keeps_its_original_type() -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut client = TcpStream::connect(listener.local_addr()?).await?;
        let (destroyed, destruction) = oneshot::channel();
        let peer = async move {
            let _destroyed = PeerDestroyed(Some(destroyed));
            let (mut stream, _) = listener.accept().await?;
            assert_eq!(read_head(&mut stream).await?, HEAD);
            stream.write_all(RESPONSE).await?;
            Err::<(), _>(Box::new(PeerFailure) as Box<dyn Error + Send + Sync>)
        };
        let owner = exchange_peer(peer, pending::<TestResult<()>>());
        client.write_all(HEAD).await?;

        let (result, response) =
            tokio::join!(timeout(CONTROL_TIMEOUT, owner), read_head(&mut client));
        assert_eq!(response?, RESPONSE);
        timeout(CONTROL_TIMEOUT, destruction).await??;

        let error: Box<dyn Error + Send + Sync> = match result {
            Ok(Err(error)) => error,
            Ok(Ok(_)) => return Err("failed peer was accepted".into()),
            Err(error) => Box::new(error),
        };
        assert!(error.downcast_ref::<PeerFailure>().is_some(), "{error}");
        Ok(())
    })
    .await?
}

#[test]
fn identical_retry_heads_must_still_contain_the_literal_hook_result() {
    let present = b"GET /retry HTTP/1.1\r\nX-Sequence: 0\r\n\r\n".to_vec();
    assert!(super::retry_heads_reuse_hook_result(&[
        present.clone(),
        present
    ]));

    let missing = b"GET /retry HTTP/1.1\r\n\r\n".to_vec();
    assert!(!super::retry_heads_reuse_hook_result(&[
        missing.clone(),
        missing
    ]));
}

#[test]
fn cookie_removal_requires_the_first_hop_to_have_sent_it() {
    let first = "GET /start HTTP/1.1\r\nCookie: fixture-cookie\r\n\r\n";
    let second = "GET /next HTTP/1.1\r\n\r\n";
    assert!(super::cookie_transition(first, second, "fixture-cookie"));

    let absent = "GET /start HTTP/1.1\r\n\r\n";
    assert!(!super::cookie_transition(absent, second, "fixture-cookie"));
}
