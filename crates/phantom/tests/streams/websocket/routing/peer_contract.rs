use std::{
    error::Error,
    fmt,
    net::Ipv4Addr,
    sync::{Arc, Weak},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::{AbortHandle, JoinHandle},
    time::timeout,
};

use super::{
    ClientFrame, ProxyOpening, TestResult, accept_opening, finish_connect_route,
    finish_opening_proxy, read_head, tunnel_and_accept,
};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

struct PeerDestroyed(Option<oneshot::Sender<()>>);

impl Drop for PeerDestroyed {
    fn drop(&mut self) {
        if let Some(observer) = self.0.take() {
            // An earlier test failure may have dropped the observation future.
            let _ = observer.send(());
        }
    }
}

struct ControlPeer {
    abort: AbortHandle,
    destruction: oneshot::Receiver<()>,
}

impl Drop for ControlPeer {
    fn drop(&mut self) {
        // This independent fallback owner stays live through the observation.
        self.abort.abort();
    }
}

async fn driven_opening_peer()
-> TestResult<(JoinHandle<TestResult<ProxyOpening>>, TcpStream, ControlPeer)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let (destroyed, destruction) = oneshot::channel();
    let peer = tokio::spawn(async move {
        let _destroyed = PeerDestroyed(Some(destroyed));
        let (mut stream, _) = listener.accept().await?;
        tunnel_and_accept(&mut stream, b"owned").await
    });
    let control = ControlPeer {
        abort: peer.abort_handle(),
        destruction,
    };
    let mut client = TcpStream::connect(address).await?;
    client
        .write_all(b"CONNECT origin.test:443 HTTP/1.1\r\nHost: origin.test:443\r\n\r\n")
        .await?;
    assert_eq!(
        read_head(&mut client).await?,
        b"HTTP/1.1 200 Connection Established\r\n\r\n".as_slice()
    );
    client
        .write_all(b"GET /owned HTTP/1.1\r\nHost: origin.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
        .await?;
    assert_eq!(
        read_head(&mut client).await?,
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n".as_slice()
    );
    let mut ping = [0_u8; 7];
    client.read_exact(&mut ping).await?;
    assert_eq!(&ping, b"\x89\x05owned");
    Ok((peer, client, control))
}

#[tokio::test]
async fn cancelling_the_opening_owner_closes_its_driven_peer_with_client_retained() -> TestResult<()>
{
    timeout(CONTROL_TIMEOUT * 3, async {
        let (peer, mut client, mut control) = driven_opening_peer().await?;
        let mut owner = Box::pin(finish_opening_proxy(peer));
        assert!(futures_util::poll!(&mut owner).is_pending());
        // Drop the actual owner future, while both client and fallback stay live.
        drop(owner);

        let stopped_before_fallback = match timeout(CONTROL_TIMEOUT, &mut control.destruction).await
        {
            Ok(result) => {
                result?;
                true
            }
            Err(_) => {
                control.abort.abort();
                timeout(CONTROL_TIMEOUT, &mut control.destruction).await??;
                false
            }
        };
        let mut byte = [0_u8; 1];
        assert_eq!(timeout(CONTROL_TIMEOUT, client.read(&mut byte)).await??, 0);
        assert!(
            stopped_before_fallback,
            "the driven opening peer survived owner cancellation"
        );
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn a_driven_opening_owner_retains_the_literal_connect_opening_and_pong() -> TestResult<()> {
    timeout(CONTROL_TIMEOUT, async {
        let (peer, mut client, mut control) = driven_opening_peer().await?;
        // Literal masked Pong: mask 01 02 03 04, payload "owned".
        client.write_all(b"\x8a\x85\x01\x02\x03\x04numae").await?;
        let (connect, opening, pong) = finish_opening_proxy(peer).await?;
        assert_eq!(
            connect,
            b"CONNECT origin.test:443 HTTP/1.1\r\nHost: origin.test:443\r\n\r\n".as_slice()
        );
        assert!(opening.starts_with(b"GET /owned HTTP/1.1\r\nHost: origin.test\r\n"));
        assert_eq!(
            pong,
            ClientFrame {
                rsv1: false,
                opcode: 0xA,
                payload: b"owned".to_vec(),
            }
        );
        (&mut control.destruction).await?;
        let mut byte = [0_u8; 1];
        assert_eq!(client.read(&mut byte).await?, 0);
        Ok(())
    })
    .await?
}

#[derive(Debug)]
struct ProxyFailure(Arc<()>);

impl fmt::Display for ProxyFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled CONNECT proxy failed")
    }
}

impl Error for ProxyFailure {}

#[derive(Debug)]
struct OriginFailure(Arc<()>);

impl fmt::Display for OriginFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled tunneled origin failed")
    }
}

impl Error for OriginFailure {}

fn find_source<'a, T: Error + 'static>(mut error: &'a (dyn Error + 'static)) -> Option<&'a T> {
    loop {
        if let Some(found) = error.downcast_ref::<T>() {
            return Some(found);
        }

        error = error.source()?;
    }
}

async fn driven_failed_head_peer(
    failure: Box<dyn Error + Send + Sync>,
    exchange: HeadExchange,
) -> TestResult<(JoinHandle<TestResult<Vec<u8>>>, DuplexStream, ControlPeer)> {
    let (mut client, mut stream) = tokio::io::duplex(64);
    let (destroyed, destruction) = oneshot::channel();
    let peer = tokio::spawn(async move {
        let _destroyed = PeerDestroyed(Some(destroyed));
        match exchange {
            HeadExchange::Connect => {
                assert_eq!(
                    read_head(&mut stream).await?,
                    b"CONNECT origin.test:443 HTTP/1.1\r\nHost: origin.test:443\r\n\r\n".as_slice()
                );
                stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
            }
            HeadExchange::Opening => {
                let opening = accept_opening(&mut stream).await?;
                assert!(opening.starts_with(b"GET /through-proxy HTTP/1.1\r\n"));
            }
        }
        Err(failure)
    });
    let mut control = ControlPeer {
        abort: peer.abort_handle(),
        destruction,
    };
    let (request, response): (&[u8], &[u8]) = match exchange {
        HeadExchange::Connect => (
            b"CONNECT origin.test:443 HTTP/1.1\r\nHost: origin.test:443\r\n\r\n",
            b"HTTP/1.1 200 Connection Established\r\n\r\n",
        ),
        HeadExchange::Opening => (
            b"GET /through-proxy HTTP/1.1\r\nHost: origin.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        ),
    };
    client.write_all(request).await?;
    assert_eq!(read_head(&mut client).await?, response);
    (&mut control.destruction).await?;
    let mut byte = [0_u8; 1];
    assert_eq!(client.read(&mut byte).await?, 0);
    Ok((peer, client, control))
}

#[derive(Clone, Copy)]
enum HeadExchange {
    Connect,
    Opening,
}

#[tokio::test]
async fn an_early_proxy_failure_retains_the_completed_origin_failure() -> TestResult<()> {
    timeout(CONTROL_TIMEOUT, async {
        let proxy_retained = Arc::new(());
        let origin_retained = Arc::new(());
        let proxy_observed: Weak<()> = Arc::downgrade(&proxy_retained);
        let origin_observed: Weak<()> = Arc::downgrade(&origin_retained);
        let (proxy, _proxy_client, _proxy_control) = driven_failed_head_peer(
            Box::new(ProxyFailure(proxy_retained)),
            HeadExchange::Connect,
        )
        .await?;
        let origin_failure = OriginFailure(origin_retained);
        assert_eq!(Arc::strong_count(&origin_failure.0), 1);
        let (origin, _origin_client, _origin_control) =
            driven_failed_head_peer(Box::new(origin_failure), HeadExchange::Opening).await?;

        let error = finish_connect_route(proxy, origin, (Ipv4Addr::LOCALHOST, 0).into())
            .await
            .err()
            .ok_or("failed CONNECT route was accepted")?;
        let primary =
            find_source::<ProxyFailure>(error.as_ref()).ok_or("typed proxy cause was lost")?;
        assert_eq!(Arc::strong_count(&primary.0), 1);
        assert!(proxy_observed.upgrade().is_some());
        assert!(
            origin_observed.upgrade().is_some(),
            "the completed origin failure was discarded"
        );
        drop(error);
        assert!(proxy_observed.upgrade().is_none());
        assert!(origin_observed.upgrade().is_none());
        Ok(())
    })
    .await?
}
