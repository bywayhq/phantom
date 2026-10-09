use std::{
    future::ready,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use bytes::Bytes;
use phantom::HttpProtocol;
use tokio::{task::JoinHandle, time::timeout};

use super::{
    Blackhole, TEST_TIMEOUT, TestResult, UntrustedAlternative, after_admission_released, bounded,
    client_builder, identity, wait_until,
};

#[tokio::test]
async fn distinct_initial_identities_share_one_udp_source() -> TestResult<()> {
    bounded(async {
        let blackhole = Blackhole::bind().await?;
        let sender = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
        let destination = (Ipv4Addr::LOCALHOST, blackhole.port);
        // Literal v1 Initial invariant headers with different destination IDs.
        // Ciphertext is irrelevant to this header-only observation control.
        let first = [0xc0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0];
        let second = [0xc0, 0, 0, 0, 1, 8, 8, 7, 6, 5, 4, 3, 2, 1, 0];
        sender.send_to(&first, destination).await?;
        sender.send_to(&first, destination).await?;
        sender.send_to(&second, destination).await?;
        wait_until(|| Ok(blackhole.datagrams() == 3)).await?;

        assert_eq!(blackhole.peers(), 2);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn admission_observation_returns_an_unrelated_failure_without_retry() -> TestResult<()> {
    let identity = identity()?;
    let client = client_builder(&identity)?.build()?;
    let invalid = client
        .get(HttpProtocol::Http3, "https://[invalid/")
        .err()
        .ok_or("invalid input was accepted")?;
    let mut first = Some(invalid.to_string());
    let mut calls = 0;
    let outcome = after_admission_released(|| {
        calls += 1;
        ready(match first.take() {
            Some(error) => Err(error),
            None => Ok(Bytes::from_static(b"later success")),
        })
    })
    .await;

    assert_eq!(calls, 1);
    assert!(outcome.is_err());
    Ok(())
}

#[tokio::test]
async fn dropping_an_untrusted_listener_releases_a_started_handshake_socket() -> TestResult<()> {
    bounded(async {
        let identity = identity()?;
        let alternative = UntrustedAlternative::spawn()?;
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, alternative.port));
        let relay = HandshakeRelay::spawn(address)?;
        let client = client_builder(&identity)?.build()?;
        let url = format!("https://127.0.0.1:{}/pending", relay.address.port());
        let request = client.get(HttpProtocol::Http3, &url)?.send();
        tokio::pin!(request);

        // A server reply proves that the accepted handshake has been polled.
        // Replies never reach the client, so that handshake remains pending.
        tokio::select! {
            result = &mut request => return Err(format!("handshake completed before teardown: {result:?}").into()),
            observed = wait_until(|| Ok(alternative.attempts() == 1 && relay.replies() > 0)) => observed?,
        }
        assert_eq!(alternative.failures(), 0);
        drop(alternative);

        timeout(TEST_TIMEOUT, wait_until(|| {
            match phantom_testkit::udp::bind(address) {
                Ok(socket) => {
                    drop(socket);
                    Ok(true)
                }
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => Ok(false),
                Err(error) => Err(error.into()),
            }
        }))
        .await
        .map_err(|_| "the dropped handshake fixture retained its UDP socket")??;
        drop(request);
        drop(client);
        relay.finish().await?;
        Ok(())
    })
    .await
}

struct HandshakeRelay {
    address: SocketAddr,
    replies: Arc<AtomicUsize>,
    task: JoinHandle<io::Result<()>>,
}

impl HandshakeRelay {
    fn spawn(server: SocketAddr) -> io::Result<Self> {
        let socket = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
        let address = socket.local_addr()?;
        let replies = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&replies);
        let task = tokio::spawn(async move {
            let mut buffer = [0_u8; 65_535];
            loop {
                let (length, peer) = socket.recv_from(&mut buffer).await?;
                if peer == server {
                    observed.fetch_add(1, Ordering::SeqCst);
                } else {
                    socket.send_to(&buffer[..length], server).await?;
                }
            }
        });
        Ok(Self {
            address,
            replies,
            task,
        })
    }

    fn replies(&self) -> usize {
        self.replies.load(Ordering::SeqCst)
    }

    async fn finish(mut self) -> TestResult<()> {
        self.task.abort();
        match (&mut self.task).await {
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error.into()),
            Ok(result) => Ok(result?),
        }
    }
}

impl Drop for HandshakeRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}
