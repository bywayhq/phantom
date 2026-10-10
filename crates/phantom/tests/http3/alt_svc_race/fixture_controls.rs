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
use phantom::{HttpProtocol, RequestErrorKind};
use tokio::{task::JoinHandle, time::timeout};

use super::{
    Blackhole, TEST_TIMEOUT, TestResult, UntrustedAlternative, after_admission_released, bounded,
    client_builder, identity, initial_identity, observe_blackhole_receive, wait_until,
};

async fn blackhole_with_observed_datagram() -> TestResult<Blackhole> {
    let blackhole = Blackhole::bind().await?;
    let sender = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
    let initial = [0xc0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0];
    sender
        .send_to(&initial, (Ipv4Addr::LOCALHOST, blackhole.port))
        .await?;
    wait_until(|| Ok(blackhole.datagrams()? == 1)).await?;

    assert_eq!(blackhole.connection_attempts()?, 1);
    Ok(blackhole)
}

#[tokio::test]
async fn a_receive_failure_cannot_be_reported_as_a_quiet_datagram_count() -> TestResult<()> {
    bounded(async {
        let blackhole = blackhole_with_observed_datagram().await?;
        let count = blackhole.datagrams()?;
        observe_blackhole_receive(
            Err(io::Error::from_raw_os_error(0x5a31)),
            &blackhole.initials,
            &blackhole.datagrams,
        );

        let error = blackhole
            .datagrams()
            .err()
            .ok_or("receive failure was reported as an unchanged datagram count")?;
        assert_eq!(count, 1);
        let mut cause: &(dyn std::error::Error + 'static) = error.as_ref();
        loop {
            if let Some(original) = cause.downcast_ref::<io::Error>()
                && original.raw_os_error() == Some(0x5a31)
            {
                break;
            }

            cause = cause
                .source()
                .ok_or("the original receive error was lost")?;
        }
        assert!(blackhole.connection_attempts().is_err());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_stopped_receiver_cannot_report_a_quiet_datagram_count() -> TestResult<()> {
    bounded(async {
        let mut blackhole = blackhole_with_observed_datagram().await?;
        blackhole.task.abort();
        let result = (&mut blackhole.task).await;
        assert!(result.is_err_and(|error| error.is_cancelled()));

        assert!(blackhole.datagrams().is_err());
        assert!(blackhole.connection_attempts().is_err());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_poisoned_observer_cannot_report_a_quiet_datagram_count() -> TestResult<()> {
    bounded(async {
        let blackhole = blackhole_with_observed_datagram().await?;
        let held = blackhole
            .initials
            .lock()
            .map_err(|_| "observation lock was already poisoned")?;

        let poisoned = std::panic::catch_unwind(move || {
            let _held = held;
            panic!("inject observation lock poisoning");
        });
        assert!(poisoned.is_err());

        assert!(blackhole.datagrams().is_err());
        assert!(blackhole.connection_attempts().is_err());
        Ok(())
    })
    .await
}

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
        wait_until(|| Ok(blackhole.datagrams()? == 3)).await?;

        assert_eq!(blackhole.connection_attempts()?, 2);
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
    let mut first = Some(invalid);
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
    let error = outcome
        .err()
        .ok_or("the observation swallowed invalid input")?;
    assert_eq!(error.kind(), RequestErrorKind::InvalidAuthority);
    Ok(())
}

#[tokio::test]
async fn one_initial_identity_is_not_counted_again_from_another_udp_source() -> TestResult<()> {
    bounded(async {
        let blackhole = Blackhole::bind().await?;
        let first = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
        let second = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
        assert_ne!(first.local_addr()?, second.local_addr()?);
        let header = [0xc0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0];
        let destination = (Ipv4Addr::LOCALHOST, blackhole.port);
        first.send_to(&header, destination).await?;
        second.send_to(&header, destination).await?;
        wait_until(|| Ok(blackhole.datagrams()? == 2)).await?;

        assert_eq!(blackhole.connection_attempts()?, 1);
        Ok(())
    })
    .await
}

#[test]
fn initial_observation_reads_literal_v1_and_v2_headers_and_rejects_truncated_ids() -> TestResult<()>
{
    let v1 = [0xc7, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 2, 9, 10];
    let v2 = [0xd3, 0x6b, 0x33, 0x43, 0xcf, 8, 8, 7, 6, 5, 4, 3, 2, 1, 0];
    let first = initial_identity(&v1)?.ok_or("v1 Initial was ignored")?;
    assert_eq!(first.version, 1);
    assert_eq!(first.destination, [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(first.source, [9, 10]);
    let second = initial_identity(&v2)?.ok_or("v2 Initial was ignored")?;
    assert_eq!(second.version, 0x6b33_43cf);
    assert_eq!(second.destination, [8, 7, 6, 5, 4, 3, 2, 1]);
    assert!(second.source.is_empty());

    assert!(initial_identity(&[0x40]).is_ok_and(|value| value.is_none()));
    assert!(initial_identity(&[0xe0, 0, 0, 0, 1]).is_ok_and(|value| value.is_none()));
    assert!(initial_identity(&[0xc0, 0, 0, 0, 0]).is_ok_and(|value| value.is_none()));
    assert!(initial_identity(&[0xc0, 0, 0, 0, 2]).is_err());
    assert!(initial_identity(&[]).is_err());
    assert!(initial_identity(&v1[..4]).is_err());
    assert!(initial_identity(&v1[..13]).is_err());
    assert!(initial_identity(&v1[..16]).is_err());
    assert!(initial_identity(&[0xc0, 0, 0, 0, 1, 21]).is_err());
    assert!(initial_identity(&[0xc0, 0, 0, 0, 1, 7]).is_err());
    let oversized_source = [0xc0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 21];
    assert!(initial_identity(&oversized_source).is_err());
    Ok(())
}

#[tokio::test]
async fn dropping_an_untrusted_listener_releases_a_started_handshake_socket() -> TestResult<()> {
    bounded(assert_pending_handshake_shutdown(ListenerShutdown::Drop)).await
}

#[tokio::test]
async fn finishing_an_untrusted_listener_cancels_and_reaps_a_started_handshake() -> TestResult<()> {
    bounded(assert_pending_handshake_shutdown(ListenerShutdown::Finish)).await
}

enum ListenerShutdown {
    Drop,
    Finish,
}

async fn assert_pending_handshake_shutdown(shutdown: ListenerShutdown) -> TestResult<()> {
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
    assert_eq!(alternative.active.load(Ordering::SeqCst), 1);
    let active = Arc::clone(&alternative.active);
    match shutdown {
        ListenerShutdown::Drop => drop(alternative),
        ListenerShutdown::Finish => alternative.finish().await?,
    }
    wait_until(|| Ok(active.load(Ordering::SeqCst) == 0)).await?;

    timeout(
        TEST_TIMEOUT,
        wait_until(|| match phantom_testkit::udp::bind(address) {
            Ok(socket) => {
                drop(socket);
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => Ok(false),
            Err(error) => Err(error.into()),
        }),
    )
    .await
    .map_err(|_| "the dropped handshake fixture retained its UDP socket")??;
    drop(client);
    relay.finish().await?;
    Ok(())
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
