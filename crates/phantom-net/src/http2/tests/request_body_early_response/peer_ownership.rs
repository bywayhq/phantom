use std::{error::Error, fmt, future::pending};

use tokio::{io::AsyncReadExt, io::AsyncWriteExt, sync::oneshot, time::timeout};

use super::{
    EarlyResponsePeerFailure, PEER_TEST_TIMEOUT, PeerOutcome, TestResult, spawn_early_peer,
};

#[tokio::test]
async fn cancelling_an_owner_stops_its_driven_peer_while_the_client_stays_live() -> TestResult<()> {
    timeout(PEER_TEST_TIMEOUT * 4, async {
        let (mut client, mut server) = tokio::io::duplex(16);
        let (ready, peer_ready) = oneshot::channel();
        let (finished, mut peer_finished) = oneshot::channel();
        let owner = async move {
            let peer = spawn_early_peer(async move {
                let _finished = PeerFinished(Some(finished));
                let mut byte = [0_u8; 1];
                server.read_exact(&mut byte).await?;
                assert_eq!(byte, [b'P']);
                ready
                    .send(())
                    .map_err(|()| "peer readiness was abandoned")?;

                server.read_exact(&mut byte).await?;
                Err("the peer unexpectedly received a second byte".into())
            });
            pending::<()>().await;
            drop(peer);
        };
        let mut owner = Box::pin(owner);

        client.write_all(b"P").await?;
        tokio::select! {
            () = &mut owner => return Err("the peer owner unexpectedly completed".into()),
            ready = timeout(PEER_TEST_TIMEOUT, peer_ready) => ready??,
        }

        drop(owner);
        let stopped_with_live_client = matches!(
            timeout(PEER_TEST_TIMEOUT, &mut peer_finished).await,
            Ok(Ok(()))
        );
        if stopped_with_live_client {
            let mut byte = [0_u8; 1];
            assert_eq!(
                timeout(PEER_TEST_TIMEOUT, client.read(&mut byte)).await??,
                0
            );
        }

        // Close only after the observation, so disconnect cannot stop the peer
        // on behalf of the cancelled owner. It also releases the old raw task
        // before the regression reports failure.
        drop(client);
        if !stopped_with_live_client {
            timeout(PEER_TEST_TIMEOUT, peer_finished).await??;
        }
        assert!(
            stopped_with_live_client,
            "the driven peer survived its owner while the client stayed live"
        );
        Ok(())
    })
    .await
    .map_err(|_| "peer ownership control exceeded its absolute deadline")?
}

#[tokio::test]
async fn an_early_test_error_joins_the_driven_peer_and_keeps_its_typed_cause() -> TestResult<()> {
    timeout(PEER_TEST_TIMEOUT * 4, async {
        let (mut client, mut server) = tokio::io::duplex(16);
        let (ready, peer_ready) = oneshot::channel();
        let (finished, peer_finished) = oneshot::channel();
        let peer = spawn_early_peer(async move {
            let _finished = PeerFinished(Some(finished));
            let mut byte = [0_u8; 1];
            server.read_exact(&mut byte).await?;
            assert_eq!(byte, [b'E']);
            ready
                .send(())
                .map_err(|()| "peer readiness was abandoned")?;

            server.read_exact(&mut byte).await?;
            Err("the peer unexpectedly received a second byte".into())
        });
        client.write_all(b"E").await?;
        timeout(PEER_TEST_TIMEOUT, peer_ready).await??;

        let error = peer
            .complete(Err(TestFailure.into()), PeerOutcome::FinalResponse)
            .await
            .err()
            .ok_or("the early test failure was accepted")?;

        assert!(error.downcast_ref::<TestFailure>().is_some());
        timeout(PEER_TEST_TIMEOUT, peer_finished).await??;
        let mut byte = [0_u8; 1];
        assert_eq!(
            timeout(PEER_TEST_TIMEOUT, client.read(&mut byte)).await??,
            0
        );
        Ok(())
    })
    .await
    .map_err(|_| "peer error cleanup control exceeded its absolute deadline")?
}

#[derive(Debug)]
struct TestFailure;

#[tokio::test(flavor = "current_thread")]
async fn simultaneous_test_and_peer_failures_keep_both_typed_causes() -> TestResult<()> {
    timeout(PEER_TEST_TIMEOUT * 4, async {
        let (mut client, mut server) = tokio::io::duplex(16);
        let (ready, peer_ready) = oneshot::channel();
        let peer = spawn_early_peer(async move {
            let mut byte = [0_u8; 1];
            server.read_exact(&mut byte).await?;
            assert_eq!(byte, [b'C']);
            ready.send(()).map_err(|()| "peer readiness was abandoned")?;
            Err(PeerFailure.into())
        });
        client.write_all(b"C").await?;
        timeout(PEER_TEST_TIMEOUT, peer_ready).await??;
        // No await follows readiness in the peer. On this single-thread
        // runtime its ready poll must finish before this task can resume.
        assert!(peer.task.is_finished());

        let error = peer
            .complete(Err(TestFailure.into()), PeerOutcome::FinalResponse)
            .await
            .err()
            .ok_or("the simultaneous failures were accepted")?;

        assert!(error.source().is_some_and(|source| source.is::<TestFailure>()));
        let combined = error
            .downcast_ref::<EarlyResponsePeerFailure>()
            .ok_or("the combined peer error was not retained")?;
        assert!(
            combined
                .cleanup
                .as_ref()
                .is_some_and(|cleanup| cleanup.is::<PeerFailure>())
        );
        assert_eq!(
            error.to_string(),
            "early-response test failed: typed early test failure; peer cleanup failed: typed peer failure"
        );
        let mut byte = [0_u8; 1];
        assert_eq!(timeout(PEER_TEST_TIMEOUT, client.read(&mut byte)).await??, 0);
        Ok(())
    })
    .await
    .map_err(|_| "combined peer failure control exceeded its absolute deadline")?
}

#[derive(Debug)]
struct PeerFailure;

impl fmt::Display for PeerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("typed peer failure")
    }
}

impl Error for PeerFailure {}

impl fmt::Display for TestFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("typed early test failure")
    }
}

impl Error for TestFailure {}

struct PeerFinished(Option<oneshot::Sender<()>>);

impl Drop for PeerFinished {
    fn drop(&mut self) {
        // The receiver may already have gone away after an earlier test error.
        if let Some(finished) = self.0.take() {
            let _ = finished.send(());
        }
    }
}
