use std::future::pending;

use tokio::{io::AsyncReadExt, io::AsyncWriteExt, sync::oneshot, time::timeout};

use super::{PEER_TEST_TIMEOUT, TestResult, spawn_early_peer};

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

struct PeerFinished(Option<oneshot::Sender<()>>);

impl Drop for PeerFinished {
    fn drop(&mut self) {
        // The receiver may already have gone away after an earlier test error.
        if let Some(finished) = self.0.take() {
            let _ = finished.send(());
        }
    }
}
