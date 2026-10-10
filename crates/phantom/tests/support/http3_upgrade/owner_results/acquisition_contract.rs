use std::{error::Error, fmt, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::{oneshot, watch},
    task::{AbortHandle, JoinHandle},
    time::timeout,
};

use super::{
    CONTROL_TIMEOUT, alternative_failure, controlled_fixture, controlled_fixture_with_preparation,
    find_source, origin_failure,
};
use crate::support::tls::TestResult;

const ACQUISITION_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
struct PreparationFailure;

impl fmt::Display for PreparationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled endpoint preparation failed")
    }
}

impl Error for PreparationFailure {}

struct PeerDestroyed(Option<oneshot::Sender<()>>);

impl Drop for PeerDestroyed {
    fn drop(&mut self) {
        if let Some(observer) = self.0.take() {
            // The enclosing deadline may already have cancelled its observer.
            let _ = observer.send(());
        }
    }
}

struct DrivenOwner {
    task: Option<JoinHandle<TestResult<()>>>,
    abort: AbortHandle,
    destruction: oneshot::Receiver<()>,
    client: DuplexStream,
    destroyed: bool,
}

impl DrivenOwner {
    fn transfer(&mut self) -> TestResult<JoinHandle<TestResult<()>>> {
        self.task
            .take()
            .ok_or_else(|| "owner already transferred".into())
    }

    async fn observe_destruction(&mut self) -> TestResult<()> {
        if !self.destroyed {
            (&mut self.destruction).await?;
            self.destroyed = true;
        }

        Ok(())
    }
}

impl Drop for DrivenOwner {
    fn drop(&mut self) {
        // Fallback ownership remains live until the contract observation ends.
        self.abort.abort();
    }
}

async fn driven_owner(failure: Option<Box<dyn Error + Send + Sync>>) -> TestResult<DrivenOwner> {
    let (client, mut peer) = tokio::io::duplex(64);
    let (destroyed, destruction) = oneshot::channel();
    let task = tokio::spawn(async move {
        let _destroyed = PeerDestroyed(Some(destroyed));
        let mut head = [0_u8; 4];
        peer.read_exact(&mut head).await?;
        assert_eq!(&head, b"OWN1");
        peer.write_all(b"ACK1").await?;

        if let Some(failure) = failure {
            return Err(failure);
        }

        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).await?, 0);
        Ok(())
    });
    let mut owner = DrivenOwner {
        abort: task.abort_handle(),
        task: Some(task),
        destruction,
        client,
        destroyed: false,
    };
    owner.client.write_all(b"OWN1").await?;
    let mut response = [0_u8; 4];
    owner.client.read_exact(&mut response).await?;
    assert_eq!(&response, b"ACK1");

    Ok(owner)
}

async fn observe_transferred_owners(owners: &mut [DrivenOwner]) -> TestResult<bool> {
    let observation = timeout(CONTROL_TIMEOUT, async {
        for owner in &mut *owners {
            owner.observe_destruction().await?;
        }

        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await;
    let destroyed_before_fallback = match observation {
        Ok(result) => {
            result?;
            true
        }
        Err(_) => false,
    };
    if !destroyed_before_fallback {
        for owner in &*owners {
            owner.abort.abort();
        }
    }

    for owner in owners {
        timeout(CONTROL_TIMEOUT, owner.observe_destruction()).await??;
        let mut byte = [0_u8; 1];
        assert_eq!(
            timeout(CONTROL_TIMEOUT, owner.client.read(&mut byte)).await??,
            0
        );
    }

    Ok(destroyed_before_fallback)
}

#[tokio::test]
async fn preparation_failure_stops_all_transferred_driven_owners() -> TestResult<()> {
    timeout(ACQUISITION_TIMEOUT, async {
        let mut owners = [
            driven_owner(None).await?,
            driven_owner(None).await?,
            driven_owner(None).await?,
        ];
        let (shutdown, _receiver) = watch::channel(false);
        let result = controlled_fixture_with_preparation(
            shutdown,
            owners[0].transfer()?,
            owners[1].transfer()?,
            Some(vec![owners[2].transfer()?]),
            |has_origin_http3| {
                assert!(has_origin_http3);
                Err(Box::new(PreparationFailure))
            },
        )
        .await;
        let error = result
            .err()
            .ok_or("endpoint preparation failure was accepted")?;
        assert!(find_source::<PreparationFailure>(error.as_ref()).is_some());

        let stopped = observe_transferred_owners(&mut owners).await?;
        assert!(
            stopped,
            "preparation returned before all transferred owners stopped"
        );
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn cancelling_unpolled_preparation_stops_all_transferred_driven_owners() -> TestResult<()> {
    timeout(ACQUISITION_TIMEOUT, async {
        let mut owners = [
            driven_owner(None).await?,
            driven_owner(None).await?,
            driven_owner(None).await?,
        ];
        let (shutdown, _receiver) = watch::channel(false);
        let preparation = Box::pin(controlled_fixture(
            shutdown,
            owners[0].transfer()?,
            owners[1].transfer()?,
            Some(vec![owners[2].transfer()?]),
        ));

        // The future owns the transferred handles even before its first poll.
        drop(preparation);
        let stopped = observe_transferred_owners(&mut owners).await?;
        assert!(
            stopped,
            "cancelled preparation left transferred owners running"
        );
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn preparation_failure_retains_two_completed_typed_owner_failures() -> TestResult<()> {
    timeout(ACQUISITION_TIMEOUT, async {
        let (origin_error, origin_retained) = origin_failure();
        let (alternative_error, alternative_retained) = alternative_failure();
        assert_eq!(Arc::strong_count(&origin_error.retained), 1);
        assert_eq!(Arc::strong_count(&alternative_error.retained), 1);
        let mut origin = driven_owner(Some(Box::new(origin_error))).await?;
        let mut alternative = driven_owner(Some(Box::new(alternative_error))).await?;
        timeout(CONTROL_TIMEOUT, origin.observe_destruction()).await??;
        timeout(CONTROL_TIMEOUT, alternative.observe_destruction()).await??;
        let mut byte = [0_u8; 1];
        assert_eq!(
            timeout(CONTROL_TIMEOUT, origin.client.read(&mut byte)).await??,
            0
        );
        assert_eq!(
            timeout(CONTROL_TIMEOUT, alternative.client.read(&mut byte)).await??,
            0
        );
        let (shutdown, _receiver) = watch::channel(false);

        let error = controlled_fixture_with_preparation(
            shutdown,
            origin.transfer()?,
            alternative.transfer()?,
            None,
            |has_origin_http3| {
                assert!(!has_origin_http3);
                Err(Box::new(PreparationFailure))
            },
        )
        .await
        .err()
        .ok_or("endpoint preparation failure was accepted")?;
        assert!(find_source::<PreparationFailure>(error.as_ref()).is_some());
        let origin_survived = origin_retained.upgrade().is_some();
        let alternative_survived = alternative_retained.upgrade().is_some();
        drop(error);

        assert!(origin_retained.upgrade().is_none());
        assert!(alternative_retained.upgrade().is_none());
        assert!(origin_survived, "setup lost the completed origin failure");
        assert!(
            alternative_survived,
            "setup lost the completed alternative failure"
        );
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn successful_preparation_keeps_actual_endpoints_and_finish_results() -> TestResult<()> {
    timeout(ACQUISITION_TIMEOUT, async {
        let (shutdown, _receiver) = watch::channel(false);
        let fixture = controlled_fixture(
            shutdown,
            tokio::spawn(async { Ok(()) }),
            tokio::spawn(async { Ok(()) }),
            Some(vec![tokio::spawn(async { Ok(()) })]),
        )
        .await?;
        assert!(
            fixture
                .alternative_endpoint
                .local_addr()?
                .ip()
                .is_loopback()
        );
        let origin_http3 = fixture
            .origin_http3
            .as_ref()
            .ok_or("origin H3 endpoint missing")?;
        assert_eq!(origin_http3.endpoints.len(), 1);
        assert!(origin_http3.endpoints[0].local_addr()?.ip().is_loopback());

        let observations = fixture.finish().await?;
        assert_eq!(observations.origin_request_count, 0);
        assert_eq!(observations.alternative_connections, 0);
        Ok(())
    })
    .await?
}
