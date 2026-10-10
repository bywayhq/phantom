use std::{error::Error, fmt};

use tokio::{sync::oneshot, time::timeout};

use super::{TEST_TIMEOUT, TestResult, https_proxy_exchange, per_origin};
use crate::support::tunnel_proxy::connection_peer::FixtureFailures;

#[tokio::test]
async fn https_proxy_certificate_caller_keeps_its_completed_peer_failure() -> TestResult<()> {
    let result = timeout(
        TEST_TIMEOUT * 3,
        https_proxy_exchange(CallerFault::CompletedPeer),
    )
    .await?;
    require_both_causes(result)
}

#[tokio::test]
async fn mapped_https_proxy_certificate_caller_keeps_its_completed_peer_failure() -> TestResult<()>
{
    let result = timeout(
        TEST_TIMEOUT * 3,
        per_origin::https_proxy_exchange(CallerFault::CompletedPeer),
    )
    .await?;
    require_both_causes(result)
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn http1_wss_certificate_caller_keeps_its_completed_peer_failure() -> TestResult<()> {
    let result = timeout(
        TEST_TIMEOUT * 3,
        per_origin::http1_wss_exchange(CallerFault::CompletedPeer),
    )
    .await?;
    require_both_causes(result)
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn http2_wss_certificate_caller_keeps_its_completed_peer_failure() -> TestResult<()> {
    let result = timeout(
        TEST_TIMEOUT * 3,
        per_origin::http2_wss_exchange(CallerFault::CompletedPeer),
    )
    .await?;
    require_both_causes(result)
}

pub(super) enum CallerFault {
    None,
    CompletedPeer,
}

impl CallerFault {
    pub(super) fn completion_gate(self) -> (Option<CallerCompletion>, Option<PeerCompletion>) {
        match self {
            Self::None => (None, None),
            Self::CompletedPeer => {
                let (release, received) = oneshot::channel();
                let (failed, failure) = oneshot::channel();
                (
                    Some(CallerCompletion { release, failure }),
                    Some(PeerCompletion { received, failed }),
                )
            }
        }
    }
}

pub(super) struct CallerCompletion {
    pub(super) release: oneshot::Sender<()>,
    pub(super) failure: oneshot::Receiver<PeerFailure>,
}

pub(super) struct PeerCompletion {
    pub(super) received: oneshot::Receiver<()>,
    pub(super) failed: oneshot::Sender<PeerFailure>,
}

fn require_both_causes(result: TestResult<()>) -> TestResult<()> {
    let error = result
        .err()
        .ok_or("controlled caller unexpectedly succeeded")?;

    let primary = error.downcast_ref::<PrimaryFailure>().is_some()
        || error
            .downcast_ref::<FixtureFailures>()
            .is_some_and(|causes| causes.primary.is::<PrimaryFailure>());
    assert!(primary, "controlled caller lost its original failure");

    let Some(causes) = error.downcast_ref::<FixtureFailures>() else {
        return Err("certificate caller discarded its completed peer failure".into());
    };

    assert!(causes.primary.is::<PrimaryFailure>());
    assert!(causes.cleanup.is::<PeerFailure>());
    Ok(())
}

#[derive(Debug)]
pub(super) struct PrimaryFailure;

impl fmt::Display for PrimaryFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled certificate caller failure")
    }
}

impl Error for PrimaryFailure {}

#[derive(Debug)]
pub(super) struct PeerFailure;

impl fmt::Display for PeerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled completed certificate peer failure")
    }
}

impl Error for PeerFailure {}
