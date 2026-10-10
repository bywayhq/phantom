use std::{error::Error, fmt};

use phantom::{RequestError, RequestErrorKind};
use phantom_net::http1::Http1Error;
use tokio::{sync::oneshot, time::timeout};

use super::{
    TEST_TIMEOUT, TestResult, https_proxy_exchange_with_origin, peer_outcome::CallerFault,
    per_origin,
};
use crate::support::tunnel_proxy::connection_peer::FixtureFailures;

#[tokio::test]
async fn https_proxy_certificate_caller_keeps_request_and_origin_failures() -> TestResult<()> {
    let (observed, observation) = oneshot::channel();
    let result = timeout(
        TEST_TIMEOUT * 3,
        https_proxy_exchange_with_origin(CallerFault::None, Some(observed)),
    )
    .await?;

    let observation = timeout(TEST_TIMEOUT, observation).await??;
    require_both_causes(result, observation)
}

#[tokio::test]
async fn mapped_https_proxy_certificate_caller_keeps_request_and_origin_failures() -> TestResult<()>
{
    let (observed, observation) = oneshot::channel();
    let result = timeout(
        TEST_TIMEOUT * 3,
        per_origin::https_proxy_exchange_with_origin(CallerFault::None, Some(observed)),
    )
    .await?;

    let observation = timeout(TEST_TIMEOUT, observation).await??;
    require_both_causes(result, observation)
}

pub(super) enum OriginResponse {
    Complete,
    Truncated {
        expected_leaf: Vec<u8>,
        observed: oneshot::Sender<OriginObservation>,
    },
}

impl OriginResponse {
    pub(super) fn for_certificate(
        expected_leaf: Vec<u8>,
        observed: Option<oneshot::Sender<OriginObservation>>,
    ) -> Self {
        match observed {
            Some(observed) => Self::Truncated {
                expected_leaf,
                observed,
            },
            None => Self::Complete,
        }
    }
}

pub(super) struct OriginObservation {
    pub(super) head: Vec<u8>,
    pub(super) presented: Vec<u8>,
}

fn require_both_causes(result: TestResult<()>, observation: OriginObservation) -> TestResult<()> {
    assert!(observation.head.starts_with(b"GET / HTTP/1.1\r\n"));
    assert!(observation.head.ends_with(b"\r\n\r\n"));
    assert!(!observation.presented.is_empty());

    let error = result
        .err()
        .ok_or("incomplete origin response was accepted")?;
    let request = find_source::<RequestError>(error.as_ref())
        .ok_or("caller lost the actual request failure")?;
    assert_eq!(request.kind(), RequestErrorKind::Http1);
    let protocol =
        find_source::<Http1Error>(request).ok_or("missing original HTTP/1 protocol cause")?;
    assert!(matches!(protocol, Http1Error::Protocol(_)));

    let causes = error
        .downcast_ref::<FixtureFailures>()
        .ok_or("certificate caller discarded its completed inline origin failure")?;
    assert!(causes.primary.is::<RequestError>());
    assert!(causes.cleanup.is::<OriginFailure>());
    Ok(())
}

fn find_source<'a, T: Error + 'static>(mut error: &'a (dyn Error + 'static)) -> Option<&'a T> {
    loop {
        if let Some(source) = error.downcast_ref::<T>() {
            return Some(source);
        }
        error = error.source()?;
    }
}

#[derive(Debug)]
pub(super) struct OriginFailure;

impl fmt::Display for OriginFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled origin failure after certificate and request receipt")
    }
}

impl Error for OriginFailure {}
