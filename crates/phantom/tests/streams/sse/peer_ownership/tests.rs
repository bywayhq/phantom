use std::{io, sync::Arc};

use phantom::{RequestError, RequestErrorKind, SseStream};

use super::{
    CONTROL_LIMIT, FixtureFailures, INVALID_TARGET, Observation, RESPONSE, ShutdownFailure,
    TestIdentity, TestResult, finish_with_cleanup, fixed_response_observed, timeout,
};

#[tokio::test]
async fn dropping_a_fixed_response_caller_closes_its_original_pending_peer() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (observation, mut backup, release) = Observation::pair(None);
    let primary = async {
        let mut operation = Box::pin(fixed_response_observed(&identity, RESPONSE, Some(observation)));
        tokio::select! {
            result = &mut operation => {
                result?;
                return Err("fixed-response caller completed before attachment".into());
            }
            result = backup.attached() => result?,
        }
        backup.connect(&identity).await?;

        drop(operation);
        backup.destroyed().await?;
        assert_eq!(backup.state.borrow().written, 0);
        drop(release);
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn a_fallible_fixed_response_caller_closes_its_original_pending_peer() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (observation, mut backup, release) = Observation::pair(None);
    let primary = async {
        let mut operation = Box::pin(fixed_response_observed(&identity, RESPONSE, Some(observation)));
        tokio::select! {
            result = &mut operation => {
                result?;
                return Err("fixed-response caller completed before attachment".into());
            }
            result = backup.attached() => result?,
        }
        backup.connect(&identity).await?;
        release
            .send(Some(INVALID_TARGET))
            .map_err(|_| "fixed-response caller stopped before invalid target")?;

        let error = timeout(CONTROL_LIMIT, operation)
            .await?
            .err()
            .ok_or("fixed-response caller accepted an invalid target")?;
        let request = error
            .downcast_ref::<RequestError>()
            .ok_or("fixed-response caller lost its original request error")?;
        assert_eq!(request.kind(), RequestErrorKind::InvalidUri);
        backup.destroyed().await?;
        assert_eq!(backup.state.borrow().written, 0);
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn caller_failure_keeps_a_completed_original_fixed_response_peer_cause() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let marker = Arc::new(());
    let fault = io::Error::new(
        io::ErrorKind::PermissionDenied,
        ShutdownFailure(Arc::clone(&marker)),
    );
    let (observation, mut backup, release) = Observation::pair(Some(fault));
    let primary = async {
        let mut operation = Box::pin(fixed_response_observed(&identity, RESPONSE, Some(observation)));
        tokio::select! {
            result = &mut operation => {
                result?;
                return Err("fixed-response caller completed before attachment".into());
            }
            result = backup.attached() => result?,
        }
        backup.connect(&identity).await?;
        backup.response().await?;
        backup.destroyed().await?;
        let state = backup.state.borrow().clone();
        assert_eq!(state.written, RESPONSE.len());
        assert!(state.shutdown);
        assert_eq!(state.injected, Some(io::ErrorKind::PermissionDenied));
        release
            .send(Some(INVALID_TARGET))
            .map_err(|_| "fixed-response caller stopped before invalid target")?;

        let error = timeout(CONTROL_LIMIT, operation)
            .await?
            .err()
            .ok_or("fixed-response caller discarded both failures")?;
        let failures = error
            .downcast_ref::<FixtureFailures>()
            .ok_or("fixed-response caller discarded its completed peer failure")?;
        let request = failures
            .primary
            .downcast_ref::<RequestError>()
            .ok_or("fixed-response caller lost its original request error")?;
        assert_eq!(request.kind(), RequestErrorKind::InvalidUri);
        let original = failures
            .cleanup
            .downcast_ref::<io::Error>()
            .ok_or("fixed-response caller lost its original peer I/O error")?;
        assert_eq!(original.kind(), io::ErrorKind::PermissionDenied);
        let cause = original
            .get_ref()
            .and_then(|source| source.downcast_ref::<ShutdownFailure>())
            .ok_or("fixed-response caller lost its original shutdown cause")?;
        assert!(Arc::ptr_eq(&cause.0, &marker));
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn healthy_fixed_response_collects_its_original_peer_and_literal_event() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (observation, mut backup, release) = Observation::pair(None);
    let primary = async {
        let mut operation = Box::pin(fixed_response_observed(&identity, RESPONSE, Some(observation)));
        tokio::select! {
            result = &mut operation => {
                result?;
                return Err("fixed-response caller completed before attachment".into());
            }
            result = backup.attached() => result?,
        }
        release
            .send(None)
            .map_err(|_| "fixed-response caller stopped before healthy request")?;

        let response = timeout(CONTROL_LIMIT, operation).await??;
        assert_eq!(response.status(), 200);
        let mut events = SseStream::from_response(response)?.into_body();
        let event = timeout(CONTROL_LIMIT, events.next_event())
            .await??
            .ok_or("healthy fixed response emitted no event")?;
        assert_eq!(event.data(), "owner");
        assert_eq!(timeout(CONTROL_LIMIT, events.next_event()).await??, None);
        backup.destroyed().await?;
        let state = backup.state.borrow().clone();
        assert_eq!(state.written, RESPONSE.len());
        assert!(state.shutdown);
        assert_eq!(state.injected, None);
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn explicit_abort_closes_the_original_fixed_response_pending_peer() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (observation, mut backup, release) = Observation::pair(None);
    let primary = async {
        let mut operation = Box::pin(fixed_response_observed(&identity, RESPONSE, Some(observation)));
        tokio::select! {
            result = &mut operation => {
                result?;
                return Err("fixed-response caller completed before attachment".into());
            }
            result = backup.attached() => result?,
        }
        backup.connect(&identity).await?;
        backup.witness()?.abort.abort();

        backup.destroyed().await?;
        assert_eq!(backup.state.borrow().written, 0);
        drop(operation);
        drop(release);
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}
