use std::{
    future::{Future, poll_fn},
    io,
    sync::Arc,
    task::Poll,
};

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
        let mut operation = Box::pin(fixed_response_observed(
            &identity,
            RESPONSE,
            Some(observation),
        ));
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
        let mut operation = Box::pin(fixed_response_observed(
            &identity,
            RESPONSE,
            Some(observation),
        ));
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
        let mut operation = Box::pin(fixed_response_observed(
            &identity,
            RESPONSE,
            Some(observation),
        ));
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
        let mut operation = Box::pin(fixed_response_observed(
            &identity,
            RESPONSE,
            Some(observation),
        ));
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
        let mut operation = Box::pin(fixed_response_observed(
            &identity,
            RESPONSE,
            Some(observation),
        ));
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

#[tokio::test(flavor = "current_thread")]
async fn pending_external_abort_keeps_the_fixed_response_caller_and_join_errors() -> TestResult<()>
{
    let identity = TestIdentity::generate()?;
    let (observation, mut backup, release) = Observation::pair(None);
    let primary = async {
        let mut operation = Box::pin(fixed_response_observed(
            &identity,
            RESPONSE,
            Some(observation),
        ));
        tokio::select! {
            result = &mut operation => {
                result?;
                return Err("fixed-response caller completed before attachment".into());
            }
            result = backup.attached() => result?,
        }
        backup.connect(&identity).await?;
        let original_task = backup.witness()?.abort.id();
        backup.witness()?.abort.abort();
        assert!(!backup.witness()?.abort.is_finished());
        release
            .send(Some(INVALID_TARGET))
            .map_err(|_| "fixed-response caller stopped before invalid target")?;

        let error = timeout(CONTROL_LIMIT, operation)
            .await?
            .err()
            .ok_or("pending external cancellation was discarded")?;
        let failures = error
            .downcast_ref::<FixtureFailures>()
            .ok_or("pending external cancellation was mistaken for local cleanup")?;
        assert_eq!(
            failures
                .primary
                .downcast_ref::<RequestError>()
                .ok_or("original invalid target error lost")?
                .kind(),
            RequestErrorKind::InvalidUri
        );
        let cancelled = failures
            .cleanup
            .downcast_ref::<tokio::task::JoinError>()
            .ok_or("original external cancellation type lost")?;
        assert!(cancelled.is_cancelled());
        assert_eq!(cancelled.id(), original_task);
        backup.destroyed().await?;
        assert_eq!(backup.state.borrow().written, 0);
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test(flavor = "current_thread")]
async fn interrupted_cleanup_keeps_the_original_invalid_target_before_outer_deadline()
-> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (observation, mut backup, release) = Observation::pair(None);
    let mut peer = super::super::FixedResponsePeer::default();
    let primary = async {
        let elapsed = {
            let mut operation = Box::pin(peer.response(&identity, RESPONSE, Some(observation)));
            tokio::select! {
                result = &mut operation => {
                    result?;
                    return Err("fixed-response caller completed before attachment".into());
                }
                result = backup.attached() => result?,
            }
            backup.connect(&identity).await?;

            // Expire a five-second caller budget while the real worker is
            // waiting for a head, then reach the caller's invalid URI failure.
            let deadline = tokio::time::Instant::now() + CONTROL_LIMIT;
            tokio::time::pause();
            // Tokio rounds timer deadlines up to a millisecond. Cross that
            // tick while keeping the original caller's five-second deadline.
            tokio::time::advance(CONTROL_LIMIT + std::time::Duration::from_millis(1)).await;
            release
                .send(Some(INVALID_TARGET))
                .map_err(|_| "fixed-response caller stopped before invalid target")?;
            let pending =
                poll_fn(|context| Poll::Ready(operation.as_mut().poll(context).is_pending())).await;
            assert!(
                pending,
                "original worker cleanup completed before interruption"
            );
            let expired = tokio::time::timeout_at(deadline, &mut operation).await;
            tokio::time::resume();
            expired
                .err()
                .ok_or("outer response watchdog did not expire")?
        };

        let error = peer
            .finish::<()>(Err(super::super::FixtureDeadline::new(
                "SSE test exceeded its deadline",
                elapsed,
            )
            .into()))
            .await
            .err()
            .ok_or("interrupted response discarded its failures")?;
        let failures = error
            .downcast_ref::<FixtureFailures>()
            .ok_or("original caller failure did not survive interrupted cleanup")?;
        assert_eq!(
            failures
                .primary
                .downcast_ref::<RequestError>()
                .ok_or("original invalid URI error lost")?
                .kind(),
            RequestErrorKind::InvalidUri
        );
        assert!(
            failures
                .cleanup
                .source()
                .is_some_and(|cause| cause.is::<tokio::time::error::Elapsed>())
        );
        assert!(
            peer.worker.is_none(),
            "original worker outcome was not collected"
        );
        backup.destroyed().await?;
        assert_eq!(backup.state.borrow().written, 0);
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}
