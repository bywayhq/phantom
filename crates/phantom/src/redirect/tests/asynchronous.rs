use std::{
    cell::Cell,
    future::{Future, pending},
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};

use super::*;
use crate::{RedirectCallbackError, RedirectDecision};

#[tokio::test]
async fn decision_can_borrow_hop_metadata_across_await_without_mutating_a_stopped_request()
-> TestResult {
    let mut state = state(Method::POST)?;
    state.policy = RedirectPolicy::custom_async(NonZeroUsize::MIN, |attempt| {
        Box::pin(async move {
            tokio::task::yield_now().await;
            assert_eq!(attempt.from_url().path(), "/start");
            assert_eq!(attempt.to_url().path(), "/next");
            assert_eq!(attempt.method(), Method::POST);
            assert_eq!(attempt.next_method(), Method::GET);
            assert_eq!(attempt.hop(), 1);
            Ok(RedirectDecision::Stop)
        })
    });

    assert_eq!(
        follow(&mut state, &redirect(StatusCode::FOUND, "/next")?).await?,
        RedirectAction::Stop
    );
    assert_eq!(state.method(), Method::POST);
    assert_eq!(state.body(), Some(&Bytes::from_static(b"body")));
    assert_eq!(state.followed(), 0);
    assert!(state.headers().iter().any(|h| h.name() == "authorization"));
    Ok(())
}

#[tokio::test]
async fn callback_failure_keeps_its_source_without_disclosing_it_in_formatting() -> TestResult {
    let mut state = state(Method::POST)?;
    state.policy = RedirectPolicy::custom_async(NonZeroUsize::MIN, |_| {
        Box::pin(async {
            Err(RedirectCallbackError::new(io::Error::other(
                "private-redirect-canary",
            )))
        })
    });

    let error = follow(&mut state, &redirect(StatusCode::FOUND, "/next")?)
        .await
        .err()
        .ok_or("failed callback followed the hop")?;
    assert_eq!(error.kind(), RequestErrorKind::Redirect);
    let callback_error = error
        .source()
        .and_then(|source| source.downcast_ref::<RedirectCallbackError>())
        .ok_or("callback source missing")?;
    assert_eq!(
        callback_error
            .source()
            .ok_or("original cause missing")?
            .to_string(),
        "private-redirect-canary"
    );
    assert!(!format!("{error} {error:?}").contains("private-redirect-canary"));
    assert_eq!(state.followed(), 0);
    assert_eq!(state.method(), Method::POST);
    Ok(())
}

#[tokio::test]
async fn asynchronous_policy_cannot_bypass_validation_or_the_hop_limit() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let mut state = state(Method::GET)?;
    state.policy = RedirectPolicy::custom_async(NonZeroUsize::MIN, move |_| {
        let observed = Arc::clone(&observed);
        Box::pin(async move {
            observed.fetch_add(1, Ordering::Relaxed);
            Ok(RedirectDecision::Follow)
        })
    });

    assert!(
        follow(&mut state, &redirect(StatusCode::FOUND, "file:///private")?)
            .await
            .is_err()
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert_eq!(
        follow(&mut state, &redirect(StatusCode::FOUND, "/next")?).await?,
        RedirectAction::Follow { same_origin: true }
    );
    assert!(
        follow(&mut state, &redirect(StatusCode::FOUND, "/last")?)
            .await
            .is_err()
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(state.followed(), 1);
    Ok(())
}

#[test]
fn dropping_a_pending_decision_releases_its_future_without_committing_the_hop() -> TestResult {
    struct Guard(Arc<AtomicBool>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    let dropped = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&dropped);
    let mut state = state(Method::POST)?;
    state.policy = RedirectPolicy::custom_async(NonZeroUsize::MIN, move |_| {
        let guard = Guard(Arc::clone(&observed));
        Box::pin(async move {
            let _guard = guard;
            pending().await
        })
    });
    let target = state.prepare(&redirect(StatusCode::FOUND, "https://other.test/")?)?;
    let mut decision = Box::pin(state.follow(target));
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        decision.as_mut().poll(&mut context),
        Poll::Pending
    ));
    assert!(!dropped.load(Ordering::Relaxed));

    drop(decision);
    assert!(dropped.load(Ordering::Relaxed));
    assert_eq!(state.followed(), 0);
    assert_eq!(state.method(), Method::POST);
    assert!(state.headers().iter().any(|h| h.name() == "authorization"));
    Ok(())
}

#[tokio::test]
async fn response_body_does_not_need_to_be_sync_while_awaiting_a_decision() -> TestResult {
    fn assert_send<T: Send>(_: &T) {}

    let mut state = state(Method::GET)?;
    state.policy = RedirectPolicy::custom_async(NonZeroUsize::MIN, |_| {
        Box::pin(async {
            tokio::task::yield_now().await;
            Ok(RedirectDecision::Follow)
        })
    });
    let response = Response::builder()
        .status(StatusCode::FOUND)
        .header(http::header::LOCATION, "/next")
        .body(Cell::new(()))?;
    let operation = async move {
        let target = state.prepare(&response)?;
        let action = state.follow(target).await?;
        drop(response);
        Ok::<_, crate::RequestError>(action)
    };
    assert_send(&operation);
    assert_eq!(
        operation.await?,
        RedirectAction::Follow { same_origin: true }
    );
    Ok(())
}
