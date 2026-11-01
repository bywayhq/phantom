use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use super::*;
use crate::RedirectDecision;

#[tokio::test]
async fn custom_policy_sees_resolved_url_and_proposed_method_before_mutation() -> TestResult {
    let mut state = state(Method::POST)?;
    state.policy = RedirectPolicy::custom(NonZeroUsize::MIN, |attempt| {
        assert_eq!(attempt.from_url().as_str(), "https://example.test/start");
        assert_eq!(
            attempt.to_url().as_str(),
            "https://example.test/final?secret=1"
        );
        assert_eq!(attempt.status(), StatusCode::FOUND);
        assert_eq!(attempt.method(), Method::POST);
        assert_eq!(attempt.next_method(), Method::GET);
        assert_eq!(attempt.hop(), 1);
        let debug = format!("{attempt:?}");
        assert!(!debug.contains("example.test"));
        assert!(!debug.contains("secret"));
        RedirectDecision::Stop
    });
    assert_eq!(
        follow(
            &mut state,
            &redirect(StatusCode::FOUND, "/a/../final?secret=1")?
        )
        .await?,
        RedirectAction::Stop,
    );
    assert_eq!(state.current_url().as_str(), "https://example.test/start");
    assert_eq!(state.method(), Method::POST);
    assert_eq!(state.body(), Some(&Bytes::from_static(b"body")));
    assert_eq!(state.followed(), 0);
    assert!(state.headers().iter().any(|h| h.name() == "authorization"));
    Ok(())
}

#[tokio::test]
async fn custom_policy_cannot_override_the_hop_limit_and_clones_share_callback() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let policy = RedirectPolicy::custom(NonZeroUsize::MIN, move |_| {
        observed.fetch_add(1, Ordering::Relaxed);
        RedirectDecision::Follow
    });
    for policy in [policy.clone(), policy] {
        let mut state = state(Method::GET)?;
        state.policy = policy;
        assert_eq!(
            follow(&mut state, &redirect(StatusCode::FOUND, "/next")?).await?,
            RedirectAction::Follow { same_origin: true },
        );
        let error = follow(&mut state, &redirect(StatusCode::FOUND, "/last")?)
            .await
            .err()
            .ok_or("custom policy exceeded its hop limit")?;
        assert_eq!(error.kind(), RequestErrorKind::Redirect);
        assert_eq!(state.followed(), 1);
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    Ok(())
}

#[tokio::test]
async fn rejecting_callback_leaves_credentials_and_body_unmodified() -> TestResult {
    let mut state = state(Method::POST)?;
    state.policy = RedirectPolicy::custom(NonZeroUsize::MIN, |_| RedirectDecision::Reject);
    let error = follow(
        &mut state,
        &redirect(StatusCode::FOUND, "https://other.test/")?,
    )
    .await
    .err()
    .ok_or("rejecting policy followed the target")?;
    assert_eq!(error.kind(), RequestErrorKind::Redirect);
    assert!(error.to_string().contains("callback rejected"));
    assert_eq!(state.method(), Method::POST);
    assert_eq!(state.body(), Some(&Bytes::from_static(b"body")));
    assert_eq!(state.followed(), 0);
    assert!(state.headers().iter().any(|h| h.name() == "authorization"));
    Ok(())
}

#[tokio::test]
async fn following_callback_preserves_credential_stripping_on_later_hops() -> TestResult {
    let mut state = state(Method::GET)?;
    state.policy = RedirectPolicy::custom(NonZeroUsize::new(2).ok_or("nonzero")?, |_| {
        RedirectDecision::Follow
    });
    follow(
        &mut state,
        &redirect(StatusCode::TEMPORARY_REDIRECT, "https://other.test/")?,
    )
    .await?;
    follow(
        &mut state,
        &redirect(StatusCode::TEMPORARY_REDIRECT, "https://example.test/")?,
    )
    .await?;
    assert!(!state.headers().iter().any(|h| h.name() == "authorization"));
    assert!(!state.trailers().iter().any(|h| h.name() == "authorization"));
    Ok(())
}

#[tokio::test]
async fn invalid_redirects_do_not_reach_the_callback() -> TestResult {
    let mut state = state(Method::GET)?;
    state.policy = RedirectPolicy::custom(NonZeroUsize::MIN, |_| panic!("invalid redirect"));
    assert_eq!(
        follow(&mut state, &Response::new(())).await?,
        RedirectAction::Stop
    );
    assert_eq!(
        follow(
            &mut state,
            &Response::builder().status(StatusCode::FOUND).body(())?
        )
        .await?,
        RedirectAction::Stop,
    );
    let error = follow(&mut state, &redirect(StatusCode::FOUND, "file:///secret")?)
        .await
        .err()
        .ok_or("unsupported scheme reached the callback")?;
    assert_eq!(error.kind(), RequestErrorKind::Redirect);
    Ok(())
}
