use std::{error::Error, num::NonZeroUsize};

use http::{Method, Response, StatusCode, header::HeaderName};
use phantom_net::request::RequestTrailerName;

use super::{ReplayBuffer, Scripted};
use crate::{
    RedirectDecision, RedirectPolicy, RequestErrorKind,
    redirect::{RedirectAction, RedirectState},
    request::RequestBodySource,
};

type TestResult = Result<(), Box<dyn Error>>;

fn policy() -> RedirectPolicy {
    RedirectPolicy::limited(NonZeroUsize::MIN)
        .credential_headers([HeaderName::from_static("x-api-key")])
}

fn state(name: &str, policy: RedirectPolicy) -> Result<RedirectState, url::ParseError> {
    Ok(RedirectState::new(
        policy,
        url::Url::parse("https://example.test/start")?,
        Method::POST,
        Vec::new(),
        Vec::new(),
        RequestBodySource::Buffered(ReplayBuffer::new(
            Scripted::data(&["body"]),
            vec![RequestTrailerName::new(name)],
            64,
        )),
    ))
}

fn redirect(status: StatusCode, location: &str) -> Result<Response<()>, http::Error> {
    Response::builder()
        .status(status)
        .header(http::header::LOCATION, location)
        .body(())
}

#[test]
fn cross_origin_body_preserving_redirects_reject_declared_credential_trailers() -> TestResult {
    for status in [
        StatusCode::TEMPORARY_REDIRECT,
        StatusCode::PERMANENT_REDIRECT,
    ] {
        for name in ["X-API-Key", "Authorization"] {
            for destination in [
                "https://other.test/next",
                "https://example.test:8443/next",
                "http://example.test/next",
            ] {
                let mut state = state(name, policy())?;
                let error = state
                    .follow(&redirect(status, destination)?)
                    .expect_err("credential trailers must not cross origins");
                assert_eq!(error.kind(), RequestErrorKind::Redirect);
                assert_eq!(state.current_url().as_str(), "https://example.test/start");
                assert_eq!(state.followed(), 0);
                assert!(state.body_mut().has_credential_trailers(&policy()));
            }
        }
    }
    Ok(())
}

#[test]
fn buffered_credential_trailers_can_follow_same_origin_redirects() -> TestResult {
    let mut state = state("X-API-Key", policy())?;
    assert_eq!(
        state.follow(&redirect(StatusCode::PERMANENT_REDIRECT, "/next")?)?,
        RedirectAction::Follow { same_origin: true }
    );
    assert!(state.body_mut().has_credential_trailers(&policy()));
    Ok(())
}

#[test]
fn buffered_safe_trailers_can_follow_cross_origin_redirects() -> TestResult {
    let mut state = state("X-Checksum", policy())?;
    assert_eq!(
        state.follow(&redirect(
            StatusCode::TEMPORARY_REDIRECT,
            "https://other.test/next"
        )?)?,
        RedirectAction::Follow { same_origin: false }
    );
    assert!(state.body_mut().can_replay());
    Ok(())
}

#[test]
fn get_rewrites_discard_buffered_credential_trailers_before_the_origin_check() -> TestResult {
    for status in [
        StatusCode::MOVED_PERMANENTLY,
        StatusCode::FOUND,
        StatusCode::SEE_OTHER,
    ] {
        let mut state = state("X-API-Key", policy())?;
        assert_eq!(
            state.follow(&redirect(status, "https://other.test/next")?)?,
            RedirectAction::Follow { same_origin: false }
        );
        assert_eq!(state.method(), Method::GET);
        assert!(matches!(state.body_mut(), RequestBodySource::Absent));
    }
    Ok(())
}

#[test]
fn callback_stop_keeps_the_buffered_body_without_rejecting_its_trailers() -> TestResult {
    let policy = RedirectPolicy::custom(NonZeroUsize::MIN, |_| RedirectDecision::Stop)
        .credential_headers([HeaderName::from_static("x-api-key")]);
    let mut state = state("X-API-Key", policy.clone())?;
    assert_eq!(
        state.follow(&redirect(
            StatusCode::TEMPORARY_REDIRECT,
            "https://other.test/next"
        )?)?,
        RedirectAction::Stop
    );
    assert!(state.body_mut().has_credential_trailers(&policy));
    assert_eq!(state.followed(), 0);
    Ok(())
}
