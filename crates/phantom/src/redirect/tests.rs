use std::{error::Error, num::NonZeroUsize};

use bytes::Bytes;
use http::{Method, Response, StatusCode};
use phantom_net::request::RequestHeader;
use phantom_profile::{ClientHint, ClientHintDelivery, ClientHintSettings};

use super::{RedirectAction, RedirectPolicy, RedirectState};
use crate::{RequestErrorKind, request::RequestBodySource};

type TestResult = Result<(), Box<dyn Error>>;

fn redirect(status: StatusCode, location: &str) -> Result<Response<()>, http::Error> {
    Response::builder()
        .status(status)
        .header(http::header::LOCATION, location)
        .body(())
}

fn state(method: Method) -> Result<RedirectState, Box<dyn Error>> {
    let maximum = NonZeroUsize::new(2).ok_or("redirect limit must be non-zero")?;
    Ok(RedirectState::new(
        RedirectPolicy::limited(maximum),
        url::Url::parse("https://example.test/start")?,
        method,
        vec![
            RequestHeader::new("content-type", "text/plain"),
            RequestHeader::new("authorization", "secret"),
            RequestHeader::new("cookie2", "legacy=secret"),
            RequestHeader::new("x-ordered", "one"),
        ],
        RequestBodySource::Bytes(Bytes::from_static(b"body")),
    ))
}

#[test]
fn policy_is_disabled_by_default() {
    assert_eq!(RedirectPolicy::default(), RedirectPolicy::none());
    assert_eq!(RedirectPolicy::none().max_hops(), None);
}

#[test]
fn found_rewrites_post_and_normalizes_relative_dot_segments() -> TestResult {
    let mut state = state(Method::POST)?;

    assert!(matches!(
        state.follow(&redirect(StatusCode::FOUND, "/a/%2e%2e/final")?)?,
        RedirectAction::Follow { same_origin: true }
    ));

    assert_eq!(state.method(), Method::GET);
    assert!(state.body().is_none());
    assert_eq!(state.current_url().as_str(), "https://example.test/final");
    assert_eq!(
        state
            .headers()
            .iter()
            .map(RequestHeader::name)
            .collect::<Vec<_>>(),
        ["authorization", "cookie2", "x-ordered"]
    );
    Ok(())
}

#[test]
fn temporary_redirect_preserves_method_body_and_header_order() -> TestResult {
    let mut state = state(Method::POST)?;

    assert!(matches!(
        state.follow(&redirect(StatusCode::TEMPORARY_REDIRECT, "/final")?)?,
        RedirectAction::Follow { same_origin: true }
    ));

    assert_eq!(state.method(), Method::POST);
    assert_eq!(state.body(), Some(&Bytes::from_static(b"body")));
    assert_eq!(
        state
            .headers()
            .iter()
            .map(RequestHeader::name)
            .collect::<Vec<_>>(),
        ["content-type", "authorization", "cookie2", "x-ordered"]
    );
    Ok(())
}

#[test]
fn cross_origin_redirect_strips_credentials_only() -> TestResult {
    let mut state = state(Method::GET)?;

    assert!(matches!(
        state.follow(&redirect(
            StatusCode::PERMANENT_REDIRECT,
            "https://other.test/final"
        )?)?,
        RedirectAction::Follow { same_origin: false }
    ));

    assert_eq!(
        state
            .headers()
            .iter()
            .map(RequestHeader::name)
            .collect::<Vec<_>>(),
        ["content-type", "x-ordered"]
    );
    Ok(())
}

#[test]
fn configured_client_hints_are_stripped_before_cross_origin_rebuild() -> TestResult {
    let mut state = state(Method::GET)?;
    state
        .headers
        .push(RequestHeader::new("Sec-CH-UA", "caller"));
    state
        .headers
        .push(RequestHeader::new("x-after-hint", "two"));
    let settings = ClientHintSettings::new(vec![ClientHint::new(
        "sec-ch-ua",
        "profile",
        ClientHintDelivery::Default,
    )]);

    assert!(matches!(
        state.follow(&redirect(
            StatusCode::PERMANENT_REDIRECT,
            "https://other.test/final"
        )?)?,
        RedirectAction::Follow { same_origin: false }
    ));
    state.strip_client_hints(&settings);

    assert_eq!(
        state
            .headers()
            .iter()
            .map(RequestHeader::name)
            .collect::<Vec<_>>(),
        ["content-type", "x-ordered", "x-after-hint"]
    );
    Ok(())
}

#[test]
fn limit_is_reported_before_an_extra_request() -> TestResult {
    let mut state = state(Method::GET)?;
    let response = redirect(StatusCode::FOUND, "/again")?;

    assert!(matches!(
        state.follow(&response)?,
        RedirectAction::Follow { .. }
    ));
    assert!(matches!(
        state.follow(&response)?,
        RedirectAction::Follow { .. }
    ));
    let error = match state.follow(&response) {
        Ok(_) => return Err("third redirect did not exceed the limit".into()),
        Err(error) => error,
    };

    assert_eq!(error.kind(), RequestErrorKind::Redirect);
    assert_eq!(state.followed(), 2);
    Ok(())
}

#[test]
fn multiple_locations_are_rejected() -> TestResult {
    let response = Response::builder()
        .status(StatusCode::FOUND)
        .header(http::header::LOCATION, "/one")
        .header(http::header::LOCATION, "/two")
        .body(())?;
    let error = match state(Method::GET)?.follow(&response) {
        Ok(_) => return Err("ambiguous Location was accepted".into()),
        Err(error) => error,
    };

    assert_eq!(error.kind(), RequestErrorKind::Redirect);
    Ok(())
}

#[test]
fn missing_location_leaves_the_response_visible() -> TestResult {
    let response = Response::builder().status(StatusCode::FOUND).body(())?;

    assert_eq!(state(Method::GET)?.follow(&response)?, RedirectAction::Stop);
    Ok(())
}

#[test]
fn redirect_statuses_apply_the_browser_method_and_body_matrix() -> TestResult {
    let cases = [
        (
            StatusCode::MOVED_PERMANENTLY,
            Method::POST,
            Method::GET,
            false,
        ),
        (
            StatusCode::MOVED_PERMANENTLY,
            Method::PUT,
            Method::PUT,
            true,
        ),
        (StatusCode::FOUND, Method::POST, Method::GET, false),
        (StatusCode::FOUND, Method::PUT, Method::PUT, true),
        (StatusCode::SEE_OTHER, Method::POST, Method::GET, false),
        (StatusCode::SEE_OTHER, Method::PUT, Method::GET, false),
        (StatusCode::SEE_OTHER, Method::GET, Method::GET, true),
        (StatusCode::SEE_OTHER, Method::HEAD, Method::HEAD, true),
        (
            StatusCode::TEMPORARY_REDIRECT,
            Method::POST,
            Method::POST,
            true,
        ),
        (
            StatusCode::TEMPORARY_REDIRECT,
            Method::PUT,
            Method::PUT,
            true,
        ),
        (
            StatusCode::PERMANENT_REDIRECT,
            Method::POST,
            Method::POST,
            true,
        ),
        (
            StatusCode::PERMANENT_REDIRECT,
            Method::PUT,
            Method::PUT,
            true,
        ),
    ];

    for (status, initial, expected, preserves_body) in cases {
        let mut state = state(initial)?;
        state.follow(&redirect(status, "/final")?)?;

        assert_eq!(state.method(), expected, "status {status}");
        assert_eq!(state.body().is_some(), preserves_body, "status {status}");
    }
    Ok(())
}

#[test]
fn explicit_default_port_is_same_origin() -> TestResult {
    let mut state = state(Method::GET)?;

    let action = state.follow(&redirect(
        StatusCode::TEMPORARY_REDIRECT,
        "https://example.test:443/final",
    )?)?;

    assert_eq!(action, RedirectAction::Follow { same_origin: true });
    assert!(
        state
            .headers()
            .iter()
            .any(|header| header.name() == "authorization")
    );
    Ok(())
}
