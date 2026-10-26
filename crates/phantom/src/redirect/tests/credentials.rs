use http::header::HeaderName;

use super::*;

#[test]
fn credential_configuration_replaces_names_without_enabling_redirects() {
    let original =
        RedirectPolicy::none().credential_headers([HeaderName::from_static("x-api-key")]);
    let changed = original
        .clone()
        .credential_headers([HeaderName::from_static("x-token")]);

    assert_eq!(changed.max_hops(), None);
    assert!(original.removes_credential_header("X-API-KEY"));
    assert!(!original.removes_credential_header("x-token"));
    assert!(!changed.removes_credential_header("x-api-key"));
    assert!(changed.removes_credential_header("X-TOKEN"));
    for name in ["Authorization", "Cookie", "Cookie2", "Proxy-Authorization"] {
        assert!(changed.removes_credential_header(name));
    }
    assert!(
        changed
            .credential_headers([])
            .removes_credential_header("cookie")
    );
}

#[test]
fn custom_credentials_leave_headers_and_trailers_permanently() -> TestResult {
    for destination in [
        "https://other.test/final",
        "https://example.test:8443/final",
        "http://example.test/final",
    ] {
        let mut state = state(Method::POST)?;
        state.policy = state
            .policy
            .clone()
            .credential_headers([HeaderName::from_static("x-api-key")]);
        state
            .headers
            .push(RequestHeader::new("X-API-Key", "caller-secret"));
        state
            .headers
            .push(RequestHeader::new("x-sensitive", "kept").sensitive());
        state
            .trailers
            .push(RequestHeader::new("X-Api-Key", "trailer-secret"));

        assert_eq!(
            state.follow(&redirect(StatusCode::TEMPORARY_REDIRECT, destination)?)?,
            RedirectAction::Follow { same_origin: false }
        );
        assert_eq!(
            state
                .headers()
                .iter()
                .map(RequestHeader::name)
                .collect::<Vec<_>>(),
            ["content-type", "x-ordered", "x-sensitive"]
        );
        assert_eq!(
            state
                .trailers()
                .iter()
                .map(RequestHeader::name)
                .collect::<Vec<_>>(),
            ["x-trailer"]
        );
        assert_eq!(state.body(), Some(&Bytes::from_static(b"body")));

        state.follow(&redirect(
            StatusCode::TEMPORARY_REDIRECT,
            "https://example.test/back",
        )?)?;
        assert!(
            !state
                .headers()
                .iter()
                .chain(state.trailers())
                .any(|header| header.name().eq_ignore_ascii_case("x-api-key"))
        );
    }
    Ok(())
}

#[test]
fn same_origin_keeps_registered_credentials_and_trailers() -> TestResult {
    let mut state = state(Method::POST)?;
    state.policy = state
        .policy
        .clone()
        .credential_headers([HeaderName::from_static("x-api-key")]);
    state
        .headers
        .push(RequestHeader::new("x-api-key", "caller-secret"));
    state
        .trailers
        .push(RequestHeader::new("x-api-key", "trailer-secret"));

    assert_eq!(
        state.follow(&redirect(StatusCode::TEMPORARY_REDIRECT, "/next")?)?,
        RedirectAction::Follow { same_origin: true }
    );
    assert_eq!(
        state.headers().last().map(RequestHeader::value),
        Some(b"caller-secret".as_slice())
    );
    assert_eq!(
        state.trailers().last().map(RequestHeader::value),
        Some(b"trailer-secret".as_slice())
    );
    Ok(())
}
