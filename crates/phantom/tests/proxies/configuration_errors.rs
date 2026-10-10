//! Proxy construction preserves validation causes without retaining secrets.

use std::error::Error;

use phantom::{EnvironmentProxies, HttpProxy, ProxyConfigError, ProxyConfigErrorKind};
use phantom_net::proxy::HttpConnectError;

mod sibling_routes;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn canary() -> TestResult<String> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    Ok(format!("{timestamp:032x}"))
}

#[test]
fn invalid_username_keeps_its_specific_validation_cause() -> TestResult {
    let marker = canary()?;
    let error = HttpProxy::new("https://proxy.example")?
        .with_basic_auth(format!("{marker}:invalid"), &marker)
        .err()
        .ok_or("invalid username was accepted")?;

    assert_eq!(error.kind(), ProxyConfigErrorKind::InvalidCredentials);
    assert!(matches!(
        error
            .source()
            .ok_or("missing credential cause")?
            .downcast_ref(),
        Some(HttpConnectError::InvalidBasicUsername)
    ));
    Ok(())
}

#[test]
fn invalid_password_keeps_its_specific_validation_cause() -> TestResult {
    let marker = canary()?;
    let error = HttpProxy::new("https://proxy.example")?
        .with_basic_auth(&marker, format!("{marker}\r"))
        .err()
        .ok_or("invalid password was accepted")?;

    assert_eq!(error.kind(), ProxyConfigErrorKind::InvalidCredentials);
    assert!(matches!(
        error
            .source()
            .ok_or("missing credential cause")?
            .downcast_ref(),
        Some(HttpConnectError::InvalidBasicPassword)
    ));
    Ok(())
}

#[test]
fn oversized_credentials_keep_their_specific_validation_cause() -> TestResult {
    let marker = canary()?;
    let password = marker.repeat(2048);
    let error = HttpProxy::new("https://proxy.example")?
        .with_basic_auth(&marker, &password)
        .err()
        .ok_or("oversized credentials were accepted")?;

    assert_eq!(error.kind(), ProxyConfigErrorKind::InvalidCredentials);
    assert!(matches!(
        error
            .source()
            .ok_or("missing credential cause")?
            .downcast_ref(),
        Some(HttpConnectError::BasicCredentialsTooLarge)
    ));
    Ok(())
}

#[test]
fn uri_authority_validation_keeps_its_static_cause() -> TestResult {
    let marker = canary()?;
    let error = HttpProxy::new(&format!("http://{marker}:{marker}@proxy.example"))
        .err()
        .ok_or("URI credentials were accepted")?;

    assert_eq!(error.kind(), ProxyConfigErrorKind::InvalidAuthority);
    assert_eq!(
        error.to_string(),
        "authority must not contain user information"
    );
    let cause = error.source().ok_or("missing URI authority cause")?;
    assert_eq!(
        cause.to_string(),
        "authority must not contain user information"
    );
    assert!(cause.source().is_none());
    Ok(())
}

#[test]
fn endpoint_port_validation_keeps_its_static_cause() -> TestResult {
    let error = HttpProxy::new("http://proxy.example:65536")
        .err()
        .ok_or("out-of-range port was accepted")?;

    assert_eq!(error.kind(), ProxyConfigErrorKind::InvalidAuthority);
    assert_eq!(error.to_string(), "port is invalid");
    let cause = error.source().ok_or("missing endpoint authority cause")?;
    assert_eq!(cause.to_string(), "port is invalid");
    assert!(cause.source().is_none());
    Ok(())
}

#[test]
fn environment_username_validation_keeps_the_proxy_cause_chain() -> TestResult {
    let marker = canary()?;
    let error = EnvironmentProxies::from_values([(
        "https_proxy",
        format!("http://{marker}%3Ainvalid:{marker}@proxy.example"),
    )])
    .err()
    .ok_or("invalid environment username was accepted")?;

    let proxy = error
        .source()
        .ok_or("missing proxy cause")?
        .downcast_ref::<ProxyConfigError>()
        .ok_or("wrong proxy cause type")?;
    assert_eq!(proxy.kind(), ProxyConfigErrorKind::InvalidCredentials);
    assert!(matches!(
        proxy
            .source()
            .ok_or("missing credential cause")?
            .downcast_ref(),
        Some(HttpConnectError::InvalidBasicUsername)
    ));
    Ok(())
}

#[test]
fn environment_password_validation_keeps_the_proxy_cause_chain() -> TestResult {
    let marker = canary()?;
    let error = EnvironmentProxies::from_values([(
        "https_proxy",
        format!("http://{marker}:{marker}%C3%A9@proxy.example"),
    )])
    .err()
    .ok_or("invalid environment password was accepted")?;

    let proxy = error
        .source()
        .ok_or("missing proxy cause")?
        .downcast_ref::<ProxyConfigError>()
        .ok_or("wrong proxy cause type")?;
    assert_eq!(proxy.kind(), ProxyConfigErrorKind::InvalidCredentials);
    assert!(matches!(
        proxy
            .source()
            .ok_or("missing credential cause")?
            .downcast_ref(),
        Some(HttpConnectError::InvalidBasicPassword)
    ));
    Ok(())
}

#[test]
fn validation_diagnostics_omit_supplied_credentials_at_every_level() -> TestResult {
    let marker = canary()?;
    let credentials = [
        (format!("{marker}:invalid"), marker.clone()),
        (marker.clone(), format!("{marker}\r")),
        (marker.clone(), marker.repeat(2048)),
    ];

    for (username, password) in credentials {
        let error = HttpProxy::new("http://proxy.example")?
            .with_basic_auth(username, password)
            .err()
            .ok_or("invalid credentials were accepted")?;
        let mut current: Option<&dyn Error> = Some(&error);
        while let Some(cause) = current {
            let diagnostic = format!("{cause} {cause:?}");
            assert!(!diagnostic.contains(&marker));
            current = cause.source();
        }
    }
    Ok(())
}

#[test]
fn uri_syntax_errors_keep_the_existing_parser_cause() -> TestResult {
    let error = HttpProxy::new("http://proxy.example/invalid path")
        .err()
        .ok_or("invalid URI syntax was accepted")?;

    assert_eq!(error.kind(), ProxyConfigErrorKind::InvalidUri);
    assert!(
        error
            .source()
            .ok_or("missing URI syntax cause")?
            .is::<http::uri::InvalidUri>()
    );
    Ok(())
}

#[test]
fn locally_rejected_proxy_options_do_not_invent_causes() -> TestResult {
    for (uri, kind) in [
        (
            "ftp://proxy.example",
            ProxyConfigErrorKind::UnsupportedScheme,
        ),
        (
            "http://proxy.example/path",
            ProxyConfigErrorKind::UnexpectedPath,
        ),
    ] {
        let error = HttpProxy::new(uri)
            .err()
            .ok_or("unsupported proxy option was accepted")?;

        assert_eq!(error.kind(), kind);
        assert!(error.source().is_none());
    }
    Ok(())
}

#[test]
fn valid_proxy_credentials_and_ports_remain_accepted() -> TestResult {
    let marker = canary()?;
    let proxy = HttpProxy::new("https://proxy.example:65535")?.with_basic_auth(&marker, &marker)?;

    assert!(!format!("{proxy:?}").contains(&marker));
    EnvironmentProxies::from_values([(
        "https_proxy",
        format!("http://{marker}:{marker}@proxy.example:8080"),
    )])?;
    Ok(())
}
