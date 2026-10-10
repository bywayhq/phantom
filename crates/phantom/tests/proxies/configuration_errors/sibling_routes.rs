use std::error::Error;

use phantom::{
    ConnectUdpProxy, ConnectUdpProxyConfigErrorKind, Socks5Proxy, Socks5ProxyConfigErrorKind,
};
use phantom_net::{proxy::HttpConnectError, request::InvalidOriginForm};

use super::TestResult;

const TEMPLATE: &str = "https://proxy.example/udp/{target_host}/{target_port}/";

#[test]
fn socks_uri_authority_validation_keeps_its_static_cause() -> TestResult {
    let error = Socks5Proxy::new("socks5h://username-canary:password-canary@proxy.example")
        .expect_err("SOCKS URI credentials were accepted");

    assert_eq!(error.kind(), Socks5ProxyConfigErrorKind::InvalidAuthority);
    assert_eq!(
        error.to_string(),
        "authority must not contain user information"
    );
    assert_eq!(
        error.source().ok_or("missing authority cause")?.to_string(),
        error.to_string()
    );
    Ok(())
}

#[test]
fn socks_endpoint_port_validation_keeps_its_static_cause() -> TestResult {
    let error = Socks5Proxy::new("socks5h://proxy.example:65536")
        .expect_err("out-of-range SOCKS port was accepted");

    assert_eq!(error.kind(), Socks5ProxyConfigErrorKind::InvalidAuthority);
    assert_eq!(error.to_string(), "port is invalid");
    assert_eq!(
        error.source().ok_or("missing authority cause")?.to_string(),
        "port is invalid"
    );
    Ok(())
}

#[test]
fn connect_udp_username_validation_keeps_its_specific_cause() -> TestResult {
    let error = ConnectUdpProxy::new(TEMPLATE)?
        .with_basic_auth("username-canary:invalid", "password-canary")
        .expect_err("invalid CONNECT-UDP username was accepted");

    assert_eq!(
        error.kind(),
        ConnectUdpProxyConfigErrorKind::InvalidCredentials
    );
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
fn connect_udp_password_validation_keeps_its_specific_cause() -> TestResult {
    let error = ConnectUdpProxy::new(TEMPLATE)?
        .with_basic_auth("username-canary", "password-canary\r")
        .expect_err("invalid CONNECT-UDP password was accepted");

    assert_eq!(
        error.kind(),
        ConnectUdpProxyConfigErrorKind::InvalidCredentials
    );
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
fn connect_udp_oversized_credentials_keep_their_specific_cause() -> TestResult {
    let error = ConnectUdpProxy::new(TEMPLATE)?
        .with_basic_auth(
            "username-canary",
            "oversized-credential-canary".repeat(2048),
        )
        .expect_err("oversized CONNECT-UDP credentials were accepted");

    assert_eq!(
        error.kind(),
        ConnectUdpProxyConfigErrorKind::InvalidCredentials
    );
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
fn connect_udp_uri_authority_validation_keeps_its_static_cause() -> TestResult {
    let error = ConnectUdpProxy::new(
        "https://username-canary:password-canary@proxy.example/udp/{target_host}/{target_port}/",
    )
    .expect_err("CONNECT-UDP URI credentials were accepted");

    assert_eq!(
        error.kind(),
        ConnectUdpProxyConfigErrorKind::InvalidAuthority
    );
    assert_eq!(
        error.to_string(),
        "authority must not contain user information"
    );
    assert_eq!(
        error.source().ok_or("missing authority cause")?.to_string(),
        error.to_string()
    );
    Ok(())
}

#[test]
fn connect_udp_endpoint_port_validation_keeps_its_static_cause() -> TestResult {
    let error =
        ConnectUdpProxy::new("https://proxy.example:65536/udp/{target_host}/{target_port}/")
            .expect_err("out-of-range CONNECT-UDP port was accepted");

    assert_eq!(
        error.kind(),
        ConnectUdpProxyConfigErrorKind::InvalidAuthority
    );
    assert_eq!(error.to_string(), "port is invalid");
    assert_eq!(
        error.source().ok_or("missing authority cause")?.to_string(),
        "port is invalid"
    );
    Ok(())
}

#[test]
fn oversized_template_expansion_keeps_its_origin_form_cause() -> TestResult {
    let template = format!(
        "https://proxy.example/{}{{target_host}}/{{target_port}}/",
        "x".repeat(65536)
    );
    let error = ConnectUdpProxy::new(&template).expect_err("oversized request target was accepted");

    assert_eq!(
        error.kind(),
        ConnectUdpProxyConfigErrorKind::InvalidTemplate
    );
    assert_eq!(
        error.to_string(),
        "CONNECT-UDP template does not expand to a valid request target"
    );
    let target = error.source().ok_or("missing template expansion cause")?;
    assert!(
        target
            .source()
            .ok_or("missing origin-form cause")?
            .is::<InvalidOriginForm>()
    );
    Ok(())
}

#[test]
fn sibling_route_diagnostics_omit_credentials_and_template_text() -> TestResult {
    let socks = Socks5Proxy::new("socks5h://username-canary:password-canary@proxy.example")
        .expect_err("SOCKS URI credentials were accepted");
    let connect_udp = ConnectUdpProxy::new(TEMPLATE)?
        .with_basic_auth("username-canary", "password-canary\r")
        .expect_err("invalid CONNECT-UDP password was accepted");

    for error in [&socks as &dyn Error, &connect_udp as &dyn Error] {
        let mut current = Some(error);
        while let Some(cause) = current {
            let diagnostic = format!("{cause} {cause:?}");
            assert!(!diagnostic.contains("username-canary"));
            assert!(!diagnostic.contains("password-canary"));
            current = cause.source();
        }
    }
    Ok(())
}
