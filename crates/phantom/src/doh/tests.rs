use std::{
    net::{IpAddr, Ipv4Addr},
    num::NonZeroUsize,
    time::Duration,
};

use super::{
    DohAddressFamilies, DohBuildErrorKind, DohConfiguration, DohMethod, transport_profile,
    validate_configuration,
};

fn configuration(endpoint: &str) -> DohConfiguration {
    DohConfiguration::new(
        endpoint,
        [IpAddr::V4(Ipv4Addr::LOCALHOST)],
        DohMethod::Post,
        DohAddressFamilies::DualIpv6First,
        Duration::from_secs(3),
        NonZeroUsize::MIN,
    )
}

#[test]
fn bootstrap_preserves_dns_identity_and_rejects_ambiguous_endpoint_configuration() {
    let normalized =
        validate_configuration(&configuration("https://BÜCHER.example/dns-query?tenant=a"));
    assert_eq!(
        normalized
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned)),
        Some("xn--bcher-kva.example".to_owned())
    );
    for endpoint in [
        "http://dns.example/dns-query",
        "https://user@dns.example/dns-query",
        "https://dns.example/dns-query#",
        "https://dns.example/dns-query{?dns}",
        "https://dns.example/dns-query?dns=x",
        "https://dns.example/dns-query?%64ns=x",
        "https://dns.example:0/dns-query",
    ] {
        assert_eq!(
            validate_configuration(&configuration(endpoint))
                .err()
                .map(|error| error.kind()),
            Some(DohBuildErrorKind::InvalidEndpoint),
            "{endpoint}"
        );
    }
}

#[test]
fn ip_endpoint_keeps_its_identity_and_cannot_substitute_bootstrap_addresses()
-> Result<(), Box<dyn std::error::Error>> {
    let mut config = configuration("https://127.0.0.1/dns-query");
    assert!(validate_configuration(&config).is_ok());
    config.bootstrap.push("192.0.2.1".parse()?);
    assert_eq!(
        validate_configuration(&config)
            .err()
            .map(|error| error.kind()),
        Some(DohBuildErrorKind::InvalidBootstrap)
    );
    config.endpoint = "https://[::1]/dns-query".into();
    config.bootstrap = vec!["::1".parse()?];
    assert!(validate_configuration(&config).is_ok());
    config.bootstrap.push("127.0.0.1".parse()?);
    assert_eq!(
        validate_configuration(&config)
            .err()
            .map(|error| error.kind()),
        Some(DohBuildErrorKind::InvalidBootstrap)
    );
    Ok(())
}

#[test]
fn external_bounds_and_bootstrap_fail_before_constructing_a_semaphore()
-> Result<(), Box<dyn std::error::Error>> {
    let mut config = configuration("https://dns.example/query");
    config.maximum_lookups =
        NonZeroUsize::new(tokio::sync::Semaphore::MAX_PERMITS + 1).ok_or("invalid test bound")?;
    assert_eq!(
        validate_configuration(&config)
            .err()
            .map(|error| error.kind()),
        Some(DohBuildErrorKind::InvalidLimits)
    );
    config.maximum_lookups = NonZeroUsize::MIN;
    for timeout in [Duration::ZERO, Duration::MAX] {
        config.lookup_timeout = timeout;
        assert_eq!(
            validate_configuration(&config)
                .err()
                .map(|error| error.kind()),
            Some(DohBuildErrorKind::InvalidLimits)
        );
    }
    config.lookup_timeout = Duration::from_secs(3);
    for addresses in [
        Vec::new(),
        vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)],
        vec![IpAddr::V4(Ipv4Addr::BROADCAST)],
        vec!["ff02::1".parse()?],
        vec!["fe80::1".parse()?],
    ] {
        config.bootstrap = addresses;
        assert_eq!(
            validate_configuration(&config)
                .err()
                .map(|error| error.kind()),
            Some(DohBuildErrorKind::InvalidBootstrap)
        );
    }
    Ok(())
}

#[test]
fn configuration_debug_omits_endpoint_query_and_addresses() {
    let debug = format!(
        "{:?}",
        configuration("https://dns.example/query?token=private")
    );
    assert!(!debug.contains("private"));
    assert!(!debug.contains("dns.example"));
    assert!(!debug.contains("127.0.0.1"));
}

#[test]
fn private_profile_preserves_transport_and_excludes_application_hints_and_templates()
-> Result<(), Box<dyn std::error::Error>> {
    use phantom_profile::browser::chrome;
    let profile =
        chrome::v154_windows().with_request_template(chrome::v154_windows_navigation_template());
    let transport = transport_profile(profile.clone())?;
    assert_eq!(transport.tls(), profile.tls());
    assert_eq!(transport.tcp(), profile.tcp());
    assert_eq!(transport.http2(), profile.http2());
    assert!(profile.client_hints().is_some());
    assert!(profile.request_template().is_some());
    assert!(transport.client_hints().is_none());
    assert!(transport.request_template().is_none());
    assert!(transport.http1().is_none());
    assert!(transport.http3().is_none());
    assert!(transport.websocket().is_none());
    assert!(transport.proxy_connect().is_none());
    let missing_http2 = phantom_profile::ClientProfile::new(chrome::v154_tcp_tls());
    assert_eq!(
        transport_profile(missing_http2)
            .err()
            .map(|error| error.kind()),
        Some(DohBuildErrorKind::MissingHttp2)
    );
    Ok(())
}
