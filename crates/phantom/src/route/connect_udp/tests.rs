use phantom_net::request::{OriginForm, RequestHeader};

use super::{ConnectUdpProxy, ConnectUdpProxyConfigErrorKind as Kind};
use crate::Route;

const DEFAULT_TEMPLATE: &str =
    "https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/";

fn expanded(
    template: &str,
    host: &str,
    port: u16,
) -> Result<OriginForm, Box<dyn std::error::Error>> {
    let proxy = ConnectUdpProxy::new(template)?;
    Ok(proxy
        .expand(host, port)
        .map_err(|_| "template expansion failed")?)
}

fn target(value: &str) -> Result<OriginForm, Box<dyn std::error::Error>> {
    Ok(OriginForm::parse(value).map_err(|_| "invalid expected target")?)
}

#[test]
fn default_template_expands_domain_and_ipv4_targets() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        expanded(DEFAULT_TEMPLATE, "origin.example", 443)?,
        target("/.well-known/masque/udp/origin.example/443/")?
    );
    assert_eq!(
        expanded(DEFAULT_TEMPLATE, "192.0.2.6", 8443)?,
        target("/.well-known/masque/udp/192.0.2.6/8443/")?
    );
    let proxy = ConnectUdpProxy::new(DEFAULT_TEMPLATE)?;
    assert_eq!(proxy.host(), "proxy.example");
    assert_eq!(proxy.port(), 443);
    assert_eq!(proxy.authority(), "proxy.example");
    Ok(())
}

#[test]
fn template_percent_encodes_ipv6_target_colons() -> Result<(), Box<dyn std::error::Error>> {
    // RFC 9298 section 3 example.
    assert_eq!(
        expanded(DEFAULT_TEMPLATE, "2001:db8::42", 443)?,
        target("/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/")?
    );
    Ok(())
}

#[test]
fn form_style_query_expressions_expand_named_pairs() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        expanded(
            "https://proxy.example:8443/masque{?target_host,target_port}",
            "::1",
            53
        )?,
        target("/masque?target_host=%3A%3A1&target_port=53")?
    );
    assert_eq!(
        expanded(
            "https://proxy.example/masque?h={target_host}{&target_port}",
            "origin.example",
            443
        )?,
        target("/masque?h=origin.example&target_port=443")?
    );
    Ok(())
}

#[test]
fn template_authority_is_canonicalized() -> Result<(), Box<dyn std::error::Error>> {
    let proxy = ConnectUdpProxy::new("HTTPS://Proxy.Example:4433/udp/{target_host}/{target_port}")?;
    assert_eq!(proxy.host(), "proxy.example");
    assert_eq!(proxy.port(), 4433);
    assert_eq!(proxy.authority(), "proxy.example:4433");

    let ipv6 = ConnectUdpProxy::new("https://[::1]:4433/udp/{target_host}/{target_port}")?;
    assert_eq!(ipv6.host(), "::1");
    assert_eq!(ipv6.authority(), "[::1]:4433");
    Ok(())
}

#[test]
fn template_requires_https_and_both_target_variables() {
    for (template, kind) in [
        (
            "http://proxy.example/udp/{target_host}/{target_port}/",
            Kind::UnsupportedScheme,
        ),
        (
            "masque://proxy.example/udp/{target_host}/{target_port}/",
            Kind::UnsupportedScheme,
        ),
        ("/udp/{target_host}/{target_port}/", Kind::InvalidTemplate),
        (
            "https://proxy.example/udp/{target_host}/",
            Kind::MissingVariable,
        ),
        (
            "https://proxy.example/udp/{target_port}/",
            Kind::MissingVariable,
        ),
        (
            "https://proxy.example{?target_host,target_port}",
            Kind::UnsupportedExpression,
        ),
    ] {
        assert_eq!(
            ConnectUdpProxy::new(template)
                .err()
                .map(|error| error.kind()),
            Some(kind),
            "{template}"
        );
    }
}

#[test]
fn template_rejects_userinfo_fragment_and_unknown_variables() {
    for (template, kind) in [
        (
            "https://user@proxy.example/udp/{target_host}/{target_port}/",
            Kind::InvalidAuthority,
        ),
        (
            "https://user:secret@proxy.example/udp/{target_host}/{target_port}/",
            Kind::InvalidAuthority,
        ),
        (
            "https://proxy.example/udp/{target_host}/{target_port}/#frag",
            Kind::Fragment,
        ),
        (
            "https://proxy.example/udp/{target_host}/{target_port}/{#target_host}",
            Kind::UnsupportedExpression,
        ),
        (
            "https://proxy.example/udp/{target_host}/{target_port}/{tenant}",
            Kind::UnknownVariable,
        ),
        (
            "https://{target_host}/udp/{target_port}/",
            Kind::UnsupportedExpression,
        ),
        (
            "https://proxy.example/udp/{+target_host}/{target_port}/",
            Kind::UnsupportedExpression,
        ),
        (
            "https://proxy.example/udp{/target_host}/{target_port}/",
            Kind::UnsupportedExpression,
        ),
        (
            "https://proxy.example/udp/{target_host:3}/{target_port}/",
            Kind::UnsupportedExpression,
        ),
        (
            "https://proxy.example/udp/{target_host/{target_port}/",
            Kind::UnknownVariable,
        ),
        (
            "https://proxy.example/udp/{target_host}/{target_port}/}",
            Kind::InvalidTemplate,
        ),
        (
            "https://proxy.example/udp/{target_host}/{target_port}/ ",
            Kind::InvalidTemplate,
        ),
        (
            "https://proxy.exämple/udp/{target_host}/{target_port}/",
            Kind::InvalidTemplate,
        ),
    ] {
        assert_eq!(
            ConnectUdpProxy::new(template)
                .err()
                .map(|error| error.kind()),
            Some(kind),
            "{template}"
        );
    }
}

#[test]
fn route_identity_includes_template_and_ordered_fields_without_debugging_values()
-> Result<(), Box<dyn std::error::Error>> {
    let base = ConnectUdpProxy::new(DEFAULT_TEMPLATE)?;
    let with_field = base
        .clone()
        .header(RequestHeader::new("proxy-token", "secret-value"));
    let other_path =
        ConnectUdpProxy::new("https://proxy.example/masque/{target_host}/{target_port}/")?;

    assert_eq!(
        Route::connect_udp(base.clone()),
        Route::connect_udp(ConnectUdpProxy::new(DEFAULT_TEMPLATE)?)
    );
    assert_ne!(
        Route::connect_udp(base.clone()),
        Route::connect_udp(with_field.clone())
    );
    assert_ne!(
        Route::connect_udp(base.clone()),
        Route::connect_udp(other_path)
    );
    assert_eq!(Route::connect_udp(base).trace_name(), "connect_udp");
    let debug = format!("{with_field:?}");
    assert!(debug.contains("header_count: 1"));
    assert!(!debug.contains("secret-value"));
    Ok(())
}
