use std::num::NonZeroUsize;

use std::time::Duration;

use phantom_profile::{
    ClientProfile, Http1IdleTimeout, Http2IdleTimeout, Http3ClientSettings, TcpKeepalive,
    TcpKeepalivePolicy,
    browser::{chrome, firefox},
};

use super::{Client, HttpProtocol};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::BuildError;
use crate::{BuildErrorKind, HttpProxy, Route};

#[test]
fn invalid_default_request_template_is_an_invalid_profile() {
    use phantom_profile::{InvalidRequestTemplate, RequestField};
    use std::error::Error as _;

    let mut template = chrome::v154_windows_navigation_template();
    template
        .http2_fields
        .push(RequestField::literal("X-Invalid", "value"));
    let profile = ClientProfile::new(chrome::v154_tcp_tls()).with_request_template(template);
    let Err(error) = Client::builder(profile).build() else {
        panic!("uppercase H2 field was accepted");
    };

    assert_eq!(error.kind(), BuildErrorKind::InvalidProfile);
    assert!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<InvalidRequestTemplate>())
            .is_some()
    );
}

#[test]
fn connect_udp_proxy_connection_omits_resumption_additions() {
    use phantom_profile::QuicTransportParameterKind;

    let recipe = chrome::v154_quic();
    let outer = super::connect_udp_proxy_quic(&recipe);
    assert!(recipe.early_data);
    assert!(!outer.early_data);
    let without_rtt: Vec<_> = recipe
        .wire_parameters
        .iter()
        .filter(|parameter| parameter.kind != QuicTransportParameterKind::InitialRtt)
        .cloned()
        .collect();
    assert_eq!(without_rtt.len() + 1, recipe.wire_parameters.len());
    assert_eq!(outer.wire_parameters, without_rtt);
    assert_eq!(outer.parameter_order, recipe.parameter_order);
}

#[test]
fn protocol_trace_names_match_negotiated_tokens() {
    assert_eq!(HttpProtocol::Http1.trace_name(), "http/1.1");
    assert_eq!(HttpProtocol::Http2.trace_name(), "h2");
    assert_eq!(HttpProtocol::Http3.trace_name(), "h3");
}

#[test]
fn profile_tcp_settings_reach_every_tcp_connector() -> Result<(), Box<dyn std::error::Error>> {
    let tcp = chrome::v154_tcp();
    let http3 = Http3ClientSettings::new(
        chrome::v154_quic_tls(),
        chrome::v154_quic(),
        chrome::v154_http3(),
        chrome::v154_http3_request(),
    );
    let profile = ClientProfile::new(chrome::v154_tcp_tls())
        .with_tcp(tcp)
        .with_http2(chrome::v154_http2())
        .with_http3(http3);
    #[cfg(feature = "websocket")]
    let profile = profile.with_websocket(chrome::v154_websocket());
    let route = Route::http_proxy(HttpProxy::new("https://proxy.example")?);
    let client = Client::builder(profile).route(route).build()?;
    let inner = &client.inner;

    let expected = Some(&tcp);
    assert_eq!(
        inner.http1.as_ref().and_then(|c| c.tcp_settings()),
        expected
    );
    assert_eq!(
        inner.http2.as_ref().and_then(|c| c.tcp_settings()),
        expected
    );
    assert_eq!(
        inner.http1_or_2.as_ref().and_then(|c| c.tcp_settings()),
        expected
    );
    assert_eq!(
        inner.http3.as_ref().and_then(|c| c.tcp_settings()),
        expected
    );
    assert_eq!(
        inner.https_proxy.as_ref().and_then(|c| c.tcp_settings()),
        expected
    );
    #[cfg(feature = "websocket")]
    assert_eq!(
        inner
            .websocket_http1
            .as_ref()
            .and_then(|c| c.tcp_settings()),
        expected
    );
    Ok(())
}

#[test]
fn profile_udp_settings_reach_every_http3_connector() -> Result<(), Box<dyn std::error::Error>> {
    let udp = chrome::v154_udp();
    let http3 = Http3ClientSettings::new(
        chrome::v154_quic_tls(),
        chrome::v154_quic(),
        chrome::v154_http3(),
        chrome::v154_http3_request(),
    );
    let profile = ClientProfile::new(chrome::v154_tcp_tls())
        .with_udp(udp)
        .with_http3(http3.clone());
    let route = Route::http_proxy(HttpProxy::new("https://proxy.example")?);
    let client = Client::builder(profile).route(route).build()?;
    let inner = &client.inner;

    let expected = Some(&udp);
    assert_eq!(
        inner.http3.as_ref().and_then(|c| c.udp_settings()),
        expected
    );
    let connect_udp = inner
        .connect_udp_proxy
        .as_ref()
        .ok_or("no CONNECT-UDP connectors")?;
    assert_eq!(
        connect_udp.http3.as_ref().and_then(|c| c.udp_settings()),
        expected
    );

    let without = ClientProfile::new(chrome::v154_tcp_tls()).with_http3(http3);
    let client = Client::builder(without).build()?;
    assert_eq!(
        client.inner.http3.as_ref().and_then(|c| c.udp_settings()),
        None
    );
    Ok(())
}

#[test]
fn source_binding_reaches_every_connector() -> Result<(), Box<dyn std::error::Error>> {
    use std::net::{IpAddr, Ipv4Addr};

    let http3 = Http3ClientSettings::new(
        chrome::v154_quic_tls(),
        chrome::v154_quic(),
        chrome::v154_http3(),
        chrome::v154_http3_request(),
    );
    let profile = ClientProfile::new(chrome::v154_tcp_tls())
        .with_http2(chrome::v154_http2())
        .with_http3(http3);
    #[cfg(feature = "websocket")]
    let profile = profile.with_websocket(chrome::v154_websocket());
    let route = Route::http_proxy(HttpProxy::new("https://proxy.example")?);
    let address = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let client = Client::builder(profile)
        .route(route)
        // A host override rebinds every connector to a host resolver.
        .resolve("example.com", [address])
        .local_address(address)
        .build()?;
    let inner = &client.inner;

    let expected = phantom_net::SourceBinding::new().with_address(address);
    let expected = Some(&expected);
    assert_eq!(
        inner.http1.as_ref().and_then(|c| c.source_binding()),
        expected
    );
    assert_eq!(
        inner.http2.as_ref().and_then(|c| c.source_binding()),
        expected
    );
    assert_eq!(
        inner.http1_or_2.as_ref().and_then(|c| c.source_binding()),
        expected
    );
    assert_eq!(
        inner.http3.as_ref().and_then(|c| c.source_binding()),
        expected
    );
    for proxy in [
        &inner.https_proxy,
        &inner.forward_https_proxy,
        #[cfg(feature = "websocket")]
        &inner.websocket_https_proxy,
    ] {
        assert_eq!(proxy.as_ref().and_then(|c| c.source_binding()), expected);
    }
    let connect_udp = inner
        .connect_udp_proxy
        .as_ref()
        .ok_or("no CONNECT-UDP connectors")?;
    assert_eq!(
        connect_udp.http3.as_ref().and_then(|c| c.source_binding()),
        expected
    );
    assert_eq!(
        connect_udp.tcp.as_ref().and_then(|c| c.source_binding()),
        expected
    );
    #[cfg(feature = "websocket")]
    assert_eq!(
        inner
            .websocket_http1
            .as_ref()
            .and_then(|c| c.source_binding()),
        expected
    );

    let unbound = Client::builder(ClientProfile::new(chrome::v154_tcp_tls())).build()?;
    assert_eq!(
        unbound
            .inner
            .http1
            .as_ref()
            .and_then(|c| c.source_binding()),
        None
    );
    Ok(())
}

#[test]
fn invalid_tcp_profile_has_invalid_profile_category() -> Result<(), &'static str> {
    let mut tcp = chrome::v154_tcp();
    tcp.keepalive = TcpKeepalivePolicy::Fixed(TcpKeepalive {
        idle: Duration::ZERO,
        interval: None,
    });
    let profile = ClientProfile::new(chrome::v154_tcp_tls()).with_tcp(tcp);
    let error = Client::builder(profile)
        .build()
        .err()
        .ok_or("a zero keepalive idle time was accepted")?;

    assert_eq!(error.kind(), BuildErrorKind::InvalidProfile);
    Ok(())
}

#[test]
fn a_timer_idle_limit_beyond_firefox_range_is_an_invalid_profile() -> Result<(), &'static str> {
    let mut http1 = firefox::v157_http1();
    http1.idle_timeout = Http1IdleTimeout::ClosedOnTimer(Duration::MAX);
    let profile = ClientProfile::new(firefox::v157_tcp_tls()).with_http1(http1);
    let error = Client::builder(profile)
        .build()
        .err()
        .ok_or("an idle limit of Duration::MAX was accepted")?;

    assert_eq!(error.kind(), BuildErrorKind::InvalidProfile);
    Ok(())
}

#[test]
fn an_http2_idle_limit_outside_firefox_range_is_an_invalid_profile() -> Result<(), &'static str> {
    for limit in [Duration::ZERO, Duration::MAX] {
        let mut http2 = firefox::v157_http2();
        http2.idle_timeout = Http2IdleTimeout::ClosedOnTimer(limit);
        let profile = ClientProfile::new(firefox::v157_tcp_tls()).with_http2(http2);
        let error = Client::builder(profile)
            .build()
            .err()
            .ok_or("an HTTP/2 idle limit outside 1..=65535 seconds was accepted")?;
        assert_eq!(error.kind(), BuildErrorKind::InvalidProfile);
    }
    Ok(())
}

#[cfg(windows)]
#[test]
fn keepalive_without_interval_is_an_invalid_profile_on_windows() -> Result<(), &'static str> {
    let mut tcp = chrome::v154_tcp();
    tcp.keepalive = TcpKeepalivePolicy::Fixed(TcpKeepalive {
        idle: Duration::from_secs(45),
        interval: None,
    });
    let profile = ClientProfile::new(chrome::v154_tcp_tls()).with_tcp(tcp);
    let error = Client::builder(profile)
        .build()
        .err()
        .ok_or("Windows accepted a keepalive it cannot apply")?;

    assert_eq!(error.kind(), BuildErrorKind::InvalidProfile);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn idle_only_keepalive_builds_where_the_host_supports_it() -> Result<(), BuildError> {
    let mut tcp = chrome::v154_tcp();
    tcp.keepalive = TcpKeepalivePolicy::Fixed(TcpKeepalive {
        idle: Duration::from_secs(45),
        interval: None,
    });
    let profile = ClientProfile::new(chrome::v154_tcp_tls()).with_tcp(tcp);

    Client::builder(profile).build().map(drop)
}

#[test]
fn invalid_proxy_root_has_trust_store_category() -> Result<(), &'static str> {
    let profile = ClientProfile::new(chrome::v154_tcp_tls());
    let error = Client::builder(profile)
        .add_proxy_root_certificate_der(b"not-a-certificate".as_slice())
        .build()
        .err()
        .ok_or("invalid HTTPS-proxy trust root was accepted")?;

    assert_eq!(error.kind(), BuildErrorKind::TrustStore);
    Ok(())
}

#[cfg(feature = "danger-disable-verification")]
#[test]
fn disabled_proxy_authentication_rejects_proxy_roots() -> Result<(), &'static str> {
    let profile = ClientProfile::new(chrome::v154_tcp_tls());
    let error = Client::builder(profile)
        .proxy_server_authentication(crate::ServerAuthentication::DangerDisabled)
        .add_proxy_root_certificate_der(b"unused".as_slice())
        .build()
        .err()
        .ok_or("disabled HTTPS-proxy authentication accepted trust roots")?;

    assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);
    Ok(())
}

#[test]
fn https_proxy_requires_http1_in_the_tls_recipe() -> Result<(), &'static str> {
    let mut tls = chrome::v154_tcp_tls();
    tls.alpn_protocols = vec![Box::from(&b"h2"[..])];
    let profile = ClientProfile::new(tls).with_http2(chrome::v154_http2());
    let route = Route::http_proxy(
        HttpProxy::new("https://proxy.example")
            .map_err(|_| "valid HTTPS proxy route was rejected")?,
    );
    let error = Client::builder(profile)
        .route(route)
        .build()
        .err()
        .ok_or("HTTPS proxy accepted TLS settings without HTTP/1.1 ALPN")?;

    assert_eq!(error.kind(), BuildErrorKind::ProtocolConfiguration);
    Ok(())
}

#[test]
fn alt_svc_requires_negotiated_http1_or_2_and_http3() -> Result<(), &'static str> {
    let capacity = NonZeroUsize::MIN;
    let without_http3 = ClientProfile::new(chrome::v154_tcp_tls()).with_http2(chrome::v154_http2());
    let error = Client::builder(without_http3)
        .alt_svc(capacity)
        .build()
        .err()
        .ok_or("Alt-Svc was accepted without HTTP/3")?;
    assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);

    let http3 = Http3ClientSettings::new(
        chrome::v154_quic_tls(),
        chrome::v154_quic(),
        chrome::v154_http3(),
        chrome::v154_http3_request(),
    );
    let without_negotiation = ClientProfile::new(chrome::v154_quic_tls()).with_http3(http3);
    let error = Client::builder(without_negotiation)
        .alt_svc(capacity)
        .build()
        .err()
        .ok_or("Alt-Svc was accepted without negotiated HTTP/1.1 and HTTP/2")?;
    assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);
    Ok(())
}
