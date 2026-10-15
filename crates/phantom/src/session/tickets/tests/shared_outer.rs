use super::*;
use phantom_net::{
    http3::{ConnectUdpError, ConnectUdpErrorKind, Http3Connector},
    proxy::{HttpsProxyConnector, HttpsProxyProtocol, PreparedConnectUdpOuter},
};

fn tcp() -> Result<HttpsProxyConnector, Box<dyn std::error::Error>> {
    let base = HttpsProxyConnector::new(&chrome::v154_tcp_tls())?
        .with_http2_settings(&chrome::v154_http2());
    assert_eq!(base.protocol(), HttpsProxyProtocol::Http1);
    Ok(base.clone().with_protocol(HttpsProxyProtocol::Http2))
}

fn quic() -> Result<Http3Connector, Box<dyn std::error::Error>> {
    Ok(Http3Connector::new(
        &chrome::v154_quic_tls(),
        &chrome::v154_quic(),
        &chrome::v154_http3(),
        &chrome::v154_http3_request(),
    )?)
}

fn proxy_endpoint(proxy: &crate::ConnectUdpProxy) -> Result<Endpoint, Box<dyn std::error::Error>> {
    Ok(Endpoint::new(proxy.authority().parse()?, proxy.port())?)
}

fn outer<'a>(
    proxy: &'a Endpoint,
    route: &'a Route,
    protocol: TicketCacheProtocol,
) -> TicketCacheBinding<'a> {
    TicketCacheBinding {
        origin: proxy,
        server_name: proxy.host(),
        leg: TicketCacheLeg::ConnectUdp,
        protocol: Ok(protocol),
        route,
    }
}

#[tokio::test]
async fn shared_h2_and_h3_register_one_actual_proxy_cache_across_inner_origins() -> TestResult {
    let tcp = tcp()?;
    let quic = quic()?;
    for protocol in [TicketCacheProtocol::Http2, TicketCacheProtocol::Http3] {
        let mut proxy = crate::ConnectUdpProxy::new(
            "https://proxy.example:8443/udp/{target_host}/{target_port}/",
        )?;
        if protocol == TicketCacheProtocol::Http2 {
            proxy = proxy.with_http2_transport();
        }
        let endpoint = proxy_endpoint(&proxy)?;
        let route = Route::connect_udp(proxy.clone());
        let owner = prepared_owner()?;
        let mut prepared = Vec::<PreparedConnectUdpOuter>::new();
        for authority in ["first.example:443", "second.example:9443"] {
            let inner = Endpoint::new(authority.parse()?, 443)?;
            assert_ne!(inner, endpoint);
            // Inner owners differ, but the actual net preparation uses the same
            // outer pool/settings and configured proxy identity as the facade.
            let initiator = quic.with_isolated_session_cache();
            let token = if protocol == TicketCacheProtocol::Http2 {
                tcp.prepare_connect_udp_outer(
                    proxy.pool(),
                    proxy.host(),
                    proxy.port(),
                    proxy.authority(),
                    proxy.headers(),
                    proxy.credentials(),
                )?
            } else {
                initiator.prepare_connect_udp_outer(
                    &quic,
                    proxy.pool(),
                    proxy.host(),
                    proxy.port(),
                    proxy.authority(),
                    proxy.headers(),
                    proxy.credentials(),
                )?
            };
            for _ in 0..32 {
                owner.register_shared_outer_before_use(
                    token.session_ticket_cache(),
                    outer(&endpoint, &route, protocol),
                )?;
            }
            prepared.push(token);
        }
        let first = prepared[0]
            .session_ticket_cache()
            .and_then(|cache| cache.upgrade())
            .ok_or("first actual outer cache absent")?;
        let second = prepared[1]
            .session_ticket_cache()
            .and_then(|cache| cache.upgrade())
            .ok_or("second actual outer cache absent")?;
        assert!(first.same_cache(&second));
        {
            let registry = owner.registry();
            assert_eq!(registry.caches.len(), 1);
            let registered = &registry.caches[0];
            let binding = registered.binding.as_ref().map_err(|error| *error)?;
            assert_eq!(binding.origin, endpoint);
            assert_eq!(binding.server_name, "proxy.example");
            assert!(binding.leg == TicketCacheLeg::ConnectUdp);
            assert!(binding.protocol == protocol);
            assert_eq!(binding.route, route);
            let actual = registered.cache.upgrade().ok_or("weak cache absent")?;
            assert!(first.same_cache(&actual));
            assert!(registered.native_binding.is_ok());
        }
        // Clear sees one actual cache; no socket or handshake was started here.
        assert_eq!(owner.clear()?, 0);
        assert_eq!(owner.registry().caches.len(), 1);
    }
    Ok(())
}

#[tokio::test]
async fn changed_shared_outer_descriptor_stays_ineligible_without_alias_growth_or_native_rebind()
-> TestResult {
    let tcp = tcp()?;
    let proxy =
        crate::ConnectUdpProxy::new("https://proxy.example/udp/{target_host}/{target_port}/")?
            .with_http2_transport();
    let endpoint = proxy_endpoint(&proxy)?;
    let route = Route::connect_udp(proxy.clone());
    let changed = Route::connect_udp(proxy.clone().with_basic_auth("user", "changed")?);
    let token = tcp.prepare_connect_udp_outer(
        proxy.pool(),
        proxy.host(),
        proxy.port(),
        proxy.authority(),
        &[],
        None,
    )?;
    let cache = token.session_ticket_cache().ok_or("missing actual cache")?;
    assert!(cache.is_live());
    let owner = prepared_owner()?;
    owner.register_shared_outer_before_use(
        Some(cache.clone()),
        outer(&endpoint, &route, TicketCacheProtocol::Http2),
    )?;
    let original_binding = owner.registry().caches[0]
        .native_binding
        .as_ref()
        .map_err(|error| *error)?
        .clone();
    for _ in 0..32 {
        owner.register_shared_outer_before_use(
            Some(cache.clone()),
            outer(&endpoint, &changed, TicketCacheProtocol::Http2),
        )?;
        owner.register_shared_outer_before_use(
            Some(cache.clone()),
            outer(&endpoint, &route, TicketCacheProtocol::Http2),
        )?;
    }
    {
        let registry = owner.registry();
        assert_eq!(registry.caches.len(), 1);
        let registered = &registry.caches[0];
        assert!(matches!(
            registered.binding,
            Err(binding::PreparationError::Unsupported(
                "conflicting cache descriptors"
            ))
        ));
        assert!(matches!(
            registered.native_binding,
            Err(binding::PreparationError::Unsupported(
                "conflicting cache descriptors"
            ))
        ));
        assert!(registered.cache.is_live());
    }
    assert!(owner.export(&[1; 32]).is_err());
    // A changed native rebind would permanently revoke the installed scope.
    let frozen = btls::ssl::PreparedSessionPolicyFreeze::new(&[&original_binding])?.try_freeze()?;
    frozen.validate_binding(&original_binding, proxy.host())?;
    drop(frozen);
    assert_eq!(owner.clear()?, 0);
    assert_eq!(owner.registry().caches.len(), 1);
    Ok(())
}

#[tokio::test]
async fn unsupported_shared_outer_metadata_retains_clear_handles_across_pool_clear_without_growth()
-> TestResult {
    let tcp = tcp()?;
    let proxy =
        crate::ConnectUdpProxy::new("https://proxy.example/udp/{target_host}/{target_port}/")?
            .with_http2_transport();
    let endpoint = proxy_endpoint(&proxy)?;
    let route = Route::connect_udp(proxy.clone());
    let prepare = || {
        tcp.prepare_connect_udp_outer(
            proxy.pool(),
            proxy.host(),
            proxy.port(),
            proxy.authority(),
            &[],
            None,
        )
    };
    let owner = prepared_owner()?;
    owner.register_shared_outer_before_use(
        None,
        outer(&endpoint, &route, TicketCacheProtocol::Http2),
    )?;
    assert!(owner.registry().caches.is_empty());
    let old = prepare()?;
    for _ in 0..32 {
        let mut invalid = outer(&endpoint, &route, TicketCacheProtocol::Http2);
        invalid.protocol = Err(binding::PreparationError::Unsupported("test protocol"));
        let error = owner
            .register_shared_outer_before_use(old.session_ticket_cache(), invalid)
            .err()
            .ok_or("unsupported protocol accepted")?;
        assert!(matches!(
            error.0,
            super::super::transfer_import::ImportError::UnsupportedRoute
        ));
        owner.register_shared_outer_before_use(
            old.session_ticket_cache(),
            outer(&endpoint, &route, TicketCacheProtocol::Http2),
        )?;
    }
    assert_eq!(owner.registry().caches.len(), 1);
    assert!(owner.registry().caches[0].binding.is_err());
    proxy.pool().clear();
    let new = prepare()?;
    let old_cache = old
        .session_ticket_cache()
        .and_then(|cache| cache.upgrade())
        .ok_or("old cache absent")?;
    let new_cache = new
        .session_ticket_cache()
        .and_then(|cache| cache.upgrade())
        .ok_or("new cache absent")?;
    assert!(!old_cache.same_cache(&new_cache));
    drop(old_cache);
    drop(new_cache);
    owner.register_shared_outer_before_use(
        new.session_ticket_cache(),
        outer(&endpoint, &route, TicketCacheProtocol::Http2),
    )?;
    assert_eq!(owner.registry().caches.len(), 2);
    assert_eq!(owner.clear()?, 0);
    assert!(
        owner
            .registry()
            .caches
            .iter()
            .all(|cache| cache.cache.is_live())
    );
    assert!(owner.export(&[1; 32]).is_err());
    // The registry retains neither old token nor current pool slot strongly.
    proxy.pool().clear();
    drop(old);
    drop(new);
    assert_eq!(owner.clear()?, 0);
    assert!(owner.registry().caches.is_empty());
    Ok(())
}

#[test]
fn shared_outer_preparation_errors_preserve_categories_and_do_not_grant_retries() -> TestResult {
    let tcp = tcp()?;
    let pool = phantom_net::proxy::ConnectUdpProxyPool::new();
    let runtime = tcp
        .prepare_connect_udp_outer(&pool, "proxy.example", 443, "proxy.example", &[], None)
        .err()
        .ok_or("preparation unexpectedly accepted missing runtime")?;
    assert_eq!(runtime.kind(), ConnectUdpErrorKind::RuntimeUnavailable);
    let configuration = tcp
        .with_protocol(HttpsProxyProtocol::Http1)
        .prepare_connect_udp_outer(&pool, "proxy.example", 443, "proxy.example", &[], None)
        .err()
        .ok_or("shared HTTP/1 preparation unexpectedly accepted")?;
    assert_eq!(configuration.kind(), ConnectUdpErrorKind::Configuration);
    for (source, expected) in [
        (runtime, crate::RequestErrorKind::RuntimeUnavailable),
        (configuration, crate::RequestErrorKind::Proxy),
    ] {
        let error = crate::RequestError::http3_connect_udp_preparation(source);
        assert_eq!(error.kind(), expected);
        assert_eq!(error.protocol(), Some(crate::HttpProtocol::Http3));
        assert!(!error.is_retryable_connection_setup());
        assert!(!error.is_http3_setup_failure());
        assert!(
            std::error::Error::source(&error).is_some_and(|source| source.is::<ConnectUdpError>())
        );
        assert!(!error.to_string().contains("proxy.example"));
    }
    Ok(())
}
