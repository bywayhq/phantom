use std::sync::Arc;

use super::{TicketCacheBinding, TicketCacheLeg, TicketCacheProtocol, TicketOwner, binding};
use crate::{Route, authority::Endpoint};
use phantom_net::http1::Http1TlsConnector;
use phantom_profile::browser::chrome;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn origin() -> Result<Endpoint, Box<dyn std::error::Error>> {
    Ok(Endpoint::new("origin.example:443".parse()?, 443)?)
}

fn direct<'a>(origin: &'a Endpoint, route: &'a Route) -> TicketCacheBinding<'a> {
    TicketCacheBinding {
        origin,
        server_name: origin.host(),
        leg: TicketCacheLeg::Origin,
        protocol: Ok(TicketCacheProtocol::Http1),
        route,
    }
}

fn prepared_owner() -> Result<TicketOwner, Box<dyn std::error::Error>> {
    prepared_owner_for(&chrome::v154_windows())
}

fn prepared_owner_for(
    profile: &phantom_profile::ClientProfile,
) -> Result<TicketOwner, Box<dyn std::error::Error>> {
    let source = phantom_net::SourceBinding::new();
    let prepared = binding::BindingPlan::capture(profile)?
        .complete(profile)?
        .with_client_context(binding::TicketClientContext {
            origin_authentication: phantom_net::ServerAuthentication::WebPki,
            origin_roots: &[],
            proxy_authentication: phantom_net::ServerAuthentication::WebPki,
            proxy_roots: &[],
            default_certificate: None,
            certificate_origins: &[],
            source_binding: &source,
            http3_early_data: None,
        })?;
    Ok(TicketOwner::with_preparation(Ok(Arc::new(prepared))))
}

#[test]
fn dead_cache_controls_are_pruned_without_retaining_connectors() -> TestResult {
    let origin = origin()?;
    let route = Route::Direct;
    let base = Http1TlsConnector::new(&chrome::v154_tcp_tls())
        .unwrap_or_else(|error| panic!("test connector failed: {error}"));
    let owner = TicketOwner::default();
    for _ in 0..100 {
        let connector = base.with_isolated_session_cache();
        owner.register(connector.session_ticket_cache(), direct(&origin, &route));
    }
    assert_eq!(owner.registry().caches.len(), 1);
    assert_eq!(owner.clear()?, 0);
    assert!(owner.registry().caches.is_empty());
    let connector = base.with_isolated_session_cache();
    owner.register(connector.session_ticket_cache(), direct(&origin, &route));
    assert_eq!(owner.clear()?, 0);
    assert_eq!(owner.registry().caches.len(), 1);
    drop(connector);
    assert_eq!(owner.clear()?, 0);
    assert!(owner.registry().caches.is_empty());
    Ok(())
}

#[test]
fn repeated_controls_clear_one_store_without_locking_it_twice() -> TestResult {
    let origin = origin()?;
    let route = Route::Direct;
    let connector = Http1TlsConnector::new(&chrome::v154_tcp_tls())
        .unwrap_or_else(|error| panic!("test connector failed: {error}"))
        .with_isolated_session_cache();
    let owner = TicketOwner::default();
    let control = connector.session_ticket_cache();
    owner.register(control.clone(), direct(&origin, &route));
    owner.register(control, direct(&origin, &route));
    assert_eq!(owner.registry().caches.len(), 2);
    assert_eq!(owner.clear()?, 0);
    assert_eq!(owner.registry().caches.len(), 2);
    Ok(())
}

#[test]
fn ineligible_preparation_keeps_local_weak_registration_and_none_is_noop() -> TestResult {
    let origin = origin()?;
    let route = Route::Direct;
    let owner = TicketOwner::with_preparation(Err(binding::PreparationError::TooLarge));
    owner.register(None, direct(&origin, &route));
    assert!(owner.registry().caches.is_empty());
    let connector = Http1TlsConnector::new(&chrome::v154_tcp_tls())?.with_isolated_session_cache();
    owner.register(connector.session_ticket_cache(), direct(&origin, &route));
    {
        let cache_registry = owner.registry();
        let caches = &cache_registry.caches;
        assert_eq!(caches.len(), 1);
        assert!(matches!(
            caches[0].binding,
            Err(binding::PreparationError::TooLarge)
        ));
        assert!(caches[0].cache.is_live());
    }
    assert_eq!(owner.clear()?, 0);
    assert_eq!(owner.registry().caches.len(), 1);
    drop(connector);
    assert_eq!(owner.clear()?, 0);
    assert!(owner.registry().caches.is_empty());
    Ok(())
}

#[test]
fn equal_duplicate_metadata_stays_eligible_and_conflicts_mark_every_copy() -> TestResult {
    let origin = origin()?;
    let route = Route::Direct;
    let connector = Http1TlsConnector::new(&chrome::v154_tcp_tls())?.with_isolated_session_cache();
    let unrelated = connector.with_isolated_session_cache();
    let owner = prepared_owner()?;
    owner.register(connector.session_ticket_cache(), direct(&origin, &route));
    owner.register(connector.session_ticket_cache(), direct(&origin, &route));
    owner.register(unrelated.session_ticket_cache(), direct(&origin, &route));
    {
        let cache_registry = owner.registry();
        let caches = &cache_registry.caches;
        assert_eq!(caches.len(), 3);
        assert!(caches.iter().all(|cache| cache.binding.is_ok()));
        assert!(caches.iter().all(|cache| cache.native_binding.is_ok()));
    }
    let mut conflicting = direct(&origin, &route);
    conflicting.server_name = "different-peer.example";
    owner.register(connector.session_ticket_cache(), conflicting);
    {
        let cache_registry = owner.registry();
        let caches = &cache_registry.caches;
        assert_eq!(caches.len(), 4);
        for position in [0, 1, 3] {
            assert!(matches!(
                caches[position].binding,
                Err(binding::PreparationError::Unsupported(
                    "conflicting cache descriptors"
                ))
            ));
        }
        assert!(caches[2].binding.is_ok());
    }
    assert_eq!(owner.clear()?, 0);
    assert_eq!(owner.registry().caches.len(), 4);
    Ok(())
}

#[test]
fn registration_retains_logical_origin_actual_peer_leg_protocol_and_route() -> TestResult {
    let origin = origin()?;
    let direct_route = Route::Direct;
    let proxy_route = Route::http_proxy(crate::HttpProxy::new("https://proxy.example")?);
    let base = Http1TlsConnector::new(&chrome::v154_tcp_tls())?;
    let connectors: Vec<_> = (0..4).map(|_| base.with_isolated_session_cache()).collect();
    let owner = prepared_owner()?;
    owner.register(
        connectors[0].session_ticket_cache(),
        direct(&origin, &direct_route),
    );
    let mut peer = direct(&origin, &direct_route);
    peer.server_name = "different-peer.example";
    owner.register(connectors[1].session_ticket_cache(), peer);
    let mut protocol = direct(&origin, &direct_route);
    protocol.protocol = Ok(TicketCacheProtocol::Negotiated);
    owner.register(connectors[2].session_ticket_cache(), protocol);
    owner.register(
        connectors[3].session_ticket_cache(),
        TicketCacheBinding {
            origin: &origin,
            server_name: "proxy.example",
            leg: TicketCacheLeg::HttpProxy,
            protocol: TicketCacheBinding::proxy_protocol(
                phantom_net::proxy::HttpsProxyProtocol::Http2,
            ),
            route: &proxy_route,
        },
    );
    let cache_registry = owner.registry();
    let caches = &cache_registry.caches;
    let first = caches[0]
        .binding
        .as_ref()
        .map_err(|_| "origin binding ineligible")?;
    for cache in &caches[1..] {
        assert!(
            first.descriptor
                != cache
                    .binding
                    .as_ref()
                    .map_err(|_| "binding ineligible")?
                    .descriptor
        );
    }
    let proxy = caches[3]
        .binding
        .as_ref()
        .map_err(|_| "proxy binding ineligible")?;
    assert_eq!(proxy.origin, origin);
    assert_eq!(proxy.server_name, "proxy.example");
    assert!(proxy.leg == TicketCacheLeg::HttpProxy);
    assert!(proxy.protocol == TicketCacheProtocol::Http2);
    assert_eq!(proxy.route, proxy_route);
    Ok(())
}

#[test]
fn owned_credentials_keep_policy_equal_across_independent_clients() -> TestResult {
    let origin = origin()?;
    let route = Route::http_proxy(
        crate::HttpProxy::new("https://proxy.example")?
            .with_digest_auth("synthetic-user", "synthetic-password")?,
    );
    let connector = Http1TlsConnector::new(&chrome::v154_tcp_tls())?.with_isolated_session_cache();
    let owner = prepared_owner()?;
    let recipient = prepared_owner()?;
    let recipient_connector = connector.with_isolated_session_cache();
    let input = || TicketCacheBinding {
        origin: &origin,
        server_name: "proxy.example",
        leg: TicketCacheLeg::HttpProxy,
        protocol: Ok(TicketCacheProtocol::Http1),
        route: &route,
    };
    owner.register(connector.session_ticket_cache(), input());
    recipient.register(recipient_connector.session_ticket_cache(), input());
    let cache_registry = owner.registry();
    let caches = &cache_registry.caches;
    let binding = caches[0]
        .binding
        .as_ref()
        .map_err(|_| "binding ineligible")?;
    let source = owner
        .preparation
        .as_ref()
        .ok_or("missing policy")?
        .as_ref()
        .map_err(|_| "ineligible policy")?;
    let recipient = recipient
        .preparation
        .as_ref()
        .ok_or("missing policy")?
        .as_ref()
        .map_err(|_| "ineligible policy")?;
    let recompute = |prepared: &binding::PreparedTicketPolicy| {
        prepared.prepare_cache_descriptor(
            &binding.origin,
            &binding.server_name,
            binding.leg,
            binding.protocol,
            &binding.route,
        )
    };
    let source_policy = recompute(source)?;
    assert!(source_policy == recompute(recipient)?);
    assert!(crate::route::transfer_credential(&binding.route)?.is_some());
    Ok(())
}

#[test]
fn direct_http1_http2_and_negotiated_caches_install_native_bindings() -> TestResult {
    let profile = chrome::v154_windows();
    let http2 = profile.http2().ok_or("missing HTTP/2 settings")?;
    let h1 = Http1TlsConnector::new(profile.tls())?.with_isolated_session_cache();
    let h2 = phantom_net::http2::Http2TlsConnector::new(profile.tls(), http2)?
        .with_isolated_session_cache();
    let negotiated = phantom_net::http1_or_2::Http1Or2TlsConnector::new(profile.tls(), http2)?
        .with_isolated_session_cache();
    let owner = prepared_owner_for(&profile)?;
    let origin = origin()?;
    let route = Route::Direct;
    for (cache, protocol) in [
        (h1.session_ticket_cache(), TicketCacheProtocol::Http1),
        (h2.session_ticket_cache(), TicketCacheProtocol::Http2),
        (
            negotiated.session_ticket_cache(),
            TicketCacheProtocol::Negotiated,
        ),
    ] {
        let mut input = direct(&origin, &route);
        input.protocol = Ok(protocol);
        owner.register(cache, input);
    }
    let cache_registry = owner.registry();
    let caches = &cache_registry.caches;
    assert_eq!(caches.len(), 3);
    assert!(caches.iter().all(|cache| cache.binding.is_ok()));
    assert!(caches.iter().all(|cache| cache.native_binding.is_ok()));
    Ok(())
}

#[cfg(feature = "websocket")]
#[test]
fn websocket_derived_connectors_reuse_the_negotiated_registration() -> TestResult {
    let profile = chrome::v154_windows();
    let connector = phantom_net::http1_or_2::Http1Or2TlsConnector::new(
        profile.tls(),
        profile.http2().ok_or("missing HTTP/2 settings")?,
    )?
    .with_isolated_session_cache();
    let websocket = profile.websocket().ok_or("missing WebSocket settings")?;
    let settings = websocket.connection.http1_tls_settings(profile.tls());
    let h1 = connector.http1_connector(&settings.alpn_protocols)?;
    let h2 = connector.http2_connector();
    let owner = prepared_owner_for(&profile)?;
    let origin = origin()?;
    let route = Route::Direct;
    for cache in [
        connector.session_ticket_cache(),
        h1.session_ticket_cache(),
        h2.session_ticket_cache(),
    ] {
        let mut input = direct(&origin, &route);
        input.protocol = Ok(TicketCacheProtocol::Negotiated);
        owner.register(cache, input);
    }
    let cache_registry = owner.registry();
    let caches = &cache_registry.caches;
    assert_eq!(caches.len(), 3);
    assert!(caches.iter().all(|cache| cache.native_binding.is_ok()));
    let first = caches[0].cache.upgrade().ok_or("missing cache")?;
    assert!(caches.iter().all(|cache| {
        cache
            .cache
            .upgrade()
            .is_some_and(|other| first.same_cache(&other))
    }));
    Ok(())
}

#[test]
fn descriptor_conflict_does_not_rebind_or_revoke_the_original_native_scope() -> TestResult {
    let origin = origin()?;
    let route = Route::Direct;
    let connector = Http1TlsConnector::new(&chrome::v154_tcp_tls())?.with_isolated_session_cache();
    let owner = prepared_owner()?;
    let native = connector
        .session_ticket_cache()
        .ok_or("missing cache")?
        .upgrade()
        .ok_or("dead cache")?;
    let prepared = owner
        .preparation
        .as_ref()
        .ok_or("missing preparation")?
        .as_ref()
        .map_err(|e| *e)?;
    let descriptor = prepared.prepare_cache_descriptor(
        &origin,
        origin.host(),
        TicketCacheLeg::Origin,
        TicketCacheProtocol::Http1,
        &route,
    )?;
    owner.register(connector.session_ticket_cache(), direct(&origin, &route));
    let mut conflict = direct(&origin, &route);
    conflict.server_name = "different-peer.example";
    owner.register(connector.session_ticket_cache(), conflict);
    owner.register(connector.session_ticket_cache(), direct(&origin, &route));
    {
        let cache_registry = owner.registry();
        let caches = &cache_registry.caches;
        assert_eq!(caches.len(), 3);
        assert!(
            caches
                .iter()
                .all(|cache| cache.binding.is_err() && cache.native_binding.is_err())
        );
    }
    // A conflicting native rebind would permanently retire this scope.
    prepared.bind_direct_tcp_transfer_policy(
        &native,
        &descriptor,
        origin.host(),
        TicketCacheLeg::Origin,
        TicketCacheProtocol::Http1,
        &route,
    )?;
    Ok(())
}

#[test]
fn proxy_legs_and_http3_metadata_do_not_install_tcp_transfer_policy() -> TestResult {
    let origin = origin()?;
    let direct_route = Route::Direct;
    let proxy_route = Route::http_proxy(crate::HttpProxy::new("https://proxy.example")?);
    let base = Http1TlsConnector::new(&chrome::v154_tcp_tls())?;
    for (route, leg, protocol) in [
        (
            &proxy_route,
            TicketCacheLeg::Origin,
            TicketCacheProtocol::Http1,
        ),
        (
            &proxy_route,
            TicketCacheLeg::HttpProxy,
            TicketCacheProtocol::Http2,
        ),
        (
            &direct_route,
            TicketCacheLeg::ConnectUdp,
            TicketCacheProtocol::Http2,
        ),
        (
            &direct_route,
            TicketCacheLeg::Origin,
            TicketCacheProtocol::Http3,
        ),
    ] {
        let connector = base.with_isolated_session_cache();
        let owner = prepared_owner()?;
        let mut input = direct(&origin, route);
        input.leg = leg;
        input.protocol = Ok(protocol);
        owner.register(connector.session_ticket_cache(), input);
        {
            let cache_registry = owner.registry();
            let caches = &cache_registry.caches;
            assert!(caches[0].binding.is_ok());
            assert!(matches!(
                caches[0].native_binding,
                Err(binding::PreparationError::Unsupported(
                    "non-direct TCP transfer"
                ))
            ));
        }
        let native = connector
            .session_ticket_cache()
            .ok_or("missing cache")?
            .upgrade()
            .ok_or("dead cache")?;
        let prepared = owner
            .preparation
            .as_ref()
            .ok_or("missing preparation")?
            .as_ref()
            .map_err(|e| *e)?;
        let descriptor = prepared.prepare_cache_descriptor(
            &origin,
            origin.host(),
            TicketCacheLeg::Origin,
            TicketCacheProtocol::Http1,
            &direct_route,
        )?;
        prepared.bind_direct_tcp_transfer_policy(
            &native,
            &descriptor,
            origin.host(),
            TicketCacheLeg::Origin,
            TicketCacheProtocol::Http1,
            &direct_route,
        )?;
        assert_eq!(owner.clear()?, 0);
    }
    Ok(())
}

#[test]
fn native_rejection_is_explicit_even_when_descriptor_preparation_succeeds() -> TestResult {
    let origin = origin()?;
    let route = Route::Direct;
    let connector = Http1TlsConnector::new(&chrome::v154_tcp_tls())?.with_isolated_session_cache();
    let owner = prepared_owner()?;
    let mut input = direct(&origin, &route);
    input.server_name = "";
    owner.register(connector.session_ticket_cache(), input);
    let cache_registry = owner.registry();
    let caches = &cache_registry.caches;
    assert!(caches[0].binding.is_ok());
    assert!(matches!(
        caches[0].native_binding,
        Err(binding::PreparationError::Unsupported(
            "native TCP transfer policy"
        ))
    ));
    Ok(())
}

#[test]
fn native_binding_registration_does_not_keep_an_evicted_cache_alive() -> TestResult {
    let origin = origin()?;
    let route = Route::Direct;
    let connector = Http1TlsConnector::new(&chrome::v154_tcp_tls())?.with_isolated_session_cache();
    let owner = prepared_owner()?;
    owner.register(connector.session_ticket_cache(), direct(&origin, &route));
    assert!(owner.registry().caches[0].native_binding.is_ok());
    drop(connector);
    assert_eq!(owner.clear()?, 0);
    assert!(owner.registry().caches.is_empty());
    Ok(())
}

#[test]
fn same_cache_changed_credentials_conflict_before_rebinding_a_live_native_scope() -> TestResult {
    let origin = origin()?;
    let connector = Http1TlsConnector::new(&chrome::v154_tcp_tls())?.with_isolated_session_cache();
    let cache = connector.session_ticket_cache().ok_or("missing cache")?;
    let native = cache.upgrade().ok_or("dead cache")?;
    let policy = || {
        btls::ssl::SessionTransferPolicy::new(b"known live native policy", &[0, 0], None, &[7; 32])
    };
    native.bind_tcp_transfer_policy("proxy.example", policy()?)?;
    let owner = prepared_owner()?;
    let route = Route::http_proxy(
        crate::HttpProxy::new("https://proxy.example")?.with_basic_auth("user", "password")?,
    );
    let changed = Route::http_proxy(
        crate::HttpProxy::new("https://proxy.example")?.with_basic_auth("user", "changed")?,
    );
    let input = |route| TicketCacheBinding {
        origin: &origin,
        server_name: "proxy.example",
        leg: TicketCacheLeg::HttpProxy,
        protocol: Ok(TicketCacheProtocol::Http1),
        route,
    };
    owner.register(Some(cache.clone()), input(&route));
    let same_route = route.clone();
    owner.register(Some(cache.clone()), input(&same_route));
    {
        let cache_registry = owner.registry();
        let caches = &cache_registry.caches;
        assert!(caches.iter().all(|cache| cache.binding.is_ok()));
        assert!(caches.iter().all(|cache| matches!(
            cache.native_binding,
            Err(binding::PreparationError::Unsupported(
                "non-direct TCP transfer"
            ))
        )));
    }
    owner.register(Some(cache), input(&changed));
    let cache_registry = owner.registry();
    let caches = &cache_registry.caches;
    assert_eq!(caches.len(), 3);
    assert!(caches.iter().all(|cache| matches!(
        cache.binding,
        Err(binding::PreparationError::Unsupported(
            "conflicting cache descriptors"
        ))
    )));
    assert!(caches.iter().all(|cache| matches!(
        cache.native_binding,
        Err(binding::PreparationError::Unsupported(
            "conflicting cache descriptors"
        ))
    )));
    native.bind_tcp_transfer_policy("proxy.example", policy()?)?;
    Ok(())
}

mod shared_outer;
