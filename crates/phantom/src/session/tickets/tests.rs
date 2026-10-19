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
            origin_pins: None,
            proxy_authentication: phantom_net::ServerAuthentication::WebPki,
            proxy_roots: &[],
            proxy_pins: None,
            default_certificate: None,
            certificate_origins: &[],
            source_binding: &source,
            http3_early_data: None,
        })?;
    Ok(TicketOwner::with_preparation(Ok(Arc::new(prepared))))
}

#[test]
fn shared_custody_seeds_existing_stores_and_bounds_later_registrations() -> TestResult {
    let owner = prepared_owner()?;
    let base = Http1TlsConnector::new(&chrome::v154_tcp_tls())?;
    let mut controls = Vec::new();
    for index in 0..4 {
        let endpoint = Endpoint::new(format!("host{index}.example:443").parse()?, 443)?;
        let connector = base.with_isolated_session_cache();
        let cache = connector.session_ticket_cache().ok_or("missing cache")?;
        owner.register_before_use(Some(cache.clone()), direct(&endpoint, &Route::Direct))?;
        if index == 0 {
            owner.enable_sharing(2);
        }
        drop(connector);
        assert!(cache.is_live());
        controls.push(cache);
        if index == 1 {
            assert!(controls[0].is_live());
        } else if index == 2 {
            assert!(!controls[0].is_live());
            let endpoint = Endpoint::new("host1.example:443".parse()?, 443)?;
            owner.select_store(Some(controls[1].clone()), direct(&endpoint, &Route::Direct))?;
        }
    }
    assert!(controls[1].is_live());
    assert!(!controls[2].is_live());
    assert!(controls[3].is_live());
    drop(owner);
    assert!(controls.iter().all(|cache| !cache.is_live()));
    Ok(())
}

#[test]
fn sharing_selects_one_actual_store_concurrently_and_preserves_legacy_controls() -> TestResult {
    let owner = Arc::new(prepared_owner()?);
    let endpoint = origin()?;
    let base = Http1TlsConnector::new(&chrome::v154_tcp_tls())?;
    let legacy = base.with_isolated_session_cache();
    owner.register(
        legacy.session_ticket_cache(),
        direct(&endpoint, &Route::Direct),
    );
    owner.enable_sharing(16);
    let expected = legacy
        .session_ticket_cache()
        .and_then(|cache| cache.upgrade())
        .ok_or("legacy cache absent")?;
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let owner = Arc::clone(&owner);
        let barrier = Arc::clone(&barrier);
        let endpoint = endpoint.clone();
        let connector = base.with_isolated_session_cache();
        tasks.push(std::thread::spawn(move || {
            barrier.wait();
            owner.select_store(
                connector.session_ticket_cache(),
                direct(&endpoint, &Route::Direct),
            )
        }));
    }
    for task in tasks {
        let selected = task
            .join()
            .map_err(|_| "selection thread panicked")??
            .ok_or("cache absent")?;
        assert!(selected.same_cache(&expected));
    }
    assert_eq!(owner.registry().caches.len(), 1);
    Ok(())
}

#[test]
fn live_selection_does_not_require_portable_transfer_support() -> TestResult {
    let owner = TicketOwner::with_preparation(Err(binding::PreparationError::Unsupported(
        "custom TCP connector identity",
    )));
    owner.enable_sharing(16);
    let base = Http1TlsConnector::new(&chrome::v154_tcp_tls())?;
    let one = super::TicketConnector::default();
    let two = super::TicketConnector::default();
    let endpoint = origin()?;
    let input = direct(&endpoint, &Route::Direct);
    let first = one.get_or_init(|| base.with_isolated_session_cache());
    let first = one.prepare(&owner, first, input)?;
    owner.register_before_use(first.session_ticket_cache(), input)?;
    let second = two.get_or_init(|| base.with_isolated_session_cache());
    let second = two.prepare(&owner, second, input)?;
    owner.register_before_use(second.session_ticket_cache(), input)?;
    let first = first
        .session_ticket_cache()
        .and_then(|cache| cache.upgrade())
        .ok_or("first cache absent")?;
    let second = second
        .session_ticket_cache()
        .and_then(|cache| cache.upgrade())
        .ok_or("second cache absent")?;
    assert!(first.same_cache(&second));
    assert!(matches!(
        owner.export(&[5; 32]),
        Err(super::transfer::ExportError::Preparation(
            binding::PreparationError::Unsupported(_)
        ))
    ));
    Ok(())
}

#[test]
fn sharing_converges_existing_cells_but_keeps_route_credentials_and_protocols_separate()
-> TestResult {
    let owner = prepared_owner()?;
    let endpoint = origin()?;
    let base = Http1TlsConnector::new(&chrome::v154_tcp_tls())?;
    let first = super::TicketConnector::default();
    let second = super::TicketConnector::default();
    let one = first.get_or_init(|| base.with_isolated_session_cache());
    let two = second.get_or_init(|| base.with_isolated_session_cache());
    let direct = direct(&endpoint, &Route::Direct);
    owner.register_before_use(one.session_ticket_cache(), direct)?;
    owner.register_before_use(two.session_ticket_cache(), direct)?;
    let legacy = two
        .session_ticket_cache()
        .and_then(|cache| cache.upgrade())
        .ok_or("legacy absent")?;
    owner.enable_sharing(16);
    let canonical = first
        .prepare(&owner, one, direct)?
        .session_ticket_cache()
        .and_then(|cache| cache.upgrade())
        .ok_or("canonical absent")?;
    let selected = second
        .prepare(&owner, two, direct)?
        .session_ticket_cache()
        .and_then(|cache| cache.upgrade())
        .ok_or("selected absent")?;
    assert!(canonical.same_cache(&selected));
    assert!(!legacy.same_cache(&selected));
    let proxy_one = Route::http_proxy(
        crate::HttpProxy::new("http://proxy.example")?.with_basic_auth("one", "secret")?,
    );
    let proxy_two = Route::http_proxy(
        crate::HttpProxy::new("http://proxy.example")?.with_basic_auth("two", "secret")?,
    );
    let mut retained = Vec::new();
    for (protocol, route) in [
        (TicketCacheProtocol::Http1, &proxy_one),
        (TicketCacheProtocol::Http1, &proxy_two),
        (TicketCacheProtocol::Http2, &Route::Direct),
    ] {
        let connector = base.with_isolated_session_cache();
        let input = TicketCacheBinding {
            protocol: Ok(protocol),
            route,
            ..direct
        };
        let selected = owner
            .select_store(connector.session_ticket_cache(), input)?
            .ok_or("store absent")?;
        assert!(!canonical.same_cache(&selected));
        assert!(
            retained
                .iter()
                .all(|other: &phantom_net::SessionTicketCacheOwner| !other.same_cache(&selected))
        );
        retained.push(selected);
    }
    let unrelated = Http1TlsConnector::new(&chrome::v154_tcp_tls())?;
    let cell = super::TicketConnector::default();
    let ordinary = cell.get_or_init(|| unrelated.with_isolated_session_cache());
    assert!(
        cell.prepare(&owner, ordinary, direct).is_err(),
        "unrelated native configuration attached"
    );
    Ok(())
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
            binding
                .route
                .ordinary()
                .ok_or(binding::PreparationError::Unsupported(
                    "ordinary route missing",
                ))?,
        )
    };
    let source_policy = recompute(source)?;
    assert!(source_policy == recompute(recipient)?);
    assert!(binding.route.credential()?.is_some());
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
    prepared.bind_transfer_policy(
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
fn proxy_legs_and_http3_install_native_policy_on_actual_matching_cache_kinds() -> TestResult {
    let origin = origin()?;
    let direct_route = Route::Direct;
    let proxy_route = Route::http_proxy(crate::HttpProxy::new("https://proxy.example")?);
    let profile = chrome::v154_windows();
    let h1 = Http1TlsConnector::new(profile.tls())?.with_isolated_session_cache();
    let h2 = phantom_net::http2::Http2TlsConnector::new(
        profile.tls(),
        profile.http2().ok_or("H2 settings missing")?,
    )?
    .with_isolated_session_cache();
    let h3_settings = profile.http3().ok_or("H3 settings missing")?;
    let h3 = phantom_net::http3::Http3Connector::new(
        h3_settings.tls(),
        h3_settings.quic_transport(),
        h3_settings.http3(),
        h3_settings.request(),
    )?
    .with_isolated_session_cache();
    for (cache, route, leg, protocol) in [
        (
            h1.session_ticket_cache(),
            &proxy_route,
            TicketCacheLeg::Origin,
            TicketCacheProtocol::Http1,
        ),
        (
            h2.session_ticket_cache(),
            &proxy_route,
            TicketCacheLeg::HttpProxy,
            TicketCacheProtocol::Http2,
        ),
        (
            h3.session_ticket_cache(),
            &direct_route,
            TicketCacheLeg::Origin,
            TicketCacheProtocol::Http3,
        ),
    ] {
        let owner = prepared_owner_for(&profile)?;
        let mut input = direct(&origin, route);
        input.leg = leg;
        input.protocol = Ok(protocol);
        if leg == TicketCacheLeg::HttpProxy {
            input.server_name = "proxy.example";
        }
        owner.register(cache, input);
        let binding = {
            let registry = owner.registry();
            assert_eq!(registry.caches.len(), 1);
            assert!(registry.caches[0].binding.is_ok());
            registry.caches[0]
                .native_binding
                .as_ref()
                .map_err(|error| *error)?
                .clone()
        };
        let frozen = btls::ssl::PreparedSessionPolicyFreeze::new(&[&binding])?.try_freeze()?;
        frozen.validate_binding(
            &binding,
            if leg == TicketCacheLeg::HttpProxy {
                "proxy.example"
            } else {
                origin.host()
            },
        )?;
        drop(frozen);
        assert_eq!(owner.clear()?, 0);
    }
    Ok(())
}

#[test]
fn invalid_route_leg_does_not_install_or_revoke_a_tcp_transfer_scope() -> TestResult {
    let origin = origin()?;
    let route = Route::Direct;
    let connector = Http1TlsConnector::new(&chrome::v154_tcp_tls())?.with_isolated_session_cache();
    let owner = prepared_owner()?;
    let mut input = direct(&origin, &route);
    input.leg = TicketCacheLeg::ConnectUdp;
    input.protocol = Ok(TicketCacheProtocol::Http2);
    owner.register(connector.session_ticket_cache(), input);
    assert!(owner.registry().caches[0].binding.is_ok());
    assert!(matches!(
        owner.registry().caches[0].native_binding,
        Err(binding::PreparationError::Unsupported(
            "ticket route and protocol"
        ))
    ));
    let native = connector
        .session_ticket_cache()
        .and_then(|cache| cache.upgrade())
        .ok_or("actual cache missing")?;
    let prepared = owner
        .preparation
        .as_ref()
        .ok_or("missing preparation")?
        .as_ref()
        .map_err(|error| *error)?;
    let descriptor = prepared.prepare_cache_descriptor(
        &origin,
        origin.host(),
        TicketCacheLeg::Origin,
        TicketCacheProtocol::Http1,
        &route,
    )?;
    prepared.bind_transfer_policy(
        &native,
        &descriptor,
        origin.host(),
        TicketCacheLeg::Origin,
        TicketCacheProtocol::Http1,
        &route,
    )?;
    assert_eq!(owner.clear()?, 0);
    Ok(())
}

#[test]
fn tcp_cache_labeled_http3_rejects_export_instead_of_claiming_quic_support() -> TestResult {
    let origin = origin()?;
    let route = Route::Direct;
    let connector = Http1TlsConnector::new(&chrome::v154_tcp_tls())?.with_isolated_session_cache();
    let owner = prepared_owner()?;
    let mut input = direct(&origin, &route);
    input.protocol = Ok(TicketCacheProtocol::Http3);
    owner.register(connector.session_ticket_cache(), input);
    assert!(owner.registry().caches[0].binding.is_ok());
    assert!(matches!(
        owner.export(&[1; 32]),
        Err(super::transfer::ExportError::Envelope(
            super::envelope::EnvelopeError::UnsupportedProtocol
        ))
    ));
    assert_eq!(owner.clear()?, 0);
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
            "native ticket transfer policy"
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
    assert!(cache.is_live());
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
    let original_binding = owner.registry().caches[0]
        .native_binding
        .as_ref()
        .map_err(|error| *error)?
        .clone();
    let same_route = route.clone();
    owner.register(Some(cache.clone()), input(&same_route));
    {
        let cache_registry = owner.registry();
        let caches = &cache_registry.caches;
        assert!(caches.iter().all(|cache| cache.binding.is_ok()));
        assert!(caches.iter().all(|cache| cache.native_binding.is_ok()));
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
    drop(cache_registry);
    let frozen = btls::ssl::PreparedSessionPolicyFreeze::new(&[&original_binding])?.try_freeze()?;
    frozen.validate_binding(&original_binding, "proxy.example")?;
    drop(frozen);
    Ok(())
}

mod shared_outer;
