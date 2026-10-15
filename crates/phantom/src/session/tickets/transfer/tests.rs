use std::sync::Arc;

use btls::ssl::{PreparedSessionPolicyFreeze, SslConnector, SslMethod};
use phantom_net::http1::Http1TlsConnector;
use phantom_profile::{ClientProfile, browser::chrome};

use super::*;
use crate::{authority::Endpoint, session::tickets::TicketCacheBinding};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const KEY: [u8; 32] = [11; 32];

fn origin(authority: &str) -> TestResult<Endpoint> {
    Ok(Endpoint::new(authority.parse()?, 443)?)
}

fn prepared(profile: &ClientProfile, roots: &[Box<[u8]>]) -> TestResult<TicketOwner> {
    let source = phantom_net::SourceBinding::new();
    let preparation = super::super::binding::BindingPlan::capture(profile)?
        .complete(profile)?
        .with_client_context(super::super::binding::TicketClientContext {
            origin_authentication: phantom_net::ServerAuthentication::WebPki,
            origin_roots: roots,
            proxy_authentication: phantom_net::ServerAuthentication::WebPki,
            proxy_roots: &[],
            default_certificate: None,
            certificate_origins: &[],
            source_binding: &source,
            http3_early_data: None,
        })?;
    Ok(TicketOwner::with_preparation(Ok(Arc::new(preparation))))
}

fn register(owner: &TicketOwner, connector: &Http1TlsConnector, endpoint: &Endpoint) {
    owner.register(
        connector.session_ticket_cache(),
        TicketCacheBinding {
            origin: endpoint,
            server_name: endpoint.host(),
            leg: TicketCacheLeg::Origin,
            protocol: Ok(TicketCacheProtocol::Http1),
            route: &Route::Direct,
        },
    );
}

fn empty_fixture() -> TestResult<(TicketOwner, Http1TlsConnector, Endpoint)> {
    let profile = chrome::v154_windows();
    let owner = prepared(&profile, &[])?;
    let connector = Http1TlsConnector::new(profile.tls())?.with_isolated_session_cache();
    let endpoint = origin("origin.example:443")?;
    register(&owner, &connector, &endpoint);
    Ok((owner, connector, endpoint))
}

#[test]
fn empty_live_owner_retains_authenticated_header_policy_witness_and_origin() -> TestResult {
    let (owner, _connector, endpoint) = empty_fixture()?;
    let sealed = owner.export_tcp(&KEY)?;
    let opened = envelope::open_manifest(sealed.as_bytes(), &KEY)?;
    assert_eq!(opened.owner_count(), 1);
    assert_eq!(opened.record_count(), 0);
    let incoming = opened.owners().next().ok_or("owner absent")??;
    assert_eq!(incoming.record_owner_index, incoming.index);
    assert_eq!(incoming.origin_authority, endpoint.authority().as_str());
    assert_eq!(incoming.origin_host, endpoint.host());
    assert_eq!(incoming.origin_port, endpoint.port());
    assert_eq!(incoming.server_name, endpoint.host());
    assert_eq!(incoming.header.record_count(), 0);
    assert_eq!(incoming.header.excluded_expired_count(), 0);
    assert_eq!(incoming.slots().len(), 0);
    let cache_registry = owner.registry();
    let registry = &cache_registry.caches;
    let registered = registry[0].binding.as_ref().map_err(|error| *error)?;
    assert_eq!(incoming.policy, registered.descriptor.policy());
    assert_eq!(
        incoming.source_witness,
        registered.descriptor.source_witness()
    );
    assert!(matches!(
        envelope::open_manifest(sealed.as_bytes(), &[12; 32]),
        Err(envelope::EnvelopeError::Authentication)
    ));
    let decoder = SslConnector::builder(SslMethod::tls())?.build();
    let verified = btls::ssl::open_envelope(opened.native_ciphertext(), &KEY, decoder.context())?;
    assert_eq!(verified.record_count(), 0);
    Ok(())
}

#[test]
fn many_exact_same_cache_aliases_export_one_owner_without_changing_registration() -> TestResult {
    let (owner, connector, endpoint) = empty_fixture()?;
    for _ in 0..MAX_OWNERS {
        register(&owner, &connector, &endpoint);
    }
    let sealed = owner.export_tcp(&KEY)?;
    assert_eq!(
        envelope::open_manifest(sealed.as_bytes(), &KEY)?.owner_count(),
        1
    );
    assert_eq!(owner.registry().caches.len(), MAX_OWNERS + 1);
    assert_eq!(owner.clear(), 0);
    Ok(())
}

#[test]
fn same_cache_changed_original_authority_is_rejected_without_retiring_its_policy() -> TestResult {
    let (owner, connector, endpoint) = empty_fixture()?;
    let omitted = origin("origin.example")?;
    register(&owner, &connector, &omitted);
    assert!(matches!(
        owner.export_tcp(&KEY),
        Err(TcpExportError::ConflictingOwner)
    ));
    assert!(
        owner
            .registry()
            .caches
            .iter()
            .all(|entry| entry.native_binding.is_ok())
    );
    let cache = connector
        .session_ticket_cache()
        .ok_or("cache absent")?
        .upgrade()
        .ok_or("cache dead")?;
    let captures = SessionTicketCacheOwner::capture_tcp_stores(&[(&cache, endpoint.host())])?;
    assert_eq!(captures.len(), 1);
    assert_eq!(captures[0].header().record_count(), 0);
    Ok(())
}

#[test]
fn distinct_stores_with_identical_logical_owner_are_rejected_before_capture() -> TestResult {
    let (owner, connector, endpoint) = empty_fixture()?;
    let second = connector.with_isolated_session_cache();
    register(&owner, &second, &endpoint);
    let binding = owner.registry().caches[0]
        .native_binding
        .as_ref()
        .map_err(|error| *error)?
        .clone();
    let frozen = PreparedSessionPolicyFreeze::new(&[&binding])?.try_freeze()?;
    assert!(matches!(
        owner.export_tcp(&KEY),
        Err(TcpExportError::ConflictingOwner)
    ));
    assert!(
        owner
            .registry()
            .caches
            .iter()
            .all(|entry| entry.native_binding.is_ok())
    );
    drop(frozen);
    assert_eq!(owner.clear(), 0);
    Ok(())
}

#[test]
fn unsupported_live_owner_rejects_the_whole_export_instead_of_a_direct_subset() -> TestResult {
    let (owner, connector, endpoint) = empty_fixture()?;
    let binding = owner.registry().caches[0]
        .native_binding
        .as_ref()
        .map_err(|error| *error)?
        .clone();
    let other = connector.with_isolated_session_cache();
    let route = Route::http_proxy(crate::HttpProxy::new("https://proxy.example")?);
    owner.register(
        other.session_ticket_cache(),
        TicketCacheBinding {
            origin: &endpoint,
            server_name: "proxy.example",
            leg: TicketCacheLeg::HttpProxy,
            protocol: Ok(TicketCacheProtocol::Http1),
            route: &route,
        },
    );
    let frozen = PreparedSessionPolicyFreeze::new(&[&binding])?.try_freeze()?;
    assert!(matches!(
        owner.export_tcp(&KEY),
        Err(TcpExportError::Preparation(PreparationError::Unsupported(
            "non-direct TCP transfer"
        )))
    ));
    drop(frozen);
    assert_eq!(owner.registry().caches.len(), 2);
    Ok(())
}

#[test]
fn missing_preparation_and_unbound_live_registration_fail_without_sealing() -> TestResult {
    let owner = TicketOwner::default();
    assert!(matches!(
        owner.export_tcp(&KEY),
        Err(TcpExportError::Preparation(_))
    ));
    let (owner, _connector, _) = empty_fixture()?;
    owner.registry().caches[0].native_binding =
        Err(PreparationError::Unsupported("unbound test registration"));
    assert!(matches!(
        owner.export_tcp(&KEY),
        Err(TcpExportError::Preparation(_))
    ));
    Ok(())
}

#[test]
fn dead_registration_is_not_exported_or_retained_by_the_snapshot() -> TestResult {
    let (owner, connector, _) = empty_fixture()?;
    drop(connector);
    let sealed = owner.export_tcp(&KEY)?;
    let opened = envelope::open_manifest(sealed.as_bytes(), &KEY)?;
    assert_eq!(opened.owner_count(), 0);
    assert_eq!(opened.record_count(), 0);
    assert_eq!(owner.registry().caches.len(), 1);
    assert!(!owner.registry().caches[0].cache.is_live());
    Ok(())
}

#[test]
fn a_busy_native_policy_fails_without_capture_and_releases_the_registry() -> TestResult {
    let (owner, _connector, _) = empty_fixture()?;
    let binding = owner.registry().caches[0]
        .native_binding
        .as_ref()
        .map_err(|error| *error)?
        .clone();
    let frozen = PreparedSessionPolicyFreeze::new(&[&binding])?.try_freeze()?;
    assert!(matches!(
        owner.export_tcp(&KEY),
        Err(TcpExportError::Native(SessionTransferError::Busy))
    ));
    assert_eq!(owner.registry().caches.len(), 1);
    drop(frozen);
    let sealed = owner.export_tcp(&KEY)?;
    assert_eq!(
        envelope::open_manifest(sealed.as_bytes(), &KEY)?.owner_count(),
        1
    );
    Ok(())
}

#[test]
fn poisoned_registry_fails_closed_instead_of_recovering_its_state() -> TestResult {
    let (owner, _connector, _) = empty_fixture()?;
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = owner
            .registry
            .lock()
            .unwrap_or_else(|error| panic!("registry already poisoned before control: {error}"));
        panic!("synthetic registry poisoning");
    }));
    assert!(panic.is_err());
    assert!(matches!(
        owner.export_tcp(&KEY),
        Err(TcpExportError::RegistryPoisoned)
    ));
    Ok(())
}

#[test]
fn more_than_256_distinct_owners_fail_before_capture() -> TestResult {
    let profile = chrome::v154_windows();
    let owner = prepared(&profile, &[])?;
    let base = Http1TlsConnector::new(profile.tls())?;
    let mut connectors = Vec::new();
    for index in 0..=MAX_OWNERS {
        let connector = base.with_isolated_session_cache();
        let endpoint = origin(&format!("owner{index}.example:443"))?;
        register(&owner, &connector, &endpoint);
        connectors.push(connector);
    }
    assert!(matches!(
        owner.export_tcp(&KEY),
        Err(TcpExportError::TooLarge)
    ));
    assert_eq!(owner.registry().caches.len(), MAX_OWNERS + 1);
    assert_eq!(owner.clear(), 0);
    Ok(())
}

#[test]
fn record_payload_binds_the_closed_format_and_exact_owner_index() {
    let payload = owner_payload(255);
    assert_eq!(payload.len(), 12);
    assert_eq!(&payload[..8], b"PHTOW001");
    assert_eq!(&payload[8..10], &[0, 1]);
    assert_eq!(&payload[10..], &255_u16.to_be_bytes());
}

mod peer;

mod bounds;
