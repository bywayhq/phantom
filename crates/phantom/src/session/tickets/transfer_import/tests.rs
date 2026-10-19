use std::{net::Ipv4Addr, pin::Pin, sync::Arc, time::Duration};

use btls::ssl::{Ssl, SslAcceptor, SslContextBuilder, SslMethod, SslVersion};
use phantom_net::{
    ServerAuthentication, SourceBinding, TcpSessionStoreHeader, http1::Http1TlsConnector,
};
use phantom_profile::{ClientProfile, EchSettings, TlsVersion, TlsVersionRange, browser::chrome};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_btls::SslStream;

use super::*;
use crate::{
    authority::Endpoint,
    session::tickets::{
        TicketCacheBinding,
        binding::{BindingPlan, TicketClientContext},
        envelope::{OwnerInput, RecordSlot},
    },
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const KEY: [u8; 32] = [7; 32];
const NAME: &str = "127.0.0.1";
const DEADLINE: Duration = Duration::from_secs(15);

#[test]
fn legacy_stores_remain_explicitly_unsupported_for_portable_sharing() -> TestResult {
    let profile = profile(TlsVersion::Tls13);
    let owner = owner(&profile, &[])?;
    let endpoint = Endpoint::new("127.0.0.1:443".parse()?, 443)?;
    let base = Http1TlsConnector::new(profile.tls())?;
    let first = base.with_isolated_session_cache();
    let second = base.with_isolated_session_cache();
    register(&owner, &first, &endpoint, &Route::Direct);
    let snapshot = empty_snapshot(&owner, header(0)?)?;
    register(&owner, &second, &endpoint, &Route::Direct);
    owner.enable_sharing(16);
    let export_error = owner
        .export(&KEY)
        .err()
        .ok_or("ambiguous export succeeded")?;
    assert!(matches!(
        export_error,
        super::super::transfer::ExportError::AmbiguousSharing
    ));
    assert_eq!(
        super::super::SessionTicketError::with_source(export_error).kind(),
        super::super::SessionTicketErrorKind::Unsupported
    );
    let decoding = decoding_context()?;
    let import_error = owner
        .import_tcp(&snapshot, &KEY, &decoding)
        .err()
        .ok_or("ambiguous import succeeded")?;
    assert!(matches!(import_error, ImportError::AmbiguousSharing));
    assert_eq!(
        super::super::SessionTicketError::with_source(import_error).kind(),
        super::super::SessionTicketErrorKind::Unsupported
    );
    assert_eq!(owner.registry().caches.len(), 2);
    assert_eq!(owner.clear()?, 0);
    assert_eq!(owner.registry().caches.len(), 2);
    Ok(())
}

fn profile(version: TlsVersion) -> ClientProfile {
    let mut tls = chrome::v154_tcp_tls();
    tls.versions = TlsVersionRange::only(version);
    tls.alps = None;
    tls.ech = EchSettings::Disabled;
    tls.requested_trust_anchor_ids = None;
    if version == TlsVersion::Tls12 {
        tls.key_shares.clear();
        tls.certificate_compression.clear();
    }
    ClientProfile::new(tls)
}

fn owner(profile: &ClientProfile, roots: &[Box<[u8]>]) -> TestResult<TicketOwner> {
    let source = SourceBinding::new();
    let preparation = BindingPlan::capture(profile)?
        .complete(profile)?
        .with_client_context(TicketClientContext {
            origin_authentication: ServerAuthentication::WebPki,
            origin_roots: roots,
            origin_pins: None,
            proxy_authentication: ServerAuthentication::WebPki,
            proxy_roots: &[],
            proxy_pins: None,
            default_certificate: None,
            certificate_origins: &[],
            source_binding: &source,
            http3_early_data: None,
        })?;
    Ok(TicketOwner::with_preparation(Ok(Arc::new(preparation))))
}

fn register(
    owner: &TicketOwner,
    connector: &Http1TlsConnector,
    endpoint: &Endpoint,
    route: &Route,
) {
    owner.register(
        connector.session_ticket_cache(),
        TicketCacheBinding {
            origin: endpoint,
            server_name: NAME,
            leg: TicketCacheLeg::Origin,
            protocol: Ok(TicketCacheProtocol::Http1),
            route,
        },
    );
}

fn header(records: u8) -> TestResult<TcpSessionStoreHeader> {
    let mut bytes = [0; 22];
    bytes[..8].copy_from_slice(b"PHTCP001");
    bytes[9] = 1;
    bytes[11] = 2;
    bytes[12] = records;
    bytes[13] = records;
    bytes[21] = u8::from(records != 0);
    Ok(TcpSessionStoreHeader::parse(&bytes)?)
}

fn empty_snapshot(owner: &TicketOwner, header: TcpSessionStoreHeader) -> TestResult<Vec<u8>> {
    let cache_registry = owner.registry();
    let registrations = &cache_registry.caches;
    let binding = registrations[0].binding.as_ref().map_err(|error| *error)?;
    let input = OwnerInput {
        record_owner_index: 0,
        origin: &binding.origin,
        server_name: &binding.server_name,
        leg: binding.leg,
        protocol: binding.protocol,
        policy: binding.descriptor.policy(),
        source_witness: binding.descriptor.source_witness(),
        has_credentials: false,
        header: SessionTicketStoreHeader::Tcp(header),
        slots: &[],
    };
    let native = btls::ssl::seal_envelope(&[], &KEY)?;
    Ok(envelope::seal_manifest(&KEY, &[input], &native)?
        .as_bytes()
        .to_vec())
}

fn decoding_context() -> TestResult<btls::ssl::SslContext> {
    Ok(SslContextBuilder::new(SslMethod::tls())?.build())
}

#[test]
fn zero_owner_noop_authenticates_even_without_recipient_preparation() -> TestResult {
    let decoding = decoding_context()?;
    let owner = TicketOwner::default();
    let native = btls::ssl::seal_envelope(&[], &KEY)?;
    let snapshot = envelope::seal_manifest(&KEY, &[], &native)?;
    assert_eq!(owner.import_tcp(snapshot.as_bytes(), &KEY, &decoding)?, 0);
    assert!(matches!(
        owner.import_tcp(snapshot.as_bytes(), &[8; 32], &decoding),
        Err(ImportError::Manifest(EnvelopeError::Authentication))
    ));
    assert!(owner.registry().caches.is_empty());
    Ok(())
}

#[test]
fn authenticated_empty_owner_replaces_one_exact_deduplicated_store() -> TestResult {
    let decoding = decoding_context()?;
    let profile = profile(TlsVersion::Tls13);
    let owner = owner(&profile, &[])?;
    let endpoint = Endpoint::new("127.0.0.1:443".parse()?, 443)?;
    let connector = Http1TlsConnector::new(profile.tls())?.with_isolated_session_cache();
    register(&owner, &connector, &endpoint, &Route::Direct);
    register(&owner, &connector, &endpoint, &Route::Direct);
    let mut header_bytes = header(0)?.to_bytes();
    header_bytes[14..].copy_from_slice(&42_u64.to_be_bytes());
    let expected = TcpSessionStoreHeader::parse(&header_bytes)?;
    let snapshot = empty_snapshot(&owner, expected)?;
    assert_eq!(owner.import_tcp(&snapshot, &KEY, &decoding)?, 0);
    assert_eq!(owner.registry().caches.len(), 2);
    let cache = connector
        .session_ticket_cache()
        .ok_or("cache missing")?
        .upgrade()
        .ok_or("cache dead")?;
    let stores = SessionTicketCacheOwner::capture_tcp_stores(&[(&cache, NAME)])?;
    assert_eq!(stores[0].header(), expected);
    let native = btls::ssl::seal_envelope(&[], &KEY)?;
    let noop = envelope::seal_manifest(&KEY, &[], &native)?;
    assert_eq!(owner.import_tcp(noop.as_bytes(), &KEY, &decoding)?, 0);
    assert_eq!(
        SessionTicketCacheOwner::capture_tcp_stores(&[(&cache, NAME)])?[0].header(),
        expected
    );
    Ok(())
}

#[test]
fn second_invalid_replacement_does_not_swap_the_first_valid_store() -> TestResult {
    let decoding = decoding_context()?;
    let profile = profile(TlsVersion::Tls13);
    let owner = owner(&profile, &[])?;
    let first_endpoint = Endpoint::new("127.0.0.1:443".parse()?, 443)?;
    let second_endpoint = Endpoint::new("127.0.0.1:444".parse()?, 443)?;
    let first = Http1TlsConnector::new(profile.tls())?.with_isolated_session_cache();
    let second = first.with_isolated_session_cache();
    register(&owner, &first, &first_endpoint, &Route::Direct);
    register(&owner, &second, &second_endpoint, &Route::Direct);
    let first_cache = first
        .session_ticket_cache()
        .ok_or("cache missing")?
        .upgrade()
        .ok_or("cache dead")?;
    let second_cache = second
        .session_ticket_cache()
        .ok_or("cache missing")?
        .upgrade()
        .ok_or("cache dead")?;
    let before = SessionTicketCacheOwner::capture_tcp_stores(&[
        (&first_cache, NAME),
        (&second_cache, NAME),
    ])?;
    let mut valid = header(0)?.to_bytes();
    valid[14..].copy_from_slice(&42_u64.to_be_bytes());
    let mut invalid = valid;
    invalid[11] = 3;
    let headers = [
        TcpSessionStoreHeader::parse(&valid)?,
        TcpSessionStoreHeader::parse(&invalid)?,
    ];
    let cache_registry = owner.registry();
    let caches = &cache_registry.caches;
    let mut inputs = Vec::new();
    for (registration, header) in caches.iter().zip(headers) {
        let binding = registration.binding.as_ref().map_err(|error| *error)?;
        inputs.push(OwnerInput {
            record_owner_index: inputs.len() as u16,
            origin: &binding.origin,
            server_name: NAME,
            leg: binding.leg,
            protocol: binding.protocol,
            policy: binding.descriptor.policy(),
            source_witness: binding.descriptor.source_witness(),
            has_credentials: false,
            header: SessionTicketStoreHeader::Tcp(header),
            slots: &[],
        });
    }
    let native = btls::ssl::seal_envelope(&[], &KEY)?;
    let snapshot = envelope::seal_manifest(&KEY, &inputs, &native)?;
    drop(cache_registry);
    assert!(matches!(
        owner.import_tcp(snapshot.as_bytes(), &KEY, &decoding),
        Err(ImportError::Native(SessionTransferError::Policy))
    ));
    let after = SessionTicketCacheOwner::capture_tcp_stores(&[
        (&first_cache, NAME),
        (&second_cache, NAME),
    ])?;
    assert_eq!(
        before
            .iter()
            .map(|store| store.header())
            .collect::<Vec<_>>(),
        after.iter().map(|store| store.header()).collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn unmatched_valid_empty_owner_is_retained_as_cold_intent() -> TestResult {
    let decoding = decoding_context()?;
    let profile = profile(TlsVersion::Tls13);
    let endpoint = Endpoint::new("127.0.0.1:443".parse()?, 443)?;
    let source = owner(&profile, &[])?;
    let connector = Http1TlsConnector::new(profile.tls())?.with_isolated_session_cache();
    register(&source, &connector, &endpoint, &Route::Direct);
    let snapshot = empty_snapshot(&source, header(0)?)?;
    let unmatched = owner(&profile, &[])?;
    assert_eq!(unmatched.import_tcp(&snapshot, &KEY, &decoding)?, 0);
    let registry = unmatched.registry();
    assert!(registry.caches.is_empty());
    let cold = registry.cold.as_ref().ok_or("cold intent missing")?;
    assert_eq!(cold.owners.len(), 1);
    assert_eq!(cold.owners[0].origin, endpoint);
    assert_eq!(
        cold.owners[0].header,
        SessionTicketStoreHeader::Tcp(header(0)?)
    );
    assert!(cold.owners[0].slots.is_empty());
    assert_eq!(cold.native.record_count(), 0);
    drop(registry);
    let native = btls::ssl::seal_envelope(&[], &KEY)?;
    let noop = envelope::seal_manifest(&KEY, &[], &native)?;
    let before = cold::cold_snapshot(&unmatched)?;
    assert_eq!(unmatched.import_tcp(noop.as_bytes(), &KEY, &decoding)?, 0);
    assert_eq!(cold::cold_snapshot(&unmatched)?, before);
    Ok(())
}

#[test]
fn ambiguous_actual_stores_are_rejected_before_replacement() -> TestResult {
    let decoding = decoding_context()?;
    let profile = profile(TlsVersion::Tls13);
    let endpoint = Endpoint::new("127.0.0.1:443".parse()?, 443)?;
    let source = owner(&profile, &[])?;
    let connector = Http1TlsConnector::new(profile.tls())?.with_isolated_session_cache();
    register(&source, &connector, &endpoint, &Route::Direct);
    let snapshot = empty_snapshot(&source, header(0)?)?;
    let ambiguous = owner(&profile, &[])?;
    let first = connector.with_isolated_session_cache();
    let second = connector.with_isolated_session_cache();
    register(&ambiguous, &first, &endpoint, &Route::Direct);
    register(&ambiguous, &second, &endpoint, &Route::Direct);
    let before = (cold::store_header(&first)?, cold::store_header(&second)?);
    assert!(matches!(
        ambiguous.import_tcp(&snapshot, &KEY, &decoding),
        Err(ImportError::OwnerMapping)
    ));
    assert_eq!(
        (cold::store_header(&first)?, cold::store_header(&second)?),
        before
    );
    assert!(ambiguous.registry().cold.is_none());
    Ok(())
}

#[test]
fn stored_preparation_conflicts_remain_errors_without_dropping_registration() -> TestResult {
    let decoding = decoding_context()?;
    let profile = profile(TlsVersion::Tls13);
    let owner = owner(&profile, &[])?;
    let endpoint = Endpoint::new("127.0.0.1:443".parse()?, 443)?;
    let connector = Http1TlsConnector::new(profile.tls())?.with_isolated_session_cache();
    register(&owner, &connector, &endpoint, &Route::Direct);
    let snapshot = empty_snapshot(&owner, header(0)?)?;
    let other = Endpoint::new("127.0.0.1:444".parse()?, 443)?;
    register(&owner, &connector, &other, &Route::Direct);
    assert!(matches!(
        owner.import_tcp(&snapshot, &KEY, &decoding),
        Err(ImportError::Preparation(_))
    ));
    assert_eq!(owner.registry().caches.len(), 2);
    assert!(
        owner
            .registry()
            .caches
            .iter()
            .all(|entry| entry.cache.is_live())
    );
    Ok(())
}

#[test]
fn empty_actual_credentials_reject_a_falsely_uncredentialed_source_flag() -> TestResult {
    let decoding = decoding_context()?;
    let profile = profile(TlsVersion::Tls13);
    let owner = owner(&profile, &[])?;
    let endpoint = Endpoint::new("127.0.0.1:443".parse()?, 443)?;
    let connector = Http1TlsConnector::new(profile.tls())?.with_isolated_session_cache();
    let route = Route::http_proxy(
        crate::HttpProxy::new("https://proxy.example")?
            .with_basic_auth("synthetic", "synthetic")?,
    );
    register(&owner, &connector, &endpoint, &route);
    let snapshot = empty_snapshot(&owner, header(0)?)?;
    assert!(matches!(
        owner.import_tcp(&snapshot, &KEY, &decoding),
        Err(ImportError::EmptyCredentials)
    ));
    assert_eq!(owner.registry().caches.len(), 1);
    Ok(())
}

#[test]
fn direct_only_fixture_rejects_proxy_mapping_and_whole_envelope_overflow() -> TestResult {
    let decoding = decoding_context()?;
    let profile = profile(TlsVersion::Tls13);
    let owner = owner(&profile, &[])?;
    let endpoint = Endpoint::new("127.0.0.1:443".parse()?, 443)?;
    let connector = Http1TlsConnector::new(profile.tls())?.with_isolated_session_cache();
    let route = Route::http_proxy(crate::HttpProxy::new("https://proxy.example")?);
    register(&owner, &connector, &endpoint, &route);
    let snapshot = empty_snapshot(&owner, header(0)?)?;
    assert!(matches!(
        owner.import_tcp(&snapshot, &KEY, &decoding),
        Err(ImportError::OwnerMapping)
    ));
    assert!(matches!(
        owner.import_tcp(&vec![0; MAX_ENVELOPE + 1], &KEY, &decoding),
        Err(ImportError::TooLarge)
    ));
    Ok(())
}

#[test]
fn record_mapping_checks_every_header_ordinal_name_payload_and_original_witness() -> TestResult {
    let endpoint = Endpoint::new("127.0.0.1:443".parse()?, 443)?;
    let slots = [RecordSlot {
        native_slot: 0,
        physical_ordinal: 0,
    }];
    let owner = OwnerInput {
        record_owner_index: 0,
        origin: &endpoint,
        server_name: NAME,
        leg: TicketCacheLeg::Origin,
        protocol: TicketCacheProtocol::Http1,
        policy: b"policy",
        source_witness: &[0, 0],
        has_credentials: false,
        header: SessionTicketStoreHeader::Tcp(header(1)?),
        slots: &slots,
    };
    // This is a structural metadata control only. It creates no native permit.
    let native = btls::ssl::seal_envelope(&[], &KEY)?;
    let snapshot = envelope::seal_manifest(&KEY, &[owner], &native)?;
    let manifest = envelope::open_manifest(snapshot.as_bytes(), &KEY)?;
    let mut source = manifest.owners().next().ok_or("owner missing")??;
    let mut metadata = header(1)?.to_bytes().to_vec();
    metadata.push(0);
    metadata.extend_from_slice(&0_u64.to_be_bytes());
    metadata.extend_from_slice(&0_u32.to_be_bytes());
    metadata.push(0);
    metadata.extend_from_slice(&(NAME.len() as u16).to_be_bytes());
    metadata.extend_from_slice(NAME.as_bytes());
    metadata.extend_from_slice(&12_u32.to_be_bytes());
    metadata.extend_from_slice(b"PHTOW001\0\x01\0\0");
    validate_record(&source, 0, &[0, 0], &metadata)?;
    // Dense manifest reordering never changes the genuine record payload.
    source.index = 17;
    validate_record(&source, 0, &[0, 0], &metadata)?;
    source.record_owner_index = 1;
    assert!(matches!(
        validate_record(&source, 0, &[0, 0], &metadata),
        Err(ImportError::OwnerMapping)
    ));
    source.record_owner_index = 0;
    validate_record(&source, 0, &[0, 0], &metadata)?;
    assert!(validate_record(&source, 0, &[0, 1], &metadata).is_err());
    assert!(validate_record(&source, 1, &[0, 0], &metadata).is_err());
    // Header order, original hostname, payload magic/version/index and length.
    for offset in [10, 38, 51, 60, 62] {
        let mut invalid = metadata.clone();
        invalid[offset] ^= 1;
        assert!(
            validate_record(&source, 0, &[0, 0], &invalid).is_err(),
            "offset {offset}"
        );
    }
    metadata.push(0);
    assert!(validate_record(&source, 0, &[0, 0], &metadata).is_err());
    Ok(())
}

async fn request(connector: &Http1TlsConnector, port: u16) -> TestResult {
    use phantom_net::{
        request::{OriginForm, RequestHeader},
        route::{DirectTlsSetup, Endpoint as NetEndpoint, Http1Route, OriginRoute, TcpRoute},
    };
    let (connection, slower) = connector
        .connect(Http1Route::Origin(OriginRoute::Tls {
            tcp: TcpRoute::Direct(NetEndpoint { host: NAME, port }),
            server_name: NAME,
            setup: DirectTlsSetup::Default,
        }))
        .await?;
    assert!(slower.is_none());
    let response = connection
        .send_get(
            OriginForm::parse("/")?,
            vec![RequestHeader::new("Host", NAME)],
        )
        .await?;
    assert_eq!(response.status(), http::StatusCode::OK);
    drop(response);
    Ok(())
}

#[tokio::test]
async fn genuine_tcp_tls12_and_tls13_import_resume_and_failed_mapping_keeps_tickets() -> TestResult
{
    let decoding = decoding_context()?;
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let identity = rcgen::generate_simple_self_signed(vec![NAME.to_owned()])?;
        let certificate = btls::x509::X509::from_der(identity.cert.der())?;
        let key = btls::pkey::PKey::private_key_from_pkcs8(&identity.signing_key.serialize_der())?;
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        acceptor.set_certificate(&certificate)?;
        acceptor.set_private_key(&key)?;
        acceptor.check_private_key()?;
        let native_version = if version == TlsVersion::Tls12 {
            SslVersion::TLS1_2
        } else {
            SslVersion::TLS1_3
        };
        acceptor.set_min_proto_version(Some(native_version))?;
        acceptor.set_max_proto_version(Some(native_version))?;
        acceptor.set_alpn_select_callback(|_, offers| {
            btls::ssl::select_next_proto(b"\x08http/1.1", offers).ok_or(btls::ssl::AlpnError::NOACK)
        });
        let acceptor = acceptor.build();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let endpoint = Endpoint::new(format!("{NAME}:{port}").parse()?, 443)?;
        let profile = profile(version);
        let roots = [Box::<[u8]>::from(identity.cert.der().as_ref())];
        let source = owner(&profile, &roots)?;
        let recipient = owner(&profile, &roots)?;
        let source_connector = Http1TlsConnector::new_with_additional_roots(
            profile.tls(),
            roots.iter().map(AsRef::as_ref),
        )?
        .with_isolated_session_cache();
        let recipient_connector = Http1TlsConnector::new_with_additional_roots(
            profile.tls(),
            roots.iter().map(AsRef::as_ref),
        )?
        .with_isolated_session_cache();
        register(&source, &source_connector, &endpoint, &Route::Direct);
        register(&recipient, &recipient_connector, &endpoint, &Route::Direct);
        let server = async {
            let mut resumed = Vec::new();
            for _ in 0..2 {
                let (socket, _) = listener.accept().await?;
                let mut stream = SslStream::new(Ssl::new(acceptor.context())?, socket)?;
                Pin::new(&mut stream).accept().await?;
                resumed.push(stream.ssl().session_reused());
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    if head.len() == 8192 {
                        return Err::<_, Box<dyn std::error::Error>>("request too large".into());
                    }
                    head.push(stream.read_u8().await?);
                }
                assert!(head.starts_with(b"GET / HTTP/1.1\r\n"));
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await?;
                stream.flush().await?;
            }
            Ok::<_, Box<dyn std::error::Error>>(resumed)
        };
        let client = async {
            request(&source_connector, port).await?;
            let (snapshot, bad) = {
                let cache_registry = source.registry();
                let caches = &cache_registry.caches;
                let registration = &caches[0];
                let binding = registration.binding.as_ref().map_err(|error| *error)?;
                let owner = registration.cache.upgrade().ok_or("source cache dead")?;
                let mut captures = SessionTicketCacheOwner::capture_tcp_stores(&[(&owner, NAME)])?;
                let capture = captures.pop().ok_or("source capture missing")?;
                let header = capture.header();
                assert!(header.record_count() > 0);
                let mut records = Vec::new();
                let mut slots = Vec::new();
                for (index, record) in capture.into_records().into_iter().enumerate() {
                    slots.push(RecordSlot {
                        native_slot: index as u16,
                        physical_ordinal: record.ordinal() as u8,
                    });
                    records.push(record.seal(b"PHTOW001\0\x01\0\0", &KEY)?);
                }
                let input = OwnerInput {
                    record_owner_index: 0,
                    origin: &binding.origin,
                    server_name: NAME,
                    leg: binding.leg,
                    protocol: binding.protocol,
                    policy: binding.descriptor.policy(),
                    source_witness: binding.descriptor.source_witness(),
                    has_credentials: false,
                    header: SessionTicketStoreHeader::Tcp(header),
                    slots: &slots,
                };
                let native = btls::ssl::seal_envelope(&records, &KEY)?;
                let snapshot = envelope::seal_manifest(&KEY, &[input], &native)?;
                let bad_input = OwnerInput {
                    record_owner_index: 0,
                    origin: &binding.origin,
                    server_name: NAME,
                    leg: binding.leg,
                    protocol: binding.protocol,
                    policy: binding.descriptor.policy(),
                    source_witness: &[0, 1],
                    has_credentials: false,
                    header: SessionTicketStoreHeader::Tcp(header),
                    slots: &slots,
                };
                let bad = envelope::seal_manifest(&KEY, &[bad_input], &native)?;
                (snapshot, bad)
            };
            assert_eq!(
                recipient.import_tcp(snapshot.as_bytes(), &KEY, &decoding)?,
                0
            );
            // A mismatched original witness must not replace imported tickets.
            assert!(
                recipient
                    .import_tcp(bad.as_bytes(), &KEY, &decoding)
                    .is_err()
            );
            request(&recipient_connector, port).await?;
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        // Both peers are directly owned futures; error, cancellation or unwind
        // drops their sockets without leaving a spawned task to join.
        let (_, resumed) =
            tokio::time::timeout(DEADLINE, async { tokio::try_join!(client, server) }).await??;
        assert_eq!(resumed, [false, true]);
    }
    Ok(())
}

#[test]
fn poisoned_recipient_registry_fails_without_replacing_stored_state() -> TestResult {
    let decoding = decoding_context()?;
    let profile = profile(TlsVersion::Tls13);
    let owner = owner(&profile, &[])?;
    let endpoint = Endpoint::new("127.0.0.1:443".parse()?, 443)?;
    let connector = Http1TlsConnector::new(profile.tls())?.with_isolated_session_cache();
    register(&owner, &connector, &endpoint, &Route::Direct);
    let cache = connector
        .session_ticket_cache()
        .ok_or("cache missing")?
        .upgrade()
        .ok_or("cache dead")?;
    let before = SessionTicketCacheOwner::capture_tcp_stores(&[(&cache, NAME)])?[0].header();
    let mut bytes = header(0)?.to_bytes();
    bytes[14..].copy_from_slice(&42_u64.to_be_bytes());
    let snapshot = empty_snapshot(&owner, TcpSessionStoreHeader::parse(&bytes)?)?;
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = owner
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        panic!("synthetic registry poison");
    }));
    assert!(poisoned.is_err());
    assert!(owner.registry.is_poisoned());
    assert!(matches!(
        owner.import_tcp(&snapshot, &KEY, &decoding),
        Err(ImportError::RegistryPoisoned)
    ));
    assert_eq!(
        SessionTicketCacheOwner::capture_tcp_stores(&[(&cache, NAME)])?[0].header(),
        before
    );
    assert_eq!(owner.registry().caches.len(), 1);
    Ok(())
}

mod cold;
