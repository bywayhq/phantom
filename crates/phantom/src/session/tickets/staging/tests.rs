//! Real direct-TCP records, opaque custody, and installed recipient bindings.

use std::{pin::Pin, sync::Arc, time::Duration};

use btls::{
    pkey::PKey,
    ssl::{
        AlpnError, SessionPolicyBinding, Ssl, SslAcceptor, SslConnector, SslMethod, SslVersion,
        select_next_proto,
    },
    x509::X509,
};
use http::Method;
use http_body_util::BodyExt;
use phantom_net::{
    ServerAuthentication, SourceBinding,
    http1::Http1TlsConnector,
    request::{OriginForm, RequestHeader},
    route::{ConnectedStream, DirectTlsSetup, Http1Route, Http1Target, OriginRoute, TcpRoute},
};
use phantom_profile::{
    ClientProfile, EchSettings, SessionTicketOrder, TlsVersion, TlsVersionRange, browser::chrome,
};
use phantom_testkit::http1::{CaptureLimits, capture_request_head};
use tokio::io::AsyncWriteExt;
use tokio_btls::SslStream;

use super::super::{
    TicketCacheBinding, TicketOwner,
    binding::{BindingPlan, TicketClientContext},
};
use super::*;
use crate::Route;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const KEY: [u8; 32] = [37; 32];
const EXPORT_KEY: [u8; 32] = [38; 32];
const NAME: &str = "origin.example";
const TIMEOUT: Duration = Duration::from_secs(10);

// The sibling transfer peer fixture is private. Keep the same owned-duplex
// handshake here rather than exposing test helpers through production modules.
struct Fixture {
    owner: TicketOwner,
    connector: Http1TlsConnector,
    retained: Vec<Http1TlsConnector>,
    endpoint: Endpoint,
    profile: ClientProfile,
    root: Box<[u8]>,
    server: SslAcceptor,
}

impl Fixture {
    fn new(version: TlsVersion, timeout: Option<u32>) -> TestResult<Self> {
        let identity =
            rcgen::generate_simple_self_signed(vec![NAME.into(), "second.example".into()])?;
        let root = identity.cert.der().to_vec().into_boxed_slice();
        let certificate = X509::from_der(&root)?;
        let key = PKey::private_key_from_pkcs8(&identity.signing_key.serialize_der())?;
        let mut server = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        server.set_certificate(&certificate)?;
        server.set_private_key(&key)?;
        server.check_private_key()?;
        let native_version = match version {
            TlsVersion::Tls12 => SslVersion::TLS1_2,
            _ => SslVersion::TLS1_3,
        };
        server.set_min_proto_version(Some(native_version))?;
        server.set_max_proto_version(Some(native_version))?;
        if let Some(timeout) = timeout {
            server.set_session_timeout(timeout);
        }
        server.set_alpn_select_callback(|_, offered| {
            select_next_proto(b"\x08http/1.1", offered).ok_or(AlpnError::NOACK)
        });
        let mut settings = chrome::v154_tcp_tls();
        settings.versions = TlsVersionRange::only(version);
        if version == TlsVersion::Tls12 {
            settings.alps = None;
            settings.key_shares.clear();
            settings.certificate_compression.clear();
            settings.ech = EchSettings::Disabled;
            settings.requested_trust_anchor_ids = None;
        }
        Self::build(
            ClientProfile::new(settings),
            root,
            server.build(),
            "origin.example:443",
        )
    }

    fn build(
        profile: ClientProfile,
        root: Box<[u8]>,
        server: SslAcceptor,
        authority: &str,
    ) -> TestResult<Self> {
        let source = SourceBinding::new();
        let preparation = BindingPlan::capture(&profile)?
            .complete(&profile)?
            .with_client_context(TicketClientContext {
                origin_authentication: ServerAuthentication::WebPki,
                origin_roots: std::slice::from_ref(&root),
                proxy_authentication: ServerAuthentication::WebPki,
                proxy_roots: &[],
                default_certificate: None,
                certificate_origins: &[],
                source_binding: &source,
                http3_early_data: None,
            })?;
        let owner = TicketOwner::with_preparation(Ok(Arc::new(preparation)));
        let connector = Http1TlsConnector::new_with_additional_roots(profile.tls(), [&*root])?
            .with_isolated_session_cache();
        let endpoint = Endpoint::new(authority.parse()?, 443)?;
        register(&owner, &connector, &endpoint);
        Ok(Self {
            owner,
            connector,
            retained: Vec::new(),
            endpoint,
            profile,
            root,
            server,
        })
    }

    fn variant(&self, profile: ClientProfile, authority: &str) -> TestResult<Self> {
        Self::build(profile, self.root.clone(), self.server.clone(), authority)
    }

    fn add_empty(&mut self, authority: &str) -> TestResult {
        let connector = self.connector.with_isolated_session_cache();
        let endpoint = Endpoint::new(authority.parse()?, 443)?;
        register(&self.owner, &connector, &endpoint);
        self.retained.push(connector);
        Ok(())
    }

    fn snapshot(&self, decoding: &SslContextRef) -> TestResult<(OpenedManifest, ColdState)> {
        let sealed = self.owner.export_tcp(&KEY)?;
        let manifest = envelope::open_manifest(sealed.as_bytes(), &KEY)?;
        let native = btls::ssl::open_envelope(manifest.native_ciphertext(), &KEY, decoding)?;
        let preparation = self
            .owner
            .preparation
            .as_ref()
            .ok_or("preparation missing")?
            .as_ref()
            .map_err(|error| *error)?;
        let registry = self.owner.registry();
        let registrations = &registry.caches;
        for view in manifest.owners() {
            let view = view?;
            let registration = registrations
                .iter()
                .find(|entry| {
                    entry.binding.as_ref().is_ok_and(|binding| {
                        binding.origin.authority().as_str() == view.origin_authority
                    })
                })
                .ok_or("registration missing")?;
            let binding = registration.binding.as_ref().map_err(|error| *error)?;
            assert!(view.policy == binding.descriptor.policy());
            assert!(!view.has_credentials);
            assert!(crate::route::transfer_credential(&binding.route)?.is_none());
            preparation.validate_source_witness(view.source_witness)?;
            let configured = preparation.configured_direct_tcp_policy(
                &binding.descriptor,
                binding.leg,
                binding.protocol,
                &binding.route,
            )?;
            for slot in view.slots() {
                preparation.validate_configured_direct_tcp_record(
                    &native,
                    usize::from(slot.native_slot),
                    &configured,
                    view.server_name,
                )?;
            }
        }
        drop(registry);
        let state = ColdState::capture(&manifest, native)?;
        Ok((manifest, state))
    }

    fn binding_for(&self, source: &ColdOwner) -> TestResult<Option<SessionPolicyBinding>> {
        let registry = self.owner.registry();
        for registration in &registry.caches {
            let binding = registration.binding.as_ref().map_err(|error| *error)?;
            if binding.origin.authority().as_str() == source.origin.authority().as_str()
                && binding.server_name == source.server_name.as_str()
                && binding.descriptor.policy() == source.policy.as_slice()
            {
                return Ok(Some(
                    registration
                        .native_binding
                        .as_ref()
                        .map_err(|error| *error)?
                        .clone(),
                ));
            }
        }
        Ok(None)
    }
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

async fn seed(fixture: &Fixture) -> TestResult {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let mut peer = SslStream::new(Ssl::new(fixture.server.context())?, server_io)?;
    tokio::time::timeout(TIMEOUT, async {
        tokio::try_join!(
            async {
                let response = fixture
                    .connector
                    .send(
                        Http1Route::Origin(OriginRoute::Tls {
                            tcp: TcpRoute::Connected(ConnectedStream::new(client_io)),
                            server_name: fixture.endpoint.host(),
                            setup: DirectTlsSetup::Default,
                        }),
                        Method::GET,
                        Http1Target::Origin(OriginForm::parse("/")?),
                        vec![RequestHeader::new(
                            "Host",
                            fixture.endpoint.authority().as_str(),
                        )],
                        None,
                    )
                    .await?;
                assert_eq!(response.status(), http::StatusCode::OK);
                assert_eq!(
                    response.into_body().collect().await?.to_bytes().as_ref(),
                    b"x"
                );
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            },
            async {
                Pin::new(&mut peer).accept().await?;
                assert!(!peer.ssl().session_reused());
                let head = capture_request_head(
                    &mut peer,
                    tokio::time::Instant::now() + TIMEOUT,
                    CaptureLimits::new(32 * 1024, 8 * 1024, 32),
                )
                .await?;
                assert_eq!(head.method(), b"GET");
                peer.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx",
                )
                .await?;
                peer.flush().await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            }
        )?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

#[derive(Debug)]
struct EncryptedTickets(Arc<dyn rustls::server::ProducesTickets>);

impl rustls::server::ProducesTickets for EncryptedTickets {
    fn enabled(&self) -> bool {
        self.0.enabled()
    }

    fn lifetime(&self) -> u32 {
        self.0.lifetime()
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        self.0.encrypt(plain)
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        self.0.decrypt(cipher)
    }
}

fn encrypted_tickets()
-> Result<Box<dyn rustls::server::ProducesTickets>, rustls::crypto::GetRandomFailed> {
    // The ring ticketer's constructor only fails when random generation fails.
    let inner =
        rustls::crypto::ring::Ticketer::new().map_err(|_| rustls::crypto::GetRandomFailed)?;
    Ok(Box::new(EncryptedTickets(inner)))
}

async fn seed_short_lived_ticket(fixture: &Fixture) -> TestResult {
    let key = fixture
        .server
        .context()
        .private_key()
        .ok_or("expiry peer has no private key")?
        .private_key_to_der_pkcs8()?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(
            fixture.root.to_vec(),
        )],
        rustls::pki_types::PrivatePkcs8KeyDer::from(key).into(),
    )?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    // The rotator erases old keys and advertises twice its rotation interval.
    config.ticketer = Arc::new(rustls::TicketRotator::new(2, encrypted_tickets)?);
    assert_eq!(config.ticketer.lifetime(), 4);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    tokio::time::timeout(TIMEOUT, async {
        tokio::try_join!(
            async {
                let response = fixture
                    .connector
                    .send(
                        Http1Route::Origin(OriginRoute::Tls {
                            tcp: TcpRoute::Connected(ConnectedStream::new(client_io)),
                            server_name: fixture.endpoint.host(),
                            setup: DirectTlsSetup::Default,
                        }),
                        Method::GET,
                        Http1Target::Origin(OriginForm::parse("/")?),
                        vec![RequestHeader::new(
                            "Host",
                            fixture.endpoint.authority().as_str(),
                        )],
                        None,
                    )
                    .await?;
                assert_eq!(response.status(), http::StatusCode::OK);
                assert_eq!(
                    response.into_body().collect().await?.to_bytes().as_ref(),
                    b"x"
                );
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            },
            async {
                let mut peer = acceptor.accept(server_io).await?;
                assert_eq!(
                    peer.get_ref().1.protocol_version(),
                    Some(rustls::ProtocolVersion::TLSv1_3)
                );
                assert!(matches!(
                    peer.get_ref().1.handshake_kind(),
                    Some(
                        rustls::HandshakeKind::Full
                            | rustls::HandshakeKind::FullWithHelloRetryRequest
                    )
                ));

                let head = capture_request_head(
                    &mut peer,
                    tokio::time::Instant::now() + TIMEOUT,
                    CaptureLimits::new(32 * 1024, 8 * 1024, 32),
                )
                .await?;
                assert_eq!(head.method(), b"GET");
                peer.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx",
                )
                .await?;
                peer.flush().await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            }
        )?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

fn decoding_context() -> TestResult<btls::ssl::SslContext> {
    Ok(SslConnector::builder(SslMethod::tls())?
        .build()
        .into_context())
}

fn export_manifest(state: &ColdState, budget: usize) -> TestResult<envelope::SealedManifest> {
    let export = state.prepare_export(&EXPORT_KEY, budget)?;
    let inputs: Vec<_> = export.owners.iter().map(ColdOwner::input).collect();
    let native = btls::ssl::seal_envelope(&export.records, &EXPORT_KEY)?;
    Ok(envelope::seal_manifest(&EXPORT_KEY, &inputs, &native)?)
}

fn views(manifest: &OpenedManifest) -> TestResult<Vec<OwnerView<'_>>> {
    manifest
        .owners()
        .map(|view| view.map_err(Into::into))
        .collect()
}

// Only hashes, structural metadata and consumed-slot markers enter assertion output.
#[derive(Debug, Eq, PartialEq)]
struct StateSnapshot {
    owners: Vec<OwnerSnapshot>,
    native: Vec<Option<[u8; 32]>>,
}

#[derive(Debug, Eq, PartialEq)]
struct OwnerSnapshot {
    authority: String,
    header: [u8; 22],
    original_index: u16,
    policy: [u8; 32],
    witness: [u8; 32],
    slots: Vec<RecordSlot>,
}

fn snapshot(state: &ColdState) -> TestResult<StateSnapshot> {
    let mut native = Vec::new();
    for index in 0..state.native.record_count() {
        native.push(match state.native.owner_metadata(index) {
            Ok(metadata) => Some(btls::sha::sha256(metadata)),
            Err(SessionTransferError::Consumed) => None,
            Err(error) => return Err(error.into()),
        });
    }
    Ok(StateSnapshot {
        owners: state
            .owners
            .iter()
            .map(|owner| OwnerSnapshot {
                authority: owner.origin.authority().as_str().to_owned(),
                header: owner.header.to_bytes(),
                original_index: owner.record_owner_index,
                policy: btls::sha::sha256(&owner.policy),
                witness: btls::sha::sha256(&owner.source_witness),
                slots: owner.slots.clone(),
            })
            .collect(),
        native,
    })
}

fn authorize_owner(state: &mut ColdState, index: usize, fixture: &Fixture) -> TestResult<usize> {
    let owner = state.owners.get(index).ok_or("owner missing")?;
    let binding = fixture
        .binding_for(owner)?
        .ok_or("installed recipient missing")?;
    for slot in &owner.slots {
        // Real installed native authority consumes only this private transaction.
        drop(
            state
                .native
                .authorize_record(usize::from(slot.native_slot), &binding)?,
        );
        assert!(matches!(
            state.native.owner_metadata(usize::from(slot.native_slot)),
            Err(SessionTransferError::Consumed)
        ));
    }
    Ok(owner.slots.len())
}

#[tokio::test]
async fn pending_owners_remap_export_and_authorize_without_consuming_sources() -> TestResult {
    let decoding = decoding_context()?;
    let first = Fixture::new(TlsVersion::Tls13, None)?;
    let second = first.variant(first.profile.clone(), "second.example:443")?;
    seed(&first).await?;
    seed(&second).await?;
    let (_, old) = first.snapshot(&decoding)?;
    let (manifest, incoming) = second.snapshot(&decoding)?;
    let before = (snapshot(&old)?, snapshot(&incoming)?);
    let union = old.prepare_union(&incoming, &views(&manifest)?, &decoding)?;
    assert_eq!(union.owners.len(), 2);
    assert!(
        union
            .owners
            .iter()
            .all(|owner| owner.record_owner_index == 0)
    );
    let slots: Vec<_> = union
        .owners
        .iter()
        .flat_map(|owner| &owner.slots)
        .map(|slot| usize::from(slot.native_slot))
        .collect();
    assert_eq!(slots, (0..union.native.record_count()).collect::<Vec<_>>());
    let union_before = snapshot(&union)?;
    let sealed = export_manifest(&union, MAX_ENVELOPE)?;
    let exact = sealed.as_bytes().len();
    assert_eq!(export_manifest(&union, exact)?.as_bytes().len(), exact);
    assert!(matches!(
        union.prepare_export(&EXPORT_KEY, exact - 1),
        Err(ColdError::Native(SessionTransferError::TooLarge))
    ));
    let opened = envelope::open_manifest(sealed.as_bytes(), &EXPORT_KEY)?;
    let native = btls::ssl::open_envelope(opened.native_ciphertext(), &EXPORT_KEY, &decoding)?;
    let mut exported = ColdState::capture(&opened, native)?;
    assert!(authorize_owner(&mut exported, 0, &first)? > 0);
    assert!(authorize_owner(&mut exported, 1, &second)? > 0);
    assert_eq!((snapshot(&old)?, snapshot(&incoming)?), before);
    assert_eq!(union.native.record_count(), slots.len());
    assert_eq!(snapshot(&union)?, union_before);
    Ok(())
}

#[tokio::test]
async fn replacement_skips_an_expired_old_owner_and_retains_an_unrelated_owner() -> TestResult {
    let decoding = decoding_context()?;
    let expiring = Fixture::new(TlsVersion::Tls13, None)?;
    let durable = Fixture::new(TlsVersion::Tls12, None)?;
    let durable = durable.variant(durable.profile.clone(), "second.example:443")?;
    seed_short_lived_ticket(&expiring).await?;
    seed(&durable).await?;
    let (_, first) = expiring.snapshot(&decoding)?;
    let (manifest, second) = durable.snapshot(&decoding)?;
    let old = first.prepare_union(&second, &views(&manifest)?, &decoding)?;
    tokio::time::timeout(TIMEOUT, async {
        loop {
            match first.prepare_export(&EXPORT_KEY, MAX_ENVELOPE) {
                Err(ColdError::Native(SessionTransferError::Expired)) => break,
                Ok(_) => tokio::time::sleep(Duration::from_millis(25)).await,
                Err(error) => return Err(error.into()),
            }
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    assert!(second.prepare_export(&EXPORT_KEY, MAX_ENVELOPE).is_ok());
    let replacement = expiring.variant(expiring.profile.clone(), "origin.example:443")?;
    seed(&replacement).await?;
    let (manifest, incoming) = replacement.snapshot(&decoding)?;
    let before = (snapshot(&old)?, snapshot(&incoming)?);
    assert!(matches!(
        old.prepare_export(&EXPORT_KEY, MAX_ENVELOPE),
        Err(ColdError::Native(SessionTransferError::Expired))
    ));
    let mut union = old.prepare_union(&incoming, &views(&manifest)?, &decoding)?;
    assert_eq!(union.owners.len(), 2);
    assert_eq!(union.owners[0].origin.host(), "second.example");
    assert_eq!(union.owners[1].origin.host(), NAME);
    assert!(authorize_owner(&mut union, 0, &durable)? > 0);
    assert!(authorize_owner(&mut union, 1, &replacement)? > 0);
    assert_eq!((snapshot(&old)?, snapshot(&incoming)?), before);
    Ok(())
}

#[tokio::test]
async fn empty_replacement_retains_clear_intent_until_the_caller_removes_it() -> TestResult {
    let decoding = decoding_context()?;
    let fixture = Fixture::new(TlsVersion::Tls13, None)?;
    seed(&fixture).await?;
    let (_, old) = fixture.snapshot(&decoding)?;
    let empty_fixture = fixture.variant(fixture.profile.clone(), "origin.example:443")?;
    let (manifest, pending) = empty_fixture.snapshot(&decoding)?;
    let replacements = views(&manifest)?;
    let union = old.prepare_union(&pending, &replacements, &decoding)?;
    assert_eq!(union.owners.len(), 1);
    assert!(union.owners[0].slots.is_empty());
    assert_eq!(union.native.record_count(), 0);
    let mut applied = pending.try_clone_remaining()?;
    applied.owners.clear();
    let union = old.prepare_union(&applied, &replacements, &decoding)?;
    assert!(union.owners.is_empty());
    assert_eq!(union.native.record_count(), 0);
    assert_eq!(pending.owners.len(), 1);
    assert!(old.native.record_count() > 0);
    Ok(())
}

#[tokio::test]
async fn partial_owner_consumption_fails_without_further_source_consumption() -> TestResult {
    let decoding = decoding_context()?;
    let fixture = Fixture::new(TlsVersion::Tls13, None)?;
    seed(&fixture).await?;
    let (manifest, mut incoming) = fixture.snapshot(&decoding)?;
    assert!(
        incoming.owners[0].slots.len() >= 2,
        "peer must issue multiple real tickets"
    );
    let binding = fixture
        .binding_for(&incoming.owners[0])?
        .ok_or("binding missing")?;
    let first = usize::from(incoming.owners[0].slots[0].native_slot);
    drop(incoming.native.authorize_record(first, &binding)?);
    let empty = fixture.variant(fixture.profile.clone(), "second.example:443")?;
    let (empty_manifest, old) = empty.snapshot(&decoding)?;
    let before = (snapshot(&old)?, snapshot(&incoming)?);
    assert!(matches!(
        old.prepare_union(&incoming, &views(&manifest)?, &decoding),
        Err(ColdError::Mapping)
    ));
    assert!(matches!(
        incoming.prepare_union(&old, &views(&empty_manifest)?, &decoding),
        Err(ColdError::Mapping)
    ));
    assert!(matches!(
        incoming.try_clone_remaining(),
        Err(ColdError::Mapping)
    ));
    assert_eq!((snapshot(&old)?, snapshot(&incoming)?), before);
    assert_eq!(
        fixture.snapshot(&decoding)?.1.native.record_count(),
        incoming.native.record_count()
    );
    Ok(())
}

#[tokio::test]
async fn same_origin_with_distinct_configured_policy_preserves_both_owners() -> TestResult {
    let decoding = decoding_context()?;
    let first = Fixture::new(TlsVersion::Tls13, None)?;
    let mut settings = first.profile.tls().clone();
    settings.session_ticket_order = SessionTicketOrder::OldestFirst;
    let second = first.variant(ClientProfile::new(settings), "origin.example:443")?;
    seed(&first).await?;
    seed(&second).await?;
    let (_, old) = first.snapshot(&decoding)?;
    let (manifest, incoming) = second.snapshot(&decoding)?;
    assert!(old.owners[0].policy != incoming.owners[0].policy);
    let mut union = old.prepare_union(&incoming, &views(&manifest)?, &decoding)?;
    assert_eq!(union.owners.len(), 2);
    assert_eq!(union.owners[0].origin, union.owners[1].origin);
    assert!(authorize_owner(&mut union, 0, &first)? > 0);
    assert!(authorize_owner(&mut union, 1, &second)? > 0);
    Ok(())
}

#[test]
fn union_owner_count_rejection_preserves_both_real_empty_sources() -> TestResult {
    let decoding = decoding_context()?;
    let mut fixture = Fixture::new(TlsVersion::Tls13, None)?;
    for port in 10_001..=10_255 {
        fixture.add_empty(&format!("origin.example:{port}"))?;
    }
    let (_, old) = fixture.snapshot(&decoding)?;
    assert_eq!(old.owners.len(), 256);
    let matching = fixture.variant(fixture.profile.clone(), "origin.example:443")?;
    let (matching_manifest, matching_incoming) = matching.snapshot(&decoding)?;
    let at_limit = old.prepare_union(&matching_incoming, &views(&matching_manifest)?, &decoding)?;
    assert_eq!(at_limit.owners.len(), 256);
    let added = fixture.variant(fixture.profile.clone(), "origin.example:30000")?;
    let (manifest, incoming) = added.snapshot(&decoding)?;
    let before = (snapshot(&old)?, snapshot(&incoming)?);
    assert!(matches!(
        old.prepare_union(&incoming, &views(&manifest)?, &decoding),
        Err(ColdError::TooLarge)
    ));
    assert_eq!((snapshot(&old)?, snapshot(&incoming)?), before);
    assert_eq!(fixture.snapshot(&decoding)?.1.owners.len(), 256);
    Ok(())
}

#[tokio::test]
async fn consumed_incoming_owner_still_replaces_old_while_another_owner_stays_pending() -> TestResult
{
    let decoding = decoding_context()?;
    let first = Fixture::new(TlsVersion::Tls13, None)?;
    let second = first.variant(first.profile.clone(), "second.example:443")?;
    seed(&first).await?;
    seed(&second).await?;
    let (_, old) = first.snapshot(&decoding)?;
    let (_, first_incoming) = first.snapshot(&decoding)?;
    let (second_manifest, second_incoming) = second.snapshot(&decoding)?;
    let mut incoming =
        first_incoming.prepare_union(&second_incoming, &views(&second_manifest)?, &decoding)?;
    let sealed = export_manifest(&incoming, MAX_ENVELOPE)?;
    let full_original = envelope::open_manifest(sealed.as_bytes(), &EXPORT_KEY)?;
    assert!(authorize_owner(&mut incoming, 0, &first)? > 0);
    let before = (snapshot(&old)?, snapshot(&incoming)?);
    let mut union = old.prepare_union(&incoming, &views(&full_original)?, &decoding)?;
    assert_eq!(union.owners.len(), 1);
    assert_eq!(union.owners[0].origin.host(), "second.example");
    assert_eq!(union.owners[0].slots[0].native_slot, 0);
    assert!(authorize_owner(&mut union, 0, &second)? > 0);
    assert_eq!((snapshot(&old)?, snapshot(&incoming)?), before);
    Ok(())
}
