use super::*;

// Composition uses directly owned duplex peers with genuine ticket callbacks.
struct ImportFixture {
    profile: ClientProfile,
    roots: [Box<[u8]>; 1],
    server: SslAcceptor,
}

impl ImportFixture {
    fn new() -> TestResult<Self> {
        Self::for_version(TlsVersion::Tls13)
    }

    fn for_version(version: TlsVersion) -> TestResult<Self> {
        let identity = rcgen::generate_simple_self_signed(vec![NAME.to_owned()])?;
        let certificate = btls::x509::X509::from_der(identity.cert.der())?;
        let key = btls::pkey::PKey::private_key_from_pkcs8(&identity.signing_key.serialize_der())?;
        let mut server = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        server.set_certificate(&certificate)?;
        server.set_private_key(&key)?;
        server.check_private_key()?;
        let native_version = if version == TlsVersion::Tls12 {
            SslVersion::TLS1_2
        } else {
            SslVersion::TLS1_3
        };
        server.set_min_proto_version(Some(native_version))?;
        server.set_max_proto_version(Some(native_version))?;
        server.set_alpn_select_callback(|_, offers| {
            btls::ssl::select_next_proto(b"\x08http/1.1", offers).ok_or(btls::ssl::AlpnError::NOACK)
        });
        Ok(Self {
            profile: profile(version),
            roots: [Box::from(identity.cert.der().as_ref())],
            server: server.build(),
        })
    }

    fn owner(&self) -> TestResult<TicketOwner> {
        owner(&self.profile, &self.roots)
    }

    fn store(&self, owner: &TicketOwner, port: u16) -> TestResult<Http1TlsConnector> {
        let connector = Http1TlsConnector::new_with_additional_roots(
            self.profile.tls(),
            self.roots.iter().map(AsRef::as_ref),
        )?
        .with_isolated_session_cache();
        let endpoint = Endpoint::new(format!("{NAME}:{port}").parse()?, 443)?;
        register(owner, &connector, &endpoint, &Route::Direct);
        Ok(connector)
    }

    async fn exchange(&self, connector: &Http1TlsConnector, resumed: bool) -> TestResult {
        use http_body_util::BodyExt;
        use phantom_net::{
            request::{OriginForm, RequestHeader},
            route::{
                ConnectedStream, DirectTlsSetup, Http1Route, Http1Target, OriginRoute, TcpRoute,
            },
        };
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let mut peer = SslStream::new(Ssl::new(self.server.context())?, server_io)?;
        tokio::time::timeout(DEADLINE, async {
            tokio::try_join!(
                async {
                    let response = connector
                        .send(
                            Http1Route::Origin(OriginRoute::Tls {
                                tcp: TcpRoute::Connected(ConnectedStream::new(client_io)),
                                server_name: NAME,
                                setup: DirectTlsSetup::Default,
                            }),
                            http::Method::GET,
                            Http1Target::Origin(OriginForm::parse("/")?),
                            vec![RequestHeader::new("Host", NAME)],
                            None,
                        )
                        .await?;
                    assert_eq!(response.status(), http::StatusCode::OK);
                    assert_eq!(
                        response.into_body().collect().await?.to_bytes().as_ref(),
                        b"x"
                    );
                    Ok::<_, Box<dyn std::error::Error>>(())
                },
                async {
                    Pin::new(&mut peer).accept().await?;
                    assert_eq!(peer.ssl().session_reused(), resumed);
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        if head.len() == 8192 {
                            return Err::<_, Box<dyn std::error::Error>>(
                                "request too large".into(),
                            );
                        }
                        head.push(peer.read_u8().await?);
                    }
                    assert!(head.starts_with(b"GET / HTTP/1.1\r\n"));
                    peer.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx",
                    )
                    .await?;
                    peer.flush().await?;
                    Ok::<_, Box<dyn std::error::Error>>(())
                }
            )?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await??;
        Ok(())
    }
}

pub(super) fn store_header(connector: &Http1TlsConnector) -> TestResult<TcpSessionStoreHeader> {
    let cache = connector
        .session_ticket_cache()
        .ok_or("cache missing")?
        .upgrade()
        .ok_or("cache dead")?;
    Ok(SessionTicketCacheOwner::capture_tcp_stores(&[(&cache, NAME)])?[0].header())
}

#[derive(Clone, Copy)]
enum InvalidLastOwner {
    Policy,
    Witness,
    RecordIndex,
}

// Capture real bound stores. Only the explicit negative control corrupts the
// final facade policy/witness or its native record's original-owner payload.
fn live_snapshot(owner: &TicketOwner, invalid: Option<InvalidLastOwner>) -> TestResult<Vec<u8>> {
    let registry = owner.registry();
    let caches: Vec<_> = registry
        .caches
        .iter()
        .map(|entry| entry.cache.upgrade().ok_or("cache dead"))
        .collect::<Result<_, _>>()?;
    let capture_inputs: Vec<_> = caches.iter().map(|cache| (cache, NAME)).collect();
    let captures = SessionTicketCacheOwner::capture_tcp_stores(&capture_inputs)?;
    let mut records = Vec::new();
    let mut all_slots = Vec::new();
    let mut headers = Vec::new();
    for (index, capture) in captures.into_iter().enumerate() {
        headers.push(capture.header());
        let mut slots = Vec::new();
        let mut payload = *b"PHTOW001\0\x01\0\0";
        let original_index = if index + 1 == caches.len()
            && matches!(invalid, Some(InvalidLastOwner::RecordIndex))
        {
            u16::try_from(index + 1)?
        } else {
            u16::try_from(index)?
        };
        payload[10..].copy_from_slice(&original_index.to_be_bytes());
        for record in capture.into_records() {
            slots.push(RecordSlot {
                native_slot: u16::try_from(records.len())?,
                physical_ordinal: u8::try_from(record.ordinal())?,
            });
            records.push(record.seal(&payload, &KEY)?);
        }
        all_slots.push(slots);
    }
    let mut policies = Vec::new();
    let mut witnesses = Vec::new();
    for registration in &registry.caches {
        let binding = registration.binding.as_ref().map_err(|error| *error)?;
        policies.push(binding.descriptor.policy().to_vec());
        witnesses.push(binding.descriptor.source_witness().to_vec());
    }
    if matches!(invalid, Some(InvalidLastOwner::Policy)) {
        policies.last_mut().ok_or("policy missing")?[0] ^= 1;
    }
    if matches!(invalid, Some(InvalidLastOwner::Witness)) {
        *witnesses.last_mut().ok_or("witness missing")? = vec![0, 1];
    }
    let mut inputs = Vec::new();
    for (index, registration) in registry.caches.iter().enumerate() {
        let binding = registration.binding.as_ref().map_err(|error| *error)?;
        inputs.push(OwnerInput {
            record_owner_index: u16::try_from(index)?,
            origin: &binding.origin,
            server_name: NAME,
            leg: binding.leg,
            protocol: binding.protocol,
            policy: &policies[index],
            source_witness: &witnesses[index],
            has_credentials: false,
            header: SessionTicketStoreHeader::Tcp(headers[index]),
            slots: &all_slots[index],
        });
    }
    let native = btls::ssl::seal_envelope(&records, &KEY)?;
    Ok(envelope::seal_manifest(&KEY, &inputs, &native)?
        .as_bytes()
        .to_vec())
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct ColdSnapshot {
    owners_address: usize,
    owners: Vec<ColdOwnerSnapshot>,
    native: Vec<([u8; 32], [u8; 32])>,
}

#[derive(Debug, Eq, PartialEq)]
struct ColdOwnerSnapshot {
    authority: String,
    header: SessionTicketStoreHeader,
    original_index: u16,
    slots: Vec<RecordSlot>,
    policy: [u8; 32],
    witness: [u8; 32],
}

// Hash assertions never print policy, witnesses, session bytes or source keys.
pub(super) fn cold_snapshot(owner: &TicketOwner) -> TestResult<ColdSnapshot> {
    let registry = owner.registry();
    let cold = registry.cold.as_ref().ok_or("cold missing")?;
    let mut native = Vec::new();
    for index in 0..cold.native.record_count() {
        native.push((
            btls::sha::sha256(cold.native.owner_metadata(index)?),
            btls::sha::sha256(cold.native.source_witness(index)?),
        ));
    }
    Ok(ColdSnapshot {
        owners_address: cold.owners.as_ptr() as usize,
        owners: cold
            .owners
            .iter()
            .map(|owner| ColdOwnerSnapshot {
                authority: owner.origin.authority().as_str().to_owned(),
                header: owner.header,
                original_index: owner.record_owner_index,
                slots: owner.slots.clone(),
                policy: btls::sha::sha256(&owner.policy),
                witness: btls::sha::sha256(&owner.source_witness),
            })
            .collect(),
        native,
    })
}

#[tokio::test]
async fn subset_import_preserves_unmentioned_live_header_and_usable_tickets() -> TestResult {
    let fixture = ImportFixture::new()?;
    let decoding = decoding_context()?;
    let source = fixture.owner()?;
    let source_store = fixture.store(&source, 443)?;
    fixture.exchange(&source_store, false).await?;
    let snapshot = live_snapshot(&source, None)?;
    let recipient = fixture.owner()?;
    let replaced = fixture.store(&recipient, 443)?;
    let unmentioned = fixture.store(&recipient, 444)?;
    fixture.exchange(&replaced, false).await?;
    fixture.exchange(&unmentioned, false).await?;
    let before = (store_header(&replaced)?, store_header(&unmentioned)?);
    assert!(before.0.record_count() > 0);
    assert!(before.1.record_count() > 0);
    assert_eq!(
        recipient.import_tcp(&snapshot, &KEY, &decoding)?,
        before.0.record_count()
    );
    assert_eq!(store_header(&replaced)?, store_header(&source_store)?);
    assert_eq!(store_header(&unmentioned)?, before.1);
    assert!(recipient.registry().cold.is_none());
    fixture.exchange(&unmentioned, true).await?;
    fixture.exchange(&replaced, true).await?;
    Ok(())
}

#[tokio::test]
async fn mixed_import_applies_live_owner_and_retains_original_cold_record_indices() -> TestResult {
    let fixture = ImportFixture::new()?;
    let decoding = decoding_context()?;
    let source = fixture.owner()?;
    let first = fixture.store(&source, 443)?;
    fixture.exchange(&first, false).await?;
    let recipient = fixture.owner()?;
    recipient.import_tcp(&live_snapshot(&source, None)?, &KEY, &decoding)?;
    assert_eq!(
        recipient
            .registry()
            .cold
            .as_ref()
            .ok_or("cold missing")?
            .owners
            .len(),
        1
    );
    let second = fixture.store(&source, 444)?;
    fixture.exchange(&second, false).await?;
    let live = fixture.store(&recipient, 443)?;
    assert_eq!(
        recipient.import_tcp(&live_snapshot(&source, None)?, &KEY, &decoding)?,
        0
    );
    {
        let registry = recipient.registry();
        let cold = registry.cold.as_ref().ok_or("cold missing")?;
        assert_eq!(cold.owners.len(), 1);
        let pending = &cold.owners[0];
        assert_eq!(pending.origin.port(), 444);
        assert_eq!(pending.record_owner_index, 1);
        assert_eq!(
            pending.header,
            SessionTicketStoreHeader::Tcp(store_header(&second)?)
        );
        assert!(!pending.slots.is_empty());
        assert_eq!(cold.native.record_count(), pending.slots.len());
        for (index, slot) in pending.slots.iter().enumerate() {
            assert_eq!(usize::from(slot.native_slot), index);
            let metadata = TcpSessionRecordMetadata::parse(cold.native.owner_metadata(index)?)?;
            assert_eq!(metadata.ordinal(), usize::from(slot.physical_ordinal));
            assert_eq!(metadata.payload(), b"PHTOW001\0\x01\0\x01");
        }
    }
    assert_eq!(store_header(&live)?, store_header(&first)?);
    fixture.exchange(&live, true).await?;
    Ok(())
}

#[tokio::test]
async fn invalid_last_unmatched_owner_preserves_live_tickets_and_existing_cold_custody()
-> TestResult {
    let fixture = ImportFixture::new()?;
    let decoding = decoding_context()?;
    let prior = fixture.owner()?;
    let prior_store = fixture.store(&prior, 445)?;
    fixture.exchange(&prior_store, false).await?;
    let recipient = fixture.owner()?;
    recipient.import_tcp(&live_snapshot(&prior, None)?, &KEY, &decoding)?;
    let live = fixture.store(&recipient, 443)?;
    fixture.exchange(&live, false).await?;
    let source = fixture.owner()?;
    let first = fixture.store(&source, 443)?;
    let last = fixture.store(&source, 444)?;
    fixture.exchange(&first, false).await?;
    fixture.exchange(&last, false).await?;
    let before_live = store_header(&live)?;
    let before_cold = cold_snapshot(&recipient)?;
    assert!(before_live.record_count() > 0);
    assert!(!before_cold.native.is_empty());
    for invalid in [
        InvalidLastOwner::Policy,
        InvalidLastOwner::Witness,
        InvalidLastOwner::RecordIndex,
    ] {
        let snapshot = live_snapshot(&source, Some(invalid))?;
        let result = recipient.import_tcp(&snapshot, &KEY, &decoding);
        match invalid {
            InvalidLastOwner::Witness => assert!(matches!(
                result,
                Err(ImportError::Preparation(PreparationError::DrawMismatch))
            )),
            InvalidLastOwner::Policy | InvalidLastOwner::RecordIndex => {
                assert!(matches!(result, Err(ImportError::OwnerMapping)))
            }
        }
        assert_eq!(store_header(&live)?, before_live);
        assert_eq!(cold_snapshot(&recipient)?, before_cold);
    }
    // The otherwise identical valid pair can commit after all three rejections.
    assert_eq!(
        recipient.import_tcp(&live_snapshot(&source, None)?, &KEY, &decoding)?,
        before_live.record_count()
    );
    {
        let registry = recipient.registry();
        let cold = registry.cold.as_ref().ok_or("cold missing")?;
        assert_eq!(
            cold.owners
                .iter()
                .map(|owner| owner.origin.port())
                .collect::<Vec<_>>(),
            [445, 444]
        );
    }
    fixture.exchange(&live, true).await?;
    Ok(())
}

#[tokio::test]
async fn empty_cold_intent_replaces_old_records_and_is_removed_when_applied_live() -> TestResult {
    let fixture = ImportFixture::new()?;
    let decoding = decoding_context()?;
    let source = fixture.owner()?;
    let seeded = fixture.store(&source, 443)?;
    fixture.exchange(&seeded, false).await?;
    let recipient = fixture.owner()?;
    recipient.import_tcp(&live_snapshot(&source, None)?, &KEY, &decoding)?;
    assert!(!cold_snapshot(&recipient)?.native.is_empty());
    let empty_source = fixture.owner()?;
    let empty = fixture.store(&empty_source, 443)?;
    let snapshot = live_snapshot(&empty_source, None)?;
    assert_eq!(recipient.import_tcp(&snapshot, &KEY, &decoding)?, 0);
    {
        let registry = recipient.registry();
        let cold = registry.cold.as_ref().ok_or("empty intent missing")?;
        assert_eq!(cold.owners.len(), 1);
        assert_eq!(
            cold.owners[0].header,
            SessionTicketStoreHeader::Tcp(store_header(&empty)?)
        );
        assert!(cold.owners[0].slots.is_empty());
        assert_eq!(cold.native.record_count(), 0);
    }
    let live = fixture.store(&recipient, 443)?;
    fixture.exchange(&live, false).await?;
    let before = store_header(&live)?;
    assert!(before.record_count() > 0);
    assert_eq!(
        recipient.import_tcp(&snapshot, &KEY, &decoding)?,
        before.record_count()
    );
    assert_eq!(store_header(&live)?, store_header(&empty)?);
    assert!(recipient.registry().cold.is_none());
    fixture.exchange(&live, false).await?;
    Ok(())
}

mod api;
mod before_use;
mod clear_failure;
mod export;
