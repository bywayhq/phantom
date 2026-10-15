use super::*;

fn empty_quic(decoding: &SslContextRef) -> TestResult<(OpenedManifest, ColdState)> {
    use phantom_net::{SessionTicketStoreExport, http3::Http3Connector};
    let connector = Http3Connector::new(
        &chrome::v154_quic_tls(),
        &chrome::v154_quic(),
        &chrome::v154_http3(),
        &chrome::v154_http3_request(),
    )?
    .with_isolated_session_cache();
    let owner = connector
        .session_ticket_cache()
        .and_then(|control| control.upgrade())
        .ok_or("QUIC cache absent")?;
    let policy = b"actual empty QUIC cache custody";
    let witness = [0, 0];
    owner.bind_transfer_policy(
        NAME,
        btls::ssl::SessionTransferPolicy::new(policy, &witness, None, &[61; 32])?,
    )?;
    let captured = phantom_net::SessionTicketCacheOwner::capture_stores(&[(&owner, NAME)])?
        .pop()
        .ok_or("capture absent")?;
    let SessionTicketStoreExport::Quic(captured) = captured else {
        return Err("wrong captured store kind".into());
    };
    let header = captured.header();
    assert_eq!(header.record_count(), 0);
    assert!(captured.into_records().is_empty());
    let endpoint = Endpoint::new("origin.example:443".parse()?, 443)?;
    let input = OwnerInput {
        record_owner_index: 17,
        origin: &endpoint,
        server_name: NAME,
        leg: TicketCacheLeg::Origin,
        protocol: TicketCacheProtocol::Http3,
        policy,
        source_witness: &witness,
        has_credentials: false,
        header: SessionTicketStoreHeader::Quic(header),
        slots: &[],
    };
    let native = btls::ssl::seal_envelope(&[], &KEY)?;
    let sealed = envelope::seal_manifest(&KEY, &[input], &native)?;
    let manifest = envelope::open_manifest(sealed.as_bytes(), &KEY)?;
    let native = btls::ssl::open_envelope(manifest.native_ciphertext(), &KEY, decoding)?;
    let custody = ColdState::capture(&manifest, native)?;
    Ok((manifest, custody))
}

#[tokio::test]
async fn real_tcp_records_and_bound_empty_quic_intent_rekey_without_source_consumption()
-> TestResult {
    let decoding = decoding_context()?;
    let tcp = Fixture::new(TlsVersion::Tls13, None)?;
    seed(&tcp).await?;
    let (_, old) = tcp.snapshot(&decoding)?;
    let (manifest, incoming) = empty_quic(&decoding)?;
    let before = (snapshot(&old)?, snapshot(&incoming)?);
    let union = old.prepare_union(&incoming, &views(&manifest)?, &decoding)?;
    assert_eq!(union.owners.len(), 2);
    assert_eq!(union.native.record_count(), old.native.record_count());
    assert!(union.native.record_count() > 0);
    assert_eq!(union.owners[0].slots, old.owners[0].slots);
    assert_eq!(union.owners[1].record_owner_index, 17);
    assert_eq!(union.owners[1].header, incoming.owners[0].header);
    assert!(union.owners[1].slots.is_empty());
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
    assert!(authorize_owner(&mut exported, 0, &tcp)? > 0);
    let pending = exported.try_clone_remaining()?;
    assert_eq!(pending.owners.len(), 1);
    assert_eq!(pending.owners[0].protocol, TicketCacheProtocol::Http3);
    assert_eq!(pending.owners[0].record_owner_index, 17);
    assert_eq!(pending.native.record_count(), 0);
    assert_eq!((snapshot(&old)?, snapshot(&incoming)?), before);
    Ok(())
}

#[tokio::test]
async fn empty_quic_replacement_keeps_real_tcp_custody_until_explicit_apply() -> TestResult {
    let decoding = decoding_context()?;
    let tcp = Fixture::new(TlsVersion::Tls13, None)?;
    seed(&tcp).await?;
    let (_, tcp_state) = tcp.snapshot(&decoding)?;
    let (manifest, quic) = empty_quic(&decoding)?;
    let old = tcp_state.prepare_union(&quic, &views(&manifest)?, &decoding)?;
    let (replacement, pending) = empty_quic(&decoding)?;
    let replacements = views(&replacement)?;
    let before = (snapshot(&old)?, snapshot(&pending)?);
    let union = old.prepare_union(&pending, &replacements, &decoding)?;
    assert_eq!(union.owners.len(), 2);
    assert_eq!(union.native.record_count(), tcp_state.native.record_count());
    let mut applied = pending.try_clone_remaining()?;
    applied.owners.clear();
    let mut union = old.prepare_union(&applied, &replacements, &decoding)?;
    assert_eq!(union.owners.len(), 1);
    assert_eq!(union.owners[0].protocol, TicketCacheProtocol::Http1);
    assert!(authorize_owner(&mut union, 0, &tcp)? > 0);
    assert_eq!((snapshot(&old)?, snapshot(&pending)?), before);
    Ok(())
}

fn structural_quic(
    transport_parameters: Option<&[u8]>,
) -> TestResult<(SessionTicketStoreHeader, Vec<u8>)> {
    // Parser input only, with no native session, record, envelope or permit.
    let mut header = [0; 26];
    header[..8].copy_from_slice(b"PHQUIC01");
    header[9] = 1;
    header[10] = 4;
    header[11] = 1;
    let header = phantom_net::QuicSessionStoreHeader::parse(&header)?;
    let mut bytes = header.to_bytes().to_vec();
    bytes.push(3);
    bytes.push(u8::from(transport_parameters.is_some()));
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&(NAME.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&(transport_parameters.map_or(0, <[u8]>::len) as u32).to_be_bytes());
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes.extend_from_slice(&12_u32.to_be_bytes());
    bytes.extend_from_slice(NAME.as_bytes());
    bytes.extend_from_slice(transport_parameters.unwrap_or_default());
    bytes.extend_from_slice(b"PHTOW001\0\x01\0\x07");
    Ok((SessionTicketStoreHeader::Quic(header), bytes))
}

#[test]
fn quic_metadata_requires_exact_owner_mapping_and_strict_present_parameters() -> TestResult {
    let (header, bytes) = structural_quic(None)?;
    let slot = RecordSlot {
        native_slot: 9,
        physical_ordinal: 3,
    };
    validate_metadata(header, NAME, b"draw", 7, slot, &bytes, b"draw")?;
    for (name, witness, index, ordinal) in [
        ("different.example", &b"draw"[..], 7, 3),
        (NAME, &b"other"[..], 7, 3),
        (NAME, &b"draw"[..], 8, 3),
        (NAME, &b"draw"[..], 7, 2),
    ] {
        let slot = RecordSlot {
            physical_ordinal: ordinal,
            ..slot
        };
        assert!(matches!(
            validate_metadata(header, name, witness, index, slot, &bytes, b"draw"),
            Err(ColdError::Mapping)
        ));
    }
    let (_, malformed_parameters) = structural_quic(Some(&[0xff]))?;
    assert!(matches!(
        validate_metadata(
            header,
            NAME,
            b"draw",
            7,
            slot,
            &malformed_parameters,
            b"draw"
        ),
        Err(ColdError::Native(_))
    ));
    let mut wrong_version = bytes.clone();
    wrong_version[28..32].fill(0);
    assert!(matches!(
        validate_metadata(header, NAME, b"draw", 7, slot, &wrong_version, b"draw"),
        Err(ColdError::Native(_))
    ));
    assert!(matches!(
        store_shape(TicketCacheProtocol::Http1, header),
        Err(ColdError::Mapping)
    ));
    Ok(())
}

#[test]
fn typed_quic_metadata_remaps_only_native_indices_and_preserves_physical_holes() -> TestResult {
    let (header, bytes) = structural_quic(None)?;
    let owner = ColdOwner {
        origin: Endpoint::new("origin.example:443".parse()?, 443)?,
        server_name: Zeroizing::new(NAME.to_owned()),
        leg: TicketCacheLeg::Origin,
        protocol: TicketCacheProtocol::Http3,
        policy: Zeroizing::new(b"policy".to_vec()),
        source_witness: Zeroizing::new(b"draw".to_vec()),
        has_credentials: false,
        record_owner_index: 7,
        header,
        slots: vec![RecordSlot {
            native_slot: 1,
            physical_ordinal: 3,
        }],
    };
    let remapped = owner.copy_remapped(&[None, Some(0)])?;
    assert_eq!(remapped.header, header);
    assert_eq!(remapped.record_owner_index, 7);
    assert_eq!(
        remapped.slots,
        [RecordSlot {
            native_slot: 0,
            physical_ordinal: 3
        }]
    );
    validate_metadata(
        remapped.header,
        &remapped.server_name,
        &remapped.source_witness,
        remapped.record_owner_index,
        remapped.slots[0],
        &bytes,
        b"draw",
    )?;
    assert_eq!(owner.slots[0].native_slot, 1);
    assert!(matches!(
        owner.copy_remapped(&[None, None]),
        Err(ColdError::Mapping)
    ));
    Ok(())
}
