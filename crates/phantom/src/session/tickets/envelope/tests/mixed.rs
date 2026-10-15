use super::*;

fn quic_header(physical: u8, records: u8) -> SessionTicketStoreHeader {
    // Storage framing only; these bytes grant no native ticket authority.
    let mut bytes = [0; 26];
    bytes[..8].copy_from_slice(b"PHQUIC01");
    bytes[9] = 1;
    bytes[10] = physical;
    bytes[11] = records;
    bytes[12] = 1;
    bytes[14..22].copy_from_slice(&3_u64.to_be_bytes());
    bytes[22..26].copy_from_slice(&42_u32.to_be_bytes());
    SessionTicketStoreHeader::Quic(
        QuicSessionStoreHeader::parse(&bytes).unwrap_or_else(fixture_failure),
    )
}

fn quic_empty<'a>(endpoint: &'a Endpoint, witness: &'a [u8]) -> OwnerInput<'a> {
    let mut owner = empty(endpoint, witness);
    owner.protocol = TicketCacheProtocol::Http3;
    owner.header = quic_header(0, 0);
    owner
}

fn opened_quic() -> OpenedManifest {
    let endpoint = origin();
    let sealed = seal_manifest(&KEY, &[quic_empty(&endpoint, b"draw")], &native_empty())
        .unwrap_or_else(fixture_failure);
    open_manifest(sealed.as_bytes(), &KEY).unwrap_or_else(fixture_failure)
}

fn owner_offsets(opened: &OpenedManifest) -> (usize, usize) {
    let mut reader = Reader(&opened.plaintext[4..]);
    reader.u16().unwrap_or_else(fixture_failure);
    reader.u16().unwrap_or_else(fixture_failure);
    reader.authority().unwrap_or_else(fixture_failure);
    reader.name().unwrap_or_else(fixture_failure);
    reader.u16().unwrap_or_else(fixture_failure);
    reader.name().unwrap_or_else(fixture_failure);
    reader.u8().unwrap_or_else(fixture_failure);
    let protocol = opened.plaintext.len() - reader.0.len();
    reader.u8().unwrap_or_else(fixture_failure);
    reader.u8().unwrap_or_else(fixture_failure);
    reader.field(MAX_POLICY).unwrap_or_else(fixture_failure);
    reader.field(MAX_POLICY).unwrap_or_else(fixture_failure);
    (protocol, opened.plaintext.len() - reader.0.len())
}

#[test]
fn mixed_empty_intents_preserve_header_kind_rtt_and_exact_frame_size() {
    let endpoint = origin();
    let native = native_empty();
    let tcp =
        seal_manifest(&KEY, &[empty(&endpoint, b"draw")], &native).unwrap_or_else(fixture_failure);
    let quic = seal_manifest(&KEY, &[quic_empty(&endpoint, b"draw")], &native)
        .unwrap_or_else(fixture_failure);
    assert_eq!(quic.as_bytes().len(), tcp.as_bytes().len() + 4);
    let sealed = seal_manifest(
        &KEY,
        &[empty(&endpoint, b"draw"), quic_empty(&endpoint, b"draw")],
        &native,
    )
    .unwrap_or_else(fixture_failure);
    assert_eq!(
        sealed.as_bytes().len(),
        tcp.as_bytes().len() + quic.as_bytes().len() - HEADER - TAG - 8 - native.as_bytes().len()
    );
    let opened = open_manifest(sealed.as_bytes(), &KEY).unwrap_or_else(fixture_failure);
    assert_eq!(opened.owner_count(), 2);
    assert_eq!(opened.record_count(), 0);
    let owners: Vec<_> = opened
        .owners()
        .map(|owner| owner.unwrap_or_else(fixture_failure))
        .collect();
    assert_eq!(owners[0].header, header(0, 0, u64::MAX));
    assert_eq!(owners[1].header, quic_header(0, 0));
    let SessionTicketStoreHeader::Quic(header) = owners[1].header else {
        panic!("expected QUIC storage header");
    };
    assert_eq!(
        header.round_trip_time(),
        Some(std::time::Duration::new(3, 42))
    );
    assert_eq!(opened.native_ciphertext(), native.as_bytes());
    assert_eq!(&sealed.as_bytes()[..10], b"PHOWN003\0\x03");
}

#[test]
fn store_kind_and_protocol_must_match_in_sealer_and_parser() {
    let endpoint = origin();
    let mut wrong = quic_empty(&endpoint, b"draw");
    wrong.protocol = TicketCacheProtocol::Http2;
    assert!(matches!(
        seal_manifest(&KEY, &[wrong], &native_empty()),
        Err(EnvelopeError::UnsupportedProtocol)
    ));
    for opened in [opened_empty(), opened_quic()] {
        let (protocol, _) = owner_offsets(&opened);
        let mut bytes = Zeroizing::new(opened.plaintext.to_vec());
        bytes[protocol] = if bytes[protocol] == 3 { 1 } else { 3 };
        assert!(matches!(
            validate_plaintext(&bytes, opened.native_backend()),
            Err(EnvelopeError::UnsupportedProtocol)
        ));
    }
}

#[test]
fn header_tags_lengths_canonical_bytes_and_truncation_are_checked() {
    for opened in [opened_empty(), opened_quic()] {
        let (_, store) = owner_offsets(&opened);
        let length = u32::from_be_bytes(
            opened.plaintext[store + 1..store + 5]
                .try_into()
                .unwrap_or_else(fixture_failure),
        ) as usize;
        for (offset, value) in [
            (store, 255),
            (store, 1 - opened.plaintext[store]),
            (store + 5, 0),
        ] {
            let mut bytes = Zeroizing::new(opened.plaintext.to_vec());
            bytes[offset] = value;
            assert!(matches!(
                validate_plaintext(&bytes, opened.native_backend()),
                Err(EnvelopeError::Malformed)
            ));
        }
        for wrong_length in [0, length - 1, length + 1] {
            let mut bytes = Zeroizing::new(opened.plaintext.to_vec());
            bytes[store + 1..store + 5].copy_from_slice(&(wrong_length as u32).to_be_bytes());
            assert!(validate_plaintext(&bytes, opened.native_backend()).is_err());
        }
        let mut oversized = Zeroizing::new(opened.plaintext.to_vec());
        oversized[store + 1..store + 5].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            validate_plaintext(&oversized, opened.native_backend()),
            Err(EnvelopeError::TooLarge)
        ));
        for end in store..store + 5 + length {
            assert!(validate_plaintext(&opened.plaintext[..end], opened.native_backend()).is_err());
        }
        let mut count = Zeroizing::new(opened.plaintext.to_vec());
        count[store + 5 + length] = 1;
        assert!(matches!(
            validate_plaintext(&count, opened.native_backend()),
            Err(EnvelopeError::Malformed)
        ));
    }
}

#[test]
fn mixed_slots_remain_dense_across_owners_and_preserve_transport_physical_holes() {
    // Structural mapping controls; the native zero-record frame grants no permit.
    let endpoint = origin();
    let a_slots = [RecordSlot {
        native_slot: 1,
        physical_ordinal: 8,
    }];
    let b_slots = [RecordSlot {
        native_slot: 0,
        physical_ordinal: 3,
    }];
    let mut tcp = empty(&endpoint, b"draw");
    tcp.header = header(10, 1, 4);
    tcp.slots = &a_slots;
    let mut quic = quic_empty(&endpoint, b"draw");
    quic.header = quic_header(4, 1);
    quic.slots = &b_slots;
    let sealed = seal_manifest(&KEY, &[tcp, quic], &native_empty()).unwrap_or_else(fixture_failure);
    let opened = open_manifest(sealed.as_bytes(), &KEY).unwrap_or_else(fixture_failure);
    let owners: Vec<_> = opened
        .owners()
        .map(|owner| owner.unwrap_or_else(fixture_failure))
        .collect();
    assert_eq!(owners[0].slots().collect::<Vec<_>>(), a_slots);
    assert_eq!(owners[1].slots().collect::<Vec<_>>(), b_slots);
    let mut duplicate = Zeroizing::new(opened.plaintext.to_vec());
    // The last owner has one slot immediately before the nested length field.
    let slot = opened.native_range.start - 4 - 3;
    duplicate[slot..slot + 2].copy_from_slice(&1_u16.to_be_bytes());
    assert!(matches!(
        validate_plaintext(&duplicate, opened.native_backend()),
        Err(EnvelopeError::Malformed)
    ));
    duplicate[slot..slot + 2].copy_from_slice(&0_u16.to_be_bytes());
    duplicate[slot + 2] = 4;
    assert!(matches!(
        validate_plaintext(&duplicate, opened.native_backend()),
        Err(EnvelopeError::Malformed)
    ));
}

#[test]
fn quic_store_bound_is_four_and_store_header_does_not_claim_record_version() {
    let SessionTicketStoreHeader::Quic(header) = quic_header(4, 1) else {
        panic!("expected QUIC header");
    };
    let mut overflow = header.to_bytes();
    overflow[10] = 5;
    assert!(QuicSessionStoreHeader::parse(&overflow).is_err());
    // V1/V2 live in per-record metadata, not this version-independent store shape.
    // These parser fixtures are not native sessions, envelopes or permits.
    for version in [1_u32, 0x6b33_43cf] {
        let mut bytes = header.to_bytes().to_vec();
        bytes.extend_from_slice(&[3, 0]);
        bytes.extend_from_slice(&version.to_be_bytes());
        bytes.extend_from_slice(&11_u16.to_be_bytes());
        bytes.extend_from_slice(&[0; 12]);
        bytes.extend_from_slice(b"origin.test");
        let record =
            phantom_net::QuicSessionRecordMetadata::parse(&bytes).unwrap_or_else(fixture_failure);
        assert_eq!(record.header(), header);
        assert_eq!(record.ordinal(), 3);
        record
            .validate_transport_parameters()
            .unwrap_or_else(fixture_failure);
    }
}

#[test]
fn previous_private_manifest_magic_and_version_are_rejected() {
    let endpoint = origin();
    let sealed = seal_manifest(&KEY, &[quic_empty(&endpoint, b"draw")], &native_empty())
        .unwrap_or_else(fixture_failure);
    for (magic, version) in [(b"PHOWN001", 1_u16), (b"PHOWN002", 2_u16)] {
        let mut old = sealed.as_bytes().to_vec();
        old[..8].copy_from_slice(magic);
        old[8..10].copy_from_slice(&version.to_be_bytes());
        assert!(matches!(
            open_manifest(&old, &KEY),
            Err(EnvelopeError::Malformed)
        ));
    }
}
