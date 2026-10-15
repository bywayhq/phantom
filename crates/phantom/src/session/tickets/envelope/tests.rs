use super::*;

const KEY: [u8; 32] = [7; 32];

fn fixture_failure<T>(error: impl std::fmt::Display) -> T {
    panic!("envelope fixture setup failed: {error}")
}

fn origin() -> Endpoint {
    Endpoint::new(
        "origin.test:443".parse().unwrap_or_else(fixture_failure),
        443,
    )
    .unwrap_or_else(fixture_failure)
}

fn header(physical: u8, records: u8, next_batch: u64) -> TcpSessionStoreHeader {
    let mut bytes = [0; STORE_HEADER];
    bytes[..8].copy_from_slice(b"PHTCP001");
    bytes[9] = 1;
    bytes[10] = 1;
    bytes[11] = 10;
    bytes[12] = physical;
    bytes[13] = records;
    bytes[14..].copy_from_slice(&next_batch.to_be_bytes());
    TcpSessionStoreHeader::parse(&bytes).unwrap_or_else(fixture_failure)
}

fn empty<'a>(origin: &'a Endpoint, witness: &'a [u8]) -> OwnerInput<'a> {
    OwnerInput {
        record_owner_index: 0,
        origin,
        server_name: "origin.test",
        leg: TicketCacheLeg::Origin,
        protocol: TicketCacheProtocol::Negotiated,
        policy: b"stable configured policy",
        source_witness: witness,
        has_credentials: false,
        header: header(0, 0, u64::MAX),
        slots: &[],
    }
}

fn native_empty() -> SessionTransferEnvelope {
    // Genuine canonical encrypted zero-record envelope; no native record is fabricated.
    btls::ssl::seal_envelope(&[], &KEY).unwrap_or_else(fixture_failure)
}

fn opened_empty() -> OpenedManifest {
    let endpoint = origin();
    let sealed = seal_manifest(&KEY, &[empty(&endpoint, b"source draw")], &native_empty())
        .unwrap_or_else(fixture_failure);
    open_manifest(sealed.as_bytes(), &KEY).unwrap_or_else(fixture_failure)
}

#[test]
fn empty_owner_intent_header_and_original_witness_survive_authenticated_roundtrip() {
    let endpoint = origin();
    let native = native_empty();
    let sealed = seal_manifest(&KEY, &[empty(&endpoint, b"source draw")], &native)
        .unwrap_or_else(fixture_failure);
    let opened = open_manifest(sealed.as_bytes(), &KEY).unwrap_or_else(fixture_failure);
    assert_eq!(opened.owner_count(), 1);
    assert_eq!(opened.record_count(), 0);
    assert_eq!(opened.native_ciphertext(), native.as_bytes());
    assert_eq!(
        opened.native_backend().as_slice(),
        &native.as_bytes()[8..40]
    );
    let owner = opened
        .owners()
        .next()
        .unwrap_or_else(|| panic!("manifest owner missing"))
        .unwrap_or_else(fixture_failure);
    assert_eq!(owner.index, 0);
    assert_eq!(owner.record_owner_index, 0);
    assert_eq!(owner.origin_authority, "origin.test:443");
    assert_eq!(owner.origin_host, "origin.test");
    assert_eq!(owner.origin_port, 443);
    assert_eq!(owner.server_name, "origin.test");
    assert_eq!(owner.policy, b"stable configured policy");
    assert_eq!(owner.source_witness, b"source draw");
    assert_eq!(owner.header.to_bytes(), header(0, 0, u64::MAX).to_bytes());
    assert_eq!(owner.slots().len(), 0);
    assert!(!owner.has_credentials);
}

#[test]
fn wrong_key_and_every_modified_envelope_byte_are_rejected() {
    let endpoint = origin();
    let sealed = seal_manifest(&KEY, &[empty(&endpoint, b"source draw")], &native_empty())
        .unwrap_or_else(fixture_failure);
    assert!(matches!(
        open_manifest(sealed.as_bytes(), &[8; 32]),
        Err(EnvelopeError::Authentication)
    ));
    for index in 0..sealed.as_bytes().len() {
        let mut changed = sealed.as_bytes().to_vec();
        changed[index] ^= 1;
        assert!(
            open_manifest(&changed, &KEY).is_err(),
            "altered byte {index}"
        );
    }
}

#[test]
fn every_truncation_and_external_trailing_bytes_are_rejected() {
    let endpoint = origin();
    let sealed = seal_manifest(&KEY, &[empty(&endpoint, b"source draw")], &native_empty())
        .unwrap_or_else(fixture_failure);
    for size in 0..sealed.as_bytes().len() {
        assert!(open_manifest(&sealed.as_bytes()[..size], &KEY).is_err());
    }
    let mut trailing = sealed.as_bytes().to_vec();
    trailing.push(0);
    assert!(matches!(
        open_manifest(&trailing, &KEY),
        Err(EnvelopeError::Malformed)
    ));
}

#[test]
fn random_nonce_changes_ciphertext_for_the_same_empty_manifest() {
    let endpoint = origin();
    let native = native_empty();
    let first = seal_manifest(&KEY, &[empty(&endpoint, b"source draw")], &native)
        .unwrap_or_else(fixture_failure);
    let second = seal_manifest(&KEY, &[empty(&endpoint, b"source draw")], &native)
        .unwrap_or_else(fixture_failure);
    assert_ne!(&first.as_bytes()[74..86], &second.as_bytes()[74..86]);
    assert_ne!(first.as_bytes(), second.as_bytes());
}

#[test]
fn empty_credentialed_owner_is_rejected_by_sealer_and_structural_parser() {
    let endpoint = origin();
    let mut owner = empty(&endpoint, b"source draw");
    owner.has_credentials = true;
    owner.leg = TicketCacheLeg::HttpProxy;
    assert!(matches!(
        seal_manifest(&KEY, &[owner], &native_empty()),
        Err(EnvelopeError::UnsupportedEmptyCredentials)
    ));
    // Structural parser input, not newly authenticated ciphertext.
    let opened = opened_empty();
    let mut bytes = Zeroizing::new(opened.plaintext.to_vec());
    let mut reader = Reader(&bytes[4..]);
    reader.u16().unwrap_or_else(fixture_failure);
    reader.u16().unwrap_or_else(fixture_failure);
    reader.authority().unwrap_or_else(fixture_failure);
    reader.name().unwrap_or_else(fixture_failure);
    reader.u16().unwrap_or_else(fixture_failure);
    reader.name().unwrap_or_else(fixture_failure);
    reader.u8().unwrap_or_else(fixture_failure);
    reader.u8().unwrap_or_else(fixture_failure);
    let flag = bytes.len() - reader.0.len();
    bytes[flag] = 1;
    assert!(matches!(
        validate_plaintext(&bytes, opened.native_backend()),
        Err(EnvelopeError::UnsupportedEmptyCredentials)
    ));
}

#[test]
fn duplicate_owner_identity_is_rejected_even_when_witnesses_differ() {
    let endpoint = origin();
    assert!(matches!(
        seal_manifest(
            &KEY,
            &[empty(&endpoint, b"draw a"), empty(&endpoint, b"draw b")],
            &native_empty()
        ),
        Err(EnvelopeError::Malformed)
    ));
    let mut other = empty(&endpoint, b"draw b");
    other.protocol = TicketCacheProtocol::Http1;
    let sealed = seal_manifest(&KEY, &[empty(&endpoint, b"draw a"), other], &native_empty())
        .unwrap_or_else(fixture_failure);
    assert_eq!(
        open_manifest(sealed.as_bytes(), &KEY)
            .unwrap_or_else(fixture_failure)
            .owner_count(),
        2
    );
}

#[test]
fn original_authority_distinguishes_owners_with_equal_host_and_effective_port() {
    let explicit = origin();
    let omitted = Endpoint::new("origin.test".parse().unwrap_or_else(fixture_failure), 443)
        .unwrap_or_else(fixture_failure);
    assert_ne!(explicit, omitted);
    assert_eq!(explicit.host(), omitted.host());
    assert_eq!(explicit.port(), omitted.port());
    let sealed = seal_manifest(
        &KEY,
        &[empty(&explicit, b"draw"), empty(&omitted, b"draw")],
        &native_empty(),
    )
    .unwrap_or_else(fixture_failure);
    let opened = open_manifest(sealed.as_bytes(), &KEY).unwrap_or_else(fixture_failure);
    let authorities: Vec<_> = opened
        .owners()
        .map(|owner| owner.unwrap_or_else(fixture_failure).origin_authority)
        .collect();
    assert_eq!(authorities, ["origin.test:443", "origin.test"]);
}

#[test]
fn whole_size_owner_count_record_count_and_field_bounds_are_enforced() {
    let oversized = vec![0; MAX_ENVELOPE + 1];
    assert!(matches!(
        open_manifest(&oversized, &KEY),
        Err(EnvelopeError::TooLarge)
    ));
    let endpoint = origin();
    let owners: Vec<_> = (0..=MAX_OWNERS)
        .map(|_| empty(&endpoint, b"draw"))
        .collect();
    assert!(matches!(
        seal_manifest(&KEY, &owners, &native_empty()),
        Err(EnvelopeError::TooLarge)
    ));
    let mut body = [0; 4];
    body[..2].copy_from_slice(&((MAX_OWNERS + 1) as u16).to_be_bytes());
    assert!(matches!(
        validate_plaintext(&body, &[0; 32]),
        Err(EnvelopeError::TooLarge)
    ));
    body[..2].fill(0);
    body[2..].copy_from_slice(&((MAX_RECORDS + 1) as u16).to_be_bytes());
    assert!(matches!(
        validate_plaintext(&body, &[0; 32]),
        Err(EnvelopeError::TooLarge)
    ));
    assert!(matches!(
        Reader(&u32::MAX.to_be_bytes()).field(MAX_POLICY),
        Err(EnvelopeError::TooLarge)
    ));
}

#[test]
fn combined_owner_fields_cannot_exceed_the_whole_envelope_bound() {
    let endpoint = origin();
    let policies: Vec<_> = (0..9)
        .map(|tag| {
            let mut policy = Zeroizing::new(vec![0; MAX_POLICY]);
            policy[0] = tag;
            policy
        })
        .collect();
    let owners: Vec<_> = policies
        .iter()
        .map(|policy| {
            let mut owner = empty(&endpoint, policy);
            owner.policy = policy;
            owner
        })
        .collect();
    assert!(matches!(
        seal_manifest(&KEY, &owners, &native_empty()),
        Err(EnvelopeError::TooLarge)
    ));
}

#[test]
fn tcp_manifest_rejects_http3_owner_without_claiming_quic_authority() {
    let endpoint = origin();
    let mut owner = empty(&endpoint, b"draw");
    owner.protocol = TicketCacheProtocol::Http3;
    assert!(matches!(
        seal_manifest(&KEY, &[owner], &native_empty()),
        Err(EnvelopeError::UnsupportedProtocol)
    ));
}

fn validate_slots(slots: &[RecordSlot], records: usize, physical: u8) -> Result<(), EnvelopeError> {
    // Structural controls only; no native session/record/permit is fabricated.
    let mut validation = Validation::new(records);
    validation.owner(
        "origin.test:443",
        "origin.test",
        443,
        "origin.test",
        TicketCacheLeg::Origin,
        TicketCacheProtocol::Http2,
        b"stable policy",
        b"draw",
        false,
        header(physical, slots.len() as u8, 4),
        slots.iter().copied(),
    )?;
    validation.finish()
}

#[test]
fn slots_cover_exact_native_indices_and_preserve_physical_holes() {
    let slots = [
        RecordSlot {
            native_slot: 1,
            physical_ordinal: 0,
        },
        RecordSlot {
            native_slot: 0,
            physical_ordinal: 2,
        },
    ];
    assert!(validate_slots(&slots, 2, 3).is_ok());
    assert!(matches!(
        validate_slots(&slots, 3, 3),
        Err(EnvelopeError::Malformed)
    ));
    let out_of_range = [RecordSlot {
        native_slot: 2,
        physical_ordinal: 0,
    }];
    assert!(matches!(
        validate_slots(&out_of_range, 1, 1),
        Err(EnvelopeError::Malformed)
    ));
}

#[test]
fn duplicate_slots_reversed_ordinals_and_ordinal_overflow_are_rejected() {
    for slots in [
        [
            RecordSlot {
                native_slot: 0,
                physical_ordinal: 0,
            },
            RecordSlot {
                native_slot: 0,
                physical_ordinal: 1,
            },
        ],
        [
            RecordSlot {
                native_slot: 0,
                physical_ordinal: 1,
            },
            RecordSlot {
                native_slot: 1,
                physical_ordinal: 0,
            },
        ],
        [
            RecordSlot {
                native_slot: 0,
                physical_ordinal: 0,
            },
            RecordSlot {
                native_slot: 1,
                physical_ordinal: 2,
            },
        ],
    ] {
        assert!(matches!(
            validate_slots(&slots, 2, 2),
            Err(EnvelopeError::Malformed)
        ));
    }
}

#[test]
fn duplicate_native_slot_across_distinct_owners_is_rejected() {
    let slot = RecordSlot {
        native_slot: 0,
        physical_ordinal: 0,
    };
    let mut validation = Validation::new(2);
    for host in ["origin.test", "second.test"] {
        let result = validation.owner(
            host,
            host,
            443,
            host,
            TicketCacheLeg::Origin,
            TicketCacheProtocol::Http2,
            b"stable policy",
            b"draw",
            false,
            header(1, 1, 4),
            [slot].into_iter(),
        );
        if host == "origin.test" {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(EnvelopeError::Malformed)));
        }
    }
}

#[test]
fn plaintext_parser_rejects_trailing_data_and_nested_backend_changes() {
    // Direct structural mutations supplement the independent AEAD tamper control.
    let opened = opened_empty();
    let mut bytes = Zeroizing::new(opened.plaintext.to_vec());
    bytes.push(0);
    assert!(matches!(
        validate_plaintext(&bytes, opened.native_backend()),
        Err(EnvelopeError::Malformed)
    ));
    bytes.pop();
    bytes[opened.native_range.start + 8] ^= 1;
    assert!(matches!(
        validate_plaintext(&bytes, opened.native_backend()),
        Err(EnvelopeError::Malformed)
    ));
}

#[test]
fn unknown_tags_indices_invalid_names_and_store_frames_are_rejected() {
    let opened = opened_empty();
    let mut reader = Reader(&opened.plaintext[4..]);
    reader.u16().unwrap_or_else(fixture_failure);
    reader.u16().unwrap_or_else(fixture_failure);
    reader.authority().unwrap_or_else(fixture_failure);
    reader.name().unwrap_or_else(fixture_failure);
    reader.u16().unwrap_or_else(fixture_failure);
    reader.name().unwrap_or_else(fixture_failure);
    let leg = opened.plaintext.len() - reader.0.len();
    for offset in [leg, leg + 1, leg + 2] {
        let mut bytes = Zeroizing::new(opened.plaintext.to_vec());
        bytes[offset] = 255;
        assert!(matches!(
            validate_plaintext(&bytes, opened.native_backend()),
            Err(EnvelopeError::Malformed)
        ));
    }
    let mut bytes = Zeroizing::new(opened.plaintext.to_vec());
    bytes[5] = 1;
    assert!(matches!(
        validate_plaintext(&bytes, opened.native_backend()),
        Err(EnvelopeError::Malformed)
    ));
    assert!(!name_valid(""));
    assert!(!name_valid("host\0name"));
    assert!(!name_valid("höst"));
    for authority in [
        "",
        "user@host",
        "host name",
        "host\tname",
        "host\0name",
        "höst",
    ] {
        assert!(!authority_valid(authority));
    }
    assert!(!authority_valid(&"a".repeat(MAX_AUTHORITY + 1)));
    assert!(TcpSessionStoreHeader::parse(&[0; STORE_HEADER]).is_err());
}

#[test]
fn zero_owner_manifest_is_authenticated_and_cannot_imply_a_store_clear() {
    let native = native_empty();
    let sealed = seal_manifest(&KEY, &[], &native).unwrap_or_else(fixture_failure);
    let opened = open_manifest(sealed.as_bytes(), &KEY).unwrap_or_else(fixture_failure);
    assert_eq!(opened.owner_count(), 0);
    assert_eq!(opened.record_count(), 0);
    assert!(opened.owners().next().is_none());
    assert_eq!(opened.native_ciphertext(), native.as_bytes());
}

#[test]
fn record_owner_indices_survive_dense_manifest_reordering() {
    let first = origin();
    let second = Endpoint::new(
        "second.test:443".parse().unwrap_or_else(fixture_failure),
        443,
    )
    .unwrap_or_else(fixture_failure);
    let native = native_empty();
    let mut a = empty(&first, b"first original witness");
    let mut b = empty(&second, b"second original witness");
    a.record_owner_index = 42;
    b.record_owner_index = 17;
    let original = seal_manifest(&KEY, &[a, b], &native).unwrap_or_else(fixture_failure);
    let original = open_manifest(original.as_bytes(), &KEY).unwrap_or_else(fixture_failure);
    let before: Vec<_> = original
        .owners()
        .map(|owner| {
            let owner = owner.unwrap_or_else(fixture_failure);
            (
                owner.index,
                owner.record_owner_index,
                owner.origin_authority,
                owner.source_witness,
            )
        })
        .collect();
    assert_eq!(
        before,
        [
            (0, 42, "origin.test:443", &b"first original witness"[..]),
            (1, 17, "second.test:443", &b"second original witness"[..])
        ]
    );
    let mut a = empty(&first, b"first original witness");
    let mut b = empty(&second, b"second original witness");
    a.record_owner_index = 42;
    b.record_owner_index = 17;
    let reordered = seal_manifest(&KEY, &[b, a], &native).unwrap_or_else(fixture_failure);
    let reordered = open_manifest(reordered.as_bytes(), &KEY).unwrap_or_else(fixture_failure);
    let after: Vec<_> = reordered
        .owners()
        .map(|owner| {
            let owner = owner.unwrap_or_else(fixture_failure);
            (
                owner.index,
                owner.record_owner_index,
                owner.origin_authority,
                owner.source_witness,
            )
        })
        .collect();
    assert_eq!(
        after,
        [
            (0, 17, "second.test:443", &b"second original witness"[..]),
            (1, 42, "origin.test:443", &b"first original witness"[..])
        ]
    );
    assert_eq!(original.native_ciphertext(), reordered.native_ciphertext());
}

#[test]
fn repeated_original_indices_allow_distinct_owners_but_require_exact_unique_slots() {
    // Structural manifest only, as in the existing record mapping controls.
    // The empty native frame is not a fabricated ticket or an import permit.
    let first = origin();
    let second = Endpoint::new(
        "second.test:443".parse().unwrap_or_else(fixture_failure),
        443,
    )
    .unwrap_or_else(fixture_failure);
    let a_slots = [RecordSlot {
        native_slot: 1,
        physical_ordinal: 0,
    }];
    let b_slots = [RecordSlot {
        native_slot: 0,
        physical_ordinal: 0,
    }];
    let mut a = empty(&first, b"first draw");
    let mut b = empty(&second, b"second draw");
    a.record_owner_index = 7;
    b.record_owner_index = 7;
    a.header = header(1, 1, 1);
    b.header = header(1, 1, 1);
    a.slots = &a_slots;
    b.slots = &b_slots;
    let sealed = seal_manifest(&KEY, &[a, b], &native_empty()).unwrap_or_else(fixture_failure);
    let opened = open_manifest(sealed.as_bytes(), &KEY).unwrap_or_else(fixture_failure);
    let owners: Vec<_> = opened
        .owners()
        .map(|owner| owner.unwrap_or_else(fixture_failure))
        .collect();
    assert_eq!(owners[0].index, 0);
    assert_eq!(owners[1].index, 1);
    assert_eq!(owners[0].record_owner_index, 7);
    assert_eq!(owners[1].record_owner_index, 7);
    assert_eq!(owners[0].slots().collect::<Vec<_>>(), a_slots);
    assert_eq!(owners[1].slots().collect::<Vec<_>>(), b_slots);
    let mut a = empty(&first, b"first draw");
    let mut b = empty(&second, b"second draw");
    for owner in [&mut a, &mut b] {
        owner.record_owner_index = 7;
        owner.header = header(1, 1, 1);
        owner.slots = &a_slots;
    }
    assert!(matches!(
        seal_manifest(&KEY, &[a, b], &native_empty()),
        Err(EnvelopeError::Malformed)
    ));
    let mut missing = empty(&first, b"first draw");
    missing.record_owner_index = 7;
    missing.header = header(1, 1, 1);
    missing.slots = &a_slots;
    assert!(matches!(
        seal_manifest(&KEY, &[missing], &native_empty()),
        Err(EnvelopeError::Malformed)
    ));
}

#[test]
fn original_index_bounds_and_old_private_format_are_rejected() {
    let endpoint = origin();
    let native = native_empty();
    let mut owner = empty(&endpoint, b"draw");
    owner.record_owner_index = (MAX_OWNERS - 1) as u16;
    let sealed = seal_manifest(&KEY, &[owner], &native).unwrap_or_else(fixture_failure);
    let opened = open_manifest(sealed.as_bytes(), &KEY).unwrap_or_else(fixture_failure);
    assert_eq!(
        opened
            .owners()
            .next()
            .unwrap_or_else(|| panic!("manifest owner missing"))
            .unwrap_or_else(fixture_failure)
            .record_owner_index,
        255
    );
    let mut too_large = empty(&endpoint, b"draw");
    too_large.record_owner_index = MAX_OWNERS as u16;
    assert!(matches!(
        seal_manifest(&KEY, &[too_large], &native),
        Err(EnvelopeError::Malformed)
    ));
    let mut plaintext = Zeroizing::new(opened.plaintext.to_vec());
    plaintext[6..8].copy_from_slice(&(MAX_OWNERS as u16).to_be_bytes());
    assert!(matches!(
        validate_plaintext(&plaintext, opened.native_backend()),
        Err(EnvelopeError::Malformed)
    ));
    // The outer header stays fixed-size; the new field adds two bytes per owner.
    assert_eq!(
        sealed.as_bytes().len(),
        HEADER
            + TAG
            + 4
            + 2
            + 2
            + 2
            + 1
            + 1
            + 1
            + STORE_HEADER
            + 1
            + 20
            + endpoint.authority().as_str().len()
            + endpoint.host().len()
            + "origin.test".len()
            + b"stable configured policy".len()
            + b"draw".len()
            + 4
            + native.as_bytes().len()
    );
    let mut old = sealed.as_bytes().to_vec();
    old[..8].copy_from_slice(b"PHOWN001");
    old[8..10].copy_from_slice(&1_u16.to_be_bytes());
    assert!(matches!(
        open_manifest(&old, &KEY),
        Err(EnvelopeError::Malformed)
    ));
}
