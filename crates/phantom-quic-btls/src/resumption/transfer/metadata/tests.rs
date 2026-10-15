use super::*;

fn checked<T>(result: Result<T, SessionTransferError>) -> T {
    result.unwrap_or_else(|error| panic!("metadata test setup failed: {error}"))
}

fn header(physical: usize, records: usize) -> QuicSessionStoreHeader {
    checked(QuicSessionStoreHeader::new(physical, records, None))
}

fn record(header: QuicSessionStoreHeader, ordinal: usize) -> QuicSessionRecordMetadata<'static> {
    checked(QuicSessionRecordMetadata::new(
        header,
        ordinal,
        "example.test",
        QuicVersion::V1,
        Some(&[1, 2]),
        Some(&[3, 4]),
        b"facade witness",
    ))
}

#[test]
fn headers_preserve_queue_shape_and_exact_optional_rtt() {
    for physical in 0..=MAX_SESSIONS {
        for records in 0..=physical {
            for rtt in [
                None,
                Some(Duration::ZERO),
                Some(Duration::new(u64::MAX, 999_999_999)),
            ] {
                let original = checked(QuicSessionStoreHeader::new(physical, records, rtt));
                let restored = checked(QuicSessionStoreHeader::parse(&original.to_bytes()));
                assert_eq!(restored, original);
                assert_eq!(restored.record_count(), records);
                assert_eq!(restored.excluded_expired_count(), physical - records);
                assert_eq!(restored.round_trip_time(), rtt);
            }
        }
    }
    assert!(QuicSessionStoreHeader::new(5, 0, None).is_err());
    assert!(QuicSessionStoreHeader::new(1, 2, None).is_err());
}

#[test]
fn headers_reject_noncanonical_fields_truncation_and_trailing_bytes() {
    let valid = header(4, 2).to_bytes();
    for len in 0..HEADER_LEN {
        assert!(QuicSessionStoreHeader::parse(&valid[..len]).is_err());
    }
    let mut trailing = valid.to_vec();
    trailing.push(0);
    assert!(QuicSessionStoreHeader::parse(&trailing).is_err());
    for (offset, value) in [
        (0, 0),
        (8, 1),
        (9, 2),
        (10, 5),
        (11, 5),
        (12, 2),
        (13, 1),
        (21, 1),
        (25, 1),
    ] {
        let mut bad = valid;
        bad[offset] = value;
        assert!(
            QuicSessionStoreHeader::parse(&bad).is_err(),
            "offset {offset}"
        );
    }
    let mut bad_nanos = valid;
    bad_nanos[12] = 1;
    bad_nanos[22..26].copy_from_slice(&1_000_000_000_u32.to_be_bytes());
    assert!(QuicSessionStoreHeader::parse(&bad_nanos).is_err());
}

#[test]
fn records_preserve_both_versions_and_all_optional_byte_states() {
    let options = [None, Some(&[][..]), Some(&[7, 8][..])];
    for version in [QuicVersion::V1, QuicVersion::V2] {
        for tp in options {
            for application in options {
                let original = checked(QuicSessionRecordMetadata::new(
                    header(4, 1),
                    3,
                    "Example.TEST",
                    version,
                    tp,
                    application,
                    b"witness",
                ));
                let bytes = checked(original.to_bytes());
                let restored = checked(QuicSessionRecordMetadata::parse(&bytes));
                assert_eq!(restored.header, original.header);
                assert_eq!(restored.ordinal, 3);
                assert_eq!(restored.hostname, "Example.TEST");
                assert_eq!(restored.version, version);
                assert_eq!(restored.peer_transport_parameters, tp);
                assert_eq!(restored.application_state, application);
                assert_eq!(restored.payload, b"witness");
                assert_eq!(&*checked(restored.to_bytes()), &*bytes);
            }
        }
    }
}

#[test]
fn records_reject_malformed_framing_and_unknown_versions() {
    let bytes = checked(record(header(4, 2), 3).to_bytes());
    for len in 0..bytes.len() {
        assert!(
            QuicSessionRecordMetadata::parse(&bytes[..len]).is_err(),
            "prefix {len}"
        );
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(QuicSessionRecordMetadata::parse(&trailing).is_err());
    for (offset, value) in [
        (HEADER_LEN, 4),
        (HEADER_LEN + 1, 4),
        (HEADER_LEN + 1, 2),
        (HEADER_LEN + 1, 1),
        (HEADER_LEN + 6, 255),
    ] {
        let mut bad = bytes.to_vec();
        bad[offset] = value;
        assert!(
            QuicSessionRecordMetadata::parse(&bad).is_err(),
            "offset {offset}"
        );
    }
    let mut bad_version = bytes.to_vec();
    bad_version[HEADER_LEN + 2..HEADER_LEN + 6].copy_from_slice(&0x1234_5678_u32.to_be_bytes());
    assert!(QuicSessionRecordMetadata::parse(&bad_version).is_err());
    let mut bad_payload_len = bytes.to_vec();
    bad_payload_len[HEADER_LEN + 16..HEADER_LEN + 20].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(QuicSessionRecordMetadata::parse(&bad_payload_len).is_err());
    let mut invalid_utf8 = bytes.to_vec();
    invalid_utf8[RECORD_FIXED_LEN] = 255;
    assert!(QuicSessionRecordMetadata::parse(&invalid_utf8).is_err());
}

#[test]
fn records_reject_invalid_names_and_out_of_range_physical_ordinals() {
    for name in ["", "nul\0.test", "nonascii-\u{e9}.test"] {
        assert!(
            QuicSessionRecordMetadata::new(header(1, 1), 0, name, QuicVersion::V1, None, None, &[])
                .is_err()
        );
    }
    let long_name = "a".repeat(254);
    assert!(
        QuicSessionRecordMetadata::new(
            header(1, 1),
            0,
            &long_name,
            QuicVersion::V1,
            None,
            None,
            &[]
        )
        .is_err()
    );
    assert!(
        QuicSessionRecordMetadata::new(
            header(1, 1),
            1,
            "example.test",
            QuicVersion::V1,
            None,
            None,
            &[]
        )
        .is_err()
    );
    assert!(
        QuicSessionRecordMetadata::new(
            header(1, 0),
            0,
            "example.test",
            QuicVersion::V1,
            None,
            None,
            &[]
        )
        .is_err()
    );
}

#[test]
fn complete_store_validation_preserves_gaps_and_rejects_reordering_or_other_owners() {
    let shape = header(4, 2);
    let values = [record(shape, 0), record(shape, 3)];
    checked(validate_store(shape, "example.test", &values));
    assert_eq!(values[1].ordinal, 3);
    assert!(validate_store(shape, "EXAMPLE.test", &values).is_err());
    assert!(validate_store(shape, "example.test", &values[..1]).is_err());
    assert!(validate_store(header(3, 2), "example.test", &values).is_err());
    assert!(validate_store(shape, "example.test", &[record(shape, 3), record(shape, 0)]).is_err());
    assert!(validate_store(shape, "example.test", &[record(shape, 0), record(shape, 0)]).is_err());
    let mut other_owner = record(shape, 3);
    other_owner.hostname = "other.test";
    assert!(validate_store(shape, "example.test", &[record(shape, 0), other_owner]).is_err());
    let mut other_header = record(shape, 3);
    other_header.header = header(4, 1);
    assert!(validate_store(shape, "example.test", &[record(shape, 0), other_header]).is_err());
}

#[test]
fn empty_replacement_and_all_expired_shape_remain_distinct() {
    let empty = header(0, 0);
    let expired = header(4, 0);
    checked(validate_store(empty, "example.test", &[]));
    checked(validate_store(expired, "example.test", &[]));
    assert_ne!(empty.to_bytes(), expired.to_bytes());
    assert!(validate_store(empty, "", &[]).is_err());
}

#[test]
fn protocol_byte_limits_are_enforced_on_both_encoding_and_parsing() {
    let tp = vec![0; MAX_PEER_TRANSPORT_PARAMETERS];
    let application = vec![0; MAX_APPLICATION_STATE_LEN];
    let valid = checked(QuicSessionRecordMetadata::new(
        header(1, 1),
        0,
        "example.test",
        QuicVersion::V2,
        Some(&tp),
        Some(&application),
        &[],
    ));
    let bytes = checked(valid.to_bytes());
    let decoded = checked(QuicSessionRecordMetadata::parse(&bytes));
    assert_eq!(
        decoded.peer_transport_parameters.map(<[u8]>::len),
        Some(tp.len())
    );
    assert_eq!(
        decoded.application_state.map(<[u8]>::len),
        Some(application.len())
    );
    let mut bad = bytes.to_vec();
    bad[HEADER_LEN + 8..HEADER_LEN + 12].copy_from_slice(&65_536_u32.to_be_bytes());
    assert!(matches!(
        QuicSessionRecordMetadata::parse(&bad),
        Err(SessionTransferError::TooLarge)
    ));
    bad = bytes.to_vec();
    bad[HEADER_LEN + 12..HEADER_LEN + 16].copy_from_slice(&1025_u32.to_be_bytes());
    assert!(matches!(
        QuicSessionRecordMetadata::parse(&bad),
        Err(SessionTransferError::TooLarge)
    ));
    let oversized_tp = vec![0; MAX_PEER_TRANSPORT_PARAMETERS + 1];
    assert!(matches!(
        QuicSessionRecordMetadata::new(
            header(1, 1),
            0,
            "example.test",
            QuicVersion::V1,
            Some(&oversized_tp),
            None,
            &[]
        ),
        Err(SessionTransferError::TooLarge)
    ));
    let oversized_app = vec![0; MAX_APPLICATION_STATE_LEN + 1];
    assert!(matches!(
        QuicSessionRecordMetadata::new(
            header(1, 1),
            0,
            "example.test",
            QuicVersion::V1,
            None,
            Some(&oversized_app),
            &[]
        ),
        Err(SessionTransferError::TooLarge)
    ));
}

#[test]
fn metadata_budget_counts_header_name_parameters_application_and_witness_jointly() {
    let tp = vec![0; MAX_PEER_TRANSPORT_PARAMETERS];
    let application = vec![0; MAX_APPLICATION_STATE_LEN];
    let name = "example.test";
    let budget = MAX_METADATA - RECORD_FIXED_LEN - name.len() - tp.len() - application.len();
    let witness = vec![0; budget];
    let value = checked(QuicSessionRecordMetadata::new(
        header(1, 1),
        0,
        name,
        QuicVersion::V1,
        Some(&tp),
        Some(&application),
        &witness,
    ));
    let bytes = checked(value.to_bytes());
    assert_eq!(bytes.len(), MAX_METADATA);
    checked(QuicSessionRecordMetadata::parse(&bytes));
    let oversized = vec![0; budget + 1];
    assert!(matches!(
        QuicSessionRecordMetadata::new(
            header(1, 1),
            0,
            name,
            QuicVersion::V1,
            Some(&tp),
            Some(&application),
            &oversized
        ),
        Err(SessionTransferError::TooLarge)
    ));
    let mut oversized_frame = bytes.to_vec();
    oversized_frame.push(0);
    assert!(matches!(
        QuicSessionRecordMetadata::parse(&oversized_frame),
        Err(SessionTransferError::TooLarge)
    ));
}

#[test]
fn debug_and_errors_do_not_print_metadata_byte_contents_or_hostnames() {
    let canary = format!("private-{}", std::process::id());
    let value = checked(QuicSessionRecordMetadata::new(
        header(1, 1),
        0,
        &canary,
        QuicVersion::V1,
        Some(canary.as_bytes()),
        Some(canary.as_bytes()),
        canary.as_bytes(),
    ));
    let debug = format!("{value:?}");
    assert!(debug.contains("QuicSessionRecordMetadata"));
    assert!(debug.contains("ordinal"));
    assert!(!debug.contains(&canary));
    let mut bytes = checked(value.to_bytes());
    bytes.push(0);
    match QuicSessionRecordMetadata::parse(&bytes) {
        Ok(_) => panic!("trailing byte accepted"),
        Err(error) => {
            assert!(!format!("{error:?}").contains(&canary));
            assert!(!error.to_string().contains(&canary));
        }
    }
}
