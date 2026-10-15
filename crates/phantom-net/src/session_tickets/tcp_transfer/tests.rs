use super::*;

const HEADER: &[u8; 22] = b"PHTCP001\x00\x01\x01\x02\x02\x01\x00\x00\x00\x00\x00\x00\x00\x09";

fn metadata() -> Vec<u8> {
    // Independent byte layout: ordinal 1, batch 2, sequence 4, no flags,
    // exact hostname a.test and opaque payload xyz.
    let mut bytes = HEADER.to_vec();
    bytes.extend_from_slice(b"\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x04\x00\x00\x06a.test\x00\x00\x00\x03xyz");
    bytes
}

#[test]
fn complete_metadata_preserves_ordinal_counter_and_payload_without_normalization() {
    let bytes = metadata();
    let parsed = TcpSessionRecordMetadata::parse(&bytes)
        .unwrap_or_else(|error| panic!("independent metadata frame rejected: {error}"));
    assert_eq!(parsed.header().to_bytes(), *HEADER);
    assert_eq!(parsed.header().record_count(), 1);
    assert_eq!(parsed.header().excluded_expired_count(), 1);
    assert_eq!(parsed.ordinal(), 1);
    assert_eq!(parsed.batch, 2);
    assert_eq!(parsed.sequence, 4);
    assert_eq!(parsed.hostname(), "a.test");
    assert_eq!(parsed.payload(), b"xyz");
    assert!(!format!("{parsed:?}").contains("xyz"));
    assert!(!format!("{parsed:?}").contains("a.test"));
}

#[test]
fn every_truncation_and_trailing_byte_is_rejected() {
    let bytes = metadata();
    for end in 0..bytes.len() {
        assert!(
            TcpSessionRecordMetadata::parse(&bytes[..end]).is_err(),
            "prefix {end}"
        );
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(TcpSessionRecordMetadata::parse(&trailing).is_err());
    for end in 0..HEADER.len() {
        assert!(TcpSessionStoreHeader::parse(&HEADER[..end]).is_err());
    }
}

#[test]
fn unknown_versions_orders_flags_and_inconsistent_counts_are_rejected() {
    for (index, value) in [
        (0, 0),
        (9, 2),
        (10, 3),
        (11, 0),
        (11, 11),
        (12, 3),
        (13, 3),
        (35, 1),
        (22, 2),
    ] {
        let mut bytes = metadata();
        bytes[index] = value;
        assert!(
            TcpSessionRecordMetadata::parse(&bytes).is_err(),
            "index {index} value {value}"
        );
    }
    let mut bytes = metadata();
    bytes[23..31].copy_from_slice(&9u64.to_be_bytes());
    assert!(TcpSessionRecordMetadata::parse(&bytes).is_err());
    let mut bytes = metadata();
    bytes[14..22].fill(0);
    assert!(TcpSessionRecordMetadata::parse(&bytes).is_err());
}

#[test]
fn hostname_and_record_size_limits_are_explicit_and_payload_lengths_are_strict() {
    for name in ["", "\0", "ÃƒÂ©"] {
        assert!(validate_hostname(name).is_err());
    }
    assert!(validate_hostname(&"a".repeat(253)).is_ok());
    assert!(validate_hostname(&"a".repeat(254)).is_err());
    let mut bytes = metadata();
    bytes[38] = 0;
    assert!(TcpSessionRecordMetadata::parse(&bytes).is_err());
    let mut bytes = metadata();
    bytes[44..48].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(TcpSessionRecordMetadata::parse(&bytes).is_err());
    assert!(matches!(
        TcpSessionRecordMetadata::parse(&vec![0; MAX_METADATA + 1]),
        Err(SessionTransferError::TooLarge)
    ));
}

#[test]
fn empty_store_may_retain_exhausted_counter_but_cannot_claim_records() {
    let bytes = b"PHTCP001\x00\x01\x00\x02\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff";
    let parsed = TcpSessionStoreHeader::parse(bytes)
        .unwrap_or_else(|error| panic!("empty exhausted store rejected: {error}"));
    assert_eq!(parsed.next_batch, u64::MAX);
    assert_eq!(parsed.to_bytes(), *bytes);
    let mut forged = *bytes;
    forged[13] = 1;
    assert!(TcpSessionStoreHeader::parse(&forged).is_err());
}
