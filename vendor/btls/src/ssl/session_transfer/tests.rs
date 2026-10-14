use super::*;

#[test]
fn transfer_preparation_bounds_and_redaction_are_explicit() {
    assert!(matches!(
        SessionTransferCredential::from_canonical_hmac_input(&vec![0; MAX_CREDENTIAL + 1]),
        Err(SessionTransferError::TooLarge)
    ));
    assert!(matches!(
        SessionTransferPolicy::new(&vec![0; MAX_POLICY + 1], &[], None, &[1; 32]),
        Err(SessionTransferError::TooLarge)
    ));
    assert!(matches!(
        SessionTransferPolicy::new(&[], &vec![0; MAX_POLICY + 1], None, &[1; 32]),
        Err(SessionTransferError::TooLarge)
    ));
    let input =
        SessionTransferCredential::from_canonical_hmac_input(b"synthetic-password").unwrap();
    assert_eq!(format!("{input:?}"), "SessionTransferCredential { .. }");
    let policy = SessionTransferPolicy::new(b"policy", b"witness", Some(input), &[1; 32]).unwrap();
    assert_eq!(format!("{policy:?}"), "SessionTransferPolicy { .. }");
}

#[test]
fn transfer_writer_never_grows_secret_allocations() {
    let mut writer = Writer::new(4).unwrap();
    let capacity = writer.bytes.capacity();
    writer.raw(&[1, 2, 3, 4]).unwrap();
    assert!(matches!(
        writer.raw(&[5]),
        Err(SessionTransferError::TooLarge)
    ));
    assert_eq!(writer.bytes.capacity(), capacity);
    assert_eq!(writer.bytes.len(), 4);
    let mut reader = Reader(&[0, 0, 0, 5, 1]);
    assert!(matches!(
        reader.field(4),
        Err(SessionTransferError::TooLarge)
    ));
    assert!(matches!(
        Reader(&[2]).boolean(),
        Err(SessionTransferError::Malformed)
    ));
    assert!(matches!(
        Reader(&[]).take(1),
        Err(SessionTransferError::Malformed)
    ));
}

#[test]
fn transfer_empty_envelope_authentication_and_whole_input_are_checked() {
    let context = super::super::SslContext::builder(super::super::SslMethod::tls())
        .unwrap()
        .build();
    let snapshot = seal_envelope(&[], &[1; 32]).unwrap();
    assert_eq!(
        open_envelope(snapshot.as_bytes(), &[1; 32], &context)
            .unwrap()
            .record_count(),
        0
    );
    assert!(matches!(
        open_envelope(snapshot.as_bytes(), &[2; 32], &context),
        Err(SessionTransferError::Authentication)
    ));
    for end in 0..snapshot.as_bytes().len() {
        assert!(open_envelope(&snapshot.as_bytes()[..end], &[1; 32], &context).is_err());
    }
    let mut trailing = snapshot.as_bytes().to_vec();
    trailing.push(0);
    assert!(matches!(
        open_envelope(&trailing, &[1; 32], &context),
        Err(SessionTransferError::Malformed)
    ));
    let mut changed = snapshot.as_bytes().to_vec();
    changed[8] ^= 1;
    assert!(matches!(
        open_envelope(&changed, &[1; 32], &context),
        Err(SessionTransferError::IncompatibleBackend)
    ));
    let mut changed = snapshot.as_bytes().to_vec();
    changed[HEADER] ^= 1;
    assert!(matches!(
        open_envelope(&changed, &[1; 32], &context),
        Err(SessionTransferError::Authentication)
    ));
}

#[test]
fn transfer_same_key_sealing_rejects_forged_record_mac_without_mutating_source() {
    let body = copy(b"synthetic malformed attacker body", MAX_ENVELOPE).unwrap();
    let original = body.clone();
    let record = AuthenticatedSessionRecord {
        body,
        mac: [0; 32],
        expires_at: u64::MAX,
    };
    assert!(matches!(
        seal_envelope(std::slice::from_ref(&record), &[1; 32]),
        Err(SessionTransferError::Authentication)
    ));
    assert_eq!(record.body.as_slice(), original.as_slice());
    assert_eq!(record.mac, [0; 32]);
}

#[test]
fn transfer_authenticated_malformed_native_record_never_grants_import_authority() {
    // A custody key holder can forge envelopes. Authentication cannot make
    // malformed native bytes or invalid record framing safe to attach.
    let mut body = Writer::new(128).unwrap();
    body.raw(&1_u16.to_be_bytes()).unwrap();
    body.raw(&[0; 32]).unwrap();
    body.raw(&[0]).unwrap();
    body.raw(&[1; 32]).unwrap();
    body.field(b"example.test").unwrap();
    body.raw(&[0]).unwrap();
    body.field(&[]).unwrap();
    body.field(b"metadata").unwrap();
    body.field(b"not a native session").unwrap();
    let mac = hmac_sha256(
        &*key(&[7; 32], b"phantom-ticket-record-v1").unwrap(),
        &body.bytes,
    )
    .unwrap();
    let record = AuthenticatedSessionRecord {
        body: body.bytes,
        mac,
        expires_at: u64::MAX,
    };
    let envelope = seal_envelope(&[record], &[7; 32]).unwrap();
    let context = super::super::SslContext::builder(super::super::SslMethod::tls())
        .unwrap()
        .build();
    assert!(matches!(
        open_envelope(envelope.as_bytes(), &[7; 32], &context),
        Err(SessionTransferError::Backend(_))
    ));
    assert!(matches!(
        Record::parse(&[0; 2]),
        Err(SessionTransferError::Malformed)
    ));
}

#[test]
fn transfer_source_witness_field_bound_rejects_before_native_decode() {
    let mut body = Writer::new(100).unwrap();
    body.raw(&1_u16.to_be_bytes()).unwrap();
    body.raw(&[0; 32]).unwrap();
    body.raw(&[0]).unwrap();
    body.raw(&[1; 32]).unwrap();
    body.field(b"example.test").unwrap();
    body.raw(&[0]).unwrap();
    body.raw(&u32::try_from(MAX_POLICY + 1).unwrap().to_be_bytes())
        .unwrap();
    assert!(matches!(
        Record::parse(&body.bytes),
        Err(SessionTransferError::TooLarge)
    ));
}
