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

fn freeze_client() -> super::super::SslConnector {
    let mut builder =
        super::super::SslConnector::bare_builder(super::super::SslMethod::tls()).unwrap();
    builder.set_verify(super::super::SslVerifyMode::PEER);
    builder.enable_scoped_client_sessions();
    builder.build()
}

fn freeze_binding(
    client: &super::super::SslConnector,
    scope: &SslSessionScope,
) -> SessionPolicyBinding {
    scope
        .bind_transfer_policy(
            client.context(),
            "example.test",
            SessionTransferPolicy::new(b"policy", b"witness", None, &[1; 32]).unwrap(),
        )
        .unwrap()
}

#[test]
fn transfer_freeze_deduplicates_shared_context_and_requires_exact_membership() {
    let client = freeze_client();
    let first = freeze_binding(&client, &SslSessionScope::default());
    let second = freeze_binding(&client, &SslSessionScope::default());
    let unlisted = freeze_binding(&client, &SslSessionScope::default());
    let first_copy = first.clone();
    let prepared = PreparedSessionPolicyFreeze::new(&[&second, &first, &first_copy]).unwrap();
    assert_eq!(prepared.contexts.len(), 1);
    assert_eq!(prepared.scopes.len(), 2);
    let context_capacity = prepared.context_guards.capacity();
    let scope_capacity = prepared.scope_guards.capacity();
    let frozen = prepared.try_freeze().unwrap();
    assert_eq!(frozen.0.context_guards.capacity(), context_capacity);
    assert_eq!(frozen.0.scope_guards.capacity(), scope_capacity);
    assert_eq!(frozen.0.context_guards.len(), 1);
    assert_eq!(frozen.0.scope_guards.len(), 2);
    frozen.validate_binding(&first, "example.test").unwrap();
    frozen
        .validate_binding(&first_copy, "EXAMPLE.TEST")
        .unwrap();
    frozen.validate_binding(&second, "example.test").unwrap();
    assert!(matches!(
        frozen.validate_binding(&unlisted, "example.test"),
        Err(SessionTransferError::Policy)
    ));
    assert!(matches!(
        frozen.validate_binding(&first, "other.test"),
        Err(SessionTransferError::Policy)
    ));
    assert!(matches!(
        first.installed.epoch_owner.freeze(),
        Err(SessionTransferError::Busy)
    ));
    assert!(matches!(
        try_policy_lock(&first.scope.0.installed),
        Err(SessionTransferError::Busy)
    ));
    drop(frozen);
    assert!(first.installed.epoch_owner.freeze().is_ok());
    assert!(try_policy_lock(&first.scope.0.installed).is_ok());
}

#[test]
fn transfer_freeze_context_contention_releases_earlier_guards() {
    let left = freeze_client();
    let right = freeze_client();
    let first = freeze_binding(&left, &SslSessionScope::default());
    let second = freeze_binding(&right, &SslSessionScope::default());
    let prepared = PreparedSessionPolicyFreeze::new(&[&second, &first]).unwrap();
    let earlier = prepared.contexts[0];
    let later = prepared.contexts[1];
    let held = later.freeze().unwrap();
    assert!(matches!(
        prepared.try_freeze(),
        Err(SessionTransferError::Busy)
    ));
    assert!(earlier.freeze().is_ok());
    assert!(try_policy_lock(&first.scope.0.installed).is_ok());
    assert!(try_policy_lock(&second.scope.0.installed).is_ok());
    drop(held);
    assert!(PreparedSessionPolicyFreeze::new(&[&first, &second])
        .unwrap()
        .try_freeze()
        .is_ok());
}

#[test]
fn transfer_freeze_scope_contention_releases_context_and_earlier_scope_guards() {
    let client = freeze_client();
    let first = freeze_binding(&client, &SslSessionScope::default());
    let second = freeze_binding(&client, &SslSessionScope::default());
    let prepared = PreparedSessionPolicyFreeze::new(&[&first, &second]).unwrap();
    let earlier = prepared.scopes[0];
    let later = prepared.scopes[1];
    let held = try_policy_lock(&later.installed).unwrap();
    assert!(matches!(
        prepared.try_freeze(),
        Err(SessionTransferError::Busy)
    ));
    assert!(first.installed.epoch_owner.freeze().is_ok());
    assert!(try_policy_lock(&earlier.installed).is_ok());
    drop(held);
    assert!(PreparedSessionPolicyFreeze::new(&[&second, &first])
        .unwrap()
        .try_freeze()
        .is_ok());
}

#[test]
fn transfer_freeze_poisoned_context_is_policy_failure_and_releases_prior_guard() {
    let left = freeze_client();
    let right = freeze_client();
    let first = freeze_binding(&left, &SslSessionScope::default());
    let second = freeze_binding(&right, &SslSessionScope::default());
    let prepared = PreparedSessionPolicyFreeze::new(&[&first, &second]).unwrap();
    let earlier = prepared.contexts[0];
    let later = prepared.contexts[1];
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = later.0.lock().unwrap();
        panic!("synthetic Rust mutex poison");
    }));
    assert!(panic.is_err());
    assert!(matches!(
        prepared.try_freeze(),
        Err(SessionTransferError::Policy)
    ));
    assert!(earlier.freeze().is_ok());
    assert!(matches!(later.freeze(), Err(SessionTransferError::Policy)));
    assert!(try_policy_lock(&first.scope.0.installed).is_ok());
    assert!(try_policy_lock(&second.scope.0.installed).is_ok());
}

#[test]
fn transfer_freeze_poisoned_scope_is_policy_failure_and_releases_prior_guards() {
    let client = freeze_client();
    let first = freeze_binding(&client, &SslSessionScope::default());
    let second = freeze_binding(&client, &SslSessionScope::default());
    let prepared = PreparedSessionPolicyFreeze::new(&[&first, &second]).unwrap();
    let earlier = prepared.scopes[0];
    let later = prepared.scopes[1];
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = later.installed.lock().unwrap();
        panic!("synthetic Rust mutex poison");
    }));
    assert!(panic.is_err());
    assert!(matches!(
        prepared.try_freeze(),
        Err(SessionTransferError::Policy)
    ));
    assert!(first.installed.epoch_owner.freeze().is_ok());
    assert!(try_policy_lock(&earlier.installed).is_ok());
    assert!(matches!(
        try_policy_lock(&later.installed),
        Err(SessionTransferError::Policy)
    ));
}

#[test]
fn transfer_freeze_checks_guarded_epoch_and_installed_identity() {
    let client = freeze_client();
    let binding = freeze_binding(&client, &SslSessionScope::default());
    let other = freeze_binding(&client, &SslSessionScope::default());
    let mut frozen = PreparedSessionPolicyFreeze::new(&[&binding])
        .unwrap()
        .try_freeze()
        .unwrap();
    frozen.validate_binding(&binding, "example.test").unwrap();
    *frozen.0.context_guards[0] = Some(Arc::new(AtomicBool::new(true)));
    assert!(matches!(
        frozen.validate_binding(&binding, "example.test"),
        Err(SessionTransferError::Policy)
    ));
    *frozen.0.context_guards[0] = Some(Arc::clone(&binding.installed.context_epoch));
    *frozen.0.scope_guards[0] = Some(Arc::clone(&other.installed));
    assert!(matches!(
        frozen.validate_binding(&binding, "example.test"),
        Err(SessionTransferError::Policy)
    ));
    *frozen.0.scope_guards[0] = Some(Arc::clone(&binding.installed));
    frozen.validate_binding(&binding, "example.test").unwrap();
}

#[test]
fn transfer_freeze_empty_plan_and_input_bound_are_explicit() {
    let frozen = PreparedSessionPolicyFreeze::new(&[])
        .unwrap()
        .try_freeze()
        .unwrap();
    assert!(frozen.0.context_guards.is_empty());
    assert!(frozen.0.scope_guards.is_empty());
    let client = freeze_client();
    let binding = freeze_binding(&client, &SslSessionScope::default());
    assert!(matches!(
        frozen.validate_binding(&binding, "example.test"),
        Err(SessionTransferError::Policy)
    ));
    assert!(matches!(
        PreparedSessionPolicyFreeze::new(&vec![&binding; MAX_RECORDS + 1]),
        Err(SessionTransferError::TooLarge)
    ));
}
