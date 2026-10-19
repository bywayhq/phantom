use super::*;
use phantom_net::dns::{HttpsRecordLookup, HttpsRecordResolver};

fn records() -> HttpsRecordResolver {
    HttpsRecordResolver::from_fn(|_, _| async { Ok(HttpsRecordLookup::new(Vec::new(), Some(60))) })
}

fn enabled(namespace: &str) -> Result<Client, crate::BuildError> {
    builder(1)
        .https_record_discovery(records())
        .https_record_checkpoint_namespace(namespace)
        .build()
}

#[test]
fn enabled_empty_https_cache_requires_an_explicit_matching_namespace() -> TestResult {
    let source = enabled("test/one")?;
    let recipient = enabled("test/one")?;
    let checkpoint = source.export_session(KEY)?;
    let restored = recipient.restore_session(&checkpoint, KEY, &[])?;
    assert!(!Arc::ptr_eq(&restored.state, &recipient.state));
    assert!(restored.state.https_records.is_some());
    assert_eq!(
        enabled("test/two")?
            .restore_session(&checkpoint, KEY, &[])
            .err()
            .ok_or("namespace accepted")?
            .kind(),
        SessionSnapshotErrorKind::Incompatible
    );
    let disabled = builder(1).build()?;
    assert_eq!(
        disabled
            .restore_session(&checkpoint, KEY, &[])
            .err()
            .ok_or("disabled accepted")?
            .kind(),
        SessionSnapshotErrorKind::Disabled
    );
    let absent = disabled.export_session(KEY)?;
    assert_eq!(
        recipient
            .restore_session(&absent, KEY, &[])
            .err()
            .ok_or("absent accepted")?
            .kind(),
        SessionSnapshotErrorKind::Incompatible
    );
    assert_eq!(
        builder(1)
            .https_record_discovery(records())
            .build()?
            .export_session(KEY)
            .err()
            .ok_or("unbound accepted")?
            .kind(),
        SessionSnapshotErrorKind::Unsupported
    );
    Ok(())
}

#[test]
fn checkpoint_namespace_is_validated_before_building() {
    for namespace in ["".to_owned(), "a\nb".to_owned(), "x".repeat(257)] {
        assert!(
            builder(1)
                .https_record_discovery(records())
                .https_record_checkpoint_namespace(namespace)
                .build()
                .is_err()
        );
    }
    assert!(
        builder(1)
            .https_record_checkpoint_namespace("test/one")
            .build()
            .is_err()
    );
}

#[test]
fn authenticated_https_count_bound_is_enforced_before_allocation() -> TestResult {
    let source = enabled("test/one")?;
    let mut state = codec::decode(&envelope::open(
        source.export_session(KEY)?.as_bytes(),
        KEY,
    )?)?;
    state.https_records = None;
    let mut bytes = codec::encode(&state)?;
    bytes.pop(); // Replace the absent HTTPS section with an oversized one.
    bytes.push(1);
    bytes.extend_from_slice(&8_u32.to_be_bytes());
    bytes.extend_from_slice(b"test/one");
    bytes.extend_from_slice(&65_536_u32.to_be_bytes());
    let snapshot = SessionSnapshot(envelope::seal(bytes, KEY)?);
    assert_eq!(
        source
            .restore_session(&snapshot, KEY, &[])
            .err()
            .ok_or("oversize accepted")?
            .kind(),
        SessionSnapshotErrorKind::TooLarge
    );
    Ok(())
}

#[test]
fn authenticated_duplicate_https_keys_reject_without_receiver_mutation() -> TestResult {
    use crate::session::alt_svc::https_record_snapshot::{Entry, HttpsRecordSnapshot};
    let source = enabled("test/one")?;
    let mut state = codec::decode(&envelope::open(
        source.export_session(KEY)?.as_bytes(),
        KEY,
    )?)?;
    state.https_records = Some(HttpsRecordSnapshot {
        namespace: "test/one".into(),
        entries: (0..2)
            .map(|_| Entry {
                host: "origin.test".into(),
                port: 443,
                expires_at: SystemTime::now() + Duration::from_secs(60),
                negative_ttl: Some(60),
                answers: Vec::new(),
            })
            .collect(),
    });
    let checkpoint = SessionSnapshot(envelope::seal(codec::encode(&state)?, KEY)?);
    let receiver = enabled("test/one")?;
    receiver.import_alt_svc(&alternatives(
        1,
        SystemTime::now() + Duration::from_secs(600),
    ))?;
    let retained = receiver.export_alt_svc();
    assert_eq!(
        receiver
            .restore_session(&checkpoint, KEY, &[])
            .err()
            .ok_or("duplicate accepted")?
            .kind(),
        SessionSnapshotErrorKind::InvalidSnapshot
    );
    assert_eq!(receiver.export_alt_svc(), retained);
    assert!(
        codec::decode(&envelope::open(
            receiver.export_session(KEY)?.as_bytes(),
            KEY
        )?)?
        .https_records
        .ok_or("disabled")?
        .entries
        .is_empty()
    );
    Ok(())
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn paired_native_resolver_is_not_a_portable_checkpoint_identity() -> TestResult {
    #[cfg(target_os = "linux")]
    use phantom_net::dns::chromium_linux_resolvers as paired;
    #[cfg(target_os = "macos")]
    use phantom_net::dns::chromium_macos_resolvers as paired;
    #[cfg(windows)]
    use phantom_net::dns::chromium_windows_resolvers as paired;
    let (addresses, records) = paired().await?;
    let client = builder(1)
        .https_record_discovery(records.clone())
        .https_record_checkpoint_namespace("native/assertion")
        .build()?;
    assert_eq!(
        client
            .export_session(KEY)
            .err()
            .ok_or("native accepted")?
            .kind(),
        SessionSnapshotErrorKind::Unsupported
    );
    drop(client);
    tokio::task::spawn_blocking(move || drop((addresses, records))).await?;
    Ok(())
}
