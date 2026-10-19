use super::*;
use phantom_net::dns::{HttpsRecord, HttpsRecordResolver};
use std::num::NonZeroUsize;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn cache(capacity: usize) -> HttpsRecordDiscovery {
    HttpsRecordDiscovery::new(
        HttpsRecordResolver::from_fn(|_, _| async {
            Ok(HttpsRecordLookup::new(Vec::new(), Some(60)))
        }),
        NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::MIN),
    )
}

fn snapshot() -> Result<HttpsRecordSnapshot, Box<dyn std::error::Error>> {
    Ok(HttpsRecordSnapshot {
        namespace: "portable/test".into(),
        entries: vec![Entry {
            host: "origin.test".into(),
            port: 443,
            expires_at: SystemTime::now() + std::time::Duration::from_secs(60),
            negative_ttl: None,
            answers: vec![HttpsRecordAnswer::new(
                "Callback Owner",
                60,
                HttpsRecord::from_rdata(&[
                    0, 1, 0, 0, 1, 0, 3, 2, b'h', b'2', 0, 5, 0, 2, 0xff, 0xfe, 0, 9, 0, 1, 7,
                ])?,
            )],
        }],
    })
}

#[test]
fn ordered_records_unknown_parameters_and_uninterpreted_ech_survive() -> TestResult {
    let snapshot = snapshot()?;
    let cache = cache(1);
    cache.restore_checkpoint(&snapshot, Some("portable/test"))?;
    let exported = cache.export_checkpoint(Some("portable/test"))?;
    assert_eq!(exported.entries.len(), 1);
    assert_eq!(exported.entries[0].answers, snapshot.entries[0].answers);
    assert_eq!(
        exported.entries[0].expires_at,
        snapshot.entries[0].expires_at
    );
    Ok(())
}

#[test]
fn empty_namespace_mismatch_and_duplicate_entries_reject_without_mutation() -> TestResult {
    let cache = cache(2);
    let mut snapshot = snapshot()?;
    assert_eq!(
        cache
            .restore_checkpoint(&snapshot, Some("other"))
            .err()
            .ok_or("mismatch")?
            .kind(),
        Kind::Incompatible
    );
    assert_eq!(
        cache
            .export_checkpoint(None)
            .err()
            .ok_or("missing namespace")?
            .kind(),
        Kind::Unsupported
    );
    snapshot.entries.push(Entry {
        host: "origin.test".into(),
        port: 443,
        expires_at: SystemTime::now(),
        negative_ttl: Some(60),
        answers: Vec::new(),
    });
    assert_eq!(
        cache
            .restore_checkpoint(&snapshot, Some("portable/test"))
            .err()
            .ok_or("duplicate")?
            .kind(),
        Kind::InvalidSnapshot
    );
    assert!(
        cache
            .export_checkpoint(Some("portable/test"))?
            .entries
            .is_empty()
    );
    Ok(())
}

#[test]
fn capacity_rejection_is_transactional_and_expiry_is_not_renewed() -> TestResult {
    let mut snapshot = snapshot()?;
    let original_expiry = snapshot.entries[0].expires_at;
    snapshot.entries.push(Entry {
        host: "negative.test".into(),
        port: 443,
        expires_at: original_expiry,
        negative_ttl: Some(60),
        answers: Vec::new(),
    });
    let small = cache(1);
    assert_eq!(
        small
            .restore_checkpoint(&snapshot, Some("portable/test"))
            .err()
            .ok_or("capacity accepted")?
            .kind(),
        Kind::Capacity
    );
    assert!(
        small
            .export_checkpoint(Some("portable/test"))?
            .entries
            .is_empty()
    );
    let first = cache(2);
    first.restore_checkpoint(&snapshot, Some("portable/test"))?;
    let exported = first.export_checkpoint(Some("portable/test"))?;
    assert_eq!(exported.entries[1].negative_ttl, Some(60));
    assert!(exported.entries[1].answers.is_empty());
    let second = cache(2);
    second.restore_checkpoint(&exported, Some("portable/test"))?;
    for entry in second.export_checkpoint(Some("portable/test"))?.entries {
        assert_eq!(entry.expires_at, original_expiry);
    }
    snapshot.entries[0].expires_at = SystemTime::UNIX_EPOCH;
    let pruned = cache(1);
    pruned.restore_checkpoint(&snapshot, Some("portable/test"))?;
    let exported = pruned.export_checkpoint(Some("portable/test"))?;
    assert_eq!(exported.entries.len(), 1);
    assert_eq!(&*exported.entries[0].host, "negative.test");
    Ok(())
}

#[test]
fn future_expiry_is_capped_by_the_original_ttl() -> TestResult {
    let mut snapshot = snapshot()?;
    snapshot.entries[0].expires_at = SystemTime::now() + std::time::Duration::from_secs(3600);
    let before = SystemTime::now();
    let cache = cache(1);
    cache.restore_checkpoint(&snapshot, Some("portable/test"))?;
    let exported = cache.export_checkpoint(Some("portable/test"))?;
    assert!(
        exported.entries[0].expires_at <= SystemTime::now() + std::time::Duration::from_secs(60)
    );
    assert!(exported.entries[0].expires_at > before);
    assert!(exported.entries[0].expires_at < snapshot.entries[0].expires_at);
    Ok(())
}

#[tokio::test]
async fn restored_lru_controls_eviction_and_all_response_records_remain_ordered() -> TestResult {
    let mut snapshot = snapshot()?;
    let first = snapshot.entries[0].answers[0].clone();
    snapshot.entries[0].answers.push(HttpsRecordAnswer::new(
        "unrelated.test.",
        120,
        HttpsRecord::from_rdata(&[0, 0, 3, b'a', b'l', b't', 0])?,
    ));
    snapshot.entries.push(Entry {
        host: "second.test.".into(),
        port: 443,
        expires_at: snapshot.entries[0].expires_at,
        negative_ttl: None,
        answers: vec![first],
    });
    let cache = cache(2);
    cache.restore_checkpoint(&snapshot, Some("portable/test"))?;
    assert_eq!(
        cache.export_checkpoint(Some("portable/test"))?.entries[0].answers,
        snapshot.entries[0].answers
    );
    let endpoint = crate::authority::Endpoint::new("origin.test".parse()?, 443)
        .map_err(|error| error.message())?;
    let _ = cache.discover(&endpoint);
    let exported = cache.export_checkpoint(Some("portable/test"))?;
    assert_eq!(&*exported.entries[0].host, "second.test.");
    assert_eq!(&*exported.entries[1].host, "origin.test");
    let third = crate::authority::Endpoint::new("third.test".parse()?, 443)
        .map_err(|error| error.message())?;
    let super::super::Discovery::Pending(pending) = cache.discover(&third) else {
        return Err("third lookup not started".into());
    };
    assert!(!pending.advertises_h3().await);
    let exported = cache.export_checkpoint(Some("portable/test"))?;
    assert_eq!(&*exported.entries[0].host, "origin.test");
    assert_eq!(&*exported.entries[1].host, "third.test");
    Ok(())
}

#[tokio::test]
async fn pending_work_and_operational_backoff_are_not_persisted() -> TestResult {
    let cache = HttpsRecordDiscovery::new(
        HttpsRecordResolver::from_fn(|host, _| async move {
            if host == "pending.test" {
                std::future::pending::<()>().await;
            }
            Err(phantom_net::dns::HttpsLookupError::other(
                std::io::Error::other("test lookup failed"),
            ))
        }),
        NonZeroUsize::MIN.saturating_add(1),
    );
    for host in ["failed.test", "pending.test"] {
        let origin =
            crate::authority::Endpoint::new(host.parse()?, 443).map_err(|error| error.message())?;
        let super::super::Discovery::Pending(pending) = cache.discover(&origin) else {
            return Err("lookup not started".into());
        };
        if host == "failed.test" {
            assert!(!pending.advertises_h3().await);
        }
    }
    let state = cache.cache.lock_state();
    assert_eq!(state.ready.len(), 1);
    assert_eq!(state.pending.len(), 1);
    drop(state);
    assert!(
        cache
            .export_checkpoint(Some("portable/test"))?
            .entries
            .is_empty()
    );
    Ok(())
}
