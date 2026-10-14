use std::time::{Duration, Instant};

use super::{HttpsRecord, HttpsRecordAnswer, HttpsRecordLookup};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const CAP: Duration = Duration::from_secs(60);

fn positive(ttl: u32) -> Result<HttpsRecordLookup, Box<dyn std::error::Error>> {
    let record = HttpsRecord::from_rdata(b"\x00\x01\x00")?;
    Ok(HttpsRecordLookup::new(
        vec![HttpsRecordAnswer::new("origin.test", ttl, record)],
        None,
    ))
}

#[test]
fn constructor_and_clone_keep_one_freshness_anchor() -> TestResult {
    let before = Instant::now();
    let lookup = positive(30)?;
    let after = Instant::now();
    assert!(lookup.created_at >= before && lookup.created_at <= after);
    assert_eq!(
        lookup.expires_at,
        lookup.created_at.checked_add(Duration::from_secs(30))
    );
    let cloned = lookup.clone();
    assert_eq!(cloned.created_at, lookup.created_at);
    assert_eq!(cloned.cache_deadline(CAP), lookup.cache_deadline(CAP));
    assert_eq!(cloned.answers(), lookup.answers());
    Ok(())
}

#[test]
fn shortest_record_lifetime_bounds_the_whole_ordered_answer() -> TestResult {
    let record = HttpsRecord::from_rdata(b"\x00\x01\x00")?;
    let lookup = HttpsRecordLookup::new(
        vec![
            HttpsRecordAnswer::new("origin.test", 40, record.clone()),
            HttpsRecordAnswer::new("origin.test", 10, record),
        ],
        Some(1),
    );
    assert_eq!(
        lookup.expires_at,
        lookup.created_at.checked_add(Duration::from_secs(10))
    );
    assert_eq!(
        lookup
            .answers()
            .iter()
            .map(HttpsRecordAnswer::ttl)
            .collect::<Vec<_>>(),
        [40, 10]
    );
    Ok(())
}

#[test]
fn cache_cap_starts_at_construction_rather_than_publication() -> TestResult {
    let mut lookup = positive(300)?;
    let anchor = Instant::now()
        .checked_sub(Duration::from_secs(5))
        .ok_or("clock underflow")?;
    lookup.created_at = anchor;
    lookup.expires_at = anchor.checked_add(Duration::from_secs(300));
    assert_eq!(lookup.cache_deadline(CAP), anchor.checked_add(CAP));
    assert_eq!(lookup.cache_deadline(Duration::ZERO), None);
    assert_eq!(lookup.cache_deadline(Duration::MAX), None);
    Ok(())
}

#[test]
fn shortening_retains_fractional_lifetime_and_cannot_extend_it() -> TestResult {
    let lookup = positive(30)?.with_cache_lifetime(Duration::from_millis(500));
    let deadline = lookup
        .cache_deadline(CAP)
        .ok_or("fractional lifetime missing")?;
    assert!(deadline.saturating_duration_since(lookup.created_at) < Duration::from_secs(1));
    let cloned = lookup.clone().with_cache_lifetime(Duration::from_secs(30));
    assert_eq!(cloned.cache_deadline(CAP), Some(deadline));
    assert_eq!(cloned.created_at, lookup.created_at);
    assert_eq!(cloned.answers()[0].ttl(), 30);
    Ok(())
}

#[test]
fn zero_overflow_missing_soa_and_expired_answers_cannot_be_revived() -> TestResult {
    assert_eq!(positive(0)?.cache_deadline(CAP), None);
    assert_eq!(
        positive(30)?
            .with_cache_lifetime(Duration::ZERO)
            .cache_deadline(CAP),
        None
    );
    assert_eq!(
        positive(30)?
            .with_cache_lifetime(Duration::MAX)
            .cache_deadline(CAP),
        None
    );
    for ttl in [None, Some(0)] {
        let lookup = HttpsRecordLookup::new(Vec::new(), ttl).with_cache_lifetime(CAP);
        assert_eq!(lookup.cache_deadline(CAP), None);
        assert_eq!(lookup.negative_ttl(), ttl);
    }
    let mut expired = positive(30)?;
    expired.expires_at = Some(Instant::now());
    assert_eq!(expired.with_cache_lifetime(CAP).cache_deadline(CAP), None);
    Ok(())
}

#[test]
fn held_absolute_deadline_cannot_be_restarted_when_applied_later() -> TestResult {
    let expired = Instant::now();
    let lookup = positive(30)?.with_cache_deadline(expired);
    assert_eq!(lookup.cache_deadline(CAP), None);
    assert_eq!(
        lookup
            .clone()
            .with_cache_deadline(Instant::now() + CAP)
            .cache_deadline(CAP),
        None
    );
    assert_eq!(lookup.answers()[0].ttl(), 30);
    let lookup = positive(30)?;
    let deadline = lookup.created_at + Duration::from_millis(500);
    assert_eq!(
        lookup.with_cache_deadline(deadline).cache_deadline(CAP),
        Some(deadline)
    );
    Ok(())
}

#[test]
fn negative_soa_lifetime_is_anchored_and_capped() {
    let lookup = HttpsRecordLookup::new(Vec::new(), Some(300));
    assert_eq!(
        lookup.cache_deadline(CAP),
        lookup.created_at.checked_add(CAP)
    );
    assert_eq!(lookup.negative_ttl(), Some(300));
}
