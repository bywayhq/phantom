use std::{num::NonZeroUsize, time::Duration};

use super::{AltSvcBrokenBackoff, AltSvcLocation, AltSvcStore, invalidates_alternative};
use crate::{HttpProtocol, RequestError, TimeoutPhase, authority::Endpoint};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn only_alternative_service_failures_trigger_alt_svc_eviction() {
    assert!(!invalidates_alternative(
        &RequestError::request_body_not_replayable()
    ));
    assert!(!invalidates_alternative(&RequestError::capacity(
        HttpProtocol::Http3
    )));
    assert!(invalidates_alternative(&RequestError::timeout(
        TimeoutPhase::ResponseHead,
        Some(HttpProtocol::Http3)
    )));
}

#[test]
fn selects_first_fresh_h3_and_canonicalizes_its_location() -> TestResult {
    let origin = endpoint("Origin.Example:443")?;
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let now = std::time::Instant::now();
    store.learn_fields_at(
        &origin,
        [
            (
                "Alt-Svc",
                b"h2=\"other.example:443\", h3=\"expired.example:7443\"; ma=0, h3=\"ALT.Example:8443\"; ma=60; unknown=ok".as_slice(),
            ),
            ("alt-svc", b"h3=\"later.example:9443\"; ma=120".as_slice()),
        ],
        now,
    );

    assert_eq!(
        store.get_at(&origin, now).map(|selected| selected.location),
        Some(AltSvcLocation {
            host: "alt.example".into(),
            port: 8443,
        })
    );
    Ok(())
}

#[test]
fn empty_host_uses_origin_and_ipv6_loses_wire_brackets() -> TestResult {
    let origin = endpoint("origin.example:443")?;
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let now = std::time::Instant::now();

    store.learn_fields_at(&origin, [("alt-svc", b"h3=\":8443\"".as_slice())], now);
    assert_eq!(
        store
            .get_at(&origin, now)
            .ok_or("same-host alternative missing")?
            .host(),
        "origin.example"
    );

    store.learn_fields_at(
        &origin,
        [("alt-svc", b"h3=\"[2001:db8::1]:9443\"".as_slice())],
        now,
    );
    let ipv6 = store
        .get_at(&origin, now)
        .ok_or("IPv6 alternative missing")?;
    assert_eq!(ipv6.host(), "2001:db8::1");
    assert_eq!(ipv6.port(), 9443);
    Ok(())
}

#[test]
fn applies_default_max_age_age_subtraction_and_expiry() -> TestResult {
    let origin = endpoint("origin.example:443")?;
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let now = std::time::Instant::now();
    store.learn_fields_at(
        &origin,
        [
            ("alt-svc", b"h3=\":8443\"".as_slice()),
            ("age", b"60".as_slice()),
        ],
        now,
    );

    assert!(
        store
            .get_at(&origin, now + Duration::from_secs(86_339))
            .is_some()
    );
    assert!(
        store
            .get_at(&origin, now + Duration::from_secs(86_340))
            .is_none()
    );
    Ok(())
}

#[test]
fn max_age_zero_and_age_exhaustion_replace_with_no_entry() -> TestResult {
    let origin = endpoint("origin.example:443")?;
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let now = std::time::Instant::now();
    learn(&store, &origin, b"h3=\":8443\"; ma=60", now);
    learn(&store, &origin, b"h3=\":9443\"; ma=0", now);
    assert!(store.get_at(&origin, now).is_none());

    learn(&store, &origin, b"h3=\":8443\"; ma=60", now);
    store.learn_fields_at(
        &origin,
        [
            ("alt-svc", b"h3=\":9443\"; ma=60".as_slice()),
            ("age", b"60".as_slice()),
        ],
        now,
    );
    assert!(store.get_at(&origin, now).is_none());
    Ok(())
}

#[test]
fn clear_wins_even_when_combined_with_an_invalid_alternative() -> TestResult {
    let origin = endpoint("origin.example:443")?;
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let now = std::time::Instant::now();
    learn(&store, &origin, b"h3=\":8443\"", now);
    learn(&store, &origin, b"h3=not-quoted, clear", now);

    assert!(store.get_at(&origin, now).is_none());
    Ok(())
}

#[test]
fn malformed_field_preserves_previous_entry() -> TestResult {
    let origin = endpoint("origin.example:443")?;
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let now = std::time::Instant::now();
    learn(&store, &origin, b"h3=\":8443\"; ma=60", now);

    for malformed in [
        b"h3=not-quoted".as_slice(),
        b"h3=\"unterminated".as_slice(),
        b"h3=\":0\"".as_slice(),
        b"h3=\":9443\"; ma=nope".as_slice(),
        b"h3=\":9443\"; ma=\"60\"".as_slice(),
        b"h3=\":9443\"; ma=1; ma=2".as_slice(),
        b"h%33=\":9443\"".as_slice(),
        b"h2=\"missing-port\"".as_slice(),
    ] {
        learn(&store, &origin, malformed, now);
        assert_eq!(
            store
                .get_at(&origin, now)
                .ok_or("prior alternative was not retained")?
                .port(),
            8443
        );
    }
    Ok(())
}

#[test]
fn valid_unsupported_list_replaces_previous_h3_entry() -> TestResult {
    let origin = endpoint("origin.example:443")?;
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let now = std::time::Instant::now();
    learn(&store, &origin, b"h3=\":8443\"", now);
    learn(&store, &origin, b"h2=\":443\"", now);

    assert!(store.get_at(&origin, now).is_none());
    Ok(())
}

#[test]
fn replacement_lru_and_explicit_removal_are_origin_scoped() -> TestResult {
    let first = endpoint("first.example:443")?;
    let second = endpoint("second.example:443")?;
    let third = endpoint("third.example:443")?;
    let store = AltSvcStore::new(NonZeroUsize::new(2).ok_or("zero capacity")?);
    let now = std::time::Instant::now();
    learn(&store, &first, b"h3=\":8001\"", now);
    learn(&store, &second, b"h3=\":8002\"", now);
    assert!(store.get_at(&first, now).is_some());
    learn(&store, &third, b"h3=\":8003\"", now);

    assert!(store.get_at(&first, now).is_some());
    assert!(store.get_at(&second, now).is_none());
    assert!(store.get_at(&third, now).is_some());
    store.remove(&first);
    assert!(store.get_at(&first, now).is_none());
    assert_eq!(store.capacity().get(), 2);
    Ok(())
}

#[test]
fn duplicate_or_malformed_age_preserves_previous_entry() -> TestResult {
    let origin = endpoint("origin.example:443")?;
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let now = std::time::Instant::now();
    learn(&store, &origin, b"h3=\":8443\"", now);

    store.learn_fields_at(
        &origin,
        [
            ("alt-svc", b"h3=\":9443\"".as_slice()),
            ("age", b"1".as_slice()),
            ("Age", b"2".as_slice()),
        ],
        now,
    );
    assert_eq!(
        store
            .get_at(&origin, now)
            .ok_or("duplicate Age replaced the prior alternative")?
            .port(),
        8443
    );
    store.learn_fields_at(
        &origin,
        [
            ("alt-svc", b"h3=\":9443\"".as_slice()),
            ("age", b"invalid".as_slice()),
        ],
        now,
    );
    assert_eq!(
        store
            .get_at(&origin, now)
            .ok_or("malformed Age replaced the prior alternative")?
            .port(),
        8443
    );
    Ok(())
}

#[test]
fn stale_failure_does_not_remove_a_newer_advertisement() -> TestResult {
    let origin = endpoint("origin.example:443")?;
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let now = std::time::Instant::now();
    learn(&store, &origin, b"h3=\":8443\"", now);
    let stale_generation = store
        .get_at(&origin, now)
        .ok_or("first alternative missing")?
        .generation;
    learn(&store, &origin, b"h3=\":9443\"", now);

    store.remove_if_current(&origin, stale_generation);

    assert_eq!(
        store
            .get_at(&origin, now)
            .ok_or("newer alternative was removed")?
            .port(),
        9443
    );
    Ok(())
}

#[test]
fn oversized_delta_seconds_saturate_instead_of_becoming_malformed() -> TestResult {
    let origin = endpoint("origin.example:443")?;
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let now = std::time::Instant::now();
    let oversized = b"999999999999999999999999999999999999999999999999";
    store.learn_fields_at(
        &origin,
        [(
            "alt-svc",
            [b"h3=\":8443\"; ma=".as_slice(), oversized]
                .concat()
                .as_slice(),
        )],
        now,
    );
    assert!(
        store
            .get_at(&origin, now + Duration::from_secs(60))
            .is_some()
    );

    store.learn_fields_at(
        &origin,
        [
            (
                "alt-svc",
                b"h3=\":9443\"; ma=999999999999999999999".as_slice(),
            ),
            ("age", oversized.as_slice()),
        ],
        now,
    );
    assert!(store.get_at(&origin, now).is_none());
    Ok(())
}

fn endpoint(authority: &str) -> TestResult<Endpoint> {
    Ok(Endpoint::new(authority.parse()?, 443)?)
}

fn learn(store: &AltSvcStore, origin: &Endpoint, value: &[u8], now: std::time::Instant) {
    store.learn_fields_at(origin, [("alt-svc", value)], now);
}

#[test]
fn canonical_origin_brackets_ipv6_and_omits_default_port() -> TestResult {
    assert_eq!(
        super::canonical_origin(&endpoint("Origin.Example:443")?),
        "https://origin.example"
    );
    assert_eq!(
        super::canonical_origin(&endpoint("origin.example:8443")?),
        "https://origin.example:8443"
    );
    assert_eq!(
        super::canonical_origin(&endpoint("[::1]:8443")?),
        "https://[::1]:8443"
    );
    Ok(())
}

#[test]
fn stream_zero_frames_apply_only_to_the_exact_canonical_origin() -> TestResult {
    let origin = endpoint("origin.example:8443")?;
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let now = std::time::Instant::now();
    for foreign in [
        b"https://other.example:8443".as_slice(),
        b"https://ORIGIN.example:8443".as_slice(),
        b"https://origin.example:8443/".as_slice(),
        b"http://origin.example:8443".as_slice(),
        b"https://origin.example".as_slice(),
    ] {
        store.learn_frames_at(&origin, [(Some(foreign), b"h3=\":9443\"".as_slice())], now);
        assert!(store.get_at(&origin, now).is_none(), "{foreign:?}");
    }

    store.learn_frames_at(
        &origin,
        [(
            Some(b"https://origin.example:8443".as_slice()),
            b"h3=\":9443\"".as_slice(),
        )],
        now,
    );
    assert_eq!(
        store
            .get_at(&origin, now)
            .ok_or("frame not learned")?
            .port(),
        9443
    );
    Ok(())
}

#[test]
fn stream_frames_apply_in_arrival_order() -> TestResult {
    let origin = endpoint("origin.example:443")?;
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let now = std::time::Instant::now();
    store.learn_frames_at(
        &origin,
        [
            (None, b"h3=\":8001\"".as_slice()),
            (None, b"h3=\":8002\"".as_slice()),
        ],
        now,
    );
    assert_eq!(
        store
            .get_at(&origin, now)
            .ok_or("frame not learned")?
            .port(),
        8002
    );
    store.learn_frames_at(&origin, [(None, b"clear".as_slice())], now);
    assert!(store.get_at(&origin, now).is_none());
    Ok(())
}

fn backoff() -> TestResult<AltSvcBrokenBackoff> {
    Ok(AltSvcBrokenBackoff::new(
        Duration::from_secs(10),
        Duration::from_secs(60),
    )?)
}

fn broken_at(store: &AltSvcStore, origin: &Endpoint, now: std::time::Instant) -> TestResult<bool> {
    Ok(store
        .get_at(origin, now)
        .ok_or("alternative not learned")?
        .is_broken())
}

fn location(
    store: &AltSvcStore,
    origin: &Endpoint,
    now: std::time::Instant,
) -> TestResult<AltSvcLocation> {
    Ok(store
        .get_at(origin, now)
        .ok_or("alternative not learned")?
        .location)
}

#[test]
fn broken_alternative_is_not_raced_until_backoff_expires() -> TestResult {
    let origin = endpoint("origin.example:443")?;
    let other = endpoint("other.example:443")?;
    let store = AltSvcStore::new(NonZeroUsize::new(4).ok_or("zero capacity")?);
    let now = std::time::Instant::now();
    learn(&store, &origin, b"h3=\":8443\"", now);
    learn(&store, &other, b"h3=\":8443\"", now);
    assert!(!broken_at(&store, &origin, now)?);

    let broken = location(&store, &origin, now)?;
    store.mark_broken_at(&origin, &broken, backoff()?, now);
    assert!(broken_at(&store, &origin, now)?);
    assert!(broken_at(
        &store,
        &origin,
        now + Duration::from_millis(9_999)
    )?);
    // Brokenness belongs to the origin and alternative pair.
    assert!(!broken_at(&store, &other, now)?);
    // A repeated advertisement does not clear brokenness.
    learn(
        &store,
        &origin,
        b"h3=\":8443\"",
        now + Duration::from_secs(1),
    );
    assert!(broken_at(&store, &origin, now + Duration::from_secs(1))?);
    // A different alternative for the same origin is not broken.
    learn(
        &store,
        &origin,
        b"h3=\":9443\"",
        now + Duration::from_secs(2),
    );
    assert!(!broken_at(&store, &origin, now + Duration::from_secs(2))?);
    learn(
        &store,
        &origin,
        b"h3=\":8443\"",
        now + Duration::from_secs(3),
    );
    assert!(broken_at(&store, &origin, now + Duration::from_secs(3))?);

    assert!(!broken_at(&store, &origin, now + Duration::from_secs(10))?);
    Ok(())
}

#[test]
fn broken_backoff_doubles_and_is_capped() -> TestResult {
    let backoff = backoff()?;
    assert_eq!(
        (0..6)
            .map(|failures| backoff.period(failures))
            .collect::<Vec<_>>(),
        [10, 20, 40, 60, 60, 60].map(Duration::from_secs)
    );
    assert_eq!(backoff.period(u32::MAX), Duration::from_secs(60));

    let origin = endpoint("origin.example:443")?;
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let mut now = std::time::Instant::now();
    learn(&store, &origin, b"h3=\":8443\"; ma=86400", now);
    let broken = location(&store, &origin, now)?;
    for expected in [10, 20, 40, 60, 60] {
        store.mark_broken_at(&origin, &broken, backoff, now);
        let period = Duration::from_secs(expected);
        assert!(broken_at(
            &store,
            &origin,
            now + period - Duration::from_millis(1)
        )?);
        assert!(!broken_at(&store, &origin, now + period)?);
        now += period;
    }

    // A successful alternative connection clears the failure history.
    store.confirm(&origin, &broken);
    assert!(!broken_at(&store, &origin, now)?);
    store.mark_broken_at(&origin, &broken, backoff, now);
    assert!(!broken_at(&store, &origin, now + Duration::from_secs(10))?);

    // Clearing the store clears brokenness with the advertisements.
    store.mark_broken_at(&origin, &broken, backoff, now);
    store.clear();
    learn(&store, &origin, b"h3=\":8443\"", now);
    assert!(!broken_at(&store, &origin, now)?);
    Ok(())
}
