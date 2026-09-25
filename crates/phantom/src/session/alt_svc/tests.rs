use std::{num::NonZeroUsize, time::Duration};

use super::{
    AltSvcBrokenBackoff, AltSvcLocation, AltSvcStore, AlternativeTarget, StoreKey,
    invalidates_alternative,
};
use crate::{HttpProtocol, RequestError, Route, TimeoutPhase, authority::Endpoint};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The route every test below uses unless it is about route scoping.
const DIRECT: Route = Route::Direct;

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
        &origin, &DIRECT,
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
        store
            .get_at(&origin, &DIRECT, now)
            .map(|selected| selected.location),
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

    store.learn_fields_at(
        &origin,
        &DIRECT,
        [("alt-svc", b"h3=\":8443\"".as_slice())],
        now,
    );
    assert_eq!(
        store
            .get_at(&origin, &DIRECT, now)
            .ok_or("same-host alternative missing")?
            .host(),
        "origin.example"
    );

    store.learn_fields_at(
        &origin,
        &DIRECT,
        [("alt-svc", b"h3=\"[2001:db8::1]:9443\"".as_slice())],
        now,
    );
    let ipv6 = store
        .get_at(&origin, &DIRECT, now)
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
        &DIRECT,
        [
            ("alt-svc", b"h3=\":8443\"".as_slice()),
            ("age", b"60".as_slice()),
        ],
        now,
    );

    assert!(
        store
            .get_at(&origin, &DIRECT, now + Duration::from_secs(86_339))
            .is_some()
    );
    assert!(
        store
            .get_at(&origin, &DIRECT, now + Duration::from_secs(86_340))
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
    assert!(store.get_at(&origin, &DIRECT, now).is_none());

    learn(&store, &origin, b"h3=\":8443\"; ma=60", now);
    store.learn_fields_at(
        &origin,
        &DIRECT,
        [
            ("alt-svc", b"h3=\":9443\"; ma=60".as_slice()),
            ("age", b"60".as_slice()),
        ],
        now,
    );
    assert!(store.get_at(&origin, &DIRECT, now).is_none());
    Ok(())
}

#[test]
fn clear_wins_even_when_combined_with_an_invalid_alternative() -> TestResult {
    let origin = endpoint("origin.example:443")?;
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let now = std::time::Instant::now();
    learn(&store, &origin, b"h3=\":8443\"", now);
    learn(&store, &origin, b"h3=not-quoted, clear", now);

    assert!(store.get_at(&origin, &DIRECT, now).is_none());
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
                .get_at(&origin, &DIRECT, now)
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

    assert!(store.get_at(&origin, &DIRECT, now).is_none());
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
    assert!(store.get_at(&first, &DIRECT, now).is_some());
    learn(&store, &third, b"h3=\":8003\"", now);

    assert!(store.get_at(&first, &DIRECT, now).is_some());
    assert!(store.get_at(&second, &DIRECT, now).is_none());
    assert!(store.get_at(&third, &DIRECT, now).is_some());
    store.remove(&first, &DIRECT);
    assert!(store.get_at(&first, &DIRECT, now).is_none());
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
        &DIRECT,
        [
            ("alt-svc", b"h3=\":9443\"".as_slice()),
            ("age", b"1".as_slice()),
            ("Age", b"2".as_slice()),
        ],
        now,
    );
    assert_eq!(
        store
            .get_at(&origin, &DIRECT, now)
            .ok_or("duplicate Age replaced the prior alternative")?
            .port(),
        8443
    );
    store.learn_fields_at(
        &origin,
        &DIRECT,
        [
            ("alt-svc", b"h3=\":9443\"".as_slice()),
            ("age", b"invalid".as_slice()),
        ],
        now,
    );
    assert_eq!(
        store
            .get_at(&origin, &DIRECT, now)
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
        .get_at(&origin, &DIRECT, now)
        .ok_or("first alternative missing")?
        .generation;
    learn(&store, &origin, b"h3=\":9443\"", now);

    store.remove_if_current(&origin, &DIRECT, stale_generation);

    assert_eq!(
        store
            .get_at(&origin, &DIRECT, now)
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
        &DIRECT,
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
            .get_at(&origin, &DIRECT, now + Duration::from_secs(60))
            .is_some()
    );

    store.learn_fields_at(
        &origin,
        &DIRECT,
        [
            (
                "alt-svc",
                b"h3=\":9443\"; ma=999999999999999999999".as_slice(),
            ),
            ("age", oversized.as_slice()),
        ],
        now,
    );
    assert!(store.get_at(&origin, &DIRECT, now).is_none());
    Ok(())
}

fn endpoint(authority: &str) -> TestResult<Endpoint> {
    Ok(Endpoint::new(authority.parse()?, 443)?)
}

fn learn(store: &AltSvcStore, origin: &Endpoint, value: &[u8], now: std::time::Instant) {
    learn_on(store, origin, &DIRECT, value, now);
}

fn learn_on(
    store: &AltSvcStore,
    origin: &Endpoint,
    route: &Route,
    value: &[u8],
    now: std::time::Instant,
) {
    store.learn_fields_at(origin, route, [("alt-svc", value)], now);
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
        store.learn_frames_at(
            &origin,
            &DIRECT,
            [(Some(foreign), b"h3=\":9443\"".as_slice())],
            now,
        );
        assert!(store.get_at(&origin, &DIRECT, now).is_none(), "{foreign:?}");
    }

    store.learn_frames_at(
        &origin,
        &DIRECT,
        [(
            Some(b"https://origin.example:8443".as_slice()),
            b"h3=\":9443\"".as_slice(),
        )],
        now,
    );
    assert_eq!(
        store
            .get_at(&origin, &DIRECT, now)
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
        &DIRECT,
        [
            (None, b"h3=\":8001\"".as_slice()),
            (None, b"h3=\":8002\"".as_slice()),
        ],
        now,
    );
    assert_eq!(
        store
            .get_at(&origin, &DIRECT, now)
            .ok_or("frame not learned")?
            .port(),
        8002
    );
    store.learn_frames_at(&origin, &DIRECT, [(None, b"clear".as_slice())], now);
    assert!(store.get_at(&origin, &DIRECT, now).is_none());
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
        .get_at(origin, &DIRECT, now)
        .ok_or("alternative not learned")?
        .is_broken())
}

fn location(
    store: &AltSvcStore,
    origin: &Endpoint,
    now: std::time::Instant,
) -> TestResult<AltSvcLocation> {
    Ok(store
        .get_at(origin, &DIRECT, now)
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
    store.mark_broken_at(&origin, &DIRECT, &broken, backoff()?, now);
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
        store.mark_broken_at(&origin, &DIRECT, &broken, backoff, now);
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
    store.confirm(&origin, &DIRECT, &broken);
    assert!(!broken_at(&store, &origin, now)?);
    store.mark_broken_at(&origin, &DIRECT, &broken, backoff, now);
    assert!(!broken_at(&store, &origin, now + Duration::from_secs(10))?);

    // Clearing the store clears brokenness with the advertisements.
    store.mark_broken_at(&origin, &DIRECT, &broken, backoff, now);
    store.clear();
    learn(&store, &origin, b"h3=\":8443\"", now);
    assert!(!broken_at(&store, &origin, now)?);
    Ok(())
}

#[test]
fn failure_during_broken_period_counts_without_extending_it() -> TestResult {
    let backoff = backoff()?;
    let origin = endpoint("origin.example:443")?;
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let now = std::time::Instant::now();
    learn(&store, &origin, b"h3=\":8443\"; ma=86400", now);
    let broken = location(&store, &origin, now)?;

    // Two races that lost concurrently report the same alternative.
    store.mark_broken_at(&origin, &DIRECT, &broken, backoff, now);
    store.mark_broken_at(
        &origin,
        &DIRECT,
        &broken,
        backoff,
        now + Duration::from_secs(1),
    );
    assert!(broken_at(
        &store,
        &origin,
        now + Duration::from_millis(9_999)
    )?);
    assert!(!broken_at(&store, &origin, now + Duration::from_secs(10))?);

    // Both failures count, as in Chromium, so the next period is 10 s << 2.
    let later = now + Duration::from_secs(10);
    store.mark_broken_at(&origin, &DIRECT, &broken, backoff, later);
    assert!(broken_at(
        &store,
        &origin,
        later + Duration::from_millis(39_999)
    )?);
    assert!(!broken_at(
        &store,
        &origin,
        later + Duration::from_secs(40)
    )?);
    Ok(())
}

fn socks5(uri: &str) -> TestResult<Route> {
    Ok(Route::socks5(crate::Socks5Proxy::new(uri)?))
}

#[test]
fn alternatives_are_scoped_to_the_route_that_learned_them() -> TestResult {
    let origin = endpoint("origin.example:443")?;
    let proxied = socks5("socks5h://proxy.example:1080")?;
    let other_proxy = socks5("socks5h://other.example:1080")?;
    let store = AltSvcStore::new(NonZeroUsize::new(4).ok_or("zero capacity")?);
    let now = std::time::Instant::now();

    learn(&store, &origin, b"h3=\":8443\"", now);
    // A proxy route never inherits the direct route's advertisement.
    assert!(store.get_at(&origin, &proxied, now).is_none());

    learn_on(&store, &origin, &proxied, b"h3=\":9443\"", now);
    assert_eq!(
        store
            .get_at(&origin, &DIRECT, now)
            .ok_or("direct alternative missing")?
            .port(),
        8443
    );
    assert_eq!(
        store
            .get_at(&origin, &proxied, now)
            .ok_or("proxied alternative missing")?
            .port(),
        9443
    );
    // Another proxy is another route, even to the same origin.
    assert!(store.get_at(&origin, &other_proxy, now).is_none());

    // Eviction is per route as well.
    store.remove(&origin, &proxied);
    assert!(store.get_at(&origin, &proxied, now).is_none());
    assert!(store.get_at(&origin, &DIRECT, now).is_some());
    Ok(())
}

#[test]
fn broken_state_is_scoped_to_the_route_that_failed() -> TestResult {
    let origin = endpoint("origin.example:443")?;
    let proxied = socks5("socks5://proxy.example:1080")?;
    let store = AltSvcStore::new(NonZeroUsize::new(4).ok_or("zero capacity")?);
    let now = std::time::Instant::now();
    learn(&store, &origin, b"h3=\":8443\"; ma=86400", now);
    learn_on(&store, &origin, &proxied, b"h3=\":8443\"; ma=86400", now);

    let broken = location(&store, &origin, now)?;
    store.mark_broken_at(&origin, &DIRECT, &broken, backoff()?, now);

    assert!(broken_at(&store, &origin, now)?);
    assert!(
        !store
            .get_at(&origin, &proxied, now)
            .ok_or("proxied alternative missing")?
            .is_broken(),
        "the same location broken on one route must not be broken on another"
    );
    Ok(())
}

#[test]
fn snapshots_carry_direct_route_alternatives_only() -> TestResult {
    let origin = endpoint("origin.example:443")?;
    let proxied_origin = endpoint("proxied.example:443")?;
    let proxied = socks5("socks5h://proxy.example:1080")?;
    let store = AltSvcStore::new(NonZeroUsize::new(4).ok_or("zero capacity")?);
    let now = std::time::Instant::now();
    learn(&store, &origin, b"h3=\":8443\"; ma=86400", now);
    learn_on(
        &store,
        &proxied_origin,
        &proxied,
        b"h3=\":9443\"; ma=86400",
        now,
    );

    let snapshot = store.export();

    assert_eq!(
        snapshot
            .entries()
            .iter()
            .map(|entry| entry.origin())
            .collect::<Vec<_>>(),
        ["https://origin.example"]
    );
    Ok(())
}

fn allows_early_data(
    store: &AltSvcStore,
    origin: &Endpoint,
    now: std::time::Instant,
) -> TestResult<bool> {
    let selection = store
        .get_at(origin, &DIRECT, now)
        .ok_or("alternative not learned")?;
    Ok(AlternativeTarget::new(&selection).allows_early_data())
}

#[test]
fn early_data_waits_until_quic_to_the_origin_connects_again() -> TestResult {
    let origin = endpoint("origin.example:443")?;
    let store = AltSvcStore::new(NonZeroUsize::new(4).ok_or("zero capacity")?);
    let now = std::time::Instant::now();
    learn(&store, &origin, b"h3=\"alt.example:8443\"", now);
    assert!(allows_early_data(&store, &origin, now)?);

    // A failure of another alternative location does not count.
    let alternative = location(&store, &origin, now)?;
    store.mark_broken_at(&origin, &DIRECT, &alternative, backoff()?, now);
    assert!(allows_early_data(&store, &origin, now)?);

    // Chromium keys the check by QUIC at the origin's own host and port, and
    // it holds after the broken period until that location connects again.
    let own = AltSvcLocation::origin(&origin);
    store.mark_broken_at(&origin, &DIRECT, &own, backoff()?, now);
    assert!(!allows_early_data(&store, &origin, now)?);
    let later = now + Duration::from_secs(3600);
    assert!(!store.is_broken_at(&StoreKey::new(&origin, &DIRECT), &own, later));
    assert!(!allows_early_data(&store, &origin, later)?);
    store.confirm(&origin, &DIRECT, &own);
    assert!(allows_early_data(&store, &origin, later)?);
    Ok(())
}

#[test]
fn a_failed_early_handshake_disallows_early_data_without_breaking_the_alternative() -> TestResult {
    let origin = endpoint("origin.example:443")?;
    let store = AltSvcStore::new(NonZeroUsize::new(4).ok_or("zero capacity")?);
    let now = std::time::Instant::now();
    learn(&store, &origin, b"h3=\"alt.example:8443\"", now);

    store.mark_origin_quic_recently_broken(&origin, &DIRECT);
    let later = std::time::Instant::now();
    assert!(!allows_early_data(&store, &origin, later)?);
    assert!(!broken_at(&store, &origin, later)?);

    // A completed handshake to the alternative confirms QUIC to the origin.
    let alternative = location(&store, &origin, later)?;
    store.confirm(&origin, &DIRECT, &alternative);
    assert!(allows_early_data(&store, &origin, later)?);
    Ok(())
}
