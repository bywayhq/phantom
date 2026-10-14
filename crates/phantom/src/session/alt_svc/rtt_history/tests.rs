use super::super::{AltSvcLocation, AltSvcSelection};
use super::*;
use crate::Socks5Proxy;
use std::num::NonZeroUsize;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn origin(port: u16) -> TestResult<Endpoint> {
    Ok(Endpoint::new(format!("origin.test:{port}").parse()?, 443)?)
}

fn history(capacity: usize) -> TestResult<Arc<RttHistory>> {
    Ok(RttHistory::new(AltSvcRttDelay::new(
        NonZeroUsize::new(capacity).ok_or("zero capacity")?,
        Duration::from_secs(10),
    )))
}

fn target(host: &str, port: u16) -> TestResult<AlternativeTarget> {
    Ok(AlternativeTarget::new(&AltSvcSelection {
        location: AltSvcLocation::parse(host, port).ok_or("invalid target")?,
        generation: 1,
        broken: false,
        origin_quic_recently_broken: false,
    }))
}

// These explicit measurements exercise store decisions only. Actual native
// completion eligibility is checked by the separate real-peer controls.
fn measured(
    history: &Arc<RttHistory>,
    origin: &Endpoint,
    host: &str,
    port: u16,
    rtt: Duration,
) -> TestResult<Arc<Publication>> {
    let publication = history
        .publication(origin, &Route::Direct, host, port, true)
        .ok_or("direct publication absent")?;
    publication.record(Some(rtt));
    Ok(publication)
}

#[tokio::test(start_paused = true)]
async fn a_client_without_success_starts_origin_immediately() -> TestResult {
    let history = history(2)?;
    let origin = origin(443)?;
    let pending = history
        .publication(&origin, &Route::Direct, "alt.test", 8443, true)
        .ok_or("publication absent")?;
    pending.record(None);
    assert_eq!(
        history.delay(&origin, &Route::Direct, &[target("alt.test", 8443)?]),
        Duration::ZERO
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn success_without_a_matching_target_uses_three_hundred_milliseconds() -> TestResult {
    let history = history(2)?;
    let origin = origin(443)?;
    measured(
        &history,
        &origin,
        "alt.test",
        8443,
        Duration::from_millis(40),
    )?;
    assert_eq!(
        history.delay(&origin, &Route::Direct, &[target("other.test", 8443)?]),
        Duration::from_millis(300)
    );
    Ok(())
}

#[test]
fn whole_microseconds_scale_round_down_and_zero_uses_the_fallback() {
    for (sample, expected) in [
        (0, 300_000),
        (1, 1),
        (3, 4),
        (40_000, 60_000),
        (2_000_000, 3_000_000),
        (u64::MAX, 3_000_000),
    ] {
        assert_eq!(
            scaled_delay(Some(Duration::from_micros(sample)), Duration::ZERO),
            Duration::from_micros(expected)
        );
    }
    assert_eq!(
        scaled_delay(Some(Duration::from_nanos(999)), Duration::ZERO),
        Duration::from_millis(300)
    );
}

#[test]
fn additional_delay_and_extreme_values_remain_capped() {
    assert_eq!(
        scaled_delay(Some(Duration::from_millis(40)), Duration::from_millis(100)),
        Duration::from_millis(160)
    );
    assert_eq!(
        scaled_delay(None, Duration::from_millis(100)),
        Duration::from_millis(400)
    );
    assert_eq!(
        scaled_delay(Some(Duration::MAX), Duration::ZERO),
        Duration::from_secs(3)
    );
    assert_eq!(scaled_delay(None, Duration::MAX), Duration::from_secs(3));
}

#[tokio::test(start_paused = true)]
async fn reading_and_reusing_a_connection_does_not_restart_its_age() -> TestResult {
    let history = history(2)?;
    let origin = origin(443)?;
    let publication = measured(
        &history,
        &origin,
        "alt.test",
        8443,
        Duration::from_millis(40),
    )?;
    tokio::time::advance(Duration::from_secs(9)).await;
    assert_eq!(
        history.delay(&origin, &Route::Direct, &[target("alt.test", 8443)?]),
        Duration::from_millis(60)
    );
    publication.record(Some(Duration::from_millis(200)));
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(
        history.delay(&origin, &Route::Direct, &[target("alt.test", 8443)?]),
        Duration::ZERO
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn expired_sample_uses_fallback_when_another_target_succeeded_recently() -> TestResult {
    let history = history(2)?;
    let origin = origin(443)?;
    measured(
        &history,
        &origin,
        "alt.test",
        8443,
        Duration::from_millis(40),
    )?;
    tokio::time::advance(Duration::from_secs(5)).await;
    measured(
        &history,
        &origin,
        "other.test",
        8443,
        Duration::from_millis(10),
    )?;
    tokio::time::advance(Duration::from_secs(5)).await;
    assert_eq!(
        history.delay(&origin, &Route::Direct, &[target("alt.test", 8443)?]),
        Duration::from_millis(300)
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn origin_and_target_ports_have_separate_samples() -> TestResult {
    let history = history(4)?;
    let first = origin(443)?;
    let second = origin(8443)?;
    measured(
        &history,
        &first,
        "alt.test",
        8443,
        Duration::from_millis(10),
    )?;
    measured(
        &history,
        &first,
        "alt.test",
        9443,
        Duration::from_millis(20),
    )?;
    measured(
        &history,
        &second,
        "alt.test",
        8443,
        Duration::from_millis(30),
    )?;
    for (origin, port, delay) in [(&first, 8443, 15), (&first, 9443, 30), (&second, 8443, 45)] {
        assert_eq!(
            history.delay(origin, &Route::Direct, &[target("alt.test", port)?]),
            Duration::from_millis(delay)
        );
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn canonical_case_and_default_origin_ports_share_one_key() -> TestResult {
    let history = history(2)?;
    let plain = Endpoint::new("origin.test".parse()?, 443)?;
    let explicit = Endpoint::new("ORIGIN.test:443".parse()?, 443)?;
    measured(
        &history,
        &plain,
        "ALT.test",
        8443,
        Duration::from_millis(20),
    )?;
    assert_eq!(
        history.delay(&explicit, &Route::Direct, &[target("alt.test", 8443)?]),
        Duration::from_millis(30)
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn first_eligible_alternative_chooses_the_single_timer() -> TestResult {
    let history = history(3)?;
    let origin = origin(443)?;
    measured(
        &history,
        &origin,
        "slow.test",
        8443,
        Duration::from_millis(80),
    )?;
    measured(
        &history,
        &origin,
        "fast.test",
        8443,
        Duration::from_millis(10),
    )?;
    let mut broken = target("broken.test", 8443)?;
    broken.broken = true;
    let targets = [
        broken,
        target("slow.test", 8443)?,
        target("fast.test", 8443)?,
    ];
    assert_eq!(
        history.delay(&origin, &Route::Direct, &targets),
        Duration::from_millis(120)
    );
    assert_eq!(targets[1].host(), "slow.test");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn recent_origin_quic_breakage_skips_the_wait() -> TestResult {
    let history = history(1)?;
    let origin = origin(443)?;
    measured(
        &history,
        &origin,
        "alt.test",
        8443,
        Duration::from_millis(20),
    )?;
    assert_eq!(
        history.delay(
            &origin,
            &Route::Direct,
            &[target("alt.test", 8443)?.without_early_data()]
        ),
        Duration::ZERO
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn clients_and_proxy_routes_cannot_share_direct_history() -> TestResult {
    let first = history(2)?;
    let second = history(2)?;
    let origin = origin(443)?;
    let proxy = Route::Socks5(Socks5Proxy::new("socks5://proxy.test:1080")?);
    assert!(
        first
            .publication(&origin, &proxy, "alt.test", 8443, true)
            .is_none()
    );
    assert!(
        first
            .publication(&origin, &Route::Direct, "alt.test", 8443, false)
            .is_none()
    );
    measured(&first, &origin, "alt.test", 8443, Duration::from_millis(20))?;
    assert_eq!(
        first.delay(&origin, &proxy, &[target("alt.test", 8443)?]),
        Duration::ZERO
    );
    assert_eq!(
        second.delay(&origin, &Route::Direct, &[target("alt.test", 8443)?]),
        Duration::ZERO
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn clear_prevents_pending_and_pooled_connections_from_reseeding() -> TestResult {
    let history = history(2)?;
    let origin = origin(443)?;
    let pooled = measured(
        &history,
        &origin,
        "alt.test",
        8443,
        Duration::from_millis(20),
    )?;
    let pending = history
        .publication(&origin, &Route::Direct, "later.test", 8443, true)
        .ok_or("pending absent")?;
    history.clear();
    pooled.record(Some(Duration::from_millis(100)));
    pending.record(Some(Duration::from_millis(100)));
    assert_eq!(
        history.delay(&origin, &Route::Direct, &[target("later.test", 8443)?]),
        Duration::ZERO
    );
    measured(
        &history,
        &origin,
        "later.test",
        8443,
        Duration::from_millis(10),
    )?;
    assert_eq!(
        history.delay(&origin, &Route::Direct, &[target("later.test", 8443)?]),
        Duration::from_millis(15)
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn broken_target_invalidation_also_revokes_delayed_publication() -> TestResult {
    let history = history(2)?;
    let origin = origin(443)?;
    measured(
        &history,
        &origin,
        "alt.test",
        8443,
        Duration::from_millis(20),
    )?;
    let delayed = history
        .publication(&origin, &Route::Direct, "alt.test", 8443, true)
        .ok_or("pending absent")?;
    history.invalidate(&origin, &Route::Direct, "alt.test", 8443);
    delayed.record(Some(Duration::from_millis(200)));
    assert_eq!(
        history.delay(&origin, &Route::Direct, &[target("alt.test", 8443)?]),
        Duration::from_millis(300)
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn lru_eviction_is_bounded_and_revokes_pending_tokens() -> TestResult {
    let history = history(2)?;
    let origin = origin(443)?;
    let evicted = history
        .publication(&origin, &Route::Direct, "first.test", 8443, true)
        .ok_or("pending absent")?;
    measured(
        &history,
        &origin,
        "second.test",
        8443,
        Duration::from_millis(20),
    )?;
    measured(
        &history,
        &origin,
        "third.test",
        8443,
        Duration::from_millis(30),
    )?;
    evicted.record(Some(Duration::from_millis(100)));
    assert_eq!(history.lock().entries.len(), 2);
    assert_eq!(
        history.delay(&origin, &Route::Direct, &[target("first.test", 8443)?]),
        Duration::from_millis(300)
    );
    Ok(())
}
