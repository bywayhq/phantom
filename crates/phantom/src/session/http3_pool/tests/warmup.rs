use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use phantom_net::http3::Http3Connector;
use phantom_profile::browser::firefox;

use super::{Http3Pool, Http3TransportTarget, PoolKey, TransportLocation, poll_once};
use crate::{
    AltSvcSnapshot, AltSvcSnapshotEntry, RequestTimeouts, Route,
    authority::Endpoint,
    session::alt_svc::{AltSvcStore, AlternativeTarget},
    timeout::TimeoutBudget,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn a_warmup_without_a_mapping_witness_does_not_create_a_pool_entry() -> TestResult {
    let one = NonZeroUsize::MIN;
    let pool = Http3Pool::new(one, one, one);
    let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
    assert!(
        !pool
            .warmup(
                &connector()?,
                None,
                &endpoint,
                &Route::Direct,
                Http3TransportTarget::for_origin(&endpoint),
                budget()?,
                None,
            )
            .await?
    );
    assert!(pool.state.lock().await.entries.is_empty());
    Ok(())
}

#[tokio::test]
async fn refresh_during_a_warmup_connect_turn_prevents_setup_and_publication() -> TestResult {
    stale_waiting_warmup(true).await
}

#[tokio::test]
async fn eviction_during_a_warmup_connect_turn_prevents_setup_and_publication() -> TestResult {
    stale_waiting_warmup(false).await
}

async fn stale_waiting_warmup(refresh: bool) -> TestResult {
    let one = NonZeroUsize::MIN;
    let pool = Http3Pool::new(one, one, one);
    let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
    let (store, target) = alternative(&endpoint)?;
    let connector = connector()?;
    let entry = pool.entry(PoolKey::new(&endpoint, &Route::Direct)).await;
    let location = TransportLocation::new(Http3TransportTarget::for_alternative(&target));
    let turn = entry.connect_turn(location).await;
    let mut warmup = Box::pin(pool.warmup(
        &connector,
        None,
        &endpoint,
        &Route::Direct,
        Http3TransportTarget::for_alternative(&target),
        budget()?,
        None,
    ));
    assert!(poll_once(warmup.as_mut()).is_none());
    assert_eq!(entry.admission.available_active(), 1);

    if refresh {
        pool.refresh_connections().await;
    } else {
        let other = Endpoint::new("other.test:443".parse()?, 443)?;
        pool.entry(PoolKey::new(&other, &Route::Direct)).await;
        pool.entry(PoolKey::new(&endpoint, &Route::Direct)).await;
    }
    drop(turn);

    assert!(!warmup.await?);
    assert!(entry.lock_slots().connections.is_empty());
    let current = pool.entry(PoolKey::new(&endpoint, &Route::Direct)).await;
    assert!(!Arc::ptr_eq(&entry, &current));
    assert!(current.lock_slots().connections.is_empty());
    assert!(!selected(&store, &endpoint)?.mapping_validated());
    Ok(())
}

#[tokio::test]
async fn cancelling_a_waiting_warmup_releases_its_connect_turn() -> TestResult {
    let one = NonZeroUsize::MIN;
    let pool = Http3Pool::new(one, one, one);
    let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
    let (_store, target) = alternative(&endpoint)?;
    let connector = connector()?;
    let entry = pool.entry(PoolKey::new(&endpoint, &Route::Direct)).await;
    let location = TransportLocation::new(Http3TransportTarget::for_alternative(&target));
    let turn = entry.connect_turn(location.clone()).await;
    let mut warmup = Box::pin(pool.warmup(
        &connector,
        None,
        &endpoint,
        &Route::Direct,
        Http3TransportTarget::for_alternative(&target),
        budget()?,
        None,
    ));
    assert!(poll_once(warmup.as_mut()).is_none());
    drop(warmup);
    drop(turn);
    let mut next = Box::pin(entry.connect_turn(location));
    let next = poll_once(next.as_mut()).ok_or("cancelled warmup retained the connect turn")?;
    drop(next);
    assert!(entry.lock_slots().connections.is_empty());
    assert_eq!(entry.admission.available_active(), 1);
    Ok(())
}

pub(super) fn alternative(endpoint: &Endpoint) -> TestResult<(AltSvcStore, AlternativeTarget)> {
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let origin = if endpoint.port() == 443 {
        format!("https://{}", endpoint.host())
    } else {
        format!("https://{}", endpoint.authority())
    };
    store.import(&AltSvcSnapshot::new(vec![AltSvcSnapshotEntry::new(
        origin,
        endpoint.host(),
        endpoint.port(),
        std::time::SystemTime::now() + Duration::from_secs(60),
    )]))?;
    let target = selected(&store, endpoint)?;
    Ok((store, target))
}

pub(super) fn selected(store: &AltSvcStore, endpoint: &Endpoint) -> TestResult<AlternativeTarget> {
    store
        .get_up_to(endpoint, &Route::Direct, 1)
        .first()
        .map(AlternativeTarget::new)
        .ok_or_else(|| "missing alternative".into())
}

fn connector() -> TestResult<Http3Connector> {
    Ok(Http3Connector::new_with_additional_roots(
        &firefox::v157_quic_tls(),
        &firefox::v157_quic(),
        &firefox::v157_http3(),
        &firefox::v157_http3_request(),
        std::iter::empty(),
    )?)
}

fn budget() -> Result<TimeoutBudget, crate::RequestError> {
    TimeoutBudget::new(RequestTimeouts::new().total(Duration::from_secs(5)))
}
