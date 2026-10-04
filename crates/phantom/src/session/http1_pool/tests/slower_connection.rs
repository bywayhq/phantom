//! The slower connection of a backup connection, which a pool key keeps,
//! and the prune timer's closing of idle connections.

use std::{sync::Arc, time::Duration};

use phantom_net::{
    http1::Http1Connection,
    tcp::{AddressFamily, SlowerConnection, SlowerProgress},
};
use tokio::{
    sync::oneshot,
    time::{Instant, timeout},
};

use super::{TestResult, bound, connection, connections};
use crate::session::{
    http1_pool::{Checkout, EntryConnections, Http1ConnectionMode, Http1Pool, PoolKey},
    prune_timer::{PruneTimer, PrunedEntry},
};
use crate::{Route, authority::Endpoint};

const WAIT: Duration = Duration::from_secs(5);
const LIMIT: Duration = Duration::from_secs(115);

/// A slower connection whose setup ends with the outcome the test sends.
fn gated() -> (
    SlowerConnection<Http1Connection>,
    SlowerProgress,
    oneshot::Sender<Option<Http1Connection>>,
) {
    let progress = SlowerProgress::new();
    let (sender, receiver) = oneshot::channel();
    let slower = SlowerConnection::new(
        progress.clone(),
        async move { receiver.await.ok().flatten() },
    );
    (slower, progress, sender)
}

/// Waits until the key's slower connections have finished.
async fn settled(connections: &EntryConnections) -> TestResult {
    timeout(WAIT, async {
        while !connections.lock().spares.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn a_finished_slower_connection_waits_idle_for_the_next_request() -> TestResult {
    let connections = connections(bound(6)?);
    let (slower, progress, finish) = gated();
    connections.adopt(slower);
    let (connection, _peer) = connection().await?;
    progress.mark_connected();
    finish
        .send(Some(connection))
        .map_err(|_| "the slower connection's task ended")?;
    settled(&connections).await?;

    assert_eq!(connections.open(), 1);
    let Checkout::Idle(_lease) = connections.checkout(false) else {
        return Err("the slower connection was not idle".into());
    };
    Ok(())
}

#[tokio::test]
async fn a_slower_connection_counts_toward_the_bound_once_it_connects() -> TestResult {
    let connections = connections(bound(6)?);
    let (slower, progress, _finish) = gated();
    connections.adopt(slower);
    assert_eq!(connections.open(), 0);

    progress.mark_connected();

    assert_eq!(connections.open(), 1);
    Ok(())
}

#[tokio::test]
async fn a_request_claims_a_slower_connection_still_in_its_setup() -> TestResult {
    let connections = connections(bound(6)?);
    let (slower, progress, finish) = gated();
    connections.adopt(slower);
    let Checkout::Spare(claim) = connections.checkout(false) else {
        return Err("the request did not claim the slower connection".into());
    };
    // Another request finds it claimed and opens a connection of its own.
    let Checkout::Reserved(_reservation) = connections.checkout(false) else {
        return Err("a second request claimed the slower connection".into());
    };

    let (connection, _peer) = connection().await?;
    progress.mark_connected();
    finish
        .send(Some(connection))
        .map_err(|_| "the slower connection's task ended")?;
    let lease = timeout(WAIT, claim.wait())
        .await?
        .ok_or("the claim was dropped")?;

    assert_eq!(connections.lock().leased, 2);
    assert!(connections.lock().idle.is_empty());
    drop(lease);
    assert_eq!(connections.lock().idle.len(), 1);
    Ok(())
}

#[tokio::test]
async fn a_failed_slower_connection_lets_its_claimant_open_a_connection() -> TestResult {
    let connections = connections(bound(6)?);
    let (slower, _progress, finish) = gated();
    connections.adopt(slower);
    let Checkout::Spare(claim) = connections.checkout(false) else {
        return Err("the request did not claim the slower connection".into());
    };

    finish
        .send(None)
        .map_err(|_| "the slower connection's task ended")?;

    assert!(timeout(WAIT, claim.wait()).await?.is_none());
    let Checkout::Reserved(_reservation) = connections.checkout(false) else {
        return Err("the request did not open a connection".into());
    };
    Ok(())
}

#[tokio::test]
async fn a_claimant_that_leaves_returns_the_slower_connection_to_idle() -> TestResult {
    let connections = connections(bound(6)?);
    let (slower, _progress, finish) = gated();
    connections.adopt(slower);
    let Checkout::Spare(claim) = connections.checkout(false) else {
        return Err("the request did not claim the slower connection".into());
    };
    drop(claim);

    let (connection, _peer) = connection().await?;
    finish
        .send(Some(connection))
        .map_err(|_| "the slower connection's task ended")?;
    settled(&connections).await?;

    assert_eq!(connections.lock().leased, 0);
    assert_eq!(connections.lock().idle.len(), 1);
    Ok(())
}

#[tokio::test]
async fn a_fresh_connection_request_skips_the_slower_connection() -> TestResult {
    let connections = connections(bound(6)?);
    let (slower, _progress, _finish) = gated();
    connections.adopt(slower);

    let Checkout::Reserved(_reservation) = connections.checkout(true) else {
        return Err("a fresh-connection request took the slower connection".into());
    };
    Ok(())
}

fn timed(timer: &Arc<PruneTimer>) -> Result<Arc<EntryConnections>, Box<dyn std::error::Error>> {
    Ok(EntryConnections::new(
        bound(6)?,
        timer.http1_limit(),
        Some(Arc::clone(timer)),
        Arc::default(),
    ))
}

#[tokio::test(start_paused = true)]
async fn the_prune_closes_a_connection_idle_for_the_limit() -> TestResult {
    let timer = PruneTimer::unscheduled(LIMIT);
    let connections = timed(&timer)?;
    let (connection, _peer) = connection().await?;
    let Checkout::Reserved(reservation) = connections.checkout(false) else {
        return Err("an empty key leased a connection".into());
    };
    let start = Instant::now();
    drop(reservation.into_lease(connection));
    assert_eq!(timer.wake_at(), Some(start + LIMIT));

    tokio::time::advance(LIMIT - Duration::from_millis(500)).await;
    let pruned = connections.prune(Instant::now(), Some(LIMIT));
    assert_eq!(pruned.next, Some(Duration::from_millis(500)));
    assert!(!pruned.empty);
    assert_eq!(connections.lock().idle.len(), 1);

    tokio::time::advance(Duration::from_millis(500)).await;
    let pruned = connections.prune(Instant::now(), Some(LIMIT));
    assert_eq!(pruned.next, None);
    assert!(pruned.empty);
    assert!(connections.lock().idle.is_empty());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn the_prune_forgets_the_family_only_of_a_key_without_connections() -> TestResult {
    let timer = PruneTimer::unscheduled(LIMIT);
    let connections = timed(&timer)?;
    connections.family.remember(AddressFamily::Ipv4);
    let (connection, _peer) = connection().await?;
    let Checkout::Reserved(reservation) = connections.checkout(false) else {
        return Err("an empty key leased a connection".into());
    };
    let lease = reservation.into_lease(connection);

    timer.fire();
    assert_eq!(connections.family.family(), Some(AddressFamily::Ipv4));

    drop(lease);
    timer.fire();
    assert_eq!(connections.family.family(), Some(AddressFamily::Ipv4));

    tokio::time::advance(LIMIT).await;
    timer.fire();
    assert_eq!(connections.family.family(), None);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_key_with_a_slower_attempt_keeps_its_family() -> TestResult {
    let timer = PruneTimer::unscheduled(LIMIT);
    let connections = timed(&timer)?;
    connections.family.remember(AddressFamily::Ipv6);
    let (slower, _progress, _finish) = gated();
    connections.adopt(slower);

    timer.fire();

    assert_eq!(connections.family.family(), Some(AddressFamily::Ipv6));
    Ok(())
}

/// A slower attempt whose runtime is dropped before it finishes leaves its
/// key, so the key reports empty and the origin's family is forgotten.
#[test]
fn a_slower_attempt_dropped_with_its_runtime_leaves_the_key() -> TestResult {
    let timer = PruneTimer::unscheduled(LIMIT);
    let connections = timed(&timer)?;
    connections.family.remember(AddressFamily::Ipv4);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (slower, progress, _finish) = gated();
    runtime.block_on(async { connections.adopt(slower) });
    progress.mark_connected();
    assert_eq!(connections.open(), 1);

    drop(runtime);

    assert!(connections.lock().spares.is_empty());
    assert_eq!(connections.open(), 0);
    assert!(connections.prune(Instant::now(), Some(LIMIT)).empty);
    timer.fire();
    assert_eq!(connections.family.family(), None);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn the_client_timer_prunes_every_pool_entry() -> TestResult {
    let timer = PruneTimer::unscheduled(LIMIT);
    let one = std::num::NonZeroUsize::MIN;
    let pool = Http1Pool::new(one, one, one).with_prune_timer(Some(Arc::clone(&timer)));
    let origin = Endpoint::new("origin.test:443".parse()?, 443)?;
    let entry = pool
        .entry(PoolKey::new(
            &origin,
            &Route::Direct,
            Http1ConnectionMode::TlsOrigin,
        ))
        .await;
    entry.connections.family.remember(AddressFamily::Ipv4);

    timer.fire();

    assert_eq!(entry.connections.family.family(), None);
    Ok(())
}

/// A pool key per runtime, so a runtime's request never takes a connection
/// another runtime drives: the first runtime's slower connection counts only
/// toward its own key, and the second runtime's request opens a connection
/// of its own. Admission and the address family stay per origin.
#[test]
fn a_slower_connection_stays_with_its_runtime_and_the_origin_state_is_shared() -> TestResult {
    let pool = Http1Pool::new(bound(4)?, bound(6)?, std::num::NonZeroUsize::MIN);
    let origin = Endpoint::new("origin.test:443".parse()?, 443)?;
    let key = || PoolKey::new(&origin, &Route::Direct, Http1ConnectionMode::TlsOrigin);
    let first = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let second = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (slower, progress, _finish) = gated();

    let on_first = first.block_on(async {
        let entry = pool.entry(key()).await;
        entry.connections.adopt(slower);
        entry
    });
    progress.mark_connected();
    let on_second = second.block_on(async { pool.entry(key()).await });

    assert!(!Arc::ptr_eq(&on_first, &on_second));
    assert!(Arc::ptr_eq(&on_first.admission, &on_second.admission));
    assert!(Arc::ptr_eq(
        &on_first.connections.family,
        &on_second.connections.family
    ));
    assert_eq!(on_first.connections.open(), 1);
    assert_eq!(on_second.connections.open(), 0);
    let Checkout::Reserved(_reservation) = on_second.connections.checkout(false) else {
        return Err("a request claimed another runtime's slower connection".into());
    };
    Ok(())
}

/// The client's timer runs on the deadline service, so an idle connection
/// on a second runtime still closes at its limit after the runtime that set
/// the timer is gone. The deadline service keeps the wall clock, so the test
/// uses a one-second limit.
#[test]
fn an_idle_connection_closes_after_the_runtime_that_set_the_timer_is_gone() -> TestResult {
    let limit = Duration::from_secs(1);
    let timer = PruneTimer::new(Some(limit));
    let pool = Http1Pool::new(bound(4)?, bound(6)?, std::num::NonZeroUsize::MIN)
        .with_used_idle_timeout(Some(limit))
        .with_prune_timer(Some(Arc::clone(&timer)));
    let origin = Endpoint::new("origin.test:443".parse()?, 443)?;
    let key = || PoolKey::new(&origin, &Route::Direct, Http1ConnectionMode::TlsOrigin);
    let first = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let second = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()?;
    let idle_on = |runtime: &tokio::runtime::Runtime| {
        runtime.block_on(async {
            let entry = pool.entry(key()).await;
            let (connection, peer) = connection().await?;
            let Checkout::Reserved(reservation) = entry.connections.checkout(false) else {
                return Err::<_, Box<dyn std::error::Error>>("the key leased a connection".into());
            };
            drop(reservation.into_lease(connection));
            Ok((entry, peer))
        })
    };

    let (_first_entry, _first_peer) = idle_on(&first)?;
    let (second_entry, _second_peer) = idle_on(&second)?;
    assert!(timer.wake_at().is_some());
    drop(first);

    let deadline = std::time::Instant::now() + WAIT;
    while !second_entry.connections.lock().idle.is_empty() {
        if std::time::Instant::now() > deadline {
            return Err("the idle connection was never closed".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}
