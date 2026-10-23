//! WebSocket contexts partition learned state and unused backup ownership.

use std::{num::NonZeroUsize, sync::Arc};

use phantom_net::{
    http1::Http1Connection,
    tcp::{AddressFamily, SlowerConnection, SlowerProgress},
};
use phantom_profile::{ClientProfile, browser::firefox};
use tokio::{io::AsyncReadExt, sync::oneshot, time::timeout};

use super::super::{bound, connection};
use super::{End, TestResult, WAIT, lifecycle_with_profile};
use crate::{
    Route,
    authority::Endpoint,
    session::{
        http1_pool::{Checkout, Http1ConnectionMode, Http1Pool, OriginOpening, PoolKey},
        prune_timer::PruneTimer,
    },
};

fn backup(opening: &OriginOpening) -> oneshot::Sender<Option<Http1Connection>> {
    let (finish, result) = oneshot::channel();
    opening.adopt(SlowerConnection::new(SlowerProgress::new(), async move {
        result.await.ok().flatten()
    }));
    finish
}

#[tokio::test]
async fn firefox_openings_release_their_separate_owner_on_every_terminal_path() -> TestResult {
    for (end, policy) in [
        (End::Cancelled, false),
        (End::Rejected, false),
        (End::Upgraded, true),
        (End::InvalidUpgrade, true),
    ] {
        lifecycle_with_profile(end, policy, firefox::v157_windows()).await?;
    }
    Ok(())
}

#[tokio::test]
async fn explicit_opening_without_websocket_settings_keeps_shared_state() -> TestResult {
    let profile = ClientProfile::new(firefox::v157_tcp_tls())
        .with_tcp(firefox::v157_tcp())
        .with_http1(firefox::v157_http1());
    lifecycle_with_profile(End::Cancelled, false, profile).await
}

#[tokio::test]
async fn two_websocket_openings_keep_their_family_and_unused_backup_out_of_http() -> TestResult {
    timeout(WAIT, async {
        let timer = PruneTimer::unscheduled(std::time::Duration::ZERO);
        let pool = Http1Pool::new(bound(4)?, NonZeroUsize::MIN, NonZeroUsize::MIN)
            .with_prune_timer(Some(Arc::clone(&timer)));
        let endpoint = Endpoint::new("origin.test:80".parse()?, 80)?;
        let first = pool.cleartext_websocket_opening(&endpoint).await;
        let family = Arc::clone(first.family());
        family.remember(AddressFamily::Ipv4);
        let finish = backup(&first);
        drop(first);
        timer.fire();

        let second = pool.cleartext_websocket_opening(&endpoint).await;
        assert!(Arc::ptr_eq(second.family(), &family));
        assert_eq!(second.family().family(), Some(AddressFamily::Ipv4));
        let http = pool
            .entry(PoolKey::new(
                &endpoint,
                &Route::Direct,
                Http1ConnectionMode::PlaintextOrigin,
            ))
            .await;
        assert_eq!(http.connections.family.family(), None);
        let Checkout::Reserved(reservation) = http.connections.checkout(false) else {
            return Err("HTTP claimed the WebSocket backup".into());
        };
        drop(reservation);

        let websocket = Arc::clone(&second.entry);
        let (connection, mut peer) = connection().await?;
        finish
            .send(Some(connection))
            .map_err(|_| "WebSocket backup cancelled")?;
        while websocket.connections.lock().idle.is_empty() {
            tokio::task::yield_now().await;
        }
        drop(second);
        timer.fire();
        assert_eq!(family.family(), Some(AddressFamily::Ipv4));
        assert!(http.connections.lock().idle.is_empty());
        pool.close_idle_connections().await;
        assert_eq!(peer.read(&mut [0; 1]).await?, 0);
        timer.fire();
        assert_eq!(family.family(), None);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn separate_context_does_not_duplicate_existing_http_admission() -> TestResult {
    let pool = Http1Pool::new(bound(4)?, NonZeroUsize::MIN, NonZeroUsize::MIN);
    let endpoint = Endpoint::new("origin.test:80".parse()?, 80)?;
    let http = pool
        .entry(PoolKey::new(
            &endpoint,
            &Route::Direct,
            Http1ConnectionMode::PlaintextOrigin,
        ))
        .await;
    let permit = http.admit().await?;
    let websocket = timeout(WAIT, pool.cleartext_websocket_opening(&endpoint)).await?;
    assert!(Arc::ptr_eq(&http.admission, &websocket.entry.admission));
    assert_eq!(http.admission.available_active(), 0);
    assert_eq!(websocket.entry.connections.lock().openings, 1);
    drop(websocket);
    assert_eq!(http.admission.available_active(), 0);
    drop(permit);
    assert_eq!(http.admission.available_active(), 1);
    Ok(())
}

#[tokio::test]
async fn refresh_and_close_idle_keep_pending_websocket_setup_owned() -> TestResult {
    timeout(WAIT, async {
        let pool = Http1Pool::new(bound(4)?, NonZeroUsize::MIN, NonZeroUsize::MIN);
        let endpoint = Endpoint::new("origin.test:80".parse()?, 80)?;
        let opening = pool.cleartext_websocket_opening(&endpoint).await;
        let family = Arc::clone(opening.family());
        family.remember(AddressFamily::Ipv4);
        let old = Arc::downgrade(&opening.entry.connections);
        let mut finish = backup(&opening);
        pool.close_idle_connections().await;
        assert!(!finish.is_closed(), "close-idle cancelled pending setup");
        pool.refresh_connections().await;
        let fresh = pool.cleartext_websocket_opening(&endpoint).await;
        assert!(!Arc::ptr_eq(
            &opening.entry.connections,
            &fresh.entry.connections
        ));
        assert!(Arc::ptr_eq(opening.family(), fresh.family()));
        assert!(Arc::ptr_eq(
            &opening.entry.admission,
            &fresh.entry.admission
        ));
        assert_eq!(fresh.family().family(), Some(AddressFamily::Ipv4));
        drop(opening);
        assert!(old.upgrade().is_some(), "refresh lost pending setup owner");
        drop(fresh);
        drop(pool);
        finish.closed().await;
        assert!(
            old.upgrade().is_none(),
            "pool drop retained abandoned setup"
        );
        Ok(())
    })
    .await?
}

#[test]
fn separate_family_is_shared_across_runtimes_but_not_origins_or_clients() -> TestResult {
    let pool = Http1Pool::new(bound(8)?, NonZeroUsize::MIN, NonZeroUsize::MIN);
    let endpoint = Endpoint::new("origin.test:80".parse()?, 80)?;
    let first = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let second = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let opening = first.block_on(pool.cleartext_websocket_opening(&endpoint));
    opening.family().remember(AddressFamily::Ipv4);
    let another = second.block_on(pool.cleartext_websocket_opening(&endpoint));
    assert!(!Arc::ptr_eq(
        &opening.entry.connections,
        &another.entry.connections
    ));
    assert!(Arc::ptr_eq(opening.family(), another.family()));
    assert_eq!(another.family().family(), Some(AddressFamily::Ipv4));
    assert!(Arc::ptr_eq(
        &opening.entry.admission,
        &another.entry.admission
    ));
    for authority in ["other.test:80", "origin.test:81"] {
        let other = Endpoint::new(authority.parse()?, 80)?;
        let isolated = first.block_on(pool.cleartext_websocket_opening(&other));
        assert_eq!(isolated.family().family(), None);
        assert!(!Arc::ptr_eq(
            &opening.entry.admission,
            &isolated.entry.admission
        ));
    }
    let independent = Http1Pool::new(bound(4)?, NonZeroUsize::MIN, NonZeroUsize::MIN);
    let isolated = first.block_on(independent.cleartext_websocket_opening(&endpoint));
    assert_eq!(isolated.family().family(), None);
    assert!(!Arc::ptr_eq(
        &opening.entry.admission,
        &isolated.entry.admission
    ));
    Ok(())
}
