mod publication;

use std::{future::pending, time::Duration};

use phantom_net::tcp::{AddressFamily, SlowerConnection, SlowerProgress};
use tokio::{io::DuplexStream, sync::oneshot};

use super::*;
use crate::session::prune_timer::{PruneTimer, PrunedEntry};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn adopt(entry: &Arc<PoolEntry>, slower: SlowerConnection<phantom_net::http2::Http2Connection>) {
    let id = {
        let mut state = entry.lock();
        entry.family.mark_active();
        state.register_spare()
    };
    entry.spawn_spare(tokio::runtime::Handle::current(), id, slower);
}

fn connected_progress() -> SlowerProgress {
    let progress = SlowerProgress::new();
    progress.mark_connected();
    progress
}

struct Ended(Option<oneshot::Sender<()>>);
impl Drop for Ended {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

async fn connection()
-> Result<(phantom_net::http2::Http2Connection, DuplexStream), Box<dyn std::error::Error>> {
    let (client, mut server) = tokio::io::duplex(64 * 1024);
    use tokio::io::AsyncWriteExt as _;
    server.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await?;
    Ok((
        phantom_net::http2::Http2Connection::connect(
            client,
            &phantom_profile::browser::firefox::v157_http2(),
        )
        .await?,
        server,
    ))
}

#[tokio::test]
async fn dropping_the_pool_entry_cancels_its_connected_backup_setup() -> TestResult {
    let entry = cold_entry().await?;
    let (started, entered) = oneshot::channel();
    let (ended, dropped) = oneshot::channel();
    adopt(
        &entry,
        SlowerConnection::new(connected_progress(), async move {
            let _ended = Ended(Some(ended));
            let _ = started.send(());
            pending().await
        }),
    );
    tokio::time::timeout(Duration::from_secs(1), entered).await??;
    assert_eq!(entry.lock().spares.len(), 1);
    assert!(!entry.prune(tokio::time::Instant::now(), None).empty);
    let owner = Arc::downgrade(&entry);
    drop(entry);
    tokio::time::timeout(Duration::from_secs(1), dropped).await??;
    assert!(
        owner.upgrade().is_none(),
        "the task retained its pool owner"
    );
    Ok(())
}

#[tokio::test]
async fn a_failed_connected_backup_wakes_waiters_and_releases_its_slot() -> TestResult {
    let entry = cold_entry().await?;
    let (release, released) = oneshot::channel();
    adopt(
        &entry,
        SlowerConnection::new(connected_progress(), async move {
            let _ = released.await;
            None
        }),
    );
    let mut waiter = std::pin::pin!(entry.setup_done.notified());
    waiter.as_mut().enable();
    assert!(poll_once(waiter.as_mut()).is_none());
    release.send(()).map_err(|_| "backup task disappeared")?;
    tokio::time::timeout(Duration::from_secs(1), waiter).await?;
    assert!(entry.lock().spares.is_empty());
    assert!(entry.prune(tokio::time::Instant::now(), None).empty);
    assert_eq!(entry.admission.available_active(), 1);
    Ok(())
}

#[tokio::test]
async fn a_finished_backup_is_closed_when_the_current_h2_session_can_serve() -> TestResult {
    let entry = cold_entry().await?;
    let (first, _first_peer) = connection().await?;
    drop(reserve(&entry).finish(first, None));
    let (spare, mut peer) = connection().await?;
    let mut changed = std::pin::pin!(entry.setup_done.notified());
    changed.as_mut().enable();
    adopt(
        &entry,
        SlowerConnection::new(connected_progress(), async { Some(spare) }),
    );
    tokio::time::timeout(Duration::from_secs(1), changed).await?;
    assert!(entry.lock().spares.is_empty());
    assert_eq!(entry.lock().slots.len(), 1);
    // Dropping the redundant connection closes its real protocol driver.
    use tokio::io::AsyncReadExt as _;
    let mut frames = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), peer.read_to_end(&mut frames)).await??;
    assert!(frames.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
    Ok(())
}

#[tokio::test]
async fn a_finished_backup_replaces_a_retired_h2_session_without_a_new_setup() -> TestResult {
    let entry = cold_entry().await?;
    let (first, _first_peer) = connection().await?;
    let lease = reserve(&entry).finish(first, None);
    let (spare, _spare_peer) = connection().await?;
    let (release, released) = oneshot::channel();
    adopt(
        &entry,
        SlowerConnection::new(connected_progress(), async move {
            let _ = released.await;
            Some(spare)
        }),
    );
    entry.invalidate(&lease.token).await;
    drop(lease);
    assert!(!entry.lock().spares.is_empty());
    assert!(!entry.lock().connecting);
    let connector = phantom_net::http2::Http2TlsConnector::new(
        &phantom_profile::browser::firefox::v157_tcp_tls(),
        &phantom_profile::browser::firefox::v157_http2(),
    )?;
    let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
    {
        let mut waiting = std::pin::pin!(entry.acquire(
            &connector,
            None,
            &endpoint,
            &Route::Direct,
            super::super::Http2ConnectionMode::TlsOrigin,
        ));
        assert!(poll_once(waiting.as_mut()).is_none());
        assert!(
            !entry.lock().connecting,
            "waiter opened another connection instead of awaiting the backup"
        );
    }
    let mut changed = std::pin::pin!(entry.setup_done.notified());
    changed.as_mut().enable();
    release.send(()).map_err(|_| "backup task disappeared")?;
    tokio::time::timeout(Duration::from_secs(1), changed).await?;
    assert!(entry.lock().spares.is_empty());
    assert_eq!(entry.lock().slots.len(), 1);
    assert!(matches!(
        entry.lock().choose(),
        super::super::Choice::Use(0)
    ));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn family_pruning_waits_for_connected_backup_ownership() -> TestResult {
    let timer = PruneTimer::unscheduled(Duration::from_secs(115));
    let one = NonZeroUsize::MIN;
    let pool = Http2Pool::new(one, one, one).with_prune_timer(Some(Arc::clone(&timer)));
    let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
    let key = PoolKey::new(
        &endpoint,
        &Route::Direct,
        super::super::Http2ConnectionMode::TlsOrigin,
    );
    let entry = pool.entry(key.clone()).await;
    let mut other_runtime_key = key;
    other_runtime_key.runtime = None;
    let other = pool.entry(other_runtime_key).await;
    assert!(Arc::ptr_eq(&entry.family, &other.family));
    entry.family.remember(AddressFamily::Ipv4);
    let (release, released) = oneshot::channel();
    adopt(
        &entry,
        SlowerConnection::new(connected_progress(), async move {
            let _ = released.await;
            None
        }),
    );
    timer.idle_added(Duration::from_secs(1));
    tokio::time::advance(Duration::from_secs(1)).await;
    timer.fire();
    assert_eq!(entry.family.family(), Some(AddressFamily::Ipv4));
    let mut changed = std::pin::pin!(entry.setup_done.notified());
    changed.as_mut().enable();
    release.send(()).map_err(|_| "backup task disappeared")?;
    tokio::time::timeout(Duration::from_secs(1), changed).await?;
    tokio::time::advance(Duration::from_secs(1)).await;
    timer.fire();
    assert_eq!(entry.family.family(), None);
    assert_eq!(other.family.family(), None);
    Ok(())
}
