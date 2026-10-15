use super::*;
use crate::session::prune_timer::PrunedEntry;
use phantom_net::{
    http2::{Http2Connection, Http2TlsConnector},
    tcp::{AddressFamily, SlowerConnection},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::oneshot,
    time::{Duration, timeout},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

async fn connection()
-> Result<(Http2Connection, tokio::io::DuplexStream), Box<dyn std::error::Error>> {
    let (stream, mut peer) = tokio::io::duplex(65536);
    peer.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await?;
    let connection =
        Http2Connection::connect(stream, &phantom_profile::browser::firefox::v157_http2()).await?;
    Ok((connection, peer))
}

async fn finished(entry: &Arc<PoolEntry>) -> TestResult {
    timeout(Duration::from_secs(1), async {
        loop {
            let notified = entry.setup_done.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if entry.lock().spares.is_empty() {
                return;
            }
            notified.await;
        }
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn cancelled_h2_opening_releases_family_ownership_and_wakes_waiters() -> TestResult {
    let entry = cold_entry().await?;
    entry.family.remember(AddressFamily::Ipv4);
    let opening = entry.begin_http2_opening();
    assert!(!entry.prune(tokio::time::Instant::now(), None).empty);
    let notified = entry.setup_done.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    drop(opening);
    timeout(Duration::from_secs(1), notified).await?;
    assert!(entry.prune(tokio::time::Instant::now(), None).empty);
    assert_eq!(entry.lock().openings, 0);
    Ok(())
}

#[tokio::test]
async fn dedicated_winner_and_backup_are_published_before_waiter_notification() -> TestResult {
    let entry = cold_entry().await?;
    let opening = entry.begin_http2_opening();
    let (winner, _winner_peer) = connection().await?;
    let (release, blocked) = oneshot::channel();
    let slower = SlowerConnection::new(phantom_net::tcp::SlowerProgress::new(), async move {
        let _ = blocked.await;
        None
    });
    let notified = entry.setup_done.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    let owner = opening.connected(&winner, Some(slower));
    timeout(Duration::from_secs(1), notified).await?;
    {
        let state = entry.lock();
        assert_eq!(state.openings, 0);
        assert_eq!(state.dedicated.len(), 1);
        assert_eq!(state.spares.len(), 1);
        assert!(!state.connecting);
        assert!(
            state.slots.is_empty(),
            "dedicated winner became an ordinary pooled session"
        );
    }
    let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
    let connector = Http2TlsConnector::new(
        &phantom_profile::browser::firefox::v157_tcp_tls(),
        &phantom_profile::browser::firefox::v157_http2(),
    )?;
    {
        let mut competing = std::pin::pin!(entry.acquire(
            &connector,
            None,
            &endpoint,
            &Route::Direct,
            super::super::Http2ConnectionMode::TlsOrigin,
        ));
        assert!(poll_once(competing.as_mut()).is_none());
        assert!(!entry.lock().connecting, "waiter reserved duplicate setup");
        assert_eq!(entry.lock().spares.len(), 1);
    }
    drop(winner);
    assert!(!entry.prune(tokio::time::Instant::now(), None).empty);
    release
        .send(())
        .map_err(|_| "backup receiver disappeared")?;
    finished(&entry).await?;
    assert!(!entry.prune(tokio::time::Instant::now(), None).empty);
    drop(owner);
    assert!(entry.prune(tokio::time::Instant::now(), None).empty);
    Ok(())
}

#[tokio::test]
async fn live_dedicated_h2_winner_closes_redundant_backup_without_pooling_either() -> TestResult {
    let entry = cold_entry().await?;
    let (winner, _winner_peer) = connection().await?;
    let (spare, mut peer) = connection().await?;
    let owner = entry.begin_http2_opening().connected(
        &winner,
        Some(SlowerConnection::new(
            phantom_net::tcp::SlowerProgress::new(),
            async { Some(spare) },
        )),
    );
    finished(&entry).await?;
    assert!(entry.lock().slots.is_empty());
    let mut bytes = Vec::new();
    timeout(Duration::from_secs(2), peer.read_to_end(&mut bytes)).await??;
    assert!(bytes.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
    assert!(winner.is_reusable());
    drop(owner);
    Ok(())
}

#[tokio::test]
async fn retired_dedicated_winner_allows_backup_but_stale_completion_cannot_install() -> TestResult
{
    let entry = cold_entry().await?;
    let (winner, mut winner_peer) = connection().await?;
    let (spare, _spare_peer) = connection().await?;
    let (release, blocked) = oneshot::channel();
    let owner = entry.begin_http2_opening().connected(
        &winner,
        Some(SlowerConnection::new(
            phantom_net::tcp::SlowerProgress::new(),
            async move {
                blocked.await.ok()?;
                Some(spare)
            },
        )),
    );
    winner_peer
        .write_all(&[0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        .await?;
    timeout(Duration::from_secs(1), async {
        while winner.is_reusable() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    release
        .send(())
        .map_err(|_| "backup receiver disappeared")?;
    finished(&entry).await?;
    assert_eq!(entry.lock().slots.len(), 1);
    let (stale, _stale_peer) = connection().await?;
    entry.spare_finished(u64::MAX, Some(stale));
    assert_eq!(entry.lock().slots.len(), 1);
    drop(owner);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn family_is_forgotten_only_after_the_last_dedicated_h2_stream_owner() -> TestResult {
    use crate::session::prune_timer::PruneTimer;
    let timer = PruneTimer::unscheduled(Duration::from_secs(115));
    let one = NonZeroUsize::MIN;
    let pool = Http2Pool::new(one, one, one).with_prune_timer(Some(Arc::clone(&timer)));
    let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
    let opening = pool.origin_http2_opening(&endpoint).await;
    let entry = Arc::clone(&opening.entry);
    entry.family.remember(AddressFamily::Ipv4);
    let (connection, _peer) = connection().await?;
    let owner = opening.connected(&connection, None);
    drop(connection);
    timer.idle_added(Duration::from_secs(1));
    tokio::time::advance(Duration::from_secs(1)).await;
    timer.fire();
    assert_eq!(entry.family.family(), Some(AddressFamily::Ipv4));
    drop(owner);
    tokio::time::advance(Duration::from_secs(1)).await;
    timer.fire();
    assert_eq!(entry.family.family(), None);
    Ok(())
}

#[tokio::test]
async fn entry_drop_aborts_the_owned_backup_after_the_dedicated_stream_leaves() -> TestResult {
    struct Cancelled(Option<oneshot::Sender<()>>);
    impl Drop for Cancelled {
        fn drop(&mut self) {
            if let Some(cancelled) = self.0.take() {
                let _ = cancelled.send(());
            }
        }
    }
    let entry = cold_entry().await?;
    let opening = entry.begin_http2_opening();
    let (winner, _peer) = connection().await?;
    let (started, running) = oneshot::channel();
    let (cancelled, observed) = oneshot::channel();
    let owner = opening.connected(
        &winner,
        Some(SlowerConnection::new(
            phantom_net::tcp::SlowerProgress::new(),
            async move {
                let _cancelled = Cancelled(Some(cancelled));
                let _ = started.send(());
                std::future::pending().await
            },
        )),
    );
    timeout(Duration::from_secs(1), running).await??;
    let weak = Arc::downgrade(&entry);
    drop(owner);
    drop(entry);
    assert!(weak.upgrade().is_none(), "backup task retained the entry");
    timeout(Duration::from_secs(1), observed).await??;
    Ok(())
}
