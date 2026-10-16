use super::*;
use crate::session::prune_timer::PrunedEntry;
use phantom_net::tcp::{AddressFamily, SlowerConnection, SlowerProgress};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::oneshot,
};

async fn opening() -> Result<super::super::OriginHttp2Opening, Box<dyn std::error::Error>> {
    let one = NonZeroUsize::MIN;
    let pool = Http1Or2Pool::new(one, one, one, one, one, one);
    let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
    Ok(pool.origin_http2_opening(&endpoint).await)
}

async fn connection() -> Result<(Http2Connection, DuplexStream), Box<dyn std::error::Error>> {
    let (stream, mut peer) = duplex(65536);
    peer.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await?;
    Ok((
        Http2Connection::connect(stream, &chrome::v154_http2()).await?,
        peer,
    ))
}

async fn finished(entry: &EntryConnections) -> TestResult {
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
async fn cancelled_negotiated_h2_opening_releases_its_origin_family_owner() -> TestResult {
    let opening = opening().await?;
    let entry = Arc::clone(&opening.entry.connections);
    entry.family.remember(AddressFamily::Ipv4);
    assert!(!entry.prune(tokio::time::Instant::now(), None).empty);
    drop(opening);
    assert_eq!(entry.lock().openings, 0);
    assert!(entry.prune(tokio::time::Instant::now(), None).empty);
    Ok(())
}

#[tokio::test]
async fn dedicated_negotiated_winner_is_registered_with_backup_and_outlives_setup() -> TestResult {
    let opening = opening().await?;
    let entry = Arc::clone(&opening.entry.connections);
    let (winner, _winner_peer) = connection().await?;
    let (spare, mut peer) = connection().await?;
    let (release, blocked) = oneshot::channel();
    let owner = opening.connected(
        &winner,
        Some(SlowerConnection::new(SlowerProgress::new(), async move {
            blocked.await.ok()?;
            Some(spare)
        })),
    );
    {
        let state = entry.lock();
        assert_eq!(state.openings, 0);
        assert_eq!(state.dedicated.len(), 1);
        assert_eq!(state.spares.len(), 1);
        assert_eq!(state.connecting, 0);
        assert!(state.http2.is_empty());
    }
    release
        .send(())
        .map_err(|_| "backup receiver disappeared")?;
    finished(&entry).await?;
    assert!(entry.lock().http2.is_empty());
    let mut bytes = Vec::new();
    timeout(Duration::from_secs(2), peer.read_to_end(&mut bytes)).await??;
    assert!(bytes.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
    assert!(!entry.prune(tokio::time::Instant::now(), None).empty);
    drop(owner);
    assert!(entry.prune(tokio::time::Instant::now(), None).empty);
    Ok(())
}

#[tokio::test]
async fn retired_negotiated_dedicated_winner_does_not_block_backup_replacement() -> TestResult {
    let opening = opening().await?;
    let entry = Arc::clone(&opening.entry.connections);
    let (winner, mut peer) = connection().await?;
    let (spare, _spare_peer) = connection().await?;
    let (release, blocked) = oneshot::channel();
    let owner = opening.connected(
        &winner,
        Some(SlowerConnection::new(SlowerProgress::new(), async move {
            blocked.await.ok()?;
            Some(spare)
        })),
    );
    peer.write_all(&[0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
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
    assert_eq!(entry.lock().http2.len(), 1);
    let (stale, _stale_peer) = connection().await?;
    entry.spare_finished(u64::MAX, Some(Http1Or2Connection::Http2(stale)));
    assert_eq!(entry.lock().http2.len(), 1);
    drop(owner);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn negotiated_family_is_forgotten_after_dedicated_stream_ownership_ends() -> TestResult {
    use crate::session::prune_timer::PruneTimer;
    let timer = PruneTimer::unscheduled(Duration::from_secs(115));
    let one = NonZeroUsize::MIN;
    let pool =
        Http1Or2Pool::new(one, one, one, one, one, one).with_prune_timer(Some(Arc::clone(&timer)));
    let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
    let opening = pool.origin_http2_opening(&endpoint).await;
    let entry = Arc::clone(&opening.entry.connections);
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
    let opening = opening().await?;
    let entry = Arc::clone(&opening.entry.connections);
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

#[tokio::test]
async fn a_dedicated_backup_cannot_install_beside_another_reserved_setup() -> TestResult {
    let opening = opening().await?;
    let entry = Arc::clone(&opening.entry.connections);
    let (winner, _winner_peer) = connection().await?;
    let (backup, mut peer) = connection().await?;
    let (release, blocked) = oneshot::channel();
    let owner = opening.connected(
        &winner,
        Some(SlowerConnection::new(SlowerProgress::new(), async move {
            blocked.await.ok()?;
            Some(backup)
        })),
    );
    drop(owner);
    drop(winner);
    // Model the ordinary acquisition's concrete reservation, as other pool
    // tests do, before the old registered backup completes.
    entry.lock().connecting += 1;
    let reservation = super::super::Reservation {
        connections: Arc::clone(&entry),
        finished: false,
    };
    release
        .send(())
        .map_err(|_| "backup receiver disappeared")?;
    finished(&entry).await?;
    {
        let state = entry.lock();
        assert_eq!(state.connecting, 1);
        assert!(state.spares.is_empty());
        assert!(
            state.http2.is_empty(),
            "backup installed beside reserved setup"
        );
    }
    let mut bytes = Vec::new();
    timeout(Duration::from_secs(2), peer.read_to_end(&mut bytes)).await??;
    assert!(bytes.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
    drop(reservation);
    assert_eq!(entry.lock().connecting, 0);
    Ok(())
}

#[tokio::test]
async fn negotiated_proxy_websocket_owner_shares_only_its_actual_route_entry_and_ticket_cache()
-> TestResult {
    let one = NonZeroUsize::MIN;
    let capacity = one.saturating_add(3);
    let pool = Http1Or2Pool::new(capacity, one, one, one, one, one);
    let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
    let route = Route::http_proxy(crate::HttpProxy::new("http://proxy.test:8080")?);
    let opening = pool.proxy_http2_opening(&endpoint, &route).await;
    let entry = pool.entry(PoolKey::new(&endpoint, &route)).await;
    assert!(Arc::ptr_eq(&opening.entry, &entry));
    let base = phantom_net::http1_or_2::Http1Or2TlsConnector::new(
        &phantom_profile::browser::firefox::v157_tcp_tls(),
        &phantom_profile::browser::firefox::v157_http2(),
    )?;
    let ordinary = entry.origin_connector(&base, &endpoint, &route)?;
    let dedicated = opening.proxy_origin_connector(&base, &endpoint, &route)?;
    let ordinary_cache = ordinary
        .session_ticket_cache()
        .and_then(|cache| cache.upgrade())
        .ok_or("missing ordinary ticket cache")?;
    let dedicated_cache = dedicated
        .session_ticket_cache()
        .and_then(|cache| cache.upgrade())
        .ok_or("missing opening ticket cache")?;
    assert!(ordinary_cache.same_cache(&dedicated_cache));
    let direct = pool.origin_http2_opening(&endpoint).await;
    assert!(!Arc::ptr_eq(&opening.entry, &direct.entry));
    let other_route = Route::http_proxy(crate::HttpProxy::new("http://proxy.test:8081")?);
    let other = pool.proxy_http2_opening(&endpoint, &other_route).await;
    assert!(!Arc::ptr_eq(&opening.entry, &other.entry));
    assert_eq!(entry.connections.lock().openings, 1);
    let notified = entry.connections.setup_done.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    drop(opening);
    timeout(Duration::from_secs(1), notified).await?;
    assert_eq!(entry.connections.lock().openings, 0);
    assert_eq!(entry.connections.lock().connecting, 0);
    assert!(ordinary_cache.same_cache(&dedicated_cache));
    drop((direct, other));
    Ok(())
}
