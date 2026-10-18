use super::*;

#[tokio::test]
async fn refresh_preserves_old_setup_and_selects_a_new_proxy_owner() -> TestResult {
    let pool = Http2ProxyPool::new();
    let settings = ConnectionSettingsId::default();
    let peers = std::sync::Mutex::new(Vec::new());
    let (release, released) = oneshot::channel();
    let mut old = Box::pin(pool.acquire(key(&settings), |_| async {
        released
            .await
            .map_err(|_| HttpConnectError::RuntimeUnavailable)?;
        connection(&peers).await
    }));
    assert!(!poll_once(&mut old).await);
    pool.clone().refresh_connections();
    let fresh = pool.acquire(key(&settings), |_| connection(&peers)).await?;
    assert!(!fresh.reused);
    release.send(()).map_err(|_| "old setup cancelled")?;
    let old = old.await?;
    assert!(!old.reused);
    // The stale setup's completion cannot replace the current physical session.
    let current = pool
        .acquire(key(&settings), |_| async {
            Err(HttpConnectError::RuntimeUnavailable)
        })
        .await?;
    assert!(current.reused);
    assert!(Arc::ptr_eq(&fresh.tunnel.route, &current.tunnel.route));
    assert!(!Arc::ptr_eq(&old.tunnel.route, &current.tunnel.route));
    Ok(())
}

#[tokio::test]
async fn close_idle_preserves_forwarding_handles_and_reopens_after_release() -> TestResult {
    let pool = Http2ProxyPool::new();
    let settings = ConnectionSettingsId::default();
    let peers = std::sync::Mutex::new(Vec::new());
    let opens = AtomicUsize::new(0);
    let open = |_| async {
        opens.fetch_add(1, Ordering::AcqRel);
        connection(&peers).await
    };
    let lease = pool.acquire(key(&settings), open).await?;
    // Forwarding keeps the connection but releases tunnel bookkeeping.
    let forwarded = lease.connection.clone();
    drop(lease);
    pool.clone().close_idle_connections();
    let reused = pool.acquire(key(&settings), open).await?;
    assert!(reused.reused);
    assert_eq!(opens.load(Ordering::Acquire), 1);
    drop(reused);
    drop(forwarded);
    pool.close_idle_connections();
    pool.close_idle_connections();
    assert_eq!(pool.lock().entries.len(), 1, "route state must survive");
    let replacement = pool.acquire(key(&settings), open).await?;
    assert!(!replacement.reused);
    assert_eq!(opens.load(Ordering::Acquire), 2);
    Ok(())
}

#[tokio::test]
async fn close_idle_does_not_cancel_physical_proxy_setup() -> TestResult {
    let pool = Http2ProxyPool::new();
    let settings = ConnectionSettingsId::default();
    let peers = std::sync::Mutex::new(Vec::new());
    let (release, released) = oneshot::channel();
    let mut acquiring = Box::pin(pool.acquire(key(&settings), |_| async {
        released
            .await
            .map_err(|_| HttpConnectError::RuntimeUnavailable)?;
        connection(&peers).await
    }));
    assert!(!poll_once(&mut acquiring).await);
    pool.clone().close_idle_connections();
    release.send(()).map_err(|_| "setup cancelled")?;
    let lease = acquiring.await?;
    assert!(!lease.reused);
    Ok(())
}
