use super::super::*;
use super::admission::{TestResult, key, setup};

#[tokio::test]
async fn close_idle_preserves_raw_tunnel_owners_and_pending_setup() -> TestResult {
    let pool = ConnectUdpProxyPool::new();
    let key = key(0)?;
    let pending = setup(pool.acquire(key.clone()).await?)?;
    pool.close_idle_connections();
    assert!(
        lock(&lock(&pool.inner.state().entries)[0].state)
            .connecting
            .is_some()
    );

    let (client, _server) = tokio::io::duplex(64 * 1024);
    let connection =
        Http2Connection::connect(client, &phantom_profile::browser::chrome::v154_http2()).await?;
    let external = connection.clone();
    let lease = pending.publish(OuterSession::Http2(connection), false)?;
    drop(external);
    // This lease represents a raw tunnel even if it holds no backend handle.
    pool.clone().close_idle_connections();
    assert!(
        lock(&lock(&pool.inner.state().entries)[0].state)
            .session
            .is_some()
    );
    let retained = {
        let entries = lock(&pool.inner.state().entries);
        let state = lock(&entries[0].state);
        state.session.clone().ok_or("session absent")?
    };
    drop(lease);
    pool.close_idle_connections();
    assert!(
        lock(&lock(&pool.inner.state().entries)[0].state)
            .session
            .is_some()
    );
    drop(retained);
    pool.close_idle_connections();
    pool.close_idle_connections();
    let entries = lock(&pool.inner.state().entries);
    assert_eq!(entries.len(), 1);
    assert!(lock(&entries[0].state).session.is_none());
    assert_eq!(
        pool.inner.state().active.available_permits(),
        pool.max_active().get()
    );
    Ok(())
}
