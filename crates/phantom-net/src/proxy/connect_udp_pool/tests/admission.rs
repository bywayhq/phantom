use std::{num::NonZeroUsize, sync::Arc};

use super::super::*;

pub(super) type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn one() -> NonZeroUsize {
    NonZeroUsize::MIN
}

pub(super) fn key(index: usize) -> Result<PoolKey, ConnectUdpError> {
    PoolKey::new(
        Settings::Http3 {
            outer: ProxySettingsId::default(),
            dial: ProxySettingsId::default(),
        },
        "localhost",
        443,
        &format!("scope-{index}"),
        &[],
        None,
    )
}

pub(super) fn setup(
    acquisition: Acquisition,
) -> Result<SetupLease, Box<dyn std::error::Error + Send + Sync>> {
    match acquisition {
        Acquisition::Setup(setup) => Ok(setup),
        _ => Err("unexpected reuse".into()),
    }
}

#[test]
fn excessive_limits_are_recoverable_configuration_errors() {
    let large = NonZeroUsize::MAX;
    assert_eq!(
        ConnectUdpProxyPool::with_limits(large, one())
            .err()
            .map(|e| e.kind()),
        Some(ConnectUdpErrorKind::Configuration)
    );
    assert_eq!(
        ConnectUdpProxyPool::with_limits(one(), large)
            .err()
            .map(|e| e.kind()),
        Some(ConnectUdpErrorKind::Configuration)
    );
}

#[tokio::test]
async fn active_and_pending_limits_release_after_cancel() -> TestResult {
    let pool = ConnectUdpProxyPool::with_limits(one(), one())?;
    let owner = setup(pool.acquire(key(0)?).await?)?;
    let pending_key = key(1)?;
    let waiting_pool = pool.clone();
    let waiting = tokio::spawn(async move { waiting_pool.acquire(pending_key).await });
    wait_until(|| pool.inner.state().pending.available_permits() == 0).await?;
    assert_eq!(
        pool.acquire(key(2)?).await.err().map(|e| e.kind()),
        Some(ConnectUdpErrorKind::Capacity)
    );
    waiting.abort();
    assert!(waiting.await.err().is_some_and(|e| e.is_cancelled()));
    assert_eq!(pool.inner.state().pending.available_permits(), 1);
    drop(owner);
    assert_eq!(pool.inner.state().active.available_permits(), 1);
    drop(setup(pool.acquire(key(3)?).await?)?);
    Ok(())
}

#[tokio::test]
async fn refresh_keeps_shared_admission_and_isolates_setup_publication() -> TestResult {
    let pool = ConnectUdpProxyPool::with_limits(one(), one())?;
    let key = key(0)?;
    let old = setup(pool.acquire(key.clone()).await?)?;
    let old_entry = Arc::clone(&old.lease.as_ref().ok_or("lease absent")?.entry);
    pool.refresh_connections();
    let fresh = pool.entry(key.clone())?;
    assert!(!Arc::ptr_eq(&old_entry, &fresh));
    let waiting_pool = pool.clone();
    let waiting = tokio::spawn(async move { waiting_pool.acquire(key).await });
    wait_until(|| pool.inner.state().pending.available_permits() == 0).await?;
    assert!(
        !waiting.is_finished(),
        "refresh reset the shared admission bound"
    );
    drop(old);
    let current = setup(waiting.await??)?;
    assert!(Arc::ptr_eq(
        &current.lease.as_ref().ok_or("lease absent")?.entry,
        &fresh
    ));
    assert!(lock(&fresh.state).connecting.is_some());
    drop(current);
    assert!(lock(&fresh.state).connecting.is_none());
    Ok(())
}

#[tokio::test]
async fn setup_failure_wakes_its_waiters_with_the_original_category() -> TestResult {
    let pool = ConnectUdpProxyPool::new();
    let key = key(0)?;
    let owner = setup(pool.acquire(key.clone()).await?)?;
    let waiting_pool = pool.clone();
    let waiting = tokio::spawn(async move { waiting_pool.acquire(key).await });
    wait_until(|| owner.finished.receiver_count() == 2).await?;
    owner.fail(ConnectUdpErrorKind::Handshake);
    assert_eq!(
        waiting.await?.err().map(|e| e.kind()),
        Some(ConnectUdpErrorKind::Handshake)
    );
    assert_eq!(pool.inner.state().active.available_permits(), 100);
    Ok(())
}

#[tokio::test]
async fn canceled_setup_does_not_leave_a_reservation_or_permit() -> TestResult {
    let pool = ConnectUdpProxyPool::new();
    let key = key(0)?;
    let owner = setup(pool.acquire(key.clone()).await?)?;
    let waiting_pool = pool.clone();
    let waiting_key = key.clone();
    let waiting = tokio::spawn(async move { waiting_pool.acquire(waiting_key).await });
    wait_until(|| owner.finished.receiver_count() == 2).await?;
    drop(owner);
    assert_eq!(
        waiting.await?.err().map(|e| e.kind()),
        Some(ConnectUdpErrorKind::Protocol)
    );
    drop(setup(pool.acquire(key).await?)?);
    assert_eq!(pool.inner.state().active.available_permits(), 100);
    Ok(())
}

#[tokio::test]
async fn full_key_table_never_evicts_a_live_scope() -> TestResult {
    let pool = ConnectUdpProxyPool::new();
    let mut owners = Vec::new();
    for index in 0..MAX_CONNECT_UDP_POOL_KEYS {
        owners.push(setup(pool.acquire(key(index)?).await?)?);
    }
    assert_eq!(
        pool.acquire(key(33)?).await.err().map(|e| e.kind()),
        Some(ConnectUdpErrorKind::Capacity)
    );
    assert_eq!(
        lock(&pool.inner.state().entries).len(),
        MAX_CONNECT_UDP_POOL_KEYS
    );
    owners.pop();
    owners.push(setup(pool.acquire(key(34)?).await?)?);
    assert_eq!(
        lock(&pool.inner.state().entries).len(),
        MAX_CONNECT_UDP_POOL_KEYS
    );
    drop(owners);
    assert_eq!(pool.inner.state().active.available_permits(), 100);
    Ok(())
}

#[tokio::test]
async fn clear_keeps_live_admission_and_fresh_pool_has_independent_state() -> TestResult {
    let pool = ConnectUdpProxyPool::with_limits(one(), one())?;
    let owner = setup(pool.acquire(key(0)?).await?)?;
    pool.clear();
    assert_eq!(pool.inner.state().active.available_permits(), 0);
    assert!(
        lock(&owner.lease.as_ref().ok_or("lease absent")?.entry.state)
            .connecting
            .is_some()
    );
    let fresh = pool.fresh();
    assert!(!Arc::ptr_eq(&pool.inner, &fresh.inner));
    assert_eq!(fresh.inner.state().active.available_permits(), 1);
    drop(owner);
    assert_eq!(pool.inner.state().active.available_permits(), 1);
    Ok(())
}

#[tokio::test]
async fn credential_and_field_order_bind_keys_without_secret_debug() -> TestResult {
    let base = key(0)?;
    let mut credential = base.clone();
    credential.credentials = Some(HttpBasicCredentials::new(
        "private-user",
        "private-password",
    )?);
    assert!(base != credential);
    let mut fields = base.clone();
    fields.fields = vec![
        RequestHeader::new("x-a", "private-first"),
        RequestHeader::new("x-b", "private-second"),
    ];
    let mut reversed = fields.clone();
    reversed.fields.reverse();
    assert!(fields != reversed);
    let pool = ConnectUdpProxyPool::new();
    let owner = setup(pool.acquire(credential).await?)?;
    let debug = format!("{pool:?}");
    for secret in ["private-user", "private-password", "private-first"] {
        assert!(!debug.contains(secret));
    }
    drop(owner);
    Ok(())
}

pub(super) async fn wait_until(check: impl Fn() -> bool) -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !check() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}
