//! Physical proxy family ownership follows the actual bounded pool entry.

use super::{
    super::*,
    admission::{TestResult, key, setup},
};
use crate::tcp::AddressFamily;

#[tokio::test]
async fn failed_cancelled_and_cleared_setups_keep_the_same_entry_family() -> TestResult {
    let pool = ConnectUdpProxyPool::new();
    let key = key(0)?;
    let first = setup(pool.acquire(key.clone()).await?)?;
    let family = first.family()?;
    family.remember(AddressFamily::Ipv4);
    first.fail(ConnectUdpErrorKind::Handshake);
    let second = setup(pool.acquire(key.clone()).await?)?;
    assert_eq!(second.family()?.family(), Some(AddressFamily::Ipv4));
    second.family()?.remember(AddressFamily::Ipv6);
    drop(second);
    let third = setup(pool.acquire(key.clone()).await?)?;
    assert_eq!(third.family()?.family(), Some(AddressFamily::Ipv6));
    pool.clear();
    assert_eq!(third.family()?.family(), Some(AddressFamily::Ipv6));
    drop(third);
    let fourth = setup(pool.acquire(key).await?)?;
    assert_eq!(fourth.family()?.family(), Some(AddressFamily::Ipv6));
    Ok(())
}

#[tokio::test]
async fn family_scope_isolated_by_fields_credentials_settings_and_fresh_pool() -> TestResult {
    let pool = ConnectUdpProxyPool::new();
    let original = key(0)?;
    let first = setup(pool.acquire(original.clone()).await?)?;
    first.family()?.remember(AddressFamily::Ipv4);
    let mut fields = original.clone();
    fields
        .fields
        .push(RequestHeader::new("x-scope", "different"));
    let mut credentials = original.clone();
    credentials.credentials = Some(HttpBasicCredentials::new("fixture", "different")?);
    let mut settings = original.clone();
    settings.settings = Settings::Http2(ConnectionSettingsId::default());
    let mut endpoint = original.clone();
    endpoint.port += 1;
    for key in [fields, credentials, settings, endpoint] {
        let other = setup(pool.acquire(key).await?)?;
        assert_eq!(other.family()?.family(), None);
        other.family()?.remember(AddressFamily::Ipv6);
    }
    assert_eq!(first.family()?.family(), Some(AddressFamily::Ipv4));
    let fresh = pool.fresh();
    assert_eq!(
        setup(fresh.acquire(original).await?)?.family()?.family(),
        None
    );
    Ok(())
}

#[tokio::test]
async fn eviction_resets_family_without_mutating_an_old_clone_or_active_entry() -> TestResult {
    let pool = ConnectUdpProxyPool::new();
    let original = key(0)?;
    let active_key = key(1)?;
    let first = setup(pool.acquire(original.clone()).await?)?;
    let retired_family = first.family()?;
    retired_family.remember(AddressFamily::Ipv4);
    drop(first);
    let active = setup(pool.acquire(active_key.clone()).await?)?;
    active.family()?.remember(AddressFamily::Ipv6);
    // A live setup remains in the 32-key bound while the idle original is evicted.
    for index in 2..=MAX_CONNECT_UDP_POOL_KEYS {
        drop(setup(pool.acquire(key(index)?).await?)?);
    }
    assert_eq!(
        lock(&pool.inner.state().entries).len(),
        MAX_CONNECT_UDP_POOL_KEYS
    );
    assert_eq!(active.family()?.family(), Some(AddressFamily::Ipv6));
    let replacement = setup(pool.acquire(original).await?)?;
    assert_eq!(replacement.family()?.family(), None);
    assert_eq!(retired_family.family(), Some(AddressFamily::Ipv4));
    assert!(
        lock(&pool.inner.state().entries)
            .iter()
            .any(|entry| entry.key == active_key)
    );
    Ok(())
}

#[test]
fn another_runtime_cannot_inherit_a_proxy_family() -> TestResult {
    let pool = ConnectUdpProxyPool::new();
    let first = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let other = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let key = first.block_on(async { key(0) })?;
    first.block_on(async {
        let entry = pool.entry(key.clone())?;
        entry.family.remember(AddressFamily::Ipv4);
        Ok::<_, ConnectUdpError>(())
    })?;
    other.block_on(async {
        let mut other_key = key.clone();
        other_key.runtime = tokio::runtime::Handle::current().id();
        assert_eq!(pool.entry(other_key)?.family.family(), None);
        Ok::<_, ConnectUdpError>(())
    })?;
    first.block_on(async {
        assert_eq!(pool.entry(key)?.family.family(), Some(AddressFamily::Ipv4));
        Ok::<_, ConnectUdpError>(())
    })?;
    Ok(())
}

#[tokio::test]
async fn a_cleared_prepared_connector_stays_invalid_without_resetting_entry_family() -> TestResult {
    let connector = HttpsProxyConnector::new(&phantom_profile::browser::firefox::v157_tcp_tls())?
        .with_protocol(super::super::super::HttpsProxyProtocol::Http2);
    let pool = ConnectUdpProxyPool::new();
    let key = PoolKey::http2(&connector, "proxy.test", 443, "proxy.test", &[], None)?;
    let prepared = pool.prepare_http2(key.clone(), &connector)?;
    let first = setup(pool.acquire_prepared(key.clone(), &prepared).await?)?;
    first.family()?.remember(AddressFamily::Ipv4);
    pool.clear();
    assert_eq!(
        first.prepared_http2(&prepared).err().map(|e| e.kind()),
        Some(ConnectUdpErrorKind::Configuration)
    );
    assert_eq!(first.family()?.family(), Some(AddressFamily::Ipv4));
    drop(first);
    assert_eq!(
        pool.acquire_prepared(key.clone(), &prepared)
            .await
            .err()
            .map(|e| e.kind()),
        Some(ConnectUdpErrorKind::Configuration)
    );
    let replacement = pool.prepare_http2(key.clone(), &connector)?;
    let next = setup(pool.acquire_prepared(key, &replacement).await?)?;
    assert_eq!(next.family()?.family(), Some(AddressFamily::Ipv4));
    assert!(next.prepared_http2(&replacement).is_ok());
    Ok(())
}
