//! The existing pool owner keeps SOCKS partitions, admission and idle age.
use super::*;
use crate::session::prune_timer::PrunedEntry;
use crate::{Socks4Proxy, Socks5Proxy, session::prune_timer::PruneTimer};
use phantom_net::tcp::{AddressFamily, SlowerConnection, SlowerProgress};
use tokio::{
    sync::oneshot,
    time::{Instant, timeout},
};
const WAIT: Duration = Duration::from_secs(5);
#[tokio::test]
async fn socks_spares_keep_origin_proxy_authentication_and_dns_partitions() -> TestResult {
    let pool = Http1Pool::new(bound(16)?, bound(2)?, bound(2)?);
    let origin = Endpoint::new("origin.test:443".parse()?, 443)?;
    let route = Route::socks5(
        Socks5Proxy::new("socks5h://127.0.0.1:1080")?.with_username_password("user", "secret")?,
    );
    let entry = pool
        .entry(PoolKey::new(
            &origin,
            &route,
            Http1ConnectionMode::TlsOrigin,
        ))
        .await;
    let progress = SlowerProgress::new();
    let (sender, receiver) = oneshot::channel();
    entry
        .connections
        .adopt(SlowerConnection::new(progress.clone(), async move {
            receiver.await.ok().flatten()
        }));
    progress.mark_connected();
    entry.connections.family.remember(AddressFamily::Ipv4);
    for route in [
        Route::socks5(
            Socks5Proxy::new("socks5h://127.0.0.1:1080")?
                .with_username_password("user", "other")?,
        ),
        Route::socks5(
            Socks5Proxy::new("socks5h://127.0.0.1:1081")?
                .with_username_password("user", "secret")?,
        ),
        Route::socks5(
            Socks5Proxy::new("socks5://127.0.0.1:1080")?
                .with_username_password("user", "secret")?,
        ),
        Route::socks4(Socks4Proxy::new("socks4a://127.0.0.1:1080")?.with_user_id("user")?),
        Route::Direct,
    ] {
        let other = pool
            .entry(PoolKey::new(
                &origin,
                &route,
                Http1ConnectionMode::TlsOrigin,
            ))
            .await;
        assert!(!Arc::ptr_eq(&entry, &other));
        assert!(!Arc::ptr_eq(&entry.admission, &other.admission));
        assert_eq!(other.connections.family.family(), None);
        assert!(matches!(
            other.connections.checkout(false),
            Checkout::Reserved(_)
        ));
    }
    let other_origin = Endpoint::new("other.test:443".parse()?, 443)?;
    let other = pool
        .entry(PoolKey::new(
            &other_origin,
            &route,
            Http1ConnectionMode::TlsOrigin,
        ))
        .await;
    assert!(!Arc::ptr_eq(&entry, &other));
    let other = pool
        .entry(PoolKey::new(
            &origin,
            &route,
            Http1ConnectionMode::PlaintextOrigin,
        ))
        .await;
    assert!(!Arc::ptr_eq(&entry, &other));
    assert_eq!(entry.connections.open(), 1);
    sender.send(None).map_err(|_| "spare ended")?;
    timeout(WAIT, async {
        while !entry.connections.lock().spares.is_empty() {
            tokio::task::yield_now().await
        }
    })
    .await?;
    assert_eq!(entry.connections.open(), 0);
    Ok(())
}
#[tokio::test]
async fn socks4_user_ids_do_not_share_an_origin_owner() -> TestResult {
    let pool = Http1Pool::new(bound(4)?, bound(2)?, bound(2)?);
    let origin = Endpoint::new("origin.test:443".parse()?, 443)?;
    let first = Route::socks4(Socks4Proxy::new("socks4a://127.0.0.1:1080")?.with_user_id("one")?);
    let second = Route::socks4(Socks4Proxy::new("socks4a://127.0.0.1:1080")?.with_user_id("two")?);
    let first = pool
        .entry(PoolKey::new(
            &origin,
            &first,
            Http1ConnectionMode::TlsOrigin,
        ))
        .await;
    let second = pool
        .entry(PoolKey::new(
            &origin,
            &second,
            Http1ConnectionMode::TlsOrigin,
        ))
        .await;
    assert!(!Arc::ptr_eq(&first.connections, &second.connections));
    assert!(!Arc::ptr_eq(&first.admission, &second.admission));
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn cancelling_an_unpolled_socks_claim_keeps_one_spare_until_its_idle_deadline() -> TestResult
{
    let limit = Duration::from_secs(30);
    let timer = PruneTimer::unscheduled(limit);
    let pool =
        Http1Pool::new(bound(4)?, bound(2)?, bound(2)?).with_prune_timer(Some(Arc::clone(&timer)));
    let origin = Endpoint::new("origin.test:443".parse()?, 443)?;
    let route = Route::socks5(Socks5Proxy::new("socks5h://127.0.0.1:1080")?);
    let entry = pool
        .entry(PoolKey::new(
            &origin,
            &route,
            Http1ConnectionMode::TlsOrigin,
        ))
        .await;
    let progress = SlowerProgress::new();
    let (sender, receiver) = oneshot::channel();
    entry
        .connections
        .adopt(SlowerConnection::new(progress.clone(), async move {
            receiver.await.ok().flatten()
        }));
    let Checkout::Spare(claim) = entry.connections.checkout(false) else {
        return Err("pending SOCKS spare was not claimed".into());
    };
    drop(claim);
    let (connection, _peer) = connection().await?;
    progress.mark_connected();
    sender
        .send(Some(connection))
        .map_err(|_| "spare owner ended")?;
    timeout(WAIT, async {
        while !entry.connections.lock().spares.is_empty() {
            tokio::task::yield_now().await
        }
    })
    .await?;
    assert_eq!(entry.connections.open(), 1);
    assert_eq!(entry.connections.lock().idle.len(), 1);
    let since = Instant::now();
    tokio::time::advance(limit).await;
    let pruned = entry.connections.prune(since + limit, Some(limit));
    assert!(pruned.empty);
    assert_eq!(entry.connections.open(), 0);
    Ok(())
}
