//! Setup coordination of one route, with connections over in-memory pipes.

use std::{
    future::{Future, pending},
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Poll,
    time::Duration,
};

use phantom_profile::{Http2IdleTimeout, browser::chrome::v154_http2};
use tokio::{io::DuplexStream, sync::oneshot, time::Instant};

use super::{ConnectionSettingsId, Http2ProxyPool, PooledConnection, RouteKey};
use crate::{
    http2::Http2Connection,
    proxy::{HttpConnectError, HttpConnectErrorKind},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn key(settings: &ConnectionSettingsId) -> RouteKey {
    RouteKey::new(settings, "proxy.test", 443, "proxy.test", None)
}

/// Opens an HTTP/2 connection whose peer end the caller keeps.
async fn connection(
    peers: &std::sync::Mutex<Vec<DuplexStream>>,
) -> Result<Http2Connection, HttpConnectError> {
    let (client, server) = tokio::io::duplex(64 * 1024);
    if let Ok(mut peers) = peers.lock() {
        peers.push(server);
    }
    Http2Connection::connect(client, &v154_http2())
        .await
        .map_err(|error| HttpConnectError::Write(io::Error::other(error)))
}

/// Polls `future` once and reports whether it finished.
async fn poll_once<F: Future>(future: &mut Pin<Box<F>>) -> bool {
    std::future::poll_fn(|context| Poll::Ready(future.as_mut().poll(context).is_ready())).await
}

fn same_connection(first: &PooledConnection, second: &PooledConnection) -> bool {
    Arc::ptr_eq(&first.tunnel.tunnels, &second.tunnel.tunnels)
}

#[tokio::test]
async fn concurrent_tunnels_share_one_setup() -> TestResult {
    let pool = Http2ProxyPool::new();
    let settings = ConnectionSettingsId::default();
    let peers = std::sync::Mutex::new(Vec::new());
    let opens = AtomicUsize::new(0);
    let (release, gate) = oneshot::channel::<()>();
    let gate = std::sync::Mutex::new(Some(gate));
    let open = || async {
        opens.fetch_add(1, Ordering::AcqRel);
        let gate = gate.lock().ok().and_then(|mut gate| gate.take());
        if let Some(gate) = gate {
            let _ = gate.await;
        }
        connection(&peers).await
    };
    let mut first = Box::pin(pool.acquire(key(&settings), open));
    let mut second = Box::pin(pool.acquire(key(&settings), open));
    let mut third = Box::pin(pool.acquire(key(&settings), open));
    assert!(!poll_once(&mut first).await);
    assert!(!poll_once(&mut second).await);
    assert!(!poll_once(&mut third).await);
    let _ = release.send(());
    let (first, second, third) = tokio::join!(first, second, third);
    let (first, second, third) = (first?, second?, third?);
    assert_eq!(opens.load(Ordering::Acquire), 1);
    assert!(same_connection(&first, &second) && same_connection(&first, &third));
    assert!(!first.reused && second.reused && third.reused);
    Ok(())
}

#[tokio::test]
async fn a_cancelled_setup_wakes_its_waiters_and_one_retries() -> TestResult {
    let pool = Http2ProxyPool::new();
    let settings = ConnectionSettingsId::default();
    let peers = std::sync::Mutex::new(Vec::new());
    let opens = AtomicUsize::new(0);
    let stalled = Box::pin(pool.acquire(key(&settings), || async {
        opens.fetch_add(1, Ordering::AcqRel);
        pending::<Result<Http2Connection, HttpConnectError>>().await
    }));
    let mut stalled = stalled;
    assert!(!poll_once(&mut stalled).await);
    let open = || async {
        opens.fetch_add(1, Ordering::AcqRel);
        connection(&peers).await
    };
    let mut second = Box::pin(pool.acquire(key(&settings), open));
    let mut third = Box::pin(pool.acquire(key(&settings), open));
    assert!(!poll_once(&mut second).await);
    assert!(!poll_once(&mut third).await);
    assert_eq!(opens.load(Ordering::Acquire), 1);

    drop(stalled);
    let (second, third) = tokio::join!(second, third);
    let (second, third) = (second?, third?);
    assert_eq!(opens.load(Ordering::Acquire), 2);
    assert!(same_connection(&second, &third));
    Ok(())
}

#[tokio::test]
async fn a_failed_setup_fails_its_waiters_with_its_kind() -> TestResult {
    let pool = Http2ProxyPool::new();
    let settings = ConnectionSettingsId::default();
    let peers = std::sync::Mutex::new(Vec::new());
    let opens = AtomicUsize::new(0);
    let (release, gate) = oneshot::channel::<()>();
    let mut failing = Box::pin(pool.acquire(key(&settings), || async {
        opens.fetch_add(1, Ordering::AcqRel);
        let _ = gate.await;
        Err::<Http2Connection, _>(HttpConnectError::Connect(io::Error::from(
            io::ErrorKind::ConnectionRefused,
        )))
    }));
    assert!(!poll_once(&mut failing).await);
    let open = || async {
        opens.fetch_add(1, Ordering::AcqRel);
        connection(&peers).await
    };
    let mut waiter = Box::pin(pool.acquire(key(&settings), open));
    assert!(!poll_once(&mut waiter).await);

    let _ = release.send(());
    let (failed, waited) = tokio::join!(failing, waiter);
    assert!(matches!(failed, Err(HttpConnectError::Connect(_))));
    assert!(matches!(
        waited,
        Err(HttpConnectError::PooledSetupFailed {
            kind: HttpConnectErrorKind::Connect
        })
    ));
    assert_eq!(opens.load(Ordering::Acquire), 1);

    // A tunnel that did not wait for the failed setup makes a new one.
    pool.acquire(key(&settings), open).await?;
    assert_eq!(opens.load(Ordering::Acquire), 2);
    Ok(())
}

#[tokio::test]
async fn a_later_setup_failure_does_not_replace_a_waiters_failure() -> TestResult {
    let pool = Http2ProxyPool::new();
    let settings = ConnectionSettingsId::default();
    let opens = AtomicUsize::new(0);
    let (release, gate) = oneshot::channel::<()>();
    let mut first = Box::pin(pool.acquire(key(&settings), || async {
        opens.fetch_add(1, Ordering::AcqRel);
        gate.await
            .map_err(|_| HttpConnectError::RuntimeUnavailable)?;
        Err::<Http2Connection, _>(HttpConnectError::Connect(io::Error::from(
            io::ErrorKind::ConnectionRefused,
        )))
    }));
    assert!(!poll_once(&mut first).await);

    let mut waiter = Box::pin(pool.acquire(key(&settings), || async {
        opens.fetch_add(1, Ordering::AcqRel);
        Err::<Http2Connection, _>(HttpConnectError::RuntimeUnavailable)
    }));
    assert!(!poll_once(&mut waiter).await);

    release
        .send(())
        .map_err(|_| "the first setup gate closed")?;
    assert!(matches!(first.await, Err(HttpConnectError::Connect(_))));

    let second = pool
        .acquire(key(&settings), || async {
            opens.fetch_add(1, Ordering::AcqRel);
            Err::<Http2Connection, _>(HttpConnectError::InvalidResponse)
        })
        .await;
    assert!(matches!(second, Err(HttpConnectError::InvalidResponse)));

    let waited = tokio::time::timeout(Duration::from_secs(5), waiter).await?;
    assert!(matches!(
        waited,
        Err(HttpConnectError::PooledSetupFailed {
            kind: HttpConnectErrorKind::Connect
        })
    ));
    assert_eq!(opens.load(Ordering::Acquire), 2, "the waiter must not open");
    Ok(())
}

#[tokio::test]
async fn a_cancelled_setup_waiter_does_not_inherit_a_later_failure() -> TestResult {
    let pool = Http2ProxyPool::new();
    let settings = ConnectionSettingsId::default();
    let peers = std::sync::Mutex::new(Vec::new());
    let opens = AtomicUsize::new(0);
    let mut first = Box::pin(pool.acquire(key(&settings), || async {
        opens.fetch_add(1, Ordering::AcqRel);
        pending::<Result<Http2Connection, HttpConnectError>>().await
    }));
    assert!(!poll_once(&mut first).await);

    let mut waiter = Box::pin(pool.acquire(key(&settings), || async {
        opens.fetch_add(1, Ordering::AcqRel);
        connection(&peers).await
    }));
    assert!(!poll_once(&mut waiter).await);
    drop(first);

    let second = pool
        .acquire(key(&settings), || async {
            opens.fetch_add(1, Ordering::AcqRel);
            Err::<Http2Connection, _>(HttpConnectError::InvalidResponse)
        })
        .await;
    assert!(matches!(second, Err(HttpConnectError::InvalidResponse)));

    let connection = tokio::time::timeout(Duration::from_secs(5), waiter).await??;
    assert!(!connection.reused, "cancellation permits a fresh setup");
    assert_eq!(opens.load(Ordering::Acquire), 3);
    Ok(())
}

/// A connection's driver runs on the runtime that opened it, so a tunnel on
/// another runtime opens its own connection instead of one that runtime no
/// longer drives.
#[test]
fn a_tunnel_on_another_runtime_opens_its_own_connection() -> TestResult {
    let pool = Http2ProxyPool::new();
    let settings = ConnectionSettingsId::default();
    let peers = std::sync::Mutex::new(Vec::new());
    let opens = AtomicUsize::new(0);
    let open = || async {
        opens.fetch_add(1, Ordering::AcqRel);
        connection(&peers).await
    };
    let first_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let second_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let first = first_runtime.block_on(async { pool.acquire(key(&settings), open).await })?;
    let again = first_runtime.block_on(async { pool.acquire(key(&settings), open).await })?;
    let other = second_runtime.block_on(async { pool.acquire(key(&settings), open).await })?;

    assert!(same_connection(&first, &again));
    assert!(!same_connection(&first, &other));
    assert_eq!(opens.load(Ordering::Acquire), 2);
    Ok(())
}

/// A connection past its idle limit takes no new tunnel: the next tunnel
/// opens a new connection.
#[tokio::test]
async fn a_connection_past_its_idle_limit_takes_no_new_tunnel() -> TestResult {
    const IDLE: Duration = Duration::from_secs(1);
    let pool = Http2ProxyPool::new();
    let settings = ConnectionSettingsId::default();
    let peers = std::sync::Mutex::new(Vec::new());
    let opens = AtomicUsize::new(0);
    let open = || async {
        opens.fetch_add(1, Ordering::AcqRel);
        let (client, server) = tokio::io::duplex(64 * 1024);
        if let Ok(mut peers) = peers.lock() {
            peers.push(server);
        }
        let mut http2 = v154_http2();
        // No PING timer may close the connection while the test waits.
        http2.preface_ping_after = None;
        http2.ping_timeout = None;
        http2.ping_failure_retries = 0;
        http2.idle_timeout = Http2IdleTimeout::ClosedOnTimer(IDLE);
        Http2Connection::connect(client, &http2)
            .await
            .map_err(|error| HttpConnectError::Write(io::Error::other(error)))
    };

    let start = Instant::now();
    let first = pool.acquire(key(&settings), open).await?;
    let opened = Instant::now();
    let within = pool.acquire(key(&settings), open).await?;
    // A slow machine may take the whole limit before the second tunnel.
    if start.elapsed() < IDLE {
        assert!(same_connection(&first, &within));
    }

    tokio::time::sleep_until(opened + IDLE + Duration::from_millis(100)).await;
    let past = pool.acquire(key(&settings), open).await?;
    assert!(!same_connection(&first, &past));
    assert!(!past.reused);
    Ok(())
}
