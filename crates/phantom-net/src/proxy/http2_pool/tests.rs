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
};

use phantom_profile::chromium::v154_http2;
use tokio::{io::DuplexStream, sync::oneshot};

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
