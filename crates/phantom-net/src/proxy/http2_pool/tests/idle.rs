//! Deadline ownership, expiry isolation, and recoverable scheduling failures.

use std::sync::atomic::Ordering;

use phantom_profile::browser::firefox::v157_http2;
use tokio::time::timeout;

use super::{
    AtomicUsize, ConnectionSettingsId, Duration, Http2Connection, Http2IdleTimeout, Http2ProxyPool,
    HttpConnectError, HttpConnectErrorKind, TestResult, connection, key, oneshot, poll_once,
    same_connection, v154_http2,
};
use crate::proxy::http2_pool::idle::prune_delay;

const DEADLINE: Duration = Duration::from_secs(5);
const QUIET: Duration = Duration::from_millis(1400);

async fn timed_connection(
    peers: &std::sync::Mutex<Vec<tokio::io::DuplexStream>>,
    limit: Duration,
) -> Result<Http2Connection, HttpConnectError> {
    let (client, server) = tokio::io::duplex(64 * 1024);
    peers
        .lock()
        .map_err(|_| HttpConnectError::RuntimeUnavailable)?
        .push(server);
    let mut settings = v154_http2();
    settings.preface_ping_after = None;
    settings.ping_timeout = None;
    settings.ping_failure_retries = 0;
    settings.idle_timeout = Http2IdleTimeout::ClosedOnTimer(limit);
    Http2Connection::connect(client, &settings)
        .await
        .map_err(|error| HttpConnectError::Write(std::io::Error::other(error)))
}

#[test]
fn pruning_uses_whole_seconds_with_a_minimum_one_second() {
    assert_eq!(prune_delay(Duration::ZERO), Duration::from_secs(1));
    assert_eq!(
        prune_delay(Duration::from_millis(900)),
        Duration::from_secs(1)
    );
    assert_eq!(
        prune_delay(Duration::from_millis(1999)),
        Duration::from_secs(1)
    );
    assert_eq!(
        prune_delay(Duration::from_secs(170)),
        Duration::from_secs(170)
    );
    assert_eq!(
        v157_http2().idle_timeout,
        Http2IdleTimeout::ClosedOnTimer(Duration::from_secs(170))
    );
    assert_eq!(v154_http2().idle_timeout, Http2IdleTimeout::Unlimited);
}

#[tokio::test]
async fn an_unlimited_connection_has_no_idle_callback() -> TestResult {
    let pool = Http2ProxyPool::new();
    let settings = ConnectionSettingsId::default();
    let peers = std::sync::Mutex::new(Vec::new());
    let route = pool.route(key(&settings));
    // A scheduling failure must not affect an untimed profile.
    route.fail_next_deadline.store(true, Ordering::Release);
    let first = pool.acquire(key(&settings), |_| connection(&peers)).await?;
    assert!(route.lock().idle.is_none());
    assert!(route.fail_next_deadline.load(Ordering::Acquire));
    let second = pool.acquire(key(&settings), |_| connection(&peers)).await?;
    assert!(same_connection(&first, &second));
    Ok(())
}

#[tokio::test]
async fn a_required_timer_failure_fails_setup_and_all_existing_waiters() -> TestResult {
    let pool = Http2ProxyPool::new();
    let settings = ConnectionSettingsId::default();
    let peers = std::sync::Mutex::new(Vec::new());
    let route = pool.route(key(&settings));
    route.fail_next_deadline.store(true, Ordering::Release);
    let opens = AtomicUsize::new(0);
    let (release, gate) = oneshot::channel();
    let mut first = Box::pin(pool.acquire(key(&settings), |_| async {
        opens.fetch_add(1, Ordering::AcqRel);
        gate.await
            .map_err(|_| HttpConnectError::RuntimeUnavailable)?;
        timed_connection(&peers, Duration::from_secs(10)).await
    }));
    assert!(!poll_once(&mut first).await);
    let mut waiter = Box::pin(pool.acquire(key(&settings), |_| async {
        opens.fetch_add(1, Ordering::AcqRel);
        timed_connection(&peers, Duration::from_secs(10)).await
    }));
    assert!(!poll_once(&mut waiter).await);

    release.send(()).map_err(|_| "setup gate closed")?;
    let (failed, waited) = timeout(DEADLINE, async { tokio::join!(first, waiter) }).await?;
    assert!(matches!(failed, Err(HttpConnectError::RuntimeUnavailable)));
    assert!(matches!(
        waited,
        Err(HttpConnectError::PooledSetupFailed {
            kind: HttpConnectErrorKind::RuntimeUnavailable
        })
    ));
    assert_eq!(opens.load(Ordering::Acquire), 1);
    assert!(route.lock().slots.is_empty());

    let retry = pool
        .acquire(key(&settings), |_| {
            timed_connection(&peers, Duration::from_secs(10))
        })
        .await?;
    assert!(!retry.reused);
    assert!(route.lock().idle.is_some());
    Ok(())
}

#[tokio::test]
async fn a_failed_rearm_is_observed_before_an_explicit_retry() -> TestResult {
    let pool = Http2ProxyPool::new();
    let settings = ConnectionSettingsId::default();
    let peers = std::sync::Mutex::new(Vec::new());
    let route = pool.route(key(&settings));
    let first = pool
        .acquire(key(&settings), |_| {
            timed_connection(&peers, Duration::from_secs(10))
        })
        .await?;
    let identity = route
        .lock()
        .idle
        .as_ref()
        .ok_or("no initial timer")?
        .identity();
    route.fail_next_deadline.store(true, Ordering::Release);
    // Force an early callback: the connection is still reusable and needs
    // another deadline, whose failure must be retained for a later caller.
    route.prune_idle(&identity);
    assert!(route.lock().slots.is_empty());
    assert!(route.lock().idle_failed);
    assert!(!first.connection.is_closed(), "a caller lease must survive");

    let observed = pool
        .acquire(key(&settings), |_| {
            timed_connection(&peers, Duration::from_secs(10))
        })
        .await;
    assert!(matches!(
        observed,
        Err(HttpConnectError::RuntimeUnavailable)
    ));
    let retry = pool
        .acquire(key(&settings), |_| {
            timed_connection(&peers, Duration::from_secs(10))
        })
        .await?;
    assert!(!same_connection(&first, &retry));
    assert!(route.lock().idle.is_some());
    Ok(())
}

#[tokio::test]
async fn a_cancelled_callback_cannot_retire_a_replacement_connection() -> TestResult {
    let pool = Http2ProxyPool::new();
    let settings = ConnectionSettingsId::default();
    let peers = std::sync::Mutex::new(Vec::new());
    let route = pool.route(key(&settings));
    let old = pool
        .acquire(key(&settings), |_| {
            timed_connection(&peers, Duration::from_secs(10))
        })
        .await?;
    let identity = route.lock().idle.as_ref().ok_or("no old timer")?.identity();
    old.retire();
    route.lock().idle = None;
    let new = pool
        .acquire(key(&settings), |_| {
            timed_connection(&peers, Duration::from_secs(10))
        })
        .await?;
    route.prune_idle(&identity);
    let again = pool.acquire(key(&settings), |_| connection(&peers)).await?;
    assert!(same_connection(&new, &again));
    assert!(route.lock().idle.is_some());
    Ok(())
}

#[tokio::test]
async fn the_pending_timer_does_not_keep_a_route_alive() -> TestResult {
    let pool = Http2ProxyPool::new();
    let settings = ConnectionSettingsId::default();
    let peers = std::sync::Mutex::new(Vec::new());
    let route = pool.route(key(&settings));
    let weak = std::sync::Arc::downgrade(&route);
    let lease = pool
        .acquire(key(&settings), |_| {
            timed_connection(&peers, Duration::from_secs(10))
        })
        .await?;
    drop(route);
    drop(pool);
    assert!(weak.upgrade().is_some(), "the lease still owns its route");
    drop(lease);
    assert!(
        weak.upgrade().is_none(),
        "the timer must own only a weak route"
    );
    Ok(())
}

#[test]
fn a_timed_pool_does_not_require_the_callers_time_driver() -> TestResult {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;
    runtime.block_on(async {
        let pool = Http2ProxyPool::new();
        let settings = ConnectionSettingsId::default();
        let peers = std::sync::Mutex::new(Vec::new());
        let first = pool
            .acquire(key(&settings), |_| {
                timed_connection(&peers, Duration::from_secs(10))
            })
            .await?;
        assert!(!first.reused);
        assert!(pool.route(key(&settings)).lock().idle.is_some());
        Ok(())
    })
}

#[tokio::test]
async fn expired_slots_do_not_retire_another_routes_live_connection() -> TestResult {
    let pool = Http2ProxyPool::new();
    let old_settings = ConnectionSettingsId::default();
    let other_settings = ConnectionSettingsId::default();
    let peers = std::sync::Mutex::new(Vec::new());
    let old = pool
        .acquire(key(&old_settings), |_| {
            timed_connection(&peers, Duration::from_secs(1))
        })
        .await?;
    let other = pool
        .acquire(key(&other_settings), |_| {
            timed_connection(&peers, Duration::from_secs(10))
        })
        .await?;
    // Caller handles intentionally survive. Verify autonomous pool removal
    // rather than testing shutdown of their still-owned native connections.
    tokio::time::sleep(QUIET).await;
    assert!(pool.route(key(&old_settings)).lock().slots.is_empty());
    let again = pool
        .acquire(key(&other_settings), |_| connection(&peers))
        .await?;
    assert!(same_connection(&other, &again));
    assert!(!old.connection.is_closed());
    Ok(())
}

#[tokio::test]
async fn expiry_removes_only_the_due_slot_from_a_multiconnection_route() -> TestResult {
    let pool = Http2ProxyPool::with_max_connections_per_route(
        std::num::NonZeroUsize::new(2).ok_or("zero connection limit")?,
    );
    let settings = ConnectionSettingsId::default();
    let peers = std::sync::Mutex::new(Vec::new());
    let mut old = Vec::new();
    for _ in 0..super::super::MAX_TUNNELS_PER_HTTP2_PROXY_CONNECTION {
        old.push(
            pool.acquire(key(&settings), |_| {
                timed_connection(&peers, Duration::from_secs(1))
            })
            .await?,
        );
    }
    let other = pool
        .acquire(key(&settings), |_| {
            timed_connection(&peers, Duration::from_secs(10))
        })
        .await?;
    assert!(!same_connection(
        old.first().ok_or("missing first lease")?,
        &other
    ));
    tokio::time::sleep(QUIET).await;
    assert_eq!(pool.route(key(&settings)).lock().slots.len(), 1);
    let again = pool.acquire(key(&settings), |_| connection(&peers)).await?;
    assert!(same_connection(&other, &again));
    Ok(())
}

struct EchoPeer(tokio::task::JoinHandle<std::io::Result<usize>>);

impl Drop for EchoPeer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl EchoPeer {
    async fn finish(mut self, operation: TestResult) -> TestResult {
        let cancelled = operation.is_err() && !self.0.is_finished();
        if cancelled {
            self.0.abort();
        }
        let cleanup: TestResult = match timeout(DEADLINE, &mut self.0).await {
            Ok(Ok(result)) => result.map(|_| ()).map_err(Into::into),
            Ok(Err(error)) if cancelled && error.is_cancelled() => Ok(()),
            Ok(Err(error)) => Err(error.into()),
            Err(error) => {
                self.0.abort();
                // Retain the elapsed failure, but also join the cancelled peer.
                match timeout(DEADLINE, &mut self.0).await {
                    Ok(Err(join)) if join.is_cancelled() => Err(error.into()),
                    Ok(Err(join)) => Err(Box::new(PeerFailures {
                        primary: error.into(),
                        cleanup: join.into(),
                    })),
                    Ok(Ok(Err(inner))) => Err(Box::new(PeerFailures {
                        primary: error.into(),
                        cleanup: inner.into(),
                    })),
                    Ok(Ok(Ok(_))) => Err(error.into()),
                    Err(elapsed) => Err(Box::new(PeerFailures {
                        primary: error.into(),
                        cleanup: elapsed.into(),
                    })),
                }
            }
        };
        match (operation, cleanup) {
            (Ok(()), result) => result,
            (Err(primary), Ok(())) => Err(primary),
            (Err(primary), Err(cleanup)) => Err(Box::new(PeerFailures { primary, cleanup })),
        }
    }
}

#[derive(Debug)]
struct PeerFailures {
    primary: Box<dyn std::error::Error>,
    cleanup: Box<dyn std::error::Error>,
}

impl std::fmt::Display for PeerFailures {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; echo peer cleanup failed: {}",
            self.primary, self.cleanup
        )
    }
}

impl std::error::Error for PeerFailures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.primary.as_ref())
    }
}

async fn echo_tunnel(server: tokio::io::DuplexStream) -> std::io::Result<usize> {
    let mut connection = ::http2::server::handshake(server)
        .await
        .map_err(std::io::Error::other)?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or_else(|| std::io::Error::other("missing CONNECT"))?
        .map_err(std::io::Error::other)?;
    if request.method() != http::Method::CONNECT {
        return Err(std::io::Error::other(
            "echo peer received a non-CONNECT request",
        ));
    }
    let mut send = respond
        .send_response(http::Response::new(()), false)
        .map_err(std::io::Error::other)?;
    let mut receive = request.into_body();
    let mut messages = 0;
    loop {
        tokio::select! {
            frame = receive.data() => {
                match frame {
                    Some(data) => {
                        let data = data.map_err(std::io::Error::other)?;
                        receive.flow_control().release_capacity(data.len()).map_err(std::io::Error::other)?;
                        send.send_data(data, false).map_err(std::io::Error::other)?;
                        messages += 1;
                    }
                    None => {
                        send.send_data(bytes::Bytes::new(), true).map_err(std::io::Error::other)?;
                        break;
                    }
                }
            }
            accepted = connection.accept() => {
                if let Some(result) = accepted {
                    result.map_err(std::io::Error::other)?;
                }
                return Err(std::io::Error::other("outer connection ended while its CONNECT was live"));
            }
        }
    }
    if let Some(result) = connection.accept().await {
        result.map_err(std::io::Error::other)?;
        return Err(std::io::Error::other(
            "unexpected second CONNECT on old connection",
        ));
    }
    if messages < 2 {
        return Err(std::io::Error::other(
            "echo peer did not observe both directions after readiness",
        ));
    }
    Ok(messages)
}

#[derive(Clone, Copy)]
enum ReadActivity {
    Quiet,
    Frequent,
}

async fn tunnel_idle(activity: ReadActivity) -> TestResult {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let pool = Http2ProxyPool::new();
    let settings = ConnectionSettingsId::default();
    let (client, server) = tokio::io::duplex(64 * 1024);
    let peer = EchoPeer(tokio::spawn(echo_tunnel(server)));
    let operation = timeout(Duration::from_secs(10), async {
        let mut profile = v154_http2();
        profile.preface_ping_after = None;
        profile.ping_timeout = None;
        profile.ping_failure_retries = 0;
        profile.idle_timeout = Http2IdleTimeout::ClosedOnTimer(Duration::from_secs(1));
        let first = pool
            .acquire(key(&settings), |_| async {
                Http2Connection::connect(client, &profile)
                    .await
                    .map_err(|error| HttpConnectError::Write(std::io::Error::other(error)))
            })
            .await?;
        let identity = std::sync::Arc::clone(&first.tunnel.tunnels);
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("echo.test:443")
            .body(())?;
        let outcome = first
            .connection
            .send_classic_connect(request, phantom_profile::Http2RejectedConnect::EndStream)
            .await?;
        let crate::http2::Http2ClassicConnectOutcome::Accepted { mut stream, .. } = outcome else {
            return Err("echo CONNECT was rejected".into());
        };
        let (outer, guard) = first.into_tunnel();
        stream.retain_until_stream_complete(guard);
        drop(outer);
        stream.write_all(b"ready").await?;
        stream.flush().await?;
        let mut echoed = [0; 5];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(&echoed, b"ready");

        match activity {
            ReadActivity::Quiet => tokio::time::sleep(QUIET).await,
            ReadActivity::Frequent => {
                for _ in 0..5 {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    stream.write_all(b"reads").await?;
                    stream.flush().await?;
                    stream.read_exact(&mut echoed).await?;
                    assert_eq!(&echoed, b"reads");
                }
            }
        }
        assert!(
            !peer.0.is_finished(),
            "live tunnel was aborted at the idle deadline"
        );
        let peers = std::sync::Mutex::new(Vec::new());
        let next = pool.acquire(key(&settings), |_| connection(&peers)).await?;
        match activity {
            ReadActivity::Quiet => {
                assert!(!std::sync::Arc::ptr_eq(&identity, &next.tunnel.tunnels))
            }
            ReadActivity::Frequent => {
                assert!(std::sync::Arc::ptr_eq(&identity, &next.tunnel.tunnels))
            }
        }
        drop(next);
        // Both client-to-proxy and proxy-to-client DATA still work after
        // the old connection was excluded from new streams.
        stream.write_all(b"after").await?;
        stream.flush().await?;
        stream.read_exact(&mut echoed).await?;
        assert_eq!(&echoed, b"after");
        stream.shutdown().await?;
        let mut tail = Vec::new();
        stream.read_to_end(&mut tail).await?;
        assert!(tail.is_empty());
        drop(stream);
        drop(pool);
        Ok(())
    })
    .await;
    let operation = match operation {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };
    peer.finish(operation).await
}

#[tokio::test]
async fn a_quiet_connect_survives_expiry_and_transfers_data_both_ways() -> TestResult {
    tunnel_idle(ReadActivity::Quiet).await
}

#[tokio::test]
async fn tunnel_reads_keep_the_outer_connection_reusable_past_its_initial_deadline() -> TestResult {
    tunnel_idle(ReadActivity::Frequent).await
}
