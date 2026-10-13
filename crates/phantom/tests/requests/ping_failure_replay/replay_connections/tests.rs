use std::{
    cell::Cell,
    error::Error,
    future::poll_fn,
    io,
    net::{Ipv4Addr, SocketAddr},
    task::Poll,
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::{AbortHandle, JoinError},
    time::timeout,
};

use crate::support::{tls, tunnel_proxy::connection_peer::FixtureFailures};

use super::super::{
    MAX_REPLAY_TASKS, Server, TEST_TIMEOUT, after_an_idle_connection, bounded,
    short_ping_timeout_client, tunnel_every_connect,
};
use super::{ReplayConnectionFailure, ReplayConnections, TestResult, lock};

const DEADLINE: Duration = Duration::from_secs(5);
const CONNECT: &[u8] = b"CONNECT origin:443 HTTP/1.1\r\nHost: origin:443\r\n\r\n";

#[tokio::test]
async fn dropping_the_caller_owner_closes_the_actual_accepted_connect_child() -> TestResult {
    let connections = ReplayConnections::new(MAX_REPLAY_TASKS);
    let (mut downstream, mut upstream, address, _done) = tunnel_pair(&connections).await?;
    drop(connections);

    assert_closed(&mut downstream).await?;
    assert_closed(&mut upstream).await?;
    let rebound = TcpListener::bind(address).await?;
    assert_eq!(rebound.local_addr()?, address);
    Ok(())
}

#[tokio::test]
async fn caller_failure_joins_the_actual_connect_child_and_releases_its_sockets() -> TestResult {
    let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
    let result = bounded(async {
        let (mut downstream, mut upstream, address, _done) = tunnel_pair(&connections).await?;
        let primary = io::Error::new(
            io::ErrorKind::InvalidInput,
            "original replay caller failure",
        );
        let error = connections
            .finish(Err(primary.into()))
            .await
            .err()
            .ok_or("caller failure disappeared")?;
        assert!(contains(&*error, &|cause| cause
            .downcast_ref::<io::Error>()
            .is_some_and(
                |error| error.kind() == io::ErrorKind::InvalidInput
            )));
        assert_closed(&mut downstream).await?;
        assert_closed(&mut upstream).await?;
        let rebound = TcpListener::bind(address).await?;
        assert_eq!(rebound.local_addr()?, address);
        assert!(lock(&connections.state).peers.is_empty());
        Ok(())
    })
    .await;
    connections.finish(result).await
}

#[tokio::test]
async fn caller_deadline_stops_the_actual_accepted_connect_child() -> TestResult {
    let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
    let mut tunnel = None;
    let setup = bounded(async {
        tunnel = Some(tunnel_pair(&connections).await?);
        Ok(())
    })
    .await;
    if setup.is_err() {
        return connections.finish(setup).await;
    }
    let result = async {
        let (mut downstream, mut upstream, address, _done) =
            tunnel.ok_or("tunnel setup returned without accepted sockets")?;
        tokio::time::pause();
        let entered = Cell::new(false);
        let pending = bounded(poll_fn(|_| {
            entered.set(true);
            Poll::<TestResult>::Pending
        }));
        tokio::pin!(pending);
        assert!(futures_util::poll!(&mut pending).is_pending());
        tokio::time::advance(TEST_TIMEOUT).await;
        let error = pending
            .await
            .err()
            .ok_or("pending tunnel caller did not time out")?;
        assert!(entered.get());
        let error = connections
            .finish(Err(error))
            .await
            .err()
            .ok_or("tunnel caller deadline disappeared")?;
        assert_eq!(error.to_string(), "test exceeded its timeout");
        assert!(contains(&*error, &|cause| cause.is::<tokio::time::error::Elapsed>()));
        assert_closed(&mut downstream).await?;
        assert_closed(&mut upstream).await?;
        let rebound = TcpListener::bind(address).await?;
        assert_eq!(rebound.local_addr()?, address);
        Ok(())
    }
    .await;
    connections.finish(result).await
}

#[tokio::test]
async fn completed_connect_failure_survives_its_coordinator_cancellation() -> TestResult {
    let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
    let result = bounded(async {
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin.local_addr()?;
        drop(origin);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (_done, done_received) = oneshot::channel();
        connections.spawner().spawn(tunnel_every_connect(
            listener,
            origin_address,
            connections.spawner(),
            done_received,
        ))?;
        let mut downstream = TcpStream::connect(address).await?;
        downstream.write_all(CONNECT).await?;
        assert_closed(&mut downstream).await?;
        let child = child_handle(&connections)?;
        wait_finished(&child).await?;
        let error = connections
            .finish(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "original failed replay caller",
            )
            .into()))
            .await
            .err()
            .ok_or("CONNECT failure disappeared")?;
        assert!(contains(&*error, &|cause| cause
            .downcast_ref::<ReplayConnectionFailure>()
            .is_some_and(|failure| failure.task == child.id()
                && contains(&*failure.cause, &|cause| cause
                    .downcast_ref::<io::Error>()
                    .is_some_and(
                        |error| error.kind() == io::ErrorKind::ConnectionRefused
                    )))));
        Ok(())
    })
    .await;
    connections.finish(result).await
}

#[tokio::test]
async fn a_completed_external_connect_cancellation_keeps_its_original_task_id() -> TestResult {
    let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
    let result = bounded(async {
        let (mut downstream, mut upstream, _, _done) = tunnel_pair(&connections).await?;
        let child = child_handle(&connections)?;
        child.abort();
        wait_finished(&child).await?;
        let error = connections
            .finish(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "caller observed an external cancellation",
            )
            .into()))
            .await
            .err()
            .ok_or("external child cancellation disappeared")?;
        assert!(contains(&*error, &|cause| cause
            .downcast_ref::<JoinError>()
            .is_some_and(
                |error| error.id() == child.id() && error.is_cancelled()
            )));
        assert_closed(&mut downstream).await?;
        assert_closed(&mut upstream).await?;
        Ok(())
    })
    .await;
    connections.finish(result).await
}

#[tokio::test]
async fn a_pending_external_connect_cancellation_keeps_its_original_task_id() -> TestResult {
    let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
    let result = bounded(async {
        let (mut downstream, mut upstream, _, _done) = tunnel_pair(&connections).await?;
        let child = child_handle(&connections)?;
        child.abort();
        assert!(!child.is_finished());

        let error = connections
            .finish(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "caller observed a pending external cancellation",
            )
            .into()))
            .await
            .err()
            .ok_or("external child cancellation disappeared")?;
        assert!(contains(&*error, &|cause| cause
            .downcast_ref::<JoinError>()
            .is_some_and(
                |error| error.id() == child.id() && error.is_cancelled()
            )));
        assert_closed(&mut downstream).await?;
        assert_closed(&mut upstream).await?;
        Ok(())
    })
    .await;
    connections.finish(result).await
}

#[tokio::test]
async fn an_interrupted_finish_retains_collected_failures_and_actual_connect_owners() -> TestResult
{
    let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
    let mut accepted = None;
    let mut failed_child = None;
    let setup = bounded(async {
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin.local_addr()?;
        drop(origin);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (done, done_received) = oneshot::channel();
        let coordinator = connections.spawner().spawn(tunnel_every_connect(
            listener,
            origin_address,
            connections.spawner(),
            done_received,
        ))?;
        let mut downstream = TcpStream::connect(address).await?;
        downstream.write_all(CONNECT).await?;
        assert_closed(&mut downstream).await?;
        let child = child_handle(&connections)?;
        wait_finished(&child).await?;
        done.send(())
            .map_err(|_| "CONNECT coordinator stopped before its signal")?;
        wait_finished(&coordinator).await?;

        failed_child = Some(child.id());
        accepted = Some(tunnel_pair(&connections).await?);
        Ok(())
    })
    .await;
    if setup.is_err() {
        return connections.finish(setup).await;
    }

    let result = async {
        let failed_child = failed_child.ok_or("missing original failed CONNECT task")?;
        let (mut downstream, mut upstream, address, _done) =
            accepted.ok_or("missing actual accepted CONNECT pair")?;
        tokio::time::pause();
        let retained = std::sync::Arc::clone(&connections.state);
        let caller = {
            let (begin, begun) = oneshot::channel();
            let pending = bounded(async {
                begun.await?;
                connections.finish(Ok(())).await
            });
            tokio::pin!(pending);
            assert!(futures_util::poll!(&mut pending).is_pending());
            tokio::time::advance(TEST_TIMEOUT - Duration::from_secs(1)).await;
            begin
                .send(())
                .map_err(|_| "replay caller stopped before cleanup")?;
            // Observe actual collection while allowing the paused timer to progress.
            tokio::select! {
                result = &mut pending => {
                    result?;
                    return Err("cleanup finished before pending CONNECT collection".into());
                }
                observed = async {
                    loop {
                        if lock(&retained).peers.len() == 2 {
                            return Ok::<(), Box<dyn Error + Send + Sync>>(());
                        }
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                } => observed?,
            }
            tokio::time::advance(Duration::from_secs(1)).await;
            pending.await
        };
        let error = caller
            .err()
            .ok_or("ordinary caller did not interrupt cleanup")?;
        assert!(contains(&*error, &|cause| cause.is::<tokio::time::error::Elapsed>()));
        assert_eq!(lock(&connections.state).peers.len(), 2);
        let error = connections
            .finish(Err(error))
            .await
            .err()
            .ok_or("interrupted cleanup outcomes disappeared")?;
        assert!(contains(&*error, &|cause| cause.is::<tokio::time::error::Elapsed>()));
        assert!(contains(&*error, &|cause| cause
            .downcast_ref::<ReplayConnectionFailure>()
            .is_some_and(|failure| failure.task == failed_child
                && contains(&*failure.cause, &|cause| cause
                    .downcast_ref::<io::Error>()
                    .is_some_and(
                        |error| error.kind() == io::ErrorKind::ConnectionRefused
                    )))));
        assert_closed(&mut downstream).await?;
        assert_closed(&mut upstream).await?;
        let rebound = TcpListener::bind(address).await?;
        assert_eq!(rebound.local_addr()?, address);
        Ok(())
    }
    .await;
    connections.finish(result).await
}

#[tokio::test]
async fn stopped_admission_destroys_the_actual_unstarted_connect_listener() -> TestResult {
    let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
    let spawner = connections.spawner();
    connections.finish(Ok(())).await?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let (_done, done_received) = oneshot::channel();
    let error = spawner
        .spawn(tunnel_every_connect(
            listener,
            address,
            spawner.clone(),
            done_received,
        ))
        .err()
        .ok_or("stopped replay owner admitted a task")?;
    assert_eq!(error.to_string(), "replay connection owner has stopped");
    let rebound = TcpListener::bind(address).await?;
    assert_eq!(rebound.local_addr()?, address);
    Ok(())
}

#[tokio::test]
async fn exhausted_admission_retains_the_actual_connect_coordinator_failure() -> TestResult {
    let mut connections = ReplayConnections::new(1);
    let result = bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (_done, done_received) = oneshot::channel();
        let coordinator = connections.spawner().spawn(tunnel_every_connect(
            listener,
            address,
            connections.spawner(),
            done_received,
        ))?;
        let mut downstream = TcpStream::connect(address).await?;
        assert_closed(&mut downstream).await?;
        wait_finished(&coordinator).await?;
        let error = connections
            .finish(Ok(()))
            .await
            .err()
            .ok_or("exhausted owner admitted a CONNECT child")?;
        assert!(contains(&*error, &|cause| {
            cause
                .downcast_ref::<ReplayConnectionFailure>()
                .is_some_and(|failure| {
                    failure.task == coordinator.id()
                        && failure.cause.to_string()
                            == "replay connection task count exceeds its script limit"
                })
        }));
        let rebound = TcpListener::bind(address).await?;
        assert_eq!(rebound.local_addr()?, address);
        Ok(())
    })
    .await;
    connections.finish(result).await
}

#[tokio::test]
async fn actual_replayed_body_limit_remains_a_typed_child_failure() -> TestResult {
    let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
    let result = bounded(async {
        let identity = tls::TestIdentity::generate()?;
        let server = Server::start(&identity, true, connections.spawner()).await?;
        let client = short_ping_timeout_client(&identity)?;
        let request = client
            .request(
                phantom::HttpProtocol::Http2,
                http::Method::POST,
                &server.url("/oversized"),
            )?
            .body("payload!")
            .send();
        let primary = match after_an_idle_connection(&client, &server, request).await? {
            Ok(_) => return Err("oversized replay body received a response".into()),
            Err(error) => Err(Box::new(error) as Box<dyn Error + Send + Sync>),
        };
        drop(client);
        let error = connections
            .finish(primary)
            .await
            .err()
            .ok_or("oversized replay body failure disappeared")?;
        assert!(contains(&*error, &|cause| {
            cause.downcast_ref::<io::Error>().is_some_and(|error| {
                error.kind() == io::ErrorKind::InvalidData
                    && error.to_string() == "replayed PING request body exceeded its script limit"
            })
        }));
        Ok(())
    })
    .await;
    connections.finish(result).await
}

async fn tunnel_pair(
    connections: &ReplayConnections,
) -> TestResult<(TcpStream, TcpStream, SocketAddr, oneshot::Sender<()>)> {
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let (done, done_received) = oneshot::channel();
    connections.spawner().spawn(tunnel_every_connect(
        listener,
        origin.local_addr()?,
        connections.spawner(),
        done_received,
    ))?;
    let mut downstream = TcpStream::connect(address).await?;
    downstream.write_all(CONNECT).await?;
    let (upstream, _) = timeout(DEADLINE, origin.accept()).await??;
    assert_eq!(
        timeout(DEADLINE, tls::read_head(&mut downstream)).await??,
        b"HTTP/1.1 200 Connection Established\r\n\r\n"
    );
    Ok((downstream, upstream, address, done))
}

fn child_handle(connections: &ReplayConnections) -> TestResult<AbortHandle> {
    lock(&connections.state)
        .peers
        .get(1)
        .map(|registered| registered.peer.abort_handle())
        .ok_or_else(|| "actual CONNECT child was not registered".into())
}

async fn wait_finished(handle: &AbortHandle) -> TestResult {
    timeout(DEADLINE, async {
        while !handle.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}

async fn assert_closed(stream: &mut TcpStream) -> TestResult {
    let closed = timeout(DEADLINE, stream.read(&mut [0_u8; 1])).await?;
    assert!(
        matches!(closed, Ok(0)) || matches!(closed, Err(ref error) if tls::is_peer_gone(error))
    );
    Ok(())
}

fn contains(
    error: &(dyn Error + 'static),
    predicate: &impl Fn(&(dyn Error + 'static)) -> bool,
) -> bool {
    if predicate(error) {
        return true;
    }
    if let Some(failures) = error.downcast_ref::<FixtureFailures>() {
        return contains(&*failures.primary, predicate) || contains(&*failures.cleanup, predicate);
    }
    error
        .source()
        .is_some_and(|cause| contains(cause, predicate))
}
