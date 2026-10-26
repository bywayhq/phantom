//! Controls for the actual negotiated origin and its caller-owned workers.
use std::{error::Error, io, pin::Pin};

use btls::{
    ssl::{SslConnector, SslMethod},
    x509::X509,
};
use tokio_btls::SslStream;

use crate::support::tunnel_proxy::connection_peer::FixtureFailures;

use super::*;

async fn raw_tls(
    identity: &TestIdentity,
    address: SocketAddr,
    alpn: &[u8],
) -> TestResult<SslStream<TcpStream>> {
    let mut connector = SslConnector::builder(SslMethod::tls())?;
    connector
        .cert_store_mut()
        .add_cert(X509::from_der(&identity.root_der)?)?;
    connector.set_alpn_protos(alpn)?;
    let ssl = connector.build().configure()?.into_ssl("127.0.0.1")?;
    let tcp = TcpStream::connect(address).await?;
    let mut stream = SslStream::new(ssl, tcp)?;
    timeout(TEST_TIMEOUT, Pin::new(&mut stream).connect())
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new("negotiated control TLS exceeded its deadline", elapsed)
        })??;
    Ok(stream)
}

fn cause<'a, T: Error + 'static>(error: &'a (dyn Error + 'static)) -> Option<&'a T> {
    if let Some(found) = error.downcast_ref::<T>() {
        return Some(found);
    }
    if let Some(failures) = error.downcast_ref::<FixtureFailures>() {
        return cause(failures.primary.as_ref()).or_else(|| cause(failures.cleanup.as_ref()));
    }
    error.source().and_then(cause::<T>)
}

async fn held_origin(
    work: &mut Work,
    identity: &TestIdentity,
) -> TestResult<(Origin, SslStream<TcpStream>)> {
    let config = Config {
        hold_responses: true,
        ..Config::new(Alpn::Http1)
    };
    let mut origin = Origin::with(identity, config, work.connections.spawner()).await?;
    let mut peer = raw_tls(identity, origin.address, H1_ALPN).await?;
    peer.write_all(b"GET /held HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    assert_eq!(origin.next().await?, Event::Accepted(0));
    assert_eq!(origin.next_request().await?, (0, "held".to_owned()));
    Ok((origin, peer))
}

async fn socket_closed(peer: &mut SslStream<TcpStream>) -> TestResult {
    let closed = timeout(TEST_TIMEOUT, peer.read(&mut [0_u8; 1]))
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new("negotiated accepted socket did not close", elapsed)
        })?;
    assert!(
        matches!(closed, Ok(0))
            || matches!(closed, Err(ref error) if tls_support::is_peer_gone(error)),
        "accepted socket remained usable: {closed:?}"
    );
    Ok(())
}

#[tokio::test]
async fn dropping_the_root_owner_closes_the_actual_accepted_origin_and_listener() -> TestResult {
    let mut work = Work::new();
    let identity = TestIdentity::generate()?;
    let (origin, mut peer) = held_origin(&mut work, &identity).await?;
    let address = origin.address;
    drop(work);
    socket_closed(&mut peer).await?;
    drop(peer);
    let rebound = TcpListener::bind(address).await?;
    assert_eq!(rebound.local_addr()?, address);
    drop(origin);
    Ok(())
}

#[tokio::test]
async fn truncated_actual_http1_head_retains_its_io_cause_and_is_not_a_close() -> TestResult {
    let mut work = Work::new();
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let mut origin =
            Origin::start(&identity, Alpn::Http1, 0, work.connections.spawner()).await?;
        let mut peer = raw_tls(&identity, origin.address, H1_ALPN).await?;
        peer.write_all(b"GET /truncated HTTP/1.1\r\nHost:").await?;
        peer.shutdown().await?;
        assert_eq!(origin.next().await?, Event::Accepted(0));
        let error = origin
            .drain()
            .await
            .err()
            .ok_or("truncated head was reported as a normal close")?;
        assert!(error.to_string().contains("connection 0 failed"));
        Err(error)
    })
    .await;
    let error = work
        .finish(result)
        .await
        .err()
        .ok_or("serving failure was discarded")?;
    assert_eq!(
        cause::<io::Error>(error.as_ref())
            .ok_or("missing original head I/O cause")?
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
    Ok(())
}

#[tokio::test]
async fn invalid_actual_http2_frame_retains_the_driver_error() -> TestResult {
    let mut work = Work::new();
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let mut origin =
            Origin::start(&identity, Alpn::Http2, 0, work.connections.spawner()).await?;
        let mut peer = raw_tls(&identity, origin.address, H2_ALPN).await?;
        peer.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await?;
        // SETTINGS on stream 1 is a connection protocol error, before any GET.
        peer.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 1]).await?;
        assert_eq!(origin.next().await?, Event::Accepted(0));
        let error = origin
            .next()
            .await
            .err()
            .ok_or("invalid H2 frame was reported as a normal close")?;
        assert!(error.to_string().contains("connection 0 failed"));
        Err(error)
    })
    .await;
    let error = work
        .finish(result)
        .await
        .err()
        .ok_or("H2 driver failure was discarded")?;
    let driver =
        cause::<::http2::Error>(error.as_ref()).ok_or("missing original H2 driver cause")?;
    assert!(
        driver.get_io().is_none(),
        "protocol error became an I/O disconnect"
    );
    Ok(())
}

#[tokio::test]
async fn an_external_pending_listener_abort_is_not_a_requested_shutdown() -> TestResult {
    let mut work = Work::new();
    let identity = TestIdentity::generate()?;
    let origin = Origin::start(&identity, Alpn::Http1, 2, work.connections.spawner()).await?;
    let peer = TcpStream::connect(origin.address).await?;
    // Awaiting the actual accept event proves the listener already owns this TCP.
    let mut origin = origin;
    assert_eq!(origin.next().await?, Event::Accepted(0));
    let id = origin.listener_abort.id();
    origin.listener_abort.abort();
    // Current-thread runtime: abort is requested but has not yet been polled.
    assert!(!origin.listener_abort.is_finished());
    drop(origin);
    let primary: TestResult =
        Err(io::Error::new(io::ErrorKind::InvalidInput, "primary caller failure").into());
    let error = work
        .finish(primary)
        .await
        .err()
        .ok_or("external listener abort was discarded")?;
    let joined = cause::<tokio::task::JoinError>(error.as_ref())
        .ok_or("missing external cancellation cause")?;
    assert!(joined.is_cancelled());
    assert_eq!(joined.id(), id);
    assert_eq!(
        cause::<io::Error>(error.as_ref())
            .ok_or("missing primary caller cause")?
            .kind(),
        io::ErrorKind::InvalidInput
    );
    drop(peer);
    Ok(())
}

#[tokio::test]
async fn interrupted_collection_retains_completed_head_failure_and_pending_resources() -> TestResult
{
    let mut work = Work::new();
    let identity = TestIdentity::generate()?;
    let mut first = Origin::start(&identity, Alpn::Http1, 0, work.connections.spawner()).await?;
    let mut truncated = raw_tls(&identity, first.address, H1_ALPN).await?;
    truncated.write_all(b"GET /bad HTTP/1.1\r\n").await?;
    truncated.shutdown().await?;
    assert_eq!(first.next().await?, Event::Accepted(0));
    assert!(first.next().await.is_err());
    drop(first);
    let (second, mut held) = held_origin(&mut work, &identity).await?;
    // The completed first child is collected before the second live listener.
    assert!(timeout(QUIET_WINDOW, work.finish(Ok(()))).await.is_err());
    let address = second.address;
    drop(second);
    let error = work
        .finish(Ok(()))
        .await
        .err()
        .ok_or("interrupted cleanup lost the completed failure")?;
    assert_eq!(
        cause::<io::Error>(error.as_ref())
            .ok_or("missing retained head I/O cause")?
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
    socket_closed(&mut held).await?;
    drop(held);
    let rebound = TcpListener::bind(address).await?;
    assert_eq!(rebound.local_addr()?, address);
    Ok(())
}

#[tokio::test]
async fn an_external_pending_request_abort_keeps_its_join_cause() -> TestResult {
    let mut work = Work::new();
    let identity = TestIdentity::generate()?;
    let config = Config {
        hold_responses: true,
        ..Config::new(Alpn::Http1)
    };
    let mut origin = Origin::with(&identity, config, work.connections.spawner()).await?;
    let client = client(&identity, bound(1)?)?;
    let caller = work.spawn_response(client.get(&origin.uri("external-abort"))?.send())?;
    assert_eq!(
        origin.next_request().await?,
        (0, "external-abort".to_owned())
    );
    let abort = work.response_peer(caller)?.abort_handle();
    abort.abort();
    assert!(!abort.is_finished());
    drop(origin);
    let error = work
        .finish(Err("primary request control failure".into()))
        .await
        .err()
        .ok_or("external request abort was discarded")?;
    let joined = cause::<tokio::task::JoinError>(error.as_ref())
        .ok_or("missing external request JoinError")?;
    assert!(joined.is_cancelled());
    assert_eq!(joined.id(), abort.id());
    Ok(())
}

#[tokio::test]
async fn an_earlier_external_outcome_abort_survives_the_scripts_abort_request() -> TestResult {
    let mut work = Work::new();
    let identity = TestIdentity::generate()?;
    let config = Config {
        hold_responses: true,
        ..Config::new(Alpn::Http1)
    };
    let mut origin = Origin::with(&identity, config, work.connections.spawner()).await?;
    let client = client(&identity, bound(1)?)?;
    let caller = spawn_all(&client, &[origin.uri("earlier-abort")], &mut work)?[0];
    assert_eq!(
        origin.next_request().await?,
        (0, "earlier-abort".to_owned())
    );

    let external = work.outcome_peer(caller)?.abort_handle();
    external.abort();
    assert!(
        !external.is_finished(),
        "external abort must still be pending"
    );
    work.abort_outcome(caller)?;
    assert!(
        !external.is_finished(),
        "the script must not wait for external cancellation"
    );
    drop(origin);
    let primary: TestResult = Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "primary outcome caller failure",
    )
    .into());
    let error = work
        .finish(primary)
        .await
        .err()
        .ok_or("earlier external abort was discarded")?;
    let joined = cause::<tokio::task::JoinError>(error.as_ref())
        .ok_or("missing earlier external cancellation cause")?;
    assert!(joined.is_cancelled());
    assert_eq!(joined.id(), external.id());
    assert_eq!(
        cause::<io::Error>(error.as_ref())
            .ok_or("missing original outcome caller cause")?
            .kind(),
        io::ErrorKind::InvalidInput
    );
    Ok(())
}

#[tokio::test]
async fn a_truncated_actual_connect_child_keeps_its_failure_during_shutdown() -> TestResult {
    let mut work = Work::new();
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy =
        connect_proxy::Proxy::start(upstream.local_addr()?, work.connections.spawner()).await?;
    let address = proxy.address;
    let mut peer = TcpStream::connect(address).await?;
    peer.write_all(b"CONNECT localhost:443 HTTP/1.1\r\nHost:")
        .await?;
    peer.shutdown().await?;
    // Socket closure comes from this actual child returning its head-read error.
    let closed = timeout(TEST_TIMEOUT, peer.read(&mut [0_u8; 1]))
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new("CONNECT child did not close its accepted socket", elapsed)
        })?;
    assert!(
        matches!(closed, Ok(0))
            || matches!(closed, Err(ref error) if tls_support::is_peer_gone(error)),
        "CONNECT child socket remained usable: {closed:?}"
    );
    let error = work
        .finish(Err("primary CONNECT control failure".into()))
        .await
        .err()
        .ok_or("completed CONNECT child failure was discarded")?;
    assert_eq!(
        cause::<io::Error>(error.as_ref())
            .ok_or("missing CONNECT head I/O cause")?
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
    drop(peer);
    let rebound = TcpListener::bind(address).await?;
    assert_eq!(rebound.local_addr()?, address);
    drop(proxy);
    Ok(())
}

#[tokio::test]
async fn the_actual_caller_deadline_retains_elapsed_and_allows_origin_cleanup() -> TestResult {
    let mut work = Work::new();
    let identity = TestIdentity::generate()?;
    let config = Config {
        hold_responses: true,
        ..Config::new(Alpn::Http1)
    };
    let mut origin = Origin::with(&identity, config, work.connections.spawner()).await?;
    let client = client(&identity, bound(1)?)?;
    let caller = work.spawn_response(client.get(&origin.uri("deadline"))?.send())?;
    assert_eq!(origin.next_request().await?, (0, "deadline".to_owned()));
    // Pause only after a real accepted TLS request, so network setup uses time.
    tokio::time::pause();
    let primary = bounded(async {
        work.response_peer(caller)?.await??;
        Ok(())
    })
    .await;
    let error = primary
        .as_ref()
        .err()
        .ok_or("held caller escaped its deadline")?;
    assert_eq!(
        error.to_string(),
        "negotiated parallel test exceeded its deadline"
    );
    assert!(cause::<tokio::time::error::Elapsed>(error.as_ref()).is_some());
    tokio::time::resume();
    let address = origin.address;
    drop(origin);
    let error = work
        .finish(primary)
        .await
        .err()
        .ok_or("caller deadline was discarded")?;
    assert!(cause::<tokio::time::error::Elapsed>(error.as_ref()).is_some());
    let rebound = TcpListener::bind(address).await?;
    assert_eq!(rebound.local_addr()?, address);
    Ok(())
}

#[tokio::test]
async fn the_actual_body_reader_rejects_a_fifth_response_byte() -> TestResult {
    let mut work = Work::new();
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        work.connections.spawner().spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, acceptor).await?;
            let _head = request_head(&mut stream, false)
                .await?
                .ok_or("body control omitted GET")?;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\ndone!",
                )
                .await?;
            Ok(())
        })?;
        let client = client(&identity, bound(1)?)?;
        let response = hold(&client, &format!("https://{address}/oversized")).await?;
        finish(response).await
    })
    .await;
    let error = work
        .finish(result)
        .await
        .err()
        .ok_or("oversized body was accepted")?;
    assert_eq!(
        cause::<io::Error>(error.as_ref())
            .ok_or("missing actual body bound cause")?
            .kind(),
        io::ErrorKind::InvalidData
    );
    Ok(())
}
