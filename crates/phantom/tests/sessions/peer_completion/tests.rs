use std::{io, net::Ipv4Addr};

use phantom::{Client, RequestError, RequestErrorKind, profile::ClientProfile};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};

use super::{CLEANUP_TIMEOUT, Peer, TestResult, finish, join};
use crate::support::{
    tls::{is_peer_gone, tls_settings},
    tunnel_proxy::connection_peer::FixtureFailures,
};

#[tokio::test]
async fn caller_failure_collects_a_completed_peer_and_pending_external_cancellation()
-> TestResult<()> {
    let failed_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let failed_address = failed_listener.local_addr()?;
    let pending_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let pending_address = pending_listener.local_addr()?;
    let (entered, accepted) = oneshot::channel();
    let mut failed = Some(Peer::spawn(async move {
        let (mut stream, _) = failed_listener.accept().await?;
        stream.read_u8().await?;
        Err::<(), _>(
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "original session peer failure",
            )
            .into(),
        )
    }));
    let mut pending = Some(Peer::spawn(async move {
        let (mut stream, _) = pending_listener.accept().await?;
        entered.send(()).map_err(|()| "accept observer stopped")?;
        stream.read_u8().await?;
        Err::<(), _>("pending session peer received unexpected data".into())
    }));
    let failed_task = failed
        .as_ref()
        .ok_or("failed peer missing")?
        .task
        .abort_handle();
    let pending_task = pending
        .as_ref()
        .ok_or("pending peer missing")?
        .task
        .abort_handle();
    let mut failed_socket = TcpStream::connect(failed_address).await?;
    failed_socket.write_all(b"!").await?;
    let mut pending_socket = TcpStream::connect(pending_address).await?;
    timeout(CLEANUP_TIMEOUT, accepted).await??;
    timeout(CLEANUP_TIMEOUT, async {
        while !failed_task.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await?;

    // Do not wait for cancellation to complete: local stop must not relabel it.
    pending_task.abort();
    let result = finish(Err::<(), _>(invalid_request()?.into()), &mut failed).await;
    let result = finish(result, &mut pending).await;
    let error = result
        .err()
        .ok_or("original session failures were discarded")?;
    assert!(failed.is_none());
    assert!(pending.is_none());
    assert!(failed_task.is_finished());
    assert!(pending_task.is_finished());
    let causes = error
        .downcast_ref::<FixtureFailures>()
        .ok_or("missing external cancellation")?;
    let cancelled = causes
        .cleanup
        .downcast_ref::<tokio::task::JoinError>()
        .ok_or("external cancellation was relabeled as local stop")?;
    assert!(cancelled.is_cancelled());
    assert_eq!(cancelled.id(), pending_task.id());
    let earlier = causes
        .primary
        .downcast_ref::<FixtureFailures>()
        .ok_or("missing caller and completed worker causes")?;
    assert_eq!(
        earlier
            .primary
            .downcast_ref::<RequestError>()
            .ok_or("missing original caller type")?
            .kind(),
        RequestErrorKind::InvalidAuthority
    );
    let original = earlier
        .cleanup
        .downcast_ref::<io::Error>()
        .ok_or("missing original completed worker error")?;
    assert_eq!(original.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(original.to_string(), "original session peer failure");
    assert_closed(&mut failed_socket).await?;
    assert_closed(&mut pending_socket).await?;
    let failed_rebound = TcpListener::bind(failed_address).await?;
    let pending_rebound = TcpListener::bind(pending_address).await?;
    assert_eq!(failed_rebound.local_addr()?, failed_address);
    assert_eq!(pending_rebound.local_addr()?, pending_address);
    Ok(())
}

#[tokio::test]
async fn each_session_deadline_collects_its_original_accepted_peer_and_elapsed() -> TestResult<()> {
    for http3 in [false, true] {
        let (mut peer, mut socket, address) = accepted_peer().await?;
        let task = peer
            .as_ref()
            .ok_or("accepted peer missing")?
            .task
            .abort_handle();
        // Acquire and observe the real socket before pausing the clock. Only
        // the original caller timer is needed while the peer remains blocked.
        tokio::time::pause();
        let caller = if http3 {
            super::super::session_http3::bounded(async { join(&mut peer).await }).await
        } else {
            super::super::session_http2_lifecycle::bounded(async { join(&mut peer).await }).await
        };
        let result = finish(caller, &mut peer).await;
        tokio::time::resume();

        let error = result
            .err()
            .ok_or("original session deadline disappeared")?;
        assert!(
            error
                .source()
                .is_some_and(|cause| cause.is::<tokio::time::error::Elapsed>())
        );
        assert!(peer.is_none());
        assert!(task.is_finished());
        assert_closed(&mut socket).await?;
        let rebound = TcpListener::bind(address).await?;
        assert_eq!(rebound.local_addr()?, address);
    }
    Ok(())
}

#[tokio::test]
async fn local_stop_collects_an_accepted_peer_without_fabricating_cancellation() -> TestResult<()> {
    let (mut peer, mut socket, address) = accepted_peer().await?;
    let task = peer
        .as_ref()
        .ok_or("accepted peer missing")?
        .task
        .abort_handle();
    finish(Ok(()), &mut peer).await?;
    assert!(peer.is_none());
    assert!(task.is_finished());
    assert_closed(&mut socket).await?;
    let rebound = TcpListener::bind(address).await?;
    assert_eq!(rebound.local_addr()?, address);
    Ok(())
}

async fn accepted_peer() -> TestResult<(Option<Peer<()>>, TcpStream, std::net::SocketAddr)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let (entered, accepted) = oneshot::channel();
    let peer = Peer::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        entered.send(()).map_err(|()| "accept observer stopped")?;
        stream.read_u8().await?;
        Err::<(), _>("pending session peer received unexpected data".into())
    });
    let socket = TcpStream::connect(address).await?;
    timeout(CLEANUP_TIMEOUT, accepted).await??;
    Ok((Some(peer), socket, address))
}

async fn assert_closed(socket: &mut TcpStream) -> TestResult<()> {
    match timeout(CLEANUP_TIMEOUT, socket.read(&mut [0_u8; 1])).await? {
        Ok(0) => Ok(()),
        Err(error) if is_peer_gone(&error) => Ok(()),
        Ok(_) => Err("session peer sent data instead of closing".into()),
        Err(error) => Err(error.into()),
    }
}

fn invalid_request() -> TestResult<RequestError> {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(phantom::profile::browser::chrome::v154_http2());
    let client = Client::builder(profile).build()?;
    client
        .get_with_protocol(phantom::HttpProtocol::Http2, "https://[invalid/")
        .err()
        .ok_or_else(|| "malformed session target was accepted".into())
}
