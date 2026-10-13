use std::{
    error::Error,
    future::{Future, pending, poll_fn},
    io,
    net::Ipv4Addr,
    task::Poll,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use super::{
    Peer, TEST_TIMEOUT, TestResult, bounded, cancel, finish, finish_negative, join, no_connection,
};
use crate::support::tunnel_proxy::connection_peer::FixtureFailures;

#[tokio::test]
async fn caller_failure_retains_completed_descendant_failure() -> TestResult<()> {
    let peer = Peer::spawn(async {
        let mut child = Some(Peer::spawn(async {
            TestResult::<()>::Err(
                io::Error::new(io::ErrorKind::PermissionDenied, DescendantFault).into(),
            )
        }));
        join(&mut child).await
    });
    bounded(async {
        while !peer.is_finished() {
            tokio::task::yield_now().await;
        }
        Ok(())
    })
    .await?;
    let primary =
        Err(io::Error::new(io::ErrorKind::InvalidInput, "original caller failure").into());
    let mut owner = Some(peer);
    let error = finish::<(), _>(primary, &mut owner)
        .await
        .expect_err("both failures must be retained");
    let failures = error
        .downcast_ref::<FixtureFailures>()
        .ok_or("missing simultaneous fixture causes")?;
    assert_eq!(
        failures
            .primary
            .downcast_ref::<io::Error>()
            .ok_or("missing caller I/O cause")?
            .kind(),
        io::ErrorKind::InvalidInput
    );
    let descendant = failures
        .cleanup
        .downcast_ref::<io::Error>()
        .ok_or("missing descendant I/O cause")?;
    assert_eq!(descendant.kind(), io::ErrorKind::PermissionDenied);
    assert!(
        descendant
            .get_ref()
            .is_some_and(|cause| cause.is::<DescendantFault>())
    );
    Ok(())
}

#[tokio::test]
async fn borrowed_join_deadline_observes_accepted_socket_destruction() -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let mut owner = Some(Peer::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        assert_eq!(stream.read_u8().await?, b'!');
        stream.write_all(b"ready").await?;
        pending::<()>().await;
        TestResult::Ok(())
    }));
    let mut client = timeout(TEST_TIMEOUT, TcpStream::connect(address)).await??;
    client.write_all(b"!").await?;
    let mut ready = [0_u8; 5];
    timeout(TEST_TIMEOUT, client.read_exact(&mut ready)).await??;
    assert_eq!(&ready, b"ready");

    tokio::time::pause();
    let primary = bounded(join(&mut owner)).await;
    assert!(
        owner.is_some(),
        "expired borrowed join must retain the worker"
    );
    let error = finish(primary, &mut owner)
        .await
        .expect_err("caller deadline must remain an error");
    assert!(
        error
            .source()
            .is_some_and(|cause| cause.is::<tokio::time::error::Elapsed>())
    );
    tokio::time::resume();
    let closed = timeout(TEST_TIMEOUT, client.read_u8()).await?;
    assert!(
        matches!(closed, Err(ref error) if error.kind() == io::ErrorKind::UnexpectedEof || crate::support::tls::is_peer_gone(error))
    );
    let rebound = TcpListener::bind(address).await?;
    assert_eq!(rebound.local_addr()?, address);
    Ok(())
}

#[tokio::test]
async fn only_requested_pending_cancellation_is_accepted() -> TestResult<()> {
    let mut pending_peer = Some(Peer::spawn(pending::<TestResult<()>>()));
    bounded(cancel(&mut pending_peer)).await?;
    assert!(pending_peer.is_none());

    for cancellation in [false, true] {
        let peer = Peer::spawn(pending::<TestResult<()>>());
        let external = peer.task.abort_handle();
        external.abort();
        assert!(
            !peer.is_finished(),
            "external abort must still be pending at cleanup entry"
        );
        let mut owner = Some(peer);
        let error = if cancellation {
            cancel(&mut owner).await
        } else {
            finish(Ok(()), &mut owner).await
        }
        .expect_err("unrequested cancellation must remain a failure");
        let join = error
            .downcast_ref::<tokio::task::JoinError>()
            .ok_or("missing original external cancellation")?;
        assert!(join.is_cancelled());
        assert_eq!(join.id(), external.id());
        assert!(owner.is_none());
    }

    let mut failed = Some(Peer::<()>::spawn(async {
        panic!("original negotiated worker panic");
    }));
    bounded(async {
        while !failed.as_ref().ok_or("missing panic owner")?.is_finished() {
            tokio::task::yield_now().await;
        }
        Ok(())
    })
    .await?;
    let error = cancel(&mut failed)
        .await
        .expect_err("a panic must not count as cancellation");
    let join = error
        .downcast::<tokio::task::JoinError>()
        .map_err(|_| "missing original panic JoinError")?;
    assert!(join.is_panic());
    assert_eq!(
        (*join).into_panic().downcast_ref::<&str>(),
        Some(&"original negotiated worker panic")
    );
    Ok(())
}

#[tokio::test]
async fn quiet_accept_preserves_io_error_and_observes_real_acceptance() -> TestResult<()> {
    let error = no_connection(async {
        Err::<(), _>(io::Error::new(
            io::ErrorKind::PermissionDenied,
            DescendantFault,
        ))
    })
    .await
    .expect_err("accept I/O must remain an error");
    let io = error
        .downcast_ref::<io::Error>()
        .ok_or("missing original accept cause")?;
    assert_eq!(io.kind(), io::ErrorKind::PermissionDenied);
    assert!(
        io.get_ref()
            .is_some_and(|cause| cause.is::<DescendantFault>())
    );

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let client = timeout(TEST_TIMEOUT, TcpStream::connect(listener.local_addr()?)).await??;
    assert!(!no_connection(listener.accept()).await?);
    drop(client);
    assert!(no_connection(pending::<io::Result<()>>()).await?);
    Ok(())
}

#[tokio::test]
async fn negative_client_outcome_survives_worker_completion_failure() -> TestResult<()> {
    let identity = crate::support::tls::TestIdentity::generate()?;
    let client = crate::support::tls::test_client(&identity, true)?;
    let request = match client.get_negotiated("https://[invalid/") {
        Err(error) => error,
        Ok(_) => return Err("invalid URI unexpectedly built a request".into()),
    };
    assert_eq!(request.kind(), phantom::RequestErrorKind::InvalidUri);
    let peer = Peer::spawn(async {
        TestResult::<()>::Err(
            io::Error::new(io::ErrorKind::PermissionDenied, DescendantFault).into(),
        )
    });
    bounded(async {
        while !peer.is_finished() {
            tokio::task::yield_now().await;
        }
        Ok(())
    })
    .await?;
    let mut owner = Some(peer);
    let completion = finish(Ok(()), &mut owner).await;
    let error =
        finish_negative(completion, Some(request)).expect_err("both original outcomes must remain");
    let failures = error
        .downcast_ref::<FixtureFailures>()
        .ok_or("missing client and worker outcomes")?;
    assert_eq!(
        failures
            .primary
            .downcast_ref::<phantom::RequestError>()
            .ok_or("missing original client error")?
            .kind(),
        phantom::RequestErrorKind::InvalidUri
    );
    assert_eq!(
        failures
            .cleanup
            .downcast_ref::<io::Error>()
            .ok_or("missing original worker error")?
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    Ok(())
}

#[tokio::test]
async fn interrupted_cleanup_retains_client_failure_and_accepted_worker() -> TestResult<()> {
    let identity = crate::support::tls::TestIdentity::generate()?;
    let client = crate::support::tls::test_client(&identity, true)?;
    let request = client
        .get_negotiated("https://[invalid/")
        .expect_err("invalid URI must retain the client failure");
    assert_eq!(request.kind(), phantom::RequestErrorKind::InvalidUri);

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let mut owner = Some(Peer::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        assert_eq!(stream.read_u8().await?, b'!');
        stream.write_all(b"ready").await?;
        pending::<()>().await;
        TestResult::Ok(())
    }));
    let mut socket = timeout(TEST_TIMEOUT, TcpStream::connect(address)).await??;
    socket.write_all(b"!").await?;
    let mut ready = [0_u8; 5];
    timeout(TEST_TIMEOUT, socket.read_exact(&mut ready)).await??;
    assert_eq!(&ready, b"ready");
    let worker_id = owner
        .as_ref()
        .ok_or("missing accepted worker")?
        .task
        .abort_handle()
        .id();

    tokio::time::pause();
    let interrupted = {
        let cleanup = bounded(async {
            // Enter the actual cleanup join on the caller's original deadline turn.
            tokio::time::sleep(TEST_TIMEOUT).await;
            finish::<(), _>(Err(request.into()), &mut owner).await
        });
        tokio::pin!(cleanup);
        poll_fn(|context| {
            assert!(cleanup.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        tokio::time::advance(TEST_TIMEOUT).await;
        cleanup
            .await
            .expect_err("ordinary caller watchdog must interrupt cleanup")
    };
    assert!(
        interrupted
            .source()
            .is_some_and(|cause| cause.is::<tokio::time::error::Elapsed>())
    );
    assert!(
        owner.is_some(),
        "interrupted cleanup must retain its original worker"
    );
    assert_eq!(
        owner
            .as_ref()
            .ok_or("interrupted cleanup lost accepted worker")?
            .task
            .abort_handle()
            .id(),
        worker_id
    );
    let error = finish::<(), _>(Err(interrupted), &mut owner)
        .await
        .expect_err("original client and deadline outcomes must remain");
    assert!(owner.is_none(), "only an observed join may clear the owner");
    let causes = error
        .downcast_ref::<FixtureFailures>()
        .ok_or("missing original client and interrupted completion")?;
    assert_eq!(
        causes
            .primary
            .downcast_ref::<phantom::RequestError>()
            .ok_or("missing original client failure")?
            .kind(),
        phantom::RequestErrorKind::InvalidUri
    );
    assert!(
        causes
            .cleanup
            .source()
            .is_some_and(|cause| cause.is::<tokio::time::error::Elapsed>())
    );
    tokio::time::resume();

    let closed = timeout(TEST_TIMEOUT, socket.read_u8()).await?;
    assert!(
        matches!(closed, Err(ref error) if error.kind() == io::ErrorKind::UnexpectedEof || crate::support::tls::is_peer_gone(error))
    );
    let rebound = TcpListener::bind(address).await?;
    assert_eq!(rebound.local_addr()?, address);
    Ok(())
}

#[derive(Debug)]
struct DescendantFault;

impl std::fmt::Display for DescendantFault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("original negotiated descendant fault")
    }
}

impl Error for DescendantFault {}
