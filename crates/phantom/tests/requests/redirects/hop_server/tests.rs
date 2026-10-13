use std::{io, net::Ipv4Addr, ptr};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::{Duration, timeout},
};

use super::{HopServer, TEST_TIMEOUT, TestResult, finish_with_cleanup};
use crate::support::tunnel_proxy::connection_peer::FixtureFailures;

#[tokio::test]
async fn a_truncated_hop_preserves_the_caller_and_child_failures() -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let (heads, _received) = mpsc::unbounded_channel();
    let mut server = HopServer::spawn(listener, heads, |_| None);
    let mut client = TcpStream::connect(address).await?;
    client.write_all(b"GET /truncated HTTP/1.1\r\n").await?;
    client.shutdown().await?;
    wait_for_child(&server, true).await?;

    let caller = Box::new(io::Error::other(
        "caller stopped after sending a partial head",
    ));
    let original = ptr::from_ref(caller.as_ref());
    let result: TestResult<()> = finish_with_cleanup(Err(caller), server.shutdown().await);
    let error = result.expect_err("truncated hop was silently discarded");
    let failures = error
        .downcast_ref::<FixtureFailures>()
        .ok_or("combined failure was not retained")?;
    let retained = failures
        .primary
        .downcast_ref::<io::Error>()
        .ok_or("caller cause lost its type")?;
    assert!(ptr::eq(original, ptr::from_ref(retained)));
    assert_eq!(
        failures
            .cleanup
            .downcast_ref::<io::Error>()
            .ok_or("child I/O cause lost its type")?
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
    Ok(())
}

#[tokio::test]
async fn a_caller_timeout_keeps_the_accepted_hop_available_for_cleanup() -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let (heads, mut received) = mpsc::unbounded_channel();
    let mut server = HopServer::spawn(listener, heads, |_| None);
    let mut client = TcpStream::connect(address).await?;
    client.write_all(b"GET /waiting HTTP/1.1\r\n").await?;
    wait_for_child(&server, false).await?;

    let result = timeout(Duration::from_millis(20), received.recv()).await;
    let elapsed = result.expect_err("incomplete request produced a head");
    let primary: TestResult<()> =
        Err(super::FixtureDeadline::new("redirect caller control expired", elapsed).into());
    let error = finish_with_cleanup(primary, server.shutdown().await)
        .expect_err("caller deadline was discarded");
    assert!(error.downcast_ref::<super::FixtureDeadline>().is_some());
    assert!(
        error
            .source()
            .and_then(|cause| cause.downcast_ref::<tokio::time::error::Elapsed>())
            .is_some()
    );
    assert!(
        server
            .connections
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .peers
            .iter()
            .all(|peer| peer.task.is_none())
    );
    assert_closed(&mut client).await?;
    Ok(())
}

#[tokio::test]
async fn dropping_a_hop_server_closes_its_accepted_child_with_runtime_live() -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let (heads, _received) = mpsc::unbounded_channel();
    let server = HopServer::spawn(listener, heads, |_| None);
    let mut client = TcpStream::connect(address).await?;
    client.write_all(b"GET /waiting HTTP/1.1\r\n").await?;
    wait_for_child(&server, false).await?;
    drop(server);
    assert_closed(&mut client).await?;
    // Socket closure establishes that the accepted task was dropped while
    // this runtime is still executing, rather than at runtime teardown.
    Ok(())
}

async fn wait_for_child(server: &HopServer, finished: bool) -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        loop {
            let ready = {
                let connections = server
                    .connections
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                connections
                    .peers
                    .first()
                    .and_then(|peer| peer.task.as_ref())
                    .is_some_and(|task| !finished || task.is_finished())
            };
            if ready {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}

async fn assert_closed(client: &mut TcpStream) -> TestResult<()> {
    match timeout(TEST_TIMEOUT, client.read_u8()).await? {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(_) => Err("accepted redirect peer remained open".into()),
    }
}
