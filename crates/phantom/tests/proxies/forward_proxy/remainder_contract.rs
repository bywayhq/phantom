use std::{
    error::Error,
    fmt, io,
    net::Ipv4Addr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use super::{
    TestResult, forward_challenge, read_closed_remainder, read_head, read_stalled_remainder,
};

const DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct ReadFailure;

impl fmt::Display for ReadFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected forward remainder read failure 937")
    }
}

impl Error for ReadFailure {}

struct FailingRead<'a>(&'a mut TcpStream);

impl AsyncRead for FailingRead<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let _socket = &self.get_mut().0;
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            ReadFailure,
        )))
    }
}

async fn ready_challenge() -> TestResult<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let mut client = TcpStream::connect(listener.local_addr()?).await?;
    let (mut proxy, _) = listener.accept().await?;
    client.write_all(super::FORWARD_ANONYMOUS).await?;
    assert_eq!(
        timeout(DEADLINE, read_head(&mut proxy)).await??,
        super::FORWARD_ANONYMOUS
    );
    let challenge = forward_challenge(b"Content-Length: 0\r\n\r\n");
    proxy.write_all(&challenge).await?;
    assert_eq!(timeout(DEADLINE, read_head(&mut client)).await??, challenge);
    Ok((proxy, client))
}

fn assert_read_failure(error: &(dyn Error + 'static)) -> TestResult<()> {
    let error = error
        .downcast_ref::<io::Error>()
        .ok_or("remainder lost its actual I/O error")?;
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(
        error
            .get_ref()
            .is_some_and(|source| source.is::<ReadFailure>())
    );
    Ok(())
}

#[tokio::test]
async fn the_closed_connection_reader_retains_an_unrelated_read_failure() -> TestResult<()> {
    let (mut proxy, mut client) = ready_challenge().await?;
    let result = read_closed_remainder(&mut FailingRead(&mut proxy)).await;
    client.shutdown().await?;
    drop(client);
    let error = result
        .err()
        .ok_or("closed reader accepted an unobserved empty buffer")?;
    assert_read_failure(error.as_ref())
}

#[tokio::test]
async fn the_stalled_connection_reader_retains_an_unrelated_read_failure() -> TestResult<()> {
    let (mut proxy, mut client) = ready_challenge().await?;
    let result = read_stalled_remainder(&mut FailingRead(&mut proxy)).await;
    client.shutdown().await?;
    drop(client);
    let error = result
        .err()
        .ok_or("stalled reader accepted an unobserved empty buffer")?;
    assert_read_failure(error.as_ref())
}

#[tokio::test]
async fn clean_eof_after_the_challenge_has_no_remaining_bytes() -> TestResult<()> {
    let (mut proxy, mut client) = ready_challenge().await?;
    client.shutdown().await?;
    assert!(
        timeout(DEADLINE, read_closed_remainder(&mut proxy))
            .await??
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn the_finite_stall_observation_keeps_the_peer_live() -> TestResult<()> {
    let (mut proxy, mut client) = ready_challenge().await?;
    assert!(
        timeout(DEADLINE, read_stalled_remainder(&mut proxy))
            .await??
            .is_empty()
    );
    // This is a finite quiet observation, with an independently live peer.
    client.write_all(b"later").await?;
    client.shutdown().await?;
    assert_eq!(
        timeout(DEADLINE, read_closed_remainder(&mut proxy)).await??,
        b"later"
    );
    Ok(())
}

#[tokio::test]
async fn bytes_after_a_challenge_are_observed_literally() -> TestResult<()> {
    let (mut proxy, mut client) = ready_challenge().await?;
    client.write_all(super::FORWARD_AUTHENTICATED).await?;
    client.shutdown().await?;
    assert_eq!(
        timeout(DEADLINE, read_closed_remainder(&mut proxy)).await??,
        super::FORWARD_AUTHENTICATED
    );
    Ok(())
}
