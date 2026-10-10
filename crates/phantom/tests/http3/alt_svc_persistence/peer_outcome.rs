use std::{error::Error, fmt, io, net::Ipv4Addr, time::Duration};

use phantom::{HttpProtocol, RequestError, RequestErrorKind};
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::oneshot, time::timeout};

use super::{PlaintextPeer, TestIdentity, TestResult, client, plaintext_response, read_head};
use crate::support::tunnel_proxy::{FixtureFailures, finish_with_cleanup};

const DEADLINE: Duration = Duration::from_secs(5);
const COMPLETE: &[u8] =
    b"HTTP/1.1 200 OK\r\nAlt-Svc: h3=\":443\"; ma=3600\r\nContent-Length: 0\r\n\r\n";
const TRUNCATED: &[u8] =
    b"HTTP/1.1 200 OK\r\nAlt-Svc: h3=\":443\"; ma=3600\r\nContent-Length: 4\r\n\r\nab";

#[derive(Debug)]
struct PeerFailure;

impl fmt::Display for PeerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("plaintext response peer failed after its writes")
    }
}

impl Error for PeerFailure {}

async fn exchange(response: &'static [u8], peer_result: TestResult<()>) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client(&identity, 8)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let (completed, completion) = oneshot::channel();
    let server = PlaintextPeer::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let head = read_head(&mut stream).await?;
        assert!(head.starts_with(b"GET /advertises HTTP/1.1\r\n"));

        stream.write_all(response).await?;
        stream.flush().await?;
        // A cancelled controller may drop this observer. Preserve the peer result.
        let _ = completed.send(());
        peer_result
    });

    let result = plaintext_response(&client, address, server).await;
    let observed = async {
        timeout(DEADLINE, completion).await??;
        Ok(())
    }
    .await;
    finish_with_cleanup(result, observed)
}

fn assert_truncated_body(error: &(dyn Error + 'static)) -> TestResult<()> {
    let mut cause = error;
    let request = loop {
        if let Some(request) = cause.downcast_ref::<RequestError>() {
            break request;
        }

        cause = cause
            .source()
            .ok_or("truncated body lost its concrete request error")?;
    };
    assert_eq!(request.kind(), RequestErrorKind::Http1);
    assert_eq!(request.protocol(), Some(HttpProtocol::Http1));

    let mut cause: &(dyn Error + 'static) = request;
    loop {
        if let Some(error) = cause.downcast_ref::<io::Error>() {
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
            return Ok(());
        }

        cause = cause
            .source()
            .ok_or("truncated body lost its concrete I/O cause")?;
    }
}

#[tokio::test]
async fn a_truncated_response_keeps_both_the_body_and_completed_peer_errors() -> TestResult<()> {
    timeout(Duration::from_secs(15), async {
        let error = exchange(TRUNCATED, Err(PeerFailure.into()))
            .await
            .err()
            .ok_or("truncated response completed successfully")?;
        assert_truncated_body(error.as_ref())?;

        let failures = error
            .downcast_ref::<FixtureFailures>()
            .ok_or("caller discarded its completed peer failure")?;

        assert!(failures.cleanup.downcast_ref::<PeerFailure>().is_some());
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn a_truncated_response_keeps_its_body_error_with_a_successful_peer() -> TestResult<()> {
    timeout(Duration::from_secs(15), async {
        let error = exchange(TRUNCATED, Ok(()))
            .await
            .err()
            .ok_or("truncated response completed successfully")?;
        assert_truncated_body(error.as_ref())
    })
    .await?
}

#[tokio::test]
async fn a_complete_response_keeps_its_completed_peer_error() -> TestResult<()> {
    timeout(Duration::from_secs(15), async {
        let error = exchange(COMPLETE, Err(PeerFailure.into()))
            .await
            .err()
            .ok_or("failed peer completed successfully")?;
        assert!(error.downcast_ref::<PeerFailure>().is_some());
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn a_complete_response_and_successful_peer_keep_the_plaintext_oracle() -> TestResult<()> {
    timeout(Duration::from_secs(15), exchange(COMPLETE, Ok(()))).await?
}
