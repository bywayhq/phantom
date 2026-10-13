use std::{
    error::Error,
    fmt, io,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Duration,
};

use phantom::{HttpProtocol, HttpProxy, RequestError, RequestErrorKind, Route};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};

use super::{
    FORWARD_ANONYMOUS, FORWARD_AUTHENTICATED, TestIdentity, TestResult, client_builder,
    finish_one_shot, forward_challenge, read_head, serve_forward_challenge,
};
use crate::support::tunnel_proxy::{
    ConnectionPeer, connection_peer::FixtureFailures, finish_with_cleanup,
};

const DEADLINE: Duration = Duration::from_secs(5);
const COMPLETE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nthrough";
const TRUNCATED: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nth";
const NO_CONTENT: &[u8] = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";

#[derive(Debug)]
struct PeerFailure;

impl fmt::Display for PeerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("forward peer failed after its actual response")
    }
}

impl Error for PeerFailure {}

async fn one_shot(response: &'static [u8], result: TestResult<()>) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let route = Route::http_proxy(HttpProxy::new(&format!("http://{address}"))?);
    let client = client_builder(&identity, false).route(route).build()?;
    let (completed, completion) = oneshot::channel();
    let proxy = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let head = read_head(&mut stream).await?;
        assert_eq!(head, b"POST http://origin.test/observed HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 7\r\n\r\n");
        let mut body = [0_u8; 7];
        stream.read_exact(&mut body).await?;
        assert_eq!(&body, b"payload");
        stream.write_all(response).await?;
        stream.flush().await?;
        let _ = completed.send(());
        result?;
        TestResult::Ok((head, body))
    });
    // The raw task is deliberately transferred to the original caller seam.
    let abort = proxy.abort_handle();
    let guard = AbortForwardPeer(abort);

    let operation = async {
        let response = client
            .request(
                HttpProtocol::Http1,
                http::Method::POST,
                "http://origin.test/observed",
            )?
            .body(bytes::Bytes::from_static(b"payload"))
            .send()
            .await?;
        finish_one_shot(response, proxy).await?;
        Ok(())
    }
    .await;
    let observed = async {
        timeout(DEADLINE, completion).await??;
        Ok(())
    }
    .await;
    drop(guard);
    finish_with_cleanup(operation, observed)
}

struct AbortForwardPeer(tokio::task::AbortHandle);

impl Drop for AbortForwardPeer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn assert_truncated(error: &(dyn Error + 'static)) -> TestResult<()> {
    let mut cause = error;
    loop {
        if let Some(request) = cause.downcast_ref::<RequestError>() {
            assert_eq!(request.kind(), RequestErrorKind::Http1);
            assert_eq!(request.protocol(), Some(HttpProtocol::Http1));
            break;
        }
        cause = cause.source().ok_or("missing concrete request error")?;
    }
    loop {
        if let Some(io) = cause.downcast_ref::<io::Error>() {
            assert_eq!(io.kind(), io::ErrorKind::UnexpectedEof);
            return Ok(());
        }
        cause = cause
            .source()
            .ok_or("missing original truncated-body I/O error")?;
    }
}

#[tokio::test]
async fn a_truncated_body_keeps_the_completed_peer_failure() -> TestResult<()> {
    let error = timeout(DEADLINE, one_shot(TRUNCATED, Err(PeerFailure.into())))
        .await?
        .err()
        .ok_or("truncated response succeeded")?;
    assert_truncated(error.as_ref())?;
    let failures = error
        .downcast_ref::<FixtureFailures>()
        .ok_or("caller discarded completed peer failure")?;
    assert!(failures.cleanup.downcast_ref::<PeerFailure>().is_some());
    Ok(())
}

#[tokio::test]
async fn a_truncated_body_keeps_its_error_with_a_successful_peer() -> TestResult<()> {
    let error = timeout(DEADLINE, one_shot(TRUNCATED, Ok(())))
        .await?
        .err()
        .ok_or("truncated response succeeded")?;
    assert_truncated(error.as_ref())
}

#[tokio::test]
async fn a_complete_body_keeps_its_completed_peer_failure() -> TestResult<()> {
    let error = timeout(DEADLINE, one_shot(COMPLETE, Err(PeerFailure.into())))
        .await?
        .err()
        .ok_or("failed peer succeeded")?;
    assert!(error.downcast_ref::<PeerFailure>().is_some());
    Ok(())
}

#[tokio::test]
async fn a_complete_body_and_peer_keep_the_literal_oracle() -> TestResult<()> {
    timeout(DEADLINE, one_shot(COMPLETE, Ok(()))).await?
}

async fn challenge_peer() -> TestResult<(
    ConnectionPeer<TestResult<usize>>,
    TcpStream,
    super::ConnectionHeads,
)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let heads = Arc::new(Mutex::new(Vec::new()));
    let peer = ConnectionPeer::spawn(serve_forward_challenge(
        listener,
        Arc::clone(&heads),
        forward_challenge(b"Content-Length: 0\r\n\r\n"),
        false,
    ));

    let mut client = TcpStream::connect(address).await?;
    client.write_all(FORWARD_ANONYMOUS).await?;
    let challenged = timeout(DEADLINE, read_head(&mut client)).await??;
    assert_eq!(challenged, forward_challenge(b"Content-Length: 0\r\n\r\n"));
    client.write_all(FORWARD_AUTHENTICATED).await?;
    assert_eq!(
        timeout(DEADLINE, read_head(&mut client)).await??,
        NO_CONTENT
    );
    Ok((peer, client, heads))
}

#[tokio::test]
async fn cancelling_the_supervisor_closes_its_ready_response_handler() -> TestResult<()> {
    let (mut peer, mut client, heads) = challenge_peer().await?;
    peer.abort();
    let joined = timeout(DEADLINE, &mut peer).await?;
    assert!(matches!(joined, Err(ref error) if error.is_cancelled()));
    let closed = timeout(Duration::from_millis(150), client.read(&mut [0_u8; 1])).await;
    client.shutdown().await?;
    drop(client);
    assert_eq!(heads.lock().map_err(|_| "head lock poisoned")?.len(), 2);
    assert!(
        matches!(closed, Ok(Ok(0)))
            || matches!(closed, Ok(Err(ref error)) if crate::support::tls::is_peer_gone(error)),
        "ready handler survived its supervisor: {closed:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_partial_next_head_keeps_the_actual_handler_failure() -> TestResult<()> {
    let (peer, mut client, heads) = challenge_peer().await?;
    client
        .write_all(b"GET http://origin.test/incomplete")
        .await?;
    client.shutdown().await?;
    let closed = timeout(DEADLINE, client.read(&mut [0_u8; 1])).await??;
    assert_eq!(closed, 0);
    let completed = timeout(DEADLINE, peer).await?;
    drop(client);
    assert_eq!(heads.lock().map_err(|_| "head lock poisoned")?.len(), 2);
    let error = completed?
        .err()
        .ok_or("supervisor discarded its failed response handler")?;
    let io = error
        .downcast_ref::<io::Error>()
        .ok_or("handler lost its concrete I/O error")?;
    assert_eq!(io.kind(), io::ErrorKind::UnexpectedEof);
    Ok(())
}

#[tokio::test]
async fn clean_eof_after_a_response_keeps_the_recorded_heads() -> TestResult<()> {
    let (peer, mut client, heads) = challenge_peer().await?;
    client.shutdown().await?;
    assert_eq!(timeout(DEADLINE, client.read(&mut [0_u8; 1])).await??, 0);
    assert_eq!(timeout(DEADLINE, peer).await???, 1);
    let heads = heads.lock().map_err(|_| "head lock poisoned")?;
    assert_eq!(
        heads.as_slice(),
        [
            (0, FORWARD_ANONYMOUS.to_vec()),
            (0, FORWARD_AUTHENTICATED.to_vec())
        ]
    );
    Ok(())
}
