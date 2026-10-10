use std::{
    cell::Cell,
    error::Error,
    fmt,
    future::pending,
    io,
    net::Ipv4Addr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};

use super::exchange_peer;
use crate::support::tls::{TestResult, is_peer_gone, read_head};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);
const HEAD: &[u8] = b"GET /ownership HTTP/1.1\r\nHost: loopback.test\r\n\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";

struct PeerDestroyed(Option<oneshot::Sender<()>>);

impl Drop for PeerDestroyed {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            // A cancelled enclosing test may no longer observe the signal.
            let _ = sender.send(());
        }
    }
}

#[derive(Debug)]
struct PeerFailure;

impl fmt::Display for PeerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("driven client peer failed")
    }
}

impl Error for PeerFailure {}

#[tokio::test]
async fn successful_peer_exchange_keeps_literal_request_and_response_bytes() -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut client = TcpStream::connect(listener.local_addr()?).await?;
        let peer = async move {
            let (mut stream, _) = listener.accept().await?;
            let head = read_head(&mut stream).await?;
            stream.write_all(RESPONSE).await?;
            Ok(head)
        };
        let request = async {
            client.write_all(HEAD).await?;
            Ok(read_head(&mut client).await?)
        };

        let (head, response) = exchange_peer(peer, request).await?;
        assert_eq!(head, HEAD);
        assert_eq!(response, RESPONSE);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn owner_cancellation_closes_a_driven_peer_with_client_retained() -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut client = TcpStream::connect(listener.local_addr()?).await?;
        let (destroyed, mut destruction) = oneshot::channel();
        let peer = async move {
            let _destroyed = PeerDestroyed(Some(destroyed));
            let (mut stream, _) = listener.accept().await?;
            assert_eq!(read_head(&mut stream).await?, HEAD);
            stream.write_all(RESPONSE).await?;
            let mut byte = [0_u8; 1];
            assert_eq!(stream.read(&mut byte).await?, 0);
            Ok(())
        };
        let mut owner = Box::pin(exchange_peer(peer, pending::<TestResult<()>>()));
        client.write_all(HEAD).await?;

        let response = tokio::select! {
            response = read_head(&mut client) => response?,
            result = &mut owner => {
                result?;
                return Err("peer owner ended before its readiness response".into());
            }
        };
        assert_eq!(response, RESPONSE);

        drop(owner);
        let mut byte = [0_u8; 1];
        let closed = timeout(CONTROL_TIMEOUT, client.read(&mut byte)).await;
        let peer_closed = match &closed {
            Ok(Ok(0)) => true,
            Ok(Err(error)) => is_peer_gone(error),
            _ => false,
        };
        let destroyed_before_client_close = destruction.try_recv().is_ok();

        if !destroyed_before_client_close {
            // Reap the intentionally defective baseline before its assertion.
            client.shutdown().await?;
            drop(client);
            timeout(CONTROL_TIMEOUT, &mut destruction).await??;
        }

        assert!(
            peer_closed,
            "peer stayed open after owner cancellation: {closed:?}"
        );
        assert!(destroyed_before_client_close);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn a_completed_driven_peer_failure_keeps_its_original_type() -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut client = TcpStream::connect(listener.local_addr()?).await?;
        let (destroyed, destruction) = oneshot::channel();
        let peer = async move {
            let _destroyed = PeerDestroyed(Some(destroyed));
            let (mut stream, _) = listener.accept().await?;
            assert_eq!(read_head(&mut stream).await?, HEAD);
            stream.write_all(RESPONSE).await?;
            Err::<(), _>(Box::new(PeerFailure) as Box<dyn Error + Send + Sync>)
        };
        let owner = exchange_peer(peer, pending::<TestResult<()>>());
        client.write_all(HEAD).await?;

        let (result, response) =
            tokio::join!(timeout(CONTROL_TIMEOUT, owner), read_head(&mut client));
        assert_eq!(response?, RESPONSE);
        timeout(CONTROL_TIMEOUT, destruction).await??;

        let error: Box<dyn Error + Send + Sync> = match result {
            Ok(Err(error)) => error,
            Ok(Ok(_)) => return Err("failed peer was accepted".into()),
            Err(error) => Box::new(error),
        };
        assert!(error.downcast_ref::<PeerFailure>().is_some(), "{error}");
        Ok(())
    })
    .await?
}

#[tokio::test(start_paused = true)]
async fn an_expired_client_test_deadline_keeps_its_typed_cause() -> TestResult<()> {
    super::bounded(async { Ok(()) }).await?;
    let error = super::bounded(pending::<TestResult<()>>())
        .await
        .err()
        .ok_or("pending workflow completed")?;
    assert!(
        error
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some()
    );
    Ok(())
}

#[test]
fn failed_upload_accept_keeps_an_unexpected_typed_protocol_failure() -> TestResult<()> {
    let error = super::accepted_failed_upload::<()>(Some(Err(::http2::Error::from(
        ::http2::Reason::INTERNAL_ERROR,
    ))))
    .err()
    .ok_or("unexpected accept failure was discarded")?;
    let error = error
        .downcast_ref::<::http2::Error>()
        .ok_or("protocol cause lost")?;
    assert_eq!(error.reason(), Some(::http2::Reason::INTERNAL_ERROR));
    Ok(())
}

#[tokio::test]
async fn failed_upload_accept_allows_only_known_peer_disconnects() -> TestResult<()> {
    for kind in [
        io::ErrorKind::BrokenPipe,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::ConnectionAborted,
    ] {
        let error = observed_accept_io_failure(kind).await?;
        assert_eq!(
            error.get_io().ok_or("accept did not fail with I/O")?.kind(),
            kind
        );
        assert!(super::accepted_failed_upload::<()>(Some(Err(error)))?.is_none());
    }

    assert!(super::accepted_failed_upload::<()>(None)?.is_none());
    assert_eq!(super::accepted_failed_upload(Some(Ok(17)))?, Some(17));
    Ok(())
}

#[tokio::test]
async fn failed_upload_accept_keeps_unrelated_io_and_its_original_cause() -> TestResult<()> {
    let observed = observed_accept_io_failure(io::ErrorKind::InvalidData).await?;
    let error = super::accepted_failed_upload::<()>(Some(Err(observed)))
        .err()
        .ok_or("unrelated accept I/O failure was discarded")?;
    let cause = error
        .downcast_ref::<::http2::Error>()
        .ok_or("HTTP/2 I/O cause lost")?
        .get_io()
        .ok_or("original I/O error lost")?;
    assert_eq!(cause.kind(), io::ErrorKind::InvalidData);
    assert!(
        cause
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<PeerFailure>())
            .is_some()
    );
    Ok(())
}

struct AcceptReadFailure<'a> {
    stream: DuplexStream,
    armed: &'a Cell<bool>,
    failure: Option<io::Error>,
}

impl AsyncRead for AcceptReadFailure<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.armed.get() {
            if let Some(error) = self.failure.take() {
                return Poll::Ready(Err(error));
            }
        }

        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for AcceptReadFailure<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

async fn observed_accept_io_failure(kind: io::ErrorKind) -> TestResult<::http2::Error> {
    timeout(Duration::from_secs(10), async {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let armed = Cell::new(false);
        let server = AcceptReadFailure {
            stream: server,
            armed: &armed,
            failure: Some(io::Error::new(kind, PeerFailure)),
        };
        let handshake = async {
            Ok::<_, Box<dyn Error + Send + Sync>>(::http2::server::handshake(server).await?)
        };
        let preface = async {
            client
                .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
                .await?;
            super::write_h2_frame(&mut client, 0x4, 0, 0, &[]).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        let (mut connection, ()) = tokio::try_join!(handshake, preface)?;

        // Complete the real handshake before faulting the pending accept read.
        armed.set(true);
        let error = match connection.accept().await {
            Some(Err(error)) => error,
            Some(Ok(_)) => return Err("request accepted without HEADERS".into()),
            None => return Err("accept lost its injected I/O failure".into()),
        };
        assert!(error.is_io());
        Ok(error)
    })
    .await?
}

#[tokio::test]
async fn upload_end_accepts_a_real_cancel_reset() -> TestResult<()> {
    assert!(
        observed_upload_reset(::http2::Reason::CANCEL)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn upload_end_keeps_a_real_unexpected_reset_with_its_type() -> TestResult<()> {
    let error = observed_upload_reset(::http2::Reason::INTERNAL_ERROR)
        .await
        .err()
        .ok_or("unexpected upload reset was discarded")?;
    let cause = error
        .downcast_ref::<::http2::Error>()
        .ok_or("protocol cause lost")?;
    assert!(cause.is_reset());
    assert_eq!(cause.reason(), Some(::http2::Reason::INTERNAL_ERROR));
    Ok(())
}

async fn observed_upload_reset(reason: ::http2::Reason) -> TestResult<Option<bytes::Bytes>> {
    timeout(Duration::from_secs(10), async {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (accepted, acceptance) = oneshot::channel();
        let peer = async move {
            let mut connection = ::http2::server::handshake(server).await?;
            let (request, _respond) = connection
                .accept()
                .await
                .ok_or("request was not accepted")??;
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().path(), "/");
            accepted
                .send(())
                .map_err(|_| "reset sender stopped before acceptance")?;
            let mut body = request.into_body();
            let frame = super::next_h2_request_data(&mut connection, &mut body).await;
            super::upload_data_or_end(frame)
        };
        let sender = async {
            client
                .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
                .await?;
            super::write_h2_frame(&mut client, 0x4, 0, 0, &[]).await?;
            // Literal HPACK: POST, http, /, then authority without indexing.
            super::write_h2_frame(
                &mut client,
                0x1,
                0x4,
                1,
                b"\x83\x86\x84\x01\x0dloopback.test",
            )
            .await?;
            acceptance.await?;
            super::write_h2_frame(&mut client, 0x3, 0, 1, &u32::from(reason).to_be_bytes()).await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        };

        let (result, ()) = tokio::try_join!(peer, sender)?;
        Ok(result)
    })
    .await?
}
