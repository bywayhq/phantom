use std::{
    error::Error,
    fmt,
    future::{pending, poll_fn},
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::{Request, StatusCode};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, duplex},
    runtime::Builder,
    sync::oneshot,
    task::{AbortHandle, JoinSet},
    time::timeout,
};

use super::driver_shutdown::{
    ScheduleFailure, ShutdownPeer, WriteControl, before_deadline, poll_before_deadline,
    terminal_headers_server,
};
use super::{TestResult, bounded_peer_test, reset_observing_server};

const DEADLINE: Duration = Duration::from_secs(2);
const CLOSE_WINDOW: Duration = Duration::from_millis(100);

#[tokio::test]
async fn an_early_fixture_error_closes_its_ready_h2_peer() -> TestResult<()> {
    let (client, stream, mut dropped, _fault) = observed_pair();
    let peer = ShutdownPeer::spawn(reset_observing_server(stream));
    let _backup = AbortPeerOnDrop(peer.abort_handle());
    let abort = peer.abort_handle();
    let client = LiveClient::ready(client, StatusCode::OK, b"partial").await?;

    let result: TestResult<()> = async move {
        let _peer = peer;
        Err(io::Error::new(io::ErrorKind::InvalidInput, "injected owner failure 614").into())
    }
    .await;
    let closed = timeout(CLOSE_WINDOW, &mut dropped).await;
    abort.abort();
    if closed.is_err() {
        timeout(DEADLINE, dropped).await??;
    }
    let cleanup = client.finish().await;
    cleanup?;

    let error = result.err().ok_or("owner failure was lost")?;
    assert_eq!(
        cause::<io::Error>(error.as_ref())
            .ok_or("missing owner cause")?
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert!(
        matches!(closed, Ok(Ok(()))),
        "peer survived its owner's early error during the finite window"
    );
    Ok(())
}

#[tokio::test]
async fn cancelling_fixture_owner_closes_its_ready_h2_peer() -> TestResult<()> {
    let (client, stream, mut dropped, _fault) = observed_pair();
    let peer = ShutdownPeer::spawn(reset_observing_server(stream));
    let _backup = AbortPeerOnDrop(peer.abort_handle());
    let abort = peer.abort_handle();
    let client = LiveClient::ready(client, StatusCode::OK, b"partial").await?;
    let (ready, owned) = oneshot::channel();
    let mut owners = JoinSet::new();
    owners.spawn(async move {
        let _peer = peer;
        ready
            .send(())
            .map_err(|_| "owner readiness receiver closed")?;
        pending::<TestResult<()>>().await
    });
    timeout(DEADLINE, owned).await??;

    owners.abort_all();
    let joined = timeout(DEADLINE, owners.join_next())
        .await?
        .ok_or("missing cancelled owner")?;
    let closed = timeout(CLOSE_WINDOW, &mut dropped).await;
    abort.abort();
    if closed.is_err() {
        timeout(DEADLINE, dropped).await??;
    }
    let cleanup = client.finish().await;

    assert!(matches!(joined, Err(ref error) if error.is_cancelled()));
    cleanup?;
    assert!(
        matches!(closed, Ok(Ok(()))),
        "peer survived owner cancellation during the finite window"
    );
    Ok(())
}

#[tokio::test]
async fn explicit_peer_stop_observes_transport_drop_after_partial_data() -> TestResult<()> {
    let (client, stream, dropped, _fault) = observed_pair();
    let peer = ShutdownPeer::spawn(reset_observing_server(stream));
    let _backup = AbortPeerOnDrop(peer.abort_handle());
    let client = LiveClient::ready(client, StatusCode::OK, b"partial").await?;

    timeout(DEADLINE, peer.stop()).await??;
    timeout(DEADLINE, dropped).await??;
    client.finish().await?;
    Ok(())
}

#[tokio::test]
async fn stopping_a_completed_peer_preserves_its_typed_failure() -> TestResult<()> {
    let (client, stream, dropped, _fault) = observed_pair();
    let (fail, failing) = oneshot::channel();
    let peer = ShutdownPeer::spawn(partial_then_failure(stream, failing));
    let _backup = AbortPeerOnDrop(peer.abort_handle());
    let client = LiveClient::ready(client, StatusCode::OK, b"partial").await?;

    fail.send(())
        .map_err(|_| "late failure peer ended before signal")?;
    timeout(DEADLINE, async {
        while !peer.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let result = timeout(DEADLINE, peer.stop()).await?;
    timeout(DEADLINE, dropped).await??;
    let cleanup = client.finish().await;
    cleanup?;

    let error = result.err().ok_or("completed peer failure was discarded")?;
    let original = cause::<io::Error>(error.as_ref()).ok_or("missing original peer IO error")?;
    assert_eq!(original.kind(), io::ErrorKind::PermissionDenied);
    assert!(
        original
            .get_ref()
            .is_some_and(|error| error.is::<LatePeerFailure>())
    );
    Ok(())
}

#[tokio::test]
async fn reset_observer_keeps_transport_error_after_literal_partial_data() -> TestResult<()> {
    let (client, stream, dropped, fault) = observed_pair();
    let peer = ShutdownPeer::spawn(reset_observing_server(stream));
    let _backup = AbortPeerOnDrop(peer.abort_handle());
    let client = LiveClient::ready(client, StatusCode::OK, b"partial").await?;

    fault
        .send(())
        .map_err(|_| "fault peer ended before signal")?;
    let joined = timeout(DEADLINE, peer).await?;
    timeout(DEADLINE, dropped).await??;
    let cleanup = client.finish().await;
    cleanup?;
    let error = joined?
        .err()
        .ok_or("fault was accepted as a stream reset")?;
    assert_transport_cause(error.as_ref())?;
    Ok(())
}

#[tokio::test]
async fn terminal_header_observer_keeps_transport_error_after_204() -> TestResult<()> {
    let (client, stream, dropped, fault) = observed_pair();
    let peer = ShutdownPeer::spawn(terminal_headers_server(stream, WriteControl::default()));
    let _backup = AbortPeerOnDrop(peer.abort_handle());
    let client = LiveClient::ready(client, StatusCode::NO_CONTENT, b"").await?;

    fault
        .send(())
        .map_err(|_| "fault peer ended before signal")?;
    let joined = timeout(DEADLINE, peer).await?;
    timeout(DEADLINE, dropped).await??;
    let cleanup = client.finish().await;
    cleanup?;
    let error = joined?
        .err()
        .ok_or("fault was accepted as clean connection closure")?;
    assert_transport_cause(error.as_ref())?;
    Ok(())
}

#[tokio::test]
async fn reset_observer_records_an_actual_remote_cancel() -> TestResult<()> {
    let (client, stream, dropped, _fault) = observed_pair();
    let peer = ShutdownPeer::spawn(reset_observing_server(stream));
    let _backup = AbortPeerOnDrop(peer.abort_handle());
    let mut client = LiveClient::ready(client, StatusCode::OK, b"partial").await?;

    client.send.send_reset(::http2::Reason::CANCEL);
    drop(client.body);
    drop(client.requests);
    drop(client.send);
    let (reason, observed) = timeout(DEADLINE, peer).await???;
    assert_eq!(reason, ::http2::Reason::CANCEL);
    assert!(observed);
    timeout(DEADLINE, dropped).await??;
    finish_driver(&mut client.drivers).await?;
    Ok(())
}

#[tokio::test]
async fn forced_transport_close_does_not_claim_an_observed_reset() -> TestResult<()> {
    let (client, stream, dropped, _fault) = observed_pair();
    let peer = ShutdownPeer::spawn(reset_observing_server(stream));
    let _backup = AbortPeerOnDrop(peer.abort_handle());
    let mut client = LiveClient::ready(client, StatusCode::OK, b"partial").await?;

    client.drivers.abort_all();
    let driver = timeout(DEADLINE, client.drivers.join_next())
        .await?
        .ok_or("missing stopped driver")?;
    assert!(matches!(driver, Err(ref error) if error.is_cancelled()));
    let joined = timeout(DEADLINE, peer).await?;
    timeout(DEADLINE, dropped).await??;
    let error = joined?
        .err()
        .ok_or("forced close was claimed as a stream reset")?;
    assert!(
        error.to_string() == "connection closed without an observable stream reset"
            || cause::<::http2::Error>(error.as_ref()).is_some_and(is_disconnect)
    );
    Ok(())
}

#[tokio::test]
async fn peer_test_deadline_retains_tokio_elapsed() -> TestResult<()> {
    let error = bounded_peer_test(pending())
        .await
        .err()
        .ok_or("pending peer test completed")?;
    assert!(
        cause::<tokio::time::error::Elapsed>(error.as_ref()).is_some(),
        "original Elapsed was lost"
    );
    Ok(())
}

#[test]
fn runtime_neutral_expiry_has_a_typed_timeout_without_time_driver() -> TestResult<()> {
    let runtime = Builder::new_current_thread().build()?;
    let error = runtime
        .block_on(before_deadline(pending::<()>(), Duration::ZERO))
        .err()
        .ok_or("pending operation completed")?;
    assert_eq!(
        cause::<io::Error>(error.as_ref())
            .ok_or("missing typed local deadline")?
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert!(cause::<tokio::time::error::Elapsed>(error.as_ref()).is_none());
    Ok(())
}

#[test]
fn unrepresentable_deadline_keeps_concrete_schedule_failure() -> TestResult<()> {
    let runtime = Builder::new_current_thread().build()?;
    let error = runtime
        .block_on(before_deadline(pending::<()>(), Duration::MAX))
        .err()
        .ok_or("unrepresentable deadline was scheduled")?;
    let failure =
        cause::<ScheduleFailure>(error.as_ref()).ok_or("concrete ScheduleError value was lost")?;
    let _: crate::shutdown_timer::ScheduleError = failure.cause;
    Ok(())
}

#[test]
fn stopped_deadline_receiver_retains_original_recv_error() -> TestResult<()> {
    let runtime = Builder::new_current_thread().build()?;
    let (signal, receiver) = oneshot::channel();
    drop(signal);
    let error = runtime
        .block_on(poll_before_deadline(pending::<()>(), receiver))
        .err()
        .ok_or("stopped service completed the pending operation")?;
    assert!(
        cause::<oneshot::error::RecvError>(error.as_ref()).is_some(),
        "original RecvError was lost"
    );
    Ok(())
}

#[test]
fn ready_operation_finishes_without_a_tokio_time_driver() -> TestResult<()> {
    let runtime = Builder::new_current_thread().build()?;
    assert_eq!(
        runtime.block_on(before_deadline(async { 73_u8 }, DEADLINE))?,
        73
    );
    Ok(())
}

fn cause<'a, T: Error + 'static>(mut error: &'a (dyn Error + 'static)) -> Option<&'a T> {
    loop {
        if let Some(cause) = error.downcast_ref::<T>() {
            return Some(cause);
        }
        error = error.source()?;
    }
}

fn assert_transport_cause(error: &(dyn Error + 'static)) -> TestResult<()> {
    let error =
        cause::<::http2::Error>(error).ok_or("original H2 transport cause was misclassified")?;
    let io = error.get_io().ok_or("missing H2 IO error")?;
    assert_eq!(io.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(io.to_string(), "injected shutdown peer transport fault 613");
    Ok(())
}

fn is_disconnect(error: &::http2::Error) -> bool {
    error.get_io().is_some_and(|error| {
        matches!(
            error.kind(),
            io::ErrorKind::BrokenPipe
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
        )
    })
}

struct AbortPeerOnDrop(AbortHandle);

impl Drop for AbortPeerOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct LiveClient {
    requests: ::http2::client::SendRequest<Bytes>,
    send: ::http2::SendStream<Bytes>,
    body: ::http2::RecvStream,
    drivers: JoinSet<TestResult<()>>,
}

impl LiveClient {
    async fn ready(stream: DuplexStream, status: StatusCode, literal: &[u8]) -> TestResult<Self> {
        let (mut requests, connection) =
            timeout(DEADLINE, ::http2::client::handshake(stream)).await??;
        let mut drivers = JoinSet::new();
        drivers.spawn(async move {
            connection.await?;
            TestResult::Ok(())
        });

        timeout(DEADLINE, poll_fn(|context| requests.poll_ready(context))).await??;
        let (response, send) = requests.send_request(
            Request::builder()
                .uri("https://example.test/resource")
                .body(())?,
            true,
        )?;

        let response = timeout(DEADLINE, response).await??;
        assert_eq!(response.status(), status);
        let mut body = response.into_body();
        if literal.is_empty() {
            assert!(body.is_end_stream());
        } else {
            let data = timeout(DEADLINE, body.data())
                .await?
                .ok_or("response ended before literal DATA")??;
            body.flow_control().release_capacity(data.len())?;
            assert_eq!(data.as_ref(), literal);
        }

        Ok(Self {
            requests,
            send,
            body,
            drivers,
        })
    }

    async fn finish(mut self) -> TestResult<()> {
        drop(self.body);
        drop(self.requests);
        drop(self.send);
        finish_driver(&mut self.drivers).await
    }
}

async fn finish_driver(drivers: &mut JoinSet<TestResult<()>>) -> TestResult<()> {
    match timeout(DEADLINE, drivers.join_next())
        .await?
        .ok_or("missing client driver")?
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) if cause::<::http2::Error>(error.as_ref()).is_some_and(is_disconnect) => {
            Ok(())
        }
        Ok(Err(error)) => Err(error),
        Err(error) => Err(error.into()),
    }
}

async fn partial_then_failure(
    stream: ObservedStream,
    fail: oneshot::Receiver<()>,
) -> TestResult<()> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (_, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before request")??;
    let mut send = respond.send_response(http::Response::new(()), false)?;
    send.send_data(Bytes::from_static(b"partial"), false)?;

    tokio::select! {
        signal = fail => {
            signal?;
            Err(io::Error::new(io::ErrorKind::PermissionDenied, LatePeerFailure).into())
        }
        accepted = connection.accept() => match accepted {
            Some(Err(error)) => Err(error.into()),
            _ => Err("late-failure control lost its ready connection".into()),
        }
    }
}

fn observed_pair() -> (
    DuplexStream,
    ObservedStream,
    oneshot::Receiver<()>,
    oneshot::Sender<()>,
) {
    let (client, inner) = duplex(16 * 1024);
    let (dropped, closed) = oneshot::channel();
    let (fault, faulted) = oneshot::channel();
    (
        client,
        ObservedStream {
            inner,
            dropped: Some(dropped),
            fault: Some(faulted),
            failed: false,
        },
        closed,
        fault,
    )
}

struct ObservedStream {
    inner: DuplexStream,
    dropped: Option<oneshot::Sender<()>>,
    fault: Option<oneshot::Receiver<()>>,
    failed: bool,
}

impl Drop for ObservedStream {
    fn drop(&mut self) {
        if let Some(dropped) = self.dropped.take() {
            let _ = dropped.send(());
        }
    }
}

impl AsyncRead for ObservedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(fault) = &mut self.fault {
            match Pin::new(fault).poll(context) {
                Poll::Ready(Ok(())) => {
                    self.fault = None;
                    self.failed = true;
                }
                Poll::Ready(Err(_)) => {
                    self.fault = None;
                }
                Poll::Pending => {}
            }
        }
        if self.failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                TransportFault,
            )));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for ObservedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[derive(Debug)]
struct TransportFault;

impl fmt::Display for TransportFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected shutdown peer transport fault 613")
    }
}

impl Error for TransportFault {}

#[derive(Debug)]
struct LatePeerFailure;

impl fmt::Display for LatePeerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected completed peer failure 615")
    }
}

impl Error for LatePeerFailure {}
