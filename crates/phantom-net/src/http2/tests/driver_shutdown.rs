use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::Response;
use http_body::Body as _;
use phantom_profile::browser::chrome::v154_http2;
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, duplex},
    runtime::Builder,
    sync::{Notify, oneshot},
    task::{AbortHandle, JoinError, JoinHandle},
    time::timeout,
};
use tracing::instrument::WithSubscriber;

use super::{PeerDeadline, TestResult, bounded_peer_test, next_nonempty_data, send_once, target};
use crate::http2::PreparedRequest;
use crate::tracing_test::OutcomeSubscriber;
use crate::{http2::driver::DRIVER_SHUTDOWN_GRACE, shutdown_timer};

#[test]
fn body_drop_after_originating_runtime_shutdown_records_driver_outcome() -> TestResult<()> {
    let subscriber = OutcomeSubscriber::default();
    let runtime = Builder::new_current_thread().enable_time().build()?;
    let body = runtime.block_on(
        async {
            // Keep the stream terminal so this isolates supervisor cancellation
            // from the vendored codec's cleanup of abandoned live streams.
            let control = WriteControl::default();
            let (client, server) = duplex(64 * 1024);
            let _server_task = tokio::spawn(terminal_headers_server(server, control.clone()));
            let response = send_once(
                BlockingWrites {
                    inner: client,
                    control,
                },
                {
                    let settings = v154_http2();
                    let method = http::Method::GET;
                    let authority = "example.test";
                    let target = target()?;
                    let headers = vec![];
                    let body = None;
                    move || {
                        PreparedRequest::new(&settings, method, authority, target, headers, body)
                    }
                },
            )
            .await?;
            let body = response.into_body();
            assert!(body.is_end_stream());
            Ok::<_, Box<dyn Error + Send + Sync>>(body)
        }
        .with_subscriber(subscriber.clone()),
    )?;

    drop(runtime);
    drop(body);

    assert_eq!(
        subscriber.outcomes_for("http2.connection_driver"),
        ["runtime_shutdown"]
    );
    Ok(())
}

#[test]
fn body_shutdown_completes_without_a_tokio_time_driver() -> TestResult<()> {
    let subscriber = OutcomeSubscriber::default();
    let runtime = Builder::new_current_thread().build()?;
    runtime.block_on(before_deadline(
        async {
            let (client, server) = duplex(64 * 1024);
            let server_task = ShutdownPeer::spawn(terminal_response_server(server));
            let response = send_once(client, {
                let settings = v154_http2();
                let method = http::Method::GET;
                let authority = "example.test";
                let target = target()?;
                let headers = vec![];
                let body = None;
                move || PreparedRequest::new(&settings, method, authority, target, headers, body)
            })
            .await?;
            let body = response.into_body();
            assert!(body.is_end_stream());
            drop(body);
            server_task.await??;
            wait_for_driver_observation(&subscriber, "complete").await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }
        .with_subscriber(subscriber.clone()),
        Duration::from_secs(5),
    ))?
}

#[test]
fn stalled_driver_times_out_without_a_tokio_time_driver() -> TestResult<()> {
    let subscriber = OutcomeSubscriber::default();
    let runtime = Builder::new_current_thread().build()?;
    runtime.block_on(before_deadline(
        async {
            let control = WriteControl::default();
            let (client, server) = duplex(64 * 1024);
            let server_task = ShutdownPeer::spawn(stalled_close_server(server));
            let result = async {
                let response = send_once(
                    BlockingWrites {
                        inner: client,
                        control: control.clone(),
                    },
                    {
                        let settings = v154_http2();
                        let method = http::Method::GET;
                        let authority = "example.test";
                        let target = target()?;
                        let headers = vec![];
                        let body = None;
                        move || {
                            PreparedRequest::new(
                                &settings, method, authority, target, headers, body,
                            )
                        }
                    },
                )
                .await?;
                let mut body = response.into_body();
                assert_eq!(next_nonempty_data(&mut body).await?, "partial");

                control.blocked.store(true, Ordering::SeqCst);
                drop(body);
                let dropped = control.dropped_notify.notified();
                if !control.dropped.load(Ordering::SeqCst) {
                    dropped.await;
                }
                assert!(control.dropped.load(Ordering::SeqCst));
                wait_for_driver_observation(&subscriber, "timeout").await?;

                Ok::<_, Box<dyn Error + Send + Sync>>(())
            }
            .await;
            server_task.finish_after(result).await
        }
        .with_subscriber(subscriber.clone()),
        Duration::from_secs(5),
    ))?
}

#[tokio::test]
async fn stalled_connection_driver_is_aborted_after_shutdown_grace() -> TestResult<()> {
    bounded_peer_test(async {
        let control = WriteControl::default();
        let subscriber = OutcomeSubscriber::default();
        let (client, server) = duplex(64 * 1024);
        let server_task = ShutdownPeer::spawn(stalled_close_server(server));

        let result = async {
            let response = send_once(
                BlockingWrites {
                    inner: client,
                    control: control.clone(),
                },
                {
                    let settings = v154_http2();
                    let method = http::Method::GET;
                    let authority = "example.test";
                    let target = target()?;
                    let headers = vec![];
                    let body = None;
                    move || {
                        PreparedRequest::new(&settings, method, authority, target, headers, body)
                    }
                },
            )
            .await?;
            let mut body = response.into_body();
            assert_eq!(next_nonempty_data(&mut body).await?, "partial");

            control.blocked.store(true, Ordering::SeqCst);
            drop(body);
            let dropped = control.dropped_notify.notified();
            if !control.dropped.load(Ordering::SeqCst) {
                timeout(DRIVER_SHUTDOWN_GRACE + Duration::from_secs(1), dropped)
                    .await
                    .map_err(|cause| PeerDeadline {
                        context: "stalled HTTP/2 transport was not dropped after grace",
                        cause,
                    })?;
            }
            timeout(Duration::from_secs(1), async {
                while subscriber.outcomes_for("http2.connection_driver") != ["timeout"] {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .map_err(|cause| PeerDeadline {
                context: "driver timeout outcome was not recorded",
                cause,
            })?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }
        .with_subscriber(subscriber.clone())
        .await;

        server_task.finish_after(result).await?;
        assert!(control.dropped.load(Ordering::SeqCst));
        Ok(())
    })
    .await
}

pub(super) async fn terminal_headers_server<S>(stream: S, control: WriteControl) -> TestResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before request")??;
    let response = Response::builder().status(204).body(())?;
    respond.send_response(response, true)?;
    control.blocked.store(true, Ordering::SeqCst);
    drop(request);
    drop(respond);

    match connection.accept().await {
        None => Ok(()),
        Some(Ok(_)) => Err("one-shot client sent an unexpected second request".into()),
        Some(Err(error)) => Err(error.into()),
    }
}

async fn stalled_close_server(stream: DuplexStream) -> TestResult<()> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (_request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before request")??;
    let mut send = respond.send_response(Response::builder().status(200).body(())?, false)?;
    send.send_data(Bytes::from_static(b"partial"), false)?;

    // The client deliberately blocks all writes, including RESET. Only transport
    // closure can complete this peer after the driver's shutdown grace expires.
    let result = match connection.accept().await {
        None => Ok(()),
        Some(Ok(_)) => Err("one-shot client sent an unexpected second request".into()),
        Some(Err(error))
            if error.get_io().is_some_and(|cause| {
                matches!(
                    cause.kind(),
                    io::ErrorKind::BrokenPipe
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                )
            }) =>
        {
            Ok(())
        }
        Some(Err(error)) => Err(error.into()),
    };
    drop(send);
    result
}

async fn terminal_response_server(stream: DuplexStream) -> TestResult<()> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before request")??;
    respond.send_response(Response::builder().status(204).body(())?, true)?;
    drop(request);
    drop(respond);
    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok(())
}

async fn wait_for_driver_observation(
    subscriber: &OutcomeSubscriber,
    expected_outcome: &str,
) -> TestResult<()> {
    let event = subscriber.connection_driver_event();
    if subscriber.outcomes_for("http2.connection_driver") != [expected_outcome]
        || subscriber.connection_driver_events() != 1
    {
        event.await;
    }
    assert_eq!(
        subscriber.outcomes_for("http2.connection_driver"),
        [expected_outcome]
    );
    assert_eq!(subscriber.connection_driver_events(), 1);
    Ok(())
}

pub(super) async fn before_deadline<F>(future: F, duration: Duration) -> TestResult<F::Output>
where
    F: Future,
{
    let deadline = shutdown_timer::after(duration).map_err(|cause| ScheduleFailure { cause })?;
    poll_before_deadline(future, deadline).await
}

pub(super) async fn poll_before_deadline<F>(
    future: F,
    mut deadline: oneshot::Receiver<()>,
) -> TestResult<F::Output>
where
    F: Future,
{
    let mut future = Box::pin(future);
    poll_fn(|context| {
        if let Poll::Ready(output) = future.as_mut().poll(context) {
            return Poll::Ready(Ok(output));
        }
        match Pin::new(&mut deadline).poll(context) {
            Poll::Ready(Ok(())) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "operation exceeded its deadline",
            )
            .into())),
            Poll::Ready(Err(cause)) => Poll::Ready(Err(StoppedTimer { cause }.into())),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

#[derive(Debug)]
struct StoppedTimer {
    cause: oneshot::error::RecvError,
}

impl fmt::Display for StoppedTimer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "HTTP/2 shutdown timer service stopped: {}",
            self.cause
        )
    }
}

impl Error for StoppedTimer {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.cause)
    }
}

#[derive(Debug)]
struct ShutdownFailures {
    primary: Box<dyn Error + Send + Sync>,
    cleanup: Box<dyn Error + Send + Sync>,
}

impl fmt::Display for ShutdownFailures {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; shutdown peer cleanup also failed: {}",
            self.primary, self.cleanup
        )
    }
}

impl Error for ShutdownFailures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.primary.as_ref())
    }
}

#[derive(Debug)]
pub(super) struct ScheduleFailure {
    pub(super) cause: shutdown_timer::ScheduleError,
}

impl fmt::Display for ScheduleFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "HTTP/2 shutdown timer service was unavailable: {:?}",
            self.cause
        )
    }
}

impl Error for ScheduleFailure {}

pub(super) struct ShutdownPeer<T> {
    task: JoinHandle<TestResult<T>>,
}

impl<T: Send + 'static> ShutdownPeer<T> {
    pub(super) fn spawn(future: impl Future<Output = TestResult<T>> + Send + 'static) -> Self {
        Self::from_handle(tokio::spawn(future))
    }

    pub(super) fn from_handle(task: JoinHandle<TestResult<T>>) -> Self {
        Self { task }
    }

    pub(super) fn abort_handle(&self) -> AbortHandle {
        self.task.abort_handle()
    }

    pub(super) fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    pub(super) async fn stop(mut self) -> TestResult<()> {
        self.task.abort();
        match before_deadline(&mut self, Duration::from_secs(5)).await? {
            Ok(result) => result.map(drop),
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    async fn finish_after(mut self, primary: TestResult<()>) -> TestResult<()> {
        let cleanup = if primary.is_ok() {
            match before_deadline(&mut self, Duration::from_secs(5)).await {
                Ok(Ok(result)) => result.map(drop),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error),
            }
        } else {
            self.stop().await
        };

        match (primary, cleanup) {
            (Ok(()), result) | (result, Ok(())) => result,
            (Err(primary), Err(cleanup)) => Err(ShutdownFailures { primary, cleanup }.into()),
        }
    }
}

impl<T: Send + 'static> From<JoinHandle<TestResult<T>>> for ShutdownPeer<T> {
    fn from(task: JoinHandle<TestResult<T>>) -> Self {
        Self::from_handle(task)
    }
}

impl<T> Drop for ShutdownPeer<T> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl<T> Future for ShutdownPeer<T> {
    type Output = Result<TestResult<T>, JoinError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.get_mut().task).poll(context)
    }
}

#[derive(Clone, Default)]
pub(super) struct WriteControl {
    blocked: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
    dropped_notify: Arc<Notify>,
}

struct BlockingWrites {
    inner: DuplexStream,
    control: WriteControl,
}

impl AsyncRead for BlockingWrites {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for BlockingWrites {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if self.control.blocked.load(Ordering::SeqCst) {
            Poll::Pending
        } else {
            Pin::new(&mut self.inner).poll_write(context, buffer)
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if self.control.blocked.load(Ordering::SeqCst) {
            Poll::Pending
        } else {
            Pin::new(&mut self.inner).poll_flush(context)
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if self.control.blocked.load(Ordering::SeqCst) {
            Poll::Pending
        } else {
            Pin::new(&mut self.inner).poll_shutdown(context)
        }
    }
}

impl Drop for BlockingWrites {
    fn drop(&mut self) {
        self.control.dropped.store(true, Ordering::SeqCst);
        self.control.dropped_notify.notify_one();
    }
}
