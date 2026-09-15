use std::{
    error::Error,
    future::{Future, poll_fn},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use http::Response;
use http_body::Body as _;
use phantom_profile::chromium::v152_macos_http2;
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, duplex},
    runtime::Builder,
    sync::Notify,
    time::timeout,
};
use tracing::instrument::WithSubscriber;

use super::{TestResult, bounded_peer_test, next_nonempty_data, reset_observing_server, target};
use crate::http2::{body::DRIVER_SHUTDOWN_GRACE, send_get, shutdown_timer};
use crate::tracing_test::OutcomeSubscriber;

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
            let response = send_get(
                BlockingWrites {
                    inner: client,
                    control,
                },
                &v152_macos_http2(),
                "example.test",
                target()?,
                vec![],
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
    runtime.block_on(
        async {
            let (client, server) = duplex(64 * 1024);
            let server_task = tokio::spawn(terminal_response_server(server));
            let response = send_get(
                client,
                &v152_macos_http2(),
                "example.test",
                target()?,
                vec![],
            )
            .await?;
            let body = response.into_body();
            assert!(body.is_end_stream());
            drop(body);
            before_deadline(server_task, Duration::from_secs(2)).await???;
            wait_for_driver_observation(&subscriber, "complete").await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }
        .with_subscriber(subscriber.clone()),
    )
}

#[test]
fn stalled_driver_times_out_without_a_tokio_time_driver() -> TestResult<()> {
    let subscriber = OutcomeSubscriber::default();
    let runtime = Builder::new_current_thread().build()?;
    runtime.block_on(
        async {
            let control = WriteControl::default();
            let (client, server) = duplex(64 * 1024);
            let server_task = tokio::spawn(reset_observing_server(server));
            let response = send_get(
                BlockingWrites {
                    inner: client,
                    control: control.clone(),
                },
                &v152_macos_http2(),
                "example.test",
                target()?,
                vec![],
            )
            .await?;
            let mut body = response.into_body();
            assert_eq!(next_nonempty_data(&mut body).await?, "partial");

            control.blocked.store(true, Ordering::SeqCst);
            drop(body);
            let dropped = control.dropped_notify.notified();
            if !control.dropped.load(Ordering::SeqCst) {
                before_deadline(dropped, DRIVER_SHUTDOWN_GRACE + Duration::from_secs(1)).await?;
            }
            wait_for_driver_observation(&subscriber, "timeout").await?;

            server_task.abort();
            let _ = server_task.await;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }
        .with_subscriber(subscriber.clone()),
    )
}

#[tokio::test]
async fn stalled_connection_driver_is_aborted_after_shutdown_grace() -> TestResult<()> {
    bounded_peer_test(async {
        let control = WriteControl::default();
        let subscriber = OutcomeSubscriber::default();
        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(reset_observing_server(server));

        async {
            let response = send_get(
                BlockingWrites {
                    inner: client,
                    control: control.clone(),
                },
                &v152_macos_http2(),
                "example.test",
                target()?,
                vec![],
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
                    .map_err(|_| "stalled HTTP/2 transport was not dropped after grace")?;
            }
            timeout(Duration::from_secs(1), async {
                while subscriber.outcomes_for("http2.connection_driver") != ["timeout"] {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .map_err(|_| "driver timeout outcome was not recorded")?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }
        .with_subscriber(subscriber.clone())
        .await?;

        server_task.abort();
        let _ = server_task.await;
        assert!(control.dropped.load(Ordering::SeqCst));
        Ok(())
    })
    .await
}

async fn terminal_headers_server(stream: DuplexStream, control: WriteControl) -> TestResult<()> {
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

    if connection.accept().await.is_some() {
        return Err("one-shot client sent an unexpected second request".into());
    }
    Ok(())
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
        before_deadline(event, Duration::from_secs(2)).await?;
    }
    assert_eq!(
        subscriber.outcomes_for("http2.connection_driver"),
        [expected_outcome]
    );
    assert_eq!(subscriber.connection_driver_events(), 1);
    Ok(())
}

async fn before_deadline<F>(future: F, duration: Duration) -> TestResult<F::Output>
where
    F: Future,
{
    let mut future = Box::pin(future);
    let mut deadline = shutdown_timer::after(duration)
        .map_err(|_| "HTTP/2 shutdown timer service was unavailable")?;
    poll_fn(|context| {
        if let Poll::Ready(output) = future.as_mut().poll(context) {
            return Poll::Ready(Ok(output));
        }
        match Pin::new(&mut deadline).poll(context) {
            Poll::Ready(Ok(())) => Poll::Ready(Err("operation exceeded its deadline".into())),
            Poll::Ready(Err(_)) => Poll::Ready(Err("HTTP/2 shutdown timer service stopped".into())),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

#[derive(Clone, Default)]
struct WriteControl {
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
