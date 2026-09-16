//! Connection-driver lifecycle for one-shot HTTP/2 transactions.

use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::Poll,
    time::Duration,
};

use ::http2::client;
use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    runtime::Handle,
    task::{JoinError, JoinHandle},
};
use tracing::{
    Dispatch, Instrument, Span, debug, debug_span, dispatcher, field, instrument::WithSubscriber,
    warn,
};

use crate::shutdown_timer;

pub(super) const DRIVER_SHUTDOWN_GRACE: Duration = Duration::from_secs(1);

/// Owns the HTTP/2 connection driver and the last request sender.
///
/// Dropping the sender asks the connection task to shut down. A supervisor
/// gives the task a fixed grace period to flush pending protocol frames, then
/// aborts a permanently stalled driver.
pub(super) struct DriverTask {
    sender: Option<client::SendRequest<Bytes>>,
    handle: Option<JoinHandle<Result<(), ::http2::Error>>>,
    runtime: Handle,
    dispatch: Dispatch,
    span: Span,
}

impl DriverTask {
    pub(super) fn spawn<T>(
        connection: client::Connection<T, Bytes>,
        sender: client::SendRequest<Bytes>,
    ) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let runtime = Handle::current();
        let dispatch = dispatcher::get_default(Clone::clone);
        let span = debug_span!("http2.connection_driver", outcome = field::Empty);
        let handle = runtime.spawn(
            connection
                .instrument(span.clone())
                .with_subscriber(dispatch.clone()),
        );
        Self {
            sender: Some(sender),
            handle: Some(handle),
            runtime,
            dispatch,
            span,
        }
    }

    pub(super) async fn ready(&mut self) -> Result<(), ::http2::Error> {
        let sender = self
            .sender
            .take()
            .ok_or_else(|| ::http2::Error::from(::http2::Reason::INTERNAL_ERROR))?;
        self.sender = Some(sender.ready().await?);
        Ok(())
    }

    pub(super) fn sender_mut(&mut self) -> Result<&mut client::SendRequest<Bytes>, ::http2::Error> {
        self.sender
            .as_mut()
            .ok_or_else(|| ::http2::Error::from(::http2::Reason::INTERNAL_ERROR))
    }

    pub(super) fn shutdown(&mut self) {
        self.sender.take();
        let Some(handle) = self.handle.take() else {
            return;
        };
        let mut driver = AbortDriver::new(handle);
        let span = self.span.clone();
        let outcome = DriverOutcome::new(&span);
        let dispatch = self.dispatch.clone();
        self.runtime.spawn(
            async move {
                let result = wait_for_driver(&mut driver).await;
                match result {
                    DriverShutdown::Finished(Ok(Ok(()))) => {
                        outcome.finish("complete");
                        debug!(parent: &span, "HTTP/2 connection driver stopped");
                    }
                    DriverShutdown::Finished(Ok(Err(error))) => {
                        outcome.finish("protocol_error");
                        warn!(
                            parent: &span,
                            reason = ?error.reason(),
                            io_error = error.is_io(),
                            "HTTP/2 connection driver failed"
                        );
                    }
                    DriverShutdown::Finished(Err(error)) => {
                        outcome.finish("task_error");
                        warn!(
                            parent: &span,
                            cancelled = error.is_cancelled(),
                            panicked = error.is_panic(),
                            "HTTP/2 connection driver task failed"
                        );
                    }
                    DriverShutdown::TimedOut => {
                        driver.abort();
                        outcome.finish("timeout");
                        warn!(parent: &span, "HTTP/2 connection driver exceeded shutdown grace");
                    }
                    DriverShutdown::TimerFailed => {
                        driver.abort();
                        outcome.finish("task_error");
                        warn!(parent: &span, "HTTP/2 shutdown timer service failed");
                    }
                }
            }
            .with_subscriber(dispatch),
        );
    }
}

type DriverResult = Result<Result<(), ::http2::Error>, JoinError>;

enum DriverShutdown {
    Finished(DriverResult),
    TimedOut,
    TimerFailed,
}

async fn wait_for_driver(driver: &mut AbortDriver) -> DriverShutdown {
    let Ok(mut deadline) = shutdown_timer::after(DRIVER_SHUTDOWN_GRACE) else {
        return DriverShutdown::TimerFailed;
    };
    poll_fn(|context| {
        if let Poll::Ready(result) = Pin::new(driver.handle_mut()).poll(context) {
            return Poll::Ready(DriverShutdown::Finished(result));
        }
        match Pin::new(&mut deadline).poll(context) {
            Poll::Ready(Ok(())) => return Poll::Ready(DriverShutdown::TimedOut),
            Poll::Ready(Err(_)) => return Poll::Ready(DriverShutdown::TimerFailed),
            Poll::Pending => {}
        }
        Poll::Pending
    })
    .await
}

struct DriverOutcome {
    span: Span,
    recorded: bool,
}

impl DriverOutcome {
    fn new(span: &Span) -> Self {
        Self {
            span: span.clone(),
            recorded: false,
        }
    }

    fn finish(mut self, outcome: &'static str) {
        self.span.record("outcome", outcome);
        self.recorded = true;
    }
}

impl Drop for DriverOutcome {
    fn drop(&mut self) {
        if !self.recorded {
            self.span.record("outcome", "runtime_shutdown");
        }
    }
}

struct AbortDriver {
    handle: JoinHandle<Result<(), ::http2::Error>>,
}

impl AbortDriver {
    fn new(handle: JoinHandle<Result<(), ::http2::Error>>) -> Self {
        Self { handle }
    }

    fn handle_mut(&mut self) -> &mut JoinHandle<Result<(), ::http2::Error>> {
        &mut self.handle
    }

    fn abort(&self) {
        self.handle.abort();
    }
}

impl Drop for AbortDriver {
    fn drop(&mut self) {
        self.abort();
    }
}

impl Drop for DriverTask {
    fn drop(&mut self) {
        self.shutdown();
    }
}
