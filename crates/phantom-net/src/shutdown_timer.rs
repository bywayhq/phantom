//! Runtime-neutral deadlines for protocol-driver shutdown, TCP attempt
//! fallback, HTTP/2 PING timeouts, the TCP keepalive schedule, the wait for
//! an HTTPS record, and the facade's idle-connection timer.
//!
//! The deadlines run on a Tokio runtime of their own, on one thread for the
//! life of the process, so they need no timer from the caller's runtime. That
//! runtime parks in its I/O driver because on macOS a timed wait on a channel
//! or condition variable can end long after its timeout.

use std::{
    io,
    sync::{OnceLock, mpsc},
    thread,
    time::{Duration, Instant},
};

use tokio::{
    runtime::{Builder, Handle, Runtime},
    sync::oneshot,
};

static SERVICE: OnceLock<Option<Handle>> = OnceLock::new();

#[derive(Clone, Copy, Debug)]
pub(crate) struct ScheduleError;

/// Completes once `delay` has passed, timed by Phantom's deadline service
/// rather than the caller's runtime, which may run without a time driver.
///
/// Returns `None` when the service cannot start or the deadline cannot be
/// represented.
///
/// This is a seam for the facade's idle-connection timer, not supported
/// API.
#[doc(hidden)]
pub fn deadline(delay: Duration) -> Option<impl std::future::Future<Output = ()> + Send + 'static> {
    let receiver = after(delay).ok()?;
    // The service never drops a pending deadline, so an error counts as the
    // deadline too.
    Some(async move {
        let _ = receiver.await;
    })
}

pub(crate) fn after(delay: Duration) -> Result<oneshot::Receiver<()>, ScheduleError> {
    let service = SERVICE
        .get_or_init(start_service)
        .as_ref()
        .ok_or(ScheduleError)?;
    let at = Instant::now().checked_add(delay).ok_or(ScheduleError)?;
    let (mut signal, receiver) = oneshot::channel();
    service.spawn(async move {
        tokio::select! {
            () = tokio::time::sleep_until(at.into()) => {
                let _ = signal.send(());
            }
            () = signal.closed() => {}
        }
    });
    Ok(receiver)
}

/// Returns whether deadlines can be scheduled. Once the service thread has
/// started it runs for the life of the process, so a `true` stays true.
pub(crate) fn is_available() -> bool {
    SERVICE.get_or_init(start_service).is_some()
}

fn start_service() -> Option<Handle> {
    start_service_with(|| {
        Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
    })
}

/// Starts the service thread, which builds its runtime with `build` and runs
/// it for the life of the process.
///
/// The runtime is built and dropped only on that thread: a caller may be
/// inside a Tokio runtime, where dropping another runtime panics. Returns
/// `None` when the thread cannot start or `build` fails.
fn start_service_with(
    build: impl FnOnce() -> io::Result<Runtime> + Send + 'static,
) -> Option<Handle> {
    let (started, handle) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("phantom-shutdown-timer".to_owned())
        .spawn(move || {
            let Ok(runtime) = build() else {
                return;
            };
            if started.send(runtime.handle().clone()).is_ok() {
                runtime.block_on(std::future::pending::<()>());
            }
        })
        .ok()?;
    handle.recv().ok()
}

#[cfg(test)]
mod tests {
    use std::{io, time::Duration};

    use tokio::runtime::Builder;

    use super::{after, start_service_with};

    #[tokio::test]
    async fn a_runtime_that_cannot_be_built_leaves_no_service() {
        assert!(start_service_with(|| Err(io::Error::other("no runtime"))).is_none());
    }

    #[tokio::test]
    async fn a_started_service_runs_its_tasks() -> Result<(), Box<dyn std::error::Error>> {
        let handle = start_service_with(|| Builder::new_current_thread().enable_all().build())
            .ok_or("the service did not start")?;
        let (signal, receiver) = tokio::sync::oneshot::channel();
        handle.spawn(async move {
            let _ = signal.send(());
        });
        receiver.await?;
        Ok(())
    }

    #[tokio::test]
    async fn a_deadline_fires_after_its_delay() -> Result<(), Box<dyn std::error::Error>> {
        let started = std::time::Instant::now();
        after(Duration::from_millis(20))
            .map_err(|_| "could not schedule")?
            .await?;
        assert!(started.elapsed() >= Duration::from_millis(20));
        Ok(())
    }
}
