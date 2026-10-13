//! Retained completion of the HTTP/2 and HTTP/3 session fixture workers.

use std::{future::Future, time::Duration};

use tokio::{sync::oneshot, task::coop, time::timeout};

use crate::support::{
    deadline::FixtureDeadline,
    tls::TestResult,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct Peer<T> {
    task: ConnectionPeer<Outcome<T>>,
    stop: Option<oneshot::Sender<()>>,
    primary: TestResult<()>,
}

enum Outcome<T> {
    Finished(TestResult<T>),
    Stopped,
}

impl<T: Send + 'static> Peer<T> {
    pub(super) fn spawn(future: impl Future<Output = TestResult<T>> + Send + 'static) -> Self {
        let (stop, stopped) = oneshot::channel();
        let task = ConnectionPeer::spawn(async move {
            tokio::select! {
                biased;
                result = future => Outcome::Finished(result),
                stopped = stopped => match stopped {
                    Ok(()) => Outcome::Stopped,
                    Err(error) => Outcome::Finished(Err(error.into())),
                },
            }
        });
        Self {
            task,
            stop: Some(stop),
            primary: Ok(()),
        }
    }

    pub(super) fn blocking(operation: impl FnOnce() -> TestResult<T> + Send + 'static) -> Self {
        // A running blocking operation cannot be interrupted. Retain its actual
        // task and observe it; this fixture builds a runtime without network I/O.
        let task = ConnectionPeer::from_task(tokio::task::spawn_blocking(move || {
            Outcome::Finished(operation())
        }));
        Self {
            task,
            stop: None,
            primary: Ok(()),
        }
    }

    fn request_stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            // A closed receiver's original outcome is still collected below.
            let _ = stop.send(());
        }
    }
}

pub(super) async fn join<T: Send + 'static>(owner: &mut Option<Peer<T>>) -> TestResult<T> {
    let peer = owner.as_mut().ok_or("session peer missing before join")?;
    let outcome = (&mut peer.task).await;
    let peer = owner.take().ok_or("session peer missing after join")?;
    let result = match outcome {
        Ok(Outcome::Finished(result)) => result,
        Ok(Outcome::Stopped) => Err("session peer stopped before its result was observed".into()),
        Err(error) => Err(error.into()),
    };
    match (peer.primary, result) {
        (Ok(()), result) => result,
        (Err(error), Ok(_)) => Err(error),
        (Err(primary), Err(error)) => finish_with_cleanup(Err(primary), Err(error)),
    }
}

pub(super) async fn finish<T, S: Send + 'static>(
    primary: TestResult<T>,
    owner: &mut Option<Peer<S>>,
) -> TestResult<T> {
    let Some(peer) = owner.as_mut() else {
        return primary;
    };
    // The caller's error survives an interrupted cleanup await on this owner.
    let value = match primary {
        Ok(value) => Some(value),
        Err(error) => {
            peer.primary =
                finish_with_cleanup(std::mem::replace(&mut peer.primary, Ok(())), Err(error));
            None
        }
    };
    peer.request_stop();
    let outcome = timeout(CLEANUP_TIMEOUT, coop::unconstrained(&mut peer.task)).await;
    let cleanup = match outcome {
        Ok(outcome) => {
            let peer = owner.take().ok_or("session peer missing after cleanup")?;
            let cleanup = match outcome {
                Ok(Outcome::Finished(result)) => result.map(|_| ()),
                Ok(Outcome::Stopped) => Ok(()),
                Err(error) => Err(error.into()),
            };
            finish_with_cleanup(peer.primary, cleanup)
        }
        Err(elapsed) => {
            // Retain the handle. Abort is a backup, never a successful join.
            peer.task.abort();
            finish_with_cleanup(
                std::mem::replace(&mut peer.primary, Ok(())),
                Err(
                    FixtureDeadline::new("session peer cleanup exceeded its deadline", elapsed)
                        .into(),
                ),
            )
        }
    };
    cleanup?;
    value.ok_or_else(|| "session caller outcome missing after cleanup".into())
}

pub(super) fn finish_negative(
    result: TestResult<()>,
    client_failure: Option<phantom::RequestError>,
) -> TestResult<()> {
    match (result, client_failure) {
        (Err(error), Some(client)) => finish_with_cleanup(Err(client.into()), Err(error)),
        (result, _) => result,
    }
}

#[cfg(test)]
mod tests;
