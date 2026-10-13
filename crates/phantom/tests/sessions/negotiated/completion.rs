use std::{future::Future, time::Duration};

use tokio::{sync::oneshot, task::coop, time::timeout};

use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

use super::{SECOND_CONNECTION_WINDOW, TEST_TIMEOUT, TestResult};

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub(super) struct Peer<T> {
    task: ConnectionPeer<Outcome<T>>,
    stop: Option<oneshot::Sender<()>>,
    primary: TestResult<()>,
}

#[derive(Debug)]
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
                result = stopped => match result {
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

    fn request_stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            // If the receiver has completed, its original task result is still observed.
            let _ = stop.send(());
        }
    }

    #[cfg(test)]
    fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

pub(super) async fn bounded<T>(future: impl Future<Output = TestResult<T>>) -> TestResult<T> {
    timeout(TEST_TIMEOUT, future).await.map_err(|elapsed| {
        FixtureDeadline::new("negotiated client test exceeded its deadline", elapsed)
    })?
}

pub(super) async fn join<T: Send + 'static>(owner: &mut Option<Peer<T>>) -> TestResult<T> {
    let peer = owner
        .as_mut()
        .ok_or("negotiated fixture worker missing before join")?;
    let result = (&mut peer.task).await;
    let peer = owner
        .take()
        .ok_or("negotiated fixture worker missing after join")?;
    let result = match result {
        Ok(Outcome::Finished(result)) => result,
        Ok(Outcome::Stopped) => Err("negotiated fixture worker stopped before join".into()),
        Err(error) => Err(error.into()),
    };
    with_retained_failure(peer.primary, result)
}

pub(super) async fn finish<T, S: Send + 'static>(
    primary: TestResult<T>,
    owner: &mut Option<Peer<S>>,
) -> TestResult<T> {
    let Some(peer) = owner.as_mut() else {
        return primary;
    };

    // Retain initiating failures on the owner before an outer deadline can drop this await.
    let value = match primary {
        Ok(value) => Some(value),
        Err(error) => {
            peer.primary =
                finish_with_cleanup(std::mem::replace(&mut peer.primary, Ok(())), Err(error));
            None
        }
    };
    peer.request_stop();
    let joined = timeout(CLEANUP_TIMEOUT, coop::unconstrained(&mut peer.task)).await;
    let cleanup = match joined {
        Ok(result) => {
            let peer = owner
                .take()
                .ok_or("negotiated fixture worker missing after cleanup")?;
            let cleanup = match result {
                Ok(Outcome::Finished(result)) => result.map(|_| ()),
                Ok(Outcome::Stopped) => Ok(()),
                Err(error) => Err(error.into()),
            };
            finish_with_cleanup(peer.primary, cleanup)
        }
        Err(elapsed) => {
            // The deadline remains a failure; abort is only the retained owner's backup.
            peer.task.abort();
            let primary = std::mem::replace(&mut peer.primary, Ok(()));
            finish_with_cleanup(
                primary,
                Err(FixtureDeadline::new(
                    "negotiated worker cleanup exceeded its deadline",
                    elapsed,
                )
                .into()),
            )
        }
    };
    cleanup?;
    value.ok_or_else(|| "negotiated caller outcome missing after cleanup".into())
}

pub(super) async fn cancel<T: Send + 'static>(owner: &mut Option<Peer<T>>) -> TestResult<()> {
    let peer = owner
        .as_mut()
        .ok_or("negotiated fixture worker missing before cancellation")?;
    peer.request_stop();
    let result = coop::unconstrained(&mut peer.task).await;
    let peer = owner
        .take()
        .ok_or("negotiated fixture worker missing after cancellation")?;
    let result = match result {
        Err(error) => Err(error.into()),
        Ok(Outcome::Finished(Err(error))) => Err(error),
        Ok(Outcome::Finished(Ok(_))) => {
            Err("negotiated fixture worker completed during cancellation".into())
        }
        Ok(Outcome::Stopped) => Ok(()),
    };
    with_retained_failure(peer.primary, result)
}

fn with_retained_failure<T>(retained: TestResult<()>, result: TestResult<T>) -> TestResult<T> {
    match (retained, result) {
        (Ok(()), result) => result,
        (Err(error), Ok(_)) => Err(error),
        (Err(primary), Err(error)) => finish_with_cleanup(Err(primary), Err(error)),
    }
}

pub(super) fn finish_negative(
    primary: TestResult<()>,
    client_error: Option<phantom::RequestError>,
) -> TestResult<()> {
    match (primary, client_error) {
        (Ok(()), _) => Ok(()),
        (Err(completion), Some(error)) => finish_with_cleanup(Err(error.into()), Err(completion)),
        (Err(error), None) => Err(error),
    }
}

pub(super) async fn no_connection<T>(
    accept: impl Future<Output = std::io::Result<T>>,
) -> TestResult<bool> {
    match timeout(SECOND_CONNECTION_WINDOW, accept).await {
        Err(_) => Ok(true),
        Ok(Ok(_)) => Ok(false),
        Ok(Err(error)) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests;
