use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, Ordering},
};

use phantom_net::route::EchRetry;
use tokio::sync::watch;

use crate::RequestError;

/// Failed HTTP/2 generations stay identifiable while their streams drain.
#[derive(Default)]
pub(super) struct EchRecoveries(Vec<(Weak<()>, Arc<EchRecovery>)>);

impl EchRecoveries {
    pub(super) fn get_or_insert(
        &mut self,
        token: &Arc<()>,
        retry: EchRetry,
        error: RequestError,
    ) -> Arc<EchRecovery> {
        self.retain_live();
        let token = Arc::downgrade(token);
        if let Some((_, recovery)) = self.0.iter().find(|(owner, _)| owner.ptr_eq(&token)) {
            return Arc::clone(recovery);
        }

        let recovery = Arc::new(EchRecovery::new(retry, error));
        self.0.push((token, Arc::clone(&recovery)));
        recovery
    }

    pub(super) fn retain_live(&mut self) {
        self.0
            .retain(|(owner, recovery)| owner.strong_count() != 0 || recovery.pending());
    }

    pub(super) fn pending(&self) -> Option<Arc<EchRecovery>> {
        self.0
            .iter()
            .find(|(_, recovery)| recovery.pending())
            .map(|(_, recovery)| Arc::clone(recovery))
    }
}

pub(super) struct EchRecovery {
    retry: EchRetry,
    completion: Arc<EchCompletion>,
}

impl EchRecovery {
    pub(super) fn new(retry: EchRetry, error: RequestError) -> Self {
        Self {
            retry,
            completion: Arc::new(EchCompletion::new(error)),
        }
    }

    pub(super) fn retry(&self) -> &EchRetry {
        &self.retry
    }

    pub(super) fn claim(&self) -> Option<EchRecoveryOwner> {
        self.completion.claim()
    }

    fn pending(&self) -> bool {
        self.completion.result.borrow().is_none()
    }

    pub(super) async fn finished(&self) -> Result<(), RequestError> {
        self.completion.finished().await
    }
}

/// The request that opens the fresh connection owns completion. Cancellation
/// publishes the original authenticated rejection and wakes every waiter.
struct EchCompletion {
    claimed: AtomicBool,
    cancelled: Arc<RequestError>,
    result: watch::Sender<Option<Result<(), Arc<RequestError>>>>,
}

impl EchCompletion {
    fn new(cancelled: RequestError) -> Self {
        Self {
            claimed: AtomicBool::new(false),
            cancelled: Arc::new(cancelled),
            result: watch::channel(None).0,
        }
    }

    fn claim(self: &Arc<Self>) -> Option<EchRecoveryOwner> {
        self.claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| EchRecoveryOwner {
                completion: Arc::clone(self),
                finished: false,
            })
    }

    async fn finished(&self) -> Result<(), RequestError> {
        let mut receiver = self.result.subscribe();
        loop {
            if let Some(result) = receiver.borrow_and_update().clone() {
                return result.map_err(|error| RequestError::shared(&error));
            }
            // This object owns the sender throughout the wait. A closed
            // channel is still a terminal failure, never setup permission.
            if receiver.changed().await.is_err() {
                return Err(RequestError::shared(&self.cancelled));
            }
        }
    }
}

pub(super) struct EchRecoveryOwner {
    completion: Arc<EchCompletion>,
    finished: bool,
}

impl EchRecoveryOwner {
    pub(super) fn finish(mut self) {
        drop(self.completion.result.send_replace(Some(Ok(()))));
        self.finished = true;
    }

    pub(super) fn fail(mut self, error: RequestError) -> RequestError {
        let error = Arc::new(error);
        drop(
            self.completion
                .result
                .send_replace(Some(Err(Arc::clone(&error)))),
        );
        self.finished = true;
        RequestError::shared(&error)
    }
}

impl Drop for EchRecoveryOwner {
    fn drop(&mut self) {
        if !self.finished {
            drop(
                self.completion
                    .result
                    .send_replace(Some(Err(Arc::clone(&self.completion.cancelled)))),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::{Future, poll_fn},
        sync::Arc,
        task::Poll,
        time::Duration,
    };

    use super::EchCompletion;
    use crate::{HttpProtocol, RequestError, RequestErrorKind};

    #[tokio::test]
    async fn cancelling_recovery_wakes_waiters_without_a_second_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        let completion = Arc::new(EchCompletion::new(RequestError::unsupported_route(
            HttpProtocol::Http2,
        )));
        let owner = completion.claim().ok_or("missing first recovery owner")?;
        let waiter = completion.finished();
        tokio::pin!(waiter);
        let pending =
            poll_fn(|context| Poll::Ready(waiter.as_mut().poll(context).is_pending())).await;
        assert!(pending);

        drop(owner);

        let error = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await?
            .err()
            .ok_or("cancelled recovery unexpectedly succeeded")?;
        assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);
        assert_eq!(error.protocol(), Some(HttpProtocol::Http2));
        assert!(completion.claim().is_none());
        assert!(completion.finished().await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn failed_recovery_is_terminal_for_current_and_late_waiters()
    -> Result<(), Box<dyn std::error::Error>> {
        let completion = Arc::new(EchCompletion::new(RequestError::client_closed()));
        let owner = completion.claim().ok_or("missing first recovery owner")?;
        let failed = RequestError::unsupported_route(HttpProtocol::Http1);

        let error = owner.fail(failed);
        let waiter = completion
            .finished()
            .await
            .err()
            .ok_or("waiter succeeded")?;

        assert_eq!(error.kind(), waiter.kind());
        assert_eq!(waiter.protocol(), Some(HttpProtocol::Http1));
        assert!(completion.claim().is_none());
        Ok(())
    }
}
