//! Admission and caller-owned work during terminal client shutdown.

use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::Notify;

use crate::RequestError;

#[derive(Default)]
pub(crate) struct Lifecycle {
    state: Mutex<State>,
    idle: Notify,
}

#[derive(Default)]
struct State {
    closed: bool,
    active: usize,
}

impl Lifecycle {
    pub(crate) fn enter(self: &Arc<Self>) -> Result<Activity, RequestError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.closed {
            return Err(RequestError::client_closed());
        }
        state.active = state
            .active
            .checked_add(1)
            .ok_or_else(RequestError::unselected_capacity)?;
        Ok(Activity(Arc::clone(self)))
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .closed
    }

    pub(crate) async fn shutdown(&self) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .closed = true;
        loop {
            // Register before checking the count so the final owner cannot
            // leave between the check and registration. All waiters are woken.
            let notified = self.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .active
                == 0
            {
                return;
            }
            notified.await;
        }
    }
}

pub(crate) struct Activity(Arc<Lifecycle>);

impl Drop for Activity {
    fn drop(&mut self) {
        let idle = {
            let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.active -= 1;
            state.active == 0
        };
        if idle {
            self.0.idle.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::Future, task::Poll};

    #[tokio::test]
    async fn shutdown_rejects_new_work_and_waits_for_every_owner() -> Result<(), RequestError> {
        let lifecycle = Arc::new(Lifecycle::default());
        let first = lifecycle.enter()?;
        let second = lifecycle.enter()?;
        let shutdown = lifecycle.shutdown();
        tokio::pin!(shutdown);
        assert!(matches!(
            std::future::poll_fn(|cx| Poll::Ready(shutdown.as_mut().poll(cx))).await,
            Poll::Pending
        ));
        assert!(lifecycle.is_closed());
        assert!(
            matches!(lifecycle.enter(), Err(error) if error.kind() == crate::RequestErrorKind::ClientClosed)
        );
        drop(first);
        assert!(matches!(
            std::future::poll_fn(|cx| Poll::Ready(shutdown.as_mut().poll(cx))).await,
            Poll::Pending
        ));
        drop(second);
        shutdown.await;
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_shutdown_stays_closed_and_all_waiters_finish() -> Result<(), RequestError> {
        let lifecycle = Arc::new(Lifecycle::default());
        let owner = lifecycle.enter()?;
        {
            let shutdown = lifecycle.shutdown();
            tokio::pin!(shutdown);
            assert!(matches!(
                std::future::poll_fn(|cx| Poll::Ready(shutdown.as_mut().poll(cx))).await,
                Poll::Pending
            ));
        }
        assert!(lifecycle.is_closed());
        let first = lifecycle.shutdown();
        let second = lifecycle.shutdown();
        tokio::pin!(first, second);
        assert!(matches!(
            std::future::poll_fn(|cx| Poll::Ready(first.as_mut().poll(cx))).await,
            Poll::Pending
        ));
        assert!(matches!(
            std::future::poll_fn(|cx| Poll::Ready(second.as_mut().poll(cx))).await,
            Poll::Pending
        ));
        drop(owner);
        tokio::join!(first, second);
        Ok(())
    }
}
