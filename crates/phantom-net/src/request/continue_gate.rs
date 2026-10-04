//! The wait for `100 Continue` before a request body is sent.
//!
//! A body armed for `Expect: 100-continue` holds its first frame until the
//! connection reports an interim `100`, the wait ends, or a final response
//! arrives first, in which case the body is never sent (RFC 9110,
//! section 10.1.1).

use std::{
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use tokio::sync::oneshot;
use tracing::warn;

const WAITING: u8 = 0;
const CONTINUED: u8 = 1;
const TIMED_OUT: u8 = 2;
const ABANDONED: u8 = 3;

/// How the wait for `100 Continue` ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContinueOutcome {
    Waiting,
    Continued,
    TimedOut,
    Abandoned,
}

struct ContinueState {
    state: AtomicU8,
    waker: Mutex<Option<Waker>>,
}

impl ContinueState {
    /// Moves from waiting to `to` and wakes the body; returns whether it did.
    fn finish(&self, to: u8) -> bool {
        if self
            .state
            .compare_exchange(WAITING, to, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        let waker = match self.waker.lock() {
            Ok(mut waker) => waker.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        true
    }

    fn outcome(&self) -> ContinueOutcome {
        match self.state.load(Ordering::Acquire) {
            CONTINUED => ContinueOutcome::Continued,
            TIMED_OUT => ContinueOutcome::TimedOut,
            ABANDONED => ContinueOutcome::Abandoned,
            _ => ContinueOutcome::Waiting,
        }
    }
}

/// The body's side of the wait.
pub(crate) struct ContinueGate {
    state: Arc<ContinueState>,
    wait: Duration,
    deadline: Option<oneshot::Receiver<()>>,
    /// Set when no timer could be scheduled for `wait`, because the deadline
    /// is past the clock's range or the timer service did not start: only
    /// `100 Continue` or a final response then ends the wait.
    untimed: bool,
}

/// The connection's side of the wait.
#[derive(Clone)]
pub(crate) struct ContinueSignal(Arc<ContinueState>);

impl ContinueGate {
    pub(crate) fn new(wait: Duration) -> (Self, ContinueSignal) {
        let state = Arc::new(ContinueState {
            state: AtomicU8::new(WAITING),
            waker: Mutex::new(None),
        });
        (
            Self {
                state: Arc::clone(&state),
                wait,
                deadline: None,
                untimed: false,
            },
            ContinueSignal(state),
        )
    }

    /// Returns `Ready` once the body may be sent. The wait starts at the
    /// first poll, which comes once the request head is written. An
    /// abandoned body stays pending until its connection drops it.
    pub(crate) fn poll_release(&mut self, context: &mut Context<'_>) -> Poll<()> {
        match self.state.outcome() {
            ContinueOutcome::Continued | ContinueOutcome::TimedOut => return Poll::Ready(()),
            ContinueOutcome::Abandoned => return Poll::Pending,
            ContinueOutcome::Waiting => {}
        }
        match self.state.waker.lock() {
            Ok(mut waker) => *waker = Some(context.waker().clone()),
            Err(poisoned) => *poisoned.into_inner() = Some(context.waker().clone()),
        }
        if self.deadline.is_none() && !self.untimed {
            match crate::shutdown_timer::after(self.wait) {
                Ok(deadline) => self.deadline = Some(deadline),
                Err(_) => {
                    // Sending the body early would change when the server
                    // sees it, so the wait goes on without an end of its own.
                    warn!(
                        "could not schedule the wait for 100 Continue; waiting for the server's answer"
                    );
                    self.untimed = true;
                }
            }
        }
        if let Some(deadline) = &mut self.deadline
            && std::pin::Pin::new(deadline).poll(context).is_ready()
        {
            self.state.finish(TIMED_OUT);
        }
        match self.state.outcome() {
            ContinueOutcome::Continued | ContinueOutcome::TimedOut => Poll::Ready(()),
            ContinueOutcome::Waiting | ContinueOutcome::Abandoned => Poll::Pending,
        }
    }
}

impl ContinueSignal {
    /// Releases the body after an interim `100 Continue`.
    pub(crate) fn proceed(&self) {
        self.0.finish(CONTINUED);
    }

    /// Withholds the body for good after a final response; returns whether
    /// the body had not started, so none of it was sent.
    pub(crate) fn abandon(&self) -> bool {
        self.0.finish(ABANDONED)
    }

    #[cfg(test)]
    fn outcome(&self) -> ContinueOutcome {
        self.0.outcome()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        task::{Context, Poll, Waker},
        time::Duration,
    };

    use super::{ContinueGate, ContinueOutcome};

    #[test]
    fn a_wait_past_the_clock_range_ends_only_with_the_servers_answer() {
        let (mut gate, signal) = ContinueGate::new(Duration::MAX);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(gate.poll_release(&mut context), Poll::Pending);
        assert_eq!(gate.poll_release(&mut context), Poll::Pending);
        assert_eq!(signal.outcome(), ContinueOutcome::Waiting);
        signal.proceed();
        assert_eq!(gate.poll_release(&mut context), Poll::Ready(()));
    }

    #[test]
    fn the_body_waits_until_a_100_continue() {
        let (mut gate, signal) = ContinueGate::new(Duration::from_secs(10));
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(gate.poll_release(&mut context), Poll::Pending);
        signal.proceed();
        assert_eq!(gate.poll_release(&mut context), Poll::Ready(()));
        assert_eq!(signal.outcome(), ContinueOutcome::Continued);
        // A final response after the body started abandons nothing.
        assert!(!signal.abandon());
    }

    #[test]
    fn an_abandoned_body_is_never_released() {
        let (mut gate, signal) = ContinueGate::new(Duration::from_secs(10));
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(gate.poll_release(&mut context), Poll::Pending);
        assert!(signal.abandon());
        signal.proceed();
        assert_eq!(gate.poll_release(&mut context), Poll::Pending);
        assert_eq!(signal.outcome(), ContinueOutcome::Abandoned);
    }

    #[tokio::test]
    async fn the_wait_ends_and_releases_the_body() {
        let (mut gate, signal) = ContinueGate::new(Duration::from_millis(20));
        std::future::poll_fn(|context| gate.poll_release(context)).await;
        assert_eq!(signal.outcome(), ContinueOutcome::TimedOut);
    }
}
