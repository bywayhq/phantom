use crate::client::PingTimer;

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

/// The payload of every idle PING.
pub(crate) const IDLE_PING_PAYLOAD: [u8; 8] = [0; 8];

/// Decides when a client PING goes out on a connection that has read nothing
/// for a configured time, whether or not streams are open, and when an
/// unanswered one closes the connection.
///
/// The PING is due once `after` has passed on the timer's clock since the last
/// frame read, and only while no earlier idle PING is outstanding. Its payload
/// is always zero. Any frame read clears the outstanding PING, so the next one
/// is due `after` that read. With a timeout, an outstanding PING fails once the
/// timeout has passed since it was queued with nothing read. This is the rule
/// of Firefox's `Http2Session::ReadTimeoutTick`.
pub(crate) struct IdlePing {
    after: Duration,
    timeout: Option<Duration>,
    timer: PingTimer,
    /// The timer's time of the last frame read, or of the connection's start.
    last_read: Instant,
    /// The timer's time when the outstanding PING was queued.
    sent_at: Option<Instant>,
    /// Whether a zero-payload ACK is still expected.
    awaiting_ack: bool,
    /// Whether the PING is queued but not yet written.
    write_pending: bool,
    sleep: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

/// What [`IdlePing::poll`] found.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum IdlePingState {
    /// A PING is due; [`IdlePing::take_pending`] returns it.
    Send,
    /// The outstanding PING went the timeout with nothing read.
    Failed,
}

impl fmt::Debug for IdlePing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdlePing")
            .field("after", &self.after)
            .field("timeout", &self.timeout)
            .field("last_read", &self.last_read)
            .field("sent_at", &self.sent_at)
            .field("awaiting_ack", &self.awaiting_ack)
            .field("write_pending", &self.write_pending)
            .finish_non_exhaustive()
    }
}

impl IdlePing {
    pub(crate) fn new(after: Duration, timeout: Option<Duration>, timer: PingTimer) -> Self {
        IdlePing {
            after,
            timeout,
            last_read: timer.now(),
            timer,
            sent_at: None,
            awaiting_ack: false,
            write_pending: false,
            sleep: None,
        }
    }

    /// Records a frame read from the peer. Returns `true` when `ack` is the
    /// acknowledgement of an idle PING, which this consumes.
    pub(crate) fn recv_frame(&mut self, ack: Option<&[u8; 8]>) -> bool {
        self.last_read = self.timer.now();
        self.sent_at = None;
        self.sleep = None;
        if self.awaiting_ack && ack == Some(&IDLE_PING_PAYLOAD) {
            self.awaiting_ack = false;
            return true;
        }
        false
    }

    /// Returns [`IdlePingState::Send`] once a PING is due and
    /// [`IdlePingState::Failed`] once an outstanding PING has gone the timeout,
    /// and otherwise sleeps until the next deadline.
    pub(crate) fn poll(&mut self, cx: &mut Context) -> Poll<IdlePingState> {
        // A sleep that ends before the deadline re-arms once; a second one
        // started here that ends at once yields instead, so a timer whose
        // sleeps end immediately cannot hold the connection in this loop.
        let mut started = false;
        loop {
            let deadline = match self.sent_at {
                Some(sent_at) => match self.timeout {
                    Some(timeout) => sent_at.checked_add(timeout),
                    None => return Poll::Pending,
                },
                None => self.last_read.checked_add(self.after),
            };
            let deadline = match deadline {
                Some(deadline) => deadline,
                None => return Poll::Pending,
            };
            let now = self.timer.now();
            if now >= deadline {
                self.sleep = None;
                if self.sent_at.take().is_some() {
                    return Poll::Ready(IdlePingState::Failed);
                }
                self.sent_at = Some(now);
                self.awaiting_ack = true;
                self.write_pending = true;
                return Poll::Ready(IdlePingState::Send);
            }
            if self.sleep.is_none() {
                if started {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                started = true;
                self.sleep = Some(self.timer.sleep(deadline - now));
            }
            if let Some(sleep) = &mut self.sleep {
                if sleep.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
            }
            self.sleep = None;
        }
    }

    /// Takes the payload of a PING that is due but not yet written.
    pub(crate) fn take_pending(&mut self) -> Option<[u8; 8]> {
        if self.write_pending {
            self.write_pending = false;
            Some(IDLE_PING_PAYLOAD)
        } else {
            None
        }
    }

    /// Puts back a PING that could not be written yet.
    pub(crate) fn restore_pending(&mut self) {
        self.write_pending = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::task::Waker;

    const AFTER: Duration = Duration::from_secs(58);
    const TIMEOUT: Duration = Duration::from_secs(8);

    /// A clock that moves only when a test advances it, and sleeps that end
    /// at once, so each poll re-reads the clock.
    #[derive(Clone)]
    struct Clock {
        start: Instant,
        offset_ms: Arc<AtomicU64>,
    }

    impl Clock {
        fn new() -> Self {
            Clock {
                start: Instant::now(),
                offset_ms: Arc::new(AtomicU64::new(0)),
            }
        }

        fn advance(&self, duration: Duration) {
            let millis = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
            self.offset_ms.fetch_add(millis, Ordering::SeqCst);
        }

        fn timer(&self) -> PingTimer {
            let clock = self.clone();
            PingTimer::new(
                move || clock.start + Duration::from_millis(clock.offset_ms.load(Ordering::SeqCst)),
                |_| Box::pin(std::future::pending()),
            )
        }
    }

    fn poll(ping: &mut IdlePing) -> Poll<IdlePingState> {
        let mut cx = Context::from_waker(Waker::noop());
        ping.poll(&mut cx)
    }

    #[test]
    fn a_ping_is_due_once_the_idle_time_has_passed() {
        let clock = Clock::new();
        let mut ping = IdlePing::new(AFTER, Some(TIMEOUT), clock.timer());
        clock.advance(AFTER - Duration::from_millis(1));
        assert_eq!(poll(&mut ping), Poll::Pending);
        clock.advance(Duration::from_millis(1));
        assert_eq!(poll(&mut ping), Poll::Ready(IdlePingState::Send));
        assert_eq!(ping.take_pending(), Some(IDLE_PING_PAYLOAD));
        assert_eq!(ping.take_pending(), None);
    }

    #[test]
    fn a_read_moves_the_next_ping_back() {
        let clock = Clock::new();
        let mut ping = IdlePing::new(AFTER, Some(TIMEOUT), clock.timer());
        clock.advance(Duration::from_secs(30));
        assert!(!ping.recv_frame(None));
        clock.advance(Duration::from_secs(30));
        assert_eq!(poll(&mut ping), Poll::Pending);
        clock.advance(Duration::from_secs(28));
        assert_eq!(poll(&mut ping), Poll::Ready(IdlePingState::Send));
    }

    #[test]
    fn only_one_ping_is_outstanding_and_every_payload_is_zero() {
        let clock = Clock::new();
        let mut ping = IdlePing::new(AFTER, None, clock.timer());
        clock.advance(AFTER);
        assert_eq!(poll(&mut ping), Poll::Ready(IdlePingState::Send));
        assert_eq!(ping.take_pending(), Some(IDLE_PING_PAYLOAD));
        clock.advance(AFTER * 3);
        assert_eq!(poll(&mut ping), Poll::Pending);
        assert!(ping.recv_frame(Some(&IDLE_PING_PAYLOAD)));
        clock.advance(AFTER);
        assert_eq!(poll(&mut ping), Poll::Ready(IdlePingState::Send));
        assert_eq!(ping.take_pending(), Some(IDLE_PING_PAYLOAD));
    }

    #[test]
    fn an_unanswered_ping_fails_after_the_timeout() {
        let clock = Clock::new();
        let mut ping = IdlePing::new(AFTER, Some(TIMEOUT), clock.timer());
        clock.advance(AFTER);
        assert_eq!(poll(&mut ping), Poll::Ready(IdlePingState::Send));
        clock.advance(TIMEOUT - Duration::from_millis(1));
        assert_eq!(poll(&mut ping), Poll::Pending);
        clock.advance(Duration::from_millis(1));
        assert_eq!(poll(&mut ping), Poll::Ready(IdlePingState::Failed));
    }

    #[test]
    fn any_read_before_the_timeout_keeps_the_connection() {
        let clock = Clock::new();
        let mut ping = IdlePing::new(AFTER, Some(TIMEOUT), clock.timer());
        clock.advance(AFTER);
        assert_eq!(poll(&mut ping), Poll::Ready(IdlePingState::Send));
        clock.advance(TIMEOUT - Duration::from_millis(1));
        // A frame other than the ACK clears the outstanding PING.
        assert!(!ping.recv_frame(None));
        clock.advance(TIMEOUT);
        assert_eq!(poll(&mut ping), Poll::Pending);
        // The late ACK is still recognized as the idle PING's.
        assert!(ping.recv_frame(Some(&IDLE_PING_PAYLOAD)));
    }

    #[test]
    fn a_ping_without_a_timeout_never_fails() {
        let clock = Clock::new();
        let mut ping = IdlePing::new(AFTER, None, clock.timer());
        clock.advance(AFTER);
        assert_eq!(poll(&mut ping), Poll::Ready(IdlePingState::Send));
        clock.advance(Duration::from_secs(3_600));
        assert_eq!(poll(&mut ping), Poll::Pending);
    }

    #[test]
    fn an_ack_with_another_payload_is_not_consumed() {
        let clock = Clock::new();
        let mut ping = IdlePing::new(AFTER, Some(TIMEOUT), clock.timer());
        clock.advance(AFTER);
        assert_eq!(poll(&mut ping), Poll::Ready(IdlePingState::Send));
        assert!(!ping.recv_frame(Some(&1_u64.to_be_bytes())));
    }

    #[test]
    fn a_sleep_that_ends_at_once_yields_instead_of_spinning() {
        let clock = Clock::new();
        let timer = PingTimer::new(
            {
                let clock = clock.clone();
                move || clock.start + Duration::from_millis(clock.offset_ms.load(Ordering::SeqCst))
            },
            |_| Box::pin(std::future::ready(())),
        );
        let mut ping = IdlePing::new(AFTER, Some(TIMEOUT), timer);
        assert_eq!(poll(&mut ping), Poll::Pending);
    }
}
