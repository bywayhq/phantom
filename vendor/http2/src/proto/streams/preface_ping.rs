use crate::client::PingTimer;
use crate::frame::{Frame, Ping};

use bytes::Buf;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

/// Decides when a client PING follows a request frame on a connection that
/// has read nothing for longer than a configured time.
///
/// A PING is due after request HEADERS, or after a DATA frame with a
/// non-empty payload, when the last frame read from the peer is older than
/// `idle` and no earlier such PING awaits its ACK. It is written before any
/// other frame, WINDOW_UPDATE, RST_STREAM, and PING and SETTINGS
/// acknowledgements included. The first PING carries the big-endian 64-bit value 1 and each
/// later one the next value. The ACK is matched by payload.
///
/// With a timeout, a PING in flight fails once the timeout has passed on the
/// timer's clock since the later of its queueing and the last frame read.
/// This is the deadline Chromium's `SpdySession::CheckPingStatus` enforces:
/// its first check runs a timeout after the PING, and each later one a
/// timeout after the last read. The idle time above uses the system clock;
/// the timeout uses only the timer's.
pub(super) struct PrefacePing {
    idle: Duration,
    last_read: Instant,
    next_payload: u64,
    in_flight: Option<[u8; 8]>,
    due: Option<[u8; 8]>,
    timeout: Option<(Duration, PingTimer)>,
    /// The timer's time when the PING in flight was queued, until it is
    /// answered or fails.
    queued_at: Option<Instant>,
    /// The timer's time of the last frame read.
    timer_last_read: Option<Instant>,
    sleep: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl fmt::Debug for PrefacePing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrefacePing")
            .field("idle", &self.idle)
            .field("last_read", &self.last_read)
            .field("next_payload", &self.next_payload)
            .field("in_flight", &self.in_flight)
            .field("due", &self.due)
            .field(
                "timeout",
                &self.timeout.as_ref().map(|(timeout, _)| timeout),
            )
            .field("queued_at", &self.queued_at)
            .field("timer_last_read", &self.timer_last_read)
            .finish_non_exhaustive()
    }
}

impl PrefacePing {
    pub(super) fn new(idle: Duration, timeout: Option<(Duration, PingTimer)>) -> Self {
        PrefacePing {
            idle,
            last_read: Instant::now(),
            next_payload: 1,
            in_flight: None,
            due: None,
            timeout,
            queued_at: None,
            timer_last_read: None,
            sleep: None,
        }
    }

    /// Records a frame read from the peer. Returns `true` when `ack` is the
    /// acknowledgement of the PING in flight, which this consumes.
    pub(super) fn recv_frame(&mut self, now: Instant, ack: Option<&[u8; 8]>) -> bool {
        self.last_read = now;
        if let Some((_, timer)) = &self.timeout {
            self.timer_last_read = Some(timer.now());
        }
        match ack {
            Some(payload) if self.in_flight.as_ref() == Some(payload) => {
                self.in_flight = None;
                self.queued_at = None;
                self.sleep = None;
                true
            }
            _ => false,
        }
    }

    /// Records a frame about to be written, making a PING due after it when
    /// the connection has been read-idle for longer than `idle`.
    pub(super) fn sent<B: Buf>(&mut self, frame: &Frame<B>, now: Instant) {
        let request_frame = match frame {
            Frame::Headers(headers) => headers.pseudo().method.is_some(),
            Frame::Data(data) => data.payload().has_remaining(),
            _ => false,
        };
        if !request_frame || self.in_flight.is_some() {
            return;
        }
        // Due only once the idle time is strictly exceeded.
        match now.checked_duration_since(self.last_read) {
            Some(elapsed) if elapsed > self.idle => {}
            _ => return,
        }
        let payload = self.next_payload.to_be_bytes();
        self.next_payload = self.next_payload.wrapping_add(1);
        self.in_flight = Some(payload);
        self.due = Some(payload);
        if let Some((_, timer)) = &self.timeout {
            self.queued_at = Some(timer.now());
        }
    }

    /// Returns `Ready` once, when the PING in flight has gone the timeout
    /// without an ACK or a read. Without a timeout it never does.
    pub(super) fn poll_timeout(&mut self, cx: &mut Context) -> Poll<()> {
        let (timeout, timer) = match &self.timeout {
            Some((timeout, timer)) => (*timeout, timer),
            None => return Poll::Pending,
        };
        // A sleep that ends before the deadline re-arms once; a second one
        // started here that ends at once yields instead, so a timer whose
        // sleeps end immediately cannot hold the connection in this loop.
        let mut started = false;
        loop {
            let queued_at = match self.queued_at {
                Some(queued_at) => queued_at,
                None => return Poll::Pending,
            };
            let quiet_since = match self.timer_last_read {
                Some(read) if read > queued_at => read,
                _ => queued_at,
            };
            let deadline = match quiet_since.checked_add(timeout) {
                Some(deadline) => deadline,
                None => return Poll::Pending,
            };
            let now = timer.now();
            if now >= deadline {
                self.queued_at = None;
                self.sleep = None;
                return Poll::Ready(());
            }
            if self.sleep.is_none() {
                if started {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                started = true;
                self.sleep = Some(timer.sleep(deadline - now));
            }
            if let Some(sleep) = &mut self.sleep {
                if sleep.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
            }
            self.sleep = None;
        }
    }

    pub(super) fn is_due(&self) -> bool {
        self.due.is_some()
    }

    /// Takes the PING due after the last request frame, if any.
    pub(super) fn take_due(&mut self) -> Option<Ping> {
        self.due.take().map(Ping::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::task::Waker;

    const PAYLOAD: [u8; 8] = 1_u64.to_be_bytes();
    const TIMEOUT: Duration = Duration::from_secs(10);

    /// A clock that moves only when a test advances it.
    #[derive(Clone)]
    struct FakeClock {
        base: Instant,
        elapsed_ms: Arc<AtomicU64>,
    }

    impl FakeClock {
        fn new() -> Self {
            FakeClock {
                base: Instant::now(),
                elapsed_ms: Arc::new(AtomicU64::new(0)),
            }
        }

        fn advance(&self, duration: Duration) {
            let ms = u64::try_from(duration.as_millis()).expect("test duration fits");
            self.elapsed_ms.fetch_add(ms, Ordering::SeqCst);
        }

        /// A timer on this clock whose sleeps never end, or end at once.
        fn timer(&self, sleeps_end: bool) -> PingTimer {
            let clock = self.clone();
            PingTimer::new(
                move || clock.base + Duration::from_millis(clock.elapsed_ms.load(Ordering::SeqCst)),
                move |_| {
                    if sleeps_end {
                        Box::pin(std::future::ready(()))
                    } else {
                        Box::pin(std::future::pending())
                    }
                },
            )
        }
    }

    /// A preface PING queued now on `timer`'s clock, as `sent` leaves it.
    fn in_flight(timer: PingTimer) -> PrefacePing {
        let queued_at = timer.now();
        let mut preface_ping = PrefacePing::new(Duration::ZERO, Some((TIMEOUT, timer)));
        preface_ping.in_flight = Some(PAYLOAD);
        preface_ping.queued_at = Some(queued_at);
        preface_ping
    }

    fn poll(preface_ping: &mut PrefacePing) -> Poll<()> {
        preface_ping.poll_timeout(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn timeout_follows_the_timer_clock() {
        let clock = FakeClock::new();
        let mut preface_ping = in_flight(clock.timer(false));
        // The system clock plays no part.
        preface_ping.last_read = Instant::now() - Duration::from_secs(60);
        clock.advance(TIMEOUT - Duration::from_millis(1));
        assert!(poll(&mut preface_ping).is_pending());
        clock.advance(Duration::from_millis(1));
        assert!(poll(&mut preface_ping).is_ready());
        assert!(
            poll(&mut preface_ping).is_pending(),
            "failure is reported once"
        );
    }

    #[test]
    fn a_read_moves_the_deadline_to_a_timeout_after_it() {
        let clock = FakeClock::new();
        let mut preface_ping = in_flight(clock.timer(false));
        clock.advance(Duration::from_secs(6));
        preface_ping.recv_frame(Instant::now(), None);
        clock.advance(Duration::from_secs(4));
        assert!(poll(&mut preface_ping).is_pending(), "10 s after the PING");
        clock.advance(Duration::from_millis(5_999));
        assert!(poll(&mut preface_ping).is_pending());
        clock.advance(Duration::from_millis(1));
        assert!(poll(&mut preface_ping).is_ready(), "10 s after the read");
    }

    #[test]
    fn a_sleep_that_ends_early_does_not_spin() {
        let clock = FakeClock::new();
        let mut preface_ping = in_flight(clock.timer(true));
        assert!(poll(&mut preface_ping).is_pending());
        assert!(poll(&mut preface_ping).is_pending());
        clock.advance(TIMEOUT);
        assert!(poll(&mut preface_ping).is_ready());
    }

    #[test]
    fn the_ack_disarms_the_timeout() {
        let clock = FakeClock::new();
        let mut preface_ping = in_flight(clock.timer(true));
        assert!(preface_ping.recv_frame(Instant::now(), Some(&PAYLOAD)));
        clock.advance(TIMEOUT);
        assert!(poll(&mut preface_ping).is_pending());
    }
}
