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
/// With a timeout, a PING in flight expires when a sleep of the timeout,
/// taken from the caller's timer, ends with no frame read since it was armed.
/// A sleep that ends after a read re-arms for another timeout, so expiry
/// comes one to two timeouts after the last read. Only the caller's sleeps
/// measure this time; the idle time above uses the system clock.
pub(super) struct PrefacePing {
    idle: Duration,
    last_read: Instant,
    /// Frames read so far, wrapping.
    reads: u64,
    next_payload: u64,
    in_flight: Option<[u8; 8]>,
    due: Option<[u8; 8]>,
    timeout: Option<(Duration, PingTimer)>,
    /// `reads` when the timeout was last armed, while a PING is unanswered
    /// and has not expired.
    armed_at_read: Option<u64>,
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
            .field("reads", &self.reads)
            .field("armed_at_read", &self.armed_at_read)
            .finish_non_exhaustive()
    }
}

impl PrefacePing {
    pub(super) fn new(idle: Duration, timeout: Option<(Duration, PingTimer)>) -> Self {
        PrefacePing {
            idle,
            last_read: Instant::now(),
            reads: 0,
            next_payload: 1,
            in_flight: None,
            due: None,
            timeout,
            armed_at_read: None,
            sleep: None,
        }
    }

    /// Records a frame read from the peer. Returns `true` when `ack` is the
    /// acknowledgement of the PING in flight, which this consumes.
    pub(super) fn recv_frame(&mut self, now: Instant, ack: Option<&[u8; 8]>) -> bool {
        self.last_read = now;
        self.reads = self.reads.wrapping_add(1);
        match ack {
            Some(payload) if self.in_flight.as_ref() == Some(payload) => {
                self.in_flight = None;
                self.armed_at_read = None;
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
        if self.timeout.is_some() {
            self.armed_at_read = Some(self.reads);
        }
    }

    /// Returns `Ready` once, when a sleep of the timeout ends with no frame
    /// read since the timeout was armed. Without a timeout it never does.
    pub(super) fn poll_timeout(&mut self, cx: &mut Context) -> Poll<()> {
        let (timeout, timer) = match &self.timeout {
            Some((timeout, timer)) => (*timeout, timer),
            None => return Poll::Pending,
        };
        loop {
            let armed_at_read = match self.armed_at_read {
                Some(reads) => reads,
                None => return Poll::Pending,
            };
            let sleep = self.sleep.get_or_insert_with(|| timer.sleep(timeout));
            if sleep.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.sleep = None;
            if self.reads == armed_at_read {
                self.armed_at_read = None;
                return Poll::Ready(());
            }
            // A frame was read during the sleep: wait another timeout.
            self.armed_at_read = Some(self.reads);
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
    use std::task::Waker;

    const PAYLOAD: [u8; 8] = 1_u64.to_be_bytes();

    /// A preface PING in flight, as `sent` leaves it, timed by `timer`.
    fn in_flight(timer: PingTimer) -> PrefacePing {
        let mut preface_ping =
            PrefacePing::new(Duration::ZERO, Some((Duration::from_secs(10), timer)));
        preface_ping.in_flight = Some(PAYLOAD);
        preface_ping.armed_at_read = Some(preface_ping.reads);
        preface_ping
    }

    fn poll(preface_ping: &mut PrefacePing) -> Poll<()> {
        preface_ping.poll_timeout(&mut Context::from_waker(Waker::noop()))
    }

    fn elapsed_timer() -> PingTimer {
        PingTimer::new(|_| Box::pin(std::future::ready(())))
    }

    #[test]
    fn timeout_follows_the_timer_not_the_clock() {
        let mut waiting = in_flight(PingTimer::new(|_| Box::pin(std::future::pending())));
        waiting.last_read = Instant::now() - Duration::from_secs(60);
        assert!(poll(&mut waiting).is_pending());

        let mut elapsed = in_flight(elapsed_timer());
        assert!(poll(&mut elapsed).is_ready());
        assert!(poll(&mut elapsed).is_pending(), "expiry is reported once");
    }

    #[test]
    fn a_read_during_a_sleep_arms_another() {
        let mut preface_ping = in_flight(elapsed_timer());
        preface_ping.recv_frame(Instant::now(), None);
        // The first sleep saw a read, so a second one runs; it sees none.
        assert!(poll(&mut preface_ping).is_ready());
        assert_eq!(preface_ping.armed_at_read, None);
    }

    #[test]
    fn the_ack_disarms_the_timeout() {
        let mut preface_ping = in_flight(elapsed_timer());
        assert!(preface_ping.recv_frame(Instant::now(), Some(&PAYLOAD)));
        assert!(poll(&mut preface_ping).is_pending());
    }
}
