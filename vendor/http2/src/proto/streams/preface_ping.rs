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
/// With a timeout, a PING in flight expires once nothing has been read for
/// the timeout since the later of its queueing and the last read. This is
/// the deadline Chromium's `SpdySession::CheckPingStatus` enforces: its
/// first check runs a timeout after the PING, and each later one a timeout
/// after the last read.
pub(super) struct PrefacePing {
    idle: Duration,
    last_read: Instant,
    next_payload: u64,
    in_flight: Option<[u8; 8]>,
    due: Option<[u8; 8]>,
    timeout: Option<(Duration, PingTimer)>,
    /// When the PING in flight was queued, until it expires or is answered.
    queued_at: Option<Instant>,
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
            sleep: None,
        }
    }

    /// Records a frame read from the peer. Returns `true` when `ack` is the
    /// acknowledgement of the PING in flight, which this consumes.
    pub(super) fn recv_frame(&mut self, now: Instant, ack: Option<&[u8; 8]>) -> bool {
        self.last_read = now;
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
        self.queued_at = Some(now);
    }

    /// Returns `Ready` once, when the PING in flight has waited the timeout
    /// with nothing read. Without a timeout it never does.
    pub(super) fn poll_timeout(&mut self, cx: &mut Context) -> Poll<()> {
        let (timeout, timer) = match &self.timeout {
            Some((timeout, timer)) => (*timeout, timer),
            None => return Poll::Pending,
        };
        loop {
            let quiet_since = match self.queued_at {
                Some(queued_at) => queued_at.max(self.last_read),
                None => return Poll::Pending,
            };
            let quiet = Instant::now().saturating_duration_since(quiet_since);
            if quiet >= timeout {
                self.queued_at = None;
                self.sleep = None;
                return Poll::Ready(());
            }
            // A read since the sleep started moves the deadline later, so an
            // elapsed sleep only means the deadline is checked again.
            let sleep = self
                .sleep
                .get_or_insert_with(|| timer.sleep(timeout - quiet));
            if sleep.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
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
