use crate::frame::{Frame, Ping};

use bytes::Buf;
use std::time::{Duration, Instant};

/// Decides when a client PING follows a request frame on a connection that
/// has read nothing for longer than a configured time.
///
/// A PING is due after request HEADERS, or after a DATA frame with a
/// non-empty payload, when the last frame read from the peer is older than
/// `idle` and no earlier such PING awaits its ACK. It is written before any
/// other frame. The first PING carries the big-endian 64-bit value 1 and each
/// later one the next value. The ACK is matched by payload.
#[derive(Debug)]
pub(super) struct PrefacePing {
    idle: Duration,
    last_read: Instant,
    next_payload: u64,
    in_flight: Option<[u8; 8]>,
    due: Option<[u8; 8]>,
}

impl PrefacePing {
    pub(super) fn new(idle: Duration) -> Self {
        PrefacePing {
            idle,
            last_read: Instant::now(),
            next_payload: 1,
            in_flight: None,
            due: None,
        }
    }

    /// Records a frame read from the peer. Returns `true` when `ack` is the
    /// acknowledgement of the PING in flight, which this consumes.
    pub(super) fn recv_frame(&mut self, now: Instant, ack: Option<&[u8; 8]>) -> bool {
        self.last_read = now;
        match ack {
            Some(payload) if self.in_flight.as_ref() == Some(payload) => {
                self.in_flight = None;
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
    }

    /// Takes the PING due after the last request frame, if any.
    pub(super) fn take_due(&mut self) -> Option<Ping> {
        self.due.take().map(Ping::new)
    }
}
