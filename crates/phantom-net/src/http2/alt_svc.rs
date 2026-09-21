//! RFC 7838 section 4 ALTSVC frames surfaced with HTTP/2 responses.

use std::fmt;

use bytes::Bytes;

/// Where an ALTSVC frame applies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AltSvcFrameScope {
    /// Received on stream 0 with this serialized `Origin`, unvalidated.
    Connection(Bytes),
    /// Received on the response's own stream; the request origin applies.
    Stream,
}

/// One ALTSVC frame received before a response's final HEADERS.
#[derive(Clone, Eq, PartialEq)]
pub struct AltSvcFrame {
    scope: AltSvcFrameScope,
    field_value: Bytes,
}

impl AltSvcFrame {
    /// Returns where the frame applies.
    #[must_use]
    pub fn scope(&self) -> &AltSvcFrameScope {
        &self.scope
    }

    /// Returns the `Alt-Svc-Field-Value`, which uses `Alt-Svc` field syntax.
    #[must_use]
    pub fn field_value(&self) -> &[u8] {
        &self.field_value
    }
}

impl fmt::Debug for AltSvcFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AltSvcFrame")
            .field(
                "connection_scoped",
                &matches!(self.scope, AltSvcFrameScope::Connection(_)),
            )
            .field("field_value_len", &self.field_value.len())
            .finish()
    }
}

/// ALTSVC frames attached to one HTTP/2 response, in arrival order.
///
/// The extension is present only when the connection received a valid,
/// client-bound frame on stream 0 or on the response's stream before its final
/// HEADERS. Each frame is attached to exactly one response. The connection
/// bounds frames awaiting delivery and discards malformed frames.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AltSvcFrames {
    frames: Vec<AltSvcFrame>,
}

impl AltSvcFrames {
    pub(super) fn from_http2(frames: &::http2::ext::AltSvcFrames) -> Self {
        Self {
            frames: frames
                .as_slice()
                .iter()
                .map(|frame| AltSvcFrame {
                    scope: match frame.origin() {
                        Some(origin) => {
                            AltSvcFrameScope::Connection(Bytes::copy_from_slice(origin))
                        }
                        None => AltSvcFrameScope::Stream,
                    },
                    field_value: Bytes::copy_from_slice(frame.field_value()),
                })
                .collect(),
        }
    }

    /// Returns the frames in arrival order.
    #[must_use]
    pub fn as_slice(&self) -> &[AltSvcFrame] {
        &self.frames
    }
}
