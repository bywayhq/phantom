//! Extensions specific to the HTTP/2 protocol.

use crate::frame::{PseudoOrder, StreamDependency};
use crate::hpack::BytesStr;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue};
use std::fmt;

/// Exact wire order for ordinary header fields.
///
/// Store this value in a request's extensions to control its field order.
/// Received requests and responses also carry this value in their extensions
/// with the order produced by HPACK decoding. Pseudo-headers are excluded.
/// Outgoing ordered fields must describe the same semantic multimap as the
/// request's [`HeaderMap`], including duplicate values and their per-name
/// order, or the request is rejected as malformed. Global field-name order is
/// intentionally ignored during that comparison because `HeaderMap` does not
/// preserve it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderedHeaders {
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl OrderedHeaders {
    /// Creates an owned ordinary-header order.
    #[must_use]
    pub fn new(headers: Vec<(HeaderName, HeaderValue)>) -> Self {
        Self { headers }
    }

    /// Returns the ordered ordinary fields.
    #[must_use]
    pub fn as_slice(&self) -> &[(HeaderName, HeaderValue)] {
        &self.headers
    }

    pub(crate) fn agrees_with(&self, semantic: &HeaderMap) -> bool {
        let mut reconstructed = HeaderMap::new();
        for (name, value) in &self.headers {
            if reconstructed.try_append(name, value.clone()).is_err() {
                return false;
            }
        }
        reconstructed.eq(semantic)
    }

    pub(crate) fn into_inner(self) -> Vec<(HeaderName, HeaderValue)> {
        self.headers
    }
}

/// Per-request overrides for a client request's initial HEADERS frame.
///
/// Store this value in a request's extensions to replace the connection's
/// configured pseudo-header order or RFC 7540 stream dependency for that one
/// request. An unset value keeps the connection default. A peer that disabled
/// RFC 7540 priorities still suppresses the priority fields.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HeadersFrameOverrides {
    pseudo_order: Option<PseudoOrder>,
    stream_dependency: Option<StreamDependency>,
}

impl HeadersFrameOverrides {
    /// Creates overrides that keep every connection default.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the connection's pseudo-header order for this request.
    #[must_use]
    pub fn pseudo_order(mut self, order: PseudoOrder) -> Self {
        self.pseudo_order = Some(order);
        self
    }

    /// Replaces the connection's HEADERS stream dependency for this request.
    #[must_use]
    pub fn stream_dependency(mut self, dependency: StreamDependency) -> Self {
        self.stream_dependency = Some(dependency);
        self
    }

    pub(crate) fn into_parts(self) -> (Option<PseudoOrder>, Option<StreamDependency>) {
        (self.pseudo_order, self.stream_dependency)
    }
}

/// One ALTSVC frame (RFC 7838 section 4) received by a client.
#[derive(Clone, Eq, PartialEq)]
pub struct AltSvc {
    origin: Option<Bytes>,
    field_value: Bytes,
}

impl AltSvc {
    pub(crate) fn from_frame(frame: crate::frame::AltSvc) -> Self {
        let origin = if frame.stream_id().is_zero() {
            Some(frame.origin().clone())
        } else {
            None
        };
        Self {
            origin,
            field_value: frame.field_value().clone(),
        }
    }

    /// Returns the `Origin` of a connection-scoped frame received on stream 0.
    ///
    /// A frame received on the response's own stream has no origin field;
    /// its origin is the request's origin.
    #[must_use]
    pub fn origin(&self) -> Option<&[u8]> {
        self.origin.as_deref()
    }

    /// Returns the frame's `Alt-Svc-Field-Value`, with `Alt-Svc` field syntax.
    #[must_use]
    pub fn field_value(&self) -> &[u8] {
        &self.field_value
    }
}

impl fmt::Debug for AltSvc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AltSvc")
            .field("connection_scoped", &self.origin.is_some())
            .field("field_value_len", &self.field_value.len())
            .finish()
    }
}

/// ALTSVC frames delivered with one client response, in arrival order.
///
/// A client attaches this value to a final response when the connection
/// received ALTSVC frames on stream 0, or on the response's stream before its
/// final HEADERS. Each queued frame is delivered with exactly one response.
/// Servers ignore ALTSVC frames and never attach this value.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AltSvcFrames {
    frames: Vec<AltSvc>,
}

impl AltSvcFrames {
    pub(crate) fn new(frames: Vec<AltSvc>) -> Self {
        Self { frames }
    }

    /// Returns the received frames in arrival order.
    #[must_use]
    pub fn as_slice(&self) -> &[AltSvc] {
        &self.frames
    }
}

/// Represents the `:protocol` pseudo-header used by
/// the [Extended CONNECT Protocol].
///
/// [Extended CONNECT Protocol]: https://datatracker.ietf.org/doc/html/rfc8441#section-4
#[derive(Clone, Eq, PartialEq)]
pub struct Protocol {
    value: BytesStr,
}

impl Protocol {
    /// Converts a static string to a protocol name.
    pub const fn from_static(value: &'static str) -> Self {
        Self {
            value: BytesStr::from_static(value),
        }
    }

    /// Returns a str representation of the header.
    pub fn as_str(&self) -> &str {
        self.value.as_str()
    }

    pub(crate) fn try_from(bytes: Bytes) -> Result<Self, std::str::Utf8Error> {
        Ok(Self {
            value: BytesStr::try_from(bytes)?,
        })
    }
}

impl<'a> From<&'a str> for Protocol {
    fn from(value: &'a str) -> Self {
        Self {
            value: BytesStr::from(value),
        }
    }
}

impl AsRef<[u8]> for Protocol {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.value.fmt(f)
    }
}
