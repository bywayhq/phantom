//! Extensions for the HTTP/3 protocol.

use std::str::FromStr;

use http::{HeaderMap, HeaderName, HeaderValue};

/// Exact field order for the ordinary fields of an outgoing request.
///
/// The ordered fields must describe the same semantic multimap as the
/// request's [`HeaderMap`], including duplicate values and their per-name
/// order and sensitivity markers, or the request is rejected. The current
/// stateless QPACK encoder does not emit the QPACK never-indexed bit from a
/// [`HeaderValue`]'s sensitivity marker.
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
        reconstructed.len() == semantic.len()
            && semantic.keys().all(|name| {
                let ordered = reconstructed.get_all(name).iter().collect::<Vec<_>>();
                let semantic = semantic.get_all(name).iter().collect::<Vec<_>>();
                ordered.len() == semantic.len()
                    && ordered
                        .into_iter()
                        .zip(semantic)
                        .all(|(ordered, semantic)| {
                            ordered.as_bytes() == semantic.as_bytes()
                                && ordered.is_sensitive() == semantic.is_sensitive()
                        })
            })
    }

    pub(crate) fn into_inner(self) -> Vec<(HeaderName, HeaderValue)> {
        self.headers
    }
}

/// A request pseudo-header in its encoded field-section order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RequestPseudoHeader {
    /// `:method`.
    Method,
    /// `:authority`.
    Authority,
    /// `:scheme`.
    Scheme,
    /// `:path`.
    Path,
    /// `:protocol`.
    Protocol,
}

/// Exact pseudo-header order for an outgoing request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestPseudoHeaderOrder {
    headers: Vec<RequestPseudoHeader>,
}

impl RequestPseudoHeaderOrder {
    /// Creates an owned request pseudo-header order.
    #[must_use]
    pub fn new(headers: Vec<RequestPseudoHeader>) -> Self {
        Self { headers }
    }

    /// Returns the ordered request pseudo-headers.
    #[must_use]
    pub fn as_slice(&self) -> &[RequestPseudoHeader] {
        &self.headers
    }

    pub(crate) fn into_inner(self) -> Vec<RequestPseudoHeader> {
        self.headers
    }
}

/// Describes the `:protocol` pseudo-header for extended connect
///
/// See: <https://www.rfc-editor.org/rfc/rfc8441#section-4>
#[derive(Copy, PartialEq, Debug, Clone)]
pub struct Protocol(ProtocolInner);

impl Protocol {
    /// WebTransport protocol
    pub const WEB_TRANSPORT: Protocol = Protocol(ProtocolInner::WebTransport);
    /// RFC 9298 protocol
    pub const CONNECT_UDP: Protocol = Protocol(ProtocolInner::ConnectUdp);
    /// RFC 9484 protocol
    pub const CONNECT_IP: Protocol = Protocol(ProtocolInner::ConnectIp);
    /// RFC 9220 (WebSocket) protocol
    pub const WEBSOCKET: Protocol = Protocol(ProtocolInner::WebSocket);

    /// Return a &str representation of the `:protocol` pseudo-header value
    #[inline]
    pub fn as_str(&self) -> &str {
        match self.0 {
            ProtocolInner::WebTransport => "webtransport",
            ProtocolInner::ConnectUdp => "connect-udp",
            ProtocolInner::ConnectIp => "connect-ip",
            ProtocolInner::WebSocket => "websocket",
        }
    }
}

#[derive(Copy, PartialEq, Debug, Clone)]
enum ProtocolInner {
    WebTransport,
    ConnectUdp,
    ConnectIp,
    WebSocket,
}

/// Error when parsing the protocol
pub struct InvalidProtocol;

impl FromStr for Protocol {
    type Err = InvalidProtocol;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "webtransport" => Ok(Self(ProtocolInner::WebTransport)),
            "connect-udp" => Ok(Self(ProtocolInner::ConnectUdp)),
            "connect-ip" => Ok(Self(ProtocolInner::ConnectIp)),
            "websocket" => Ok(Self(ProtocolInner::WebSocket)),
            _ => Err(InvalidProtocol),
        }
    }
}
