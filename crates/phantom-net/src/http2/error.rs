//! Errors returned by one-shot HTTP/2 transactions.

use std::{error::Error as StdError, fmt};

use phantom_profile::InvalidHttp2Settings;

use crate::request::RequestBodyError;

/// Stable classification of an HTTP/2 protocol-driver failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http2ProtocolErrorKind {
    /// The underlying byte transport failed.
    Transport,
    /// An HTTP/2 stream was reset.
    StreamReset,
    /// The HTTP/2 connection was closed with `GOAWAY`.
    ConnectionError,
    /// A protocol error code was produced without a stream reset or `GOAWAY`.
    Protocol,
    /// The backend rejected a local operation.
    Local,
}

/// HTTP/2 protocol-driver failure without exposing the backend error type.
#[derive(Debug)]
pub struct Http2ProtocolError {
    kind: Http2ProtocolErrorKind,
    reason_code: Option<u32>,
    source: ::http2::Error,
}

impl Http2ProtocolError {
    fn new(source: ::http2::Error) -> Self {
        let kind = if source.is_io() {
            Http2ProtocolErrorKind::Transport
        } else if source.is_reset() {
            Http2ProtocolErrorKind::StreamReset
        } else if source.is_go_away() {
            Http2ProtocolErrorKind::ConnectionError
        } else if source.reason().is_some() {
            Http2ProtocolErrorKind::Protocol
        } else {
            Http2ProtocolErrorKind::Local
        };
        let reason_code = source.reason().map(u32::from);
        Self {
            kind,
            reason_code,
            source,
        }
    }

    fn stream_reset(reason: ::http2::Reason) -> Self {
        Self {
            kind: Http2ProtocolErrorKind::StreamReset,
            reason_code: Some(u32::from(reason)),
            source: ::http2::Error::from(reason),
        }
    }

    /// Returns the stable failure classification.
    #[must_use]
    pub fn kind(&self) -> Http2ProtocolErrorKind {
        self.kind
    }

    /// Returns the HTTP/2 error code when the failure carried one.
    #[must_use]
    pub fn reason_code(&self) -> Option<u32> {
        self.reason_code
    }

    /// Returns whether a frame received from the peer ended this operation.
    ///
    /// This is `true` for a received `RST_STREAM` (kind
    /// [`StreamReset`](Http2ProtocolErrorKind::StreamReset)) or a received
    /// `GOAWAY` (kind [`ConnectionError`](Http2ProtocolErrorKind::ConnectionError)).
    /// Locally detected protocol errors, transport failures, and a reset
    /// observed while uploading the request body, whose initiator is not
    /// recorded, are `false`.
    ///
    /// A received `GOAWAY` fails a request only when its stream identifier is
    /// above the frame's last-stream-id, or when the request was refused
    /// before its stream opened; RFC 9113, sections 6.8 and 8.7, state that
    /// such streams were not processed. Streams at or below the
    /// last-stream-id keep running, and a later connection close fails them
    /// as [`Transport`](Http2ProtocolErrorKind::Transport), never as a remote
    /// `GOAWAY`.
    #[must_use]
    pub fn is_remote(&self) -> bool {
        self.source.is_remote()
    }
}

impl fmt::Display for Http2ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl StdError for Http2ProtocolError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.source)
    }
}

/// Error returned by a one-shot HTTP/2 transaction.
#[derive(Debug)]
pub enum Http2Error {
    /// The HTTP/2 profile is internally inconsistent.
    InvalidSettings(InvalidHttp2Settings),
    /// The profile contains a setting this transport version cannot translate.
    UnsupportedSetting,
    /// The request stream was configured to depend on itself.
    InvalidPriorityDependency {
        /// Stream ID used by this one-shot transport.
        stream_id: u32,
    },
    /// A per-request priority has a weight outside 1..=256 or a dependency
    /// stream ID wider than 31 bits.
    InvalidPriority {
        /// Requested dependency stream ID.
        dependency_stream_id: u32,
        /// Requested RFC 7540 weight.
        weight: u16,
    },
    /// The request authority is not a valid URI authority.
    InvalidAuthority(http::uri::InvalidUri),
    /// The request authority included forbidden URI user information.
    AuthorityContainsUserinfo,
    /// Standard CONNECT cannot be represented by an origin-form target.
    ConnectUnsupported,
    /// The profile has no verified extended CONNECT pseudo-header order.
    MissingExtendedConnectPseudoHeaderOrder,
    /// This connection was not created with the extended CONNECT pseudo-header order.
    ExtendedConnectConnectionRequired,
    /// The peer did not enable extended CONNECT in its initial settings.
    ExtendedConnectProtocolDisabled,
    /// The internally composed HTTPS request URI was rejected.
    InvalidRequestUri(http::Error),
    /// The request contained more headers than the fixed safety bound.
    TooManyHeaders {
        /// Number of supplied headers.
        count: usize,
        /// Maximum accepted number of headers.
        maximum: usize,
    },
    /// The aggregate request header bytes exceeded the fixed safety bound.
    HeadersTooLarge {
        /// Number of supplied field-name and field-value bytes.
        bytes: usize,
        /// Maximum accepted aggregate bytes.
        maximum: usize,
    },
    /// The request contained more trailer fields than the fixed safety bound.
    TooManyTrailers {
        /// Number of supplied trailer fields.
        count: usize,
        /// Maximum accepted number of trailer fields.
        maximum: usize,
    },
    /// The aggregate request trailer bytes exceeded the fixed safety bound.
    TrailersTooLarge {
        /// Number of supplied trailer field-name and field-value bytes.
        bytes: usize,
        /// Maximum accepted aggregate bytes.
        maximum: usize,
    },
    /// Static trailers and body-produced trailers were configured together.
    ConflictingRequestTrailers,
    /// Body-produced trailers were passed to a metadata-only validator.
    BodyTrailerPlanRequired,
    /// A request field name was invalid or not entirely lowercase.
    InvalidHeaderName {
        /// Position in the ordered header list.
        index: usize,
    },
    /// A request field value contained bytes forbidden by HTTP.
    InvalidHeaderValue {
        /// Position in the ordered header list.
        index: usize,
        /// Field name supplied at that position.
        name: Box<str>,
    },
    /// A request trailer name was invalid or not entirely lowercase.
    InvalidTrailerName {
        /// Position in the ordered trailer list.
        index: usize,
    },
    /// A request trailer value contained bytes forbidden by HTTP.
    InvalidTrailerValue {
        /// Position in the ordered trailer list.
        index: usize,
        /// Field name supplied at that position.
        name: Box<str>,
    },
    /// A field forbidden in an HTTP/2 request was supplied.
    ForbiddenHeader {
        /// Forbidden field name.
        name: Box<str>,
    },
    /// A field forbidden in an HTTP/2 trailer block was supplied.
    ForbiddenTrailer {
        /// Forbidden trailer field name.
        name: Box<str>,
    },
    /// `TE` had a value other than the exact token `trailers`.
    InvalidTe,
    /// `Content-Length` was not the canonical decimal request-body length.
    InvalidContentLength {
        /// Position in the ordered header list.
        index: usize,
    },
    /// More than one `Content-Length` field was supplied.
    DuplicateContentLength {
        /// Position of the duplicate field in the ordered header list.
        index: usize,
    },
    /// `Content-Length` was supplied for a body without an exact size hint.
    ContentLengthRequiresExactBody {
        /// Position of the rejected field in the ordered header list.
        index: usize,
    },
    /// Pulling the caller-provided request body failed.
    RequestBody(RequestBodyError),
    /// The erased request body returned a frame other than DATA.
    UnsupportedRequestBodyFrame,
    /// The peer closed the request stream before the body was sent.
    RequestBodyClosed,
    /// The validated fields could not fit in the semantic header map.
    HeaderMapCapacity,
    /// The HTTP backend completed a response without its ordered field capture.
    MissingResponseHeaderOrder,
    /// A response header list exceeded the receive limit, and the stream was
    /// reset with `PROTOCOL_ERROR`.
    ///
    /// The limit is the lower of the profile's advertised
    /// `SETTINGS_MAX_HEADER_LIST_SIZE` and an unadvertised 393,216-byte
    /// ceiling, counted as in RFC 9113 section 6.5.2.
    ResponseHeaderListTooLarge,
    /// The peer sent more interim `1xx` responses than the fixed bound, and
    /// the stream was reset with `ENHANCE_YOUR_CALM`.
    TooManyInformationalResponses {
        /// Maximum accepted interim responses before the final response.
        maximum: usize,
    },
    /// A PING sent under the profile's
    /// [`preface_ping_after`](phantom_profile::Http2Settings::preface_ping_after)
    /// went unanswered, with nothing read from the peer, for its
    /// [`ping_timeout`](phantom_profile::Http2Settings::ping_timeout).
    ///
    /// The connection sent `GOAWAY` with `PROTOCOL_ERROR` and closed, so every
    /// request on it fails with this error. Chromium reports the same event
    /// as `ERR_HTTP2_PING_FAILED`.
    PingTimeout,
    /// The connection had already closed after an unanswered PING when this
    /// request reached it, so nothing of the request was sent.
    ///
    /// A client may send the request again on another connection.
    ReusedConnectionClosed,
    /// The connection was polled outside a Tokio runtime, or the timer a
    /// profile's [`ping_timeout`](phantom_profile::Http2Settings::ping_timeout)
    /// needs could not be started.
    RuntimeUnavailable,
    /// The HTTP protocol driver failed.
    Protocol(Http2ProtocolError),
}

impl fmt::Display for Http2Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSettings(error) => error.fmt(formatter),
            Self::UnsupportedSetting => formatter.write_str(
                "HTTP/2 profile contains a setting unsupported by this transport version",
            ),
            Self::InvalidPriorityDependency { stream_id } => write!(
                formatter,
                "HTTP/2 request stream {stream_id} cannot depend on itself"
            ),
            Self::InvalidPriority {
                dependency_stream_id,
                weight,
            } => write!(
                formatter,
                "HTTP/2 request priority depending on stream {dependency_stream_id} with weight \
                 {weight} needs a 31-bit stream ID and a weight in 1..=256"
            ),
            Self::InvalidAuthority(_) => formatter.write_str("request authority is invalid"),
            Self::AuthorityContainsUserinfo => {
                formatter.write_str("request authority must not contain URI user information")
            }
            Self::ConnectUnsupported => {
                formatter.write_str("HTTP/2 CONNECT requires an authority-form request API")
            }
            Self::MissingExtendedConnectPseudoHeaderOrder => formatter.write_str(
                "HTTP/2 profile does not configure an extended CONNECT pseudo-header order",
            ),
            Self::ExtendedConnectConnectionRequired => formatter.write_str(
                "HTTP/2 connection was not configured for exact extended CONNECT pseudo-header order",
            ),
            Self::ExtendedConnectProtocolDisabled => formatter.write_str(
                "HTTP/2 peer did not enable extended CONNECT in its initial settings",
            ),
            Self::InvalidRequestUri(_) => {
                formatter.write_str("failed to compose the absolute HTTPS request URI")
            }
            Self::TooManyHeaders { count, maximum } => {
                write!(
                    formatter,
                    "request has {count} headers; maximum is {maximum}"
                )
            }
            Self::HeadersTooLarge { bytes, maximum } => write!(
                formatter,
                "request field names and values total {bytes} bytes; maximum is {maximum}"
            ),
            Self::TooManyTrailers { count, maximum } => {
                write!(
                    formatter,
                    "request has {count} trailer fields; maximum is {maximum}"
                )
            }
            Self::TrailersTooLarge { bytes, maximum } => write!(
                formatter,
                "request trailer field names and values total {bytes} bytes; maximum is {maximum}"
            ),
            Self::ConflictingRequestTrailers => formatter.write_str(
                "static and streaming-body-produced HTTP/2 request trailers cannot be combined",
            ),
            Self::BodyTrailerPlanRequired => formatter
                .write_str("body-produced HTTP/2 request trailers require source-aware validation"),
            Self::InvalidHeaderName { index } => write!(
                formatter,
                "request header at index {index} has an invalid or non-lowercase field name"
            ),
            Self::InvalidHeaderValue { index, name } => write!(
                formatter,
                "request header {name:?} at index {index} has an invalid field value"
            ),
            Self::InvalidTrailerName { index } => write!(
                formatter,
                "request trailer at index {index} has an invalid or non-lowercase field name"
            ),
            Self::InvalidTrailerValue { index, name } => write!(
                formatter,
                "request trailer {name:?} at index {index} has an invalid field value"
            ),
            Self::ForbiddenHeader { name } => {
                write!(formatter, "{name} is not allowed on this HTTP/2 request")
            }
            Self::ForbiddenTrailer { name } => {
                write!(
                    formatter,
                    "{name} is not allowed in HTTP/2 request trailers"
                )
            }
            Self::InvalidTe => {
                formatter.write_str("HTTP/2 TE must have the exact value `trailers`")
            }
            Self::InvalidContentLength { index } => write!(
                formatter,
                "request content-length at index {index} must equal the canonical decimal body length"
            ),
            Self::DuplicateContentLength { index } => write!(
                formatter,
                "request content-length at index {index} duplicates an earlier field"
            ),
            Self::ContentLengthRequiresExactBody { index } => write!(
                formatter,
                "request content-length at index {index} requires a body with an exact size hint"
            ),
            Self::RequestBody(error) => write!(formatter, "HTTP/2 request body failed: {error}"),
            Self::UnsupportedRequestBodyFrame => {
                formatter.write_str("HTTP/2 request body returned an unsupported frame")
            }
            Self::RequestBodyClosed => {
                formatter.write_str("HTTP/2 request body stream closed before completion")
            }
            Self::HeaderMapCapacity => {
                formatter.write_str("request fields exceed the semantic header-map capacity")
            }
            Self::MissingResponseHeaderOrder => {
                formatter.write_str("HTTP/2 response header order was not captured")
            }
            Self::ResponseHeaderListTooLarge => {
                formatter.write_str("HTTP/2 response header list exceeded the receive limit")
            }
            Self::TooManyInformationalResponses { maximum } => write!(
                formatter,
                "HTTP/2 response sent more than {maximum} informational responses; stream reset"
            ),
            Self::PingTimeout => formatter
                .write_str("HTTP/2 PING went unanswered; the connection was closed with GOAWAY"),
            Self::ReusedConnectionClosed => formatter.write_str(
                "HTTP/2 connection closed after an unanswered PING before the request was sent",
            ),
            Self::RuntimeUnavailable => {
                formatter.write_str("HTTP/2 connections require a Tokio runtime")
            }
            Self::Protocol(error) => write!(formatter, "HTTP/2 protocol error: {error}"),
        }
    }
}

impl StdError for Http2Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::InvalidSettings(error) => Some(error),
            Self::InvalidAuthority(error) => Some(error),
            Self::InvalidRequestUri(error) => Some(error),
            Self::RequestBody(error) => Some(error),
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}

impl Http2Error {
    pub(super) fn protocol(error: ::http2::Error) -> Self {
        if error.is_header_list_too_large() {
            return Self::ResponseHeaderListTooLarge;
        }
        if error.is_ping_timeout() {
            return Self::PingTimeout;
        }
        if error.is_too_many_informational_responses() {
            return Self::TooManyInformationalResponses {
                maximum: super::limits::MAX_INFORMATIONAL_RESPONSES,
            };
        }
        Self::Protocol(Http2ProtocolError::new(error))
    }

    /// Maps a failure to open a request stream, before any of the request
    /// was written.
    pub(super) fn before_send(error: ::http2::Error) -> Self {
        if error.is_ping_timeout() {
            return Self::ReusedConnectionClosed;
        }
        Self::protocol(error)
    }

    pub(super) fn stream_reset(reason: ::http2::Reason) -> Self {
        Self::Protocol(Http2ProtocolError::stream_reset(reason))
    }

    pub(super) fn trace_kind(&self) -> &'static str {
        match self {
            Self::InvalidSettings(_) => "invalid_settings",
            Self::UnsupportedSetting => "unsupported_setting",
            Self::InvalidPriorityDependency { .. } => "invalid_priority_dependency",
            Self::InvalidPriority { .. } => "invalid_priority",
            Self::InvalidAuthority(_) => "invalid_authority",
            Self::AuthorityContainsUserinfo => "authority_contains_userinfo",
            Self::ConnectUnsupported => "connect_unsupported",
            Self::MissingExtendedConnectPseudoHeaderOrder => {
                "missing_extended_connect_pseudo_header_order"
            }
            Self::ExtendedConnectConnectionRequired => "extended_connect_connection_required",
            Self::ExtendedConnectProtocolDisabled => "extended_connect_protocol_disabled",
            Self::InvalidRequestUri(_) => "invalid_request_uri",
            Self::TooManyHeaders { .. } => "too_many_headers",
            Self::HeadersTooLarge { .. } => "headers_too_large",
            Self::TooManyTrailers { .. } => "too_many_trailers",
            Self::TrailersTooLarge { .. } => "trailers_too_large",
            Self::ConflictingRequestTrailers => "conflicting_request_trailers",
            Self::BodyTrailerPlanRequired => "body_trailer_plan_required",
            Self::InvalidHeaderName { .. } => "invalid_header_name",
            Self::InvalidHeaderValue { .. } => "invalid_header_value",
            Self::InvalidTrailerName { .. } => "invalid_trailer_name",
            Self::InvalidTrailerValue { .. } => "invalid_trailer_value",
            Self::ForbiddenHeader { .. } => "forbidden_header",
            Self::ForbiddenTrailer { .. } => "forbidden_trailer",
            Self::InvalidTe => "invalid_te",
            Self::InvalidContentLength { .. } => "invalid_content_length",
            Self::DuplicateContentLength { .. } => "duplicate_content_length",
            Self::ContentLengthRequiresExactBody { .. } => "content_length_requires_exact_body",
            Self::RequestBody(_) => "request_body",
            Self::UnsupportedRequestBodyFrame => "unsupported_request_body_frame",
            Self::RequestBodyClosed => "request_body_closed",
            Self::HeaderMapCapacity => "header_map_capacity",
            Self::MissingResponseHeaderOrder => "missing_response_header_order",
            Self::ResponseHeaderListTooLarge => "response_header_list_too_large",
            Self::TooManyInformationalResponses { .. } => "too_many_informational_responses",
            Self::PingTimeout => "ping_timeout",
            Self::ReusedConnectionClosed => "reused_connection_closed",
            Self::RuntimeUnavailable => "runtime_unavailable",
            Self::Protocol(_) => "protocol",
        }
    }
}
