//! Errors returned by one-shot HTTP/2 transactions.

use std::{error::Error as StdError, fmt};

use phantom_profile::InvalidHttp2Settings;

/// Stable classification of an HTTP/2 protocol-driver failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
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
#[non_exhaustive]
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
    /// The request authority is not a valid URI authority.
    InvalidAuthority(http::uri::InvalidUri),
    /// The request authority included forbidden URI user information.
    AuthorityContainsUserinfo,
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
    /// A field forbidden in an HTTP/2 request was supplied.
    ForbiddenHeader {
        /// Forbidden field name.
        name: Box<str>,
    },
    /// `TE` had a value other than the exact token `trailers`.
    InvalidTe,
    /// `Content-Length` was not the exact decimal value `0` for the empty GET.
    InvalidContentLength {
        /// Position in the ordered header list.
        index: usize,
    },
    /// The validated fields could not fit in the semantic header map.
    HeaderMapCapacity,
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
            Self::InvalidAuthority(_) => formatter.write_str("request authority is invalid"),
            Self::AuthorityContainsUserinfo => {
                formatter.write_str("request authority must not contain URI user information")
            }
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
            Self::InvalidHeaderName { index } => write!(
                formatter,
                "request header at index {index} has an invalid or non-lowercase field name"
            ),
            Self::InvalidHeaderValue { index, name } => write!(
                formatter,
                "request header {name:?} at index {index} has an invalid field value"
            ),
            Self::ForbiddenHeader { name } => {
                write!(formatter, "{name} is not allowed on this HTTP/2 request")
            }
            Self::InvalidTe => {
                formatter.write_str("HTTP/2 TE must have the exact value `trailers`")
            }
            Self::InvalidContentLength { index } => write!(
                formatter,
                "request content-length at index {index} must be the exact value `0` for an empty GET"
            ),
            Self::HeaderMapCapacity => {
                formatter.write_str("request fields exceed the semantic header-map capacity")
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
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}

impl Http2Error {
    pub(super) fn protocol(error: ::http2::Error) -> Self {
        Self::Protocol(Http2ProtocolError::new(error))
    }

    pub(super) fn trace_kind(&self) -> &'static str {
        match self {
            Self::InvalidSettings(_) => "invalid_settings",
            Self::UnsupportedSetting => "unsupported_setting",
            Self::InvalidPriorityDependency { .. } => "invalid_priority_dependency",
            Self::InvalidAuthority(_) => "invalid_authority",
            Self::AuthorityContainsUserinfo => "authority_contains_userinfo",
            Self::InvalidRequestUri(_) => "invalid_request_uri",
            Self::TooManyHeaders { .. } => "too_many_headers",
            Self::HeadersTooLarge { .. } => "headers_too_large",
            Self::InvalidHeaderName { .. } => "invalid_header_name",
            Self::InvalidHeaderValue { .. } => "invalid_header_value",
            Self::ForbiddenHeader { .. } => "forbidden_header",
            Self::InvalidTe => "invalid_te",
            Self::InvalidContentLength { .. } => "invalid_content_length",
            Self::HeaderMapCapacity => "header_map_capacity",
            Self::Protocol(_) => "protocol",
        }
    }
}
