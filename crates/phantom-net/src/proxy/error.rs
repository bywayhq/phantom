use std::{error::Error as StdError, fmt};

/// Stable category of HTTP CONNECT failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HttpConnectErrorKind {
    /// The CONNECT authority or ordered fields are invalid.
    InvalidRequest,
    /// The request was polled outside a Tokio runtime.
    RuntimeUnavailable,
    /// Connecting to the proxy failed.
    Connect,
    /// Proxy request or response I/O failed.
    Io,
    /// The proxy response was malformed or exceeded a bound.
    InvalidResponse,
    /// The proxy rejected the tunnel request.
    Rejected,
}

/// Error returned before an HTTP CONNECT tunnel is established.
#[derive(Debug)]
#[non_exhaustive]
pub enum HttpConnectError {
    /// The CONNECT target is not a valid authority with an explicit port.
    InvalidAuthority,
    /// The complete CONNECT request exceeded the field-count bound.
    TooManyHeaders {
        /// Number of ordered CONNECT fields.
        count: usize,
        /// Maximum accepted field count.
        maximum: usize,
    },
    /// The complete CONNECT request exceeded the byte bound.
    RequestHeadTooLarge {
        /// Attempted request-head size.
        bytes: usize,
        /// Maximum accepted request-head size.
        maximum: usize,
    },
    /// A caller-supplied field name is invalid.
    InvalidHeaderName {
        /// Zero-based position in the caller-supplied field list.
        index: usize,
    },
    /// A caller-supplied field value is invalid.
    InvalidHeaderValue {
        /// Zero-based position in the caller-supplied field list.
        index: usize,
    },
    /// `Host` must use the destination-dependent authority placeholder.
    AuthorityHeader,
    /// CONNECT requests cannot contain request-body framing fields.
    RequestFramingHeader,
    /// The CONNECT field sequence contains no authority placeholder.
    MissingAuthorityHeader,
    /// The CONNECT field sequence contains more than one authority placeholder.
    MultipleAuthorityHeaders,
    /// The proxy request was polled outside a Tokio runtime.
    RuntimeUnavailable,
    /// Establishing the TCP connection to the proxy failed.
    Connect(std::io::Error),
    /// Writing the CONNECT request failed.
    Write(std::io::Error),
    /// Reading the CONNECT response failed.
    Read(std::io::Error),
    /// The CONNECT response head exceeded the fixed byte bound.
    ResponseHeadTooLarge {
        /// Maximum accepted response-head size.
        maximum: usize,
    },
    /// The proxy sent too many informational responses before a final status.
    TooManyInformationalResponses {
        /// Maximum accepted informational response count.
        maximum: usize,
    },
    /// The proxy returned an invalid HTTP/1 response head.
    InvalidResponse,
    /// The proxy returned a non-success status.
    Rejected {
        /// HTTP response status returned by the proxy.
        status: u16,
    },
}

impl HttpConnectError {
    /// Returns the stable failure category.
    #[must_use]
    pub fn kind(&self) -> HttpConnectErrorKind {
        match self {
            Self::InvalidAuthority
            | Self::TooManyHeaders { .. }
            | Self::RequestHeadTooLarge { .. }
            | Self::InvalidHeaderName { .. }
            | Self::InvalidHeaderValue { .. }
            | Self::AuthorityHeader
            | Self::RequestFramingHeader
            | Self::MissingAuthorityHeader
            | Self::MultipleAuthorityHeaders => HttpConnectErrorKind::InvalidRequest,
            Self::RuntimeUnavailable => HttpConnectErrorKind::RuntimeUnavailable,
            Self::Connect(_) => HttpConnectErrorKind::Connect,
            Self::Write(_) | Self::Read(_) => HttpConnectErrorKind::Io,
            Self::ResponseHeadTooLarge { .. }
            | Self::TooManyInformationalResponses { .. }
            | Self::InvalidResponse => HttpConnectErrorKind::InvalidResponse,
            Self::Rejected { .. } => HttpConnectErrorKind::Rejected,
        }
    }
}

impl fmt::Display for HttpConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAuthority => formatter
                .write_str("HTTP CONNECT target must be a valid authority with an explicit port"),
            Self::TooManyHeaders { count, maximum } => write!(
                formatter,
                "HTTP CONNECT has {count} fields; maximum is {maximum}"
            ),
            Self::RequestHeadTooLarge { bytes, maximum } => write!(
                formatter,
                "HTTP CONNECT request head has {bytes} bytes; maximum is {maximum}"
            ),
            Self::InvalidHeaderName { index } => {
                write!(formatter, "HTTP CONNECT field {index} has an invalid name")
            }
            Self::InvalidHeaderValue { index } => {
                write!(formatter, "HTTP CONNECT field {index} has an invalid value")
            }
            Self::AuthorityHeader => {
                formatter.write_str("HTTP CONNECT Host must use the authority placeholder")
            }
            Self::RequestFramingHeader => {
                formatter.write_str("HTTP CONNECT must not contain request framing fields")
            }
            Self::MissingAuthorityHeader => {
                formatter.write_str("HTTP CONNECT fields must contain one authority placeholder")
            }
            Self::MultipleAuthorityHeaders => formatter
                .write_str("HTTP CONNECT fields must not contain multiple authority placeholders"),
            Self::RuntimeUnavailable => {
                formatter.write_str("HTTP CONNECT requires a Tokio runtime")
            }
            Self::Connect(error) => write!(formatter, "proxy TCP connection failed: {error}"),
            Self::Write(error) => write!(formatter, "HTTP CONNECT request write failed: {error}"),
            Self::Read(error) => write!(formatter, "HTTP CONNECT response read failed: {error}"),
            Self::ResponseHeadTooLarge { maximum } => write!(
                formatter,
                "HTTP CONNECT response head exceeds {maximum} bytes"
            ),
            Self::TooManyInformationalResponses { maximum } => write!(
                formatter,
                "HTTP CONNECT response exceeds {maximum} informational responses"
            ),
            Self::InvalidResponse => {
                formatter.write_str("proxy returned an invalid HTTP CONNECT response")
            }
            Self::Rejected { status } => {
                write!(
                    formatter,
                    "proxy rejected HTTP CONNECT with status {status}"
                )
            }
        }
    }
}

impl StdError for HttpConnectError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Connect(error) | Self::Write(error) | Self::Read(error) => Some(error),
            _ => None,
        }
    }
}

impl HttpConnectErrorKind {
    pub(super) const fn trace_name(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::RuntimeUnavailable => "runtime_unavailable",
            Self::Connect => "connect_error",
            Self::Io => "io_error",
            Self::InvalidResponse => "invalid_response",
            Self::Rejected => "rejected",
        }
    }
}
