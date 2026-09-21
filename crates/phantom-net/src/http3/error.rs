use std::{error::Error as StdError, fmt};

/// Stable category of a forced HTTP/3 transaction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http3ErrorKind {
    /// The request cannot be represented by the current HTTP/3 path.
    Request,
    /// The selected QUIC transport profile is incompatible with the runtime.
    Configuration,
    /// No current Tokio runtime with network I/O enabled was available.
    RuntimeUnavailable,
    /// The local UDP or QUIC endpoint could not be initialized.
    Endpoint,
    /// The remote QUIC connection could not be started.
    Connect,
    /// QUIC failed while establishing or driving the connection.
    Connection,
    /// The TLS handshake did not produce the required HTTP/3 state.
    Handshake,
    /// The HTTP/3 connection or request stream failed.
    Protocol,
    /// The local request driver was no longer available.
    Local,
    /// The peer did not enable extended CONNECT in its SETTINGS.
    ///
    /// No request stream was opened, and no other protocol was attempted.
    ExtendedConnectUnavailable,
}

impl Http3ErrorKind {
    pub(super) const fn trace_name(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Configuration => "configuration",
            Self::RuntimeUnavailable => "runtime_unavailable",
            Self::Endpoint => "endpoint",
            Self::Connect => "connect",
            Self::Connection => "connection",
            Self::Handshake => "handshake",
            Self::Protocol => "protocol",
            Self::Local => "local",
            Self::ExtendedConnectUnavailable => "extended_connect_unavailable",
        }
    }
}

/// Error returned by a forced HTTP/3 transaction.
#[derive(Debug)]
pub struct Http3Error {
    kind: Http3ErrorKind,
    message: &'static str,
    source: Option<Box<dyn StdError + Send + Sync>>,
}

impl Http3Error {
    pub(super) fn with_source(
        kind: Http3ErrorKind,
        message: &'static str,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            message,
            source: Some(Box::new(source)),
        }
    }

    pub(super) const fn without_source(kind: Http3ErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            message,
            source: None,
        }
    }

    pub(super) fn request_body(source: crate::request::RequestBodyError) -> Self {
        Self::with_source(
            Http3ErrorKind::Request,
            "HTTP/3 request body failed",
            source,
        )
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> Http3ErrorKind {
        self.kind
    }

    pub(super) const fn trace_kind(&self) -> &'static str {
        self.kind.trace_name()
    }
}

impl fmt::Display for Http3Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl StdError for Http3Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}

impl From<h3::error::StreamError> for Http3Error {
    fn from(error: h3::error::StreamError) -> Self {
        Self::with_source(
            Http3ErrorKind::Protocol,
            "HTTP/3 request stream failed",
            error,
        )
    }
}
