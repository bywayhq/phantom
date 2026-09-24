use std::{error::Error as StdError, fmt};

/// Stable category of a forced HTTP/3 transaction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

/// Peer signal that a request was not processed and may be sent again.
///
/// A request carrying this signal was either refused by the peer before any
/// processing or never sent at all. No response head was received.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3Unprocessed {
    /// The peer reset the request stream or stopped reading it with
    /// `H3_REQUEST_REJECTED` before a response head. RFC 9114, section 4.1.1,
    /// forbids that code for a request that was partially or fully processed.
    RequestRejected,
    /// The peer's `GOAWAY` was received before this request opened a stream,
    /// so the request was never sent. RFC 9114, section 5.2, forbids new
    /// requests on a connection after its `GOAWAY`.
    ///
    /// A request whose stream was already open when `GOAWAY` arrived is never
    /// reported here: the HTTP/3 backend does not expose the `GOAWAY`
    /// identifier needed to prove that its stream was not processed.
    GoAway,
    /// The request was sent as early (0-RTT) data and the server rejected
    /// that data. RFC 9001, section 4.6.2: rejected 0-RTT packets are not
    /// processed. Requests that waited for the handshake on the same
    /// connection report this too, because Quinn reset the streams the
    /// HTTP/3 connection opened before the handshake.
    EarlyDataRejected,
}

/// Error returned by a forced HTTP/3 transaction.
#[derive(Debug)]
pub struct Http3Error {
    kind: Http3ErrorKind,
    message: &'static str,
    unprocessed: Option<Http3Unprocessed>,
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
            unprocessed: None,
            source: Some(Box::new(source)),
        }
    }

    pub(super) const fn without_source(kind: Http3ErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            message,
            unprocessed: None,
            source: None,
        }
    }

    pub(super) const fn early_data_rejected() -> Self {
        Self {
            kind: Http3ErrorKind::Protocol,
            message: "the server rejected early data; the request was not processed",
            unprocessed: Some(Http3Unprocessed::EarlyDataRejected),
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

    /// Classifies a failure to open a request stream.
    ///
    /// `RemoteClosing` here means the peer's `GOAWAY` arrived before the
    /// stream was opened, so no request byte was sent.
    pub(super) fn request_open(error: h3::error::StreamError) -> Self {
        let unprocessed = match &error {
            h3::error::StreamError::RemoteClosing => Some(Http3Unprocessed::GoAway),
            _ => rejected(&error),
        };
        Self {
            unprocessed,
            ..Self::from(error)
        }
    }

    /// Classifies a request-stream failure observed before any response head.
    pub(super) fn request_stream(error: h3::error::StreamError) -> Self {
        Self {
            unprocessed: rejected(&error),
            ..Self::from(error)
        }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> Http3ErrorKind {
        self.kind
    }

    /// Returns the peer's signal that this request was not processed.
    ///
    /// Only a request that failed before its response head can carry a
    /// signal. `None` means the request may have been processed.
    #[must_use]
    pub const fn unprocessed(&self) -> Option<Http3Unprocessed> {
        self.unprocessed
    }

    pub(super) const fn trace_kind(&self) -> &'static str {
        self.kind.trace_name()
    }
}

/// `RemoteTerminate` covers both a received `RESET_STREAM` and a received
/// `STOP_SENDING` on the request stream.
fn rejected(error: &h3::error::StreamError) -> Option<Http3Unprocessed> {
    matches!(
        error,
        h3::error::StreamError::RemoteTerminate { code, .. }
            if *code == h3::error::Code::H3_REQUEST_REJECTED
    )
    .then_some(Http3Unprocessed::RequestRejected)
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
