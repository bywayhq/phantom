use std::{error, fmt, io, sync::Arc};

use bytes::Bytes;

use crate::codec::{SendError, UserError};
pub use crate::frame::Reason;
use crate::frame::StreamId;
use crate::proto::{self, Initiator};

/// Represents HTTP/2 operation errors.
///
/// `Error` covers error cases raised by protocol errors caused by the
/// peer, I/O (transport) errors, and errors caused by the user of the library.
///
/// If the error was caused by the remote peer, then it will contain a
/// [`Reason`] which can be obtained with the [`reason`] function.
///
/// [`Reason`]: struct.Reason.html
/// [`reason`]: #method.reason
#[derive(Debug)]
pub struct Error {
    kind: Kind,
    local_limit: Option<LocalLimit>,
}

/// A local receive limit whose violation made the library reset a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LocalLimit {
    /// The decoded header list exceeded the local receive limit.
    HeaderListSize,
    /// The peer sent more informational responses than the client allows.
    InformationalResponses,
}

#[derive(Debug)]
enum Kind {
    /// A RST_STREAM frame was received or sent.
    #[allow(dead_code)]
    Reset(StreamId, Reason, Initiator),

    /// A GO_AWAY frame was received or sent.
    GoAway(Bytes, Reason, Initiator),

    /// The user created an error from a bare Reason.
    Reason(Reason),

    /// An error resulting from an invalid action taken by the user of this
    /// library.
    User(UserError),

    /// An `io::Error` occurred while trying to read or write.
    Io(Arc<io::Error>),
}

// ===== impl Error =====

impl Error {
    /// If the error was caused by the remote peer, the error reason.
    ///
    /// This is either an error received by the peer or caused by an invalid
    /// action taken by the peer (i.e. a protocol error).
    pub fn reason(&self) -> Option<Reason> {
        match self.kind {
            Kind::Reset(_, reason, _) | Kind::GoAway(_, reason, _) | Kind::Reason(reason) => {
                Some(reason)
            }
            _ => None,
        }
    }

    /// Returns true if the error is an io::Error
    pub fn is_io(&self) -> bool {
        matches!(self.kind, Kind::Io(..))
    }

    /// Borrows the original transport error, including its payload and OS code.
    pub fn get_io(&self) -> Option<&io::Error> {
        match self.kind {
            Kind::Io(ref e) => Some(e.as_ref()),
            _ => None,
        }
    }

    /// Returns the shared original transport error, or `None` for other errors.
    ///
    /// The connection and its failed streams share this same error.
    pub fn into_io(self) -> Option<Arc<io::Error>> {
        match self.kind {
            Kind::Io(e) => Some(e),
            _ => None,
        }
    }

    pub(crate) fn from_io(err: io::Error) -> Self {
        Error {
            kind: Kind::Io(Arc::new(err)),
            local_limit: None,
        }
    }

    /// Returns true if the error is from a `GOAWAY`.
    pub fn is_go_away(&self) -> bool {
        matches!(self.kind, Kind::GoAway(..))
    }

    /// Returns true if the error is from a `RST_STREAM`.
    pub fn is_reset(&self) -> bool {
        matches!(self.kind, Kind::Reset(..))
    }

    /// Returns true if the error was received in a frame from the remote.
    ///
    /// Such as from a received `RST_STREAM` or `GOAWAY` frame.
    pub fn is_remote(&self) -> bool {
        matches!(
            self.kind,
            Kind::GoAway(_, _, Initiator::Remote) | Kind::Reset(_, _, Initiator::Remote)
        )
    }

    /// Returns true if the error was created by `http2`.
    ///
    /// Such as noticing some protocol error and sending a GOAWAY or RST_STREAM.
    pub fn is_library(&self) -> bool {
        matches!(
            self.kind,
            Kind::GoAway(_, _, Initiator::Library) | Kind::Reset(_, _, Initiator::Library)
        )
    }

    /// Returns true if the library reset the stream because a received header
    /// list exceeded the local receive limit.
    ///
    /// The limit is the lower of the advertised `SETTINGS_MAX_HEADER_LIST_SIZE`
    /// and any unadvertised client limit. The stream is still reset with
    /// `PROTOCOL_ERROR`, so this does not change the frames sent to the peer.
    pub fn is_header_list_too_large(&self) -> bool {
        self.local_limit == Some(LocalLimit::HeaderListSize)
    }

    /// Returns true if the library closed the connection because a preface
    /// PING went unanswered, with nothing read from the peer, for the time
    /// set by `client::Builder::preface_ping_timeout`, or an idle PING for
    /// the timeout set by `client::Builder::idle_ping`.
    ///
    /// For a preface PING the connection sent GOAWAY with `PROTOCOL_ERROR` and
    /// the debug data `Failed ping.` before closing; for an idle PING, GOAWAY
    /// with `INTERNAL_ERROR` and no debug data. Nothing else in the library
    /// closes a connection with `INTERNAL_ERROR`.
    pub fn is_ping_timeout(&self) -> bool {
        match self.kind {
            Kind::GoAway(ref debug_data, Reason::PROTOCOL_ERROR, Initiator::Library) => {
                debug_data.as_ref() == proto::PING_TIMEOUT_DEBUG_DATA
            }
            Kind::GoAway(ref debug_data, Reason::INTERNAL_ERROR, Initiator::Library) => {
                debug_data.is_empty()
            }
            _ => false,
        }
    }

    /// Returns true if the library reset the stream because the peer sent more
    /// informational (1xx) responses than the client's configured maximum.
    pub fn is_too_many_informational_responses(&self) -> bool {
        self.local_limit == Some(LocalLimit::InformationalResponses)
    }

    /// Marks a library stream reset with the local limit that caused it.
    pub(crate) fn from_stream_reset(src: proto::Error, local_limit: Option<LocalLimit>) -> Self {
        let local_limit = match src {
            proto::Error::Reset(_, _, Initiator::Library) => local_limit,
            _ => None,
        };
        Error {
            local_limit,
            ..src.into()
        }
    }
}

impl From<proto::Error> for Error {
    fn from(src: proto::Error) -> Error {
        use crate::proto::Error::*;

        Error {
            kind: match src {
                Reset(stream_id, reason, initiator) => Kind::Reset(stream_id, reason, initiator),
                GoAway(debug_data, reason, initiator) => {
                    Kind::GoAway(debug_data, reason, initiator)
                }
                Io(error) => Kind::Io(error),
            },
            local_limit: None,
        }
    }
}

impl From<Reason> for Error {
    fn from(src: Reason) -> Error {
        Error {
            kind: Kind::Reason(src),
            local_limit: None,
        }
    }
}

impl From<SendError> for Error {
    fn from(src: SendError) -> Error {
        match src {
            SendError::User(e) => e.into(),
            SendError::Connection(e) => e.into(),
        }
    }
}

impl From<UserError> for Error {
    fn from(src: UserError) -> Error {
        Error {
            kind: Kind::User(src),
            local_limit: None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let debug_data = match self.kind {
            Kind::Reset(_, reason, Initiator::User) => {
                return write!(fmt, "stream error sent by user: {}", reason)
            }
            Kind::Reset(_, reason, Initiator::Library) => {
                return write!(fmt, "stream error detected: {}", reason)
            }
            Kind::Reset(_, reason, Initiator::Remote) => {
                return write!(fmt, "stream error received: {}", reason)
            }
            Kind::GoAway(ref debug_data, reason, Initiator::User) => {
                write!(fmt, "connection error sent by user: {}", reason)?;
                debug_data
            }
            Kind::GoAway(ref debug_data, reason, Initiator::Library) => {
                write!(fmt, "connection error detected: {}", reason)?;
                debug_data
            }
            Kind::GoAway(ref debug_data, reason, Initiator::Remote) => {
                write!(fmt, "connection error received: {}", reason)?;
                debug_data
            }
            Kind::Reason(reason) => return write!(fmt, "protocol error: {}", reason),
            Kind::User(ref e) => return write!(fmt, "user error: {}", e),
            Kind::Io(ref e) => return e.fmt(fmt),
        };

        if !debug_data.is_empty() {
            write!(fmt, " ({:?})", debug_data)?;
        }

        Ok(())
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        self.get_io()
            .map(|error| error as &(dyn error::Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::Error;
    use crate::Reason;

    #[test]
    fn error_from_reason() {
        let err = Error::from(Reason::HTTP_1_1_REQUIRED);
        assert_eq!(err.reason(), Some(Reason::HTTP_1_1_REQUIRED));
    }

    #[test]
    fn direct_io_error_keeps_its_payload_and_public_source() {
        let payload = "https://example.test/invalid uri"
            .parse::<http::Uri>()
            .expect_err("invalid static URI was accepted");
        let error = Error::from_io(io::Error::new(io::ErrorKind::PermissionDenied, payload));
        let original = error.get_io().expect("direct I/O error missing");
        assert!(matches!(
            original.get_ref(),
            Some(cause) if cause.is::<http::uri::InvalidUri>()
        ));

        let source = std::error::Error::source(&error)
            .and_then(|cause| cause.downcast_ref::<io::Error>())
            .expect("direct I/O source missing");
        assert!(std::ptr::eq(original, source));

        let owned = error.into_io().expect("direct I/O owner missing");
        assert_eq!(owned.kind(), io::ErrorKind::PermissionDenied);
        assert!(matches!(
            owned.get_ref(),
            Some(cause) if cause.is::<http::uri::InvalidUri>()
        ));
    }

    #[test]
    fn kind_only_io_error_keeps_its_kind_and_source() {
        let error = Error::from(crate::proto::Error::from(io::ErrorKind::UnexpectedEof));
        let original = error.get_io().expect("kind-only I/O error missing");
        assert_eq!(original.kind(), io::ErrorKind::UnexpectedEof);
        assert!(original.get_ref().is_none());

        let source = std::error::Error::source(&error)
            .and_then(|cause| cause.downcast_ref::<io::Error>())
            .expect("kind-only I/O source missing");
        assert!(std::ptr::eq(original, source));
    }
}
