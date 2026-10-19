use std::{error::Error as StdError, fmt};

use btls::ssl::{SessionTransferError, SslConnector, SslMethod};
use zeroize::Zeroizing;

use super::{
    binding::PreparationError, envelope::EnvelopeError, staging::ColdError, transfer::ExportError,
    transfer_import::ImportError,
};
use crate::Client;

const MAX_SNAPSHOT: usize = 16 * 1024 * 1024;

/// Encrypted session tickets and their authenticated configuration bindings.
///
/// Keep this snapshot and its key private. Together they allow another client
/// with matching settings to resume the captured sessions. The format is
/// tied to this library and its TLS backend; it is not a portable browser
/// ticket format. Debug formatting omits its contents.
pub struct SessionTicketSnapshot(Zeroizing<Vec<u8>>);

impl SessionTicketSnapshot {
    /// Copies encrypted bytes after checking the 16 MiB size bound.
    ///
    /// This does not authenticate or import them. Use
    /// [`Client::import_session_tickets`] to validate the complete snapshot.
    ///
    /// # Errors
    ///
    /// Returns a size or allocation error without retaining a partial copy.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SessionTicketError> {
        if bytes.len() > MAX_SNAPSHOT {
            return Err(SessionTicketError::without_source(
                SessionTicketErrorKind::TooLarge,
            ));
        }
        let mut owned = Zeroizing::new(Vec::new());
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| SessionTicketError::without_source(SessionTicketErrorKind::Allocation))?;
        owned.extend_from_slice(bytes);
        Ok(Self(owned))
    }

    /// Returns the encrypted bytes for storage or transfer.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SessionTicketSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionTicketSnapshot")
            .finish_non_exhaustive()
    }
}

/// The category of a session-ticket operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SessionTicketErrorKind {
    /// A snapshot or one of its owner or record counts exceeds a library bound.
    TooLarge,
    /// A bounded buffer could not be allocated.
    Allocation,
    /// Snapshot framing or native session encoding is invalid.
    InvalidSnapshot,
    /// The snapshot did not authenticate with the supplied key.
    Authentication,
    /// The snapshot format or compiled TLS backend differs.
    IncompatibleBackend,
    /// A retained session has expired.
    Expired,
    /// The origin, peer, profile, credentials or installed policy does not match.
    Policy,
    /// The snapshot contains an unsupported route or protocol owner.
    Unsupported,
    /// A native policy lock is in use. The caller may retry later.
    Busy,
    /// The TLS backend or a retained registry failed.
    Backend,
}

/// A session-ticket failure whose formatting omits snapshot and key contents.
pub struct SessionTicketError {
    kind: SessionTicketErrorKind,
    source: Option<Box<dyn StdError + Send + Sync>>,
}

impl SessionTicketError {
    /// Returns the failure category.
    #[must_use]
    pub fn kind(&self) -> SessionTicketErrorKind {
        self.kind
    }

    fn without_source(kind: SessionTicketErrorKind) -> Self {
        Self { kind, source: None }
    }

    pub(super) fn with_source(source: impl StdError + Send + Sync + 'static) -> Self {
        Self {
            kind: classify(&source),
            source: Some(Box::new(source)),
        }
    }
}

impl fmt::Debug for SessionTicketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionTicketError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for SessionTicketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            SessionTicketErrorKind::TooLarge => "session ticket snapshot exceeds a library bound",
            SessionTicketErrorKind::Allocation => "session ticket allocation failed",
            SessionTicketErrorKind::InvalidSnapshot => "invalid session ticket snapshot",
            SessionTicketErrorKind::Authentication => {
                "session ticket snapshot authentication failed"
            }
            SessionTicketErrorKind::IncompatibleBackend => "incompatible session ticket snapshot",
            SessionTicketErrorKind::Expired => {
                "session ticket snapshot contains an expired session"
            }
            SessionTicketErrorKind::Policy => "session ticket configuration does not match",
            SessionTicketErrorKind::Unsupported => "session ticket owner is unsupported",
            SessionTicketErrorKind::Busy => "session ticket policy is busy",
            SessionTicketErrorKind::Backend => "session ticket backend failed",
        })
    }
}

impl StdError for SessionTicketError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source.as_deref().map(|source| source as &dyn StdError)
    }
}

fn classify(error: &(dyn StdError + 'static)) -> SessionTicketErrorKind {
    use SessionTicketErrorKind as Kind;

    let mut kind = Kind::Backend;
    let mut next = Some(error);
    while let Some(error) = next {
        if let Some(error) = error.downcast_ref::<SessionTransferError>() {
            kind = match error {
                SessionTransferError::TooLarge => Kind::TooLarge,
                SessionTransferError::Allocation => Kind::Allocation,
                SessionTransferError::Malformed => Kind::InvalidSnapshot,
                SessionTransferError::Authentication => Kind::Authentication,
                SessionTransferError::IncompatibleBackend => Kind::IncompatibleBackend,
                SessionTransferError::Expired => Kind::Expired,
                SessionTransferError::Busy => Kind::Busy,
                SessionTransferError::Policy
                | SessionTransferError::Credentials
                | SessionTransferError::Unauthenticated
                | SessionTransferError::Consumed => Kind::Policy,
                _ => Kind::Backend,
            };
        } else if let Some(error) = error.downcast_ref::<EnvelopeError>() {
            kind = match error {
                EnvelopeError::TooLarge => Kind::TooLarge,
                EnvelopeError::Allocation => Kind::Allocation,
                EnvelopeError::Malformed => Kind::InvalidSnapshot,
                EnvelopeError::Authentication => Kind::Authentication,
                EnvelopeError::IncompatibleFormat => Kind::IncompatibleBackend,
                EnvelopeError::UnsupportedEmptyCredentials | EnvelopeError::UnsupportedProtocol => {
                    Kind::Unsupported
                }
                EnvelopeError::Backend(_) => Kind::Backend,
            };
        } else if let Some(error) = error.downcast_ref::<PreparationError>() {
            kind = match error {
                PreparationError::TooLarge => Kind::TooLarge,
                PreparationError::Allocation => Kind::Allocation,
                PreparationError::Unsupported(_) => Kind::Unsupported,
                PreparationError::DrawMismatch => Kind::Policy,
                PreparationError::Backend => Kind::Backend,
            };
        } else if let Some(error) = error.downcast_ref::<ImportError>() {
            kind = match error {
                ImportError::TooLarge => Kind::TooLarge,
                ImportError::Allocation => Kind::Allocation,
                ImportError::OwnerMapping => Kind::Policy,
                ImportError::Application(_) => Kind::InvalidSnapshot,
                ImportError::UnsupportedRoute
                | ImportError::EmptyCredentials
                | ImportError::AmbiguousSharing => Kind::Unsupported,
                _ => kind,
            };
        } else if let Some(error) = error.downcast_ref::<ExportError>() {
            kind = match error {
                ExportError::AmbiguousSharing => Kind::Unsupported,
                ExportError::TooLarge => Kind::TooLarge,
                ExportError::Allocation => Kind::Allocation,
                ExportError::ConflictingOwner | ExportError::InvalidCapture => Kind::Policy,
                _ => kind,
            };
        } else if let Some(error) = error.downcast_ref::<ColdError>() {
            kind = match error {
                ColdError::TooLarge => Kind::TooLarge,
                ColdError::Allocation => Kind::Allocation,
                ColdError::Mapping => Kind::Policy,
                ColdError::UnsupportedOwner => Kind::Unsupported,
                _ => kind,
            };
        }
        next = error.source();
    }
    kind
}

impl Client {
    /// Exports this client's retained TCP TLS and QUIC session tickets.
    ///
    /// Supply a secret, randomly generated 32-byte key. Keep it separate from
    /// the returned snapshot. Export preserves the source caches and pending
    /// imported owners. Clones share those caches.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use phantom::{Client, SessionTicketError};
    ///
    /// fn transfer(source: &Client, recipient: &Client, key: &[u8; 32])
    ///     -> Result<(), SessionTicketError>
    /// {
    ///     let snapshot = source.export_session_tickets(key)?;
    ///     recipient.import_session_tickets(&snapshot, key, &[])
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Rejects the complete export if any live owner lacks supported policy
    /// or exceeds the 256-owner, 2,560-record or
    /// 16 MiB bounds. Already-expired live entries are excluded. Expired records
    /// retained in cold custody, and records that expire during preparation,
    /// return an expiry error.
    /// A busy native policy returns an error without consuming source tickets.
    /// Custom TCP connectors return [`SessionTicketErrorKind::Unsupported`]
    /// because their callbacks have no persistent route identity.
    pub fn export_session_tickets(
        &self,
        key: &[u8; 32],
    ) -> Result<SessionTicketSnapshot, SessionTicketError> {
        if self.inner.custom_tcp_connector {
            return Err(SessionTicketError::without_source(
                SessionTicketErrorKind::Unsupported,
            ));
        }
        self.state
            .tickets
            .export(key)
            .map(|sealed| SessionTicketSnapshot(sealed.into_bytes()))
            .map_err(SessionTicketError::with_source)
    }

    /// Imports matching TCP TLS and QUIC session tickets without network I/O.
    ///
    /// The key must match the export key. Every owner must match this client's
    /// profile, peer identity, certificate settings and receiving route.
    /// Supply request-only proxy routes in `receiving_routes`. The selected
    /// client route and actual live owner routes are considered too. This list
    /// does not change how later requests are routed. At most 256 routes may
    /// be supplied. The owner's protocol must be configured. Owners without
    /// a cache stay private until first use. An empty owner clears its matching
    /// cache. Unmentioned owners keep their tickets. Import replaces caches;
    /// existing connections continue working.
    /// If installation before first use fails, the request returns
    /// [`RequestErrorKind::SessionTickets`](crate::RequestErrorKind::SessionTickets)
    /// without being sent. Pending tickets remain available for another attempt.
    ///
    /// # Errors
    ///
    /// Authenticates and validates every owner before replacing any cache.
    /// Rejects malformed, incompatible or expired snapshots, unsupported
    /// settings and empty credentialed owners. Failure preserves live and pending
    /// tickets. Native policy contention can be retried by the caller.
    /// Custom TCP connectors return [`SessionTicketErrorKind::Unsupported`].
    pub fn import_session_tickets(
        &self,
        snapshot: &SessionTicketSnapshot,
        key: &[u8; 32],
        receiving_routes: &[crate::Route],
    ) -> Result<(), SessionTicketError> {
        if self.inner.custom_tcp_connector {
            return Err(SessionTicketError::without_source(
                SessionTicketErrorKind::Unsupported,
            ));
        }
        let context = SslConnector::builder(SslMethod::tls())
            .map_err(SessionTicketError::with_source)?
            .build()
            .into_context();
        let _ = self
            .state
            .tickets
            .import_for_client(
                snapshot.as_bytes(),
                key,
                &context,
                &self.inner,
                receiving_routes,
            )
            .map_err(SessionTicketError::with_source)?;
        Ok(())
    }
}
