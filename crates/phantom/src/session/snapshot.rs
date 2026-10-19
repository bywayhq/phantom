//! Versioned checkpoints of the state that has supported persistence.

use std::{collections::HashMap, error::Error as StdError, fmt, time::SystemTime};

use zeroize::Zeroizing;

use crate::{Client, Route, SessionSharing, SessionTicketSnapshot};

mod codec;
mod envelope;

pub(in crate::session) const MAX_BYTES: usize = 32 * 1024 * 1024;
#[cfg(feature = "cookies")]
const MAX_COOKIES: usize = 16_384;
const MAX_ALTERNATIVES: usize = 32_768;

/// An authenticated, encrypted version-2 session checkpoint.
///
/// Includes enabled cookies, direct-route Alt-Svc alternatives and TLS tickets.
/// Explicitly opted-in HTTPS discovery includes completed answers and ECH.
/// It contains no address DNS cache, client hints, connections,
/// hooks or serialized client configuration. Keep the key separate from the
/// checkpoint. Its format is tied to this library and its TLS backend.
/// Debug formatting omits its contents.
pub struct SessionSnapshot(Zeroizing<Vec<u8>>);

impl SessionSnapshot {
    /// Copies checkpoint bytes after checking the 32 MiB bound.
    ///
    /// This does not authenticate them. [`Client::restore_session`] performs
    /// authentication and validates all state against receiving configuration.
    ///
    /// # Errors
    /// Returns a size or allocation error without retaining a partial copy.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SessionSnapshotError> {
        Ok(Self(codec::copy(bytes, MAX_BYTES)?))
    }

    /// Returns encrypted bytes for caller-owned storage.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SessionSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionSnapshot").finish_non_exhaustive()
    }
}

/// Why a session checkpoint operation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SessionSnapshotErrorKind {
    /// A checkpoint or section exceeds a documented resource bound.
    TooLarge,
    /// A bounded allocation failed.
    Allocation,
    /// Framing or state encoding is invalid.
    InvalidSnapshot,
    /// The checkpoint did not authenticate with the supplied key.
    Authentication,
    /// The format, profile, trust, certificate or default route differs.
    Incompatible,
    /// The receiving client has a disabled category present in the checkpoint.
    Disabled,
    /// Receiving cookie, Alt-Svc or HTTPS-answer capacity would discard live entries.
    Capacity,
    /// Configuration has no supported checkpoint identity.
    Unsupported,
    /// Existing native ticket validation or custody rejected the checkpoint.
    Tickets,
    /// Cookie validation rejected an entry.
    Cookies,
    /// Alt-Svc validation rejected an entry.
    AltSvc,
    /// A cryptographic backend operation failed.
    Backend,
}

/// A checkpoint failure. Formatting never includes keys or stored state.
#[derive(Debug)]
pub struct SessionSnapshotError {
    kind: SessionSnapshotErrorKind,
    source: Option<Box<dyn StdError + Send + Sync>>,
}

impl SessionSnapshotError {
    pub(in crate::session) fn new(kind: SessionSnapshotErrorKind) -> Self {
        Self { kind, source: None }
    }

    fn source(
        kind: SessionSnapshotErrorKind,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            source: Some(Box::new(source)),
        }
    }

    /// Returns the failure category.
    #[must_use]
    pub const fn kind(&self) -> SessionSnapshotErrorKind {
        self.kind
    }
}

impl fmt::Display for SessionSnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "session checkpoint failed: {:?}", self.kind)
    }
}

impl StdError for SessionSnapshotError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source.as_deref().map(|source| source as _)
    }
}

impl From<btls::error::ErrorStack> for SessionSnapshotError {
    fn from(source: btls::error::ErrorStack) -> Self {
        Self::source(SessionSnapshotErrorKind::Backend, source)
    }
}

impl From<super::PreparationError> for SessionSnapshotError {
    fn from(source: super::PreparationError) -> Self {
        use super::PreparationError;
        let kind = match source {
            PreparationError::TooLarge => SessionSnapshotErrorKind::TooLarge,
            PreparationError::Allocation => SessionSnapshotErrorKind::Allocation,
            PreparationError::Unsupported(_) => SessionSnapshotErrorKind::Unsupported,
            PreparationError::DrawMismatch => SessionSnapshotErrorKind::Incompatible,
            PreparationError::Backend => SessionSnapshotErrorKind::Backend,
        };
        Self::source(kind, source)
    }
}

struct State {
    context: Zeroizing<Vec<u8>>,
    #[cfg(feature = "cookies")]
    cookies: Option<crate::CookieSnapshot>,
    alt_svc: Option<crate::AltSvcSnapshot>,
    #[cfg(feature = "https-records")]
    https_records: Option<super::alt_svc::https_record_snapshot::HttpsRecordSnapshot>,
    tickets: SessionTicketSnapshot,
}

impl Client {
    fn snapshot_context(&self) -> Result<Zeroizing<Vec<u8>>, SessionSnapshotError> {
        if self.inner.custom_tcp_connector {
            return Err(super::PreparationError::Unsupported(
                "session checkpoints with custom TCP connectors",
            )
            .into());
        }
        let policy = self
            .inner
            .ticket_preparation
            .as_ref()
            .map_err(|error| *error)?;
        let route = self.inner.session_snapshot_route()?;
        Ok(policy.session_snapshot_context(&route)?)
    }

    /// Exports supported state into an encrypted session checkpoint.
    ///
    /// Supply a secret random 32-byte key. Cookies, direct-route Alt-Svc and
    /// tickets retain their existing order and expiry. Opted-in HTTPS discovery
    /// includes whole completed answers, including ECH and negative SOA TTLs.
    /// Export does not consume tickets. Categories are sampled separately, so
    /// concurrent changes are not one atomic point in time. No network or
    /// storage I/O occurs.
    ///
    /// # Errors
    /// Rejects more than 16,384 cookies, 32,768 Alt-Svc alternatives, 64 KiB
    /// fields, or 32 MiB overall. HTTPS discovery permits 65,535 entries,
    /// records per answer and bytes per encoded record. Native tickets retain
    /// their 16 MiB, 256-owner and 2,560-record bounds. Custom TCP connectors, environment
    /// proxy routing, default routes with configured credentials, SOCKS4 default
    /// routes, and unsupported ticket policies return an error. No category is
    /// silently omitted. HTTPS discovery requires an explicit portable resolver
    /// namespace. Paired native resolver configurations are unsupported.
    pub fn export_session(&self, key: &[u8; 32]) -> Result<SessionSnapshot, SessionSnapshotError> {
        let state = State {
            context: self.snapshot_context()?,
            #[cfg(feature = "cookies")]
            cookies: self.export_cookies(),
            alt_svc: self.export_alt_svc(),
            #[cfg(feature = "https-records")]
            https_records: self
                .state
                .https_records
                .as_ref()
                .map(|discovery| {
                    discovery.export_checkpoint(
                        self.state
                            .options
                            .https_record_checkpoint_namespace
                            .as_deref(),
                    )
                })
                .transpose()?,
            tickets: self.export_session_tickets(key).map_err(|error| {
                SessionSnapshotError::source(SessionSnapshotErrorKind::Tickets, error)
            })?,
        };
        envelope::seal(codec::encode(&state)?, key).map(SessionSnapshot)
    }

    /// Restores a checkpoint into fresh independent pools using this client's settings.
    ///
    /// The receiving profile, trust, certificates, source binding and default
    /// route must match. Supply request-only ticket routes in `receiving_routes`,
    /// as for [`Self::import_session_tickets`]. Existing cookies and caches in
    /// this client are not copied or changed. Returned state is independent.
    /// Address DNS, client hints and racing history start empty. HTTPS discovery
    /// must have the same enabled state and explicit portable resolver namespace.
    /// Hooks and custom resolver callback state remain caller owned, as with
    /// [`Self::fork`]. Configuration is supplied by this client, not deserialized.
    ///
    /// Expired cookies, alternatives and HTTPS answers are discarded without
    /// extending expiry. HTTPS answers preserve response order and LRU order.
    /// Their remaining lifetime is capped by both their absolute expiry and
    /// original DNS TTL. Absolute expiry depends on the system wall clock.
    /// Pending HTTPS lookups and operational-error backoff are not restored.
    /// Expired tickets follow native import's rejection rules. No live entry is
    /// silently dropped to fit smaller receiving limits. An error never exposes
    /// a partially restored client or changes this client or its clones.
    ///
    /// # Errors
    /// Rejects invalid authentication, unsupported versions/configuration,
    /// disabled receiving categories, insufficient capacity or any state that
    /// its existing importer rejects. Performs no network or storage I/O.
    pub fn restore_session(
        &self,
        snapshot: &SessionSnapshot,
        key: &[u8; 32],
        receiving_routes: &[Route],
    ) -> Result<Self, SessionSnapshotError> {
        let state = codec::decode(&envelope::open(snapshot.as_bytes(), key)?)?;
        if *state.context != *self.snapshot_context()? {
            return Err(SessionSnapshotError::new(
                SessionSnapshotErrorKind::Incompatible,
            ));
        }
        let restored = self.fork(SessionSharing::none());
        #[cfg(feature = "https-records")]
        match (&state.https_records, &restored.state.https_records) {
            (Some(snapshot), Some(discovery)) => discovery.restore_checkpoint(
                snapshot,
                restored
                    .state
                    .options
                    .https_record_checkpoint_namespace
                    .as_deref(),
            )?,
            (Some(_), None) => {
                return Err(SessionSnapshotError::new(
                    SessionSnapshotErrorKind::Disabled,
                ));
            }
            (None, Some(_)) => {
                return Err(SessionSnapshotError::new(
                    SessionSnapshotErrorKind::Incompatible,
                ));
            }
            (None, None) => {}
        }
        #[cfg(feature = "cookies")]
        if let Some(cookies) = &state.cookies {
            let jar = restored
                .state
                .cookies
                .as_ref()
                .ok_or_else(|| SessionSnapshotError::new(SessionSnapshotErrorKind::Disabled))?;
            if !jar.snapshot_fits(cookies).map_err(|error| {
                SessionSnapshotError::source(SessionSnapshotErrorKind::Cookies, error)
            })? {
                return Err(SessionSnapshotError::new(
                    SessionSnapshotErrorKind::Capacity,
                ));
            }
            restored.import_cookies(cookies).map_err(|error| {
                SessionSnapshotError::source(SessionSnapshotErrorKind::Cookies, error)
            })?;
        }
        if let Some(alt_svc) = &state.alt_svc {
            let store = restored
                .state
                .alt_svc
                .as_ref()
                .ok_or_else(|| SessionSnapshotError::new(SessionSnapshotErrorKind::Disabled))?;
            let mut origins = HashMap::new();
            for entry in alt_svc.entries() {
                if entry.expires_at() > SystemTime::now() {
                    let count = origins.entry(entry.origin()).or_insert(0);
                    *count += 1;
                    if *count > super::alt_svc::MAX_ALTERNATIVES_PER_ORIGIN
                        || origins.len() > store.capacity().get()
                    {
                        return Err(SessionSnapshotError::new(
                            SessionSnapshotErrorKind::Capacity,
                        ));
                    }
                }
            }
            restored.import_alt_svc(alt_svc).map_err(|error| {
                SessionSnapshotError::source(SessionSnapshotErrorKind::AltSvc, error)
            })?;
        }
        restored
            .import_session_tickets(&state.tickets, key, receiving_routes)
            .map_err(|error| {
                SessionSnapshotError::source(SessionSnapshotErrorKind::Tickets, error)
            })?;
        Ok(restored)
    }
}

#[cfg(test)]
mod tests;
