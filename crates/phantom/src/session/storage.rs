//! Explicit asynchronous storage of encrypted client checkpoints.

use std::{error::Error as StdError, fmt, future::Future, pin::Pin, time::Instant};

use crate::{Client, Route, SessionSnapshot};

/// An asynchronous store operation with its original backend error.
pub type SessionStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, Box<dyn StdError + Send + Sync>>> + Send + 'a>>;

/// Caller-owned storage for encrypted session checkpoints.
///
/// Methods must return promptly and put asynchronous work in the returned
/// future. Dropping that future must release its operation's resources without
/// cancelling unrelated operations. Phantom does not spawn storage tasks.
/// Client operations pass encrypted bytes, never keys or plaintext state.
///
/// Bound reads to 32 MiB before allocating or collecting a complete object,
/// then construct it with [`SessionSnapshot::from_bytes`]. Return `None` only
/// when the name is absent; report read, size and permission failures as errors.
/// The store defines admission limits, concurrent-write ordering, atomicity
/// and durability.
/// Cancellation or a timeout cannot undo a write already accepted externally.
/// Names are caller-selected identifiers, not paths authorized by Phantom.
pub trait SessionStore: Send + Sync {
    /// Loads one encrypted checkpoint, or `None` when it is absent.
    fn load<'a>(&'a self, name: &'a str) -> SessionStoreFuture<'a, Option<SessionSnapshot>>;

    /// Saves encrypted bytes under a name using the backend's write semantics.
    fn save<'a>(
        &'a self,
        name: &'a str,
        snapshot: &'a SessionSnapshot,
    ) -> SessionStoreFuture<'a, ()>;
}

/// Why an explicit checkpoint storage operation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SessionStorageErrorKind {
    /// The name is empty, exceeds 256 UTF-8 bytes or contains a control character.
    InvalidName,
    /// The operation's absolute deadline expired.
    Deadline,
    /// The caller's store returned an error.
    Backend,
    /// Checkpoint encoding, authentication or restoration failed.
    Snapshot,
}

/// A storage failure with the original backend or checkpoint error as its source.
///
/// `Debug` and `Display` omit names, state, keys and backend error messages.
/// Inspect [`StdError::source`] deliberately; backend errors are caller supplied.
pub struct SessionStorageError {
    kind: SessionStorageErrorKind,
    source: Option<Box<dyn StdError + Send + Sync>>,
}

impl SessionStorageError {
    fn new(kind: SessionStorageErrorKind) -> Self {
        Self { kind, source: None }
    }

    fn backend(source: Box<dyn StdError + Send + Sync>) -> Self {
        Self {
            kind: SessionStorageErrorKind::Backend,
            source: Some(source),
        }
    }

    /// Returns the failure category.
    #[must_use]
    pub const fn kind(&self) -> SessionStorageErrorKind {
        self.kind
    }
}

impl fmt::Debug for SessionStorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionStorageError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for SessionStorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "session storage failed: {:?}", self.kind)
    }
}

impl StdError for SessionStorageError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source.as_deref().map(|source| source as _)
    }
}

impl From<crate::SessionSnapshotError> for SessionStorageError {
    fn from(source: crate::SessionSnapshotError) -> Self {
        Self {
            kind: SessionStorageErrorKind::Snapshot,
            source: Some(Box::new(source)),
        }
    }
}

fn check_deadline(deadline: Instant) -> Result<(), SessionStorageError> {
    if Instant::now() >= deadline {
        return Err(SessionStorageError::new(SessionStorageErrorKind::Deadline));
    }
    Ok(())
}

fn validate(name: &str, deadline: Instant) -> Result<(), SessionStorageError> {
    if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
        return Err(SessionStorageError::new(
            SessionStorageErrorKind::InvalidName,
        ));
    }
    check_deadline(deadline)
}

async fn wait_for_store<T>(
    operation: SessionStoreFuture<'_, T>,
    deadline: Instant,
) -> Result<T, SessionStorageError> {
    let result = tokio::time::timeout_at(deadline.into(), operation).await;
    // A backend poll that blocks the runtime can complete after the timer.
    check_deadline(deadline)?;
    result
        .map_err(|_| SessionStorageError::new(SessionStorageErrorKind::Deadline))?
        .map_err(SessionStorageError::backend)
}

impl Client {
    /// Exports an encrypted checkpoint and saves it through a caller-owned store.
    ///
    /// Requires `session-snapshot`. Names must be nonempty, at most 256 UTF-8
    /// bytes and contain no control characters. The store gets encrypted bytes,
    /// never the key. Snapshot limits and compatibility are those of
    /// [`Self::export_session`]. No state is consumed or changed.
    ///
    /// The absolute deadline includes encoding and the backend operation, but
    /// cannot interrupt synchronous encoding or a backend that blocks instead
    /// of yielding. Late completion returns a deadline error. Dropping this
    /// future drops the backend future; external writes may already have
    /// committed. There is no automatic persistence, retry or fallback.
    /// Call in a Tokio runtime with timers enabled.
    ///
    /// ```no_run
    /// # async fn example(client: &phantom::Client, store: &dyn phantom::SessionStore,
    /// # key: &[u8; 32]) -> Result<(), phantom::SessionStorageError> {
    /// let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    /// client.save_session(store, "job/session", key, deadline).await?;
    /// let restored = client.load_session(store, "job/session", key, deadline, &[]).await?;
    /// # drop(restored);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    /// Returns an invalid-name, deadline, backend or checkpoint error.
    pub async fn save_session(
        &self,
        store: &dyn SessionStore,
        name: &str,
        key: &[u8; 32],
        deadline: Instant,
    ) -> Result<(), SessionStorageError> {
        validate(name, deadline)?;
        let snapshot = self.export_session(key);
        check_deadline(deadline)?;
        let snapshot = snapshot?;
        wait_for_store(store.save(name, &snapshot), deadline).await
    }

    /// Loads a checkpoint and restores it into a fresh independent client.
    ///
    /// Returns `None` only for an absent name. The receiving configuration,
    /// routes and restore rules are those of [`Self::restore_session`]. This
    /// client and its clones are unchanged on success and failure. The store
    /// receives no key and must bound its reads before constructing a snapshot.
    ///
    /// Names, absolute deadlines and cancellation follow [`Self::save_session`].
    /// Synchronous decoding and restoration cannot be interrupted; a client
    /// completed after the deadline is discarded rather than returned.
    ///
    /// # Errors
    /// Returns an invalid-name, deadline, backend or checkpoint error. Storage
    /// failures never create an empty client as a fallback.
    pub async fn load_session(
        &self,
        store: &dyn SessionStore,
        name: &str,
        key: &[u8; 32],
        deadline: Instant,
        receiving_routes: &[Route],
    ) -> Result<Option<Self>, SessionStorageError> {
        validate(name, deadline)?;
        let Some(snapshot) = wait_for_store(store.load(name), deadline).await? else {
            return Ok(None);
        };
        let restored = self.restore_session(&snapshot, key, receiving_routes);
        check_deadline(deadline)?;
        restored.map(Some).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests;
