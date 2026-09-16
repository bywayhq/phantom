use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::key_schedule::{CipherSuite, TrafficSecret};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EncryptionLevel {
    Initial,
    Handshake,
    Application,
}

impl EncryptionLevel {
    const fn index(self) -> usize {
        match self {
            Self::Initial => 0,
            Self::Handshake => 1,
            Self::Application => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SecretDirection {
    Local,
    Remote,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum CallbackError {
    NullCipher,
    NullInput {
        input: &'static str,
        len: usize,
    },
    UnsupportedEncryptionLevel {
        raw: u32,
    },
    EarlyDataUnsupported,
    SecretAtInitialLevel,
    UnsupportedCipherSuite {
        id: u16,
    },
    InvalidSecretLength {
        actual: usize,
        expected: usize,
    },
    DuplicateSecret {
        level: EncryptionLevel,
        direction: SecretDirection,
    },
    MismatchedCipherSuite {
        level: EncryptionLevel,
        local: u16,
        remote: u16,
    },
    InvalidFlightLimit {
        level: EncryptionLevel,
    },
    HandshakeDataTooLarge {
        level: EncryptionLevel,
        attempted: usize,
        limit: usize,
    },
    AllocationFailed,
    CallbackPanicked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FlightLimits {
    initial: usize,
    handshake: usize,
    application: usize,
}

impl FlightLimits {
    pub(super) const fn new(initial: usize, handshake: usize, application: usize) -> Self {
        Self {
            initial,
            handshake,
            application,
        }
    }

    const fn for_level(self, level: EncryptionLevel) -> usize {
        match level {
            EncryptionLevel::Initial => self.initial,
            EncryptionLevel::Handshake => self.handshake,
            EncryptionLevel::Application => self.application,
        }
    }
}

impl Default for FlightLimits {
    fn default() -> Self {
        const MAX_QUEUED_FLIGHT: usize = 256 * 1024;
        Self::new(MAX_QUEUED_FLIGHT, MAX_QUEUED_FLIGHT, MAX_QUEUED_FLIGHT)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct HandshakeChunk {
    pub(super) level: EncryptionLevel,
    pub(super) bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Alert {
    pub(super) level: EncryptionLevel,
    pub(super) description: u8,
}

struct StoredSecret {
    cipher_suite: u16,
    value: TrafficSecret,
}

impl StoredSecret {
    fn copy(cipher_suite: u16, value: &[u8]) -> Result<Self, CallbackError> {
        let suite = CipherSuite::from_id(cipher_suite)
            .map_err(|_| CallbackError::UnsupportedCipherSuite { id: cipher_suite })?;
        let expected = suite.digest().output_len();
        if value.len() != expected {
            return Err(CallbackError::InvalidSecretLength {
                actual: value.len(),
                expected,
            });
        }
        let value = TrafficSecret::new(suite.digest(), value).map_err(|_| {
            CallbackError::InvalidSecretLength {
                actual: value.len(),
                expected,
            }
        })?;
        Ok(Self {
            cipher_suite,
            value,
        })
    }
}

impl fmt::Debug for StoredSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredSecret")
            .field("cipher_suite", &self.cipher_suite)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

#[derive(Default)]
struct DirectionalSecrets {
    local: Option<StoredSecret>,
    remote: Option<StoredSecret>,
}

impl DirectionalSecrets {
    fn slot(&self, direction: SecretDirection) -> &Option<StoredSecret> {
        match direction {
            SecretDirection::Local => &self.local,
            SecretDirection::Remote => &self.remote,
        }
    }

    fn slot_mut(&mut self, direction: SecretDirection) -> &mut Option<StoredSecret> {
        match direction {
            SecretDirection::Local => &mut self.local,
            SecretDirection::Remote => &mut self.remote,
        }
    }

    fn validate_pair(&self, level: EncryptionLevel) -> Result<(), CallbackError> {
        let (Some(local), Some(remote)) = (&self.local, &self.remote) else {
            return Ok(());
        };
        if local.cipher_suite != remote.cipher_suite {
            return Err(CallbackError::MismatchedCipherSuite {
                level,
                local: local.cipher_suite,
                remote: remote.cipher_suite,
            });
        }
        Ok(())
    }
}

#[derive(Default)]
struct CallbackStateInner {
    terminal_error: Option<CallbackError>,
    handshake_secrets: DirectionalSecrets,
    application_secrets: DirectionalSecrets,
    pending: Vec<HandshakeChunk>,
    published: Vec<HandshakeChunk>,
    buffered_by_level: [usize; 3],
    alerts: Vec<Alert>,
    completed_flushes: usize,
}

pub(super) struct CallbackState {
    limits: FlightLimits,
    inner: Arc<Mutex<CallbackStateInner>>,
}

impl Clone for CallbackState {
    fn clone(&self) -> Self {
        Self {
            limits: self.limits,
            inner: Arc::clone(&self.inner),
        }
    }
}

impl fmt::Debug for CallbackState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CallbackState([REDACTED])")
    }
}

impl CallbackState {
    pub(super) fn new(limits: FlightLimits) -> Self {
        Self {
            limits,
            inner: Arc::new(Mutex::new(CallbackStateInner::default())),
        }
    }

    fn lock(&self) -> MutexGuard<'_, CallbackStateInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(super) fn terminal_error(&self) -> Option<CallbackError> {
        self.lock().terminal_error.clone()
    }

    pub(super) fn record_terminal(&self, error: CallbackError) {
        let mut inner = self.lock();
        if inner.terminal_error.is_none() {
            inner.terminal_error = Some(error);
        }
    }

    pub(super) fn has_terminal_error(&self) -> bool {
        self.lock().terminal_error.is_some()
    }

    pub(super) fn set_secret(
        &self,
        level: EncryptionLevel,
        direction: SecretDirection,
        cipher_suite: u16,
        value: &[u8],
    ) -> Result<(), CallbackError> {
        let secret = StoredSecret::copy(cipher_suite, value)?;
        let mut inner = self.lock();
        let secrets = match level {
            EncryptionLevel::Handshake => &mut inner.handshake_secrets,
            EncryptionLevel::Application => &mut inner.application_secrets,
            EncryptionLevel::Initial => return Err(CallbackError::SecretAtInitialLevel),
        };
        if secrets.slot(direction).is_some() {
            return Err(CallbackError::DuplicateSecret { level, direction });
        }
        *secrets.slot_mut(direction) = Some(secret);
        secrets.validate_pair(level)
    }

    pub(super) fn append_handshake(
        &self,
        level: EncryptionLevel,
        data: &[u8],
        backend_limit: usize,
    ) -> Result<(), CallbackError> {
        let limit = self.effective_flight_limit(level, backend_limit)?;
        let mut inner = self.lock();
        let level_index = level.index();
        let attempted = Self::bounded_handshake_len(&inner, level, data.len(), limit)?;
        inner
            .pending
            .try_reserve(1)
            .map_err(|_| CallbackError::AllocationFailed)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(data.len())
            .map_err(|_| CallbackError::AllocationFailed)?;
        bytes.extend_from_slice(data);
        inner.pending.push(HandshakeChunk { level, bytes });
        inner.buffered_by_level[level_index] = attempted;
        Ok(())
    }

    pub(super) fn validate_handshake_len(
        &self,
        level: EncryptionLevel,
        additional: usize,
        backend_limit: usize,
    ) -> Result<(), CallbackError> {
        let limit = self.effective_flight_limit(level, backend_limit)?;
        let inner = self.lock();
        Self::bounded_handshake_len(&inner, level, additional, limit).map(|_| ())
    }

    fn effective_flight_limit(
        &self,
        level: EncryptionLevel,
        backend_limit: usize,
    ) -> Result<usize, CallbackError> {
        let limit = self.limits.for_level(level).min(backend_limit);
        if limit == 0 {
            Err(CallbackError::InvalidFlightLimit { level })
        } else {
            Ok(limit)
        }
    }

    fn bounded_handshake_len(
        inner: &CallbackStateInner,
        level: EncryptionLevel,
        additional: usize,
        limit: usize,
    ) -> Result<usize, CallbackError> {
        let level_index = level.index();
        let attempted = inner.buffered_by_level[level_index]
            .checked_add(additional)
            .ok_or(CallbackError::HandshakeDataTooLarge {
                level,
                attempted: usize::MAX,
                limit,
            })?;
        if attempted > limit {
            return Err(CallbackError::HandshakeDataTooLarge {
                level,
                attempted,
                limit,
            });
        }
        Ok(attempted)
    }

    pub(super) fn flush(&self) -> Result<(), CallbackError> {
        let mut inner = self.lock();
        let pending_len = inner.pending.len();
        inner
            .published
            .try_reserve(pending_len)
            .map_err(|_| CallbackError::AllocationFailed)?;
        let mut pending = std::mem::take(&mut inner.pending);
        inner.published.append(&mut pending);
        inner.completed_flushes = inner.completed_flushes.saturating_add(1);
        Ok(())
    }

    pub(super) fn drain_handshake(&self) -> Result<Vec<HandshakeChunk>, CallbackError> {
        let mut inner = self.lock();
        if let Some(error) = inner.terminal_error.clone() {
            return Err(error);
        }
        let published = std::mem::take(&mut inner.published);
        for chunk in &published {
            let buffered = &mut inner.buffered_by_level[chunk.level.index()];
            *buffered -= chunk.bytes.len();
        }
        Ok(published)
    }

    pub(super) fn push_alert(&self, alert: Alert) -> Result<(), CallbackError> {
        let mut inner = self.lock();
        inner
            .alerts
            .try_reserve(1)
            .map_err(|_| CallbackError::AllocationFailed)?;
        inner.alerts.push(alert);
        Ok(())
    }

    pub(super) fn drain_alerts(&self) -> Result<Vec<Alert>, CallbackError> {
        let mut inner = self.lock();
        if let Some(error) = inner.terminal_error.clone() {
            return Err(error);
        }
        Ok(std::mem::take(&mut inner.alerts))
    }

    #[cfg(test)]
    pub(super) fn completed_flushes(&self) -> usize {
        self.lock().completed_flushes
    }

    #[cfg(test)]
    pub(super) fn secret_len(
        &self,
        level: EncryptionLevel,
        direction: SecretDirection,
    ) -> Option<usize> {
        let inner = self.lock();
        let secrets = match level {
            EncryptionLevel::Handshake => &inner.handshake_secrets,
            EncryptionLevel::Application => &inner.application_secrets,
            EncryptionLevel::Initial => return None,
        };
        secrets
            .slot(direction)
            .as_ref()
            .map(|secret| secret.value.as_slice().len())
    }

    #[cfg(test)]
    pub(super) fn secret_matches(
        &self,
        level: EncryptionLevel,
        direction: SecretDirection,
        expected: &[u8],
    ) -> bool {
        let inner = self.lock();
        let secrets = match level {
            EncryptionLevel::Handshake => &inner.handshake_secrets,
            EncryptionLevel::Application => &inner.application_secrets,
            EncryptionLevel::Initial => return false,
        };
        secrets
            .slot(direction)
            .as_ref()
            .is_some_and(|secret| secret.value.as_slice() == expected)
    }

    #[cfg(test)]
    pub(super) fn owner_count(&self) -> usize {
        Arc::strong_count(&self.inner)
    }
}

#[cfg(test)]
mod tests;
