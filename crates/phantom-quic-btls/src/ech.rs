//! Encrypted Client Hello offered by one QUIC connection.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

/// An `ECHConfigList` for one QUIC connection, and how that connection's
/// handshake treated it.
///
/// Give it to [`crate::QuicClientConfig::with_ech`]; the connection started
/// from the returned configuration offers Encrypted Client Hello with the
/// first configuration in the list that BoringSSL supports and records the
/// result here. Clones share the result. Use a new offer for each
/// connection, including a retry with the server's retry configurations.
#[derive(Clone)]
pub struct EchOffer {
    config_list: Arc<[u8]>,
    outcome: Arc<Mutex<Option<EchOutcome>>>,
}

impl EchOffer {
    /// Wraps the bytes of an `ECHConfigList`, such as the `ech` value of an
    /// HTTPS record.
    ///
    /// The list is checked when the connection starts: one BoringSSL does
    /// not accept fails that start and records
    /// [`EchOutcome::InvalidConfigList`].
    #[must_use]
    pub fn new(config_list: &[u8]) -> Self {
        Self {
            config_list: Arc::from(config_list),
            outcome: Arc::new(Mutex::new(None)),
        }
    }

    /// Returns the offered `ECHConfigList`.
    #[must_use]
    pub fn config_list(&self) -> &[u8] {
        &self.config_list
    }

    /// Returns what the handshake did with the offer, or `None` while it is
    /// still running or when it failed for another reason.
    #[must_use]
    pub fn outcome(&self) -> Option<EchOutcome> {
        self.lock().clone()
    }

    pub(crate) fn record(&self, outcome: EchOutcome) {
        let mut slot = self.lock();
        if slot.is_none() {
            *slot = Some(outcome);
        }
    }

    fn lock(&self) -> MutexGuard<'_, Option<EchOutcome>> {
        self.outcome
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl fmt::Debug for EchOffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EchOffer")
            .field("config_list_len", &self.config_list.len())
            .field("outcome", &self.outcome())
            .finish()
    }
}

/// What one QUIC handshake did with an [`EchOffer`].
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum EchOutcome {
    /// The server decrypted the inner ClientHello and the handshake
    /// completed with it.
    Accepted,
    /// The server could not decrypt it and authenticated as the
    /// configuration's public name; the handshake failed with the TLS
    /// `ech_required` alert.
    Rejected {
        /// The server's retry configurations, authenticated by that
        /// handshake, or `None` when it sent none.
        retry_configs: Option<Box<[u8]>>,
    },
    /// BoringSSL did not accept the list, so no packet was sent.
    InvalidConfigList,
}

impl fmt::Debug for EchOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accepted => formatter.write_str("Accepted"),
            Self::Rejected { retry_configs } => formatter
                .debug_struct("Rejected")
                .field(
                    "retry_configs_len",
                    &retry_configs.as_ref().map(|list| list.len()),
                )
                .finish(),
            Self::InvalidConfigList => formatter.write_str("InvalidConfigList"),
        }
    }
}
