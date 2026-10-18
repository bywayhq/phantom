//! Immutable restrictions on the server leaf's SubjectPublicKeyInfo.

use std::{error::Error, fmt};

/// SHA-256 digests of accepted leaf DER SubjectPublicKeyInfo values.
///
/// A leaf may match any digest. Pins supplement certificate-chain and hostname
/// verification. They do not trust an otherwise invalid certificate. Use more
/// than one digest when rotating keys. Input order and duplicates do not change
/// the policy. Debug output omits digest values.
#[derive(Clone, Eq, PartialEq)]
pub struct ServerSpkiPins(btls::ssl::SpkiPins);

impl ServerSpkiPins {
    /// Accepts one to 32 supplied SHA-256 digests, then sorts and deduplicates.
    ///
    /// Hash the certificate's encoded DER SubjectPublicKeyInfo, including its
    /// algorithm identifier. A whole-certificate or raw-key hash is different.
    ///
    /// # Errors
    /// Returns [`InvalidServerSpkiPins`] for empty or oversized input.
    pub fn new(digests: Vec<[u8; 32]>) -> Result<Self, InvalidServerSpkiPins> {
        btls::ssl::SpkiPins::new(digests)
            .map(Self)
            .map_err(|_| InvalidServerSpkiPins)
    }

    /// Returns the distinct digests in canonical ascending order.
    #[must_use]
    pub fn sha256_digests(&self) -> &[[u8; 32]] {
        self.0.sha256_digests()
    }

    pub(super) fn install(
        &self,
        builder: &mut btls::ssl::SslConnectorBuilder,
    ) -> Result<(), super::TlsError> {
        builder.set_spki_pins(self.0.clone()).map_err(|source| {
            super::TlsError::new(
                super::TlsErrorKind::BackendConfiguration,
                Some("server_spki_pins"),
                "the TLS context cannot install server pins".into(),
                Some(Box::new(source)),
            )
        })
    }
}

impl fmt::Debug for ServerSpkiPins {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerSpkiPins")
            .field("count", &self.sha256_digests().len())
            .finish_non_exhaustive()
    }
}

/// A leaf pin set contained fewer than one or more than 32 supplied digests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidServerSpkiPins;

impl fmt::Display for InvalidServerSpkiPins {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("server SPKI pins require one to 32 supplied digests")
    }
}

impl Error for InvalidServerSpkiPins {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equivalent_pin_sets_have_one_identity_without_debugging_values()
    -> Result<(), InvalidServerSpkiPins> {
        let pins = ServerSpkiPins::new(vec![[2; 32], [1; 32], [2; 32]])?;
        assert_eq!(pins, ServerSpkiPins::new(vec![[1; 32], [2; 32]])?);
        assert_eq!(pins.sha256_digests(), &[[1; 32], [2; 32]]);
        assert_eq!(format!("{pins:?}"), "ServerSpkiPins { count: 2, .. }");
        assert_eq!(ServerSpkiPins::new(Vec::new()), Err(InvalidServerSpkiPins));
        assert_eq!(
            ServerSpkiPins::new(vec![[1; 32]; 33]),
            Err(InvalidServerSpkiPins)
        );
        Ok(())
    }
}
