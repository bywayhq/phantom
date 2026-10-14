use std::time::{Duration, Instant};

use crate::BuildError;

/// HTTPS-record lookup for a learned direct HTTP/3 alternative.
///
/// The logical origin still supplies the certificate name, inner TLS name,
/// and HTTP authority. DNS metadata for the destination has its own lifetime.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AltSvcHttpsPolicy {
    /// Keep the existing origin-only HTTPS discovery behavior.
    #[default]
    OriginOnly,
    /// Query the selected Alt-Svc host and port before starting QUIC.
    ///
    /// A compatible record can supply ECH for that destination. Lookup
    /// failure, incompatible records, and rejected ECH fail the candidate.
    /// An authoritative empty answer permits that alternative without ECH.
    /// Further DNS target or port relocation and AliasMode are unsupported.
    /// Proxy routes and explicitly pinned alternatives keep their behavior.
    Destination {
        /// Maximum lookup time, also bounded by the connection setup budget.
        /// Must be nonzero and fit the runtime clock.
        lookup_timeout: Duration,
    },
}

impl AltSvcHttpsPolicy {
    pub(crate) fn validate(self) -> Result<(), BuildError> {
        if let Self::Destination { lookup_timeout } = self
            && (lookup_timeout.is_zero() || Instant::now().checked_add(lookup_timeout).is_none())
        {
            return Err(BuildError::invalid_policy(
                "Alt-Svc destination lookup needs a nonzero timeout within the runtime clock range",
            ));
        }
        Ok(())
    }
}
