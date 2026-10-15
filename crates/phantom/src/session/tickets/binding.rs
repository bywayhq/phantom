//! Private profile preparation; it grants no session import authority.

use std::fmt;

use zeroize::Zeroizing;

use phantom_profile::{ClientProfile, TrustAnchorIds};

mod descriptor;
pub(crate) mod encoding;
mod http;
mod profile;
mod quic;
mod requests;
mod route;
mod tls;

pub(crate) use descriptor::{
    PreparedCacheDescriptor, TicketCacheLeg, TicketCacheProtocol, TicketClientContext,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PreparationError {
    TooLarge,
    Allocation,
    Unsupported(&'static str),
    DrawMismatch,
    Backend,
}

impl fmt::Display for PreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => formatter.write_str("ticket policy exceeds its preparation bound"),
            Self::Allocation => formatter.write_str("ticket policy allocation failed"),
            Self::Unsupported(field) => write!(formatter, "ticket policy does not support {field}"),
            Self::Backend => formatter.write_str("ticket preparation backend failed"),
            Self::DrawMismatch => {
                formatter.write_str("ticket policy differs after its client draw")
            }
        }
    }
}

impl std::error::Error for PreparationError {}

/// Configured policy and the two actual per-client selections are separate.
pub(crate) struct PreparedTicketPolicy {
    canonical: Zeroizing<Vec<u8>>,
    tcp_draw: Option<Zeroizing<Vec<u8>>>,
    quic_draw: Option<Zeroizing<Vec<u8>>>,
    tcp_draw_policy: Option<TrustAnchorIds>,
    quic_draw_policy: Option<TrustAnchorIds>,
    derived_offers: Zeroizing<Vec<u8>>,
    tcp_early_data: bool,
    quic_early_data: bool,
    context: Option<descriptor::ClientContext>,
}

impl PreparedTicketPolicy {
    /// Checks allowed source draws; the caller separately authenticates the envelope.
    pub(crate) fn validate_source_witness(&self, witness: &[u8]) -> Result<(), PreparationError> {
        tls::validate_source_witness(
            self.tcp_draw_policy.as_ref(),
            self.quic_draw_policy.as_ref(),
            witness,
        )
    }
}

impl fmt::Debug for PreparedTicketPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedTicketPolicy")
            .finish_non_exhaustive()
    }
}

/// Retains only the policies whose draw replaces their input representation.
pub(crate) struct BindingPlan {
    canonical: Zeroizing<Vec<u8>>,
    tcp: Option<TrustAnchorIds>,
    quic: Option<TrustAnchorIds>,
}

impl BindingPlan {
    pub(crate) fn capture(profile: &ClientProfile) -> Result<Self, PreparationError> {
        // Encoding bounds the candidate lists before cloning them.
        let canonical = Zeroizing::new(profile::encode(profile, None, None)?);
        let sampled = |ids: Option<&TrustAnchorIds>| match ids {
            Some(ids @ TrustAnchorIds::PerClient(_)) => Some(ids.clone()),
            _ => None,
        };
        Ok(Self {
            canonical,
            tcp: sampled(profile.tls().requested_trust_anchor_ids.as_ref()),
            quic: sampled(
                profile
                    .http3()
                    .and_then(|settings| settings.tls().requested_trust_anchor_ids.as_ref()),
            ),
        })
    }

    pub(crate) fn complete(
        self,
        profile: &ClientProfile,
    ) -> Result<PreparedTicketPolicy, PreparationError> {
        let tcp_draw = tls::witness(
            self.tcp.as_ref(),
            profile.tls().requested_trust_anchor_ids.as_ref(),
        )?;
        let quic_draw = tls::witness(
            self.quic.as_ref(),
            profile
                .http3()
                .and_then(|settings| settings.tls().requested_trust_anchor_ids.as_ref()),
        )?;
        let normalized = Zeroizing::new(profile::encode(
            profile,
            self.tcp.as_ref(),
            self.quic.as_ref(),
        )?);
        if normalized != self.canonical {
            return Err(PreparationError::DrawMismatch);
        }
        let tcp_draw = tcp_draw.map(Zeroizing::new);
        let quic_draw = quic_draw.map(Zeroizing::new);
        let derived_offers =
            descriptor::derived_offers(profile, self.tcp.as_ref(), self.quic.as_ref())?;
        Ok(PreparedTicketPolicy {
            canonical: self.canonical,
            tcp_draw,
            quic_draw,
            tcp_draw_policy: self.tcp,
            quic_draw_policy: self.quic,
            derived_offers,
            tcp_early_data: profile.tls().tcp_early_data,
            quic_early_data: profile
                .http3()
                .is_some_and(|settings| settings.quic_transport().early_data),
            context: None,
        })
    }
}

#[cfg(test)]
mod tests;
