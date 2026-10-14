//! Explicit HTTPS metadata selection for an already chosen Alt-Svc destination.
//!
//! RFC 9460 sections 9.3 and 9.4 keep the alternative's network destination
//! separate from origin authentication. Unlike origin discovery, this path
//! must not turn a failed or unsupported lookup into permission to omit ECH.

use std::{error::Error, fmt, sync::Arc};

use phantom_net::dns::{
    EchConfigList, HttpsLookupError, HttpsRecord, HttpsRecordLookup, TargetName,
};

/// Metadata fixed before either connection attempt starts.
#[derive(Clone, Debug)]
pub(crate) struct DestinationPlan {
    pub(crate) ech: Option<EchConfigList>,
}

/// A destination lookup that cannot authorize a connection attempt.
#[derive(Clone, Debug)]
pub(crate) enum DestinationError {
    Lookup(Arc<HttpsLookupError>),
    UnsupportedRecords,
    IpLiteral,
    RuntimeUnavailable,
    Capacity,
    Cancelled,
    DiscoveryUnavailable,
}

impl fmt::Display for DestinationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Lookup(_) => "Alt-Svc destination HTTPS lookup failed",
            Self::UnsupportedRecords => "Alt-Svc destination HTTPS records are unsupported",
            Self::IpLiteral => "Alt-Svc destination HTTPS lookup needs a DNS name",
            Self::RuntimeUnavailable => "Alt-Svc destination HTTPS lookup needs a runtime",
            Self::Capacity => "Alt-Svc destination HTTPS lookup capacity is exhausted",
            Self::Cancelled => "Alt-Svc destination HTTPS lookup ended without a result",
            Self::DiscoveryUnavailable => "Alt-Svc destination HTTPS discovery is unavailable",
        })
    }
}

impl Error for DestinationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Lookup(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

/// Selects one compatible record without moving to another target or port.
pub(crate) fn select(
    lookup: &HttpsRecordLookup,
    host: &str,
    port: u16,
) -> Result<DestinationPlan, DestinationError> {
    if lookup.answers().is_empty() {
        return Ok(DestinationPlan { ech: None });
    }
    // AliasMode requires a separate follow-up contract. It cannot authorize
    // cleartext SNI merely because origin discovery ignores it.
    if lookup
        .answers()
        .iter()
        .any(|answer| matches!(answer.record(), HttpsRecord::Alias(_)))
    {
        return Err(DestinationError::UnsupportedRecords);
    }
    let mut selected = None;
    for answer in lookup.answers() {
        let HttpsRecord::Service(service) = answer.record() else {
            continue;
        };
        // RFC 9460 section 2.5.2 makes "." the actual record owner.
        // A prefixed or CNAME owner is not evidence for the chosen dial host.
        let same_target = match service.target() {
            TargetName::Owner => answer.owner().eq_ignore_ascii_case(host),
            TargetName::Name(name) => name.eq_ignore_ascii_case(host),
            _ => false,
        };
        if !same_target
            || service.port().is_some_and(|value| value != port)
            || !service.mandatory().iter().all(|key| (1..=6).contains(key))
            || !service
                .alpn()
                .iter()
                .any(|protocol| protocol.as_ref() == b"h3")
        {
            continue;
        }
        // Strictly lower priority replaces the selection; equal priorities
        // retain response order. Explicit h3 remains usable with no-default-alpn.
        if selected.is_none_or(|previous: &phantom_net::dns::ServiceRecord| {
            service.priority() < previous.priority()
        }) {
            selected = Some(service);
        }
    }
    let selected = selected.ok_or(DestinationError::UnsupportedRecords)?;
    Ok(DestinationPlan {
        ech: selected.ech().cloned(),
    })
}

#[cfg(test)]
mod tests;
