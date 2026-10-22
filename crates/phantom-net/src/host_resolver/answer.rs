//! Address answers whose DNS lifetimes must not be extended by the cache.

use std::{
    error::Error,
    fmt, io,
    net::IpAddr,
    time::{Duration, Instant},
};

/// A validated address lookup with a remaining DNS lifetime.
///
/// Use this with [`super::AddressResolver::from_answer_fn`]. An answer keeps
/// its construction time when moved or cloned, so waiting to return it does
/// not restart its lifetime. A zero or expired lifetime allows the current
/// lookup to use the answer, but prevents the address cache from storing it.
///
/// The resolver must validate the DNS response and account for elapsed query
/// time before constructing this answer. For DNS over HTTPS, subtract the
/// HTTP `Age` as well. This type does not perform those checks.
#[derive(Clone, Debug)]
pub struct AddressAnswer {
    outcome: AnswerOutcome,
    lifetime: AnswerLifetime,
}

#[derive(Clone, Debug)]
enum AnswerOutcome {
    Positive(Vec<IpAddr>),
    Negative(AddressNegative),
}

impl AddressAnswer {
    /// Creates a positive answer, keeping address order and duplicates.
    ///
    /// `remaining_ttl` bounds cache reuse from this call's time. The cache
    /// does not raise it to the profile's minimum record lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] when `addresses` is empty.
    pub fn positive(addresses: Vec<IpAddr>, remaining_ttl: Duration) -> io::Result<Self> {
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a positive DNS answer needs at least one address",
            ));
        }
        Ok(Self {
            outcome: AnswerOutcome::Positive(addresses),
            lifetime: AnswerLifetime {
                created_at: Instant::now(),
                ttl: Some(remaining_ttl),
                negative: false,
            },
        })
    }

    /// Creates a negative answer for the complete configured address lookup.
    ///
    /// Use the remaining lifetime derived from the SOA record's TTL and
    /// MINIMUM field, or `None` when it supplies no negative lifetime. The
    /// address cache also caps it by the configured negative lifetime.
    /// Both bounds start at this call's time.
    ///
    /// With queries for both address families, one family's NODATA does not
    /// make the whole lookup negative if the other has usable addresses or
    /// has not finished. Aggregate the family answers before calling this.
    /// A negative answer becomes a [`AddressNegative`] cause inside an
    /// [`io::Error`] with kind [`io::ErrorKind::NotFound`].
    #[must_use]
    pub fn negative(kind: AddressNegativeKind, remaining_ttl: Option<Duration>) -> Self {
        Self {
            outcome: AnswerOutcome::Negative(AddressNegative { kind }),
            lifetime: AnswerLifetime {
                created_at: Instant::now(),
                ttl: remaining_ttl,
                negative: true,
            },
        }
    }

    /// Shortens freshness to an already adjusted absolute deadline.
    ///
    /// Preserve the deadline computed from a DoH exchange or earlier CNAME
    /// response without a duration round-trip. The construction anchor and
    /// negative cache cap stay in force. This cannot revive a zero, missing
    /// or unrepresentable lifetime.
    #[must_use]
    pub fn with_cache_deadline(mut self, deadline: Instant) -> Self {
        let anchor = self.lifetime.created_at;
        self.lifetime.ttl = self
            .lifetime
            .ttl
            .and_then(|ttl| anchor.checked_add(ttl))
            .map(|original| original.min(deadline).saturating_duration_since(anchor));
        self
    }

    pub(super) fn into_parts(self) -> (io::Result<Vec<IpAddr>>, AnswerLifetime) {
        let outcome = match self.outcome {
            AnswerOutcome::Positive(addresses) => Ok(addresses),
            AnswerOutcome::Negative(error) => Err(io::Error::new(io::ErrorKind::NotFound, error)),
        };
        (outcome, self.lifetime)
    }
}

/// Why a validated address lookup returned no addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressNegativeKind {
    /// The queried DNS name does not exist.
    NxDomain,
    /// The configured address queries returned no usable records.
    NoData,
}

/// The typed cause of a negative answer from
/// [`super::AddressResolver::from_answer_fn`].
///
/// Inspect [`io::Error::get_ref`] or the cached error's source chain to find
/// this cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressNegative {
    kind: AddressNegativeKind,
}

impl AddressNegative {
    /// Returns the negative DNS answer's kind.
    #[must_use]
    pub const fn kind(&self) -> AddressNegativeKind {
        self.kind
    }
}

impl fmt::Display for AddressNegative {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            AddressNegativeKind::NxDomain => "the DNS name does not exist",
            AddressNegativeKind::NoData => "the DNS lookup returned no address records",
        })
    }
}

impl Error for AddressNegative {}

/// Both the DNS lifetime and the cache's negative cap start at creation.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AnswerLifetime {
    created_at: Instant,
    ttl: Option<Duration>,
    negative: bool,
}

impl AnswerLifetime {
    pub(crate) fn expires_at(self, negative_cap: Option<Duration>) -> Option<Instant> {
        let ttl = self.ttl?;
        let ttl = if self.negative {
            ttl.min(negative_cap?)
        } else {
            ttl
        };
        if ttl.is_zero() {
            return None;
        }
        // An unrepresentable finite DNS lifetime cannot authorize infinite
        // freshness. The current resolution still receives the answer.
        self.created_at.checked_add(ttl)
    }
}

#[cfg(test)]
mod tests {
    use super::{AddressAnswer, AddressNegativeKind, Duration, Instant, io};
    use std::net::Ipv4Addr;

    #[test]
    fn absolute_deadline_is_retained_without_resetting_the_answer_anchor() -> io::Result<()> {
        let answer =
            AddressAnswer::positive(vec![Ipv4Addr::LOCALHOST.into()], Duration::from_secs(30))?;
        let deadline = answer.lifetime.created_at + Duration::from_millis(500);
        let shortened = answer.clone().with_cache_deadline(deadline);
        assert_eq!(shortened.lifetime.created_at, answer.lifetime.created_at);
        assert_eq!(shortened.lifetime.expires_at(None), Some(deadline));
        let later = shortened
            .clone()
            .with_cache_deadline(deadline + Duration::from_secs(30));
        assert_eq!(later.lifetime.expires_at(None), Some(deadline));
        assert!(later.into_parts().0.is_ok());
        Ok(())
    }

    #[test]
    fn held_expired_deadline_and_missing_or_overflow_lifetimes_cannot_revive() -> io::Result<()> {
        let expired = Instant::now();
        let answer =
            AddressAnswer::positive(vec![Ipv4Addr::LOCALHOST.into()], Duration::from_secs(30))?
                .with_cache_deadline(expired);
        assert_eq!(answer.lifetime.expires_at(None), None);
        assert!(answer.into_parts().0.is_ok());
        let later = Instant::now() + Duration::from_secs(30);
        for ttl in [Duration::ZERO, Duration::MAX] {
            let answer = AddressAnswer::positive(vec![Ipv4Addr::LOCALHOST.into()], ttl)?
                .with_cache_deadline(later);
            assert_eq!(answer.lifetime.expires_at(None), None);
        }
        let negative =
            AddressAnswer::negative(AddressNegativeKind::NoData, None).with_cache_deadline(later);
        assert_eq!(
            negative.lifetime.expires_at(Some(Duration::from_secs(60))),
            None
        );
        Ok(())
    }

    #[test]
    fn negative_deadline_and_configured_cap_share_the_original_anchor() {
        let answer =
            AddressAnswer::negative(AddressNegativeKind::NxDomain, Some(Duration::from_secs(30)));
        let anchor = answer.lifetime.created_at;
        let deadline = anchor + Duration::from_secs(10);
        let answer = answer.with_cache_deadline(deadline);
        assert_eq!(
            answer.lifetime.expires_at(Some(Duration::from_secs(20))),
            Some(deadline)
        );
        assert_eq!(
            answer.lifetime.expires_at(Some(Duration::from_secs(5))),
            Some(anchor + Duration::from_secs(5))
        );
    }
}
