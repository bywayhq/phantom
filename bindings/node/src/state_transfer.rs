//! Typed state transfer bounds and exact Unix time conversion.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use napi::{Error, Result, Status, bindgen_prelude::BigInt};
use phantom::{
    AltSvcSnapshotError, AltSvcSnapshotErrorKind, CookieSnapshotError, CookieSnapshotErrorKind,
    SessionTicketError, SessionTicketErrorKind,
};

// Admission ceilings match session/snapshot.rs; these are not a wire format.
pub(crate) const MAXIMUM_TEXT: usize = 32 * 1024 * 1024;
pub(crate) const MAXIMUM_COOKIES: u32 = 16_384;
pub(crate) const MAXIMUM_ALTERNATIVES: u32 = 32_768;
pub(crate) const MAXIMUM_TICKETS: usize = 16 * 1024 * 1024;

pub(crate) fn failure(category: &str, kind: &str, index: Option<usize>) -> Error {
    let index = index.map_or_else(String::new, |index| index.to_string());
    Error::new(
        Status::GenericFailure,
        format!("PHANTOM_STATE:{category}:{kind}:{index}:state transfer failed"),
    )
}

pub(crate) fn cookie_error(error: CookieSnapshotError) -> Error {
    let kind = match error.kind() {
        CookieSnapshotErrorKind::Disabled => "disabled",
        CookieSnapshotErrorKind::InvalidCookie => "invalid_cookie",
        CookieSnapshotErrorKind::CookieTooLarge => "cookie_too_large",
        CookieSnapshotErrorKind::PublicSuffix => "public_suffix",
        CookieSnapshotErrorKind::InvalidPrefix => "invalid_prefix",
        CookieSnapshotErrorKind::UnsupportedPolicy => "unsupported_policy",
        CookieSnapshotErrorKind::InvalidPartitionKey => "invalid_partition_key",
        _ => "unknown",
    };
    failure("CookieSnapshot", kind, error.entry_index())
}

pub(crate) fn alt_svc_error(error: AltSvcSnapshotError) -> Error {
    let kind = match error.kind() {
        AltSvcSnapshotErrorKind::Disabled => "disabled",
        AltSvcSnapshotErrorKind::NoncanonicalOrigin => "noncanonical_origin",
        AltSvcSnapshotErrorKind::InvalidAlternative => "invalid_alternative",
        _ => "unknown",
    };
    failure("AltSvcSnapshot", kind, error.entry_index())
}

pub(crate) fn ticket_error(error: SessionTicketError) -> Error {
    let kind = match error.kind() {
        SessionTicketErrorKind::TooLarge => "too_large",
        SessionTicketErrorKind::Allocation => "allocation",
        SessionTicketErrorKind::InvalidSnapshot => "invalid_snapshot",
        SessionTicketErrorKind::Authentication => "authentication",
        SessionTicketErrorKind::IncompatibleBackend => "incompatible_backend",
        SessionTicketErrorKind::Expired => "expired",
        SessionTicketErrorKind::Policy => "policy",
        SessionTicketErrorKind::Unsupported => "unsupported",
        SessionTicketErrorKind::Busy => "busy",
        SessionTicketErrorKind::Backend => "backend",
        _ => "unknown",
    };
    failure("SessionTickets", kind, None)
}

pub(crate) fn time(value: BigInt) -> Result<SystemTime> {
    let invalid = || failure("StateSnapshot", "invalid_expiry", None);
    if value.words.len() > 2 {
        return Err(invalid());
    }
    let magnitude = u128::from(value.words.first().copied().unwrap_or(0))
        | (u128::from(value.words.get(1).copied().unwrap_or(0)) << 64);
    let seconds = u64::try_from(magnitude / 1_000_000_000).map_err(|_| invalid())?;
    let nanos = u32::try_from(magnitude % 1_000_000_000).map_err(|_| invalid())?;
    let duration = Duration::new(seconds, nanos);
    let result = if value.sign_bit {
        UNIX_EPOCH.checked_sub(duration)
    } else {
        UNIX_EPOCH.checked_add(duration)
    }
    .ok_or_else(invalid)?;
    // Windows SystemTime has 100ns ticks; checked arithmetic may round without
    // reporting overflow. Reject precision loss rather than extending expiry.
    if timestamp(result) != value {
        return Err(invalid());
    }
    Ok(result)
}

pub(crate) fn timestamp(value: SystemTime) -> BigInt {
    let (negative, duration) = match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => (false, duration),
        Err(error) => (true, error.duration()),
    };
    let nanos = duration.as_nanos();
    BigInt {
        sign_bit: negative,
        words: vec![nanos as u64, (nanos >> 64) as u64],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_nanoseconds_round_trip_without_fraction_loss() {
        for negative in [false, true] {
            for duration in [
                Duration::ZERO,
                Duration::new(1, 234_567_891),
                Duration::new(253_402_300_799, 999_999_999),
            ] {
                let original = if negative {
                    UNIX_EPOCH.checked_sub(duration)
                } else {
                    UNIX_EPOCH.checked_add(duration)
                };
                if let Some(original) = original {
                    assert_eq!(time(timestamp(original)).ok(), Some(original));
                }
            }
        }
    }

    #[test]
    fn expiry_overflow_is_rejected_instead_of_truncated() {
        for words in [vec![0, 0, 1], vec![u64::MAX, u64::MAX]] {
            assert!(
                time(BigInt {
                    sign_bit: false,
                    words
                })
                .is_err()
            );
        }
    }

    #[test]
    fn expiry_rejects_host_precision_loss() {
        let hundred = BigInt {
            sign_bit: false,
            words: vec![100],
        };
        assert_eq!(
            time(hundred).ok(),
            UNIX_EPOCH.checked_add(Duration::from_nanos(100))
        );
        let one = BigInt {
            sign_bit: false,
            words: vec![1],
        };
        let representable = UNIX_EPOCH
            .checked_add(Duration::from_nanos(1))
            .is_some_and(|value| timestamp(value) == one);
        assert_eq!(time(one).is_ok(), representable);
    }
}
