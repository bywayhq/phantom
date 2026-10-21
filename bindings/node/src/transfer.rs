//! Exact native transfer limits; the core owns counters and per-frame pacing.

use std::num::NonZeroU64;

use napi::{Result, bindgen_prelude::BigInt};
use phantom::TransferLimits;

use crate::{error::failure, ffi::TransferLimitsOptions};

fn unsigned(value: BigInt, field: &str) -> Result<u64> {
    match (value.sign_bit, value.words.as_slice()) {
        (false, []) => Ok(0),
        (false, [value]) => Ok(*value),
        _ => Err(failure("InvalidArgument", &format!("{field} must fit u64"))),
    }
}

fn rate(value: BigInt, field: &str) -> Result<NonZeroU64> {
    NonZeroU64::new(unsigned(value, field)?)
        .ok_or_else(|| failure("InvalidArgument", &format!("{field} must be positive")))
}

pub(crate) fn limits(options: TransferLimitsOptions) -> Result<TransferLimits> {
    let mut limits = TransferLimits::new();
    if let Some(value) = options.upload_bytes {
        limits = limits.upload_bytes(unsigned(value, "uploadBytes")?);
    }
    if let Some(value) = options.download_bytes {
        limits = limits.download_bytes(unsigned(value, "downloadBytes")?);
    }
    if let Some(value) = options.upload_bytes_per_second {
        limits = limits.upload_rate(rate(value, "uploadBytesPerSecond")?);
    }
    if let Some(value) = options.download_bytes_per_second {
        limits = limits.download_rate(rate(value, "downloadBytesPerSecond")?);
    }
    Ok(limits)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn integer(value: u64) -> BigInt {
        BigInt {
            sign_bit: false,
            words: vec![value],
        }
    }

    #[test]
    fn counts_preserve_zero_and_full_u64_and_rates_reject_zero() -> Result<()> {
        assert_eq!(unsigned(integer(0), "uploadBytes")?, 0);
        assert_eq!(unsigned(integer(u64::MAX), "downloadBytes")?, u64::MAX);
        assert!(rate(integer(0), "uploadBytesPerSecond").is_err());
        assert_eq!(
            rate(integer(u64::MAX), "downloadBytesPerSecond")?.get(),
            u64::MAX
        );
        assert!(
            unsigned(
                BigInt {
                    sign_bit: true,
                    words: vec![1]
                },
                "uploadBytes"
            )
            .is_err()
        );
        assert!(
            unsigned(
                BigInt {
                    sign_bit: false,
                    words: vec![0, 1]
                },
                "downloadBytes"
            )
            .is_err()
        );
        Ok(())
    }
}
