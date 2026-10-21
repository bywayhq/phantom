//! Native attempt budgets, transfer controls and request cancellation.

use std::sync::Arc;

use napi::{
    Result,
    bindgen_prelude::{BigInt, Either},
};
use napi_derive::napi;

use crate::{error::failure, response::Exchange};

/// Native shared allowance for origin HTTP attempts.
#[derive(Debug)]
#[napi]
pub struct NativeAttemptBudget {
    pub(super) budget: phantom::HttpAttemptBudget,
}

#[napi]
impl NativeAttemptBudget {
    /// Creates one counter shared by every request receiving this object.
    #[napi(constructor)]
    pub fn new(maximum: BigInt) -> Result<Self> {
        let maximum = match (maximum.sign_bit, maximum.words.as_slice()) {
            (false, [value]) => usize::try_from(*value).ok(),
            _ => None,
        }
        .ok_or_else(|| failure("InvalidArgument", "maximum must fit usize"))?;
        Ok(Self {
            budget: phantom::HttpAttemptBudget::new(maximum),
        })
    }
    /// Returns a snapshot, not a reservation.
    #[napi(getter)]
    #[must_use]
    pub fn remaining(&self) -> Either<f64, BigInt> {
        let remaining = self.budget.remaining() as u64;
        if remaining < (1_u64 << 53) {
            Either::A(remaining as f64)
        } else {
            Either::B(BigInt {
                sign_bit: false,
                words: vec![remaining],
            })
        }
    }
    /// Charges an external attempt; Phantom requests already charge themselves.
    #[napi]
    pub fn try_admit(&self) -> Result<()> {
        self.budget.try_admit().map_err(|_| {
            failure(
                "AttemptBudgetExhausted",
                "shared HTTP attempt budget exhausted",
            )
        })
    }
}

/// Immutable optional shared body-byte caps and rates.
#[derive(Debug)]
#[napi(object)]
pub struct TransferLimitsOptions {
    /// Shared upload cap, including zero.
    pub upload_bytes: Option<BigInt>,
    /// Shared encoded response-body cap, including zero.
    pub download_bytes: Option<BigInt>,
    /// Positive upload body bytes per second.
    pub upload_bytes_per_second: Option<BigInt>,
    /// Positive encoded response-body bytes per second.
    pub download_bytes_per_second: Option<BigInt>,
}

/// Coherent core counters, without JavaScript number conversion.
#[derive(Debug)]
#[napi(object)]
pub struct TransferSnapshotInfo {
    /// Accepted upload quota, including cancelled paced chunks.
    pub upload_reserved_bytes: BigInt,
    /// Request body bytes passed to protocol writers, including resends.
    pub upload_body_bytes: BigInt,
    /// Accepted encoded response quota, including cancelled paced chunks.
    pub download_reserved_bytes: BigInt,
    /// Encoded response bytes delivered by the control.
    pub download_encoded_bytes: BigInt,
    /// Core decoded frames delivered to the binding, including buffered remainders.
    pub download_decoded_bytes: BigInt,
}

/// Shared native transfer state, retained by attached requests independently.
#[derive(Debug)]
#[napi]
pub struct NativeTransferControl {
    pub(super) control: phantom::TransferControl,
}

#[napi]
impl NativeTransferControl {
    /// Creates fresh state from immutable exact limits.
    #[napi(constructor)]
    pub fn new(options: TransferLimitsOptions) -> Result<Self> {
        Ok(Self {
            control: phantom::TransferControl::new(crate::transfer::limits(options)?),
        })
    }

    /// Reads all counters under the core's single lock.
    #[must_use]
    #[napi]
    pub fn snapshot(&self) -> TransferSnapshotInfo {
        let counts = self.control.snapshot();
        let integer = |value| BigInt {
            sign_bit: false,
            words: vec![value],
        };
        TransferSnapshotInfo {
            upload_reserved_bytes: integer(counts.upload_reserved_bytes),
            upload_body_bytes: integer(counts.upload_body_bytes),
            download_reserved_bytes: integer(counts.download_reserved_bytes),
            download_encoded_bytes: integer(counts.download_encoded_bytes),
            download_decoded_bytes: integer(counts.download_decoded_bytes),
        }
    }
}

/// One request's native cancellation and body owner.
#[derive(Debug)]
#[napi]
pub struct NativeCancellation {
    pub(super) exchange: Arc<Exchange>,
}

#[napi]
impl NativeCancellation {
    /// Creates a handle usable by one request.
    #[napi(constructor)]
    #[must_use]
    pub fn new() -> Self {
        Self {
            exchange: Exchange::new(),
        }
    }
    /// Cancels setup, upload or response reading and drops any idle body.
    #[napi]
    pub fn cancel(&self) {
        self.exchange.cancel();
    }
}

impl Default for NativeCancellation {
    fn default() -> Self {
        Self::new()
    }
}
