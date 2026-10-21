use crate::error;
use phantom::{TransferControl, TransferLimits};
use pyo3::{prelude::*, types::PyInt};
use std::num::NonZeroU64;

/// Clones attached to requests share the core counters, caps and rate schedule.
#[pyclass(frozen)]
pub(super) struct NativeTransferControl {
    pub(super) inner: TransferControl,
}

fn integer(value: Option<Bound<'_, PyAny>>) -> PyResult<Option<u64>> {
    value
        .map(|value| {
            value
                .cast_exact::<PyInt>()
                .map_err(|_| error::input("invalid_transfer_limit"))?
                .extract::<u64>()
                .map_err(|_| error::input("invalid_transfer_limit"))
        })
        .transpose()
}

fn limits(values: [Option<u64>; 4]) -> PyResult<TransferLimits> {
    let mut limits = TransferLimits::new();
    if let Some(value) = values[0] {
        limits = limits.upload_bytes(value);
    }
    if let Some(value) = values[1] {
        limits = limits.download_bytes(value);
    }
    if let Some(value) = values[2] {
        limits = limits.upload_rate(
            NonZeroU64::new(value).ok_or_else(|| error::input("invalid_transfer_rate"))?,
        );
    }
    if let Some(value) = values[3] {
        limits = limits.download_rate(
            NonZeroU64::new(value).ok_or_else(|| error::input("invalid_transfer_rate"))?,
        );
    }
    Ok(limits)
}

#[pymethods]
impl NativeTransferControl {
    #[new]
    #[pyo3(signature = (upload_bytes=None, download_bytes=None, upload_bytes_per_second=None, download_bytes_per_second=None))]
    fn new(
        upload_bytes: Option<Bound<'_, PyAny>>,
        download_bytes: Option<Bound<'_, PyAny>>,
        upload_bytes_per_second: Option<Bound<'_, PyAny>>,
        download_bytes_per_second: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        Ok(Self {
            inner: TransferControl::new(limits([
                integer(upload_bytes)?,
                integer(download_bytes)?,
                integer(upload_bytes_per_second)?,
                integer(download_bytes_per_second)?,
            ])?),
        })
    }

    fn snapshot(&self) -> (u64, u64, u64, u64, u64) {
        let counts = self.inner.snapshot();
        (
            counts.upload_reserved_bytes,
            counts.upload_body_bytes,
            counts.download_reserved_bytes,
            counts.download_encoded_bytes,
            counts.download_decoded_bytes,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_preserve_zero_caps_and_full_integer_range() -> PyResult<()> {
        assert_eq!(
            limits([Some(0), Some(u64::MAX), Some(1), Some(u64::MAX)])?,
            TransferLimits::new()
                .upload_bytes(0)
                .download_bytes(u64::MAX)
                .upload_rate(NonZeroU64::MIN)
                .download_rate(NonZeroU64::MAX)
        );
        assert_eq!(limits([None; 4])?, TransferLimits::new());
        assert!(limits([None, None, Some(0), None]).is_err());
        assert!(limits([None, None, None, Some(0)]).is_err());
        Ok(())
    }
}
