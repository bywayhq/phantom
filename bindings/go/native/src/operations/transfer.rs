use std::num::NonZeroU64;

use phantom::{TransferControl, TransferLimits};
use serde::Deserialize;
use serde_json::{Value, json};

use super::Failure;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Limits {
    upload_bytes: Option<u64>,
    download_bytes: Option<u64>,
    upload_bytes_per_second: Option<u64>,
    download_bytes_per_second: Option<u64>,
}

impl Limits {
    pub(super) fn control(self) -> Result<TransferControl, Failure> {
        let mut limits = TransferLimits::new();
        if let Some(maximum) = self.upload_bytes {
            limits = limits.upload_bytes(maximum);
        }
        if let Some(maximum) = self.download_bytes {
            limits = limits.download_bytes(maximum);
        }
        if let Some(rate) = self.upload_bytes_per_second {
            limits = limits.upload_rate(
                NonZeroU64::new(rate).ok_or_else(|| Failure::new("invalid_transfer_limits"))?,
            );
        }
        if let Some(rate) = self.download_bytes_per_second {
            limits = limits.download_rate(
                NonZeroU64::new(rate).ok_or_else(|| Failure::new("invalid_transfer_limits"))?,
            );
        }
        Ok(TransferControl::new(limits))
    }
}

pub(super) fn snapshot(control: &TransferControl) -> Value {
    let snapshot = control.snapshot();
    json!({
        "upload_reserved_bytes": snapshot.upload_reserved_bytes,
        "upload_body_bytes": snapshot.upload_body_bytes,
        "download_reserved_bytes": snapshot.download_reserved_bytes,
        "download_encoded_bytes": snapshot.download_encoded_bytes,
        "download_decoded_bytes": snapshot.download_decoded_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_reject_invalid_wire_values_and_zero_rates() -> Result<(), serde_json::Error> {
        for input in [
            r#"{"upload_bytes":-1}"#,
            r#"{"download_bytes":18446744073709551616}"#,
            r#"{"upload_bytes":true}"#,
            r#"{"download_bytes":1.5}"#,
            r#"{"unknown":1}"#,
        ] {
            assert!(serde_json::from_str::<Limits>(input).is_err(), "{input}");
        }
        for input in [
            r#"{"upload_bytes_per_second":0}"#,
            r#"{"download_bytes_per_second":0}"#,
        ] {
            let limits: Limits = serde_json::from_str(input)?;
            assert_eq!(
                limits.control().err().map(|failure| failure.kind),
                Some("invalid_transfer_limits")
            );
        }
        Ok(())
    }

    #[test]
    fn zero_caps_and_exact_u64_max_are_valid() -> Result<(), Box<dyn std::error::Error>> {
        for input in [
            "{}",
            r#"{"upload_bytes":0,"download_bytes":0}"#,
            r#"{"upload_bytes":18446744073709551615,"download_bytes_per_second":18446744073709551615}"#,
        ] {
            let control = serde_json::from_str::<Limits>(input)?
                .control()
                .map_err(|failure| failure.kind)?;
            assert_eq!(snapshot(&control)["upload_reserved_bytes"], 0);
            assert_eq!(snapshot(&control)["download_reserved_bytes"], 0);
        }
        Ok(())
    }
}
