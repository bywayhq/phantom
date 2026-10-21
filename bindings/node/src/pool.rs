//! Apply operational pool overrides without replacing browser wire settings.

use std::{num::NonZeroUsize, time::Duration};

use napi::Result;
use phantom::ClientBuilder;

use crate::{error::failure, ffi::PoolOptions};

const MAXIMUM_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

pub(crate) fn apply(mut builder: ClientBuilder, options: PoolOptions) -> Result<ClientBuilder> {
    if let Some(value) = options.max_retained_http1_connections {
        builder =
            builder.max_retained_http1_connections(count(value, "maxRetainedHttp1Connections")?);
    }
    if let Some(value) = options.max_concurrent_http1_requests_per_origin {
        builder = builder.max_concurrent_http1_requests_per_origin(count(
            value,
            "maxConcurrentHttp1RequestsPerOrigin",
        )?);
    }
    if let Some(value) = options.max_pending_http1_requests_per_origin {
        builder = builder.max_pending_http1_requests_per_origin(count(
            value,
            "maxPendingHttp1RequestsPerOrigin",
        )?);
    }
    if let Some(value) = options.max_retained_http2_connections {
        builder =
            builder.max_retained_http2_connections(count(value, "maxRetainedHttp2Connections")?);
    }
    if let Some(value) = options.max_concurrent_http2_requests_per_origin {
        builder = builder.max_concurrent_http2_requests_per_origin(count(
            value,
            "maxConcurrentHttp2RequestsPerOrigin",
        )?);
    }
    if let Some(value) = options.max_pending_http2_requests_per_origin {
        builder = builder.max_pending_http2_requests_per_origin(count(
            value,
            "maxPendingHttp2RequestsPerOrigin",
        )?);
    }
    if let Some(value) = options.max_http2_connections_per_origin {
        builder =
            builder.max_http2_connections_per_origin(count(value, "maxHttp2ConnectionsPerOrigin")?);
    }
    if let Some(value) = options.max_retained_http3_connections {
        builder =
            builder.max_retained_http3_connections(count(value, "maxRetainedHttp3Connections")?);
    }
    if let Some(value) = options.max_concurrent_http3_requests_per_origin {
        builder = builder.max_concurrent_http3_requests_per_origin(count(
            value,
            "maxConcurrentHttp3RequestsPerOrigin",
        )?);
    }
    if let Some(value) = options.max_pending_http3_requests_per_origin {
        builder = builder.max_pending_http3_requests_per_origin(count(
            value,
            "maxPendingHttp3RequestsPerOrigin",
        )?);
    }
    if let Some(value) = options.max_http3_connections_per_origin {
        builder =
            builder.max_http3_connections_per_origin(count(value, "maxHttp3ConnectionsPerOrigin")?);
    }
    if let Some(value) = options.negotiated_setup_wait_limit_ms {
        integer(value, 0.0, "negotiatedSetupWaitLimitMs")?;
        builder = builder.negotiated_setup_wait_limit(Duration::from_millis(value as u64));
    }
    Ok(builder)
}

fn integer(value: f64, minimum: f64, field: &str) -> Result<()> {
    if !value.is_finite()
        || value.fract() != 0.0
        || !(minimum..=MAXIMUM_SAFE_INTEGER).contains(&value)
    {
        return Err(failure(
            "InvalidConfiguration",
            &format!("pool {field} must be a safe integer at least {minimum}"),
        ));
    }
    Ok(())
}

fn count(value: f64, field: &str) -> Result<NonZeroUsize> {
    integer(value, 1.0, field)?;
    if value > usize::MAX as f64 {
        return Err(failure(
            "InvalidConfiguration",
            &format!("pool {field} exceeds the platform count range"),
        ));
    }
    NonZeroUsize::new(value as usize).ok_or_else(|| {
        failure(
            "InvalidConfiguration",
            &format!("pool {field} must be positive"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_counts_reject_lossy_and_out_of_range_values() {
        for value in [
            0.0,
            -1.0,
            1.5,
            f64::NAN,
            f64::INFINITY,
            MAXIMUM_SAFE_INTEGER + 1.0,
        ] {
            assert!(count(value, "maximum").is_err());
        }
        assert_eq!(count(1.0, "maximum").map(NonZeroUsize::get).ok(), Some(1));
        if usize::BITS == 32 {
            assert!(count(4_294_967_296.0, "maximum").is_err());
        }
    }

    #[test]
    fn native_wait_accepts_zero_but_rejects_invalid_durations() {
        let builder = || phantom::Client::builder(phantom_profile::browser::chrome::v154_windows());
        assert!(
            apply(
                builder(),
                PoolOptions {
                    negotiated_setup_wait_limit_ms: Some(0.0),
                    ..PoolOptions::default()
                }
            )
            .is_ok()
        );
        for value in [-1.0, 0.5, f64::NAN, f64::INFINITY] {
            assert!(
                apply(
                    builder(),
                    PoolOptions {
                        negotiated_setup_wait_limit_ms: Some(value),
                        ..PoolOptions::default()
                    }
                )
                .is_err()
            );
        }
    }
}
