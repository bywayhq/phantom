//! Convert owned retry settings into the public core policy once.

use std::time::Duration;

use napi::Result;

use crate::{
    error::failure,
    ffi::{RetryPolicyOptions, policy_count, positive_count},
};

fn duration(milliseconds: f64) -> Result<Duration> {
    if !milliseconds.is_finite() || milliseconds < 0.0 {
        return Err(failure(
            "InvalidArgument",
            "retry delay must be finite and nonnegative",
        ));
    }
    Duration::try_from_secs_f64(milliseconds / 1000.0).map_err(|_| {
        failure(
            "InvalidArgument",
            "retry delay exceeds the native duration range",
        )
    })
}

pub(crate) fn policy(options: RetryPolicyOptions) -> Result<phantom::RetryPolicy> {
    let mut result = match options.connection_failures {
        None => phantom::RetryPolicy::none(),
        Some(connection) => {
            let mut value = phantom::RetryPolicy::connection_failures(
                positive_count(connection.maximum)?,
                duration(connection.delay_ms)?,
            );
            if let Some(maximum) = connection.maximum_delay_ms {
                value = value.with_exponential_backoff(duration(maximum)?);
            }
            value.with_full_jitter(connection.full_jitter.unwrap_or(false))
        }
    };
    result =
        result.with_reused_connection_replay(options.reused_connection_replay.unwrap_or(false));
    result = result.with_unprocessed_replay(
        options
            .unprocessed_replays
            .map(positive_count)
            .transpose()?,
    );
    result = result.with_max_retries(options.maximum_retries.map(policy_count).transpose()?);
    result = result.with_http2_fallback(options.http2_fallback.unwrap_or(false));
    if let Some(status) = options.status_retry {
        let statuses = status
            .statuses
            .into_iter()
            .map(|value| {
                u16::try_from(value)
                    .ok()
                    .and_then(|value| phantom::StatusCode::from_u16(value).ok())
                    .ok_or_else(|| failure("InvalidArgument", "invalid retry status"))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut value = phantom::StatusRetry::new(
            &statuses,
            positive_count(status.maximum)?,
            duration(status.delay_ms)?,
        )
        .map_err(|_| {
            failure(
                "InvalidArgument",
                "status list must contain core-supported retry statuses",
            )
        })?;
        if let Some(maximum) = status.maximum_delay_ms {
            value = value.with_exponential_backoff(duration(maximum)?);
        }
        if let Some(maximum) = status.retry_after_limit_ms {
            value = value.honor_retry_after(duration(maximum)?);
        }
        result =
            result.with_status_retry(value.with_full_jitter(status.full_jitter.unwrap_or(false)));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::{ConnectionRetryOptions, StatusRetryOptions};
    use napi::bindgen_prelude::BigInt;

    fn count(value: u64) -> BigInt {
        BigInt {
            sign_bit: false,
            words: vec![value],
        }
    }

    fn options() -> RetryPolicyOptions {
        RetryPolicyOptions {
            connection_failures: None,
            reused_connection_replay: None,
            unprocessed_replays: None,
            status_retry: None,
            maximum_retries: None,
            http2_fallback: None,
        }
    }

    #[test]
    fn caller_classes_and_independent_schedules_reach_the_core() -> Result<()> {
        let policy = policy(RetryPolicyOptions {
            connection_failures: Some(ConnectionRetryOptions {
                maximum: count(2),
                delay_ms: 0.25,
                maximum_delay_ms: Some(1.5),
                full_jitter: Some(true),
            }),
            reused_connection_replay: Some(true),
            unprocessed_replays: Some(count(3)),
            status_retry: Some(StatusRetryOptions {
                statuses: vec![429, 503],
                maximum: count(4),
                delay_ms: 2.5,
                maximum_delay_ms: Some(8.5),
                full_jitter: Some(true),
                retry_after_limit_ms: Some(12.25),
            }),
            maximum_retries: Some(count(0)),
            http2_fallback: Some(true),
        })?;
        assert_eq!(
            policy
                .max_connection_failures()
                .map(std::num::NonZeroUsize::get),
            Some(2)
        );
        assert_eq!(policy.delay(), Duration::from_micros(250));
        assert_eq!(policy.backoff_limit(), Some(Duration::from_micros(1500)));
        assert!(
            policy.full_jitter() && policy.reused_connection_replay() && policy.http2_fallback()
        );
        assert_eq!(
            policy.unprocessed_replay().map(std::num::NonZeroUsize::get),
            Some(3)
        );
        assert_eq!(policy.max_retries(), Some(0));
        let status = policy
            .status_retry()
            .ok_or_else(|| failure("Test", "status policy missing"))?;
        assert!(status.retries(phantom::StatusCode::TOO_MANY_REQUESTS));
        assert!(status.retries(phantom::StatusCode::SERVICE_UNAVAILABLE));
        assert!(!status.retries(phantom::StatusCode::INTERNAL_SERVER_ERROR));
        assert_eq!(status.max_retries().get(), 4);
        assert_eq!(status.delay(), Duration::from_micros(2500));
        assert_eq!(status.backoff_limit(), Some(Duration::from_micros(8500)));
        assert_eq!(
            status.retry_after_limit(),
            Some(Duration::from_micros(12250))
        );
        assert!(status.full_jitter());
        Ok(())
    }

    #[test]
    fn empty_policy_is_disabled_and_invalid_numeric_settings_are_recoverable() -> Result<()> {
        assert_eq!(policy(options())?, phantom::RetryPolicy::none());
        for value in [f64::NAN, f64::INFINITY, -1.0, f64::MAX] {
            assert!(duration(value).is_err());
        }
        assert_eq!(duration(0.0)?, Duration::ZERO);
        assert!(positive_count(count(0)).is_err());
        assert!(
            policy_count(BigInt {
                sign_bit: true,
                words: vec![1]
            })
            .is_err()
        );
        assert!(
            policy_count(BigInt {
                sign_bit: false,
                words: vec![0, 1]
            })
            .is_err()
        );
        for statuses in [vec![], vec![421], vec![65_536]] {
            assert!(
                policy(RetryPolicyOptions {
                    status_retry: Some(StatusRetryOptions {
                        statuses,
                        maximum: count(1),
                        delay_ms: 0.0,
                        maximum_delay_ms: None,
                        full_jitter: None,
                        retry_after_limit_ms: None,
                    }),
                    ..options()
                })
                .is_err()
            );
        }
        Ok(())
    }
}
