use crate::error::Failure;
use serde::Deserialize;
use std::{num::NonZeroUsize, time::Duration};

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct RetryPolicy {
    connection: Option<ConnectionRetry>,
    status: Option<StatusRetry>,
    reused_connection_replay: bool,
    unprocessed_replays: Option<u64>,
    maximum_retries: Option<u64>,
    http2_fallback: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionRetry {
    maximum: u64,
    delay_ns: u64,
    maximum_delay_ns: Option<u64>,
    #[serde(default)]
    full_jitter: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusRetry {
    statuses: Vec<u16>,
    maximum: u64,
    delay_ns: u64,
    maximum_delay_ns: Option<u64>,
    #[serde(default)]
    full_jitter: bool,
    retry_after_limit_ns: Option<u64>,
}

fn invalid() -> Failure {
    Failure::new("invalid_retry_policy")
}

fn count(value: u64) -> Result<usize, Failure> {
    usize::try_from(value).map_err(|_| invalid())
}

fn positive(value: u64) -> Result<NonZeroUsize, Failure> {
    NonZeroUsize::new(count(value)?).ok_or_else(invalid)
}

fn backoff(initial: u64, maximum: Option<u64>) -> Result<Option<Duration>, Failure> {
    if maximum.is_some_and(|maximum| maximum < initial) {
        return Err(invalid());
    }
    Ok(maximum.map(Duration::from_nanos))
}

impl RetryPolicy {
    pub(super) fn core(self) -> Result<phantom::RetryPolicy, Failure> {
        let mut policy = if let Some(connection) = self.connection {
            let mut policy = phantom::RetryPolicy::connection_failures(
                positive(connection.maximum)?,
                Duration::from_nanos(connection.delay_ns),
            )
            .with_full_jitter(connection.full_jitter);
            if let Some(maximum) = backoff(connection.delay_ns, connection.maximum_delay_ns)? {
                policy = policy.with_exponential_backoff(maximum);
            }
            policy
        } else {
            phantom::RetryPolicy::none()
        };
        if let Some(status) = self.status {
            let statuses = status
                .statuses
                .into_iter()
                .map(phantom::StatusCode::from_u16)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| invalid())?;
            let mut retry = phantom::StatusRetry::new(
                &statuses,
                positive(status.maximum)?,
                Duration::from_nanos(status.delay_ns),
            )
            .map_err(|_| invalid())?
            .with_full_jitter(status.full_jitter);
            if let Some(maximum) = backoff(status.delay_ns, status.maximum_delay_ns)? {
                retry = retry.with_exponential_backoff(maximum);
            }
            if let Some(maximum) = status.retry_after_limit_ns {
                retry = retry.honor_retry_after(Duration::from_nanos(maximum));
            }
            policy = policy.with_status_retry(retry);
        }
        Ok(policy
            .with_reused_connection_replay(self.reused_connection_replay)
            .with_unprocessed_replay(self.unprocessed_replays.map(positive).transpose()?)
            .with_max_retries(self.maximum_retries.map(count).transpose()?)
            .with_http2_fallback(self.http2_fallback))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_retry_class_maps_to_core_without_rounding() -> Result<(), Failure> {
        let policy: RetryPolicy = serde_json::from_str(
            r#"{
                "connection":{"maximum":2,"delay_ns":7,"maximum_delay_ns":31,"full_jitter":true},
                "status":{"statuses":[429,503],"maximum":3,"delay_ns":11,
                    "maximum_delay_ns":41,"full_jitter":true,"retry_after_limit_ns":61},
                "reused_connection_replay":true,"unprocessed_replays":4,
                "maximum_retries":5,"http2_fallback":true
            }"#,
        )
        .map_err(|_| Failure::new("invalid_json"))?;
        let policy = policy.core()?;
        assert_eq!(
            policy.max_connection_failures().map(NonZeroUsize::get),
            Some(2)
        );
        assert_eq!(policy.delay(), Duration::from_nanos(7));
        assert_eq!(policy.backoff_limit(), Some(Duration::from_nanos(31)));
        assert!(policy.full_jitter());
        assert!(policy.reused_connection_replay());
        assert_eq!(policy.unprocessed_replay().map(NonZeroUsize::get), Some(4));
        assert_eq!(policy.max_retries(), Some(5));
        assert!(policy.http2_fallback());
        let status = policy.status_retry().ok_or_else(invalid)?;
        assert!(status.retries(phantom::StatusCode::TOO_MANY_REQUESTS));
        assert!(status.retries(phantom::StatusCode::SERVICE_UNAVAILABLE));
        assert!(!status.retries(phantom::StatusCode::INTERNAL_SERVER_ERROR));
        assert_eq!(status.max_retries().get(), 3);
        assert_eq!(status.delay(), Duration::from_nanos(11));
        assert_eq!(status.backoff_limit(), Some(Duration::from_nanos(41)));
        assert!(status.full_jitter());
        assert_eq!(status.retry_after_limit(), Some(Duration::from_nanos(61)));
        let zero: RetryPolicy = serde_json::from_str(r#"{"maximum_retries":0}"#)
            .map_err(|_| Failure::new("invalid_json"))?;
        assert_eq!(zero.core()?.max_retries(), Some(0));
        assert_eq!(RetryPolicy::default().core()?, phantom::RetryPolicy::none());
        Ok(())
    }

    #[test]
    fn malformed_shapes_and_invalid_retry_values_are_rejected() -> Result<(), Failure> {
        for input in [
            r#"{"extra":true}"#,
            r#"{"maximum_retries":-1}"#,
            r#"{"maximum_retries":1.5}"#,
            r#"{"connection":{"maximum":1}}"#,
            r#"{"connection":{"maximum":1,"delay_ns":-1}}"#,
            r#"{"connection":{"maximum":1,"delay_ns":0,"extra":true}}"#,
            r#"{"status":{"statuses":[503],"maximum":1}}"#,
            r#"{"status":{"statuses":[65536],"maximum":1,"delay_ns":0}}"#,
            r#"{"status":{"statuses":[503],"maximum":1,"delay_ns":0,"extra":true}}"#,
        ] {
            assert!(
                serde_json::from_str::<RetryPolicy>(input).is_err(),
                "{input}"
            );
        }
        for input in [
            r#"{"unprocessed_replays":0}"#,
            r#"{"connection":{"maximum":0,"delay_ns":0}}"#,
            r#"{"connection":{"maximum":1,"delay_ns":2,"maximum_delay_ns":1}}"#,
            r#"{"status":{"statuses":[],"maximum":1,"delay_ns":0}}"#,
            r#"{"status":{"statuses":[421],"maximum":1,"delay_ns":0}}"#,
            r#"{"status":{"statuses":[503],"maximum":0,"delay_ns":0}}"#,
            r#"{"status":{"statuses":[503],"maximum":1,"delay_ns":2,"maximum_delay_ns":1}}"#,
        ] {
            let policy: RetryPolicy =
                serde_json::from_str(input).map_err(|_| Failure::new("invalid_json"))?;
            assert_eq!(
                policy.core().err().map(|error| error.kind),
                Some("invalid_retry_policy")
            );
        }
        #[cfg(target_pointer_width = "32")]
        {
            assert!(count(u64::MAX).is_err());
            assert!(positive(u64::MAX).is_err());
        }
        Ok(())
    }
}
