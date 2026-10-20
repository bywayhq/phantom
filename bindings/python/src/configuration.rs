use crate::error;
use phantom::{RequestTimeoutOverrides, RequestTimeouts, Route, TimeoutOverride};
use pyo3::prelude::*;
use std::num::NonZeroUsize;
use std::time::Duration;

pub(super) type TimeoutFields = Vec<(String, Option<f64>)>;
type ConnectionRetryFields = (usize, f64, Option<f64>, bool);
type StatusRetryFields = (Vec<u16>, usize, f64, Option<f64>, bool, Option<f64>);
pub(super) type RetryFields = (
    Option<ConnectionRetryFields>,
    bool,
    Option<usize>,
    Option<StatusRetryFields>,
    Option<usize>,
    bool,
);

fn retry_duration(seconds: f64) -> PyResult<Duration> {
    Duration::try_from_secs_f64(seconds).map_err(|_| error::input("invalid_retry_duration"))
}

fn retry_maximum(maximum: usize) -> PyResult<NonZeroUsize> {
    NonZeroUsize::new(maximum).ok_or_else(|| error::input("invalid_retry_maximum"))
}

pub(super) fn retry_policy(fields: RetryFields) -> PyResult<phantom::RetryPolicy> {
    let (connection, reused, unprocessed, status, maximum, fallback) = fields;
    let mut policy = match connection {
        None => phantom::RetryPolicy::none(),
        Some((maximum, delay, cap, jitter)) => {
            let mut policy = phantom::RetryPolicy::connection_failures(
                retry_maximum(maximum)?,
                retry_duration(delay)?,
            )
            .with_full_jitter(jitter);
            if let Some(cap) = cap {
                policy = policy.with_exponential_backoff(retry_duration(cap)?);
            }
            policy
        }
    };
    if let Some((statuses, maximum, delay, cap, jitter, retry_after)) = status {
        let statuses = statuses
            .into_iter()
            .map(phantom::StatusCode::from_u16)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| error::input("invalid_retry_status"))?;
        let mut status =
            phantom::StatusRetry::new(&statuses, retry_maximum(maximum)?, retry_duration(delay)?)
                .map_err(|_| error::input("invalid_retry_status"))?
                .with_full_jitter(jitter);
        if let Some(cap) = cap {
            status = status.with_exponential_backoff(retry_duration(cap)?);
        }
        if let Some(maximum) = retry_after {
            status = status.honor_retry_after(retry_duration(maximum)?);
        }
        policy = policy.with_status_retry(status);
    }
    Ok(policy
        .with_reused_connection_replay(reused)
        .with_unprocessed_replay(unprocessed.map(retry_maximum).transpose()?)
        .with_max_retries(maximum)
        .with_http2_fallback(fallback))
}

pub(super) fn redirect_policy(maximum: usize) -> phantom::RedirectPolicy {
    NonZeroUsize::new(maximum).map_or_else(
        phantom::RedirectPolicy::none,
        phantom::RedirectPolicy::limited,
    )
}

pub(super) fn route(
    uri: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
) -> PyResult<Route> {
    let credentials = match (username, password) {
        (None, None) => None,
        (Some(username), Some(password)) => Some((username, password)),
        _ => return Err(error::input("proxy_credentials_pair")),
    };
    let Some(uri) = uri else {
        return if credentials.is_none() {
            Ok(Route::direct())
        } else {
            Err(error::input("proxy_credentials_without_route"))
        };
    };
    match uri.split_once("://").map(|(scheme, _)| scheme) {
        Some("http" | "https") => {
            let mut proxy =
                phantom::HttpProxy::new(uri).map_err(|_| error::input("invalid_http_proxy"))?;
            if let Some((username, password)) = credentials {
                proxy = proxy
                    .with_basic_auth(username, password)
                    .map_err(|_| error::input("invalid_proxy_credentials"))?;
            }
            Ok(Route::http_proxy(proxy))
        }
        Some("socks4" | "socks4a") if credentials.is_none() => phantom::Socks4Proxy::new(uri)
            .map(Route::socks4)
            .map_err(|_| error::input("invalid_socks4_proxy")),
        Some("socks5" | "socks5h") => {
            let mut proxy =
                phantom::Socks5Proxy::new(uri).map_err(|_| error::input("invalid_socks5_proxy"))?;
            if let Some((username, password)) = credentials {
                proxy = proxy
                    .with_username_password(username, password)
                    .map_err(|_| error::input("invalid_proxy_credentials"))?;
            }
            Ok(Route::socks5(proxy))
        }
        Some("socks4" | "socks4a") => Err(error::input("proxy_credentials_unsupported")),
        _ => Err(error::input("invalid_proxy_scheme")),
    }
}

fn fields(input: TimeoutFields) -> PyResult<[TimeoutOverride; 5]> {
    let mut values = [TimeoutOverride::Inherit; 5];
    let mut seen = [false; 5];
    if input.len() > values.len() {
        return Err(error::input("invalid_timeouts"));
    }
    for (name, seconds) in input {
        let index = match name.as_str() {
            "pool_admission" => 0,
            "connect" => 1,
            "response_head" => 2,
            "read_idle" => 3,
            "total" => 4,
            _ => return Err(error::input("invalid_timeout_phase")),
        };
        if seen[index] {
            return Err(error::input("duplicate_timeout_phase"));
        }
        seen[index] = true;
        values[index] = match seconds {
            None => TimeoutOverride::Disabled,
            Some(seconds) => TimeoutOverride::Limit(
                Duration::try_from_secs_f64(seconds)
                    .map_err(|_| error::input("invalid_timeout"))?,
            ),
        };
    }
    Ok(values)
}

pub(super) fn request_timeouts(
    timeout_ms: Option<u64>,
    input: Option<TimeoutFields>,
) -> PyResult<RequestTimeoutOverrides> {
    if timeout_ms.is_some() && input.is_some() {
        return Err(error::input("conflicting_timeouts"));
    }
    if let Some(timeout) = timeout_ms {
        return Ok(RequestTimeoutOverrides::new()
            .total(TimeoutOverride::Limit(Duration::from_millis(timeout))));
    }
    let [pool, connect, head, idle, total] = fields(input.unwrap_or_default())?;
    Ok(RequestTimeoutOverrides::new()
        .pool_admission(pool)
        .connect(connect)
        .response_head(head)
        .read_idle(idle)
        .total(total))
}

pub(super) fn client_timeouts(
    timeout_ms: Option<u64>,
    input: Option<TimeoutFields>,
) -> PyResult<RequestTimeouts> {
    Ok(request_timeouts(timeout_ms, input)?.resolve(RequestTimeouts::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_fields_preserve_every_core_class_and_schedule() -> PyResult<()> {
        let policy = retry_policy((
            Some((3, 0.25, Some(4.0), true)),
            true,
            Some(5),
            Some((vec![503, 429, 503], 6, 0.5, Some(8.0), true, Some(9.0))),
            Some(0),
            true,
        ))?;
        assert_eq!(policy.max_connection_failures(), NonZeroUsize::new(3));
        assert_eq!(policy.delay(), Duration::from_millis(250));
        assert_eq!(policy.backoff_limit(), Some(Duration::from_secs(4)));
        assert!(policy.full_jitter());
        assert!(policy.reused_connection_replay());
        assert_eq!(policy.unprocessed_replay(), NonZeroUsize::new(5));
        assert_eq!(policy.max_retries(), Some(0));
        assert!(policy.http2_fallback());
        let status = policy
            .status_retry()
            .ok_or_else(|| error::input("test_status_policy_missing"))?;
        assert!(status.retries(phantom::StatusCode::SERVICE_UNAVAILABLE));
        assert!(status.retries(phantom::StatusCode::TOO_MANY_REQUESTS));
        assert!(!status.retries(phantom::StatusCode::INTERNAL_SERVER_ERROR));
        assert_eq!(status.max_retries().get(), 6);
        assert_eq!(status.delay(), Duration::from_millis(500));
        assert_eq!(status.backoff_limit(), Some(Duration::from_secs(8)));
        assert_eq!(status.retry_after_limit(), Some(Duration::from_secs(9)));
        assert!(status.full_jitter());
        assert_eq!(
            retry_policy((None, false, None, None, None, false))?,
            phantom::RetryPolicy::none()
        );
        Ok(())
    }
}
