use std::{num::NonZeroUsize, time::Duration};

use phantom::{RequestTimeoutOverrides, RequestTimeouts, Route, TimeoutOverride};
use pyo3::{
    prelude::*,
    types::{PyBytes, PyTuple},
};

use crate::error;

pub(super) type TimeoutFields = Vec<(String, Option<f64>)>;

#[derive(FromPyObject)]
struct ConnectionRetrySettings {
    maximum: usize,
    delay: f64,
    maximum_delay: Option<f64>,
    full_jitter: bool,
}

#[derive(FromPyObject)]
struct StatusRetrySettings {
    statuses: Vec<u16>,
    maximum: usize,
    delay: f64,
    maximum_delay: Option<f64>,
    full_jitter: bool,
    retry_after_limit: Option<f64>,
}

#[derive(FromPyObject)]
pub(super) struct RetrySettings {
    connection_failures: Option<ConnectionRetrySettings>,
    reused_connection_replay: bool,
    unprocessed_replays: Option<usize>,
    status_retry: Option<StatusRetrySettings>,
    maximum_retries: Option<usize>,
    http2_fallback: bool,
}

pub(super) fn server_pins(
    value: Option<&Bound<'_, PyAny>>,
    kind: &'static str,
) -> PyResult<Option<phantom::ServerSpkiPins>> {
    let Some(value) = value else { return Ok(None) };
    let values = value.cast::<PyTuple>().map_err(|_| error::input(kind))?;
    if !(1..=32).contains(&values.len()) {
        return Err(error::input(kind));
    }
    let mut digests = Vec::with_capacity(values.len());
    for value in values.iter() {
        let bytes = value.cast::<PyBytes>().map_err(|_| error::input(kind))?;
        let digest = bytes
            .as_bytes()
            .try_into()
            .map_err(|_| error::input(kind))?;
        digests.push(digest);
    }
    phantom::ServerSpkiPins::new(digests)
        .map(Some)
        .map_err(|_| error::input(kind))
}

fn retry_duration(seconds: f64) -> PyResult<Duration> {
    Duration::try_from_secs_f64(seconds).map_err(|_| error::input("invalid_retry_duration"))
}

fn retry_maximum(maximum: usize) -> PyResult<NonZeroUsize> {
    NonZeroUsize::new(maximum).ok_or_else(|| error::input("invalid_retry_maximum"))
}

pub(super) fn retry_policy(settings: RetrySettings) -> PyResult<phantom::RetryPolicy> {
    let mut policy = match settings.connection_failures {
        None => phantom::RetryPolicy::none(),
        Some(connection) => {
            let mut policy = phantom::RetryPolicy::connection_failures(
                retry_maximum(connection.maximum)?,
                retry_duration(connection.delay)?,
            )
            .with_full_jitter(connection.full_jitter);
            if let Some(cap) = connection.maximum_delay {
                policy = policy.with_exponential_backoff(retry_duration(cap)?);
            }
            policy
        }
    };
    if let Some(settings) = settings.status_retry {
        let statuses = settings
            .statuses
            .into_iter()
            .map(phantom::StatusCode::from_u16)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| error::input("invalid_retry_status"))?;
        let mut status = phantom::StatusRetry::new(
            &statuses,
            retry_maximum(settings.maximum)?,
            retry_duration(settings.delay)?,
        )
        .map_err(|_| error::input("invalid_retry_status"))?
        .with_full_jitter(settings.full_jitter);
        if let Some(cap) = settings.maximum_delay {
            status = status.with_exponential_backoff(retry_duration(cap)?);
        }
        if let Some(maximum) = settings.retry_after_limit {
            status = status.honor_retry_after(retry_duration(maximum)?);
        }
        policy = policy.with_status_retry(status);
    }
    Ok(policy
        .with_reused_connection_replay(settings.reused_connection_replay)
        .with_unprocessed_replay(
            settings
                .unprocessed_replays
                .map(retry_maximum)
                .transpose()?,
        )
        .with_max_retries(settings.maximum_retries)
        .with_http2_fallback(settings.http2_fallback))
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
    fn native_pin_boundary_rejects_invalid_shapes_and_keeps_core_canonicalization() -> PyResult<()>
    {
        Python::initialize();
        Python::attach(|py| {
            assert!(server_pins(None, "invalid_server_spki_pins")?.is_none());
            let kind = "invalid_server_spki_pins";
            for expression in [
                "[]",
                "()",
                "(b'x' * 32,) * 33",
                "(b'x',)",
                "(bytearray(32),)",
                "('private',)",
            ] {
                let code = std::ffi::CString::new(expression)
                    .map_err(|_| error::input("test_expression"))?;
                let value = py.eval(&code, None, None)?;
                let error = server_pins(Some(&value), kind)
                    .err()
                    .ok_or_else(|| error::input("test_expected_pin_error"))?;
                let fields: (String, String, Option<String>, Option<String>) =
                    error.value(py).getattr("args")?.extract()?;
                assert_eq!(fields, ("input".into(), kind.into(), None, None));
                assert!(!error.to_string().contains("private"));
            }
            let value = PyTuple::new(
                py,
                [
                    PyBytes::new(py, &[2; 32]),
                    PyBytes::new(py, &[1; 32]),
                    PyBytes::new(py, &[2; 32]),
                ],
            )?;
            let pins = server_pins(Some(value.as_any()), kind)?
                .ok_or_else(|| error::input("test_missing_pins"))?;
            assert_eq!(pins.sha256_digests(), &[[1; 32], [2; 32]]);
            let value = PyTuple::new(py, (0..32).map(|_| PyBytes::new(py, &[1; 32])))?;
            assert!(server_pins(Some(value.as_any()), "invalid_proxy_server_spki_pins")?.is_some());
            Ok(())
        })
    }

    #[test]
    fn retry_attributes_preserve_every_core_class_and_schedule() -> PyResult<()> {
        Python::initialize();
        Python::attach(|py| {
            let fields = py.eval(
                c"__import__('types').SimpleNamespace(
                    http2_fallback=True, maximum_retries=0, unprocessed_replays=5,
                    reused_connection_replay=True,
                    connection_failures=__import__('types').SimpleNamespace(
                        full_jitter=True, maximum_delay=4, delay=0.25, maximum=3),
                    status_retry=__import__('types').SimpleNamespace(
                        retry_after_limit=9, full_jitter=True, maximum_delay=8,
                        delay=0.5, maximum=6, statuses=(503, 429, 503)))",
                None,
                None,
            )?;
            let policy = retry_policy(fields.extract()?)?;
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
            Ok(())
        })
    }

    #[test]
    fn retry_boundary_rejects_positional_and_incomplete_settings() -> PyResult<()> {
        Python::initialize();
        Python::attach(|py| {
            for expression in [
                "(None, False, None, None, None, False)",
                "__import__('types').SimpleNamespace()",
                "__import__('types').SimpleNamespace(connection_failures=None)",
            ] {
                let code = std::ffi::CString::new(expression)
                    .map_err(|_| error::input("test_expression"))?;
                let fields = py.eval(&code, None, None)?;
                assert!(fields.extract::<RetrySettings>().is_err());
            }

            let fields = py.eval(
                c"__import__('types').SimpleNamespace(
                    connection_failures=None, reused_connection_replay=False,
                    unprocessed_replays=None, status_retry=None,
                    maximum_retries=None, http2_fallback=False)",
                None,
                None,
            )?;
            assert_eq!(
                retry_policy(fields.extract()?)?,
                phantom::RetryPolicy::none()
            );
            Ok(())
        })
    }
}
