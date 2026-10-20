use crate::error;
use phantom::{RequestTimeoutOverrides, RequestTimeouts, Route, TimeoutOverride};
use pyo3::prelude::*;
use std::time::Duration;

pub(super) type TimeoutFields = Vec<(String, Option<f64>)>;

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
