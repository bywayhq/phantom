//! Data-only operational pool overrides; defaults and policy bounds stay in core.

use std::{num::NonZeroUsize, time::Duration};

use phantom::ClientBuilder;
use serde::Deserialize;

use crate::error::Failure;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct PoolOptions {
    max_retained_http1_connections: Option<u64>,
    max_retained_http2_connections: Option<u64>,
    max_retained_http3_connections: Option<u64>,
    max_concurrent_http1_requests_per_origin: Option<u64>,
    max_pending_http1_requests_per_origin: Option<u64>,
    max_concurrent_http2_requests_per_origin: Option<u64>,
    max_pending_http2_requests_per_origin: Option<u64>,
    max_http2_connections_per_origin: Option<u64>,
    max_concurrent_http3_requests_per_origin: Option<u64>,
    max_pending_http3_requests_per_origin: Option<u64>,
    max_http3_connections_per_origin: Option<u64>,
    negotiated_setup_wait_limit_ns: Option<u64>,
}

impl PoolOptions {
    pub(super) fn apply(self, mut builder: ClientBuilder) -> Result<ClientBuilder, Failure> {
        if let Some(value) = count(self.max_retained_http1_connections)? {
            builder = builder.max_retained_http1_connections(value);
        }
        if let Some(value) = count(self.max_retained_http2_connections)? {
            builder = builder.max_retained_http2_connections(value);
        }
        if let Some(value) = count(self.max_retained_http3_connections)? {
            builder = builder.max_retained_http3_connections(value);
        }
        if let Some(value) = count(self.max_concurrent_http1_requests_per_origin)? {
            builder = builder.max_concurrent_http1_requests_per_origin(value);
        }
        if let Some(value) = count(self.max_pending_http1_requests_per_origin)? {
            builder = builder.max_pending_http1_requests_per_origin(value);
        }
        if let Some(value) = count(self.max_concurrent_http2_requests_per_origin)? {
            builder = builder.max_concurrent_http2_requests_per_origin(value);
        }
        if let Some(value) = count(self.max_pending_http2_requests_per_origin)? {
            builder = builder.max_pending_http2_requests_per_origin(value);
        }
        if let Some(value) = count(self.max_http2_connections_per_origin)? {
            builder = builder.max_http2_connections_per_origin(value);
        }
        if let Some(value) = count(self.max_concurrent_http3_requests_per_origin)? {
            builder = builder.max_concurrent_http3_requests_per_origin(value);
        }
        if let Some(value) = count(self.max_pending_http3_requests_per_origin)? {
            builder = builder.max_pending_http3_requests_per_origin(value);
        }
        if let Some(value) = count(self.max_http3_connections_per_origin)? {
            builder = builder.max_http3_connections_per_origin(value);
        }
        if let Some(value) = self.negotiated_setup_wait_limit_ns {
            builder = builder.negotiated_setup_wait_limit(Duration::from_nanos(value));
        }
        Ok(builder)
    }
}

fn count(value: Option<u64>) -> Result<Option<NonZeroUsize>, Failure> {
    value
        .map(|value| {
            usize::try_from(value)
                .ok()
                .and_then(NonZeroUsize::new)
                .ok_or_else(|| Failure::new("invalid_pool_options"))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(value: serde_json::Value) -> Result<phantom::Client, Failure> {
        let options: PoolOptions =
            serde_json::from_value(value).map_err(|_| Failure::new("invalid_test_fixture"))?;
        let profile = crate::profile::named("chrome/154.0.8037.97/windows-11-26200/r1", None)?;
        options
            .apply(phantom::Client::builder(profile))?
            .build()
            .map_err(Failure::from)
    }

    #[test]
    fn native_pool_options_reject_unknown_and_noninteger_fields() {
        for value in [
            serde_json::json!({"max_http2_proxy_connections_per_route": 2}),
            serde_json::json!({"max_retained_http1_connections": true}),
            serde_json::json!({"max_retained_http1_connections": -1}),
            serde_json::json!({"max_retained_http1_connections": 1.5}),
            serde_json::json!({"negotiated_setup_wait_limit_ns": -1}),
        ] {
            assert!(serde_json::from_value::<PoolOptions>(value).is_err());
        }
        assert_eq!(
            count(Some(0)).err().map(|error| error.kind),
            Some("invalid_pool_options")
        );
        assert!(count(Some(1)).is_ok());
    }

    #[test]
    fn core_validates_pool_bounds_without_an_invented_http2_connection_ceiling() {
        assert!(build(serde_json::json!({})).is_ok());
        assert!(
            build(serde_json::json!({"max_http2_connections_per_origin": 9,
            "max_http3_connections_per_origin": 8, "negotiated_setup_wait_limit_ns": 0}))
            .is_ok()
        );
        assert_eq!(
            build(serde_json::json!({"max_http3_connections_per_origin": 9}))
                .err()
                .map(|error| error.kind),
            Some("invalid_client_configuration")
        );
        assert_eq!(
            build(serde_json::json!({"max_pending_http2_requests_per_origin": u64::MAX}))
                .err()
                .map(|error| error.kind),
            Some("invalid_client_configuration")
        );
    }
}
