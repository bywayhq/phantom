//! Synchronous ownership and validation of encrypted resolver settings.

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    num::NonZeroU16,
    time::Duration,
};

use napi::{
    Env, Result,
    bindgen_prelude::{BigInt, Buffer, Either3, Null},
};
use napi_derive::napi;
use phantom::{
    AddressResolver,
    dns::{DohAddressFamilies, DohConfiguration, DohMethod, DotAddressFamilies, DotConfiguration},
    profile::ClientProfile,
};

use super::{
    buffer::{buffer_info, copy_buffer_info},
    positive_count,
};
use crate::{dns::Dns, error::failure};

const MAXIMUM_ENTRIES: usize = 1024;
const MAXIMUM_BYTES: usize = 65536;

/// Private normalized configuration; endpoint and certificate bytes stay out of Debug.
#[napi(object)]
pub struct DnsOptions {
    /// https or tls.
    pub kind: String,
    /// HTTPS endpoint URL.
    pub endpoint: Option<String>,
    /// DNS-over-TLS verification identity.
    pub server_name: Option<String>,
    /// IP literals for HTTPS, socket addresses for TLS.
    pub bootstrap: Vec<String>,
    /// Positive milliseconds for a complete lookup.
    pub timeout_ms: f64,
    /// Positive lookup admission bound.
    pub max_concurrent: BigInt,
    /// dual or ipv4.
    pub families: String,
    /// Additional DNS-only DER roots.
    pub roots: Vec<Buffer>,
    /// inherit keeps the preset, null disables padding, a number selects block bytes.
    pub padding_block: Either3<String, Null, f64>,
    /// HTTPS-only post or get.
    pub method: Option<String>,
    /// HTTPS-only standard or chromium154.
    pub wire: Option<String>,
    /// HTTPS-only response ID, 0..65535.
    pub query_id: Option<f64>,
}

impl fmt::Debug for DnsOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("DnsOptions").finish_non_exhaustive()
    }
}

enum Padding {
    Inherit,
    Disabled,
    Block(NonZeroU16),
}

fn invalid(message: &str) -> napi::Error {
    failure("InvalidConfiguration", message)
}

fn u16_value(value: f64, field: &str) -> Result<u16> {
    if !value.is_finite() || value.fract() != 0.0 || !(0.0..=f64::from(u16::MAX)).contains(&value) {
        return Err(invalid(field));
    }
    Ok(value as u16)
}

fn padding(value: Either3<String, Null, f64>) -> Result<Padding> {
    match value {
        Either3::A(value) if value == "inherit" => Ok(Padding::Inherit),
        Either3::A(_) => Err(invalid("invalid DNS padding block")),
        Either3::B(Null) => Ok(Padding::Disabled),
        Either3::C(value) => u16_value(value, "invalid DNS padding block").and_then(|value| {
            NonZeroU16::new(value)
                .map(Padding::Block)
                .ok_or_else(|| invalid("invalid DNS padding block"))
        }),
    }
}

pub(crate) fn resolver(
    env: &Env,
    profile: &ClientProfile,
    options: DnsOptions,
) -> Result<AddressResolver> {
    if options.bootstrap.is_empty()
        || options.bootstrap.len().saturating_add(options.roots.len()) > MAXIMUM_ENTRIES
    {
        return Err(failure(
            "InputLimit",
            "DNS configuration exceeds its entry limit",
        ));
    }
    let identity = match options.kind.as_str() {
        "https" if options.server_name.is_none() => options.endpoint.as_deref(),
        "tls"
            if options.endpoint.is_none()
                && options.method.is_none()
                && options.wire.is_none()
                && options.query_id.is_none() =>
        {
            options.server_name.as_deref()
        }
        _ => return Err(invalid("DNS fields do not match their transport")),
    }
    .ok_or_else(|| invalid("DNS identity is required"))?;
    let mut remaining = MAXIMUM_BYTES
        .checked_sub(identity.len())
        .ok_or_else(|| failure("InputLimit", "DNS configuration exceeds its byte limit"))?;
    for address in &options.bootstrap {
        remaining = remaining
            .checked_sub(address.len())
            .ok_or_else(|| failure("InputLimit", "DNS configuration exceeds its byte limit"))?;
    }
    let roots = options
        .roots
        .into_iter()
        .map(|root| {
            let info = buffer_info(env, root)?;
            remaining = remaining
                .checked_sub(info.1)
                .ok_or_else(|| failure("InputLimit", "DNS configuration exceeds its byte limit"))?;
            Ok(info)
        })
        .collect::<Result<Vec<_>>>()?;

    if !options.timeout_ms.is_finite() || options.timeout_ms <= 0.0 {
        return Err(invalid(
            "DNS timeoutMs must be finite positive milliseconds",
        ));
    }
    let timeout = Duration::try_from_secs_f64(options.timeout_ms / 1000.0)
        .map_err(|_| invalid("invalid DNS timeoutMs"))?;
    if timeout.is_zero() {
        return Err(invalid("DNS timeoutMs is smaller than one nanosecond"));
    }
    let maximum =
        positive_count(options.max_concurrent).map_err(|_| invalid("invalid DNS maxConcurrent"))?;
    let dual = match options.families.as_str() {
        "dual" => true,
        "ipv4" => false,
        _ => return Err(invalid("DNS families must be dual or ipv4")),
    };
    let padding = padding(options.padding_block)?;
    let roots = roots
        .into_iter()
        .map(|info| copy_buffer_info(info, MAXIMUM_BYTES))
        .collect::<Result<Vec<_>>>()?;
    let dns = match options.kind.as_str() {
        "https" => {
            let method = match options.method.as_deref() {
                Some("post") => DohMethod::Post,
                Some("get") => DohMethod::Get,
                _ => return Err(invalid("DNS method must be post or get")),
            };
            let query_id = u16_value(
                options
                    .query_id
                    .ok_or_else(|| invalid("DNS queryId is required"))?,
                "invalid DNS queryId",
            )?;
            let bootstrap = options
                .bootstrap
                .iter()
                .map(|address| {
                    address
                        .parse::<IpAddr>()
                        .map_err(|_| invalid("invalid DNS-over-HTTPS bootstrap address"))
                })
                .collect::<Result<Vec<_>>>()?;
            let families = if dual {
                DohAddressFamilies::DualIpv6First
            } else {
                DohAddressFamilies::Ipv4Only
            };
            let configuration =
                DohConfiguration::new(identity, bootstrap, method, families, timeout, maximum);
            let configuration = match options.wire.as_deref() {
                Some("standard") => configuration,
                Some("chromium154") => configuration.chromium154_wire(),
                _ => return Err(invalid("DNS wire must be standard or chromium154")),
            };
            let configuration = match padding {
                Padding::Inherit => configuration,
                Padding::Disabled => configuration.padding_block(None),
                Padding::Block(block) => configuration.padding_block(Some(block)),
            };
            Dns::Https(configuration.query_id(query_id), roots)
        }
        "tls" => {
            if maximum.get() > 32767 {
                return Err(invalid("DNS-over-TLS maxConcurrent must be at most 32767"));
            }
            let bootstrap = options
                .bootstrap
                .iter()
                .map(|address| {
                    address
                        .parse::<SocketAddr>()
                        .map_err(|_| invalid("invalid DNS-over-TLS bootstrap address"))
                })
                .collect::<Result<Vec<_>>>()?;
            let families = if dual {
                DotAddressFamilies::DualIpv6First
            } else {
                DotAddressFamilies::Ipv4Only
            };
            let block = match padding {
                Padding::Inherit | Padding::Disabled => None,
                Padding::Block(block) => Some(block),
            };
            Dns::Tls(
                DotConfiguration::new(identity, bootstrap, families, timeout, maximum)
                    .padding_block(block),
                roots,
            )
        }
        _ => return Err(invalid("DNS kind must be https or tls")),
    };
    dns.build(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_dns_fields_reject_fractional_out_of_range_and_nonfinite_values() {
        for value in [-1.0, 0.5, 65536.0, f64::NAN, f64::INFINITY] {
            assert!(u16_value(value, "invalid DNS queryId").is_err());
            assert!(padding(Either3::C(value)).is_err());
        }
        assert!(padding(Either3::C(0.0)).is_err());
        assert_eq!(u16_value(0.0, "invalid DNS queryId").ok(), Some(0));
        assert_eq!(u16_value(65535.0, "invalid DNS queryId").ok(), Some(65535));
        assert!(matches!(
            padding(Either3::A("inherit".into())),
            Ok(Padding::Inherit)
        ));
        assert!(padding(Either3::A("private".into())).is_err());
        assert!(matches!(padding(Either3::B(Null)), Ok(Padding::Disabled)));
        assert!(
            matches!(padding(Either3::C(128.0)), Ok(Padding::Block(block)) if block.get() == 128)
        );
    }

    #[test]
    fn debug_omits_dns_identity_bootstrap_and_roots() {
        let options = DnsOptions {
            kind: "https".into(),
            endpoint: Some("https://private.invalid/query".into()),
            server_name: None,
            bootstrap: vec!["private-bootstrap".into()],
            timeout_ms: 1000.0,
            max_concurrent: BigInt::from(1u64),
            families: "ipv4".into(),
            roots: Vec::new(),
            padding_block: Either3::A("inherit".into()),
            method: Some("post".into()),
            wire: Some("standard".into()),
            query_id: Some(0.0),
        };
        assert_eq!(format!("{options:?}"), "DnsOptions { .. }");
    }
}
