//! Construction-only encrypted DNS settings; lookups stay in the Rust resolver.

use std::{
    error::Error as _,
    net::{IpAddr, SocketAddr},
    num::{NonZeroU16, NonZeroUsize},
    time::Duration,
};

use phantom::{
    AddressResolver, BuildError, BuildErrorKind,
    dns::{
        DnsOverHttps, DnsOverTls, DohAddressFamilies, DohBuildError, DohBuildErrorKind,
        DohConfiguration, DohMethod, DotAddressFamilies, DotConfiguration,
    },
    profile::ClientProfile,
};
use serde::Deserialize;

use crate::error::Failure;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub(super) enum Dns {
    Https {
        endpoint: String,
        bootstrap: Vec<String>,
        timeout_ns: u64,
        max_concurrent: u32,
        families: Families,
        additional_roots_der: Vec<Vec<u8>>,
        method: Method,
        wire: Wire,
        query_id: u16,
        padding_block: Option<u16>,
    },
    Tls {
        server_name: String,
        bootstrap: Vec<String>,
        timeout_ns: u64,
        max_concurrent: u32,
        families: Families,
        additional_roots_der: Vec<Vec<u8>>,
        padding_block: Option<u16>,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Families {
    Dual,
    Ipv4,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Method {
    Post,
    Get,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Wire {
    Standard,
    Chromium154,
}

impl Dns {
    pub(super) fn validate(&self, entries: &mut usize, bytes: &mut usize) -> Result<(), Failure> {
        let (identity, bootstrap, roots, timeout, maximum) = match self {
            Self::Https {
                endpoint,
                bootstrap,
                additional_roots_der,
                timeout_ns,
                max_concurrent,
                ..
            } => (
                endpoint,
                bootstrap,
                additional_roots_der,
                timeout_ns,
                max_concurrent,
            ),
            Self::Tls {
                server_name,
                bootstrap,
                additional_roots_der,
                timeout_ns,
                max_concurrent,
                ..
            } => (
                server_name,
                bootstrap,
                additional_roots_der,
                timeout_ns,
                max_concurrent,
            ),
        };
        if bootstrap.is_empty() {
            return Err(Failure::new("invalid_dns_bootstrap"));
        }
        *entries = entries
            .checked_add(bootstrap.len())
            .and_then(|count| count.checked_add(roots.len()))
            .filter(|count| *count <= 1024)
            .ok_or_else(|| Failure::new("input_limit"))?;
        for size in std::iter::once(identity.len())
            .chain(bootstrap.iter().map(String::len))
            .chain(roots.iter().map(Vec::len))
        {
            *bytes = bytes
                .checked_sub(size)
                .ok_or_else(|| Failure::new("input_limit"))?;
        }
        if *timeout == 0 {
            return Err(Failure::new("invalid_dns_timeout"));
        }
        let maximum = usize::try_from(*maximum).map_err(|_| Failure::new("invalid_dns_limits"))?;
        if maximum == 0 || maximum > tokio::sync::Semaphore::MAX_PERMITS {
            return Err(Failure::new("invalid_dns_limits"));
        }
        if matches!(self, Self::Tls { .. }) && maximum > 32767 {
            return Err(Failure::new("invalid_dns_limits"));
        }
        Ok(())
    }

    pub(super) fn build(self, profile: &ClientProfile) -> Result<AddressResolver, Failure> {
        match self {
            Self::Https {
                endpoint,
                bootstrap,
                timeout_ns,
                max_concurrent,
                families,
                additional_roots_der,
                method,
                wire,
                query_id,
                padding_block,
            } => {
                let bootstrap = bootstrap
                    .iter()
                    .map(|address| address.parse::<IpAddr>())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| Failure::new("invalid_dns_bootstrap"))?;
                let families = match families {
                    Families::Dual => DohAddressFamilies::DualIpv6First,
                    Families::Ipv4 => DohAddressFamilies::Ipv4Only,
                };
                let method = match method {
                    Method::Get => DohMethod::Get,
                    Method::Post => DohMethod::Post,
                };
                let maximum = maximum(max_concurrent)?;
                let configuration = DohConfiguration::new(
                    endpoint,
                    bootstrap,
                    method,
                    families,
                    Duration::from_nanos(timeout_ns),
                    maximum,
                );
                let configuration = match wire {
                    Wire::Standard => configuration,
                    Wire::Chromium154 => configuration.chromium154_wire(),
                };
                let configuration = match padding_block {
                    None => configuration,
                    Some(block) => configuration.padding_block(NonZeroU16::new(block)),
                };
                let mut builder =
                    DnsOverHttps::builder(profile.clone(), configuration.query_id(query_id))
                        .map_err(https_error)?;
                for root in additional_roots_der {
                    builder = builder.add_root_certificate_der(root);
                }
                builder
                    .build()
                    .map(|endpoint| endpoint.address_resolver())
                    .map_err(https_error)
            }
            Self::Tls {
                server_name,
                bootstrap,
                timeout_ns,
                max_concurrent,
                families,
                additional_roots_der,
                padding_block,
            } => {
                let bootstrap = bootstrap
                    .iter()
                    .map(|address| address.parse::<SocketAddr>())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| Failure::new("invalid_dns_bootstrap"))?;
                if bootstrap.iter().any(|address| address.port() == 0) {
                    return Err(Failure::new("invalid_dns_bootstrap"));
                }
                let families = match families {
                    Families::Dual => DotAddressFamilies::DualIpv6First,
                    Families::Ipv4 => DotAddressFamilies::Ipv4Only,
                };
                let configuration = DotConfiguration::new(
                    server_name,
                    bootstrap,
                    families,
                    Duration::from_nanos(timeout_ns),
                    maximum(max_concurrent)?,
                )
                .padding_block(padding_block.and_then(NonZeroU16::new));
                let mut builder = DnsOverTls::builder(profile.tls().clone(), configuration);
                for root in additional_roots_der {
                    builder = builder.add_root_certificate_der(root);
                }
                builder
                    .build()
                    .map(|endpoint| endpoint.address_resolver())
                    .map_err(|_| Failure::new("invalid_dns_tls"))
            }
        }
    }
}

fn maximum(value: u32) -> Result<NonZeroUsize, Failure> {
    usize::try_from(value)
        .ok()
        .and_then(NonZeroUsize::new)
        .ok_or_else(|| Failure::new("invalid_dns_limits"))
}

fn https_error(error: DohBuildError) -> Failure {
    Failure::new(match error.kind() {
        DohBuildErrorKind::InvalidEndpoint => "invalid_dns_endpoint",
        DohBuildErrorKind::InvalidBootstrap => "invalid_dns_bootstrap",
        DohBuildErrorKind::InvalidLimits => "invalid_dns_limits",
        DohBuildErrorKind::MissingHttp2 => "dns_missing_http2",
        DohBuildErrorKind::Client => match error
            .source()
            .and_then(|cause| cause.downcast_ref::<BuildError>())
            .map(BuildError::kind)
        {
            Some(BuildErrorKind::TrustStore) => "invalid_dns_roots",
            _ => "invalid_dns_profile",
        },
    })
}
