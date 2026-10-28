//! Verified encrypted DNS endpoints independent of application routes.

use std::error::Error as _;

use napi::Result;
use phantom::{
    AddressResolver, BuildError, BuildErrorKind,
    dns::{
        DnsOverHttps, DnsOverTls, DohBuildError, DohBuildErrorKind, DohConfiguration,
        DotConfiguration,
    },
    profile::ClientProfile,
};

use crate::error::failure;

pub(crate) enum Dns {
    Https(DohConfiguration, Vec<Vec<u8>>),
    Tls(DotConfiguration, Vec<Vec<u8>>),
}

impl Dns {
    pub(crate) fn build(self, profile: &ClientProfile) -> Result<AddressResolver> {
        match self {
            Self::Https(configuration, roots) => {
                let mut builder =
                    DnsOverHttps::builder(profile.clone(), configuration).map_err(https_error)?;
                for root in roots {
                    builder = builder.add_root_certificate_der(root);
                }
                builder
                    .build()
                    .map(|endpoint| endpoint.address_resolver())
                    .map_err(https_error)
            }
            Self::Tls(configuration, roots) => {
                let mut builder = DnsOverTls::builder(profile.tls().clone(), configuration);
                for root in roots {
                    builder = builder.add_root_certificate_der(root);
                }
                builder.build().map(|endpoint| endpoint.address_resolver()).map_err(|_| {
                    failure("InvalidConfiguration", "invalid DNS-over-TLS identity, bootstrap, limits, roots or TLS settings")
                })
            }
        }
    }
}

fn https_error(error: DohBuildError) -> napi::Error {
    let message = match error.kind() {
        DohBuildErrorKind::InvalidEndpoint => "invalid DNS-over-HTTPS endpoint",
        DohBuildErrorKind::InvalidBootstrap => "invalid DNS-over-HTTPS bootstrap addresses",
        DohBuildErrorKind::InvalidLimits => "invalid DNS-over-HTTPS lookup limits",
        DohBuildErrorKind::MissingHttp2 => "DNS-over-HTTPS requires an HTTP/2 profile",
        DohBuildErrorKind::Client => match error
            .source()
            .and_then(|cause| cause.downcast_ref::<BuildError>())
            .map(BuildError::kind)
        {
            Some(BuildErrorKind::TrustStore) => "invalid DNS-over-HTTPS trust roots",
            _ => "invalid DNS-over-HTTPS profile settings",
        },
    };
    failure("InvalidConfiguration", message)
}
