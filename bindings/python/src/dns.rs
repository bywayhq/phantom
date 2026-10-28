//! Data-only encrypted DNS endpoints using the core's bounded resolvers.

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
use pyo3::{
    prelude::*,
    types::{PyBytes, PyFloat, PyInt, PyString, PyTuple},
};

use crate::error;

const MAXIMUM_ENTRIES: usize = 1024;
const MAXIMUM_BYTES: usize = 65536;

pub(super) enum Dns {
    Https(DohConfiguration, Vec<Vec<u8>>),
    Tls(DotConfiguration, Vec<Vec<u8>>),
}

#[derive(FromPyObject)]
struct Fields<'py> {
    bootstrap: Bound<'py, PyTuple>,
    timeout: Bound<'py, PyAny>,
    max_concurrent: Bound<'py, PyAny>,
    families: Bound<'py, PyAny>,
    roots: Bound<'py, PyTuple>,
    padding_block: Bound<'py, PyAny>,
}

enum Padding {
    Inherit,
    Disabled,
    Block(NonZeroU16),
}

pub(super) fn is_inherit(value: &Bound<'_, PyAny>, kind: &'static str) -> PyResult<bool> {
    let inherit = value
        .py()
        .import("phantom_http._configuration")
        .and_then(|module| module.getattr("INHERIT"))
        .map_err(|_| error::input(kind))?;
    Ok(value.is(&inherit))
}

fn text<'a>(value: &'a Bound<'_, PyAny>, kind: &'static str) -> PyResult<&'a str> {
    let value = value
        .cast_exact::<PyString>()
        .map_err(|_| error::input(kind))?;
    if value.len()? > MAXIMUM_BYTES {
        return Err(error::input("dns_limit"));
    }
    value.to_str().map_err(|_| error::input(kind))
}

fn field<'py>(value: &Bound<'py, PyAny>, name: &str) -> PyResult<Bound<'py, PyAny>> {
    value.getattr(name).map_err(|_| error::input("invalid_dns"))
}

fn integer(value: &Bound<'_, PyAny>, kind: &'static str) -> PyResult<usize> {
    value
        .cast_exact::<PyInt>()
        .map_err(|_| error::input(kind))?
        .extract()
        .map_err(|_| error::input(kind))
}

fn padding(value: &Bound<'_, PyAny>) -> PyResult<Padding> {
    if value.is_none() {
        return Ok(Padding::Disabled);
    }
    if value.cast_exact::<PyInt>().is_ok() {
        return integer(value, "invalid_dns_padding")?
            .try_into()
            .ok()
            .and_then(NonZeroU16::new)
            .map(Padding::Block)
            .ok_or_else(|| error::input("invalid_dns_padding"));
    }
    if is_inherit(value, "invalid_dns_padding")? {
        return Ok(Padding::Inherit);
    }
    Err(error::input("invalid_dns_padding"))
}

fn account(remaining: &mut usize, size: usize) -> PyResult<()> {
    *remaining = remaining
        .checked_sub(size)
        .ok_or_else(|| error::input("dns_limit"))?;
    Ok(())
}

pub(super) fn parse(value: &Bound<'_, PyAny>) -> PyResult<Dns> {
    let kind = field(value, "_kind")?;
    let kind = text(&kind, "invalid_dns")?;
    let identity = match kind {
        "https" => field(value, "endpoint")?,
        "tls" => field(value, "server_name")?,
        _ => return Err(error::input("invalid_dns")),
    };
    let fields = value
        .extract::<Fields<'_>>()
        .map_err(|_| error::input("invalid_dns"))?;
    if fields.bootstrap.is_empty()
        || fields.bootstrap.len().saturating_add(fields.roots.len()) > MAXIMUM_ENTRIES
    {
        return Err(error::input("dns_limit"));
    }
    let identity = text(&identity, "invalid_dns_identity")?;
    let mut remaining = MAXIMUM_BYTES;
    account(&mut remaining, identity.len())?;
    for address in fields.bootstrap.iter() {
        account(
            &mut remaining,
            text(&address, "invalid_dns_bootstrap")?.len(),
        )?;
    }
    for root in fields.roots.iter() {
        let root = root
            .cast_exact::<PyBytes>()
            .map_err(|_| error::input("invalid_dns_roots"))?;
        account(&mut remaining, root.as_bytes().len())?;
    }

    if fields.timeout.cast_exact::<PyInt>().is_err()
        && fields.timeout.cast_exact::<PyFloat>().is_err()
    {
        return Err(error::input("invalid_dns_timeout"));
    }
    let timeout = Duration::try_from_secs_f64(
        fields
            .timeout
            .extract::<f64>()
            .map_err(|_| error::input("invalid_dns_timeout"))?,
    )
    .map_err(|_| error::input("invalid_dns_timeout"))?;
    if timeout.is_zero() {
        return Err(error::input("invalid_dns_timeout"));
    }
    let maximum = NonZeroUsize::new(integer(&fields.max_concurrent, "invalid_dns_limits")?)
        .ok_or_else(|| error::input("invalid_dns_limits"))?;
    let dual = match text(&fields.families, "invalid_dns_families")? {
        "dual" => true,
        "ipv4" => false,
        _ => return Err(error::input("invalid_dns_families")),
    };
    let padding = padding(&fields.padding_block)?;
    let roots = fields
        .roots
        .iter()
        .map(|root| {
            root.cast_exact::<PyBytes>()
                .map(|root| root.as_bytes().to_vec())
                .map_err(|_| error::input("invalid_dns_roots"))
        })
        .collect::<PyResult<_>>()?;

    match kind {
        "https" => {
            let method = field(value, "method")?;
            let method = match text(&method, "invalid_dns_method")? {
                "post" => DohMethod::Post,
                "get" => DohMethod::Get,
                _ => return Err(error::input("invalid_dns_method")),
            };
            let wire = field(value, "wire")?;
            let query_id = integer(&field(value, "query_id")?, "invalid_dns_query_id")?
                .try_into()
                .map_err(|_| error::input("invalid_dns_query_id"))?;
            let bootstrap = fields
                .bootstrap
                .iter()
                .map(|address| {
                    text(&address, "invalid_dns_bootstrap")?
                        .parse::<IpAddr>()
                        .map_err(|_| error::input("invalid_dns_bootstrap"))
                })
                .collect::<PyResult<Vec<_>>>()?;
            let families = if dual {
                DohAddressFamilies::DualIpv6First
            } else {
                DohAddressFamilies::Ipv4Only
            };
            let configuration =
                DohConfiguration::new(identity, bootstrap, method, families, timeout, maximum);
            let configuration = match text(&wire, "invalid_dns_wire")? {
                "standard" => configuration,
                "chromium154" => configuration.chromium154_wire(),
                _ => return Err(error::input("invalid_dns_wire")),
            };
            let configuration = match padding {
                Padding::Inherit => configuration,
                Padding::Disabled => configuration.padding_block(None),
                Padding::Block(block) => configuration.padding_block(Some(block)),
            };
            Ok(Dns::Https(configuration.query_id(query_id), roots))
        }
        "tls" => {
            if maximum.get() > 32767 {
                return Err(error::input("invalid_dns_limits"));
            }
            let bootstrap = fields
                .bootstrap
                .iter()
                .map(|address| {
                    text(&address, "invalid_dns_bootstrap")?
                        .parse::<SocketAddr>()
                        .map_err(|_| error::input("invalid_dns_bootstrap"))
                })
                .collect::<PyResult<Vec<_>>>()?;
            let families = if dual {
                DotAddressFamilies::DualIpv6First
            } else {
                DotAddressFamilies::Ipv4Only
            };
            let configuration =
                DotConfiguration::new(identity, bootstrap, families, timeout, maximum);
            let block = match padding {
                Padding::Inherit | Padding::Disabled => None,
                Padding::Block(block) => Some(block),
            };
            Ok(Dns::Tls(configuration.padding_block(block), roots))
        }
        _ => Err(error::input("invalid_dns")),
    }
}

impl Dns {
    pub(super) fn build(self, profile: &ClientProfile) -> PyResult<AddressResolver> {
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
                builder
                    .build()
                    .map(|endpoint| endpoint.address_resolver())
                    .map_err(|_| error::input("invalid_dns_tls"))
            }
        }
    }
}

fn https_error(failure: DohBuildError) -> PyErr {
    let kind = match failure.kind() {
        DohBuildErrorKind::InvalidEndpoint => "invalid_dns_endpoint",
        DohBuildErrorKind::InvalidBootstrap => "invalid_dns_bootstrap",
        DohBuildErrorKind::InvalidLimits => "invalid_dns_limits",
        DohBuildErrorKind::MissingHttp2 => "dns_missing_http2",
        DohBuildErrorKind::Client => match failure
            .source()
            .and_then(|source| source.downcast_ref::<BuildError>())
            .map(BuildError::kind)
        {
            Some(BuildErrorKind::TrustStore) => "invalid_dns_roots",
            _ => "invalid_dns_profile",
        },
    };
    error::input(kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_dns_rejects_invalid_fields_without_coercion_or_private_values() -> PyResult<()> {
        Python::initialize();
        Python::attach(|py| {
            let scope = pyo3::types::PyDict::new(py);
            py.run(
                c"from types import SimpleNamespace
def dns(**changes):
    values = dict(_kind='https', endpoint='https://dns.invalid/query',
        bootstrap=('127.0.0.1',), timeout=1, max_concurrent=2,
        families='dual', roots=(), padding_block=None,
        method='post', wire='standard', query_id=0)
    values.update(changes)
    return SimpleNamespace(**values)
class Coerce:
    def __float__(self): raise ValueError('private')
    def __index__(self): raise ValueError('private')
class Subclass(int): pass
class Raising:
    @property
    def _kind(self): raise ValueError('private')
",
                Some(&scope),
                None,
            )?;
            for source in [
                c"Raising()",
                c"dns(_kind='private')",
                c"dns(bootstrap=())",
                c"dns(bootstrap=['127.0.0.1'])",
                c"dns(bootstrap=('private',))",
                c"dns(bootstrap=('127.0.0.1',) * 1025)",
                c"dns(endpoint='é' * 32769)",
                c"dns(roots=(b'private' * 10000,))",
                c"dns(roots=('private',))",
                c"dns(timeout=Coerce())",
                c"dns(timeout=True)",
                c"dns(timeout=float('nan'))",
                c"dns(timeout=0)",
                c"dns(max_concurrent=True)",
                c"dns(max_concurrent=Subclass(2))",
                c"dns(max_concurrent=0)",
                c"dns(families='private')",
                c"dns(padding_block=0)",
                c"dns(padding_block=65536)",
                c"dns(query_id=True)",
                c"dns(query_id=65536)",
                c"dns(method='private')",
                c"dns(wire='private')",
                c"dns(_kind='tls', server_name='dns.invalid', bootstrap=('127.0.0.1:853',), max_concurrent=32768)",
            ] {
                let value = py.eval(source, Some(&scope), None)?;
                let failure = parse(&value)
                    .err()
                    .ok_or_else(|| error::input("test_expected_dns_error"))?;
                let fields: (String, String, Option<String>, Option<String>) =
                    failure.value(py).getattr("args")?.extract()?;
                assert_eq!(fields.0, "input");
                assert!(!failure.to_string().contains("private"));
            }
            Ok(())
        })
    }

    #[test]
    fn dns_fields_are_snapshotted_once_and_core_validates_without_io() -> PyResult<()> {
        Python::initialize();
        Python::attach(|py| {
            let scope = pyo3::types::PyDict::new(py);
            py.run(
                c"class Settings:
    def __init__(self): self.reads = {}
    def __getattr__(self, name):
        self.reads[name] = self.reads.get(name, 0) + 1
        if self.reads[name] != 1: raise ValueError('private')
        return dict(_kind='https', endpoint='https://dns.invalid/query',
            bootstrap=('127.0.0.1',), timeout=1, max_concurrent=2,
            families='dual', roots=(), padding_block=None,
            method='post', wire='standard', query_id=0)[name]
settings = Settings()
",
                Some(&scope),
                None,
            )?;
            let value = scope
                .get_item("settings")?
                .ok_or_else(|| error::input("test_settings"))?;
            let dns = parse(&value)?;
            assert!(py.eval(c"all(value == 1 for value in settings.reads.values()) and len(settings.reads) == 11", Some(&scope), None)?.is_truthy()?);
            assert!(
                dns.build(&phantom::profile::browser::chrome::v154_windows())
                    .is_ok()
            );
            Ok(())
        })
    }
}
