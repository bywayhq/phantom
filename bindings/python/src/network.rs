//! Bounded synchronous ownership of network settings before client construction.

use crate::error;
use phantom::ClientBuilder;
use pyo3::{
    prelude::*,
    types::{PyBool, PyString, PyTuple},
};
use std::net::IpAddr;

const MAXIMUM_ENTRIES: usize = 1024;
const MAXIMUM_BYTES: usize = 65536;

#[derive(Default)]
pub(super) struct Network {
    overrides: Vec<(String, Vec<IpAddr>)>,
    locals: Vec<IpAddr>,
    interface: Option<String>,
    unix_socket: Option<String>,
    public_only: bool,
}

#[derive(FromPyObject)]
struct Settings<'py> {
    host_overrides: Bound<'py, PyTuple>,
    local_addresses: Bound<'py, PyTuple>,
    interface: Bound<'py, PyAny>,
    unix_socket: Bound<'py, PyAny>,
    public_only: Bound<'py, PyAny>,
}

#[derive(FromPyObject)]
struct HostSettings<'py> {
    host: Bound<'py, PyAny>,
    addresses: Bound<'py, PyTuple>,
}

fn text<'py>(value: &'py Bound<'_, PyAny>, kind: &'static str) -> PyResult<&'py str> {
    value
        .cast_exact::<PyString>()
        .map_err(|_| error::input(kind))?
        .to_str()
        .map_err(|_| error::input(kind))
}

fn account(value: &Bound<'_, PyAny>, remaining: &mut usize, kind: &'static str) -> PyResult<()> {
    let value = value
        .cast_exact::<PyString>()
        .map_err(|_| error::input(kind))?;
    if value.len()? > *remaining {
        return Err(error::input("network_limit"));
    }
    *remaining = remaining
        .checked_sub(value.to_str().map_err(|_| error::input(kind))?.len())
        .ok_or_else(|| error::input("network_limit"))?;
    Ok(())
}

pub(super) fn parse(value: Option<&Bound<'_, PyAny>>) -> PyResult<Network> {
    let Some(value) = value else {
        return Ok(Network::default());
    };
    let Settings {
        host_overrides: overrides,
        local_addresses: locals,
        interface,
        unix_socket,
        public_only,
    } = value
        .extract::<Settings<'_>>()
        .map_err(|_| error::input("invalid_network"))?;
    let public_only = public_only
        .cast_exact::<PyBool>()
        .map_err(|_| error::input("invalid_network"))?
        .is_true();
    let unix_socket = (!unix_socket.is_none()).then_some(unix_socket);
    let mut count = overrides.len().saturating_add(locals.len());
    if count > MAXIMUM_ENTRIES {
        return Err(error::input("network_limit"));
    }
    let mut remaining = MAXIMUM_BYTES;
    // Retain each borrowed field once, before validating and copying its value.
    let mut borrowed_overrides = Vec::with_capacity(overrides.len());
    for value in overrides.iter() {
        let host = value
            .extract::<HostSettings<'_>>()
            .map_err(|_| error::input("invalid_network"))?;
        account(&host.host, &mut remaining, "invalid_network_host")?;
        count = count.saturating_add(host.addresses.len());
        if count > MAXIMUM_ENTRIES {
            return Err(error::input("network_limit"));
        }
        for value in host.addresses.iter() {
            account(&value, &mut remaining, "invalid_network_address")?;
        }
        borrowed_overrides.push(host);
    }
    for value in locals.iter() {
        account(&value, &mut remaining, "invalid_network_local_address")?;
    }
    if !interface.is_none() {
        account(&interface, &mut remaining, "invalid_network_interface")?;
    }
    if let Some(path) = &unix_socket {
        account(path, &mut remaining, "invalid_unix_socket")?;
        let path = text(path, "invalid_unix_socket")?;
        if path.is_empty() || path.contains('\0') {
            return Err(error::input("invalid_unix_socket"));
        }
    }
    // The aggregate is bounded before allocating owned strings or address lists.
    let overrides = borrowed_overrides
        .into_iter()
        .map(|host| {
            let addresses = host
                .addresses
                .iter()
                .map(|value| {
                    text(&value, "invalid_network_address")?
                        .parse()
                        .map_err(|_| error::input("invalid_network_address"))
                })
                .collect::<PyResult<Vec<IpAddr>>>()?;
            Ok((
                text(&host.host, "invalid_network_host")?.to_owned(),
                addresses,
            ))
        })
        .collect::<PyResult<Vec<_>>>()?;
    let locals = locals
        .iter()
        .map(|value| {
            text(&value, "invalid_network_local_address")?
                .parse()
                .map_err(|_| error::input("invalid_network_local_address"))
        })
        .collect::<PyResult<Vec<IpAddr>>>()?;
    let interface = if interface.is_none() {
        None
    } else {
        Some(text(&interface, "invalid_network_interface")?.to_owned())
    };
    Ok(Network {
        public_only,
        overrides,
        locals,
        interface,
        unix_socket: unix_socket
            .as_ref()
            .map(|path| text(path, "invalid_unix_socket").map(str::to_owned))
            .transpose()?,
    })
}

impl Network {
    pub(super) fn apply(self, mut builder: ClientBuilder) -> PyResult<ClientBuilder> {
        for (host, addresses) in self.overrides {
            builder = builder.resolve(&host, addresses);
        }
        for address in self.locals {
            builder = builder.local_address(address);
        }
        if let Some(interface) = self.interface {
            builder = builder.interface(&interface);
        }
        if let Some(path) = self.unix_socket {
            #[cfg(unix)]
            {
                builder = builder.tcp_connector(phantom::TcpConnector::unix_socket(path));
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                return Err(error::input("unsupported_platform"));
            }
        }
        if self.public_only {
            builder = builder.destination_policy(phantom::DestinationPolicy::public_only());
        }
        Ok(builder)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_boundary_checks_shape_and_combined_limits_before_ownership() -> PyResult<()> {
        Python::initialize();
        Python::attach(|py| {
            let scope = pyo3::types::PyDict::new(py);
            py.run(
                c"from types import SimpleNamespace
def network(host_overrides=(), local_addresses=(), interface=None, unix_socket=None, public_only=False):
    return SimpleNamespace(host_overrides=host_overrides, local_addresses=local_addresses, interface=interface, unix_socket=unix_socket, public_only=public_only)
def host(value, addresses=()):
    return SimpleNamespace(host=value, addresses=addresses)
class Lying(str):
    def __len__(self): return 0
class Throwing(str):
    def __len__(self): raise ValueError('private')
class Raising:
    @property
    def host_overrides(self): raise ValueError('private')
",
                Some(&scope),
                None,
            )?;
            for source in [
                c"object()",
                c"Raising()",
                c"network(host_overrides=[])",
                c"network(public_only=1)",
                c"network(public_only=None)",
                c"network(host_overrides=(('host', ()),))",
                c"network(unix_socket='')",
                c"network(unix_socket='private\\x00path')",
                c"network(unix_socket='private\\ud800')",
                c"network(interface='x', unix_socket='é' * 32768)",
                c"network(unix_socket=Lying('private'))",
                c"network(host_overrides=(host(''),) * 1025)",
                c"network(host_overrides=(host('', ('',) * 1023),), local_addresses=('',))",
                c"network(interface='é' * 32769)",
                c"network(local_addresses=('private',))",
                c"network(interface=Lying('private'))",
                c"network(host_overrides=(host('host', (Lying('127.0.0.1'),)),))",
                c"network(host_overrides=(host(Throwing('private')),))",
                c"network(local_addresses=(Throwing('127.0.0.1'),))",
            ] {
                let value = py.eval(source, Some(&scope), None)?;
                let failure = parse(Some(&value))
                    .err()
                    .ok_or_else(|| error::input("test_expected_network_error"))?;
                let args: (String, String, Option<String>, Option<String>) =
                    failure.value(py).getattr("args")?.extract()?;
                assert_eq!(args.0, "input");
                assert!(!args.1.contains("private"));
            }
            let value = py.eval(c"network(host_overrides=(host('Host.invalid'), host('host.invalid', ('127.0.0.1', '::1'))), local_addresses=('127.0.0.1',))", Some(&scope), None)?;
            let owned = parse(Some(&value))?;
            assert_eq!(owned.overrides.len(), 2);
            assert!(owned.overrides[0].1.is_empty());
            assert_eq!(owned.overrides[1].1.len(), 2);
            assert_eq!(owned.locals.len(), 1);
            let public = py.eval(c"network(public_only=True)", Some(&scope), None)?;
            let owned = parse(Some(&public))?;
            assert!(owned.public_only);
            assert!(owned.unix_socket.is_none());
            let boundary = py.eval(c"network(interface='é' * 32768)", Some(&scope), None)?;
            assert!(parse(Some(&boundary)).is_ok());
            let path = py.eval(
                c"network(unix_socket='/private/socket')",
                Some(&scope),
                None,
            )?;
            let owned = parse(Some(&path))?;
            assert_eq!(owned.unix_socket.as_deref(), Some("/private/socket"));
            let builder =
                phantom::Client::builder(phantom::profile::browser::chrome::v154_windows());
            #[cfg(unix)]
            assert!(owned.apply(builder)?.build().is_ok());
            #[cfg(not(unix))]
            {
                let failure = owned
                    .apply(builder)
                    .err()
                    .ok_or_else(|| error::input("test_expected_platform_error"))?;
                let args: (String, String, Option<String>, Option<String>) =
                    failure.value(py).getattr("args")?.extract()?;
                assert_eq!(args.1, "unsupported_platform");
            }
            Ok(())
        })
    }

    #[test]
    fn named_settings_are_read_once_before_ownership() -> PyResult<()> {
        Python::initialize();
        Python::attach(|py| {
            let scope = pyo3::types::PyDict::new(py);
            py.run(
                c"class Host:
    def __init__(self): self.host_reads = 0; self.address_reads = 0
    @property
    def host(self):
        self.host_reads += 1
        return 'host.invalid' if self.host_reads == 1 else 'private\\ud800'
    @property
    def addresses(self):
        self.address_reads += 1
        return ('127.0.0.1',) if self.address_reads == 1 else ('private',)
class Settings:
    def __init__(self): self.reads = {}; self.record = Host()
    def __getattr__(self, name):
        self.reads[name] = self.reads.get(name, 0) + 1
        if self.reads[name] != 1: raise ValueError('private')
        return {'host_overrides': (self.record,), 'local_addresses': ('::1',), 'interface': None, 'unix_socket': None, 'public_only': False}[name]
settings = Settings()
",
                Some(&scope),
                None,
            )?;
            let value = scope
                .get_item("settings")?
                .ok_or_else(|| error::input("test_settings"))?;
            let owned = parse(Some(&value))?;
            assert_eq!(owned.overrides.len(), 1);
            assert_eq!(owned.overrides[0].0, "host.invalid");
            assert_eq!(owned.overrides[0].1, [IpAddr::from([127, 0, 0, 1])]);
            assert_eq!(owned.locals, [IpAddr::from(std::net::Ipv6Addr::LOCALHOST)]);
            assert!(py.eval(c"all(value == 1 for value in settings.reads.values()) and settings.record.host_reads == settings.record.address_reads == 1", Some(&scope), None)?.is_truthy()?);
            Ok(())
        })
    }
}
