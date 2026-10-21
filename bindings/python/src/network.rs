//! Bounded synchronous ownership of network settings before client construction.

use crate::error;
use phantom::ClientBuilder;
use pyo3::{
    prelude::*,
    types::{PyString, PyTuple},
};
use std::net::IpAddr;

const MAXIMUM_ENTRIES: usize = 1024;
const MAXIMUM_BYTES: usize = 65536;

#[derive(Default)]
pub(super) struct Network {
    overrides: Vec<(String, Vec<IpAddr>)>,
    locals: Vec<IpAddr>,
    interface: Option<String>,
}

fn text<'py>(value: &'py Bound<'_, PyAny>, kind: &'static str) -> PyResult<&'py str> {
    value
        .cast_exact::<PyString>()
        .map_err(|_| error::input(kind))?
        .to_str()
        .map_err(|_| error::input(kind))
}

fn tuple<'a, 'py>(value: &'a Bound<'py, PyAny>) -> PyResult<&'a Bound<'py, PyTuple>> {
    value
        .cast::<PyTuple>()
        .map_err(|_| error::input("invalid_network"))
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
    let fields = tuple(value)?;
    if fields.len() != 3 {
        return Err(error::input("invalid_network"));
    }
    let overrides = fields.get_item(0)?;
    let overrides = tuple(&overrides)?;
    let locals = fields.get_item(1)?;
    let locals = tuple(&locals)?;
    let interface = fields.get_item(2)?;
    let mut count = overrides.len().saturating_add(locals.len());
    if count > MAXIMUM_ENTRIES {
        return Err(error::input("network_limit"));
    }
    let mut remaining = MAXIMUM_BYTES;
    // Validate the entire aggregate before copying owned strings or address lists.
    for value in overrides.iter() {
        let pair = tuple(&value)?;
        if pair.len() != 2 {
            return Err(error::input("invalid_network"));
        }
        account(&pair.get_item(0)?, &mut remaining, "invalid_network_host")?;
        let addresses = pair.get_item(1)?;
        let addresses = tuple(&addresses)?;
        count = count.saturating_add(addresses.len());
        if count > MAXIMUM_ENTRIES {
            return Err(error::input("network_limit"));
        }
        for value in addresses.iter() {
            account(&value, &mut remaining, "invalid_network_address")?;
        }
    }
    for value in locals.iter() {
        account(&value, &mut remaining, "invalid_network_local_address")?;
    }
    if !interface.is_none() {
        account(&interface, &mut remaining, "invalid_network_interface")?;
    }
    let overrides = overrides
        .iter()
        .map(|value| {
            let pair = tuple(&value)?;
            let host = pair.get_item(0)?;
            let addresses = pair.get_item(1)?;
            let addresses = tuple(&addresses)?
                .iter()
                .map(|value| {
                    text(&value, "invalid_network_address")?
                        .parse()
                        .map_err(|_| error::input("invalid_network_address"))
                })
                .collect::<PyResult<Vec<IpAddr>>>()?;
            Ok((text(&host, "invalid_network_host")?.to_owned(), addresses))
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
        overrides,
        locals,
        interface,
    })
}

impl Network {
    pub(super) fn apply(self, mut builder: ClientBuilder) -> ClientBuilder {
        for (host, addresses) in self.overrides {
            builder = builder.resolve(&host, addresses);
        }
        for address in self.locals {
            builder = builder.local_address(address);
        }
        if let Some(interface) = self.interface {
            builder = builder.interface(&interface);
        }
        builder
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
                c"class Lying(str):\n    def __len__(self): return 0\nclass Throwing(str):\n    def __len__(self): raise ValueError('private')\n",
                Some(&scope),
                None,
            )?;
            for source in [
                c"([], (), None)",
                c"((('host', ('127.0.0.1',)),), (), None, None)",
                c"((('', ()) ,) * 1025, (), None)",
                c"((('', ('',) * 1023),), ('',), None)",
                c"((), (), 'é' * 32769)",
                c"((), ('private',), None)",
                c"((), (), Lying('private'))",
                c"((('host', (Lying('127.0.0.1'),)),), (), None)",
                c"(((Throwing('private'), ()),), (), None)",
                c"((), (Throwing('127.0.0.1'),), None)",
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
            let value = py.eval(c"((('Host.invalid', ()), ('host.invalid', ('127.0.0.1', '::1'))), ('127.0.0.1',), None)", None, None)?;
            let owned = parse(Some(&value))?;
            assert_eq!(owned.overrides.len(), 2);
            assert!(owned.overrides[0].1.is_empty());
            assert_eq!(owned.overrides[1].1.len(), 2);
            assert_eq!(owned.locals.len(), 1);
            let boundary = py.eval(c"((), (), 'é' * 32768)", None, None)?;
            assert!(parse(Some(&boundary)).is_ok());
            Ok(())
        })
    }
}
