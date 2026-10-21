//! Explicit host overrides and socket source selection.

use std::net::IpAddr;

use napi::Result;
use phantom::ClientBuilder;

use crate::{error::failure, ffi::NetworkOptions};

const MAXIMUM_BYTES: usize = 65536;
const MAXIMUM_ENTRIES: usize = 1024;

pub(crate) fn apply(mut builder: ClientBuilder, options: NetworkOptions) -> Result<ClientBuilder> {
    let overrides = options.host_overrides.unwrap_or_default();
    let locals = options.local_addresses.unwrap_or_default();
    let mut entries = overrides.len().saturating_add(locals.len());
    let mut bytes = options.interface.as_ref().map_or(0, String::len);
    for entry in &overrides {
        entries = entries.saturating_add(entry.addresses.len());
        bytes = bytes.saturating_add(entry.host.len());
        for address in &entry.addresses {
            bytes = bytes.saturating_add(address.len());
        }
    }
    for address in &locals {
        bytes = bytes.saturating_add(address.len());
    }
    if entries > MAXIMUM_ENTRIES || bytes > MAXIMUM_BYTES {
        return Err(failure(
            "InputLimit",
            "network configuration exceeds its input limit",
        ));
    }

    for entry in overrides {
        let addresses = entry
            .addresses
            .iter()
            .map(|value| address(value))
            .collect::<Result<Vec<_>>>()?;
        builder = builder.resolve(&entry.host, addresses);
    }
    for value in locals {
        builder = builder.local_address(address(&value)?);
    }
    if let Some(name) = options.interface {
        builder = builder.interface(&name);
    }
    Ok(builder)
}

fn address(value: &str) -> Result<IpAddr> {
    value.parse().map_err(|_| {
        failure(
            "InvalidConfiguration",
            "network address must be an unscoped IP literal",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ffi::HostOverrideOptions;

    fn builder() -> ClientBuilder {
        phantom::Client::builder(phantom_profile::browser::chrome::v154_windows())
    }

    #[test]
    fn native_boundary_checks_aggregate_limits_before_address_parsing() {
        let options = NetworkOptions {
            host_overrides: Some(vec![HostOverrideOptions {
                host: "x".repeat(65536),
                addresses: vec!["invalid".into()],
            }]),
            local_addresses: None,
            interface: None,
        };
        let error = apply(builder(), options).err();
        assert!(error.is_some_and(|error| error.reason.starts_with("PHANTOM:InputLimit:")));

        let options = NetworkOptions {
            host_overrides: Some(vec![HostOverrideOptions {
                host: "example.invalid".into(),
                addresses: vec![String::new(); 1024],
            }]),
            local_addresses: None,
            interface: None,
        };
        let error = apply(builder(), options).err();
        assert!(error.is_some_and(|error| error.reason.starts_with("PHANTOM:InputLimit:")));
    }

    #[test]
    fn native_invalid_addresses_are_redacted() {
        for value in ["private supplied input", "fe80::1%private-interface"] {
            let error = address(value).err();
            assert!(error.is_some_and(|error| error.reason
                == "PHANTOM:InvalidConfiguration:network address must be an unscoped IP literal"));
        }
    }
}
