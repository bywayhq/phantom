//! Bounded, data-only socket and host-resolution configuration.

use std::net::IpAddr;

use phantom::ClientBuilder;
use serde::Deserialize;

use crate::error::Failure;

const MAX_ENTRIES: usize = 1024;
const MAX_BYTES: usize = 64 * 1024;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct NetworkOptions {
    host_overrides: Vec<HostOverride>,
    local_addresses: Vec<String>,
    interface: Option<String>,
    unix_socket: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostOverride {
    host: String,
    addresses: Vec<String>,
}

impl NetworkOptions {
    pub(super) fn apply(self, mut builder: ClientBuilder) -> Result<ClientBuilder, Failure> {
        // Check every collection before the core builder copies any supplied field.
        let mut entries = self.host_overrides.len();
        if entries > MAX_ENTRIES || self.local_addresses.len() > MAX_ENTRIES - entries {
            return Err(Failure::new("input_limit"));
        }
        entries += self.local_addresses.len();
        for entry in &self.host_overrides {
            if entry.addresses.len() > MAX_ENTRIES - entries {
                return Err(Failure::new("input_limit"));
            }
            entries += entry.addresses.len();
        }
        let mut bytes = MAX_BYTES;
        for value in self
            .interface
            .iter()
            .chain(&self.unix_socket)
            .chain(&self.local_addresses)
            .chain(
                self.host_overrides
                    .iter()
                    .flat_map(|entry| std::iter::once(&entry.host).chain(&entry.addresses)),
            )
        {
            bytes = bytes
                .checked_sub(value.len())
                .ok_or_else(|| Failure::new("input_limit"))?;
        }
        if let Some(path) = self.unix_socket {
            if path.is_empty() || path.contains('\0') {
                return Err(Failure::new("invalid_network_options"));
            }
            #[cfg(unix)]
            {
                builder = builder.tcp_connector(phantom::TcpConnector::unix_socket(path));
            }
            #[cfg(not(unix))]
            {
                return Err(Failure::new("unsupported_platform"));
            }
        }
        for entry in self.host_overrides {
            let addresses = entry
                .addresses
                .iter()
                .map(|value| address(value))
                .collect::<Result<Vec<_>, _>>()?;
            builder = builder.resolve(&entry.host, addresses);
        }
        for value in self.local_addresses {
            builder = builder.local_address(address(&value)?);
        }
        if let Some(name) = self.interface {
            builder = builder.interface(&name);
        }
        Ok(builder)
    }
}

fn address(value: &str) -> Result<IpAddr, Failure> {
    value
        .parse()
        .map_err(|_| Failure::new("invalid_network_address"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply(value: serde_json::Value) -> Result<ClientBuilder, Failure> {
        let options: NetworkOptions =
            serde_json::from_value(value).map_err(|_| Failure::new("invalid_test_fixture"))?;
        let profile = crate::profile::named("chrome/154.0.8037.97/windows-11-26200/r1", None)?;
        options.apply(phantom::Client::builder(profile))
    }

    #[test]
    fn native_network_schema_is_strict() {
        for value in [
            serde_json::json!({"unknown": 1}),
            serde_json::json!({"host_overrides": [{"host": "example.invalid"}]}),
            serde_json::json!({"host_overrides": [{"host": "example.invalid", "addresses": [], "unknown": 1}]}),
            serde_json::json!({"local_addresses": [1]}),
            serde_json::json!({"interface": false}),
            serde_json::json!({"unix_socket": 1}),
        ] {
            assert!(serde_json::from_value::<NetworkOptions>(value).is_err());
        }
    }

    #[test]
    fn native_unix_socket_checks_path_and_shared_byte_bound() {
        for path in ["", "private\0socket"] {
            assert_eq!(
                apply(serde_json::json!({"unix_socket": path}))
                    .err()
                    .map(|error| error.kind),
                Some("invalid_network_options")
            );
        }
        assert_eq!(
            apply(serde_json::json!({"unix_socket": "é".repeat(32768), "interface": "x"}))
                .err()
                .map(|error| error.kind),
            Some("input_limit")
        );
        let result = apply(serde_json::json!({"unix_socket": "é".repeat(32768)}));
        #[cfg(unix)]
        assert!(result.is_ok());
        #[cfg(not(unix))]
        assert_eq!(
            result.err().map(|error| error.kind),
            Some("unsupported_platform")
        );
        assert!(apply(serde_json::json!({})).is_ok());
    }

    #[test]
    fn native_network_checks_combined_count_and_raw_byte_limits() {
        let mut values = vec![serde_json::json!("127.0.0.1"); 1022];
        assert!(
            apply(serde_json::json!({
                "host_overrides": [{"host": "example.invalid", "addresses": values}],
                "local_addresses": ["::1"],
            }))
            .is_ok()
        );
        values.push(serde_json::json!("127.0.0.1"));
        assert_eq!(
            apply(serde_json::json!({
                "host_overrides": [{"host": "example.invalid", "addresses": values}],
                "local_addresses": ["::1"],
            }))
            .err()
            .map(|error| error.kind),
            Some("input_limit")
        );
        assert_eq!(
            apply(serde_json::json!({
                "host_overrides": vec![serde_json::json!({"host": "x", "addresses": []}); 1025],
            }))
            .err()
            .map(|error| error.kind),
            Some("input_limit")
        );
        assert!(apply(serde_json::json!({"interface": "é".repeat(32768)})).is_ok());
        assert_eq!(
            apply(serde_json::json!({"interface": "é".repeat(32769)}))
                .err()
                .map(|error| error.kind),
            Some("input_limit")
        );
    }

    #[test]
    fn native_network_rejects_invalid_addresses_and_accepts_empty_override() {
        for value in ["private.invalid", "fe80::1%private", "", "127.0.0.999"] {
            for options in [
                serde_json::json!({"local_addresses": [value]}),
                serde_json::json!({"host_overrides": [{"host": "example.invalid", "addresses": [value]}]}),
            ] {
                assert_eq!(
                    apply(options).err().map(|error| error.kind),
                    Some("invalid_network_address")
                );
            }
        }
        assert!(
            apply(serde_json::json!({
                "host_overrides": [
                    {"host": "EXAMPLE.invalid", "addresses": ["127.0.0.1", "::1"]},
                    {"host": "example.invalid", "addresses": []},
                ],
            }))
            .is_ok()
        );
    }
}
