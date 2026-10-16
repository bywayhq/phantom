//! Owned effective settings and an explicit raw-query eligibility decision.

use super::{
    ABI, INVALID, OK, OPTIONS, RESOLVERS, RawSettings, UNAVAILABLE, phantom_macos_dns_read,
};
use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

/// No paths, domains, nameserver values or native pointers in errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConfigurationError {
    Native { status: u32, code: u32 },
    InvalidData(&'static str),
    Allocation,
}
impl fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "macOS DNS configuration unavailable: {self:?}")
    }
}
impl std::error::Error for ConfigurationError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SystemOnlyReason {
    WitnessUnavailable,
    Unsupported {
        resolver_options: bool,
        multiple_resolvers: bool,
    },
}

/// A SystemOnly decision must be applied before raw DNS queries or probes.
pub(crate) enum MacDnsConfiguration {
    BuiltIn(MacDnsSettings),
    SystemOnly(SystemOnlyReason),
}
impl fmt::Debug for MacDnsConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BuiltIn(settings) => f.debug_tuple("BuiltIn").field(settings).finish(),
            Self::SystemOnly(reason) => f.debug_tuple("SystemOnly").field(reason).finish(),
        }
    }
}

/// Copied before the native res_state and dnsinfo graph are destroyed.
pub(crate) struct MacDnsSettings {
    pub(crate) nameservers: Vec<SocketAddr>,
    pub(crate) search: Vec<String>,
    pub(crate) ndots: u8,
    pub(crate) attempts: u32,
    pub(crate) retrans: Duration,
    pub(crate) rotate: bool,
}
impl fmt::Debug for MacDnsSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacDnsSettings")
            .field("nameserver_count", &self.nameservers.len())
            .field("search_count", &self.search.len())
            .finish_non_exhaustive()
    }
}

/// Blocking, read-only OS configuration access. Start the watch before calling,
/// then native-check it on both sides of this call before publishing settings.
pub(crate) fn read_macos_settings() -> Result<MacDnsConfiguration, ConfigurationError> {
    let mut raw = RawSettings::default();
    let mut code = 0;
    // SAFETY: exclusive, initialized fixed-width output storage matches the C
    // projection's compile-time ABI assertions. C retains no output pointer and
    // releases its native allocations before returning on every path.
    let status = unsafe { phantom_macos_dns_read(&mut raw, &mut code) };
    match status {
        OK => decode(&raw),
        UNAVAILABLE => Ok(MacDnsConfiguration::SystemOnly(
            SystemOnlyReason::WitnessUnavailable,
        )),
        INVALID => Err(ConfigurationError::InvalidData("native projection")),
        status => Err(ConfigurationError::Native { status, code }),
    }
}

pub(super) fn decode(raw: &RawSettings) -> Result<MacDnsConfiguration, ConfigurationError> {
    let invalid = ConfigurationError::InvalidData;
    if raw.abi != ABI || raw.ineligible & !(OPTIONS | RESOLVERS) != 0 {
        return Err(invalid("projection ABI"));
    }
    if raw.ineligible != 0 {
        return Ok(MacDnsConfiguration::SystemOnly(
            SystemOnlyReason::Unsupported {
                resolver_options: raw.ineligible & OPTIONS != 0,
                multiple_resolvers: raw.ineligible & RESOLVERS != 0,
            },
        ));
    }
    let count = usize::try_from(raw.nameserver_count).map_err(|_| invalid("nameserver count"))?;
    let search_count = usize::try_from(raw.search_count).map_err(|_| invalid("search count"))?;
    if count == 0 || count > raw.nameservers.len() || search_count > raw.search.len() {
        return Err(invalid("projection count"));
    }
    let ndots = u8::try_from(raw.ndots).map_err(|_| invalid("ndots"))?;
    if ndots > 15 || raw.attempts == 0 || raw.retrans_seconds == 0 || raw.rotate > 1 {
        return Err(invalid("resolver options"));
    }
    let mut nameservers = Vec::new();
    nameservers
        .try_reserve_exact(count)
        .map_err(|_| ConfigurationError::Allocation)?;
    for address in &raw.nameservers[..count] {
        let port = u16::try_from(address.port).map_err(|_| invalid("nameserver port"))?;
        if port == 0 {
            return Err(invalid("nameserver port"));
        }
        let endpoint = match address.family {
            4 => {
                if address.scope != 0 || address.flow != 0 || address.address[4..] != [0; 12] {
                    return Err(invalid("IPv4 metadata"));
                }
                let ip = Ipv4Addr::new(
                    address.address[0],
                    address.address[1],
                    address.address[2],
                    address.address[3],
                );
                SocketAddr::V4(SocketAddrV4::new(ip, port))
            }
            6 => SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(address.address),
                port,
                address.flow,
                address.scope,
            )),
            _ => return Err(invalid("nameserver family")),
        };
        if endpoint.ip().is_unspecified() {
            return Err(invalid("unspecified nameserver"));
        }
        nameservers.push(endpoint);
    }
    let mut search = Vec::new();
    search
        .try_reserve_exact(search_count)
        .map_err(|_| ConfigurationError::Allocation)?;
    for bytes in &raw.search[..search_count] {
        let length = bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(invalid("unterminated search suffix"))?;
        let suffix =
            std::str::from_utf8(&bytes[..length]).map_err(|_| invalid("search suffix encoding"))?;
        if suffix.is_empty() || !suffix.is_ascii() {
            return Err(invalid("search suffix encoding"));
        }
        let mut owned = String::new();
        owned
            .try_reserve_exact(length)
            .map_err(|_| ConfigurationError::Allocation)?;
        owned.push_str(suffix);
        search.push(owned);
    }
    Ok(MacDnsConfiguration::BuiltIn(MacDnsSettings {
        nameservers,
        search,
        ndots,
        attempts: raw.attempts,
        retrans: Duration::from_secs(u64::from(raw.retrans_seconds)),
        rotate: raw.rotate == 1,
    }))
}
