//! Owned Windows DNS configuration and Chromium's eligibility/search conversion.
//!
//! A snapshot does not watch changes or implement a search resolver. The native
//! reader owns API/registry access; this module never calls Windows APIs.

use std::fmt;
use std::net::SocketAddr;

pub(crate) const MAX_ADAPTER_NODES: usize = 1024;
pub(crate) const MAX_SUFFIX_UNITS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConfigurationError {
    #[cfg(windows)]
    Native {
        operation: &'static str,
        code: u32,
    },
    InvalidData(&'static str),
    Limit(&'static str),
    Allocation,
    #[cfg(windows)]
    UnsupportedArchitecture,
    NoNameserver,
}

impl fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(windows)]
            Self::Native { operation, code } => {
                write!(f, "Windows DNS {operation} failed ({code})")
            }
            Self::InvalidData(field) => write!(f, "invalid Windows DNS {field}"),
            Self::Limit(field) => write!(f, "Windows DNS {field} exceeds the supported bound"),
            Self::Allocation => f.write_str("cannot allocate Windows DNS configuration"),
            #[cfg(windows)]
            Self::UnsupportedArchitecture => {
                f.write_str("Windows DNS configuration requires a 64-bit process")
            }
            Self::NoNameserver => f.write_str("Windows DNS configuration has no usable nameserver"),
        }
    }
}

impl std::error::Error for ConfigurationError {}

#[derive(Clone, Default)]
pub(crate) struct WindowsDnsSettings {
    pub(crate) adapters: Vec<AdapterDns>,
    pub(crate) registry: RegistryDnsSettings,
}

impl fmt::Debug for WindowsDnsSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WindowsDnsSettings")
            .field("adapter_count", &self.adapters.len())
            .field("registry", &self.registry)
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct AdapterDns {
    pub(crate) if_index: u32,
    pub(crate) ipv6_if_index: u32,
    pub(crate) if_type: u32,
    pub(crate) oper_status: i32,
    pub(crate) servers: Vec<SocketAddr>,
    pub(crate) suffix: String,
}

impl fmt::Debug for AdapterDns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdapterDns")
            .field("if_type", &self.if_type)
            .field("oper_status", &self.oper_status)
            .field("server_count", &self.servers.len())
            .field("has_suffix", &!self.suffix.is_empty())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default)]
pub(crate) struct RegistryDnsSettings {
    pub(crate) policy_search: Option<String>,
    pub(crate) tcpip_search: Option<String>,
    pub(crate) tcpip_domain: Option<String>,
    pub(crate) primary_suffix: Option<String>,
    pub(crate) policy_devolution: Devolution,
    pub(crate) cache_devolution: Devolution,
    pub(crate) tcpip_devolution: Devolution,
    pub(crate) append_to_multi_label: Option<u32>,
    pub(crate) nrpt_present: bool,
    pub(crate) proxy_present: bool,
}

impl fmt::Debug for RegistryDnsSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegistryDnsSettings")
            .field("has_policy_search", &self.policy_search.is_some())
            .field("has_tcpip_search", &self.tcpip_search.is_some())
            .field("has_primary_suffix", &self.primary_suffix.is_some())
            .field("has_tcpip_domain", &self.tcpip_domain.is_some())
            .field("nrpt_present", &self.nrpt_present)
            .field("proxy_present", &self.proxy_present)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Devolution {
    pub(crate) enabled: Option<u32>,
    pub(crate) level: Option<u32>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct WindowsDnsIneligibility {
    pub(crate) nrpt: bool,
    pub(crate) proxy: bool,
    /// Chromium's PPP-based VPN heuristic.
    pub(crate) ppp: bool,
    pub(crate) differing_nameservers: bool,
}

impl WindowsDnsIneligibility {
    fn any(self) -> bool {
        self.nrpt || self.proxy || self.ppp || self.differing_nameservers
    }
}

pub(crate) enum WindowsDnsEligibility {
    BuiltIn(WindowsDnsConfiguration),
    SystemOnly {
        configuration: WindowsDnsConfiguration,
        reasons: WindowsDnsIneligibility,
    },
}

impl fmt::Debug for WindowsDnsEligibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BuiltIn(config) => f.debug_tuple("BuiltIn").field(config).finish(),
            Self::SystemOnly {
                configuration,
                reasons,
            } => f
                .debug_struct("SystemOnly")
                .field("configuration", configuration)
                .field("reasons", reasons)
                .finish(),
        }
    }
}

pub(crate) struct WindowsDnsConfiguration {
    pub(crate) servers: Vec<SocketAddr>,
    pub(crate) search: Vec<String>,
    pub(crate) ndots: u8,
    pub(crate) append_to_multi_label: bool,
    pub(crate) use_local_ipv6: bool,
    /// Diagnostic identity only. It is not an instruction to bind DNS sockets.
    pub(crate) adapter_indices: (u32, u32),
}

impl fmt::Debug for WindowsDnsConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WindowsDnsConfiguration")
            .field("server_count", &self.servers.len())
            .field("search_count", &self.search.len())
            .field("ndots", &self.ndots)
            .field("append_to_multi_label", &self.append_to_multi_label)
            .field("use_local_ipv6", &self.use_local_ipv6)
            .finish_non_exhaustive()
    }
}

pub(crate) fn chromium_windows(
    settings: &WindowsDnsSettings,
) -> Result<WindowsDnsEligibility, ConfigurationError> {
    if settings.adapters.len() > MAX_ADAPTER_NODES {
        return Err(ConfigurationError::Limit("adapter count"));
    }
    let mut reasons = WindowsDnsIneligibility {
        nrpt: settings.registry.nrpt_present,
        proxy: settings.registry.proxy_present,
        ..WindowsDnsIneligibility::default()
    };
    let mut configuration = WindowsDnsConfiguration {
        servers: Vec::new(),
        search: Vec::new(),
        ndots: 1,
        append_to_multi_label: settings
            .registry
            .append_to_multi_label
            .is_some_and(|value| value != 0),
        use_local_ipv6: reasons.nrpt,
        adapter_indices: (0, 0),
    };
    let mut previous = Vec::new();
    let mut server_count = settings.adapters.len();
    for adapter in &settings.adapters {
        server_count = server_count
            .checked_add(adapter.servers.len())
            .ok_or(ConfigurationError::Limit("DNS node count"))?;
        if server_count > MAX_ADAPTER_NODES {
            return Err(ConfigurationError::Limit("DNS node count"));
        }
        reasons.ppp |= adapter.if_type == 23;
        let mut servers = Vec::new();
        servers
            .try_reserve_exact(adapter.servers.len())
            .map_err(|_| ConfigurationError::Allocation)?;
        for server in &adapter.servers {
            if stateless_discovery(*server) {
                continue;
            }
            let mut server = *server;
            if server.port() == 0 {
                server.set_port(53);
            }
            servers.push(server);
        }
        if adapter.oper_status == 1 && !servers.is_empty() {
            let mut current = Vec::new();
            current
                .try_reserve_exact(servers.len())
                .map_err(|_| ConfigurationError::Allocation)?;
            current.extend(servers.iter().copied().map(comparison_endpoint));
            current.sort_unstable();
            current.dedup();
            reasons.differing_nameservers |= !previous.is_empty() && previous != current;
            previous = current;
        }
        if adapter.oper_status != 1 || adapter.if_type == 24 || !configuration.servers.is_empty() {
            continue;
        }
        configuration.servers = servers;
        configuration.adapter_indices = (adapter.if_index, adapter.ipv6_if_index);
        // Chromium appends this even for an earlier up adapter with no servers.
        if let Some(suffix) = domain_ascii(&adapter.suffix)? {
            push(&mut configuration.search, suffix)?;
        }
    }
    if configuration.servers.is_empty() {
        return Err(ConfigurationError::NoNameserver);
    }
    suffix_search(&settings.registry, &mut configuration.search)?;
    if reasons.any() {
        Ok(WindowsDnsEligibility::SystemOnly {
            configuration,
            reasons,
        })
    } else {
        Ok(WindowsDnsEligibility::BuiltIn(configuration))
    }
}

// IPEndPoint compares address/port and link-local scope, not flowinfo. Keep
// those comparison rules separate from the fully preserved output endpoints.
fn comparison_endpoint(mut server: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(ref mut address) = server {
        address.set_flowinfo(0);
        if !address.ip().is_unicast_link_local() {
            address.set_scope_id(0);
        }
    }
    server
}

fn stateless_discovery(server: SocketAddr) -> bool {
    let SocketAddr::V6(server) = server else {
        return false;
    };
    let bytes = server.ip().octets();
    bytes[..15] == [0xfe, 0xc0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0] && bytes[15] < 4
}

fn push<T>(values: &mut Vec<T>, value: T) -> Result<(), ConfigurationError> {
    values
        .try_reserve(1)
        .map_err(|_| ConfigurationError::Allocation)?;
    values.push(value);
    Ok(())
}

fn domain_ascii(value: &str) -> Result<Option<String>, ConfigurationError> {
    if value.encode_utf16().count() >= MAX_SUFFIX_UNITS {
        return Err(ConfigurationError::Limit("suffix length"));
    }
    if value.is_empty() {
        return Ok(None);
    }
    // Preserve the pinned ASCII fast path, including case and non-host syntax.
    if value.is_ascii() {
        return Ok(Some(value.to_owned()));
    }
    // UTS46, nontransitional, CheckHyphens/VerifyDNSLength disabled, no STD3.
    // ContextJ is enabled by default in the pin. Unicode-table equivalence with
    // Chromium ICU is not established by matching these processing options.
    Ok(idna::domain_to_ascii(value)
        .ok()
        .filter(|value| !value.is_empty()))
}

fn search_list(value: &str) -> Result<Vec<String>, ConfigurationError> {
    if value.encode_utf16().count() >= MAX_SUFFIX_UNITS {
        return Err(ConfigurationError::Limit("search-list length"));
    }
    let mut result = Vec::new();
    for part in value.split(',') {
        // Chromium base::kWhitespaceWide; keep its list independent of Rust's
        // Unicode-version-dependent char::is_whitespace.
        let part = part.trim_matches(search_whitespace);
        let Some(domain) = domain_ascii(part)? else {
            break;
        };
        push(&mut result, domain)?;
    }
    Ok(result)
}

fn search_whitespace(character: char) -> bool {
    matches!(
        character,
        '\u{9}'..='\u{d}'
            | '\u{20}'
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

fn suffix_search(
    registry: &RegistryDnsSettings,
    search: &mut Vec<String>,
) -> Result<(), ConfigurationError> {
    let explicit = registry
        .policy_search
        .as_deref()
        .or(registry.tcpip_search.as_deref());
    if let Some(explicit) = explicit {
        let parsed = search_list(explicit)?;
        if !parsed.is_empty() {
            *search = parsed;
            return Ok(());
        }
    }
    let primary = match registry
        .primary_suffix
        .as_deref()
        .map(domain_ascii)
        .transpose()?
        .flatten()
    {
        Some(primary) => Some(primary),
        None => registry
            .tcpip_domain
            .as_deref()
            .map(domain_ascii)
            .transpose()?
            .flatten(),
    };
    let Some(primary) = primary else {
        return Ok(());
    };
    search
        .try_reserve(1)
        .map_err(|_| ConfigurationError::Allocation)?;
    search.insert(0, primary.clone());
    let enabled = registry
        .policy_devolution
        .enabled
        .or(registry.cache_devolution.enabled)
        .or(registry.tcpip_devolution.enabled);
    let level = registry
        .policy_devolution
        .level
        .or(registry.cache_devolution.level)
        .or(registry.tcpip_devolution.level);
    if enabled == Some(0) {
        return Ok(());
    }
    let Some(level) = level.filter(|level| *level >= 2) else {
        return Ok(());
    };
    let mut dots = primary.bytes().filter(|byte| *byte == b'.').count();
    let mut offset = 0;
    while dots >= level as usize {
        // The pinned loop starts its search after the previous delimiter, with
        // initial offset zero. This also preserves its unusual leading-dot case.
        let start = offset + 1;
        let Some(next) = primary[start..].find('.') else {
            return Err(ConfigurationError::InvalidData("devolution"));
        };
        offset = start + next;
        push(search, primary[offset + 1..].to_owned())?;
        dots -= 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
