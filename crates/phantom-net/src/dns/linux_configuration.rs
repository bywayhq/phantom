//! Pure Linux DNS intake for Chromium 154's built-in resolver selection.
//!
//! Chromium `dns_config_service_linux.cc:61-113,217-340` and
//! `nsswitch_reader.cc:65-94,96-300,303-346` at 154.0.8037.58 define the
//! projection and NSS rules. The file syntax/defaults below follow glibc 2.39/2.42
//! `res_init.c`, `resolv_conf.c:480-536` and `bits/types/res_state.h`.
//! The caller owns host reads, environment witnesses and change observation.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
};

pub(crate) const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_TOKENS: usize = 4096;
const MAX_TOKEN_BYTES: usize = 1024;
const MAX_SERVICES: usize = 64;
const MAX_ACTIONS: usize = 128;
const MAX_INTERFACE_INDICES: usize = 1024;
// These are libc's effective res_state limits, not parser resource limits.
const MAX_SERVERS: usize = 3;
const MAX_SEARCH: usize = 6;
const SEARCH_STORAGE_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LinuxConfigurationError {
    Invalid(&'static str),
    Limit(&'static str),
    MissingInterfaceIndex,
    Allocation,
}

impl fmt::Display for LinuxConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(field) => write!(f, "invalid Linux DNS {field}"),
            Self::Limit(field) => write!(f, "Linux DNS {field} exceeds its bound"),
            Self::MissingInterfaceIndex => f.write_str("Linux DNS interface index is unavailable"),
            Self::Allocation => f.write_str("cannot allocate Linux DNS configuration"),
        }
    }
}

impl std::error::Error for LinuxConfigurationError {}

/// Owned values from the selected host intake, borrowed only during projection.
#[derive(Default)]
pub(crate) struct LinuxDnsOverrides<'a> {
    pub(crate) local_domain: Option<&'a str>,
    pub(crate) res_options: Option<&'a str>,
    pub(crate) hostname: Option<&'a str>,
    pub(crate) interface_indices: &'a [(&'a str, u32)],
    pub(crate) option_syntax: LibcOptionSyntax,
}

/// Actual libc syntax, supplied by the caller; never inferred from a distro.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) enum LibcOptionSyntax {
    /// glibc 2.39 ignores negative boolean options.
    #[default]
    Legacy,
    /// glibc 2.42 accepts a leading `-` to clear a boolean option.
    Negation,
}

impl fmt::Debug for LinuxDnsOverrides<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxDnsOverrides")
            .field("has_local_domain", &self.local_domain.is_some())
            .field("has_res_options", &self.res_options.is_some())
            .field("has_hostname", &self.hostname.is_some())
            .field("interface_count", &self.interface_indices.len())
            .field("option_syntax", &self.option_syntax)
            .finish()
    }
}

pub(crate) struct LinuxDnsConfiguration {
    pub(crate) servers: Vec<SocketAddr>,
    pub(crate) search: Vec<String>,
    pub(crate) ndots: u8,
    pub(crate) attempts: u8,
    pub(crate) rotate: bool,
}

impl fmt::Debug for LinuxDnsConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxDnsConfiguration")
            .field("server_count", &self.servers.len())
            .field("search_count", &self.search.len())
            .field("ndots", &self.ndots)
            .field("attempts", &self.attempts)
            .field("rotate", &self.rotate)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct LinuxDnsIneligibility {
    pub(crate) use_vc: bool,
    pub(crate) nsswitch: bool,
}

#[derive(Debug)]
pub(crate) enum LinuxDnsEligibility {
    BuiltIn(LinuxDnsConfiguration),
    SystemOnly {
        configuration: LinuxDnsConfiguration,
        reasons: LinuxDnsIneligibility,
    },
}

/// File-only legacy-syntax projection; not an effective native configuration.
pub(crate) fn chromium_linux(
    resolv_conf: &[u8],
    nsswitch_conf: &[u8],
) -> Result<LinuxDnsEligibility, LinuxConfigurationError> {
    chromium_linux_with_overrides(resolv_conf, nsswitch_conf, &LinuxDnsOverrides::default())
}

pub(crate) fn chromium_linux_with_overrides(
    resolv_conf: &[u8],
    nsswitch_conf: &[u8],
    overrides: &LinuxDnsOverrides<'_>,
) -> Result<LinuxDnsEligibility, LinuxConfigurationError> {
    let resolv = input(resolv_conf)?;
    let nsswitch = input(nsswitch_conf)?;
    validate_overrides(overrides)?;
    let mut configuration = LinuxDnsConfiguration {
        servers: Vec::new(),
        search: Vec::new(),
        ndots: 1,
        attempts: 2,
        rotate: false,
    };
    let mut use_vc = false;
    let mut search = Vec::new();
    if let Some(value) = overrides.local_domain {
        let value = value.split('\n').next().unwrap_or_default();
        set_search(&mut search, value, false)?;
        // Unlike a file directive, LOCALDOMAIN installs the initial empty
        // suffix too. An explicit empty value therefore suppresses fallback.
        if value.is_empty() || value.starts_with([' ', '\t']) {
            search
                .try_reserve(1)
                .map_err(|_| LinuxConfigurationError::Allocation)?;
            search.insert(0, String::new());
        }
    }
    for line in resolv.lines() {
        // glibc matches directive names in column zero, followed by space/tab.
        let Some((directive, value)) = line.split_once([' ', '\t']) else {
            continue;
        };
        match directive {
            "nameserver" => {
                let value = value
                    .split_ascii_whitespace()
                    .next()
                    .ok_or(LinuxConfigurationError::Invalid("nameserver"))?;
                let address = nameserver(value, overrides.interface_indices)?;
                if address.ip().is_unspecified() {
                    return Err(LinuxConfigurationError::Invalid("unspecified nameserver"));
                }
                if configuration.servers.len() < MAX_SERVERS {
                    push(&mut configuration.servers, address)?;
                }
            }
            "domain" | "search" if overrides.local_domain.is_none() => {
                if !value.trim_matches([' ', '\t', '\r']).is_empty() {
                    set_search(&mut search, value, directive == "domain")?;
                }
            }
            "options" => options(
                value,
                &mut configuration,
                &mut use_vc,
                overrides.option_syntax,
            )?,
            // sortlist and unknown directives do not enter Chromium's DnsConfig.
            _ => {}
        }
    }
    if configuration.servers.is_empty() {
        push(
            &mut configuration.servers,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        )?;
    }
    if search.is_empty()
        && let Some((_, domain)) = overrides.hostname.and_then(|host| host.split_once('.'))
    {
        push(&mut search, owned(domain)?)?;
    }
    // glibc exposes only the prefix that fits its six slots/256-byte buffer.
    let mut storage = 0;
    for suffix in search {
        storage += suffix.len() + 1;
        if configuration.search.len() == MAX_SEARCH || storage > SEARCH_STORAGE_BYTES {
            break;
        }
        push(&mut configuration.search, suffix)?;
    }
    if let Some(value) = overrides.res_options {
        options(
            value,
            &mut configuration,
            &mut use_vc,
            overrides.option_syntax,
        )?;
    }
    let reasons = LinuxDnsIneligibility {
        use_vc,
        nsswitch: !nsswitch_compatible(nsswitch, &configuration.servers)?,
    };
    if reasons.use_vc || reasons.nsswitch {
        Ok(LinuxDnsEligibility::SystemOnly {
            configuration,
            reasons,
        })
    } else {
        Ok(LinuxDnsEligibility::BuiltIn(configuration))
    }
}

fn input(bytes: &[u8]) -> Result<&str, LinuxConfigurationError> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(LinuxConfigurationError::Limit("input bytes"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| LinuxConfigurationError::Invalid("UTF-8"))?;
    if text
        .bytes()
        .any(|byte| byte == 0 || (byte.is_ascii_control() && !byte.is_ascii_whitespace()))
    {
        return Err(LinuxConfigurationError::Invalid("control byte"));
    }
    let mut tokens = 0;
    for token in text.split_ascii_whitespace() {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(LinuxConfigurationError::Limit("token bytes"));
        }
        tokens += 1;
        if tokens > MAX_TOKENS {
            return Err(LinuxConfigurationError::Limit("tokens"));
        }
    }
    Ok(text)
}

fn validate_overrides(overrides: &LinuxDnsOverrides<'_>) -> Result<(), LinuxConfigurationError> {
    for value in [
        overrides.local_domain,
        overrides.res_options,
        overrides.hostname,
    ]
    .into_iter()
    .flatten()
    {
        input(value.as_bytes())?;
    }
    if overrides.interface_indices.len() > MAX_INTERFACE_INDICES {
        return Err(LinuxConfigurationError::Limit("interface count"));
    }
    for (position, &(name, index)) in overrides.interface_indices.iter().enumerate() {
        if name.is_empty()
            || name.len() >= 16
            || matches!(name, "." | "..")
            || index == 0
            || name
                .bytes()
                .any(|b| b == 0 || b.is_ascii_whitespace() || b == b'/')
        {
            return Err(LinuxConfigurationError::Invalid("interface witness"));
        }
        if overrides.interface_indices[..position]
            .iter()
            .any(|&(prior, prior_index)| prior == name && prior_index != index)
        {
            return Err(LinuxConfigurationError::Invalid(
                "conflicting interface witnesses",
            ));
        }
    }
    Ok(())
}

fn set_search(
    search: &mut Vec<String>,
    value: &str,
    single: bool,
) -> Result<(), LinuxConfigurationError> {
    search.clear();
    for suffix in value.split_ascii_whitespace() {
        push(search, owned(suffix)?)?;
        if single {
            break;
        }
    }
    Ok(())
}

fn nameserver(value: &str, indices: &[(&str, u32)]) -> Result<SocketAddr, LinuxConfigurationError> {
    if let Some((ip, scope)) = value.split_once('%') {
        let ip = ip
            .parse::<Ipv6Addr>()
            .map_err(|_| LinuxConfigurationError::Invalid("nameserver"))?;
        // inet6_scopeid_pton tries interface names only for link-local unicast
        // and node/link-local multicast. Numeric scopes work for other IPv6.
        let first = ip.segments()[0];
        let named = first & 0xffc0 == 0xfe80
            || (first & 0xff00 == 0xff00 && matches!(first & 0x000f, 1 | 2));
        let index = if named {
            indices
                .iter()
                .find_map(|&(name, index)| (name == scope).then_some(index))
        } else {
            None
        };
        let scope = match index {
            Some(index) => index,
            None if !scope.is_empty() && scope.bytes().all(|b| b.is_ascii_digit()) => scope
                .parse()
                .map_err(|_| LinuxConfigurationError::Invalid("IPv6 scope"))?,
            None if named && !scope.is_empty() => {
                return Err(LinuxConfigurationError::MissingInterfaceIndex);
            }
            None => return Err(LinuxConfigurationError::Invalid("IPv6 scope")),
        };
        return Ok(SocketAddr::V6(SocketAddrV6::new(ip, 53, 0, scope)));
    }
    if let Ok(ip) = value.parse::<Ipv6Addr>() {
        return Ok(SocketAddr::new(IpAddr::V6(ip), 53));
    }
    Ok(SocketAddr::new(IpAddr::V4(ipv4(value)?), 53))
}

// inet_aton accepts the historical one-to-four-part, decimal/octal/hex syntax.
fn ipv4(value: &str) -> Result<Ipv4Addr, LinuxConfigurationError> {
    let mut parts = [0u32; 4];
    let mut count = 0;
    for part in value.split('.') {
        if part.is_empty() || count == parts.len() {
            return Err(LinuxConfigurationError::Invalid("nameserver"));
        }
        let (radix, digits) =
            if let Some(digits) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
                (16, digits)
            } else if part.len() > 1 && part.starts_with('0') {
                (8, &part[1..])
            } else {
                (10, part)
            };
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(LinuxConfigurationError::Invalid("nameserver"));
        }
        parts[count] = u32::from_str_radix(digits, radix)
            .map_err(|_| LinuxConfigurationError::Invalid("nameserver"))?;
        count += 1;
    }
    let last = parts[count - 1];
    let tail_bits = 8 * (5 - count);
    if tail_bits < 32 && last >= (1u32 << tail_bits) {
        return Err(LinuxConfigurationError::Invalid("nameserver"));
    }
    let mut address = last;
    for (index, &part) in parts[..count - 1].iter().enumerate() {
        if part > 255 {
            return Err(LinuxConfigurationError::Invalid("nameserver"));
        }
        address |= part << (24 - index * 8);
    }
    Ok(Ipv4Addr::from(address))
}

fn options(
    value: &str,
    configuration: &mut LinuxDnsConfiguration,
    use_vc: &mut bool,
    syntax: LibcOptionSyntax,
) -> Result<(), LinuxConfigurationError> {
    for option in value.split_ascii_whitespace() {
        if let Some(value) = option.strip_prefix("ndots:") {
            configuration.ndots = decimal(value, 15)?;
        } else if let Some(value) = option.strip_prefix("attempts:") {
            configuration.attempts = decimal(value, 5)?;
        } else if let Some(value) = option.strip_prefix("timeout:") {
            // Chromium overrides libc retrans with its own fallback period.
            decimal(value, 30)?;
        } else {
            let (option, enabled) = match syntax {
                LibcOptionSyntax::Legacy => (option, true),
                LibcOptionSyntax::Negation => option
                    .strip_prefix('-')
                    .map_or((option, true), |value| (value, false)),
            };
            if option.starts_with("rotate") {
                configuration.rotate = enabled;
            }
            if option.starts_with("use-vc") {
                *use_vc = enabled;
            }
            // glibc ignores unknown options. Other recognized flags are absent
            // from Chromium's conversion (RES_IGNTC/RES_USE_DNSSEC cannot be
            // enabled through glibc 2.42's res_setoptions table).
        }
    }
    Ok(())
}

fn decimal(value: &str, maximum: u8) -> Result<u8, LinuxConfigurationError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(LinuxConfigurationError::Invalid("numeric option"));
    }
    let value = value
        .parse::<u32>()
        .map_err(|_| LinuxConfigurationError::Invalid("numeric option"))?;
    u8::try_from(value.min(u32::from(maximum)))
        .map_err(|_| LinuxConfigurationError::Invalid("numeric option"))
}

#[derive(Clone, Copy)]
enum Service {
    Files,
    Dns,
    Resolve,
    MinimalMdns,
    MyHostname,
    Other,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Action {
    Return,
    Continue,
    Merge,
}

struct Specification {
    service: Service,
    actions: [Option<Action>; 4],
    valid: bool,
}

fn nsswitch_compatible(
    text: &str,
    servers: &[SocketAddr],
) -> Result<bool, LinuxConfigurationError> {
    // Chromium selects the first hosts: database, case-insensitively. Missing
    // and empty databases use files/dns, including a completely empty file.
    let database = text.lines().find_map(|line| {
        let line = line.trim_start_matches(|c: char| c.is_ascii_whitespace());
        line.get(..6)
            .filter(|prefix| prefix.eq_ignore_ascii_case("hosts:"))?;
        Some(line[6..].trim_matches(|c: char| c.is_ascii_whitespace()))
    });
    let Some(database) = database.filter(|value| !value.is_empty()) else {
        return Ok(true);
    };
    let specifications = specifications(database)?;
    let mut files = false;
    for specification in specifications {
        if !specification.valid {
            return Ok(false);
        }
        match specification.service {
            Service::Files => {
                if files
                    || !compatible(
                        &specification,
                        &[
                            (0, Action::Return),
                            (1, Action::Continue),
                            (2, Action::Continue),
                            (3, Action::Continue),
                        ],
                    )
                {
                    return Ok(false);
                }
                files = true;
            }
            Service::Resolve => {
                if servers != [SocketAddr::from((Ipv4Addr::new(127, 0, 0, 53), 53))].as_slice() {
                    return Ok(false);
                }
                return Ok(compatible(&specification, &[(0, Action::Return)]));
            }
            Service::Dns => return Ok(files && compatible(&specification, &[(0, Action::Return)])),
            Service::MinimalMdns => {
                if !compatible(&specification, &[(2, Action::Continue)]) {
                    return Ok(false);
                }
            }
            Service::MyHostname => {
                if !compatible(
                    &specification,
                    &[
                        (1, Action::Continue),
                        (2, Action::Continue),
                        (3, Action::Continue),
                    ],
                ) {
                    return Ok(false);
                }
            }
            Service::Other => return Ok(false),
        }
    }
    Ok(false)
}

fn compatible(specification: &Specification, expected: &[(usize, Action)]) -> bool {
    expected.iter().all(|&(status, action)| {
        specification.actions[status].unwrap_or(if status == 0 {
            Action::Return
        } else {
            Action::Continue
        }) == action
    })
}

fn specifications(mut text: &str) -> Result<Vec<Specification>, LinuxConfigurationError> {
    let mut result: Vec<Specification> = Vec::new();
    let mut action_count = 0;
    while !text.is_empty() {
        if text.starts_with('#') {
            break;
        }
        if text.starts_with('[') {
            let end = text
                .find(']')
                .ok_or(LinuxConfigurationError::Invalid("NSS action brackets"))?;
            let actions = &text[1..end];
            if actions.contains('[') {
                return Err(LinuxConfigurationError::Invalid("NSS action brackets"));
            }
            let specification = result.last_mut().ok_or(LinuxConfigurationError::Invalid(
                "NSS action without service",
            ))?;
            for action in actions.split_ascii_whitespace() {
                action_count += 1;
                if action_count > MAX_ACTIONS {
                    return Err(LinuxConfigurationError::Limit("NSS action count"));
                }
                apply_action(specification, action);
            }
            text = &text[end + 1..];
            if text.starts_with(']') {
                return Err(LinuxConfigurationError::Invalid("NSS action brackets"));
            }
        } else {
            let end = text
                .find(|c: char| c.is_ascii_whitespace())
                .unwrap_or(text.len());
            let service = &text[..end];
            if result.len() == MAX_SERVICES {
                return Err(LinuxConfigurationError::Limit("NSS service count"));
            }
            let service = if service.eq_ignore_ascii_case("files") {
                Service::Files
            } else if service.eq_ignore_ascii_case("dns") {
                Service::Dns
            } else if service.eq_ignore_ascii_case("resolve") {
                Service::Resolve
            } else if ["mdns_minimal", "mdns4_minimal", "mdns6_minimal"]
                .iter()
                .any(|value| service.eq_ignore_ascii_case(value))
            {
                Service::MinimalMdns
            } else if service.eq_ignore_ascii_case("myhostname") {
                Service::MyHostname
            } else {
                Service::Other
            };
            push(
                &mut result,
                Specification {
                    service,
                    actions: [None; 4],
                    valid: true,
                },
            )?;
            text = &text[end..];
        }
        text = text.trim_start_matches(|c: char| c.is_ascii_whitespace());
    }
    Ok(result)
}

fn apply_action(specification: &mut Specification, value: &str) {
    let Some((status, action)) = value.split_once('=') else {
        specification.valid = false;
        return;
    };
    let (status, negated) = status
        .strip_prefix('!')
        .map_or((status, false), |status| (status, true));
    let status = ["SUCCESS", "NOTFOUND", "UNAVAIL", "TRYAGAIN"]
        .iter()
        .position(|value| status.eq_ignore_ascii_case(value));
    let action = if action.eq_ignore_ascii_case("return") {
        Some(Action::Return)
    } else if action.eq_ignore_ascii_case("continue") {
        Some(Action::Continue)
    } else if action.eq_ignore_ascii_case("merge") {
        Some(Action::Merge)
    } else {
        None
    };
    let (Some(status), Some(action)) = (status, action) else {
        specification.valid = false;
        return;
    };
    for (index, current) in specification.actions.iter_mut().enumerate() {
        if (index == status) != negated {
            if current.is_some_and(|prior| prior != action) {
                specification.valid = false;
            }
            *current = Some(action);
        }
    }
}

fn owned(value: &str) -> Result<String, LinuxConfigurationError> {
    let mut result = String::new();
    result
        .try_reserve_exact(value.len())
        .map_err(|_| LinuxConfigurationError::Allocation)?;
    result.push_str(value);
    Ok(result)
}

fn push<T>(values: &mut Vec<T>, value: T) -> Result<(), LinuxConfigurationError> {
    values
        .try_reserve(1)
        .map_err(|_| LinuxConfigurationError::Allocation)?;
    values.push(value);
    Ok(())
}

#[cfg(test)]
mod tests;
