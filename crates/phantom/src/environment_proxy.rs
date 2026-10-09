use std::{
    error::Error as StdError,
    ffi::{OsStr, OsString},
    fmt,
    net::IpAddr,
};

use crate::{
    authority::Endpoint,
    route::{HttpProxy, ProxyConfigError, Route, Socks5Proxy, Socks5ProxyConfigError},
};

const MAX_VARIABLE_BYTES: usize = 32 * 1024;
const MAX_BYPASS_RULES: usize = 1024;
const VARIABLES: [&str; 8] = [
    "http_proxy",
    "HTTP_PROXY",
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "no_proxy",
    "NO_PROXY",
];

/// Read proxy settings once and apply the snapshot to a client.
///
/// Environment settings are opt-in. Explicit request and client routes,
/// including Direct, take precedence. A matching `NO_PROXY` rule selects
/// Direct before a scheme proxy or `ALL_PROXY`. Proxy failures never select
/// another route. Redirects select a route for their new logical origin.
///
/// Lowercase names take precedence, even when their value is empty.
/// An empty scheme setting still permits `ALL_PROXY`. Uppercase `HTTP_PROXY`
/// is ignored when `REQUEST_METHOD` is present. Other proxy settings and
/// lowercase `http_proxy` remain available. Only `http_proxy`, `https_proxy`,
/// `all_proxy`, `no_proxy`, their uppercase forms, and `REQUEST_METHOD` are
/// inspected. System proxy settings and certificate variables are ignored.
///
/// `HTTP_PROXY` applies to HTTP and WebSocket origins. `HTTPS_PROXY` applies
/// to HTTPS and secure WebSocket origins. The value's scheme selects the
/// proxy transport: `http`, `https`, `socks5` or `socks5h`. HTTP proxies use
/// their existing default HTTP/1.1 transport. SOCKS5 retains its explicit
/// local or remote DNS mode. Unsupported protocol combinations fail before I/O.
/// URL schemes are case-insensitive.
///
/// Proxy URLs may carry percent-encoded username and password values.
/// A literal `+` remains `+`. Existing proxy validators check the decoded
/// credentials, and existing challenge and pooling rules apply.
///
/// # Bypass rules
///
/// `NO_PROXY` contains comma-separated entries. Surrounding spaces and empty
/// entries are ignored. Domains match the apex and subdomains at a dot
/// boundary. A leading dot has the same meaning. Case, IDNA and one trailing
/// root dot are normalized only for matching. IPv4 and IPv6 literals match
/// exactly. An optional port restricts the effective origin port.
///
/// Use brackets for an IPv6 address with a port. Bare IPv6 has no port.
/// Unbracketed IPv4 or IPv6 CIDR entries match literal origin addresses in
/// that family. Host bits are masked. CIDR rules never trigger DNS lookups.
/// A whole-entry `*` matches every origin. URLs, other wildcards, empty domain
/// labels, IPv6 zones and user information are rejected.
///
/// Each selected variable may contain at most 32 KiB. A bypass list may
/// contain at most 1024 nonempty entries. Controls are rejected.
///
/// # Examples
///
/// ```
/// use phantom::EnvironmentProxies;
///
/// # fn example() -> Result<(), phantom::EnvironmentProxyError> {
/// let proxies = EnvironmentProxies::from_values([
///     ("https_proxy", "http://proxy.example:8080"),
///     ("no_proxy", "localhost,.internal.example,127.0.0.0/8"),
/// ])?;
/// # drop(proxies);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Default, Eq, PartialEq)]
pub struct EnvironmentProxies {
    http: Option<Route>,
    https: Option<Route>,
    all: Option<Route>,
    bypass: Vec<Bypass>,
}

impl EnvironmentProxies {
    /// Takes one snapshot of the process environment.
    ///
    /// Later changes do not affect this value. Reading exact names through
    /// [`std::env::vars_os`] preserves the CGI guard on Windows too.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentProxyError`] for a selected non-Unicode value,
    /// invalid proxy URL or credentials, invalid bypass rule, or size limit.
    /// Shadowed settings and CGI-ignored `HTTP_PROXY` values are not parsed.
    pub fn from_env() -> Result<Self, EnvironmentProxyError> {
        Self::from_values(std::env::vars_os())
    }

    /// Parses injected environment values without reading process state.
    ///
    /// Unknown names are ignored. The last value for the same exact name
    /// wins. Lowercase and uppercase names retain their separate precedence.
    /// A present `REQUEST_METHOD`, even empty, activates the CGI guard.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentProxyError`] under the same rules as
    /// [`Self::from_env`]. All selected settings are validated, including
    /// proxies that a wildcard bypass rule would prevent using.
    pub fn from_values<I, K, V>(values: I) -> Result<Self, EnvironmentProxyError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        let mut slots: [Option<OsString>; 8] = Default::default();
        let mut cgi = false;
        for (name, value) in values {
            let Some(name) = name.as_ref().to_str() else {
                continue;
            };
            if name == "REQUEST_METHOD" {
                cgi = true;
            } else if let Some(index) = VARIABLES.iter().position(|variable| *variable == name) {
                slots[index] = Some(value.as_ref().to_owned());
            }
        }
        let http = setting(&mut slots, 0, !cgi)?.map(parse_proxy).transpose()?;
        let https = setting(&mut slots, 2, true)?.map(parse_proxy).transpose()?;
        let all = setting(&mut slots, 4, true)?.map(parse_proxy).transpose()?;
        let bypass = setting(&mut slots, 6, true)?
            .map(parse_bypass)
            .transpose()?
            .unwrap_or_default();
        Ok(Self {
            http,
            https,
            all,
            bypass,
        })
    }

    pub(crate) fn route_for(&self, scheme: &str, endpoint: &Endpoint) -> Route {
        let specific = match scheme {
            "http" | "ws" => &self.http,
            "https" | "wss" => &self.https,
            _ => return Route::Direct,
        };
        if self
            .bypass
            .iter()
            .any(|rule| rule.matches(endpoint.host(), endpoint.port()))
        {
            return Route::Direct;
        }
        specific
            .as_ref()
            .or(self.all.as_ref())
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn uses_tls_proxy(&self) -> bool {
        [&self.http, &self.https, &self.all]
            .into_iter()
            .flatten()
            .any(|route| route.as_http_proxy().is_some_and(HttpProxy::uses_tls))
    }
}

impl fmt::Debug for EnvironmentProxies {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvironmentProxies")
            .field("http_configured", &self.http.is_some())
            .field("https_configured", &self.https.is_some())
            .field("all_configured", &self.all.is_some())
            .field("bypass_rules", &self.bypass.len())
            .finish()
    }
}

/// Stable category of environment proxy configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EnvironmentProxyErrorKind {
    /// A selected variable is not Unicode.
    NonUnicodeValue,
    /// A variable or bypass list exceeds its size bound.
    TooLarge,
    /// A proxy URL is invalid.
    InvalidProxy,
    /// A proxy URL uses an unsupported scheme.
    UnsupportedProxyScheme,
    /// URL credentials cannot be decoded or accepted by the proxy validator.
    InvalidCredentials,
    /// A bypass entry uses invalid or unsupported syntax.
    InvalidBypassRule,
}

/// Configuration error that reports the variable and category without its value.
pub struct EnvironmentProxyError {
    variable: &'static str,
    kind: EnvironmentProxyErrorKind,
    source: Option<ProxySource>,
}

impl EnvironmentProxyError {
    fn new(variable: &'static str, kind: EnvironmentProxyErrorKind) -> Self {
        Self {
            variable,
            kind,
            source: None,
        }
    }

    /// Returns the exact selected environment variable name.
    #[must_use]
    pub const fn variable(&self) -> &'static str {
        self.variable
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> EnvironmentProxyErrorKind {
        self.kind
    }

    fn with_source(mut self, source: ProxySource) -> Self {
        self.source = Some(source);
        self
    }
}

impl fmt::Debug for EnvironmentProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvironmentProxyError")
            .field("variable", &self.variable)
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for EnvironmentProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid environment proxy setting {} ({:?})",
            self.variable, self.kind
        )
    }
}

enum ProxySource {
    Http(ProxyConfigError),
    Socks5(Socks5ProxyConfigError),
}

impl StdError for EnvironmentProxyError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match &self.source {
            Some(ProxySource::Http(error)) => Some(error),
            Some(ProxySource::Socks5(error)) => Some(error),
            None => None,
        }
    }
}

fn setting(
    slots: &mut [Option<OsString>; 8],
    lower: usize,
    allow_upper: bool,
) -> Result<Option<(&'static str, String)>, EnvironmentProxyError> {
    let selected = slots[lower].take().map(|value| (lower, value)).or_else(|| {
        allow_upper
            .then(|| slots[lower + 1].take())
            .flatten()
            .map(|value| (lower + 1, value))
    });
    let Some((index, value)) = selected else {
        return Ok(None);
    };
    let variable = VARIABLES[index];
    let value = value.into_string().map_err(|_| {
        EnvironmentProxyError::new(variable, EnvironmentProxyErrorKind::NonUnicodeValue)
    })?;
    if value.len() > MAX_VARIABLE_BYTES {
        return Err(EnvironmentProxyError::new(
            variable,
            EnvironmentProxyErrorKind::TooLarge,
        ));
    }
    if value.chars().any(char::is_control) {
        let kind = if lower == 6 {
            EnvironmentProxyErrorKind::InvalidBypassRule
        } else {
            EnvironmentProxyErrorKind::InvalidProxy
        };
        return Err(EnvironmentProxyError::new(variable, kind));
    }
    let value = value.trim_matches(' ').to_owned();
    Ok((!value.is_empty()).then_some((variable, value)))
}

fn parse_proxy((variable, value): (&'static str, String)) -> Result<Route, EnvironmentProxyError> {
    let invalid = |kind| EnvironmentProxyError::new(variable, kind);
    let (scheme, rest) = value
        .split_once("://")
        .ok_or_else(|| invalid(EnvironmentProxyErrorKind::InvalidProxy))?;
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https" | "socks5" | "socks5h") {
        return Err(invalid(EnvironmentProxyErrorKind::UnsupportedProxyScheme));
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let (clean, credentials) = if let Some((userinfo, host)) = authority.split_once('@') {
        if host.contains('@') {
            return Err(invalid(EnvironmentProxyErrorKind::InvalidCredentials));
        }
        let (username, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
        let username = decode_credential(username)
            .ok_or_else(|| invalid(EnvironmentProxyErrorKind::InvalidCredentials))?;
        let password = decode_credential(password)
            .ok_or_else(|| invalid(EnvironmentProxyErrorKind::InvalidCredentials))?;
        (
            format!("{scheme}://{host}{}", &rest[authority_end..]),
            Some((username, password)),
        )
    } else {
        (format!("{scheme}://{rest}"), None)
    };
    match scheme.as_str() {
        "http" | "https" => {
            let mut proxy = HttpProxy::new(&clean).map_err(|source| {
                invalid(EnvironmentProxyErrorKind::InvalidProxy)
                    .with_source(ProxySource::Http(source))
            })?;
            if let Some((username, password)) = credentials {
                proxy = proxy
                    .with_basic_auth(username, password)
                    .map_err(|source| {
                        invalid(EnvironmentProxyErrorKind::InvalidCredentials)
                            .with_source(ProxySource::Http(source))
                    })?;
            }
            Ok(Route::http_proxy(proxy))
        }
        _ => {
            let mut proxy = Socks5Proxy::new(&clean).map_err(|source| {
                invalid(EnvironmentProxyErrorKind::InvalidProxy)
                    .with_source(ProxySource::Socks5(source))
            })?;
            if let Some((username, password)) = credentials {
                proxy = proxy
                    .with_username_password(username, password)
                    .map_err(|source| {
                        invalid(EnvironmentProxyErrorKind::InvalidCredentials)
                            .with_source(ProxySource::Socks5(source))
                    })?;
            }
            Ok(Route::socks5(proxy))
        }
    }
}

fn decode_credential(value: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(value.len());
    let mut input = value.as_bytes().iter().copied();
    while let Some(byte) = input.next() {
        let decoded = if byte == b'%' {
            let high = char::from(input.next()?).to_digit(16)?;
            let low = char::from(input.next()?).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()?
        } else {
            byte
        };
        bytes.push(decoded);
    }
    let decoded = String::from_utf8(bytes).ok()?;
    (!decoded.chars().any(char::is_control)).then_some(decoded)
}

#[derive(Clone, Eq, PartialEq)]
enum Bypass {
    All,
    Host { host: BypassHost, port: Option<u16> },
    Network { address: IpAddr, prefix: u8 },
}

#[derive(Clone, Eq, PartialEq)]
enum BypassHost {
    Domain(String),
    Ip(IpAddr),
}

fn parse_bypass(
    (variable, value): (&'static str, String),
) -> Result<Vec<Bypass>, EnvironmentProxyError> {
    let mut rules = Vec::new();
    for entry in value
        .split(',')
        .map(|entry| entry.trim_matches(' '))
        .filter(|entry| !entry.is_empty())
    {
        if rules.len() == MAX_BYPASS_RULES {
            return Err(EnvironmentProxyError::new(
                variable,
                EnvironmentProxyErrorKind::TooLarge,
            ));
        }
        rules.push(Bypass::parse(entry).ok_or_else(|| {
            EnvironmentProxyError::new(variable, EnvironmentProxyErrorKind::InvalidBypassRule)
        })?);
    }
    Ok(rules)
}

impl Bypass {
    fn parse(entry: &str) -> Option<Self> {
        if entry == "*" {
            return Some(Self::All);
        }
        if entry.contains(['*', '?', '#', '@', '%']) {
            return None;
        }
        if let Some((address, prefix)) = entry.split_once('/') {
            if !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            let address: IpAddr = address.parse().ok()?;
            let prefix: u8 = prefix.parse().ok()?;
            if prefix > if address.is_ipv4() { 32 } else { 128 } {
                return None;
            }
            return Some(Self::Network { address, prefix });
        }
        if let Ok(address) = entry.parse::<IpAddr>() {
            return Some(Self::Host {
                host: BypassHost::Ip(address),
                port: None,
            });
        }
        if let Some(bracketed) = entry.strip_prefix('[') {
            let (address, suffix) = bracketed.split_once(']')?;
            let address = IpAddr::V6(address.parse().ok()?);
            let port = if suffix.is_empty() {
                None
            } else {
                Some(parse_port(suffix.strip_prefix(':')?)?)
            };
            return Some(Self::Host {
                host: BypassHost::Ip(address),
                port,
            });
        }
        let (host, port) = match entry.split_once(':') {
            Some((host, port)) => (host, Some(parse_port(port)?)),
            None => (entry, None),
        };
        if let Ok(address) = host.parse::<IpAddr>() {
            return Some(Self::Host {
                host: BypassHost::Ip(address),
                port,
            });
        }
        let host = host.strip_prefix('.').unwrap_or(host);
        let without_root_dot = host.strip_suffix('.').unwrap_or(host);
        if without_root_dot.split('.').any(str::is_empty)
            || host.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return None;
        }
        let url::Host::Domain(host) = url::Host::parse(host).ok()? else {
            return None;
        };
        let host = host.strip_suffix('.').unwrap_or(&host);
        if host.split('.').any(str::is_empty) {
            return None;
        }
        Some(Self::Host {
            host: BypassHost::Domain(host.to_owned()),
            port,
        })
    }

    fn matches(&self, host: &str, port: u16) -> bool {
        match self {
            Self::All => true,
            Self::Host {
                host: expected,
                port: expected_port,
            } => {
                if expected_port.is_some_and(|expected| expected != port) {
                    return false;
                }
                match expected {
                    BypassHost::Ip(expected) => {
                        host.parse::<IpAddr>().is_ok_and(|host| host == *expected)
                    }
                    BypassHost::Domain(expected) => {
                        let host = host.strip_suffix('.').unwrap_or(host);
                        host.eq_ignore_ascii_case(expected)
                            || host
                                .get(host.len().saturating_sub(expected.len() + 1)..)
                                .is_some_and(|suffix| {
                                    suffix.starts_with('.')
                                        && suffix[1..].eq_ignore_ascii_case(expected)
                                })
                    }
                }
            }
            Self::Network { address, prefix } => match (address, host.parse::<IpAddr>()) {
                (IpAddr::V4(network), Ok(IpAddr::V4(host))) => {
                    let mask = if *prefix == 0 {
                        0
                    } else {
                        u32::MAX << (32 - *prefix)
                    };
                    u32::from(host) & mask == u32::from(*network) & mask
                }
                (IpAddr::V6(network), Ok(IpAddr::V6(host))) => {
                    let mask = if *prefix == 0 {
                        0
                    } else {
                        u128::MAX << (128 - *prefix)
                    };
                    u128::from(host) & mask == u128::from(*network) & mask
                }
                _ => false,
            },
        }
    }
}

fn parse_port(value: &str) -> Option<u16> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

#[cfg(test)]
mod tests;
