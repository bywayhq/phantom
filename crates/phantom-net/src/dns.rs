//! Phantom's own DNS queries: HTTPS resource record lookups (RFC 9460), and
//! the address lookups of `AddressResolver::system_nameservers`.
//!
//! Address records are resolved by the operating system through
//! `getaddrinfo` unless a client is given that resolver. HTTPS records cannot
//! be: the portable system resolver interface returns addresses only, and the
//! platform DNS APIs that can return other record types need an FFI boundary
//! that Phantom forbids outside its audited modules. [`HttpsRecordResolver`]
//! therefore sends its own DNS queries, over UDP with a TCP retry on
//! truncation, to the system's configured nameservers or to explicit ones.
//!
//! Each UDP query carries one question with only the recursion-desired flag set
//! and no EDNS(0) OPT record, the shape of Chromium's insecure DNS queries.
//! The query leaves from Phantom's process rather than the operating
//! system's resolver, as Chromium's built-in DNS client sends its queries
//! from the browser. Its UDP socket opens through the profile's
//! [`UdpSettings`] once a client applies them.

use std::{
    collections::HashMap,
    error::Error as StdError,
    fmt,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use hickory_resolver::{
    Resolver,
    config::{
        ConnectionConfig, NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts,
        ServerOrderingStrategy,
    },
    net::{DnsError, NetError},
    proto::{
        op::Message,
        rr::{DNSClass, LowerName, Name, RData, Record, RecordType, rdata::CNAME},
        serialize::binary::BinEncodable,
    },
};
use phantom_profile::UdpSettings;

mod address_lookup;
mod over_tls;
pub use over_tls::DnsOverTlsTransport;
#[cfg(any(target_os = "linux", test))]
mod linux_configuration;
#[cfg(target_os = "linux")]
mod linux_system_configuration;
#[cfg(target_os = "macos")]
mod macos_system_configuration;
#[cfg(any(windows, test))]
pub(crate) mod system_configuration;
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
mod system_resolver;
#[cfg(target_os = "linux")]
pub use system_resolver::chromium_linux_resolvers;
#[cfg(target_os = "macos")]
pub use system_resolver::chromium_macos_resolvers;
#[cfg(windows)]
pub use system_resolver::chromium_windows_resolvers;
mod ech_config;
mod https_record;
mod query_sockets;
pub mod wire;

pub(crate) use address_lookup::AddressLookup;
use query_sockets::QuerySockets;

pub use ech_config::{
    EchCipherSuite, EchConfig, EchConfigExtension, EchConfigListError, EchConfigListErrorKind,
};
pub use https_record::{
    AliasRecord, EchConfigList, HttpsRecord, HttpsRecordError, HttpsRecordErrorKind, ServiceRecord,
    SvcParam, TargetName,
};

/// Looks up HTTPS records, by DNS queries to a fixed set of nameservers or
/// through a caller-supplied function.
///
/// Clones share one resolver. It keeps no response cache: callers own
/// caching, so its bound and lifetime follow the caller's state.
#[derive(Clone)]
pub struct HttpsRecordResolver {
    backend: Backend,
}

type LookupFuture =
    Pin<Box<dyn Future<Output = Result<HttpsRecordLookup, HttpsLookupError>> + Send + 'static>>;

#[derive(Clone)]
enum Backend {
    Dns(Nameservers),
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    System(system_resolver::SystemDnsView),
    Function(Arc<dyn Fn(String, u16) -> LookupFuture + Send + Sync>),
}

/// The nameservers Phantom's own DNS queries go to, and the hickory resolver
/// that sends them through sockets opened with one set of [`UdpSettings`].
#[derive(Clone)]
struct Nameservers {
    configs: Arc<[NameServerConfig]>,
    scopes: Arc<[(SocketAddr, SocketAddr)]>,
    policy: Option<QueryPolicy>,
    udp: Option<UdpSettings>,
    /// Built on first use after [`Self::with_udp_settings`]; clones with the
    /// same settings share it.
    resolver: Arc<OnceLock<Resolver<QuerySockets>>>,
}

#[derive(Clone, Copy, Debug)]
struct QueryPolicy {
    attempts: usize,
    rotate: bool,
}

impl Nameservers {
    /// Reads the nameservers configured on this host: `/etc/resolv.conf` on
    /// Unix, the adapter DNS servers on Windows, and the System
    /// Configuration store on Apple platforms.
    fn system() -> Result<Self, NameserverConfigurationError> {
        let (config, _) = hickory_resolver::system_conf::read_system_conf()
            .map_err(NameserverConfigurationError::system)?;
        let (_, _, nameservers) = config.into_parts();
        Self::new(nameservers)
    }

    fn with_addresses(
        nameservers: impl IntoIterator<Item = SocketAddr>,
    ) -> Result<Self, NameserverConfigurationError> {
        Self::with_address_policy(nameservers, None)
    }

    fn with_address_policy(
        nameservers: impl IntoIterator<Item = SocketAddr>,
        policy: Option<QueryPolicy>,
    ) -> Result<Self, NameserverConfigurationError> {
        let mut configs = Vec::new();
        let mut scopes = Vec::new();
        for address in nameservers {
            let unscoped = SocketAddr::new(address.ip(), address.port());
            if let Some((_, known)) = scopes.iter().find(|(key, _)| *key == unscoped)
                && *known != address
            {
                return Err(NameserverConfigurationError::AmbiguousScope);
            }
            // Hickory stores only an IP and port. Its runtime restores the
            // native IPv6 scope for both UDP and truncated-response TCP.
            if !scopes.iter().any(|(key, _)| *key == unscoped) {
                scopes.push((unscoped, address));
            }
            configs.push(nameserver(address.ip(), address.port()));
        }
        Self::configured(configs, scopes, policy)
    }

    /// Builds the resolver once, so a configuration it rejects fails here.
    fn new(nameservers: Vec<NameServerConfig>) -> Result<Self, NameserverConfigurationError> {
        Self::configured(nameservers, Vec::new(), None)
    }

    fn configured(
        nameservers: Vec<NameServerConfig>,
        scopes: Vec<(SocketAddr, SocketAddr)>,
        policy: Option<QueryPolicy>,
    ) -> Result<Self, NameserverConfigurationError> {
        if nameservers.is_empty() {
            return Err(NameserverConfigurationError::MissingNameserver);
        }

        let nameservers = Self {
            configs: nameservers
                .into_iter()
                .map(bind_loopback_nameserver)
                .collect(),
            scopes: scopes.into(),
            policy,
            udp: None,
            resolver: Arc::default(),
        };
        nameservers
            .resolver()
            .map_err(NameserverConfigurationError::Build)?;
        Ok(nameservers)
    }

    #[cfg(target_os = "linux")]
    fn from_linux(
        configuration: &linux_configuration::LinuxDnsConfiguration,
    ) -> Result<Self, NameserverConfigurationError> {
        Self::with_address_policy(
            configuration.servers.iter().copied(),
            Some(QueryPolicy {
                attempts: usize::from(configuration.attempts),
                rotate: configuration.rotate,
            }),
        )
    }

    #[cfg(target_os = "macos")]
    fn from_macos(
        configuration: &crate::macos_dns_ffi::configuration::MacDnsSettings,
    ) -> Result<Self, NameserverConfigurationError> {
        Self::with_address_policy(
            configuration.nameservers.iter().copied(),
            Some(QueryPolicy {
                attempts: usize::try_from(configuration.attempts)
                    .map_err(NameserverConfigurationError::system)?,
                rotate: configuration.rotate,
            }),
        )
    }

    fn with_udp_settings(&self, settings: UdpSettings) -> Self {
        Self {
            configs: Arc::clone(&self.configs),
            scopes: Arc::clone(&self.scopes),
            policy: self.policy,
            udp: Some(settings),
            resolver: Arc::default(),
        }
    }

    fn len(&self) -> usize {
        self.configs.len()
    }

    /// Returns the resolver, building it on first use.
    fn resolver(&self) -> Result<&Resolver<QuerySockets>, NetError> {
        if let Some(resolver) = self.resolver.get() {
            return Ok(resolver);
        }
        let sockets = QuerySockets::new(self.udp).with_scopes(Arc::clone(&self.scopes));
        let mut options = ResolverOpts::default();
        // One question, recursion desired, no OPT record: see the module docs.
        options.edns0 = false;
        options.case_randomization = false;
        // Ask one nameserver at a time instead of racing two.
        options.num_concurrent_reqs = 1;
        // Callers cache results under their own bound.
        options.cache_size = 0;
        // The address lookup reads the hosts file itself, and HTTPS records
        // have no hosts entries.
        options.use_hosts_file = ResolveHosts::Never;
        options.os_port_selection = sockets.leaves_port_to_the_os();
        if let Some(policy) = self.policy {
            // Chromium154 dns_config_service_linux.cc:475-477 and
            // dns_config_service_posix.cc:115-116 replace libc's native
            // retrans timeout with dns_config.h's one-second period.
            options.timeout = Duration::from_secs(1);
            // Hickory's RetryDnsHandle sends once before spending retries.
            options.attempts = policy.attempts.saturating_sub(1);
            options.server_ordering_strategy = if policy.rotate {
                ServerOrderingStrategy::RoundRobin
            } else {
                ServerOrderingStrategy::UserProvidedOrder
            };
        }
        let resolver = Resolver::builder_with_config(
            ResolverConfig::from_name_servers(self.configs.to_vec()),
            sockets,
        )
        .with_options(options)
        .build()?;
        Ok(self.resolver.get_or_init(|| resolver))
    }
}

impl fmt::Debug for Nameservers {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Nameservers")
            .field("count", &self.len())
            .field("udp", &self.udp)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
enum NameserverConfigurationError {
    MissingNameserver,
    AmbiguousScope,
    System(Box<dyn StdError + Send + Sync>),
    Build(NetError),
}

impl NameserverConfigurationError {
    fn system(error: impl StdError + Send + Sync + 'static) -> Self {
        Self::System(Box::new(error))
    }
}

impl fmt::Display for NameserverConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid DNS resolver configuration: ")?;
        match self {
            Self::MissingNameserver => formatter.write_str("no DNS nameserver is configured"),
            Self::AmbiguousScope => {
                formatter.write_str("one DNS endpoint has conflicting IPv6 scopes")
            }
            Self::System(error) => fmt::Display::fmt(error, formatter),
            Self::Build(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl StdError for NameserverConfigurationError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::MissingNameserver | Self::AmbiguousScope => None,
            Self::System(error) => Some(error.as_ref()),
            Self::Build(error) => Some(error),
        }
    }
}

impl HttpsRecordResolver {
    /// Answers lookups with `lookup`, called with the origin host and port.
    ///
    /// The function owns name resolution policy entirely: which names it
    /// queries, over what transport, and how it treats special-use names such
    /// as `localhost`, which [`Self::system`] and [`Self::with_nameservers`]
    /// answer locally with no records, as RFC 6761 section 6.3 asks.
    pub fn from_fn<F, Fut>(lookup: F) -> Self
    where
        F: Fn(String, u16) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<HttpsRecordLookup, HttpsLookupError>> + Send + 'static,
    {
        Self {
            backend: Backend::Function(Arc::new(move |host, port| {
                Box::pin(lookup(host, port)) as LookupFuture
            })),
        }
    }

    /// Queries the nameservers configured on this host.
    ///
    /// The configuration is read once, now: `/etc/resolv.conf` on Unix, the
    /// adapter DNS servers on Windows, and the System Configuration store on
    /// Apple platforms. Search domains are not used, because every query
    /// names a fully qualified domain.
    ///
    /// # Errors
    ///
    /// Returns [`HttpsLookupErrorKind::Configuration`] when the host
    /// configuration cannot be read or names no nameserver. The error retains
    /// the configuration reader's original failure as its source.
    pub fn system() -> Result<Self, HttpsLookupError> {
        Nameservers::system()
            .map(Self::from_nameservers)
            .map_err(HttpsLookupError::configuration)
    }

    /// Queries the given nameservers, in order, over UDP and then TCP when a
    /// UDP response is truncated.
    ///
    /// # Errors
    ///
    /// Returns [`HttpsLookupErrorKind::Configuration`] when `nameservers` is empty.
    pub fn with_nameservers(
        nameservers: impl IntoIterator<Item = SocketAddr>,
    ) -> Result<Self, HttpsLookupError> {
        Nameservers::with_addresses(nameservers)
            .map(Self::from_nameservers)
            .map_err(HttpsLookupError::configuration)
    }

    const fn from_nameservers(nameservers: Nameservers) -> Self {
        Self {
            backend: Backend::Dns(nameservers),
        }
    }

    /// Opens the UDP sockets of this resolver's DNS queries with `settings`,
    /// as a client does with its profile's [`UdpSettings`].
    ///
    /// With `port_randomization` on Windows, each query socket sets
    /// `SO_RANDOMIZE_PORT` and binds port 0, so Windows picks a random port,
    /// as Chromium's built-in DNS client gets one; otherwise the resolver
    /// binds a random port itself. A resolver built with [`Self::from_fn`]
    /// is returned unchanged.
    ///
    /// A client given this resolver through `ClientBuilder::https_record_discovery`
    /// replaces these settings with its profile's `UdpSettings` when the
    /// profile has them, and keeps them otherwise.
    #[must_use]
    pub fn with_udp_settings(self, settings: UdpSettings) -> Self {
        match &self.backend {
            Backend::Dns(nameservers) => {
                Self::from_nameservers(nameservers.with_udp_settings(settings))
            }
            #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
            Backend::System(view) => Self::from_system(view.with_udp_settings(settings)),
            Backend::Function(_) => self,
        }
    }

    /// Returns the UDP settings of this resolver's DNS queries, if it sends
    /// any and was given some.
    #[must_use]
    pub fn udp_settings(&self) -> Option<UdpSettings> {
        match &self.backend {
            Backend::Dns(nameservers) => nameservers.udp,
            #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
            Backend::System(view) => view.udp_settings(),
            Backend::Function(_) => None,
        }
    }

    /// Looks up the HTTPS records of the `https` origin `host` and `port`.
    ///
    /// The query name is `host` for port 443 and `_<port>._https.<host>`
    /// otherwise (RFC 9460 section 9.1), always fully qualified. A name with
    /// no HTTPS records is an empty [`HttpsRecordLookup`], not an error.
    ///
    /// Names under `localhost`, `invalid`, and `onion` are answered locally
    /// with no records and no query (RFC 6761 section 6, RFC 7686 section 2).
    ///
    /// # Errors
    ///
    /// Returns [`HttpsLookupError`] when `host` cannot form a DNS name, no
    /// nameserver answers usably, or an answer's RDATA is malformed.
    pub async fn lookup(
        &self,
        host: &str,
        port: u16,
    ) -> Result<HttpsRecordLookup, HttpsLookupError> {
        let token = self
            .configuration_token()
            .map_err(Self::configuration_error)?;
        self.lookup_with_configuration(host, port, token).await
    }

    fn configuration_error(error: std::io::Error) -> HttpsLookupError {
        HttpsLookupError::configuration(error)
    }

    /// Samples delivered configuration changes without reading settings or opening sockets.
    /// Returns the current configuration stamp for a paired system resolver.
    ///
    /// Fixed and callback resolvers return `None`.
    ///
    /// # Errors
    ///
    /// Returns a terminal configuration-watch error.
    pub fn configuration_token(
        &self,
    ) -> std::io::Result<Option<crate::host_resolver::DnsConfigurationToken>> {
        match &self.backend {
            #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
            Backend::System(view) => view.configuration_token().map(Some),
            Backend::Dns(_) | Backend::Function(_) => Ok(None),
        }
    }

    /// Uses exactly the sampled generation. The caller must also fence its cache.
    /// Looks up HTTPS records using a previously sampled configuration stamp.
    ///
    /// Pass the current stamp from this resolver, or `None` for a fixed or
    /// callback resolver. A changed configuration fails the lookup.
    ///
    /// # Errors
    ///
    /// Returns configuration, DNS transport, or record errors. Configuration
    /// errors must not be stored as negative DNS answers.
    pub async fn lookup_with_configuration(
        &self,
        host: &str,
        port: u16,
        token: Option<crate::host_resolver::DnsConfigurationToken>,
    ) -> Result<HttpsRecordLookup, HttpsLookupError> {
        match &self.backend {
            #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
            Backend::System(view) => {
                view.https(
                    host,
                    port,
                    token.ok_or_else(|| {
                        HttpsLookupError::configuration(
                            crate::host_resolver::configuration_changed(),
                        )
                    })?,
                )
                .await
            }
            Backend::Dns(nameservers) => {
                if token.is_some() {
                    return Err(HttpsLookupError::configuration(
                        crate::host_resolver::configuration_changed(),
                    ));
                }
                lookup_dns(nameservers, host, port).await
            }
            Backend::Function(lookup) => {
                if token.is_some() {
                    return Err(HttpsLookupError::configuration(
                        crate::host_resolver::configuration_changed(),
                    ));
                }
                lookup(host.to_owned(), port).await
            }
        }
    }

    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    fn from_system(view: system_resolver::SystemDnsView) -> Self {
        Self {
            backend: Backend::System(view),
        }
    }
}

async fn lookup_dns(
    nameservers: &Nameservers,
    host: &str,
    port: u16,
) -> Result<HttpsRecordLookup, HttpsLookupError> {
    let resolver = nameservers.resolver().map_err(HttpsLookupError::resolve)?;
    let query_name = query_name(host, port);
    let name = Name::from_ascii(&query_name).map_err(|_| HttpsLookupError::invalid_name())?;
    let lookup = match resolver.lookup(name.clone(), RecordType::HTTPS).await {
        Ok(lookup) => lookup,
        Err(NetError::Dns(DnsError::NoRecordsFound(no_records))) => {
            return Ok(HttpsRecordLookup::new(Vec::new(), no_records.negative_ttl));
        }
        Err(error) => return Err(HttpsLookupError::resolve(error)),
    };
    Ok(HttpsRecordLookup::new(
        https_answers(&name, lookup.answers())?.into_vec(),
        None,
    ))
}

/// Extracts the HTTPS records that answer `query` from an answer section.
///
/// hickory returns a response's whole answer section when any record in it
/// matches the question, so the section can carry HTTPS records owned by
/// other names. As in Chromium's `ValidateNamesAndAliases`
/// (`net/dns/dns_response_result_extractor.cc` at 154.0.8037.58), every
/// HTTPS record must be owned by the end of the CNAME chain that starts at
/// `query`, or the whole response is unusable. Records of a class other than
/// `IN` are ignored, as Chromium ignores them.
fn https_answers(
    query: &Name,
    records: &[Record],
) -> Result<Box<[HttpsRecordAnswer]>, HttpsLookupError> {
    let mut aliases = HashMap::new();
    for record in records {
        if let RData::CNAME(CNAME(target)) = &record.data
            && record.dns_class == DNSClass::IN
        {
            aliases
                .entry(LowerName::new(&record.name))
                .or_insert(target);
        }
    }
    // Each step consumes an alias, so a CNAME loop ends within the map's size.
    let mut owner = query;
    for _ in 0..aliases.len() {
        match aliases.remove(&LowerName::new(owner)) {
            Some(target) => owner = target,
            None => break,
        }
    }
    let mut answers = Vec::new();
    for record in records {
        let RData::HTTPS(https) = &record.data else {
            continue;
        };
        if record.dns_class != DNSClass::IN {
            continue;
        }
        if record.name != *owner {
            return Err(HttpsLookupError::unexpected_owner());
        }
        // hickory has already decoded the RDATA; re-encoding it without
        // name compression recovers the RFC 9460 wire form, so one parser
        // defines the typed record whatever the transport.
        let rdata = https
            .to_bytes()
            .map_err(|error| HttpsLookupError::resolve(error.into()))?;
        let parsed = HttpsRecord::from_rdata(&rdata).map_err(HttpsLookupError::malformed_record)?;
        answers.push(HttpsRecordAnswer {
            owner: dotted(&record.name.to_ascii()),
            ttl: record.ttl,
            record: parsed,
        });
    }
    Ok(answers.into_boxed_slice())
}

/// Decodes a DNS response `message` and extracts its HTTPS answers for the
/// `https` origin `host` and `port`, as [`HttpsRecordResolver::lookup`]
/// extracts them from a resolver's answer section.
///
/// This is a fuzzing seam, not supported API. It applies none of the
/// resolver's own response handling: no ID or question matching, response
/// code, truncation retry, CNAME follow-up query, or negative answer.
///
/// # Errors
///
/// Returns [`HttpsLookupErrorKind::InvalidName`] when `host` cannot form a
/// query name, [`HttpsLookupErrorKind::Resolve`] when `message` does not
/// decode, and [`HttpsLookupErrorKind::MalformedRecord`] as `lookup` does.
#[doc(hidden)]
pub fn https_answers_from_message(
    host: &str,
    port: u16,
    message: &[u8],
) -> Result<HttpsRecordLookup, HttpsLookupError> {
    let name =
        Name::from_ascii(query_name(host, port)).map_err(|_| HttpsLookupError::invalid_name())?;
    let message =
        Message::from_vec(message).map_err(|error| HttpsLookupError::resolve(error.into()))?;
    Ok(HttpsRecordLookup::new(
        https_answers(&name, &message.answers)?.into_vec(),
        None,
    ))
}

impl fmt::Debug for HttpsRecordResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("HttpsRecordResolver");
        match &self.backend {
            Backend::Dns(nameservers) => debug
                .field("nameservers", &nameservers.len())
                .field("udp", &nameservers.udp),
            #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
            Backend::System(view) => debug.field("backend", view),
            Backend::Function(_) => debug.field("backend", &"function"),
        };
        debug.finish_non_exhaustive()
    }
}

fn nameserver(address: IpAddr, port: u16) -> NameServerConfig {
    let mut udp = ConnectionConfig::udp();
    udp.port = port;
    let mut tcp = ConnectionConfig::tcp();
    tcp.port = port;
    NameServerConfig::new(address, true, vec![udp, tcp])
}

/// Binds the client sockets for a loopback nameserver to the loopback
/// address of its family.
///
/// hickory otherwise binds its UDP sockets to the unspecified address, which
/// listens on every interface. The kernel chooses the loopback source for a
/// loopback destination either way, so the queries on the wire do not
/// change. The port stays 0, so hickory still picks a random source port.
/// Other nameservers, and connections that already name a bind address, are
/// left as they are.
fn bind_loopback_nameserver(mut nameserver: NameServerConfig) -> NameServerConfig {
    if let Some(bind) = loopback_bind_address(nameserver.ip) {
        for connection in &mut nameserver.connections {
            connection.bind_addr.get_or_insert(bind);
        }
    }
    nameserver
}

fn loopback_bind_address(remote: IpAddr) -> Option<SocketAddr> {
    let ip = match remote {
        IpAddr::V4(ip) if ip.is_loopback() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_loopback() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        _ => return None,
    };
    Some(SocketAddr::new(ip, 0))
}

/// Returns the fully qualified HTTPS query name for an `https` origin.
///
/// RFC 9460 section 9.1 prefixes `_<port>._https` for any port but 443,
/// as Chromium does (`dns_util::GetNameForHttpsQuery`,
/// `net/dns/public/util.cc` at 154.0.8037.58).
pub(crate) fn query_name(host: &str, port: u16) -> String {
    let host = host.trim_end_matches('.');
    if port == 443 {
        format!("{host}.")
    } else {
        format!("_{port}._https.{host}.")
    }
}

fn dotted(name: &str) -> Box<str> {
    name.strip_suffix('.').unwrap_or(name).into()
}

/// The HTTPS records found for one query name.
///
/// Cache freshness starts at construction. Moving or cloning a result does
/// not restart its lifetime. Raw record TTLs remain available separately.
#[derive(Clone, Debug)]
pub struct HttpsRecordLookup {
    answers: Box<[HttpsRecordAnswer]>,
    negative_ttl: Option<u32>,
    created_at: Instant,
    expires_at: Option<Instant>,
}

impl HttpsRecordLookup {
    /// Creates a lookup result, for a resolver built with
    /// [`HttpsRecordResolver::from_fn`].
    ///
    /// The lowest answer TTL starts now. For an empty result, `negative_ttl`
    /// supplies the SOA-derived lifetime in seconds. Zero or missing lifetimes
    /// allow the current lookup to use the result but prevent cache reuse.
    #[must_use]
    pub fn new(answers: Vec<HttpsRecordAnswer>, negative_ttl: Option<u32>) -> Self {
        let created_at = Instant::now();
        let ttl = answers
            .iter()
            .map(HttpsRecordAnswer::ttl)
            .min()
            .or(negative_ttl);
        let expires_at = ttl
            .filter(|ttl| *ttl != 0)
            .and_then(|ttl| created_at.checked_add(Duration::from_secs(u64::from(ttl))));
        Self {
            answers: answers.into_boxed_slice(),
            negative_ttl,
            created_at,
            expires_at,
        }
    }

    /// Shortens freshness to at most `remaining` from this call's time.
    ///
    /// Subtract HTTP age and elapsed exchange time before calling this for
    /// DoH answers. The original deadline and construction anchor stay in
    /// force. A zero or unrepresentable duration prevents cache reuse. This
    /// cannot make an expired or missing-SOA result fresh again.
    #[must_use]
    pub fn with_cache_lifetime(mut self, remaining: Duration) -> Self {
        self.expires_at = if remaining.is_zero() {
            None
        } else {
            self.expires_at
                .zip(Instant::now().checked_add(remaining))
                .map(|(original, adjusted)| original.min(adjusted))
        };
        self
    }

    /// Shortens freshness to an already adjusted absolute deadline.
    ///
    /// Use this after aging a DoH response or CNAME chain. Passing the exact
    /// deadline avoids restarting freshness between clock reads. It cannot
    /// revive an expired or missing-SOA result or change the construction anchor.
    #[must_use]
    pub fn with_cache_deadline(mut self, deadline: Instant) -> Self {
        self.expires_at = self.expires_at.map(|original| original.min(deadline));
        self
    }

    /// Returns the absolute deadline for cache reuse, capped from construction.
    ///
    /// Returns `None` for expired, zero, missing or unrepresentable lifetimes.
    /// A cache must check this deadline again when publishing a result.
    #[must_use]
    pub fn cache_deadline(&self, maximum: Duration) -> Option<Instant> {
        let deadline = self.expires_at?.min(self.created_at.checked_add(maximum)?);
        (deadline > Instant::now()).then_some(deadline)
    }

    /// Returns the HTTPS answer records in response order.
    ///
    /// A lookup through DNS returns only records owned by the query name or,
    /// when the name is an alias, by the end of its CNAME chain.
    #[must_use]
    pub fn answers(&self) -> &[HttpsRecordAnswer] {
        &self.answers
    }

    /// Returns how long, in seconds, the absence of records may be cached,
    /// when the response was negative and carried an SOA record.
    #[must_use]
    pub const fn negative_ttl(&self) -> Option<u32> {
        self.negative_ttl
    }
}

/// One HTTPS answer record with its owner name and TTL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpsRecordAnswer {
    owner: Box<str>,
    ttl: u32,
    record: HttpsRecord,
}

impl HttpsRecordAnswer {
    /// Creates an answer record with its owner name, in dotted form without
    /// the root dot, and its TTL in seconds.
    #[must_use]
    pub fn new(owner: impl Into<Box<str>>, ttl: u32, record: HttpsRecord) -> Self {
        Self {
            owner: owner.into(),
            ttl,
            record,
        }
    }

    /// Returns the owner name in dotted form, without the trailing root dot.
    ///
    /// It differs from the query name when the answer follows a CNAME.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Returns the record's TTL in seconds.
    #[must_use]
    pub const fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Returns the parsed record.
    #[must_use]
    pub const fn record(&self) -> &HttpsRecord {
        &self.record
    }
}

/// Stable category of an HTTPS record lookup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HttpsLookupErrorKind {
    /// The resolver has no usable nameserver configuration.
    Configuration,
    /// The origin host cannot form a DNS query name.
    InvalidName,
    /// No nameserver returned a usable response: a timeout, a network
    /// error, an error response code, an undecodable message, or an HTTPS
    /// answer owned by a name other than the end of the query name's CNAME
    /// chain.
    Resolve,
    /// An HTTPS answer record's RDATA is malformed.
    MalformedRecord,
}

/// An HTTPS record lookup failure.
#[derive(Debug)]
pub struct HttpsLookupError {
    kind: HttpsLookupErrorKind,
    detail: Option<String>,
    source: Option<Box<dyn StdError + Send + Sync>>,
}

impl HttpsLookupError {
    /// Creates a configuration error for unavailable or changed resolver settings.
    /// Resolver callbacks can return this category without treating it as a DNS
    /// answer or an operational lookup failure. The original source is retained.
    pub fn configuration(source: impl StdError + Send + Sync + 'static) -> Self {
        Self {
            kind: HttpsLookupErrorKind::Configuration,
            detail: None,
            source: Some(Box::new(source)),
        }
    }

    const fn invalid_name() -> Self {
        Self {
            kind: HttpsLookupErrorKind::InvalidName,
            detail: None,
            source: None,
        }
    }

    fn resolve(source: NetError) -> Self {
        Self {
            kind: HttpsLookupErrorKind::Resolve,
            detail: None,
            source: Some(Box::new(source)),
        }
    }

    fn unexpected_owner() -> Self {
        Self {
            kind: HttpsLookupErrorKind::Resolve,
            detail: Some(
                "an HTTPS answer is owned by a name the query did not resolve to".to_owned(),
            ),
            source: None,
        }
    }

    fn malformed_record(source: HttpsRecordError) -> Self {
        Self {
            kind: HttpsLookupErrorKind::MalformedRecord,
            detail: None,
            source: Some(Box::new(source)),
        }
    }

    /// Creates a [`HttpsLookupErrorKind::Resolve`] error, for a resolver
    /// built with [`HttpsRecordResolver::from_fn`].
    pub fn other(source: impl StdError + Send + Sync + 'static) -> Self {
        Self {
            kind: HttpsLookupErrorKind::Resolve,
            detail: None,
            source: Some(Box::new(source)),
        }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> HttpsLookupErrorKind {
        self.kind
    }
}

impl fmt::Display for HttpsLookupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.kind == HttpsLookupErrorKind::Configuration {
            return match &self.source {
                Some(error) => fmt::Display::fmt(error, formatter),
                None => formatter.write_str("invalid DNS resolver configuration"),
            };
        }

        formatter.write_str(match self.kind {
            HttpsLookupErrorKind::Configuration => "invalid DNS resolver configuration",
            HttpsLookupErrorKind::InvalidName => "host cannot form an HTTPS query name",
            HttpsLookupErrorKind::Resolve => "HTTPS record lookup failed",
            HttpsLookupErrorKind::MalformedRecord => "malformed HTTPS record",
        })?;
        match &self.detail {
            Some(detail) => write!(formatter, ": {detail}"),
            None => Ok(()),
        }
    }
}

impl StdError for HttpsLookupError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}

#[cfg(test)]
mod lifetime_tests;
#[cfg(test)]
mod tests;
