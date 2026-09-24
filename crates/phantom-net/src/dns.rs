//! HTTPS resource record lookups (RFC 9460).
//!
//! Address records are still resolved by the operating system through
//! `getaddrinfo`. HTTPS records cannot be: the portable system resolver
//! interface returns addresses only, and the platform DNS APIs that can
//! return other record types need an FFI boundary that Phantom forbids
//! outside its audited TLS backend. [`HttpsRecordResolver`] therefore sends
//! its own DNS queries, over UDP with a TCP retry on truncation, to the
//! system's configured nameservers or to explicit ones.
//!
//! Each query carries one question with only the recursion-desired flag set
//! and no EDNS(0) OPT record, the shape of Chromium's insecure DNS queries.
//! The query leaves from Phantom's process rather than the operating
//! system's resolver, so the DNS traffic of a Phantom client differs from
//! that of a browser that sends its address queries from the same stub.

use std::{
    error::Error as StdError,
    fmt,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
};

use hickory_resolver::{
    TokioResolver,
    config::{ConnectionConfig, NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts},
    net::{DnsError, NetError, runtime::TokioRuntimeProvider},
    proto::{
        rr::{Name, RData, RecordType},
        serialize::binary::BinEncodable,
    },
};

mod https_record;

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
    Dns {
        resolver: TokioResolver,
        nameservers: usize,
    },
    Function(Arc<dyn Fn(String, u16) -> LookupFuture + Send + Sync>),
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
    /// configuration cannot be read or names no nameserver.
    pub fn system() -> Result<Self, HttpsLookupError> {
        let (config, _) = hickory_resolver::system_conf::read_system_conf()
            .map_err(|error| HttpsLookupError::configuration(error.to_string()))?;
        let (_, _, nameservers) = config.into_parts();
        Self::from_nameservers(nameservers)
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
        Self::from_nameservers(
            nameservers
                .into_iter()
                .map(|address| nameserver(address.ip(), address.port()))
                .collect(),
        )
    }

    fn from_nameservers(nameservers: Vec<NameServerConfig>) -> Result<Self, HttpsLookupError> {
        if nameservers.is_empty() {
            return Err(HttpsLookupError::configuration(
                "no DNS nameserver is configured".to_owned(),
            ));
        }
        let count = nameservers.len();
        let mut options = ResolverOpts::default();
        // One question, recursion desired, no OPT record: see the module docs.
        options.edns0 = false;
        options.case_randomization = false;
        // Ask one nameserver at a time instead of racing two.
        options.num_concurrent_reqs = 1;
        // Callers cache results under their own bound.
        options.cache_size = 0;
        // Hosts files carry addresses only.
        options.use_hosts_file = ResolveHosts::Never;
        let resolver = TokioResolver::builder_with_config(
            ResolverConfig::from_name_servers(nameservers),
            TokioRuntimeProvider::default(),
        )
        .with_options(options)
        .build()
        .map_err(|error| HttpsLookupError::configuration(error.to_string()))?;
        Ok(Self {
            backend: Backend::Dns {
                resolver,
                nameservers: count,
            },
        })
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
        let resolver = match &self.backend {
            Backend::Dns { resolver, .. } => resolver,
            Backend::Function(lookup) => return lookup(host.to_owned(), port).await,
        };
        let query_name = query_name(host, port);
        let name = Name::from_ascii(&query_name).map_err(|_| HttpsLookupError::invalid_name())?;
        let lookup = match resolver.lookup(name, RecordType::HTTPS).await {
            Ok(lookup) => lookup,
            Err(NetError::Dns(DnsError::NoRecordsFound(no_records))) => {
                return Ok(HttpsRecordLookup {
                    answers: Box::default(),
                    negative_ttl: no_records.negative_ttl,
                });
            }
            Err(error) => return Err(HttpsLookupError::resolve(error)),
        };
        let mut answers = Vec::new();
        for record in lookup.answers() {
            let RData::HTTPS(https) = &record.data else {
                continue;
            };
            // hickory has already decoded the RDATA; re-encoding it without
            // name compression recovers the RFC 9460 wire form, so one parser
            // defines the typed record whatever the transport.
            let rdata = https
                .to_bytes()
                .map_err(|error| HttpsLookupError::resolve(error.into()))?;
            let parsed =
                HttpsRecord::from_rdata(&rdata).map_err(HttpsLookupError::malformed_record)?;
            answers.push(HttpsRecordAnswer {
                owner: dotted(&record.name.to_ascii()),
                ttl: record.ttl,
                record: parsed,
            });
        }
        Ok(HttpsRecordLookup {
            answers: answers.into_boxed_slice(),
            negative_ttl: None,
        })
    }
}

impl fmt::Debug for HttpsRecordResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("HttpsRecordResolver");
        match &self.backend {
            Backend::Dns { nameservers, .. } => debug.field("nameservers", nameservers),
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpsRecordLookup {
    answers: Box<[HttpsRecordAnswer]>,
    negative_ttl: Option<u32>,
}

impl HttpsRecordLookup {
    /// Creates a lookup result, for a resolver built with
    /// [`HttpsRecordResolver::from_fn`].
    ///
    /// `negative_ttl` is how long, in seconds, an empty result may be cached.
    #[must_use]
    pub fn new(answers: Vec<HttpsRecordAnswer>, negative_ttl: Option<u32>) -> Self {
        Self {
            answers: answers.into_boxed_slice(),
            negative_ttl,
        }
    }

    /// Returns the HTTPS answer records in response order.
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
    /// error, an error response code, or an undecodable message.
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
    fn configuration(detail: String) -> Self {
        Self {
            kind: HttpsLookupErrorKind::Configuration,
            detail: Some(detail),
            source: None,
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
mod tests;
