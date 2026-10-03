//! Local host-name resolution: caller overrides, a caller-supplied resolver
//! or the operating system, and the address cache.

use std::{
    collections::HashMap,
    fmt,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use phantom_profile::{DnsCacheSettings, UdpSettings};

use crate::address_cache::AddressCache;

pub(crate) type ResolveFuture =
    Pin<Box<dyn Future<Output = io::Result<Resolved>> + Send + 'static>>;

/// A resolver that sends its own DNS queries, behind a trait object.
///
/// The object keeps the resolver's types out of every connection future
/// that holds a [`HostResolver`]: proving such a future `Send` would
/// otherwise walk hickory's whole resolver type, past the depth the pinned
/// nightly accepts (see the nightly recursion check in
/// `scripts/dev/README.md`).
#[cfg(feature = "https-records")]
pub(crate) trait DnsLookup: fmt::Debug + Send + Sync {
    /// Starts a lookup of `host`, already lowercased.
    fn start(self: Arc<Self>, host: String) -> ResolveFuture;
    /// Returns a resolver like this one whose query sockets open with
    /// `settings`.
    fn opened_with(&self, settings: UdpSettings) -> Arc<dyn DnsLookup>;
    /// Returns the UDP settings of the query sockets, if any.
    fn socket_settings(&self) -> Option<UdpSettings>;
}

/// One lookup's answer: the addresses, each with port 0, in the order to try
/// them, and the record TTL when the resolver reports one.
pub(crate) struct Resolved {
    pub(crate) addresses: Vec<SocketAddr>,
    pub(crate) ttl: Option<Duration>,
}

impl Resolved {
    /// An answer without a record TTL, as the operating system reports.
    pub(crate) fn without_ttl(addresses: impl IntoIterator<Item = IpAddr>) -> Self {
        Self {
            addresses: with_port(addresses, 0),
            ttl: None,
        }
    }
}

/// Resolves host names to addresses in place of the operating system
/// resolver: with a caller-supplied async function, or, with the
/// `https-records` feature, with Phantom's own DNS queries.
///
/// The resolver receives the host name as the connection names it, in ASCII
/// lowercase (for a URL host, with IDNA A-labels), never an IP literal, and
/// returns the addresses in the order connections should try them. Address
/// racing starts from that order as it does from the operating system's. An
/// error is reported as a failed system lookup would be on the same path; an
/// empty list is reported as a system answer with no addresses.
///
/// Clones share one resolver. A resolver that sends its own DNS queries
/// keeps its IPv6 route check and its count of fallbacks to the operating
/// system across the copies a client makes for its profile's UDP settings,
/// so every client given one resolver shares that state.
#[derive(Clone)]
pub struct AddressResolver {
    backend: Backend,
}

#[derive(Clone)]
enum Backend {
    Function(Arc<dyn Fn(String) -> ResolveFuture + Send + Sync>),
    #[cfg(feature = "https-records")]
    Dns(Arc<dyn DnsLookup>),
}

impl AddressResolver {
    /// Answers lookups with `lookup`.
    ///
    /// Its answers carry no record TTL, so an address cache keeps them for
    /// [`DnsCacheSettings::ttl`].
    ///
    /// Without an address cache, the returned future runs inside the
    /// connection attempt that asked for it, and is dropped with that
    /// attempt. With a cache, it runs as a task on the Tokio runtime of the
    /// connection that started the lookup, so that concurrent connections to
    /// one name share it and a dropped connection does not cancel it.
    pub fn from_fn<F, Fut>(lookup: F) -> Self
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<Vec<IpAddr>>> + Send + 'static,
    {
        Self::from_resolved_fn(move |host| {
            let lookup = lookup(host);
            async move { lookup.await.map(Resolved::without_ttl) }
        })
    }

    /// Answers lookups with `lookup`, whose answers may carry a record TTL.
    pub(crate) fn from_resolved_fn<F, Fut>(lookup: F) -> Self
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<Resolved>> + Send + 'static,
    {
        Self {
            backend: Backend::Function(Arc::new(move |host| {
                Box::pin(lookup(host)) as ResolveFuture
            })),
        }
    }

    /// Resolves names with Phantom's own DNS queries to the nameservers
    /// configured on this host, as Chromium's built-in DNS client does.
    ///
    /// The configuration is read once, now, as
    /// [`HttpsRecordResolver::system`](crate::dns::HttpsRecordResolver::system)
    /// reads it, and so is the hosts file. Each name is answered, in order:
    ///
    /// 1. `localhost` and names under it, with `::1` and `127.0.0.1`, without
    ///    a query;
    /// 2. a name without a dot, a name under `local`, or every name once the
    ///    operating system has answered 16 lookups in a row through the
    ///    fallback in step 5, through the operating system;
    /// 3. from the hosts file, without a query;
    /// 4. with an AAAA query, when this host has a global IPv6 route, and an
    ///    A query, sent once the AAAA datagram has left, each a single
    ///    question with recursion desired and no EDNS(0) record; IPv6
    ///    addresses come first;
    /// 5. through the operating system when a query fails or no address
    ///    comes back.
    ///
    /// Without a global IPv6 route, an answer from the operating system
    /// keeps only its IPv4 addresses, unless they are all loopback
    /// addresses.
    ///
    /// An answer from step 4 carries the smallest TTL of its address and
    /// alias records and of the SOA record of an empty answer, so an address
    /// cache keeps it for that TTL, at least
    /// [`DnsCacheSettings::min_record_ttl`]. Every other answer carries none.
    /// The IPv6 route check binds a UDP socket to `[::]:0`, connects it to
    /// `2001:4860:4860::8888` port 443 without sending anything, and reuses
    /// its result for one second.
    ///
    /// # Errors
    ///
    /// Returns an error when the host configuration cannot be read or names
    /// no nameserver.
    #[cfg(feature = "https-records")]
    pub fn system_nameservers() -> io::Result<Self> {
        crate::dns::AddressLookup::system().map(Self::from_dns)
    }

    /// Resolves names as [`Self::system_nameservers`] does, with queries to
    /// the given nameservers, in order, over UDP and then TCP when a UDP
    /// response is truncated.
    ///
    /// # Errors
    ///
    /// Returns an error when `nameservers` is empty.
    #[cfg(feature = "https-records")]
    pub fn with_nameservers(nameservers: impl IntoIterator<Item = SocketAddr>) -> io::Result<Self> {
        crate::dns::AddressLookup::with_nameservers(nameservers).map(Self::from_dns)
    }

    #[cfg(feature = "https-records")]
    pub(crate) fn from_dns(lookup: crate::dns::AddressLookup) -> Self {
        Self {
            backend: Backend::Dns(Arc::new(lookup)),
        }
    }

    /// Opens the UDP sockets of this resolver's own DNS queries with
    /// `settings`: the client applies its profile's [`UdpSettings`] here
    /// when it builds.
    ///
    /// With `port_randomization` on Windows, each query socket sets
    /// `SO_RANDOMIZE_PORT` and binds port 0, so Windows picks a random port;
    /// otherwise the resolver binds a random port itself. A resolver built
    /// with [`Self::from_fn`] opens no sockets and is returned unchanged.
    #[doc(hidden)]
    #[must_use]
    pub fn with_udp_settings(self, settings: UdpSettings) -> Self {
        match self.backend {
            #[cfg(feature = "https-records")]
            Backend::Dns(lookup) => Self {
                backend: Backend::Dns(lookup.opened_with(settings)),
            },
            backend @ Backend::Function(_) => {
                let _ = settings;
                Self { backend }
            }
        }
    }

    /// Returns the UDP settings of this resolver's own DNS queries, if it
    /// sends any and was given some.
    #[doc(hidden)]
    #[must_use]
    pub fn udp_settings(&self) -> Option<UdpSettings> {
        match &self.backend {
            #[cfg(feature = "https-records")]
            Backend::Dns(lookup) => lookup.socket_settings(),
            Backend::Function(_) => None,
        }
    }

    /// Starts a lookup of `host`, already lowercased.
    pub(crate) fn lookup(&self, host: &str) -> ResolveFuture {
        match &self.backend {
            Backend::Function(lookup) => lookup(host.to_owned()),
            #[cfg(feature = "https-records")]
            Backend::Dns(lookup) => Arc::clone(lookup).start(host.to_owned()),
        }
    }
}

impl fmt::Debug for AddressResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("AddressResolver");
        match &self.backend {
            Backend::Function(_) => debug.field("backend", &"function"),
            #[cfg(feature = "https-records")]
            Backend::Dns(lookup) => debug.field("backend", lookup),
        };
        debug.finish_non_exhaustive()
    }
}

/// How a client turns the host names it connects to itself into addresses.
///
/// It covers each name a connector resolves locally: the origin host of a
/// direct connection, every proxy host, and the target of a local-DNS
/// SOCKS5 route. A target that a proxy resolves (`socks5h://`, an HTTP
/// proxy, or CONNECT-UDP) never reaches it.
///
/// A name is answered, in order:
///
/// 1. as written, when it is an IP literal;
/// 2. from its override, when it has one, without a lookup or the cache;
/// 3. from the address cache, when there is one, which looks the name up
///    through the resolver below when it holds no fresh answer;
/// 4. through the [`AddressResolver`], when there is one, or the operating
///    system otherwise.
///
/// Every answer takes its port from the connection, so an override or a
/// resolver never changes the port. Names are compared without regard to
/// ASCII case. The TLS server name and the `Host` or `:authority` field
/// always carry the name, not the address.
///
/// Clones share the overrides, the resolver, and the cache. The overrides
/// are fixed once built.
#[derive(Clone, Default)]
pub struct HostResolver {
    overrides: Arc<HashMap<Box<str>, Arc<[IpAddr]>>>,
    resolver: Option<AddressResolver>,
    cache: Option<AddressCache>,
}

impl HostResolver {
    /// Creates a resolver that asks the operating system for every name,
    /// with no overrides and no cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Answers `host` with `addresses` in the given order, replacing any
    /// earlier override for the same name.
    ///
    /// An empty list makes the name fail to resolve. An override for an IP
    /// literal is never consulted, because an IP literal is used as written.
    #[must_use]
    pub fn with_override(
        mut self,
        host: &str,
        addresses: impl IntoIterator<Item = IpAddr>,
    ) -> Self {
        Arc::make_mut(&mut self.overrides).insert(
            host.to_ascii_lowercase().into_boxed_str(),
            addresses.into_iter().collect(),
        );
        self
    }

    /// Resolves names through `resolver` instead of the operating system.
    ///
    /// An address cache already set is replaced by an empty one with the
    /// same settings that looks names up through `resolver`.
    #[must_use]
    pub fn with_resolver(mut self, resolver: AddressResolver) -> Self {
        self.cache = self
            .cache
            .as_ref()
            .map(|cache| AddressCache::with_resolver(*cache.settings(), resolver.clone()));
        self.resolver = Some(resolver);
        self
    }

    /// Keeps the answers of this resolver's lookups in a new address cache
    /// with `settings`.
    #[must_use]
    pub fn with_cache(mut self, settings: DnsCacheSettings) -> Self {
        self.cache = Some(match &self.resolver {
            Some(resolver) => AddressCache::with_resolver(settings, resolver.clone()),
            None => AddressCache::new(settings),
        });
        self
    }

    /// Uses `cache` as the address cache, whatever resolver it looks names
    /// up with, for tests that count blocking lookups.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_address_cache(mut self, cache: AddressCache) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Returns the address cache, if any.
    #[must_use]
    pub fn cache(&self) -> Option<&AddressCache> {
        self.cache.as_ref()
    }

    /// Returns the resolver that answers names without an override, or
    /// `None` when the operating system does.
    #[doc(hidden)]
    #[must_use]
    pub fn resolver(&self) -> Option<&AddressResolver> {
        self.resolver.as_ref()
    }

    /// Returns the addresses `host` is overridden to, if it has an override.
    #[must_use]
    pub fn override_for(&self, host: &str) -> Option<&[IpAddr]> {
        if self.overrides.is_empty() {
            return None;
        }
        self.overrides
            .get(host.to_ascii_lowercase().as_str())
            .map(|addresses| &addresses[..])
    }

    /// Returns `host`'s addresses with `port`, and whether a stored answer
    /// supplied them without a lookup.
    ///
    /// An override reports `false`: it took no resolution time, so a
    /// handshake that waits for an HTTPS record after the addresses waits
    /// only that wait's minimum, as for any other near-instant resolution.
    async fn lookup(&self, host: &str, port: u16) -> io::Result<(Vec<SocketAddr>, bool)> {
        if let Ok(address) = host.parse::<IpAddr>() {
            return Ok((vec![SocketAddr::new(address, port)], false));
        }
        if let Some(addresses) = self.override_for(host) {
            return Ok((with_port(addresses.iter().copied(), port), false));
        }
        if let Some(cache) = &self.cache {
            return cache.lookup_noting_cache(host, port).await;
        }
        let addresses = match &self.resolver {
            Some(resolver) => resolver
                .lookup(&host.to_ascii_lowercase())
                .await?
                .addresses
                .into_iter()
                .map(|mut address| {
                    address.set_port(port);
                    address
                })
                .collect(),
            None => tokio::net::lookup_host((host, port)).await?.collect(),
        };
        Ok((addresses, false))
    }
}

impl fmt::Debug for HostResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostResolver")
            .field("overrides", &self.overrides.len())
            .field("resolver", &self.resolver.is_some())
            .field("cache", &self.cache)
            .finish()
    }
}

fn with_port(addresses: impl IntoIterator<Item = IpAddr>, port: u16) -> Vec<SocketAddr> {
    addresses
        .into_iter()
        .map(|address| SocketAddr::new(address, port))
        .collect()
}

/// Resolves `host` as [`resolve`] does, and reports whether a stored answer
/// supplied the addresses without a lookup.
#[cfg(feature = "https-records")]
pub(crate) async fn resolve_noting_cache(
    resolver: Option<&HostResolver>,
    host: &str,
    port: u16,
) -> io::Result<(Vec<SocketAddr>, bool)> {
    match resolver {
        Some(resolver) => resolver.lookup(host, port).await,
        None => Ok((
            tokio::net::lookup_host((host, port)).await?.collect(),
            false,
        )),
    }
}

/// Resolves `host` through `resolver`, or through the operating system on
/// every call when there is none.
pub(crate) async fn resolve(
    resolver: Option<&HostResolver>,
    host: &str,
    port: u16,
) -> io::Result<Vec<SocketAddr>> {
    match resolver {
        Some(resolver) => resolver
            .lookup(host, port)
            .await
            .map(|(addresses, _)| addresses),
        None => Ok(tokio::net::lookup_host((host, port)).await?.collect()),
    }
}

#[cfg(test)]
mod tests;
