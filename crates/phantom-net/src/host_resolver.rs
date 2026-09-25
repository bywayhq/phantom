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
};

use phantom_profile::DnsCacheSettings;

use crate::address_cache::AddressCache;

type ResolveFuture = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'static>>;

/// Resolves host names to addresses with a caller-supplied async function,
/// in place of the operating system resolver.
///
/// The function receives the host name as the connection names it, in ASCII
/// lowercase (for a URL host, with IDNA A-labels), never an IP literal, and
/// returns the addresses in the order connections should try them. Address
/// racing starts from that order as it does from the operating system's. An error is reported as a failed system lookup would
/// be on the same path; an empty list is reported as a system answer with
/// no addresses.
///
/// Clones share one function.
#[derive(Clone)]
pub struct AddressResolver {
    lookup: Arc<dyn Fn(String) -> ResolveFuture + Send + Sync>,
}

impl AddressResolver {
    /// Answers lookups with `lookup`.
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
        Self {
            lookup: Arc::new(move |host| Box::pin(lookup(host)) as ResolveFuture),
        }
    }

    /// Starts a lookup of `host`, already lowercased.
    pub(crate) fn lookup(&self, host: &str) -> ResolveFuture {
        (self.lookup)(host.to_owned())
    }
}

impl fmt::Debug for AddressResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AddressResolver")
            .finish_non_exhaustive()
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

    /// Returns a clone with the same overrides and resolver and an empty
    /// cache of its own, or no cache when this one has none.
    #[must_use]
    pub fn with_empty_cache(&self) -> Self {
        Self {
            overrides: Arc::clone(&self.overrides),
            resolver: self.resolver.clone(),
            cache: self.cache.as_ref().map(AddressCache::emptied),
        }
    }

    /// Returns the address cache, if any.
    #[must_use]
    pub fn cache(&self) -> Option<&AddressCache> {
        self.cache.as_ref()
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
            Some(resolver) => with_port(resolver.lookup(&host.to_ascii_lowercase()).await?, port),
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
