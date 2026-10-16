//! Bounded per-client cache of resolved host addresses.

use std::{
    collections::HashMap,
    error::Error,
    fmt,
    future::Future,
    io,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Instant,
};

use phantom_profile::{DnsAddressFailurePolicy, DnsCacheSettings};
use tokio::sync::watch;

use crate::host_resolver::{
    AddressResolver, CacheLifetime, DnsConfigurationToken, Resolved,
    address_feedback::AddressRecord, tcp_addresses::TcpAddresses,
};

#[cfg(test)]
type LookupFuture = Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>>;
type ResolverFuture = Pin<Box<dyn Future<Output = io::Result<Resolved>> + Send>>;

/// Identifies one shared resolution in flight: the name, and for a caller's
/// resolver the runtime whose task runs it.
type PendingKey = (Box<str>, Option<tokio::runtime::Id>);

/// How the cache looks up a name it holds no fresh answer for.
#[derive(Clone)]
enum Lookup {
    /// Runs on the blocking pool, as the operating system resolver must.
    Blocking(Arc<dyn Fn(Box<str>) -> ResolverFuture + Send + Sync>),
    /// A caller's async resolver, run as a task on the runtime.
    Task(AddressResolver),
}

/// Addresses a client resolved for its own connections, reused until they
/// expire.
///
/// Each connector that holds the cache, through its
/// [`HostResolver`](crate::host_resolver::HostResolver), resolves an origin
/// host, a proxy host, or a local-DNS SOCKS5 target through it. A target a
/// proxy resolves is never looked up locally, so it never reaches the cache,
/// and neither does a name with an override. Names are compared without
/// regard to ASCII case, and an IP literal is used as written without a
/// lookup.
///
/// A lookup's answer keeps the resolver's address order, on which address
/// racing depends. A system answer with a native remaining lifetime keeps
/// its absolute expiry without a floor. An answer without a record TTL is
/// kept for [`DnsCacheSettings::ttl`]; one with a record TTL,
/// from the built-in DNS resolver, for that TTL or
/// [`DnsCacheSettings::min_record_ttl`], whichever is longer. A failure or an
/// empty answer is kept for [`DnsCacheSettings::negative_ttl`], or not at
/// all. A lifetime too long for the clock never expires on these legacy
/// paths. Answers from [`AddressResolver::from_answer_fn`] keep their DNS
/// lifetime from construction without a minimum floor. Negative answers also
/// obey the configured negative cap; operational errors are never stored.
/// Addresses keep everything the resolver returned except the port, which
/// each lookup supplies, so an IPv6 scope ID and flow label survive.
///
/// Concurrent lookups of one name share one resolution. An operating system
/// resolution runs with `spawn_blocking` on the blocking pool of the runtime
/// that started it, as Tokio's own `lookup_host` does, so resolutions in
/// flight are bounded by that pool: 512 threads unless the runtime was built
/// with another `max_blocking_threads`; further names wait in the pool's
/// queue. A blocking thread runs whether or not its runtime is being driven,
/// and the answer is published through a channel that any runtime can wait
/// on, so a lookup from one runtime never depends on another runtime being
/// driven. A caller's [`AddressResolver`] instead runs as a task on the
/// runtime that started the resolution, and only lookups from that runtime
/// share it: a lookup of the same name from another runtime starts a
/// resolution of its own, so it never waits on a runtime that has stopped
/// being driven. Either way, the resolution completes and fills the cache
/// even when every connection that asked for it has been dropped. If the
/// runtime drops the resolution before it finishes, as a runtime that is
/// shutting down does, or the resolution panics, its waiters get an error and
/// the next lookup of the name starts again.
/// The lock is never held across an `.await`.
///
/// Clones share one cache. It holds at most
/// [`DnsCacheSettings::max_entries`] names; when it is full, a new answer
/// replaces an expired one, then the one that would expire soonest. At most
/// as many shared resolutions are in flight. Past that bound, a lookup
/// through a caller's resolver runs inside the connection that asked for it
/// and ends with it, and a system lookup runs on the blocking pool without
/// being shared; either still stores its answer. A resolver that never
/// answers therefore holds at most `max_entries` tasks and pending entries.
#[derive(Clone)]
pub struct AddressCache {
    inner: Arc<Inner>,
}

struct Inner {
    settings: DnsCacheSettings,
    lookup: Lookup,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    entries: HashMap<Box<str>, Entry>,
    /// Shared resolutions in flight, at most `max_entries` of them.
    pending: HashMap<PendingKey, watch::Receiver<Option<Outcome>>>,
    /// Shared resolutions still running, including those a clear detached
    /// from `pending`. Their publishers release these reservations on drop.
    shared_resolutions: usize,
    /// Advanced by [`AddressCache::clear`], so that a resolution started
    /// before the clear does not store its answer after it.
    generation: u64,
    configuration: Option<DnsConfigurationToken>,
}

struct Entry {
    outcome: Outcome,
    /// `None` when the lifetime reaches past what `Instant` can represent.
    expires_at: Option<Instant>,
}

impl Entry {
    fn is_fresh(&self, now: Instant) -> bool {
        self.expires_at.is_none_or(|expires_at| expires_at > now)
    }

    /// Orders entries by expiry, soonest first, with never-expiring last.
    fn eviction_key(&self) -> (bool, Option<Instant>) {
        (self.expires_at.is_none(), self.expires_at)
    }
}

/// One resolution's result, shared by every lookup that waited for it.
#[derive(Clone)]
enum Outcome {
    /// The resolver's answer, possibly empty; each connection path reports an
    /// empty answer as it would without the cache.
    Resolved(Arc<CachedAddresses>),
    Failed(SharedResolverError),
}

struct CachedAddresses {
    addresses: Arc<[SocketAddr]>,
    record: Option<Arc<AddressRecord>>,
}

/// Shares one original resolver failure across waiters and stored outcomes.
#[derive(Clone, Debug)]
struct SharedResolverError {
    original: Arc<io::Error>,
}

impl fmt::Display for SharedResolverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.original.as_ref(), formatter)
    }
}

impl Error for SharedResolverError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.original.as_ref())
    }
}

impl Outcome {
    /// Keeps answer lifetime metadata separate from an operational error.
    fn from_resolution(result: io::Result<Resolved>, cache_errors: bool) -> (Self, CacheLifetime) {
        match result {
            Ok(resolved) => {
                let (result, lifetime) = resolved.into_parts();
                (Self::from_result(result), lifetime)
            }
            Err(error) => (
                Self::from_result(Err(error)),
                if cache_errors {
                    CacheLifetime::Legacy(None)
                } else {
                    CacheLifetime::Never
                },
            ),
        }
    }

    fn from_result(result: io::Result<Vec<SocketAddr>>) -> Self {
        match result {
            Ok(addresses) => Self::Resolved(Arc::new(CachedAddresses {
                addresses: addresses.into(),
                record: None,
            })),
            Err(error) => Self::Failed(SharedResolverError {
                original: Arc::new(error),
            }),
        }
    }

    /// Whether this outcome is kept for the negative lifetime.
    fn is_negative(&self) -> bool {
        match self {
            Self::Resolved(addresses) => addresses.addresses.is_empty(),
            Self::Failed(_) => true,
        }
    }

    fn tcp_addresses(
        &self,
        port: u16,
        configuration: Option<DnsConfigurationToken>,
    ) -> io::Result<TcpAddresses> {
        let addresses = self.addresses(port)?;
        let record = match self {
            Self::Resolved(answer) => answer.record.clone(),
            Self::Failed(_) => None,
        };
        Ok(TcpAddresses::cached(addresses, record, port, configuration))
    }

    fn addresses(&self, port: u16) -> io::Result<Vec<SocketAddr>> {
        match self {
            Self::Resolved(addresses) => Ok(addresses
                .addresses
                .iter()
                .map(|address| {
                    let mut address = *address;
                    address.set_port(port);
                    address
                })
                .collect()),
            Self::Failed(error) => Err(io::Error::new(error.original.kind(), error.clone())),
        }
    }
}

impl AddressCache {
    /// Creates an empty cache that resolves names through the operating
    /// system.
    #[must_use]
    pub fn new(settings: DnsCacheSettings) -> Self {
        // Runs on a blocking-pool thread, so blocking here is intended.
        Self::with_blocking_lookup(settings, move |host| {
            Box::pin(async move {
                #[cfg(windows)]
                if settings.system_ttl == phantom_profile::SystemDnsTtlPolicy::FirefoxWindows
                    && host.is_ascii()
                {
                    let (addresses, ttl) = crate::system_dns_ffi::resolve(&host)?;
                    return Ok(Resolved::System { addresses, ttl });
                }

                Ok(Resolved::Legacy {
                    addresses: (&*host, 0).to_socket_addrs()?.collect(),
                    ttl: None,
                })
            })
        })
    }

    /// Creates an empty cache that resolves names with `lookup`.
    ///
    /// `lookup` receives the lowercased name. Its future runs on a
    /// blocking-pool thread under a Tokio current-thread runtime without I/O
    /// or timer drivers.
    #[cfg(test)]
    pub(crate) fn with_lookup<F>(settings: DnsCacheSettings, lookup: F) -> Self
    where
        F: Fn(Box<str>) -> LookupFuture + Send + Sync + 'static,
    {
        Self::with_blocking_lookup(settings, move |host| {
            let resolution = lookup(host);
            Box::pin(async move {
                resolution.await.map(|addresses| Resolved::Legacy {
                    addresses,
                    ttl: None,
                })
            })
        })
    }

    fn with_blocking_lookup<F>(settings: DnsCacheSettings, lookup: F) -> Self
    where
        F: Fn(Box<str>) -> ResolverFuture + Send + Sync + 'static,
    {
        Self::with(settings, Lookup::Blocking(Arc::new(lookup)))
    }

    /// Creates an empty cache that resolves names with `resolver`.
    pub(crate) fn with_resolver(settings: DnsCacheSettings, resolver: AddressResolver) -> Self {
        Self::with(settings, Lookup::Task(resolver))
    }

    fn with(settings: DnsCacheSettings, lookup: Lookup) -> Self {
        Self {
            inner: Arc::new(Inner {
                settings,
                lookup,
                state: Mutex::new(State::default()),
            }),
        }
    }

    /// Returns the settings the cache was created with.
    #[must_use]
    pub fn settings(&self) -> &DnsCacheSettings {
        &self.inner.settings
    }

    /// Returns the number of names with a stored answer or failure, expired
    /// ones included until they are replaced.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    /// Reports whether no name has a stored answer or failure.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Forgets every stored answer and failure.
    ///
    /// A resolution in flight still answers the connections waiting for it,
    /// but its answer is not stored.
    pub fn clear(&self) {
        let mut state = self.lock();
        state.entries.clear();
        state.pending.clear();
        state.generation += 1;
    }

    /// Returns what [`Self::lookup_noting_cache`] returns, without the flag.
    #[cfg(test)]
    pub(crate) async fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        self.lookup_noting_cache(host, port)
            .await
            .map(|(addresses, _)| addresses)
    }

    /// Returns `host`'s addresses with `port`, in resolver order, and whether
    /// a stored answer supplied them without a resolution.
    ///
    /// A fresh stored answer or failure is returned at once. Otherwise the
    /// lookup joins the resolution in flight for the name, or starts one.
    ///
    /// # Errors
    ///
    /// Returns the resolver's error, or a stored copy of it, when the name
    /// does not resolve; an error when there is no Tokio runtime to run the
    /// resolution on, or when it ends without an answer, as when that runtime
    /// drops it while shutting down. An empty answer is returned as `Ok`.
    pub(crate) async fn lookup_noting_cache(
        &self,
        host: &str,
        port: u16,
    ) -> io::Result<(Vec<SocketAddr>, bool)> {
        self.lookup_outcome(host)
            .await
            .and_then(|(outcome, stored, configuration)| {
                Self::check_configuration(&configuration)?;
                outcome.addresses(port).map(|addresses| (addresses, stored))
            })
    }

    pub(crate) async fn lookup_tcp_noting_cache(
        &self,
        host: &str,
        port: u16,
    ) -> io::Result<(TcpAddresses, bool)> {
        let (outcome, stored, configuration) = self.lookup_outcome(host).await?;
        Self::check_configuration(&configuration)?;
        outcome
            .tcp_addresses(port, configuration)
            .map(|addresses| (addresses, stored))
    }

    async fn lookup_outcome(
        &self,
        host: &str,
    ) -> io::Result<(Outcome, bool, Option<DnsConfigurationToken>)> {
        if let Ok(address) = host.parse::<IpAddr>() {
            return Ok((
                Outcome::from_result(Ok(vec![SocketAddr::new(address, 0)])),
                false,
                None,
            ));
        }
        let configuration = self.configuration_token()?;
        let answer = self.cached_or_pending_with_configuration(
            host.to_ascii_lowercase().into_boxed_str(),
            configuration.clone(),
        )?;
        let result = self.consume_outcome(answer).await;
        Self::check_configuration(&configuration)?;
        result.map(|(outcome, stored)| (outcome, stored, configuration))
    }

    #[cfg(test)]
    async fn consume_answer(
        &self,
        answer: Answer,
        port: u16,
    ) -> io::Result<(Vec<SocketAddr>, bool)> {
        self.consume_outcome(answer)
            .await
            .and_then(|(outcome, stored)| {
                outcome.addresses(port).map(|addresses| (addresses, stored))
            })
    }

    /// Waits for the selected answer and gives its addresses the caller's port.
    async fn consume_outcome(&self, answer: Answer) -> io::Result<(Outcome, bool)> {
        let mut receiver = match answer {
            Answer::Stored(outcome) => {
                return Ok((outcome, true));
            }
            Answer::Wait(receiver) => receiver,
            Answer::Inline {
                host,
                generation,
                configuration,
                resolution,
            } => {
                let mut result = resolution.await;
                if let Err(error) = Self::check_configuration(&configuration) {
                    result = Err(error);
                }
                let (outcome, lifetime) = Outcome::from_resolution(result, self.cache_errors());
                let outcome =
                    self.complete(&host, None, generation, &configuration, &outcome, lifetime);
                return Ok((outcome, false));
            }
        };

        let outcome = match receiver.wait_for(Option::is_some).await {
            Ok(outcome) => outcome.clone(),
            Err(_) => None,
        };

        match outcome {
            Some(outcome) => Ok((outcome, false)),
            None => Err(io::Error::other(
                "the address lookup ended without an answer",
            )),
        }
    }

    /// Selects a stored outcome or a resolution, starting one when needed.
    ///
    /// Provenance is decided under the lock: a resolution publishing before
    /// its caller starts waiting does not make that lookup a cache hit.
    /// Past the shared bound, a caller's resolution runs inline.
    #[cfg(test)]
    fn cached_or_pending(&self, host: Box<str>) -> io::Result<Answer> {
        let configuration = self.configuration_token()?;
        self.cached_or_pending_with_configuration(host, configuration)
    }

    fn cached_or_pending_with_configuration(
        &self,
        host: Box<str>,
        configuration: Option<DnsConfigurationToken>,
    ) -> io::Result<Answer> {
        let mut state = self.lock();
        Self::check_configuration(&configuration)?;
        if state.configuration != configuration {
            state.entries.clear();
            state.pending.clear();
            state.configuration = configuration.clone();
        }
        let now = Instant::now();
        match state.entries.get(&host) {
            Some(entry) if entry.is_fresh(now) => {
                return Ok(Answer::Stored(entry.outcome.clone()));
            }
            Some(_) => {
                if matches!(
                    self.inner.settings.address_failure_policy,
                    DnsAddressFailurePolicy::Ignore
                ) {
                    state.entries.remove(&host);
                }
            }
            None => {}
        }

        // A resolution that ended without an answer, as when its runtime shut
        // down or its task panicked, has dropped its sender; such entries are
        // pruned here and the name is resolved again.
        state
            .pending
            .retain(|_, receiver| receiver.has_changed().is_ok());

        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| io::Error::other("an address lookup needs a Tokio runtime"))?;
        let key = match &self.inner.lookup {
            Lookup::Blocking(_) => (host, None),
            Lookup::Task(_) => (host, Some(runtime.id())),
        };
        if let Some(receiver) = state.pending.get(&key) {
            return Ok(Answer::Wait(receiver.clone()));
        }

        let generation = state.generation;
        let shared = state.shared_resolutions < self.inner.settings.max_entries.get();
        if !shared && let Lookup::Task(resolver) = &self.inner.lookup {
            drop(state);
            let resolution = resolver.lookup_with_configuration(&key.0, configuration.clone());
            return Ok(Answer::Inline {
                host: key.0,
                generation,
                configuration,
                resolution,
            });
        }

        let (sender, receiver) = watch::channel(None);
        if shared {
            state.shared_resolutions += 1;
            state.pending.insert(key.clone(), receiver.clone());
        }
        drop(state);

        let publisher = Publisher {
            cache: self.clone(),
            key,
            shared,
            generation,
            configuration,
            sender: Some(sender),
        };
        match &self.inner.lookup {
            Lookup::Blocking(lookup) => {
                let resolution = lookup(publisher.key.0.clone());
                drop(runtime.spawn_blocking(move || {
                    let result = tokio::runtime::Builder::new_current_thread()
                        .build()
                        .map_err(io::Error::other)
                        .and_then(|runtime| runtime.block_on(resolution));
                    publisher.publish(result);
                }));
            }
            Lookup::Task(resolver) => {
                let resolution = resolver
                    .lookup_with_configuration(&publisher.key.0, publisher.configuration.clone());
                drop(runtime.spawn(async move {
                    publisher.publish(resolution.await);
                }));
            }
        }

        Ok(Answer::Wait(receiver))
    }

    /// Stores a finished resolution, unless the cache was cleared after it
    /// started, and releases its shared entry in `pending`, if it has one.
    ///
    /// `lifetime` distinguishes legacy retention from bounded DNS answers.
    fn complete(
        &self,
        host: &str,
        pending: Option<&PendingKey>,
        generation: u64,
        configuration: &Option<DnsConfigurationToken>,
        outcome: &Outcome,
        lifetime: CacheLifetime,
    ) -> Outcome {
        let mut state = self.lock();
        if state.generation != generation
            || state.configuration != *configuration
            || Self::check_configuration(configuration).is_err()
        {
            return outcome.clone();
        }

        if let Some(key) = pending {
            state.pending.remove(key);
        }
        state
            .pending
            .retain(|_, receiver| receiver.has_changed().is_ok());
        let settings = &self.inner.settings;
        let now = Instant::now();
        let expires_at = match lifetime {
            CacheLifetime::Legacy(record_ttl) => {
                let ttl = if outcome.is_negative() {
                    settings.negative_ttl
                } else {
                    Some(record_ttl.map_or(settings.ttl, |ttl| ttl.max(settings.min_record_ttl)))
                };
                // Preserve legacy answers' never-expiring overflow behavior.
                let Some(expires_at) = ttl
                    .filter(|ttl| !ttl.is_zero())
                    .map(|ttl| now.checked_add(ttl))
                else {
                    return outcome.clone();
                };
                expires_at
            }
            CacheLifetime::Dns(lifetime) => {
                let Some(expires_at) = lifetime.expires_at(settings.negative_ttl) else {
                    return outcome.clone();
                };
                if expires_at <= now {
                    return outcome.clone();
                }
                Some(expires_at)
            }
            CacheLifetime::Never => return outcome.clone(),
            #[cfg(any(windows, test))]
            CacheLifetime::System(expiry) => {
                let Some(expiry) = expiry.filter(|expiry| *expiry > now) else {
                    return outcome.clone();
                };
                Some(expiry)
            }
        };
        let outcome = match (outcome, settings.address_failure_policy) {
            (
                Outcome::Resolved(answer),
                DnsAddressFailurePolicy::Record {
                    max_unusable_addresses,
                },
            ) if !answer.addresses.is_empty() => {
                let record = state
                    .entries
                    .get(host)
                    .and_then(|entry| match &entry.outcome {
                        Outcome::Resolved(previous) => previous.record.clone(),
                        Outcome::Failed(_) => None,
                    });
                let record = match record {
                    Some(record) => {
                        if let Err(error) = record.refresh(answer.addresses.to_vec()) {
                            return Outcome::from_result(Err(io::Error::other(error)));
                        }
                        record
                    }
                    None => Arc::new(AddressRecord::new(
                        answer.addresses.to_vec(),
                        max_unusable_addresses,
                    )),
                };
                Outcome::Resolved(Arc::new(CachedAddresses {
                    addresses: Arc::clone(&answer.addresses),
                    record: Some(record),
                }))
            }
            _ => outcome.clone(),
        };
        if !state.entries.contains_key(host)
            && state.entries.len() >= self.inner.settings.max_entries.get()
        {
            state.entries.retain(|_, entry| entry.is_fresh(now));
            while state.entries.len() >= self.inner.settings.max_entries.get() {
                let Some(soonest) = state
                    .entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.eviction_key())
                    .map(|(name, _)| name.clone())
                else {
                    break;
                };
                state.entries.remove(&soonest);
            }
        }

        state.entries.insert(
            host.into(),
            Entry {
                outcome: outcome.clone(),
                expires_at,
            },
        );
        outcome
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // Every critical section leaves the maps valid, so a panic in another
        // thread cannot leave state that needs repair.
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn configuration_token(&self) -> io::Result<Option<DnsConfigurationToken>> {
        match &self.inner.lookup {
            Lookup::Blocking(_) => Ok(None),
            Lookup::Task(resolver) => resolver.configuration_token(),
        }
    }

    fn check_configuration(token: &Option<DnsConfigurationToken>) -> io::Result<()> {
        token
            .as_ref()
            .map_or(Ok(()), DnsConfigurationToken::require_current)
    }

    fn cache_errors(&self) -> bool {
        match &self.inner.lookup {
            Lookup::Blocking(_) => true,
            Lookup::Task(resolver) => resolver.cache_errors(),
        }
    }
}

/// The sending side of one resolution.
///
/// Dropped without sending, as when the runtime shuts down before the
/// resolution finishes, it releases the pending entry so that waiters see an
/// error and the next lookup of the name starts a new resolution.
struct Publisher {
    cache: AddressCache,
    key: PendingKey,
    /// Whether `key` is in `pending`, so that completion releases it.
    shared: bool,
    generation: u64,
    configuration: Option<DnsConfigurationToken>,
    sender: Option<watch::Sender<Option<Outcome>>>,
}

impl Publisher {
    /// Stores the resolution's result and answers its waiters.
    fn publish(mut self, mut result: io::Result<Resolved>) {
        if let Err(error) = AddressCache::check_configuration(&self.configuration) {
            result = Err(error);
        }
        let (outcome, lifetime) = Outcome::from_resolution(result, self.cache.cache_errors());
        let pending = self.shared.then_some(&self.key);
        let outcome = self.cache.complete(
            &self.key.0,
            pending,
            self.generation,
            &self.configuration,
            &outcome,
            lifetime,
        );
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(Some(outcome));
        }
    }
}

impl Drop for Publisher {
    fn drop(&mut self) {
        let unanswered = self.sender.take().is_some();
        let mut state = self.cache.lock();
        if self.shared {
            state.shared_resolutions -= 1;
        }

        if unanswered {
            state
                .pending
                .retain(|_, receiver| receiver.has_changed().is_ok());
        }
    }
}

/// How [`AddressCache::cached_or_pending_with_configuration`] answers a lookup.
enum Answer {
    /// A fresh cache entry selected while holding the cache lock.
    Stored(Outcome),
    /// A newly started or joined resolution, whether or not it has published.
    Wait(watch::Receiver<Option<Outcome>>),
    /// A caller's resolution past the bound, for the lookup to run itself.
    Inline {
        host: Box<str>,
        generation: u64,
        configuration: Option<DnsConfigurationToken>,
        resolution: ResolverFuture,
    },
}

impl fmt::Debug for AddressCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AddressCache")
            .field("settings", &self.inner.settings)
            .field("entries", &self.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
