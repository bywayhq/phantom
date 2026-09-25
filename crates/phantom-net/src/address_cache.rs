//! Bounded per-client cache of resolved host addresses.

use std::{
    collections::HashMap,
    fmt,
    future::Future,
    io,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Instant,
};

use phantom_profile::DnsCacheSettings;
use tokio::sync::watch;

type LookupFuture = Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>>;
type Lookup = Arc<dyn Fn(Box<str>) -> LookupFuture + Send + Sync>;

/// Addresses a client resolved for its own connections, reused until they
/// expire.
///
/// Each connector that holds the cache resolves an origin host, a proxy host,
/// or a local-DNS SOCKS5 target through it. A target a proxy resolves is never
/// looked up locally, so it never reaches the cache. Names are compared
/// without regard to ASCII case, and an IP literal is used as written without
/// a lookup.
///
/// A lookup's answer keeps the operating system resolver's address order, on
/// which address racing depends. It is kept for [`DnsCacheSettings::ttl`]; a
/// failure or an empty answer is kept for [`DnsCacheSettings::negative_ttl`],
/// or not at all. A lifetime too long for the clock never expires.
/// Addresses keep everything the resolver returned except the port, which
/// each lookup supplies, so an IPv6 scope ID and flow label survive.
///
/// Concurrent lookups of one name share one resolution. It runs with
/// `spawn_blocking` on the blocking pool of the runtime that started it, as
/// Tokio's own `lookup_host` does, so resolutions in flight are bounded by
/// that pool: 512 threads unless the runtime was built with another
/// `max_blocking_threads`; further names wait in the pool's queue. A blocking
/// thread runs whether or not its runtime is being driven, and the answer is
/// published through a channel that any runtime can wait on, so a lookup from
/// one runtime never depends on another runtime being driven. The resolution
/// completes and fills the cache even when every connection that asked for it
/// has been dropped. If the runtime drops the resolution before it runs, as
/// a runtime that is shutting down does, its waiters get an error and the
/// next lookup of the name starts again.
/// The lock is never held across an `.await`.
///
/// Clones share one cache. It holds at most
/// [`DnsCacheSettings::max_entries`] names; when it is full, a new answer
/// replaces an expired one, then the one that would expire soonest.
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
    /// Resolutions in flight.
    pending: HashMap<Box<str>, watch::Receiver<Option<Outcome>>>,
    /// Advanced by [`AddressCache::clear`], so that a resolution started
    /// before the clear does not store its answer after it.
    generation: u64,
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
    Resolved(Arc<[SocketAddr]>),
    Failed {
        kind: io::ErrorKind,
        message: Arc<str>,
    },
}

impl Outcome {
    fn from_result(result: io::Result<Vec<SocketAddr>>) -> Self {
        match result {
            Ok(addresses) => Self::Resolved(addresses.into()),
            Err(error) => Self::Failed {
                kind: error.kind(),
                message: Arc::from(error.to_string()),
            },
        }
    }

    /// Whether this outcome is kept for the negative lifetime.
    fn is_negative(&self) -> bool {
        match self {
            Self::Resolved(addresses) => addresses.is_empty(),
            Self::Failed { .. } => true,
        }
    }

    fn addresses(&self, port: u16) -> io::Result<Vec<SocketAddr>> {
        match self {
            Self::Resolved(addresses) => Ok(addresses
                .iter()
                .map(|address| {
                    let mut address = *address;
                    address.set_port(port);
                    address
                })
                .collect()),
            Self::Failed { kind, message } => Err(io::Error::new(*kind, message.to_string())),
        }
    }
}

impl AddressCache {
    /// Creates an empty cache that resolves names through the operating
    /// system.
    #[must_use]
    pub fn new(settings: DnsCacheSettings) -> Self {
        // Runs on a blocking-pool thread, so blocking here is intended.
        Self::with_lookup(settings, |host| {
            Box::pin(async move { Ok((&*host, 0).to_socket_addrs()?.collect()) })
        })
    }

    /// Creates an empty cache that resolves names with `lookup`.
    ///
    /// Test plumbing for the `phantom` facade, which counts lookups through
    /// its connectors. `lookup` receives the lowercased name. Its future runs
    /// on a blocking-pool thread under a Tokio current-thread runtime without
    /// I/O or timer drivers.
    #[doc(hidden)]
    pub fn with_lookup<F>(settings: DnsCacheSettings, lookup: F) -> Self
    where
        F: Fn(Box<str>) -> LookupFuture + Send + Sync + 'static,
    {
        Self {
            inner: Arc::new(Inner {
                settings,
                lookup: Arc::new(lookup),
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

    /// Returns `host`'s addresses with `port`, in resolver order.
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
    pub(crate) async fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        self.lookup_noting_cache(host, port)
            .await
            .map(|(addresses, _)| addresses)
    }

    /// Returns what [`Self::lookup`] returns, and whether a stored answer
    /// supplied it without a resolution.
    pub(crate) async fn lookup_noting_cache(
        &self,
        host: &str,
        port: u16,
    ) -> io::Result<(Vec<SocketAddr>, bool)> {
        if let Ok(address) = host.parse::<IpAddr>() {
            return Ok((vec![SocketAddr::new(address, port)], false));
        }
        let mut receiver = self.cached_or_pending(host.to_ascii_lowercase().into_boxed_str())?;
        let stored = receiver.borrow().is_some();
        let outcome = match receiver.wait_for(Option::is_some).await {
            Ok(outcome) => outcome.clone(),
            Err(_) => None,
        };
        match outcome {
            Some(outcome) => outcome.addresses(port).map(|addresses| (addresses, stored)),
            None => Err(io::Error::other(
                "the address lookup ended without an answer",
            )),
        }
    }

    /// Returns a receiver already holding the stored outcome for `host`, or
    /// one for the resolution in flight, starting it when there is none.
    fn cached_or_pending(&self, host: Box<str>) -> io::Result<watch::Receiver<Option<Outcome>>> {
        let mut state = self.lock();
        let now = Instant::now();
        match state.entries.get(&host) {
            Some(entry) if entry.is_fresh(now) => {
                return Ok(watch::channel(Some(entry.outcome.clone())).1);
            }
            Some(_) => {
                state.entries.remove(&host);
            }
            None => {}
        }
        // A resolution that ended without an answer, as when its runtime shut
        // down or its task panicked, has dropped its sender; such entries are
        // pruned here and the name is resolved again.
        state
            .pending
            .retain(|_, receiver| receiver.has_changed().is_ok());
        if let Some(receiver) = state.pending.get(&host) {
            return Ok(receiver.clone());
        }
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| io::Error::other("an address lookup needs a Tokio runtime"))?;
        let (sender, receiver) = watch::channel(None);
        let generation = state.generation;
        state.pending.insert(host.clone(), receiver.clone());
        drop(state);

        let resolution = (self.inner.lookup)(host.clone());
        let mut publisher = Publisher {
            cache: self.clone(),
            sender: Some(sender),
        };
        drop(runtime.spawn_blocking(move || {
            let result = tokio::runtime::Builder::new_current_thread()
                .build()
                .map_err(io::Error::other)
                .and_then(|runtime| runtime.block_on(resolution));
            let outcome = Outcome::from_result(result);
            publisher.cache.complete(host, generation, &outcome);
            if let Some(sender) = publisher.sender.take() {
                let _ = sender.send(Some(outcome));
            }
        }));
        Ok(receiver)
    }

    /// Stores a finished resolution, unless the cache was cleared after it
    /// started.
    fn complete(&self, host: Box<str>, generation: u64, outcome: &Outcome) {
        let mut state = self.lock();
        if state.generation != generation {
            return;
        }
        state.pending.remove(&host);
        state
            .pending
            .retain(|_, receiver| receiver.has_changed().is_ok());
        let ttl = if outcome.is_negative() {
            self.inner.settings.negative_ttl
        } else {
            Some(self.inner.settings.ttl)
        };
        let now = Instant::now();
        // A lifetime too long for `Instant` never expires rather than
        // expiring at once.
        let Some(expires_at) = ttl
            .filter(|ttl| !ttl.is_zero())
            .map(|ttl| now.checked_add(ttl))
        else {
            return;
        };
        if !state.entries.contains_key(&host)
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
            host,
            Entry {
                outcome: outcome.clone(),
                expires_at,
            },
        );
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // Every critical section leaves the maps valid, so a panic in another
        // thread cannot leave state that needs repair.
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// The sending side of one resolution.
///
/// Dropped without sending, as when the runtime shuts down before the
/// blocking task starts, it releases the pending entry so that waiters see an
/// error and the next lookup of the name starts a new resolution.
struct Publisher {
    cache: AddressCache,
    sender: Option<watch::Sender<Option<Outcome>>>,
}

impl Drop for Publisher {
    fn drop(&mut self) {
        if self.sender.take().is_some() {
            self.cache
                .lock()
                .pending
                .retain(|_, receiver| receiver.has_changed().is_ok());
        }
    }
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

/// Resolves `host` as [`resolve`] does, and reports whether a stored answer
/// supplied the addresses without a resolution.
#[cfg(feature = "https-records")]
pub(crate) async fn resolve_noting_cache(
    cache: Option<&AddressCache>,
    host: &str,
    port: u16,
) -> io::Result<(Vec<SocketAddr>, bool)> {
    match cache {
        Some(cache) => cache.lookup_noting_cache(host, port).await,
        None => Ok((
            tokio::net::lookup_host((host, port)).await?.collect(),
            false,
        )),
    }
}

/// Resolves `host` through `cache`, or through the operating system on every
/// call when there is none.
pub(crate) async fn resolve(
    cache: Option<&AddressCache>,
    host: &str,
    port: u16,
) -> io::Result<Vec<SocketAddr>> {
    match cache {
        Some(cache) => cache.lookup(host, port).await,
        None => Ok(tokio::net::lookup_host((host, port)).await?.collect()),
    }
}

#[cfg(test)]
mod tests;
