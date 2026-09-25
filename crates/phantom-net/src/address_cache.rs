//! Bounded per-client cache of resolved host addresses.

use std::{
    collections::HashMap,
    fmt,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Instant,
};

use phantom_profile::DnsCacheSettings;
use tokio::sync::watch;

type LookupFuture = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send>>;
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
/// failure is kept for [`DnsCacheSettings::negative_ttl`], or not at all.
/// Concurrent lookups of one name share one resolution, which runs as its own
/// task, so it completes and fills the cache even when every connection that
/// asked for it has been dropped. The lock is never held across an `.await`.
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
    expires_at: Instant,
}

/// One resolution's result, shared by every lookup that waited for it.
#[derive(Clone)]
enum Outcome {
    Resolved(Arc<[IpAddr]>),
    Failed {
        kind: io::ErrorKind,
        message: Arc<str>,
    },
}

impl Outcome {
    fn from_result(result: io::Result<Vec<IpAddr>>) -> Self {
        match result {
            Ok(addresses) if !addresses.is_empty() => Self::Resolved(addresses.into()),
            Ok(_) => Self::Failed {
                kind: io::ErrorKind::InvalidInput,
                message: Arc::from("could not resolve to any addresses"),
            },
            Err(error) => Self::Failed {
                kind: error.kind(),
                message: Arc::from(error.to_string()),
            },
        }
    }

    fn addresses(&self, port: u16) -> io::Result<Vec<SocketAddr>> {
        match self {
            Self::Resolved(addresses) => Ok(addresses
                .iter()
                .map(|address| SocketAddr::new(*address, port))
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
        Self::with_lookup(settings, |host| {
            Box::pin(async move {
                let addresses = tokio::net::lookup_host((&*host, 0)).await?;
                Ok(addresses.map(|address| address.ip()).collect())
            })
        })
    }

    /// Creates an empty cache that resolves names with `lookup`.
    ///
    /// Test plumbing for the `phantom` facade, which counts lookups through
    /// its connectors. `lookup` receives the lowercased name.
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
    /// does not resolve; an error of kind `InvalidInput` when it resolves to
    /// no address; and an error when there is no Tokio runtime to run the
    /// resolution or it ends without an answer.
    pub(crate) async fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        if let Ok(address) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(address, port)]);
        }
        let mut receiver = self.cached_or_pending(host.to_ascii_lowercase().into_boxed_str())?;
        let outcome = match receiver.wait_for(Option::is_some).await {
            Ok(outcome) => outcome.clone(),
            Err(_) => None,
        };
        match outcome {
            Some(outcome) => outcome.addresses(port),
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
            Some(entry) if entry.expires_at > now => {
                return Ok(watch::channel(Some(entry.outcome.clone())).1);
            }
            Some(_) => {
                state.entries.remove(&host);
            }
            None => {}
        }
        // A resolution whose task ended without an answer, as when its
        // runtime shut down, has dropped its sender and is started again.
        match state.pending.get(&host) {
            Some(receiver) if receiver.has_changed().is_ok() => return Ok(receiver.clone()),
            Some(_) => {
                state.pending.remove(&host);
            }
            None => {}
        }
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| io::Error::other("an address lookup needs a Tokio runtime"))?;
        let (sender, receiver) = watch::channel(None);
        let generation = state.generation;
        state.pending.insert(host.clone(), receiver.clone());
        drop(state);

        let cache = self.clone();
        let resolution = (self.inner.lookup)(host.clone());
        drop(runtime.spawn(async move {
            let outcome = Outcome::from_result(resolution.await);
            cache.complete(host, generation, &outcome);
            let _ = sender.send(Some(outcome));
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
        let ttl = match outcome {
            Outcome::Resolved(_) => Some(self.inner.settings.ttl),
            Outcome::Failed { .. } => self.inner.settings.negative_ttl,
        };
        let now = Instant::now();
        let Some(expires_at) = ttl
            .filter(|ttl| !ttl.is_zero())
            .map(|ttl| now.checked_add(ttl).unwrap_or(now))
        else {
            return;
        };
        if !state.entries.contains_key(&host)
            && state.entries.len() >= self.inner.settings.max_entries.get()
        {
            state.entries.retain(|_, entry| entry.expires_at > now);
            while state.entries.len() >= self.inner.settings.max_entries.get() {
                let Some(soonest) = state
                    .entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.expires_at)
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

impl fmt::Debug for AddressCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AddressCache")
            .field("settings", &self.inner.settings)
            .field("entries", &self.len())
            .finish_non_exhaustive()
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
