use std::{fmt, sync::Arc};

use phantom_quic_btls::{
    FrozenQuicSessionTicketCache, QuicSessionTicketCache, QuicSessionTicketCacheOwner,
    QuicTicketGeneration, RetiredQuicTicketPublications,
};

use crate::tls::{
    FrozenTlsSessionCache, RetiredTlsTicketPublications, TlsSessionControl, TlsSessionOwner,
};

/// A weak control for one connector's TCP TLS or QUIC ticket cache.
///
/// Keeping this handle does not retain a connector or its tickets. It lets a
/// client clear caches that still belong to an evicted connection pool entry.
#[derive(Clone)]
pub struct SessionTicketCache {
    cache: Cache,
}

#[derive(Clone)]
enum Cache {
    Tcp(TlsSessionControl),
    Quic(QuicSessionTicketCache),
}

/// A temporary strong cache owner for a synchronous client transaction.
pub struct SessionTicketCacheOwner {
    cache: OwnedCache,
}

enum OwnedCache {
    Tcp(TlsSessionOwner),
    Quic(QuicSessionTicketCacheOwner),
}

/// Blocks cache takes and publication without holding a capture lock.
pub struct FrozenSessionTicketCache<'a> {
    cache: FrozenCache<'a>,
}

enum FrozenCache<'a> {
    Tcp(FrozenTlsSessionCache<'a>),
    Quic(FrozenQuicSessionTicketCache<'a>),
}

/// Fresh publication identities allocated before a transaction locks stores.
///
/// This value is consumed once and cannot be cloned or reused.
pub struct SessionTicketGeneration {
    tcp: Arc<()>,
    quic: QuicTicketGeneration,
}

impl Default for SessionTicketGeneration {
    fn default() -> Self {
        Self {
            tcp: Arc::new(()),
            quic: QuicTicketGeneration::default(),
        }
    }
}

/// Deferred cleanup that must run after every transaction store guard drops.
pub struct RetiredSessionTicketPublications {
    retained: usize,
    publications: RetiredPublications,
}

enum RetiredPublications {
    Tcp(RetiredTlsTicketPublications),
    Quic(RetiredQuicTicketPublications),
}

impl SessionTicketCache {
    /// Temporarily retain a live cache without changing the weak registry.
    #[must_use]
    pub fn upgrade(&self) -> Option<SessionTicketCacheOwner> {
        let cache = match &self.cache {
            Cache::Tcp(cache) => OwnedCache::Tcp(cache.upgrade()?),
            Cache::Quic(cache) => OwnedCache::Quic(cache.upgrade()?),
        };
        Some(SessionTicketCacheOwner { cache })
    }

    pub(crate) fn tcp(cache: TlsSessionControl) -> Self {
        Self {
            cache: Cache::Tcp(cache),
        }
    }

    pub(crate) fn quic(cache: QuicSessionTicketCache) -> Self {
        Self {
            cache: Cache::Quic(cache),
        }
    }

    /// Returns whether a connector or handshake still owns this cache.
    #[must_use]
    pub fn is_live(&self) -> bool {
        match &self.cache {
            Cache::Tcp(cache) => cache.is_live(),
            Cache::Quic(cache) => cache.is_live(),
        }
    }

    /// Removes retained tickets and retires older ticket publication.
    ///
    /// Existing connections keep working. Returns the number of retained
    /// tickets removed, excluding native handshake buffers. QUIC also forgets
    /// the RTTs retained with its tickets.
    #[must_use]
    pub fn clear(&self) -> usize {
        match &self.cache {
            Cache::Tcp(cache) => cache.clear(),
            Cache::Quic(cache) => cache.clear(),
        }
    }
}

impl SessionTicketCacheOwner {
    /// Compare identity only to avoid locking the same live store twice.
    #[must_use]
    pub fn same_cache(&self, other: &Self) -> bool {
        match (&self.cache, &other.cache) {
            (OwnedCache::Tcp(left), OwnedCache::Tcp(right)) => left.same_cache(right),
            (OwnedCache::Quic(left), OwnedCache::Quic(right)) => left.same_cache(right),
            _ => false,
        }
    }

    /// Freeze consumption and publication until the returned guard drops.
    #[must_use]
    pub fn freeze(&self) -> FrozenSessionTicketCache<'_> {
        let cache = match &self.cache {
            OwnedCache::Tcp(cache) => FrozenCache::Tcp(cache.freeze()),
            OwnedCache::Quic(cache) => FrozenCache::Quic(cache.freeze()),
        };
        FrozenSessionTicketCache { cache }
    }
}

impl FrozenSessionTicketCache<'_> {
    /// Drain retained state and retire older publication without allocating.
    ///
    /// Prepare the generation before locking stores. Finish the returned
    /// cleanup only after every store guard has dropped.
    #[must_use]
    pub fn drain(
        &mut self,
        generation: SessionTicketGeneration,
    ) -> RetiredSessionTicketPublications {
        let (retained, publications) = match &mut self.cache {
            FrozenCache::Tcp(cache) => (
                cache.retained_count(),
                RetiredPublications::Tcp(cache.drain(generation.tcp)),
            ),
            FrozenCache::Quic(cache) => (
                cache.retained_count(),
                RetiredPublications::Quic(cache.drain(generation.quic)),
            ),
        };
        RetiredSessionTicketPublications {
            retained,
            publications,
        }
    }
}

impl RetiredSessionTicketPublications {
    /// Drop pending or held tickets after all transaction guards are released.
    #[must_use]
    pub fn finish(self) -> usize {
        self.retained
            + match self.publications {
                RetiredPublications::Tcp(publications) => publications.finish(),
                RetiredPublications::Quic(publications) => publications.finish(),
            }
    }
}

impl fmt::Debug for SessionTicketCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionTicketCache")
            .field("live", &self.is_live())
            .finish()
    }
}

impl fmt::Debug for SessionTicketCacheOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionTicketCacheOwner")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for FrozenSessionTicketCache<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenSessionTicketCache")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for SessionTicketGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionTicketGeneration")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for RetiredSessionTicketPublications {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetiredSessionTicketPublications")
            .finish_non_exhaustive()
    }
}
