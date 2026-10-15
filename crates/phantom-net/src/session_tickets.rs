pub(crate) mod tcp_transfer;

pub use tcp_transfer::{
    PreparedTcpSessionReplacement, RetiredTcpSessionReplacements, TcpSessionExportRecord,
    TcpSessionRecordMetadata, TcpSessionStoreExport, TcpSessionStoreHeader,
};

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
    /// Clears distinct TCP and QUIC stores at one frozen-store boundary.
    ///
    /// Aliases are cleared once. TCP stores lock before QUIC stores, each in
    /// its actual owner's private order. Unlike transfer, clear has no owner
    /// count limit and accepts stores without an installed transfer binding.
    /// All allocation precedes locks; retirement runs after every guard drops.
    ///
    /// # Errors
    /// Returns an allocation failure before changing any store.
    pub fn clear_stores(owners: &[Self]) -> Result<usize, btls::ssl::SessionTransferError> {
        let order = Self::clear_order(owners)?;
        let mut generations = tcp_transfer::reserved(order.len())?;
        let mut guards = tcp_transfer::reserved(order.len())?;
        let mut retired = tcp_transfer::reserved(order.len())?;
        for _ in &order {
            generations.push(SessionTicketGeneration::default());
        }
        for index in order {
            guards.push(owners[index].freeze());
        }
        for (guard, generation) in guards.iter_mut().zip(generations) {
            retired.push(guard.drain(generation));
        }
        drop(guards);
        Ok(retired
            .into_iter()
            .map(RetiredSessionTicketPublications::finish)
            .sum())
    }

    fn clear_order(owners: &[Self]) -> Result<Vec<usize>, btls::ssl::SessionTransferError> {
        let mut tcp = tcp_transfer::reserved(owners.len())?;
        let mut quic = tcp_transfer::reserved(owners.len())?;
        let mut tcp_indices = tcp_transfer::reserved(owners.len())?;
        let mut quic_indices = tcp_transfer::reserved(owners.len())?;
        for (index, owner) in owners.iter().enumerate() {
            match &owner.cache {
                OwnedCache::Tcp(cache) => {
                    if !tcp
                        .iter()
                        .any(|other: &&TlsSessionOwner| other.same_cache(cache))
                    {
                        tcp.push(cache);
                        tcp_indices.push(index);
                    }
                }
                OwnedCache::Quic(cache) => {
                    if !quic
                        .iter()
                        .any(|other: &&QuicSessionTicketCacheOwner| other.same_cache(cache))
                    {
                        quic.push(cache);
                        quic_indices.push(index);
                    }
                }
            }
        }
        let tcp_order = TlsSessionOwner::ordered_store_indices(&tcp)?;
        let quic_order = QuicSessionTicketCacheOwner::ordered_store_indices(&quic)?;
        let mut order = tcp_transfer::reserved(tcp.len() + quic.len())?;
        order.extend(tcp_order.into_iter().map(|index| tcp_indices[index]));
        order.extend(quic_order.into_iter().map(|index| quic_indices[index]));
        Ok(order)
    }

    /// Capture distinct TCP stores without serializing while their locks are held.
    /// The caller authenticates every store header and record-slot mapping.
    /// QUIC, duplicate stores or an unbound cache return a policy error.
    pub fn capture_tcp_stores(
        inputs: &[(&Self, &str)],
    ) -> Result<Vec<TcpSessionStoreExport>, btls::ssl::SessionTransferError> {
        if inputs.len() > tcp_transfer::MAX_OWNERS {
            return Err(btls::ssl::SessionTransferError::TooLarge);
        }
        let mut tcp = tcp_transfer::reserved(inputs.len())?;
        for (owner, hostname) in inputs {
            let OwnedCache::Tcp(cache) = &owner.cache else {
                return Err(btls::ssl::SessionTransferError::Policy);
            };
            tcp.push((cache, *hostname));
        }
        TlsSessionOwner::capture_stores(&tcp)
    }

    /// Privately consume native-authorized permits before transaction locking.
    /// Authenticate the complete manifest and validate source witnesses before
    /// native authorization. Metadata alone never authorizes a session.
    pub fn prepare_tcp_replacement(
        &self,
        hostname: Arc<str>,
        header: TcpSessionStoreHeader,
        permits: Vec<btls::ssl::SessionImportPermit>,
    ) -> Result<PreparedTcpSessionReplacement, btls::ssl::SessionTransferError> {
        match &self.cache {
            OwnedCache::Tcp(cache) => cache
                .prepare_replacement(hostname, header, permits)
                .map(PreparedTcpSessionReplacement),
            OwnedCache::Quic(_) => Err(btls::ssl::SessionTransferError::Policy),
        }
    }

    /// Validate every destination before replacing any store, without allocation
    /// under frozen stores. Finish cleanup only after this function returns.
    pub fn replace_tcp_stores(
        replacements: Vec<PreparedTcpSessionReplacement>,
    ) -> Result<RetiredTcpSessionReplacements, btls::ssl::SessionTransferError> {
        if replacements.len() > tcp_transfer::MAX_OWNERS {
            return Err(btls::ssl::SessionTransferError::TooLarge);
        }
        let mut tcp = tcp_transfer::reserved(replacements.len())?;
        for replacement in replacements {
            tcp.push(replacement.0);
        }
        TlsSessionOwner::replace_stores(tcp).map(RetiredTcpSessionReplacements)
    }

    /// Installs native transfer policy on this live TCP cache before its first use.
    ///
    /// The cache supplies its actual TLS context and application scope. Repeating
    /// an equal installation is allowed. A QUIC owner or a first installation
    /// after a handshake starts returns a policy error. These policy bytes do
    /// not establish peer authentication or authorize imported sessions.
    ///
    /// # Errors
    /// Returns the native policy, allocation or configuration failure.
    pub fn bind_tcp_transfer_policy(
        &self,
        server_name: &str,
        policy: btls::ssl::SessionTransferPolicy,
    ) -> Result<btls::ssl::SessionPolicyBinding, btls::ssl::SessionTransferError> {
        match &self.cache {
            OwnedCache::Tcp(cache) => cache.bind_transfer_policy(server_name, policy),
            OwnedCache::Quic(_) => Err(btls::ssl::SessionTransferError::Policy),
        }
    }

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

#[cfg(test)]
mod tests;
