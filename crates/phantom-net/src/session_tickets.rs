use std::fmt;

use phantom_quic_btls::QuicSessionTicketCache;

use crate::tls::TlsSessionControl;

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

impl SessionTicketCache {
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

impl fmt::Debug for SessionTicketCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionTicketCache")
            .field("live", &self.is_live())
            .finish()
    }
}
