//! Controls every TLS and QUIC cache owned by one client.

use std::sync::{Mutex, MutexGuard, PoisonError};

use phantom_net::SessionTicketCache;

/// Registered caches remain weak so evicted entries can release their tickets.
/// Dead registrations are removed on every registration and clear. The live
/// set follows pool entries plus evicted entries still used by a connection
/// or setup. No connection or setup is retained by this registry.
#[derive(Default)]
pub(super) struct TicketOwner {
    caches: Mutex<Vec<SessionTicketCache>>,
}

impl TicketOwner {
    /// Register before the connector is used. The registry lock serializes
    /// this with clear, so a new cache is either cleared or starts empty after
    /// it. Cache callbacks never acquire the owner lock.
    pub(super) fn register(&self, cache: Option<SessionTicketCache>) {
        let Some(cache) = cache else {
            return;
        };
        let mut caches = self.caches();
        caches.retain(SessionTicketCache::is_live);
        caches.push(cache);
    }

    pub(super) fn clear(&self) -> usize {
        let mut caches = self.caches();
        caches.retain(SessionTicketCache::is_live);
        caches.shrink_to_fit();
        caches.iter().map(SessionTicketCache::clear).sum()
    }

    fn caches(&self) -> MutexGuard<'_, Vec<SessionTicketCache>> {
        self.caches.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::TicketOwner;
    use phantom_net::http1::Http1TlsConnector;
    use phantom_profile::browser::chrome;

    #[test]
    fn dead_cache_controls_are_pruned_without_retaining_connectors() {
        let base = Http1TlsConnector::new(&chrome::v154_tcp_tls())
            .unwrap_or_else(|error| panic!("test connector failed: {error}"));
        let owner = TicketOwner::default();
        for _ in 0..100 {
            let connector = base.with_isolated_session_cache();
            owner.register(connector.session_ticket_cache());
        }
        assert_eq!(owner.caches().len(), 1);
        assert_eq!(owner.clear(), 0);
        assert!(owner.caches().is_empty());
        let connector = base.with_isolated_session_cache();
        owner.register(connector.session_ticket_cache());
        assert_eq!(owner.clear(), 0);
        assert_eq!(owner.caches().len(), 1);
        drop(connector);
        assert_eq!(owner.clear(), 0);
        assert!(owner.caches().is_empty());
    }
}
