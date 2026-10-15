mod transfer;

pub(crate) use transfer::{PreparedTlsSessionReplacement, RetiredTlsSessionReplacements};

use std::{
    cmp::Reverse,
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::{SystemTime, UNIX_EPOCH},
};

use btls::{
    error::ErrorStack,
    ssl::{
        ScopedSslSession, SessionPolicyBinding, SessionTransferError, SessionTransferPolicy,
        SslContext, SslSessionScope,
    },
};
use phantom_profile::SessionTicketOrder;
use tracing::debug;

/// Bounds the whole cache, and so the per-hostname bound, which
/// `phantom-profile` validates up to the same number.
const MAX_SESSIONS: usize = 10;

#[derive(Clone)]
pub(super) struct TlsSessionCache {
    inner: Arc<CacheInner>,
}

/// Holds newly issued sessions until the handshake authenticates the peer.
#[derive(Clone)]
pub(super) struct TlsSessionCapture {
    cache: TlsSessionCache,
    hostname: Arc<str>,
    state: Arc<Mutex<CaptureState>>,
    generation: Arc<()>,
    transfer_binding: Option<SessionPolicyBinding>,
}

#[derive(Default)]
struct CaptureState {
    authenticated: bool,
    retired: bool,
    pending: Vec<ScopedSslSession>,
    /// The connection's batch, assigned when its first session is stored.
    batch: Option<u64>,
    next_sequence: u32,
}

struct CacheInner {
    context: SslContext,
    scope: SslSessionScope,
    /// The profile's TCP session-ticket limit, applied per verified
    /// hostname within this cache, whatever the port. The `phantom` client
    /// makes one cache per origin and route, so there it bounds one origin.
    per_hostname: usize,
    order: TicketOrder,
    store: Mutex<Store>,
}

#[derive(Default)]
struct Store {
    started: bool,
    transfer_binding: Option<SessionPolicyBinding>,
    /// Sessions in the order they were stored.
    sessions: VecDeque<CachedSession>,
    next_batch: u64,
    /// A clear retires this token while outstanding handshakes retain it.
    generation: Arc<()>,
    captures: Vec<Weak<Mutex<CaptureState>>>,
}

/// A weak handle that clears a cache without keeping its connector alive.
#[derive(Clone)]
pub(crate) struct TlsSessionControl {
    inner: Weak<CacheInner>,
}

pub(crate) struct TlsSessionOwner {
    inner: Arc<CacheInner>,
}

pub(crate) struct FrozenTlsSessionCache<'a> {
    store: MutexGuard<'a, Store>,
}

pub(crate) struct RetiredTlsTicketPublications {
    captures: Vec<Weak<Mutex<CaptureState>>>,
}

impl TlsSessionControl {
    pub(crate) fn is_live(&self) -> bool {
        self.inner.strong_count() != 0
    }

    pub(crate) fn clear(&self) -> usize {
        let Some(owner) = self.upgrade() else {
            return 0;
        };
        let generation = Arc::new(());
        let mut frozen = owner.freeze();
        let count = frozen.store.sessions.len();
        let retired = frozen.drain(generation);
        drop(frozen);
        count + retired.finish()
    }

    pub(crate) fn upgrade(&self) -> Option<TlsSessionOwner> {
        self.inner.upgrade().map(|inner| TlsSessionOwner { inner })
    }
}

impl TlsSessionOwner {
    /// Original indices in private actual-store lock order, with no transfer bound.
    /// Reject aliases before any locks; this operation grants no ticket authority.
    ///
    /// # Errors
    /// Returns allocation failure or a policy error for duplicate stores.
    pub(crate) fn ordered_store_indices(
        owners: &[&Self],
    ) -> Result<Vec<usize>, SessionTransferError> {
        let mut order = Vec::new();
        order
            .try_reserve_exact(owners.len())
            .map_err(|_| SessionTransferError::Allocation)?;
        order.extend(0..owners.len());
        order.sort_unstable_by_key(|index| Arc::as_ptr(&owners[*index].inner) as usize);
        if order
            .windows(2)
            .any(|pair| owners[pair[0]].same_cache(owners[pair[1]]))
        {
            return Err(SessionTransferError::Policy);
        }
        Ok(order)
    }

    pub(crate) fn bind_transfer_policy(
        &self,
        server_name: &str,
        policy: SessionTransferPolicy,
    ) -> Result<SessionPolicyBinding, SessionTransferError> {
        let mut store = self
            .inner
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if store.started && store.transfer_binding.is_none() {
            return Err(SessionTransferError::Policy);
        }
        let binding =
            self.inner
                .scope
                .bind_transfer_policy(&self.inner.context, server_name, policy)?;
        store.transfer_binding = Some(binding.clone());
        Ok(binding)
    }

    pub(crate) fn same_cache(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    pub(crate) fn freeze(&self) -> FrozenTlsSessionCache<'_> {
        FrozenTlsSessionCache {
            store: self
                .inner
                .store
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        }
    }
}

impl FrozenTlsSessionCache<'_> {
    pub(crate) fn retained_count(&self) -> usize {
        self.store.sessions.len()
    }

    /// Retire publication under the store lock; finish only after every
    /// transaction store guard has been released.
    pub(crate) fn drain(&mut self, generation: Arc<()>) -> RetiredTlsTicketPublications {
        self.store.sessions.clear();
        self.store.generation = generation;
        self.store.next_batch = 0;
        RetiredTlsTicketPublications {
            captures: std::mem::take(&mut self.store.captures),
        }
    }
}

impl RetiredTlsTicketPublications {
    pub(crate) fn finish(self) -> usize {
        let mut count = 0;
        // Callbacks lock their capture before the store. Transaction store
        // guards must all be released before taking any capture lock.
        for capture in self
            .captures
            .into_iter()
            .filter_map(|capture| capture.upgrade())
        {
            let mut capture = capture
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            count += capture.pending.len();
            capture.pending.clear();
            capture.retired = true;
        }
        count
    }
}

/// A session with the verified hostname that authenticated it.
///
/// The TLS backend attaches a session only for its own hostname, so lookup
/// must select by hostname rather than recency.
struct CachedSession {
    hostname: Arc<str>,
    session: ScopedSslSession,
    arrival: Arrival,
}

/// The connector's `TlsSettings::session_ticket_order`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TicketOrder {
    Newest,
    OldestConnection,
    Oldest,
}

impl TicketOrder {
    /// Returns `None` for an order this cache does not implement.
    pub(super) const fn from_profile(order: SessionTicketOrder) -> Option<Self> {
        match order {
            SessionTicketOrder::NewestFirst => Some(Self::Newest),
            SessionTicketOrder::OldestConnectionFirst => Some(Self::OldestConnection),
            SessionTicketOrder::OldestFirst => Some(Self::Oldest),
            _ => None,
        }
    }
}

/// When a session was stored: `batch` numbers connections in the order
/// their first session was stored, and `sequence` numbers a connection's
/// sessions in the order they were stored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Arrival {
    batch: u64,
    sequence: u32,
}

impl TlsSessionCache {
    pub(super) fn new(per_hostname: u8, order: TicketOrder, context: SslContext) -> Self {
        Self {
            inner: Arc::new(CacheInner {
                context,
                scope: SslSessionScope::default(),
                per_hostname: usize::from(per_hostname).clamp(1, MAX_SESSIONS),
                order,
                store: Mutex::default(),
            }),
        }
    }

    pub(super) fn begin_handshake(&self, hostname: &str) -> TlsSessionCapture {
        let state = Arc::default();
        let mut store = self.store();
        store.started = true;
        store.captures.retain(|capture| capture.strong_count() != 0);
        store.captures.push(Arc::downgrade(&state));
        TlsSessionCapture {
            cache: self.clone(),
            hostname: hostname.into(),
            state,
            generation: Arc::clone(&store.generation),
            transfer_binding: store.transfer_binding.clone(),
        }
    }

    pub(super) fn control(&self) -> TlsSessionControl {
        TlsSessionControl {
            inner: Arc::downgrade(&self.inner),
        }
    }

    /// Stores `session` as number `sequence` of `batch`, or as the first
    /// session of a new batch, and returns its batch.
    fn insert(
        &self,
        hostname: Arc<str>,
        session: ScopedSslSession,
        batch: Option<u64>,
        sequence: u32,
        generation: &Arc<()>,
    ) -> Option<u64> {
        let now = unix_time();
        let mut store = self.store();
        if !Arc::ptr_eq(&store.generation, generation) {
            return None;
        }
        let batch = if let Some(batch) = batch {
            batch
        } else {
            let batch = store.next_batch;
            // Do not wrap connection order or panic if this cache outlives
            // the counter. Clearing the cache starts a fresh generation.
            store.next_batch = batch.checked_add(1)?;
            batch
        };
        let sessions = &mut store.sessions;
        prune_expired(sessions, now);
        let stored = sessions
            .iter()
            .filter(|cached| hostnames_match(&cached.hostname, &hostname))
            .count();
        if stored >= self.inner.per_hostname
            && let Some(evicted) =
                eviction_position(self.inner.order, arrivals_for(sessions, &hostname))
        {
            sessions.remove(evicted);
        } else if sessions.len() == MAX_SESSIONS {
            sessions.pop_front();
        }
        sessions.push_back(CachedSession {
            hostname,
            session,
            arrival: Arrival { batch, sequence },
        });
        Some(batch)
    }

    /// Removes the unexpired session for `hostname` that the cache's order
    /// presents next.
    #[cfg(test)]
    pub(super) fn take(&self, hostname: &str) -> Option<ScopedSslSession> {
        let generation = Arc::clone(&self.store().generation);
        self.take_in_generation(hostname, &generation)
    }

    fn take_in_generation(&self, hostname: &str, generation: &Arc<()>) -> Option<ScopedSslSession> {
        let now = unix_time();
        let mut store = self.store();
        if !Arc::ptr_eq(&store.generation, generation) {
            return None;
        }
        store.started = true;
        let sessions = &mut store.sessions;
        prune_expired(sessions, now);
        let position = next_position(self.inner.order, arrivals_for(sessions, hostname))?;
        sessions.remove(position).map(|cached| cached.session)
    }

    /// Removes every session for `hostname`.
    pub(super) fn forget(&self, hostname: &str) {
        self.store()
            .sessions
            .retain(|cached| !hostnames_match(&cached.hostname, hostname));
    }

    /// Stores again a reusable session that a connection resumed without
    /// receiving a new one, as the only session of a new batch.
    #[cfg(test)]
    pub(super) fn restore(&self, hostname: &str, session: ScopedSslSession) {
        self.begin_handshake(hostname).restore(session);
    }

    pub(super) fn scope(&self) -> &SslSessionScope {
        &self.inner.scope
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.store().sessions.len()
    }

    fn store(&self) -> MutexGuard<'_, Store> {
        self.inner
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl TlsSessionCapture {
    pub(super) fn transfer_binding(&self) -> Option<&SessionPolicyBinding> {
        self.transfer_binding.as_ref()
    }

    pub(super) fn take_session(&self) -> Option<ScopedSslSession> {
        self.cache
            .take_in_generation(&self.hostname, &self.generation)
    }

    pub(super) fn restore(&self, session: ScopedSslSession) {
        self.cache.insert(
            Arc::clone(&self.hostname),
            session,
            None,
            0,
            &self.generation,
        );
    }

    pub(super) fn capture(&self, session: Result<ScopedSslSession, ErrorStack>) {
        let session = match session {
            Ok(session) => session,
            Err(error) => {
                debug!(error = %error, "TLS session ticket discarded");
                return;
            }
        };

        let mut state = self.state();
        if state.retired {
            return;
        }
        if state.authenticated {
            self.store(&mut state, session);
        } else {
            if state.pending.len() == MAX_SESSIONS {
                state.pending.remove(0);
            }
            state.pending.push(session);
        }
    }

    pub(super) fn commit_authenticated(&self) -> usize {
        let mut state = self.state();
        if state.retired {
            return 0;
        }
        state.authenticated = true;
        let pending = std::mem::take(&mut state.pending);
        let mut count = 0;
        for session in pending {
            count += usize::from(self.store(&mut state, session));
        }
        count
    }

    /// Stores `session` as this connection's next session. The capture's
    /// lock is held across the cache's, never the reverse, so a connection's
    /// sessions keep their order.
    fn store(&self, state: &mut CaptureState, session: ScopedSslSession) -> bool {
        let Some(batch) = self.cache.insert(
            Arc::clone(&self.hostname),
            session,
            state.batch,
            state.next_sequence,
            &self.generation,
        ) else {
            return false;
        };
        state.batch = Some(batch);
        state.next_sequence = state.next_sequence.saturating_add(1);
        true
    }

    fn state(&self) -> MutexGuard<'_, CaptureState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The position and arrival of each session stored for `hostname`, in the
/// order they were stored.
fn arrivals_for<'a>(
    sessions: &'a VecDeque<CachedSession>,
    hostname: &'a str,
) -> impl Iterator<Item = (usize, Arrival)> + 'a {
    sessions
        .iter()
        .enumerate()
        .filter(move |(_, cached)| hostnames_match(&cached.hostname, hostname))
        .map(|(position, cached)| (position, cached.arrival))
}

/// Returns the position of the session `order` presents next, from one
/// hostname's sessions in the order they were stored. `OldestFirst` takes
/// the first stored, as Firefox does when no two tickets share a clock
/// value.
fn next_position(
    order: TicketOrder,
    mut arrivals: impl Iterator<Item = (usize, Arrival)>,
) -> Option<usize> {
    match order {
        TicketOrder::Newest => arrivals.last().map(|(position, _)| position),
        TicketOrder::OldestConnection => arrivals
            .min_by_key(|(_, arrival)| (arrival.batch, Reverse(arrival.sequence)))
            .map(|(position, _)| position),
        TicketOrder::Oldest => arrivals.next().map(|(position, _)| position),
    }
}

/// Returns the position of the session that storing one more evicts from a
/// full hostname: the oldest for `NewestFirst`, and for the Firefox orders
/// the one `next_position` presents, as Firefox evicts the record it would
/// offer.
fn eviction_position(
    order: TicketOrder,
    mut arrivals: impl Iterator<Item = (usize, Arrival)>,
) -> Option<usize> {
    match order {
        TicketOrder::Newest => arrivals.next().map(|(position, _)| position),
        TicketOrder::OldestConnection | TicketOrder::Oldest => next_position(order, arrivals),
    }
}

fn prune_expired(sessions: &mut VecDeque<CachedSession>, now: u64) {
    sessions.retain(|cached| !is_expired(&cached.session, now));
}

/// Mirrors the TLS backend's session hostname binding: IP literals compare as
/// addresses and DNS names compare ASCII case-insensitively.
fn hostnames_match(established: &str, requested: &str) -> bool {
    match (
        established.parse::<std::net::IpAddr>(),
        requested.parse::<std::net::IpAddr>(),
    ) {
        (Ok(established), Ok(requested)) => established == requested,
        (Err(_), Err(_)) => established.eq_ignore_ascii_case(requested),
        _ => false,
    }
}

fn is_expired(session: &ScopedSslSession, now: u64) -> bool {
    session
        .time()
        .checked_add(u64::from(session.timeout()))
        .is_none_or(|expires_at| expires_at <= now)
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    mod clear;
    mod transaction;

    use super::{TicketOrder, TlsSessionCache};

    fn context() -> Result<btls::ssl::SslContext, btls::error::ErrorStack> {
        Ok(btls::ssl::SslContextBuilder::new(btls::ssl::SslMethod::tls())?.build())
    }

    #[test]
    fn weak_control_does_not_retain_an_evicted_cache() -> Result<(), btls::error::ErrorStack> {
        let cache = TlsSessionCache::new(2, TicketOrder::Newest, context()?);
        let control = cache.control();
        let capture = cache.begin_handshake("example.test");
        drop(cache);
        assert!(control.is_live());
        assert_eq!(control.clear(), 0);
        assert!(capture.state().retired);
        drop(capture);
        assert!(!control.is_live());
        assert_eq!(control.clear(), 0);
        Ok(())
    }

    #[test]
    fn clear_retires_old_captures_and_prunes_cancelled_handshakes()
    -> Result<(), btls::error::ErrorStack> {
        let cache = TlsSessionCache::new(2, TicketOrder::OldestConnection, context()?);
        for _ in 0..100 {
            drop(cache.begin_handshake("example.test"));
        }
        let old = cache.begin_handshake("example.test");
        assert_eq!(cache.store().captures.len(), 1);
        assert_eq!(cache.control().clear(), 0);
        assert!(old.state().retired);
        assert!(cache.store().captures.is_empty());
        let fresh = cache.begin_handshake("example.test");
        assert!(!fresh.state().retired);
        assert!(!std::sync::Arc::ptr_eq(&old.generation, &fresh.generation));
        assert_eq!(cache.store().captures.len(), 1);
        Ok(())
    }

    #[test]
    fn dropping_a_frozen_store_preserves_publication_and_owned_identity()
    -> Result<(), btls::error::ErrorStack> {
        let cache = TlsSessionCache::new(2, TicketOrder::Newest, context()?);
        let control = cache.control();
        let capture = cache.begin_handshake("example.test");
        let owner = control
            .upgrade()
            .unwrap_or_else(|| panic!("live test cache missing"));
        let same = control
            .upgrade()
            .unwrap_or_else(|| panic!("live test cache missing"));
        let other = TlsSessionCache::new(2, TicketOrder::Newest, context()?);
        let other = other
            .control()
            .upgrade()
            .unwrap_or_else(|| panic!("live test cache missing"));
        assert!(owner.same_cache(&same));
        assert!(!owner.same_cache(&other));
        let frozen = owner.freeze();
        assert_eq!(frozen.retained_count(), 0);
        drop(frozen);
        assert!(std::sync::Arc::ptr_eq(
            &cache.store().generation,
            &capture.generation
        ));
        assert!(!capture.state().retired);
        drop(cache);
        drop(capture);
        drop(same);
        assert!(control.is_live());
        drop(owner);
        assert!(!control.is_live());
        Ok(())
    }
}
