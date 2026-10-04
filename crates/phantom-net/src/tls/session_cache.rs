use std::{
    cmp::Reverse,
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

use btls::{
    error::ErrorStack,
    ssl::{ScopedSslSession, SslSessionScope},
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
}

#[derive(Default)]
struct CaptureState {
    authenticated: bool,
    pending: Vec<ScopedSslSession>,
    /// The connection's batch, assigned when its first session is stored.
    batch: Option<u64>,
    next_sequence: u32,
}

struct CacheInner {
    scope: SslSessionScope,
    /// `TlsSettings::session_tickets_per_origin`, applied per verified
    /// hostname within this cache, whatever the port. The `phantom` client
    /// makes one cache per origin and route, so there it bounds one origin.
    per_hostname: usize,
    order: TicketOrder,
    store: Mutex<Store>,
}

#[derive(Default)]
struct Store {
    /// Sessions in the order they were stored.
    sessions: VecDeque<CachedSession>,
    next_batch: u64,
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
    NewestFirst,
    OldestConnectionFirst,
    OldestFirst,
}

impl TicketOrder {
    /// Returns `None` for an order this cache does not implement.
    pub(super) const fn from_profile(order: SessionTicketOrder) -> Option<Self> {
        match order {
            SessionTicketOrder::NewestFirst => Some(Self::NewestFirst),
            SessionTicketOrder::OldestConnectionFirst => Some(Self::OldestConnectionFirst),
            SessionTicketOrder::OldestFirst => Some(Self::OldestFirst),
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
    pub(super) fn new(per_hostname: u8, order: TicketOrder) -> Self {
        Self {
            inner: Arc::new(CacheInner {
                scope: SslSessionScope::default(),
                per_hostname: usize::from(per_hostname).clamp(1, MAX_SESSIONS),
                order,
                store: Mutex::default(),
            }),
        }
    }

    pub(super) fn begin_handshake(&self, hostname: &str) -> TlsSessionCapture {
        TlsSessionCapture {
            cache: self.clone(),
            hostname: hostname.into(),
            state: Arc::default(),
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
    ) -> u64 {
        let now = unix_time();
        let mut store = self.store();
        let batch = batch.unwrap_or_else(|| {
            let batch = store.next_batch;
            store.next_batch += 1;
            batch
        });
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
        batch
    }

    /// Removes the unexpired session for `hostname` that the cache's order
    /// presents next.
    pub(super) fn take(&self, hostname: &str) -> Option<ScopedSslSession> {
        let now = unix_time();
        let mut store = self.store();
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
    pub(super) fn restore(&self, hostname: &str, session: ScopedSslSession) {
        self.insert(hostname.into(), session, None, 0);
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
    pub(super) fn capture(&self, session: Result<ScopedSslSession, ErrorStack>) {
        let session = match session {
            Ok(session) => session,
            Err(error) => {
                debug!(error = %error, "TLS session ticket discarded");
                return;
            }
        };

        let mut state = self.state();
        if state.authenticated {
            self.store(&mut state, session);
        } else {
            state.pending.push(session);
        }
    }

    pub(super) fn commit_authenticated(&self) -> usize {
        let mut state = self.state();
        state.authenticated = true;
        let pending = std::mem::take(&mut state.pending);
        let count = pending.len();
        for session in pending {
            self.store(&mut state, session);
        }
        count
    }

    /// Stores `session` as this connection's next session. The capture's
    /// lock is held across the cache's, never the reverse, so a connection's
    /// sessions keep their order.
    fn store(&self, state: &mut CaptureState, session: ScopedSslSession) {
        let batch = self.cache.insert(
            Arc::clone(&self.hostname),
            session,
            state.batch,
            state.next_sequence,
        );
        state.batch = Some(batch);
        state.next_sequence = state.next_sequence.saturating_add(1);
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
        TicketOrder::NewestFirst => arrivals.last().map(|(position, _)| position),
        TicketOrder::OldestConnectionFirst => arrivals
            .min_by_key(|(_, arrival)| (arrival.batch, Reverse(arrival.sequence)))
            .map(|(position, _)| position),
        TicketOrder::OldestFirst => arrivals.next().map(|(position, _)| position),
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
        TicketOrder::NewestFirst => arrivals.next().map(|(position, _)| position),
        TicketOrder::OldestConnectionFirst | TicketOrder::OldestFirst => {
            next_position(order, arrivals)
        }
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
