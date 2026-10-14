//! Client-side retention of TLS 1.3 session tickets for QUIC resumption.
//!
//! A [`SessionCache`] belongs to exactly one [`crate::QuicClientConfig`] and
//! therefore to one BoringSSL context. Callers isolate tickets by giving each
//! pool key its own configuration clone with a fresh cache, as Phantom's TCP
//! connectors do with their TLS session caches. A ticket is stored only after
//! the connection completed its configured authentication policy, and is
//! presented only for the same server name. Debugging or custom verification
//! can retain local tickets without providing authenticated publication proof.
//!
//! The cache also keeps the round-trip time last measured to each server
//! name, which a resumed connection advertises as `initial_rtt_us` when its
//! transport profile includes that parameter. It follows the same isolation.
//!
//! A connection given an [`ApplicationState`] stores application state, such
//! as the server's HTTP/3 SETTINGS, with each ticket it receives, and holds
//! its tickets until that state is known. A later connection that offers
//! early data with one of those tickets reads the state back.
//!
//! Memory is bounded per cache, so a client's total is bounded by the number
//! of caches it keeps: one per pool entry, which its pool already caps.
//! Locks are held only for in-memory lookup and insertion, never across I/O.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use btls::ssl::{ScopedSslSession, SslSessionScope};

use crate::QuicVersion;

/// Largest application state stored with a ticket, in bytes.
///
/// HTTP/3 stores the server's SETTINGS frame, which the vendored engine keeps
/// to at most eight known settings, far below this bound.
pub(crate) const MAX_APPLICATION_STATE_LEN: usize = 1024;

/// Tickets one connection holds while its application state is unknown,
/// matching the two a Chromium client handshaker holds.
pub(crate) const MAX_HELD_TICKETS: usize = 2;

/// Tickets retained per cache; the least recently stored is evicted first.
///
/// A cache serves one origin and route, and a presented ticket is consumed,
/// so a few tickets cover concurrent connection setup. Eviction only costs a
/// later full handshake.
pub(crate) const MAX_SESSIONS: usize = 4;

#[derive(Clone, Default)]
pub(crate) struct SessionCache {
    state: Arc<Mutex<CacheState>>,
}

#[derive(Default)]
struct CacheState {
    scope: SslSessionScope,
    sessions: VecDeque<CachedSession>,
    /// The latest round-trip time per server name, least recently recorded
    /// first, bounded like the tickets.
    round_trip_times: VecDeque<(Box<str>, Duration)>,
    generation: Arc<()>,
    application_states: Vec<Weak<Mutex<ApplicationStateInner>>>,
}

/// A weak handle for clearing one configuration's retained QUIC tickets.
///
/// The handle does not retain the configuration. Clearing also removes its
/// remembered RTTs and prevents older handshakes from publishing tickets.
#[derive(Clone)]
pub struct QuicSessionTicketCache {
    state: Weak<Mutex<CacheState>>,
}

/// A temporary strong owner used while a client freezes its ticket stores.
pub struct QuicSessionTicketCacheOwner {
    state: Arc<Mutex<CacheState>>,
}

/// A synchronous guard that blocks ticket consumption and publication.
pub struct FrozenQuicSessionTicketCache<'a> {
    state: MutexGuard<'a, CacheState>,
}

/// Deferred held-ticket retirement, completed after all store guards drop.
pub struct RetiredQuicTicketPublications {
    generation: Arc<()>,
    application_states: Vec<Weak<Mutex<ApplicationStateInner>>>,
}

/// A fresh, single-use publication identity prepared before stores lock.
pub struct QuicTicketGeneration(Arc<()>);

impl Default for QuicTicketGeneration {
    fn default() -> Self {
        Self(Arc::new(()))
    }
}

impl QuicSessionTicketCache {
    /// Returns whether the configuration or a handshake still owns the cache.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.state.strong_count() != 0
    }

    /// Clears retained tickets and retires pending ticket publication.
    ///
    /// Existing connections keep working. Returns the number of retained
    /// tickets removed, excluding native handshake buffers.
    #[must_use]
    pub fn clear(&self) -> usize {
        let Some(owner) = self.upgrade() else {
            return 0;
        };
        let generation = QuicTicketGeneration::default();
        let mut frozen = owner.freeze();
        let count = frozen.state.sessions.len();
        let retired = frozen.drain(generation);
        drop(frozen);
        count + retired.finish()
    }

    /// Temporarily retain a live cache for a bounded synchronous transaction.
    #[must_use]
    pub fn upgrade(&self) -> Option<QuicSessionTicketCacheOwner> {
        self.state
            .upgrade()
            .map(|state| QuicSessionTicketCacheOwner { state })
    }
}

impl QuicSessionTicketCacheOwner {
    /// Compare live cache identity solely to avoid locking it twice.
    #[must_use]
    pub fn same_cache(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }

    /// Block consumption and publication until the guard drops.
    #[must_use]
    pub fn freeze(&self) -> FrozenQuicSessionTicketCache<'_> {
        FrozenQuicSessionTicketCache {
            state: self.state.lock().unwrap_or_else(PoisonError::into_inner),
        }
    }
}

impl FrozenQuicSessionTicketCache<'_> {
    /// Count locally retained sessions in this locked store.
    #[must_use]
    pub fn retained_count(&self) -> usize {
        self.state.sessions.len()
    }

    /// Drain tickets and retire old publication with a preallocated token.
    ///
    /// Finish the returned retirement only after every transaction store
    /// guard has dropped. Dropping this guard before draining changes nothing.
    #[must_use]
    pub fn drain(&mut self, generation: QuicTicketGeneration) -> RetiredQuicTicketPublications {
        self.state.sessions.clear();
        self.state.round_trip_times.clear();
        RetiredQuicTicketPublications {
            generation: std::mem::replace(&mut self.state.generation, generation.0),
            application_states: std::mem::take(&mut self.state.application_states),
        }
    }
}

impl RetiredQuicTicketPublications {
    /// Release held tickets without acquiring any ticket-store guard.
    #[must_use]
    pub fn finish(self) -> usize {
        let mut count = 0;
        for inner in self
            .application_states
            .into_iter()
            .filter_map(|inner| inner.upgrade())
        {
            let mut inner = inner.lock().unwrap_or_else(PoisonError::into_inner);
            if inner
                .cache
                .as_ref()
                .is_some_and(|(cache, _)| Arc::ptr_eq(&cache.generation, &self.generation))
            {
                count += inner.held.len();
                inner.held.clear();
                inner.cache = None;
                inner.refused = true;
            }
        }
        count
    }
}

impl std::fmt::Debug for QuicSessionTicketCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QuicSessionTicketCache")
            .field("live", &self.is_live())
            .finish()
    }
}

impl std::fmt::Debug for QuicSessionTicketCacheOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QuicSessionTicketCacheOwner")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for FrozenQuicSessionTicketCache<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FrozenQuicSessionTicketCache")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for QuicTicketGeneration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QuicTicketGeneration")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for RetiredQuicTicketPublications {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetiredQuicTicketPublications")
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub(crate) struct SessionCacheCapture {
    cache: SessionCache,
    generation: Arc<()>,
}

impl SessionCacheCapture {
    fn register_application_state(&self, inner: &Arc<Mutex<ApplicationStateInner>>) -> bool {
        let mut state = self.cache.state();
        if !Arc::ptr_eq(&state.generation, &self.generation) {
            return false;
        }
        state
            .application_states
            .retain(|inner| inner.strong_count() != 0);
        let control = Arc::downgrade(inner);
        if !state
            .application_states
            .iter()
            .any(|existing| existing.ptr_eq(&control))
        {
            state.application_states.push(control);
        }
        true
    }

    fn is_current(&self) -> bool {
        Arc::ptr_eq(&self.cache.state().generation, &self.generation)
    }

    pub(crate) fn insert(&self, server_name: &str, ticket: ResumptionTicket) {
        self.cache
            .insert_in_generation(server_name, ticket, &self.generation);
    }

    pub(crate) fn take_for_version(
        &self,
        server_name: &str,
        version: QuicVersion,
    ) -> Option<ResumptionTicket> {
        self.cache
            .take_in_generation(server_name, version, &self.generation)
    }

    pub(crate) fn round_trip_time(&self, server_name: &str) -> Option<Duration> {
        let state = self.cache.state();
        if !Arc::ptr_eq(&state.generation, &self.generation) {
            return None;
        }
        state
            .round_trip_times
            .iter()
            .rev()
            .find(|(name, _)| server_names_match(name, server_name))
            .map(|(_, rtt)| *rtt)
    }
}

/// A resumable session and the server name configured when it was issued.
///
/// BoringSSL does not bind a client session to a hostname, so lookup selects
/// by the name configured for the original handshake.
struct CachedSession {
    server_name: Box<str>,
    ticket: ResumptionTicket,
}

/// A session to present, with the transport parameters its issuer sent.
///
/// A client that sends 0-RTT data must apply the server's remembered
/// transport parameters to it (RFC 9000, section 7.4.1). BoringSSL keeps no
/// client copy, so they are stored beside the session.
///
/// The application state is what the issuing connection recorded through its
/// [`ApplicationState`], if it had one.
#[derive(Clone)]
pub(crate) struct ResumptionTicket {
    pub(crate) session: Arc<ScopedSslSession>,
    /// The QUIC version of the connection that received the ticket.
    pub(crate) version: QuicVersion,
    pub(crate) peer_transport_parameters: Option<Box<[u8]>>,
    pub(crate) application_state: Option<Arc<[u8]>>,
}

/// One connection's application state for session resumption.
///
/// HTTP/3 uses it to remember the server's SETTINGS with each session ticket
/// (RFC 9114, section 7.2.4.2), as Chromium does. Give each connection a
/// handle through [`crate::QuicClientConfig::with_application_state`]. A
/// handle serves the connection started most recently with it: starting
/// another resets it, and tickets an earlier connection still receives are
/// dropped rather than stored with the later connection's state.
///
/// - When the connection presents a ticket and offers early data,
///   [`Self::remembered`] returns the state stored with that ticket.
/// - Tickets the connection receives are held until [`Self::store`] records
///   the state to keep with them, then stored in the configuration's ticket
///   cache with it. At most two tickets are held; a connection that never
///   records its state stores none of its tickets.
///
/// The state follows the ticket cache's isolation: it is stored only with
/// tickets in that cache, and read back only by a connection that presents
/// one of them for the same verified server name.
#[derive(Clone, Default)]
pub struct ApplicationState {
    inner: Arc<Mutex<ApplicationStateInner>>,
}

#[derive(Default)]
struct ApplicationStateInner {
    /// The state stored with the ticket presented for early data.
    remembered: Option<Arc<[u8]>>,
    /// The state to keep with tickets this connection receives.
    stored: Option<Arc<[u8]>>,
    /// Set when the state was too large to keep; later tickets are dropped.
    refused: bool,
    held: VecDeque<ResumptionTicket>,
    cache: Option<(SessionCacheCapture, Box<str>)>,
    /// Only callbacks from the latest connection may publish tickets.
    generation: Arc<()>,
}

impl ApplicationState {
    /// Returns an empty handle for one new connection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the application state stored with the ticket this connection
    /// presented, when the connection offers early data with it.
    #[must_use]
    pub fn remembered(&self) -> Option<Arc<[u8]>> {
        self.lock().remembered.clone()
    }

    /// Records the state to keep with every ticket this connection receives,
    /// and stores the tickets held until now.
    ///
    /// Only the first call has an effect. State longer than 1024 bytes is
    /// not kept, and neither is any ticket from this connection. Returns
    /// whether the state was recorded.
    #[must_use = "check whether the application state was recorded"]
    pub fn store(&self, state: &[u8]) -> bool {
        let mut inner = self.lock();
        if inner.stored.is_some() || inner.refused {
            return false;
        }
        if state.len() > MAX_APPLICATION_STATE_LEN {
            inner.refused = true;
            inner.held.clear();
            return false;
        }
        let state: Arc<[u8]> = Arc::from(state);
        inner.stored = Some(Arc::clone(&state));
        let held = std::mem::take(&mut inner.held);
        if let Some((cache, server_name)) = &inner.cache {
            for mut ticket in held {
                ticket.application_state = Some(Arc::clone(&state));
                cache.insert(server_name, ticket);
            }
        }
        true
    }

    /// Binds the handle to the connection that `start_session` begins.
    ///
    /// Everything left from an earlier connection is dropped, so a reused
    /// handle never stores that connection's state or tickets with the new
    /// connection's.
    /// Returns the generation that the connection passes to
    /// [`Self::receive`].
    pub(crate) fn start_capture(
        &self,
        cache: Option<(SessionCacheCapture, Box<str>)>,
        remembered: Option<Arc<[u8]>>,
    ) -> Arc<()> {
        let mut inner = self.lock();
        let generation = Arc::new(());
        let refused = cache
            .as_ref()
            .is_some_and(|(cache, _)| !cache.register_application_state(&self.inner));
        *inner = ApplicationStateInner {
            remembered,
            cache,
            refused,
            generation: Arc::clone(&generation),
            ..ApplicationStateInner::default()
        };
        generation
    }

    #[cfg(test)]
    pub(crate) fn start(
        &self,
        cache: Option<(SessionCache, Box<str>)>,
        remembered: Option<Arc<[u8]>>,
    ) -> Arc<()> {
        self.start_capture(
            cache.map(|(cache, name)| (cache.capture(), name)),
            remembered,
        )
    }

    /// Stores `ticket` with the recorded state, or holds it until the state
    /// is recorded. A ticket from a connection other than the latest one
    /// started with this handle is dropped.
    pub(crate) fn receive(&self, generation: &Arc<()>, mut ticket: ResumptionTicket) {
        let mut inner = self.lock();
        if inner.refused || !Arc::ptr_eq(&inner.generation, generation) {
            return;
        }
        if inner
            .cache
            .as_ref()
            .is_some_and(|(cache, _)| !cache.is_current())
        {
            inner.held.clear();
            inner.refused = true;
            return;
        }
        if let Some(state) = inner.stored.clone() {
            ticket.application_state = Some(state);
            if let Some((cache, server_name)) = &inner.cache {
                cache.insert(server_name, ticket);
            }
            return;
        }
        if inner.held.len() == MAX_HELD_TICKETS {
            inner.held.pop_front();
        }
        inner.held.push_back(ticket);
    }

    #[cfg(test)]
    pub(crate) fn held_len(&self) -> usize {
        self.lock().held.len()
    }

    #[cfg(test)]
    pub(crate) fn generation(&self) -> Arc<()> {
        Arc::clone(&self.lock().generation)
    }

    fn lock(&self) -> MutexGuard<'_, ApplicationStateInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl std::fmt::Debug for ApplicationState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.lock();
        formatter
            .debug_struct("ApplicationState")
            .field(
                "remembered_len",
                &inner.remembered.as_ref().map(|state| state.len()),
            )
            .field(
                "stored_len",
                &inner.stored.as_ref().map(|state| state.len()),
            )
            .field("held_tickets", &inner.held.len())
            .finish()
    }
}

impl SessionCache {
    pub(crate) fn capture(&self) -> SessionCacheCapture {
        SessionCacheCapture {
            cache: self.clone(),
            generation: Arc::clone(&self.state().generation),
        }
    }

    pub(crate) fn control(&self) -> QuicSessionTicketCache {
        QuicSessionTicketCache {
            state: Arc::downgrade(&self.state),
        }
    }

    /// Stores a ticket issued by an authenticated peer for `server_name`.
    #[cfg(test)]
    pub(crate) fn insert(&self, server_name: &str, ticket: ResumptionTicket) {
        self.capture().insert(server_name, ticket);
    }

    fn insert_in_generation(
        &self,
        server_name: &str,
        ticket: ResumptionTicket,
        generation: &Arc<()>,
    ) {
        let now = unix_time();
        if is_expired(&ticket.session, now) {
            return;
        }
        let mut state = self.state();
        if !Arc::ptr_eq(&state.generation, generation) {
            return;
        }
        let sessions = &mut state.sessions;
        sessions.retain(|cached| !is_expired(&cached.ticket.session, now));
        if sessions.len() == MAX_SESSIONS {
            sessions.pop_front();
        }
        sessions.push_back(CachedSession {
            server_name: server_name.into(),
            ticket,
        });
    }

    /// Takes a ticket that a QUIC v1 connection received.
    #[cfg(test)]
    pub(crate) fn take(&self, server_name: &str) -> Option<ResumptionTicket> {
        self.take_for_version(server_name, QuicVersion::V1)
    }

    /// Returns the most recent unexpired session for `server_name` that a
    /// connection in `version` received.
    ///
    /// A ticket from a connection in another QUIC version is not presented
    /// (RFC 9369 section 3.4). A session BoringSSL marks single-use is
    /// removed. Every TLS 1.3 session is single-use, to prevent correlation
    /// (RFC 8446, Appendix C.4), so for QUIC a lookup always consumes the
    /// ticket it returns.
    #[cfg(test)]
    pub(crate) fn take_for_version(
        &self,
        server_name: &str,
        version: QuicVersion,
    ) -> Option<ResumptionTicket> {
        self.capture().take_for_version(server_name, version)
    }

    fn take_in_generation(
        &self,
        server_name: &str,
        version: QuicVersion,
        generation: &Arc<()>,
    ) -> Option<ResumptionTicket> {
        let now = unix_time();
        let mut state = self.state();
        if !Arc::ptr_eq(&state.generation, generation) {
            return None;
        }
        let sessions = &mut state.sessions;
        sessions.retain(|cached| !is_expired(&cached.ticket.session, now));
        let position = sessions.iter().rposition(|cached| {
            cached.ticket.version == version && server_names_match(&cached.server_name, server_name)
        })?;
        if sessions[position].ticket.session.should_be_single_use() {
            return sessions.remove(position).map(|cached| cached.ticket);
        }
        let cached = sessions.remove(position)?;
        let ticket = cached.ticket.clone();
        sessions.push_back(cached);
        Some(ticket)
    }

    /// Returns the QUIC version of the connection that received the newest
    /// unexpired session for `server_name`.
    pub(crate) fn version(&self, server_name: &str) -> Option<QuicVersion> {
        let now = unix_time();
        let state = self.state();
        state
            .sessions
            .iter()
            .rev()
            .filter(|cached| !is_expired(&cached.ticket.session, now))
            .find(|cached| server_names_match(&cached.server_name, server_name))
            .map(|cached| cached.ticket.version)
    }

    /// Returns whether an unexpired session for `server_name` is retained.
    pub(crate) fn contains(&self, server_name: &str) -> bool {
        let now = unix_time();
        let mut state = self.state();
        let sessions = &mut state.sessions;
        sessions.retain(|cached| !is_expired(&cached.ticket.session, now));
        sessions
            .iter()
            .any(|cached| server_names_match(&cached.server_name, server_name))
    }

    /// Records the round-trip time a connection to `server_name` measured,
    /// replacing any earlier value for that name.
    pub(crate) fn record_round_trip_time(&self, server_name: &str, rtt: Duration) {
        let mut state = self.state();
        let times = &mut state.round_trip_times;
        times.retain(|(name, _)| !server_names_match(name, server_name));
        if times.len() == MAX_SESSIONS {
            times.pop_front();
        }
        times.push_back((server_name.into(), rtt));
    }

    /// Returns the round-trip time last recorded for `server_name`.
    #[cfg(test)]
    pub(crate) fn round_trip_time(&self, server_name: &str) -> Option<Duration> {
        self.state()
            .round_trip_times
            .iter()
            .rev()
            .find(|(name, _)| server_names_match(name, server_name))
            .map(|(_, rtt)| *rtt)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.state().sessions.len()
    }

    #[cfg(test)]
    pub(crate) fn shares_storage_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }

    fn state(&self) -> MutexGuard<'_, CacheState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn scope(&self) -> SslSessionScope {
        self.state().scope.clone()
    }
}

/// IP literals compare as addresses and DNS names ASCII case-insensitively,
/// matching how certificate verification treats the same name.
fn server_names_match(established: &str, requested: &str) -> bool {
    match (
        established.parse::<std::net::IpAddr>(),
        requested.parse::<std::net::IpAddr>(),
    ) {
        (Ok(established), Ok(requested)) => established == requested,
        (Err(_), Err(_)) => established.eq_ignore_ascii_case(requested),
        _ => false,
    }
}

/// A session expires at its establishment time plus its lifetime, which
/// BoringSSL has already capped by the server's `ticket_lifetime`.
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
    use std::time::Duration;

    use super::{MAX_SESSIONS, SessionCache, server_names_match};

    #[test]
    fn round_trip_times_keep_the_latest_value_per_server_name() {
        let cache = SessionCache::default();
        assert_eq!(cache.round_trip_time("example.test"), None);
        cache.record_round_trip_time("example.test", Duration::from_millis(40));
        cache.record_round_trip_time("EXAMPLE.test", Duration::from_millis(3));
        assert_eq!(
            cache.round_trip_time("example.test"),
            Some(Duration::from_millis(3))
        );

        for index in 0..MAX_SESSIONS {
            cache.record_round_trip_time(&format!("{index}.test"), Duration::from_millis(1));
        }
        assert_eq!(cache.round_trip_time("example.test"), None);
        assert_eq!(
            cache.clone().round_trip_time("0.test"),
            Some(Duration::from_millis(1))
        );
    }

    #[test]
    fn weak_cache_controls_do_not_retain_the_cache_and_clear_rtts() {
        let cache = SessionCache::default();
        let control = cache.control();
        let old = cache.capture();
        cache.record_round_trip_time("example.test", Duration::from_millis(5));
        assert_eq!(
            old.round_trip_time("example.test"),
            Some(Duration::from_millis(5))
        );
        assert_eq!(control.clear(), 0);
        assert_eq!(cache.round_trip_time("example.test"), None);
        cache.record_round_trip_time("example.test", Duration::from_millis(9));
        assert_eq!(old.round_trip_time("example.test"), None);
        assert_eq!(
            cache.capture().round_trip_time("example.test"),
            Some(Duration::from_millis(9))
        );
        drop(old);
        drop(cache);
        assert!(!control.is_live());
        assert_eq!(control.clear(), 0);
    }

    #[test]
    fn reusing_application_state_keeps_one_weak_registration() {
        let cache = SessionCache::default();
        let state = super::ApplicationState::new();
        for _ in 0..100 {
            state.start(Some((cache.clone(), Box::from("example.test"))), None);
        }
        assert_eq!(cache.state().application_states.len(), 1);
        drop(state);
        let state = super::ApplicationState::new();
        state.start(Some((cache.clone(), Box::from("example.test"))), None);
        assert_eq!(cache.state().application_states.len(), 1);
        assert_eq!(cache.control().clear(), 0);
        assert!(cache.state().application_states.is_empty());
    }

    #[test]
    fn dropping_a_frozen_store_preserves_rtts_and_publication() {
        let cache = SessionCache::default();
        let control = cache.control();
        let capture = cache.capture();
        cache.record_round_trip_time("example.test", Duration::from_millis(5));
        let owner = control
            .upgrade()
            .unwrap_or_else(|| panic!("live test cache missing"));
        let same = control
            .upgrade()
            .unwrap_or_else(|| panic!("live test cache missing"));
        let other = SessionCache::default();
        let other = other
            .control()
            .upgrade()
            .unwrap_or_else(|| panic!("live test cache missing"));
        assert!(owner.same_cache(&same));
        assert!(!owner.same_cache(&other));
        let frozen = owner.freeze();
        assert_eq!(frozen.retained_count(), 0);
        drop(frozen);
        assert_eq!(
            capture.round_trip_time("example.test"),
            Some(Duration::from_millis(5))
        );
        drop(cache);
        drop(capture);
        drop(same);
        assert!(control.is_live());
        drop(owner);
        assert!(!control.is_live());
    }

    #[test]
    fn server_names_match_like_certificate_verification() {
        assert!(server_names_match("Example.TEST", "example.test"));
        assert!(server_names_match("::1", "0:0:0:0:0:0:0:1"));
        assert!(!server_names_match("example.test", "other.test"));
        assert!(!server_names_match("127.0.0.1", "localhost"));
    }
}
