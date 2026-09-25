//! Client-side retention of TLS 1.3 session tickets for QUIC resumption.
//!
//! A [`SessionCache`] belongs to exactly one [`crate::QuicClientConfig`] and
//! therefore to one BoringSSL context. Callers isolate tickets by giving each
//! pool key its own configuration clone with a fresh cache, as Phantom's TCP
//! connectors do with their TLS session caches. A ticket is stored only after
//! the connection that received it authenticated the peer, and is presented
//! only for the same verified server name.
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
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use btls::ssl::SslSession;

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
    sessions: VecDeque<CachedSession>,
    /// The latest round-trip time per server name, least recently recorded
    /// first, bounded like the tickets.
    round_trip_times: VecDeque<(Box<str>, Duration)>,
}

/// A resumable session and the verified name of the peer that issued it.
///
/// BoringSSL does not bind a client session to a hostname, so lookup selects
/// by the name that authenticated the original handshake.
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
    pub(crate) session: SslSession,
    pub(crate) peer_transport_parameters: Option<Box<[u8]>>,
    pub(crate) application_state: Option<Arc<[u8]>>,
}

/// One connection's application state for session resumption.
///
/// HTTP/3 uses it to remember the server's SETTINGS with each session ticket
/// (RFC 9114, section 7.2.4.2), as Chromium does. Give each connection its
/// own handle through [`crate::QuicClientConfig::with_application_state`]:
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
    cache: Option<(SessionCache, Box<str>)>,
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
    pub(crate) fn start(
        &self,
        cache: Option<(SessionCache, Box<str>)>,
        remembered: Option<Arc<[u8]>>,
    ) {
        let mut inner = self.lock();
        inner.cache = cache;
        inner.remembered = remembered;
    }

    /// Stores `ticket` with the recorded state, or holds it until the state
    /// is recorded.
    pub(crate) fn receive(&self, mut ticket: ResumptionTicket) {
        let mut inner = self.lock();
        if inner.refused {
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
    /// Stores a ticket issued by an authenticated peer for `server_name`.
    pub(crate) fn insert(&self, server_name: &str, ticket: ResumptionTicket) {
        let now = unix_time();
        if is_expired(&ticket.session, now) {
            return;
        }
        let mut state = self.state();
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

    /// Returns the most recent unexpired session for `server_name`.
    ///
    /// A session BoringSSL marks single-use is removed. Every TLS 1.3 session
    /// is single-use, to prevent correlation (RFC 8446, Appendix C.4), so for
    /// QUIC a lookup always consumes the ticket it returns.
    pub(crate) fn take(&self, server_name: &str) -> Option<ResumptionTicket> {
        let now = unix_time();
        let mut state = self.state();
        let sessions = &mut state.sessions;
        sessions.retain(|cached| !is_expired(&cached.ticket.session, now));
        let position = sessions
            .iter()
            .rposition(|cached| server_names_match(&cached.server_name, server_name))?;
        if sessions[position].ticket.session.should_be_single_use() {
            return sessions.remove(position).map(|cached| cached.ticket);
        }
        let cached = sessions.remove(position)?;
        let ticket = cached.ticket.clone();
        sessions.push_back(cached);
        Some(ticket)
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
fn is_expired(session: &SslSession, now: u64) -> bool {
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
    fn server_names_match_like_certificate_verification() {
        assert!(server_names_match("Example.TEST", "example.test"));
        assert!(server_names_match("::1", "0:0:0:0:0:0:0:1"));
        assert!(!server_names_match("example.test", "other.test"));
        assert!(!server_names_match("127.0.0.1", "localhost"));
    }
}
