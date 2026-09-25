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
//! Memory is bounded per cache, so a client's total is bounded by the number
//! of caches it keeps: one per pool entry, which its pool already caps.
//! Locks are held only for in-memory lookup and insertion, never across I/O.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use btls::ssl::SslSession;

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
#[derive(Clone)]
pub(crate) struct ResumptionTicket {
    pub(crate) session: SslSession,
    pub(crate) peer_transport_parameters: Option<Box<[u8]>>,
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
