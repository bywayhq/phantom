//! Client-side retention of TLS 1.3 session tickets for QUIC resumption.
//!
//! A [`SessionCache`] belongs to exactly one [`crate::QuicClientConfig`] and
//! therefore to one BoringSSL context. Callers isolate tickets by giving each
//! pool key its own configuration clone with a fresh cache, as Phantom's TCP
//! connectors do with their TLS session caches. A ticket is stored only after
//! the connection that received it authenticated the peer, and is presented
//! only for the same verified server name.
//!
//! Memory is bounded per cache, so a client's total is bounded by the number
//! of caches it keeps: one per pool entry, which its pool already caps.
//! Locks are held only for in-memory lookup and insertion, never across I/O.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use btls::ssl::SslSession;

/// Tickets retained per cache; the least recently stored is evicted first.
///
/// A cache serves one origin and route, and a presented ticket is consumed,
/// so a few tickets cover concurrent connection setup. Eviction only costs a
/// later full handshake.
pub(crate) const MAX_SESSIONS: usize = 4;

#[derive(Clone, Default)]
pub(crate) struct SessionCache {
    sessions: Arc<Mutex<VecDeque<CachedSession>>>,
}

/// A resumable session and the verified name of the peer that issued it.
///
/// BoringSSL does not bind a client session to a hostname, so lookup selects
/// by the name that authenticated the original handshake.
struct CachedSession {
    server_name: Box<str>,
    session: SslSession,
}

impl SessionCache {
    /// Stores a session issued by an authenticated peer for `server_name`.
    pub(crate) fn insert(&self, server_name: &str, session: SslSession) {
        let now = unix_time();
        if is_expired(&session, now) {
            return;
        }
        let mut sessions = self.sessions();
        sessions.retain(|cached| !is_expired(&cached.session, now));
        if sessions.len() == MAX_SESSIONS {
            sessions.pop_front();
        }
        sessions.push_back(CachedSession {
            server_name: server_name.into(),
            session,
        });
    }

    /// Returns the most recent unexpired session for `server_name`.
    ///
    /// A session BoringSSL marks single-use is removed. Every TLS 1.3 session
    /// is single-use, to prevent correlation (RFC 8446, Appendix C.4), so for
    /// QUIC a lookup always consumes the ticket it returns.
    pub(crate) fn take(&self, server_name: &str) -> Option<SslSession> {
        let now = unix_time();
        let mut sessions = self.sessions();
        sessions.retain(|cached| !is_expired(&cached.session, now));
        let position = sessions
            .iter()
            .rposition(|cached| server_names_match(&cached.server_name, server_name))?;
        if sessions[position].session.should_be_single_use() {
            return sessions.remove(position).map(|cached| cached.session);
        }
        let cached = sessions.remove(position)?;
        let session = cached.session.clone();
        sessions.push_back(cached);
        Some(session)
    }

    /// Returns whether an unexpired session for `server_name` is retained.
    pub(crate) fn contains(&self, server_name: &str) -> bool {
        let now = unix_time();
        let mut sessions = self.sessions();
        sessions.retain(|cached| !is_expired(&cached.session, now));
        sessions
            .iter()
            .any(|cached| server_names_match(&cached.server_name, server_name))
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.sessions().len()
    }

    #[cfg(test)]
    pub(crate) fn shares_storage_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.sessions, &other.sessions)
    }

    fn sessions(&self) -> MutexGuard<'_, VecDeque<CachedSession>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
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
    use super::server_names_match;

    #[test]
    fn server_names_match_like_certificate_verification() {
        assert!(server_names_match("Example.TEST", "example.test"));
        assert!(server_names_match("::1", "0:0:0:0:0:0:0:1"));
        assert!(!server_names_match("example.test", "other.test"));
        assert!(!server_names_match("127.0.0.1", "localhost"));
    }
}
