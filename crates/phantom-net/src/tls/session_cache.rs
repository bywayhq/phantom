use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

use btls::{
    error::ErrorStack,
    ssl::{ScopedSslSession, SslSessionScope},
};
use tracing::debug;

const MAX_SESSIONS: usize = 8;

#[derive(Clone, Default)]
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
}

#[derive(Default)]
struct CacheInner {
    scope: SslSessionScope,
    sessions: Mutex<VecDeque<CachedSession>>,
}

/// A session with the verified hostname that authenticated it.
///
/// The TLS backend attaches a session only for its own hostname, so lookup
/// must select by hostname rather than recency.
struct CachedSession {
    hostname: Arc<str>,
    session: ScopedSslSession,
}

impl TlsSessionCache {
    pub(super) fn begin_handshake(&self, hostname: &str) -> TlsSessionCapture {
        TlsSessionCapture {
            cache: self.clone(),
            hostname: hostname.into(),
            state: Arc::default(),
        }
    }

    fn insert(&self, hostname: Arc<str>, session: ScopedSslSession) {
        let now = unix_time();
        let mut sessions = self.sessions();
        prune_expired(&mut sessions, now);
        if sessions.len() == MAX_SESSIONS {
            sessions.pop_front();
        }
        sessions.push_back(CachedSession { hostname, session });
    }

    /// Removes the most recent unexpired session for `hostname`.
    pub(super) fn take(&self, hostname: &str) -> Option<ScopedSslSession> {
        let now = unix_time();
        let mut sessions = self.sessions();
        prune_expired(&mut sessions, now);
        let position = sessions
            .iter()
            .rposition(|cached| hostnames_match(&cached.hostname, hostname))?;
        sessions.remove(position).map(|cached| cached.session)
    }

    pub(super) fn restore(&self, hostname: &str, session: ScopedSslSession) {
        self.insert(hostname.into(), session);
    }

    pub(super) fn scope(&self) -> &SslSessionScope {
        &self.inner.scope
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.sessions().len()
    }

    fn sessions(&self) -> MutexGuard<'_, VecDeque<CachedSession>> {
        self.inner
            .sessions
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

        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.authenticated {
            drop(state);
            self.cache.insert(Arc::clone(&self.hostname), session);
        } else {
            state.pending.push(session);
        }
    }

    pub(super) fn commit_authenticated(&self) -> usize {
        let pending = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.authenticated = true;
            std::mem::take(&mut state.pending)
        };
        let count = pending.len();
        for session in pending {
            self.cache.insert(Arc::clone(&self.hostname), session);
        }
        count
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
