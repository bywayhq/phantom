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
    sessions: Mutex<VecDeque<ScopedSslSession>>,
}

impl TlsSessionCache {
    pub(super) fn begin_handshake(&self) -> TlsSessionCapture {
        TlsSessionCapture {
            cache: self.clone(),
            state: Arc::default(),
        }
    }

    fn insert(&self, session: ScopedSslSession) {
        let now = unix_time();
        let mut sessions = self.sessions();
        prune_expired(&mut sessions, now);
        if sessions.len() == MAX_SESSIONS {
            sessions.pop_front();
        }
        sessions.push_back(session);
    }

    pub(super) fn take(&self) -> Option<ScopedSslSession> {
        let now = unix_time();
        let mut sessions = self.sessions();
        prune_expired(&mut sessions, now);
        sessions.pop_back()
    }

    pub(super) fn restore(&self, session: ScopedSslSession) {
        self.insert(session);
    }

    pub(super) fn scope(&self) -> &SslSessionScope {
        &self.inner.scope
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.sessions().len()
    }

    fn sessions(&self) -> MutexGuard<'_, VecDeque<ScopedSslSession>> {
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
            self.cache.insert(session);
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
            self.cache.insert(session);
        }
        count
    }
}

fn prune_expired(sessions: &mut VecDeque<ScopedSslSession>, now: u64) {
    sessions.retain(|session| !is_expired(session, now));
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
