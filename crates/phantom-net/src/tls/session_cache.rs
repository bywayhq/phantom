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

#[derive(Default)]
struct CacheInner {
    scope: SslSessionScope,
    sessions: Mutex<VecDeque<ScopedSslSession>>,
}

impl TlsSessionCache {
    pub(super) fn capture(&self, session: Result<ScopedSslSession, ErrorStack>) {
        let session = match session {
            Ok(session) => session,
            Err(error) => {
                debug!(error = %error, "TLS session ticket discarded");
                return;
            }
        };
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
        let now = unix_time();
        let mut sessions = self.sessions();
        prune_expired(&mut sessions, now);
        if sessions.len() == MAX_SESSIONS {
            sessions.pop_front();
        }
        sessions.push_back(session);
    }

    pub(super) fn scope(&self) -> &SslSessionScope {
        &self.inner.scope
    }

    fn sessions(&self) -> MutexGuard<'_, VecDeque<ScopedSslSession>> {
        self.inner
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
