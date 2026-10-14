//! Credential-owned nonce sessions, partitioned by proxy and TLS settings.

use std::sync::{Arc, Mutex, PoisonError};

use super::{DigestAuthError, DigestChallenge, DigestPolicy, DigestSession, HttpDigestCredentials};
use crate::proxy::{ProxyScheme, http2_pool::ConnectionSettingsId};

const MAX_DIGEST_SESSIONS: usize = 128;

#[derive(Clone, Eq, PartialEq)]
pub(in crate::proxy) struct DigestCacheKey {
    scheme: ProxyScheme,
    host: Box<str>,
    port: u16,
    settings: Option<ConnectionSettingsId>,
    server_name: Option<Box<str>>,
    policy: DigestPolicy,
}

impl DigestCacheKey {
    pub(in crate::proxy) fn new(
        scheme: ProxyScheme,
        host: &str,
        port: u16,
        settings: Option<&ConnectionSettingsId>,
        policy: DigestPolicy,
    ) -> Self {
        Self {
            scheme,
            host: host.to_ascii_lowercase().into(),
            port,
            settings: settings.cloned(),
            server_name: None,
            policy,
        }
    }

    pub(in crate::proxy) fn with_server_name(mut self, name: &str) -> Self {
        self.server_name = Some(name.to_ascii_lowercase().into());
        self
    }
}

#[derive(Clone, Default)]
pub(super) struct DigestCache(Arc<Mutex<Vec<Entry>>>);

struct Entry {
    key: DigestCacheKey,
    session: Arc<DigestSession>,
    accepted: bool,
}

impl HttpDigestCredentials {
    pub(in crate::proxy) fn remembered(&self, key: &DigestCacheKey) -> Option<Arc<DigestSession>> {
        let mut entries = self.cache.0.lock().unwrap_or_else(PoisonError::into_inner);
        let index = entries
            .iter()
            .rposition(|entry| entry.key == *key && entry.accepted)?;
        let entry = entries.remove(index);
        let session = Arc::clone(&entry.session);
        entries.push(entry);
        Some(session)
    }

    /// Pending sessions share counts too. Two simultaneous challenges with the
    /// same nonce must not each start at one with the same client nonce.
    pub(in crate::proxy) fn challenged(
        &self,
        key: &DigestCacheKey,
        challenge: DigestChallenge,
    ) -> Result<Arc<DigestSession>, DigestAuthError> {
        // Random generation and hashing happen outside the cache lock.
        let session = Arc::new(DigestSession::new(challenge, self)?);
        let mut entries = self.cache.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(index) = entries.iter().position(|entry| {
            entry.key == *key
                && entry.session.challenge.realm == session.challenge.realm
                && entry.session.challenge.nonce == session.challenge.nonce
                && entry.session.challenge.opaque == session.challenge.opaque
                && entry.session.challenge.algorithm == session.challenge.algorithm
                && entry.session.challenge.userhash == session.challenge.userhash
        }) {
            let entry = entries.remove(index);
            let existing = Arc::clone(&entry.session);
            entries.push(entry);
            return Ok(existing);
        }
        if entries.len() == MAX_DIGEST_SESSIONS {
            entries.remove(0);
        }
        entries.push(Entry {
            key: key.clone(),
            session: Arc::clone(&session),
            accepted: false,
        });
        Ok(session)
    }

    pub(in crate::proxy) fn accept(
        &self,
        key: &DigestCacheKey,
        session: &Arc<DigestSession>,
        nextnonce: Option<Box<[u8]>>,
    ) -> Result<(), DigestAuthError> {
        let replacement = nextnonce
            .map(|nonce| {
                let mut challenge = session.challenge.clone();
                challenge.nonce = nonce;
                challenge.stale = false;
                DigestSession::new(challenge, self).map(Arc::new)
            })
            .transpose()?;
        let mut entries = self.cache.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(index) = entries
            .iter()
            .position(|entry| entry.key == *key && Arc::ptr_eq(&entry.session, session))
        {
            let mut entry = entries.remove(index);
            if let Some(replacement) = replacement {
                entry.session = replacement;
            }
            entry.accepted = true;
            entries.retain(|other| other.key != *key);
            entries.push(entry);
        }
        // A delayed response cannot resurrect an evicted or replaced nonce.
        Ok(())
    }

    pub(in crate::proxy) fn forget(&self, key: &DigestCacheKey, session: &Arc<DigestSession>) {
        self.cache
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|entry| entry.key != *key || !Arc::ptr_eq(&entry.session, session));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn challenge(nonce: &str) -> Result<DigestChallenge, DigestAuthError> {
        let value = format!("Digest realm=proxy, nonce={nonce}, qop=auth, algorithm=SHA-256");
        DigestChallenge::select(
            [value.as_bytes()],
            &HttpDigestCredentials::new("user", "password")?,
        )
    }

    #[test]
    fn only_accepted_sessions_are_preemptive_and_credentials_clones_share_counts() -> TestResult {
        let credentials = HttpDigestCredentials::new("user", "password")?;
        let key = DigestCacheKey::new(ProxyScheme::Http, "proxy", 80, None, credentials.policy());
        let first = credentials.challenged(&key, challenge("first")?)?;
        assert!(credentials.remembered(&key).is_none());
        let clone = credentials.clone();
        let second = clone.challenged(&key, challenge("first")?)?;
        assert!(Arc::ptr_eq(&first, &second));
        let first_request = first.request(&http::Method::CONNECT, "origin:443")?;
        let second_request = second.request(&http::Method::CONNECT, "other:443")?;
        assert_eq!(first_request.nonce_count, "00000001");
        assert_eq!(second_request.nonce_count, "00000002");
        credentials.accept(&key, &first, None)?;
        assert!(clone.remembered(&key).is_some());
        assert!(
            HttpDigestCredentials::new("user", "password")?
                .remembered(&key)
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn proxy_scheme_port_host_and_tls_settings_partition_sessions() -> TestResult {
        let credentials = HttpDigestCredentials::new("user", "password")?;
        let settings = ConnectionSettingsId::default();
        let key = DigestCacheKey::new(
            ProxyScheme::Https,
            "PROXY",
            443,
            Some(&settings),
            credentials.policy(),
        );
        let session = credentials.challenged(&key, challenge("first")?)?;
        credentials.accept(&key, &session, None)?;
        let equivalent = DigestCacheKey::new(
            ProxyScheme::Https,
            "proxy",
            443,
            Some(&settings.clone()),
            credentials.policy(),
        );
        assert!(credentials.remembered(&equivalent).is_some());
        for key in [
            DigestCacheKey::new(ProxyScheme::Http, "proxy", 443, None, credentials.policy()),
            DigestCacheKey::new(
                ProxyScheme::Https,
                "other",
                443,
                Some(&settings),
                credentials.policy(),
            ),
            DigestCacheKey::new(
                ProxyScheme::Https,
                "proxy",
                8443,
                Some(&settings),
                credentials.policy(),
            ),
            DigestCacheKey::new(
                ProxyScheme::Https,
                "proxy",
                443,
                Some(&ConnectionSettingsId::default()),
                credentials.policy(),
            ),
            DigestCacheKey::new(
                ProxyScheme::Https,
                "proxy",
                443,
                Some(&settings),
                DigestPolicy::AllowLegacyMd5,
            ),
        ] {
            assert!(credentials.remembered(&key).is_none());
        }
        Ok(())
    }

    #[test]
    fn old_response_cannot_replace_nextnonce_or_resurrect_a_rejected_session() -> TestResult {
        let credentials = HttpDigestCredentials::new("user", "password")?;
        let key = DigestCacheKey::new(ProxyScheme::Http, "proxy", 80, None, credentials.policy());
        let old = credentials.challenged(&key, challenge("old")?)?;
        credentials.accept(&key, &old, Some(Box::from(&b"new"[..])))?;
        credentials.accept(&key, &old, Some(Box::from(&b"late"[..])))?;
        credentials.forget(&key, &old);
        let current = credentials.remembered(&key).ok_or("missing replacement")?;
        assert_eq!(&*current.challenge.nonce, b"new");
        credentials.forget(&key, &current);
        credentials.accept(&key, &current, None)?;
        assert!(credentials.remembered(&key).is_none());
        Ok(())
    }

    #[test]
    fn tls_server_identity_partitions_accepted_nonces() -> TestResult {
        let credentials = HttpDigestCredentials::new("user", "password")?;
        let settings = ConnectionSettingsId::default();
        let key = DigestCacheKey::new(
            ProxyScheme::Https,
            "proxy",
            443,
            Some(&settings),
            credentials.policy(),
        )
        .with_server_name("FIRST.example");
        let session = credentials.challenged(&key, challenge("first")?)?;
        credentials.accept(&key, &session, None)?;
        let equivalent = DigestCacheKey::new(
            ProxyScheme::Https,
            "PROXY",
            443,
            Some(&settings),
            credentials.policy(),
        )
        .with_server_name("first.example");
        assert!(credentials.remembered(&equivalent).is_some());
        for other in ["second.example", "proxy"] {
            let other = DigestCacheKey::new(
                ProxyScheme::Https,
                "proxy",
                443,
                Some(&settings),
                credentials.policy(),
            )
            .with_server_name(other);
            assert!(credentials.remembered(&other).is_none());
        }
        Ok(())
    }

    #[test]
    fn accepting_a_new_challenge_retires_other_nonces_in_the_same_scope() -> TestResult {
        let credentials = HttpDigestCredentials::new("user", "password")?;
        let key = DigestCacheKey::new(ProxyScheme::Http, "proxy", 80, None, credentials.policy());
        let old = credentials.challenged(&key, challenge("old")?)?;
        let new = credentials.challenged(&key, challenge("new")?)?;
        credentials.accept(&key, &new, None)?;
        credentials.accept(&key, &old, None)?;
        let current = credentials.remembered(&key).ok_or("missing new nonce")?;
        assert!(Arc::ptr_eq(&current, &new));
        old.request(&http::Method::CONNECT, "origin:443")?;
        Ok(())
    }

    #[test]
    fn cache_is_bounded_and_eviction_does_not_invalidate_an_open_exchange() -> TestResult {
        let credentials = HttpDigestCredentials::new("user", "password")?;
        let key = DigestCacheKey::new(ProxyScheme::Http, "first", 80, None, credentials.policy());
        let held = credentials.challenged(&key, challenge("first")?)?;
        credentials.accept(&key, &held, None)?;
        for index in 0..MAX_DIGEST_SESSIONS {
            let key = DigestCacheKey::new(
                ProxyScheme::Http,
                &format!("proxy{index}"),
                80,
                None,
                credentials.policy(),
            );
            credentials.challenged(&key, challenge("nonce")?)?;
        }
        assert!(credentials.remembered(&key).is_none());
        assert_eq!(
            credentials
                .cache
                .0
                .lock()
                .map_err(|_| "poisoned cache")?
                .len(),
            MAX_DIGEST_SESSIONS
        );
        held.request(&http::Method::CONNECT, "origin:443")?;
        credentials.accept(&key, &held, None)?;
        assert!(credentials.remembered(&key).is_none());
        Ok(())
    }
}
