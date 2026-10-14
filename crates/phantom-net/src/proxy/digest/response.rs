//! Response proof ownership until the forwarded body is complete.

use std::{fmt, sync::Arc};

use http::{HeaderMap, HeaderValue};

use super::{
    DigestAuthError, DigestRequest, DigestSession, HttpDigestCredentials, cache::DigestCacheKey,
};

/// Verifies Digest proxy response headers and trailers without buffering data.
///
/// Dropping this guard before successful completion forgets only its matching
/// nonce session. It cannot remove a newer accepted nonce from another request.
pub struct DigestResponseAuthentication {
    credentials: HttpDigestCredentials,
    key: DigestCacheKey,
    session: Arc<DigestSession>,
    request: DigestRequest,
    head: Vec<HeaderValue>,
    nextnonce: Option<Box<[u8]>>,
    trailer_required: bool,
    trailers_seen: bool,
    completed: bool,
    failed: bool,
}

impl DigestResponseAuthentication {
    pub(super) fn new(
        credentials: &HttpDigestCredentials,
        key: &DigestCacheKey,
        session: Arc<DigestSession>,
        request: DigestRequest,
        headers: &HeaderMap,
    ) -> Result<Self, DigestAuthError> {
        let values = headers.get_all("proxy-authentication-info");
        if values.iter().count() > 32 {
            credentials.forget(key, &session);
            return Err(DigestAuthError::InvalidResponseAuthentication);
        }
        let nextnonce = match request.verify(values.iter().map(|value| value.as_bytes())) {
            Ok(nextnonce) => nextnonce,
            Err(error) => {
                credentials.forget(key, &session);
                return Err(error);
            }
        };
        let trailer_required = headers.get_all(http::header::TRAILER).iter().any(|value| {
            value.as_bytes().split(|&byte| byte == b',').any(|name| {
                name.trim_ascii()
                    .eq_ignore_ascii_case(b"proxy-authentication-info")
            })
        });
        Ok(Self {
            credentials: credentials.clone(),
            key: key.clone(),
            session,
            request,
            head: values.iter().cloned().collect(),
            nextnonce,
            trailer_required,
            trailers_seen: false,
            completed: false,
            failed: false,
        })
    }

    /// Checks a trailer frame together with the response-head parameters.
    ///
    /// # Errors
    /// Rejects malformed, conflicting or duplicate authentication parameters,
    /// an incorrect proof, or a second trailer frame.
    pub fn trailers(&mut self, headers: &HeaderMap) -> Result<(), DigestAuthError> {
        let result = self.verify_trailers(headers);
        if result.is_err() {
            self.failed = true;
            self.credentials.forget(&self.key, &self.session);
        }
        result
    }

    fn verify_trailers(&mut self, headers: &HeaderMap) -> Result<(), DigestAuthError> {
        if self.trailers_seen {
            return Err(DigestAuthError::InvalidResponseAuthentication);
        }
        let values = headers.get_all("proxy-authentication-info");
        if self.head.len().saturating_add(values.iter().count()) > 32 {
            return Err(DigestAuthError::InvalidResponseAuthentication);
        }
        if self.trailer_required && values.iter().next().is_none() {
            return Err(DigestAuthError::InvalidResponseAuthentication);
        }
        self.nextnonce = self.request.verify(
            self.head
                .iter()
                .chain(values.iter())
                .map(|value| value.as_bytes()),
        )?;
        self.trailers_seen = true;
        Ok(())
    }

    /// Publishes the verified nonce after the complete body has been consumed.
    ///
    /// # Errors
    /// Rejects an announced authentication trailer that never arrived, or a
    /// cryptographic failure when preparing `nextnonce`.
    pub fn finish(mut self) -> Result<(), DigestAuthError> {
        if self.failed || (self.trailer_required && !self.trailers_seen) {
            return Err(DigestAuthError::InvalidResponseAuthentication);
        }
        self.credentials
            .accept(&self.key, &self.session, self.nextnonce.take())?;
        self.completed = true;
        Ok(())
    }
}

impl Drop for DigestResponseAuthentication {
    fn drop(&mut self) {
        if !self.completed {
            self.credentials.forget(&self.key, &self.session);
        }
    }
}

impl fmt::Debug for DigestResponseAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DigestResponseAuthentication")
            .field("trailer_required", &self.trailer_required)
            .field("trailers_seen", &self.trailers_seen)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{
        ProxyScheme,
        digest::{DigestChallenge, tests::proxy_peer},
    };

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    fn pending(
        head: &HeaderMap,
    ) -> Result<
        (
            HttpDigestCredentials,
            DigestCacheKey,
            DigestResponseAuthentication,
            String,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let credentials = HttpDigestCredentials::new("user", "password")?;
        let key = DigestCacheKey::new(ProxyScheme::Http, "proxy", 8080, None, credentials.policy());
        let challenge = DigestChallenge::select(
            [proxy_peer::challenge("SHA-256", "first", false).as_bytes()],
            &credentials,
        )?;
        let session = credentials.challenged(&key, challenge)?;
        let request = session.request(&http::Method::GET, "http://origin/resource")?;
        let proof = proxy_peer::verify(
            std::str::from_utf8(request.header.value())?,
            "GET",
            "http://origin/resource",
            "SHA-256",
            "first",
        )?;
        let guard = DigestResponseAuthentication::new(&credentials, &key, session, request, head)?;
        Ok((credentials, key, guard, proof.information))
    }

    #[test]
    fn trailer_proof_and_nextnonce_are_published_only_at_body_completion() -> TestResult {
        let mut head = HeaderMap::new();
        head.insert(http::header::TRAILER, "Proxy-Authentication-Info".parse()?);
        let (credentials, key, mut guard, proof) = pending(&head)?;
        let mut trailers = HeaderMap::new();
        trailers.insert(
            "proxy-authentication-info",
            format!("{proof}, nextnonce=second").parse()?,
        );
        guard.trailers(&trailers)?;
        assert!(credentials.remembered(&key).is_none());
        guard.finish()?;
        let accepted = credentials.remembered(&key).ok_or("nonce missing")?;
        assert_eq!(&*accepted.challenge.nonce, b"second");
        Ok(())
    }

    #[test]
    fn missing_announced_trailer_partial_drop_and_bad_proof_never_accept_nonces() -> TestResult {
        let mut head = HeaderMap::new();
        head.insert(http::header::TRAILER, "proxy-authentication-info".parse()?);
        let (credentials, key, guard, _) = pending(&head)?;
        assert!(matches!(
            guard.finish(),
            Err(DigestAuthError::InvalidResponseAuthentication)
        ));
        assert!(credentials.remembered(&key).is_none());

        let (credentials, key, guard, _) = pending(&HeaderMap::new())?;
        drop(guard);
        assert!(credentials.remembered(&key).is_none());

        let (credentials, key, mut guard, proof) = pending(&head)?;
        let mut trailers = HeaderMap::new();
        trailers.insert(
            "proxy-authentication-info",
            proof.replacen("rspauth=\"", "rspauth=\"0", 1).parse()?,
        );
        assert!(matches!(
            guard.trailers(&trailers),
            Err(DigestAuthError::InvalidResponseAuthentication)
        ));
        assert!(matches!(
            guard.finish(),
            Err(DigestAuthError::InvalidResponseAuthentication)
        ));
        assert!(credentials.remembered(&key).is_none());
        Ok(())
    }

    #[test]
    fn head_and_trailer_parameters_cannot_duplicate_or_conflict() -> TestResult {
        let mut head = HeaderMap::new();
        head.insert("proxy-authentication-info", "nextnonce=second".parse()?);
        let (credentials, key, mut guard, _) = pending(&head)?;
        let mut trailers = HeaderMap::new();
        trailers.insert("proxy-authentication-info", "nextnonce=third".parse()?);
        assert!(matches!(
            guard.trailers(&trailers),
            Err(DigestAuthError::InvalidResponseAuthentication)
        ));
        assert!(matches!(
            guard.finish(),
            Err(DigestAuthError::InvalidResponseAuthentication)
        ));
        assert!(credentials.remembered(&key).is_none());
        Ok(())
    }
}
