//! Digest state for one forwarded request, including its bounded challenges.

use std::{fmt, sync::Arc};

use http::{HeaderMap, Method};

use super::cache::DigestCacheKey;
use super::{
    DigestAuthError, DigestChallenge, DigestRequest, DigestSession, HttpDigestCredentials,
};
use crate::{proxy::ProxyScheme, request::RequestHeader, route::ProxyTransport};

/// Authentication state for one request forwarded through a Digest proxy.
///
/// Each authorization call consumes a unique nonce count, even if the attempt
/// is cancelled. Only a verified response makes its nonce available for later
/// requests. The caller owns connection reuse and request-body replay.
pub struct DigestForwardAuthentication<'a> {
    credentials: &'a HttpDigestCredentials,
    key: DigestCacheKey,
    session: Option<Arc<DigestSession>>,
    request: Option<DigestRequest>,
    stale_retried: bool,
}

impl<'a> DigestForwardAuthentication<'a> {
    /// Starts a request in the supplied proxy and TLS authentication scope.
    /// `preemptive` allows reuse of a nonce previously accepted in this scope.
    #[must_use]
    pub fn new(
        credentials: &'a HttpDigestCredentials,
        proxy: ProxyTransport<'_>,
        preemptive: bool,
    ) -> Self {
        let key = match proxy {
            ProxyTransport::Tcp(endpoint) => DigestCacheKey::new(
                ProxyScheme::Http,
                endpoint.host,
                endpoint.port,
                None,
                credentials.policy(),
            ),
            ProxyTransport::Tls {
                endpoint,
                server_name,
                connector,
            } => DigestCacheKey::new(
                ProxyScheme::Https,
                endpoint.host,
                endpoint.port,
                Some(connector.digest_settings()),
                credentials.policy(),
            )
            .with_server_name(server_name),
        };
        let session = preemptive.then(|| credentials.remembered(&key)).flatten();
        Self {
            credentials,
            key,
            session,
            request: None,
            stale_retried: false,
        }
    }

    /// Whether the next attempt can carry an accepted or challenged nonce.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.session.is_some()
    }

    /// Creates a field for the exact method and encoded request target.
    ///
    /// # Errors
    /// Returns an error for an invalid target, exhausted nonce count or hashing
    /// failure. A cancelled attempt must call this again before sending.
    pub fn authorization(
        &mut self,
        method: &Method,
        target: &str,
    ) -> Result<Option<RequestHeader>, DigestAuthError> {
        self.request = self
            .session
            .as_ref()
            .map(|session| session.request(method, target))
            .transpose()?;
        Ok(self.request.as_ref().map(|request| request.header.clone()))
    }

    /// Processes a `407`, permitting one replacement with `stale=true`.
    ///
    /// # Errors
    /// Rejects unsupported, malformed, repeated or non-stale challenges after
    /// authentication. No other authentication scheme is selected.
    pub fn challenge(&mut self, headers: &HeaderMap) -> Result<(), DigestAuthError> {
        let challenge = DigestChallenge::select(
            headers
                .get_all(http::header::PROXY_AUTHENTICATE)
                .iter()
                .map(|value| value.as_bytes()),
            self.credentials,
        );
        let authenticated = self.session.is_some();
        if let Some(session) = self.session.take() {
            self.credentials.forget(&self.key, &session);
        }
        self.request = None;
        let challenge = challenge?;
        if authenticated {
            if !challenge.stale || self.stale_retried {
                return Err(DigestAuthError::AuthenticationRejected);
            }
            self.stale_retried = true;
        }
        self.session = Some(self.credentials.challenged(&self.key, challenge)?);
        Ok(())
    }

    /// Checks the response head and returns a guard for its body and trailers.
    ///
    /// # Errors
    /// Rejects malformed or incorrect head authentication. The rejected nonce
    /// is forgotten. Complete the returned guard before accepting its nonce.
    pub fn accept(
        &mut self,
        headers: &HeaderMap,
    ) -> Result<Option<super::DigestResponseAuthentication>, DigestAuthError> {
        let Some(request) = self.request.take() else {
            return Ok(None);
        };
        let Some(session) = self.session.as_ref().cloned() else {
            return Err(DigestAuthError::InvalidResponseAuthentication);
        };
        match super::DigestResponseAuthentication::new(
            self.credentials,
            &self.key,
            session,
            request,
            headers,
        ) {
            Ok(authentication) => Ok(Some(authentication)),
            Err(error) => {
                self.session = None;
                Err(error)
            }
        }
    }
}

impl fmt::Debug for DigestForwardAuthentication<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DigestForwardAuthentication")
            .field("authenticated", &self.session.is_some())
            .field("stale_retried", &self.stale_retried)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::digest::tests::proxy_peer;

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    fn transport() -> ProxyTransport<'static> {
        ProxyTransport::Tcp(crate::route::Endpoint {
            host: "proxy.example",
            port: 8080,
        })
    }

    fn challenge(nonce: &str, stale: bool) -> Result<HeaderMap, http::header::InvalidHeaderValue> {
        let mut fields = HeaderMap::new();
        fields.insert(
            http::header::PROXY_AUTHENTICATE,
            proxy_peer::challenge("SHA-256", nonce, stale).parse()?,
        );
        Ok(fields)
    }

    #[test]
    fn cancelled_and_parallel_forward_attempts_never_reuse_a_nonce_count() -> TestResult {
        let credentials = HttpDigestCredentials::new("user", "password")?;
        let mut first = DigestForwardAuthentication::new(&credentials, transport(), false);
        let mut second = DigestForwardAuthentication::new(&credentials, transport(), false);
        first.challenge(&challenge("first", false)?)?;
        second.challenge(&challenge("first", false)?)?;
        let cancelled = first
            .authorization(&Method::GET, "http://origin/a")?
            .ok_or("field missing")?;
        let simultaneous = second
            .authorization(&Method::GET, "http://origin/a")?
            .ok_or("field missing")?;
        let replay = first
            .authorization(&Method::GET, "http://origin/a")?
            .ok_or("field missing")?;
        let cancelled = proxy_peer::verify(
            std::str::from_utf8(cancelled.value())?,
            "GET",
            "http://origin/a",
            "SHA-256",
            "first",
        )?;
        let simultaneous = proxy_peer::verify(
            std::str::from_utf8(simultaneous.value())?,
            "GET",
            "http://origin/a",
            "SHA-256",
            "first",
        )?;
        let replay = proxy_peer::verify(
            std::str::from_utf8(replay.value())?,
            "GET",
            "http://origin/a",
            "SHA-256",
            "first",
        )?;
        assert_eq!(
            [cancelled.count, simultaneous.count, replay.count],
            ["00000001", "00000002", "00000003"]
        );
        assert_eq!(cancelled.cnonce, simultaneous.cnonce);
        assert_eq!(simultaneous.cnonce, replay.cnonce);
        assert!(
            !DigestForwardAuthentication::new(&credentials, transport(), true).is_authenticated()
        );
        Ok(())
    }

    #[test]
    fn repeated_stale_or_wrong_proof_clears_forward_authentication() -> TestResult {
        let credentials = HttpDigestCredentials::new("user", "password")?;
        let mut state = DigestForwardAuthentication::new(&credentials, transport(), false);
        state.challenge(&challenge("first", false)?)?;
        state.authorization(&Method::GET, "/resource")?;
        state.challenge(&challenge("second", true)?)?;
        assert!(matches!(
            state.challenge(&challenge("third", true)?),
            Err(DigestAuthError::AuthenticationRejected)
        ));
        assert!(!state.is_authenticated());
        state.challenge(&challenge("fourth", false)?)?;
        state.authorization(&Method::GET, "/resource")?;
        let mut fields = HeaderMap::new();
        fields.insert(
            "proxy-authentication-info",
            "rspauth=wrong, nextnonce=unsafe".parse()?,
        );
        assert!(matches!(
            state.accept(&fields),
            Err(DigestAuthError::InvalidResponseAuthentication)
        ));
        assert!(!state.is_authenticated());
        assert!(
            !DigestForwardAuthentication::new(&credentials, transport(), true).is_authenticated()
        );
        Ok(())
    }
}
