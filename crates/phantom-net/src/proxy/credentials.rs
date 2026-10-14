//! Explicit credential schemes for HTTP proxy routes.

use super::{HttpBasicCredentials, HttpDigestCredentials};

/// Owned credentials for one explicitly selected HTTP authentication scheme.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpProxyCredentials {
    /// HTTP Basic authentication, without negotiation of another scheme.
    Basic(HttpBasicCredentials),
    /// HTTP Digest authentication with the credential's algorithm policy.
    Digest(HttpDigestCredentials),
}

impl HttpProxyCredentials {
    /// Borrows the configured scheme without copying credential values.
    #[must_use]
    pub fn as_ref(&self) -> HttpProxyAuthentication<'_> {
        match self {
            Self::Basic(credentials) => HttpProxyAuthentication::Basic(credentials),
            Self::Digest(credentials) => HttpProxyAuthentication::Digest(credentials),
        }
    }
}

/// Borrowed credentials for a proxy route. Schemes never fall back to each other.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpProxyAuthentication<'a> {
    /// HTTP Basic credentials.
    Basic(&'a HttpBasicCredentials),
    /// HTTP Digest credentials.
    Digest(&'a HttpDigestCredentials),
}

impl HttpProxyAuthentication<'_> {
    pub(super) fn to_owned(self) -> HttpProxyCredentials {
        match self {
            Self::Basic(credentials) => HttpProxyCredentials::Basic(credentials.clone()),
            Self::Digest(credentials) => HttpProxyCredentials::Digest(credentials.clone()),
        }
    }
}
