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
    /// Prepares opaque configured credentials for authenticated session transfer.
    ///
    /// Native code compares these inputs using the authenticated source owner's
    /// private key. Digest challenges and nonce state do not affect the input.
    /// This input does not prove successful proxy authentication.
    ///
    /// # Errors
    ///
    /// Returns an allocation or framing-bound failure without credential contents.
    pub fn session_transfer_credential(
        self,
    ) -> Result<btls::ssl::SessionTransferCredential, btls::ssl::SessionTransferError> {
        match self {
            Self::Basic(credentials) => credentials.session_transfer_credential(),
            Self::Digest(credentials) => credentials.session_transfer_credential(),
        }
    }

    pub(super) fn to_owned(self) -> HttpProxyCredentials {
        match self {
            Self::Basic(credentials) => HttpProxyCredentials::Basic(credentials.clone()),
            Self::Digest(credentials) => HttpProxyCredentials::Digest(credentials.clone()),
        }
    }
}

#[cfg(test)]
mod tests;
