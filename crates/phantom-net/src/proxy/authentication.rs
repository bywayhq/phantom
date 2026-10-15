use std::fmt;

use http::{HeaderMap, header::PROXY_AUTHENTICATE};

use super::{HttpConnectError, http_connect::MAX_CONNECT_HEAD_BYTES};
use crate::{
    authorization::{BasicAuthorizationError, basic_value},
    request::RequestHeader,
};

/// Validated credentials for challenge-driven HTTP Basic proxy authentication.
#[derive(Clone, Eq, PartialEq)]
pub struct HttpBasicCredentials {
    authorization: Box<[u8]>,
}

impl HttpBasicCredentials {
    pub(super) fn session_transfer_credential(
        &self,
    ) -> Result<btls::ssl::SessionTransferCredential, btls::ssl::SessionTransferError> {
        super::credential_frame::credential(1, 0, &[&self.authorization])
    }

    /// Validates and prepares an HTTP Basic credential pair.
    ///
    /// Usernames and passwords are intentionally restricted to ASCII so the
    /// encoded octets never depend on an implicit character-set convention.
    ///
    /// # Errors
    ///
    /// Returns [`HttpConnectError`] when either value is invalid or the
    /// encoded credentials cannot fit within a bounded CONNECT request.
    pub fn new(
        username: impl AsRef<str>,
        password: impl AsRef<str>,
    ) -> Result<Self, HttpConnectError> {
        let authorization =
            basic_value(username.as_ref(), password.as_ref(), MAX_CONNECT_HEAD_BYTES).map_err(
                |error| match error {
                    BasicAuthorizationError::Username => HttpConnectError::InvalidBasicUsername,
                    BasicAuthorizationError::Password => HttpConnectError::InvalidBasicPassword,
                    BasicAuthorizationError::TooLarge => HttpConnectError::BasicCredentialsTooLarge,
                },
            )?;
        Ok(Self { authorization })
    }

    pub(crate) fn authorization(&self) -> &[u8] {
        &self.authorization
    }

    /// Produces the canonical authorization field for a validated Basic challenge.
    ///
    /// The returned field is marked sensitive so its value is redacted from
    /// diagnostics. HTTP/3 sends it as a never-indexed literal, and so does
    /// HTTP/2 unless the connection is to a proxy and the profile's
    /// [`Http2SensitiveProxyAuthorization`](phantom_profile::Http2SensitiveProxyAuthorization)
    /// leaves it to the field indexing rule, as the browser recipes do.
    #[must_use]
    pub fn proxy_authorization_header(&self) -> RequestHeader {
        RequestHeader::new("Proxy-Authorization", &self.authorization).sensitive()
    }
}

impl fmt::Debug for HttpBasicCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HttpBasicCredentials([REDACTED])")
    }
}

pub(super) fn has_valid_basic_challenge(
    headers: &[httparse::Header<'_>],
) -> Result<(), HttpConnectError> {
    validate_basic_challenge_values(headers.iter().filter_map(|header| {
        header
            .name
            .eq_ignore_ascii_case("Proxy-Authenticate")
            .then_some(header.value)
    }))
}

/// Validates the `Proxy-Authenticate` fields from an HTTP 407 response.
///
/// At least one syntactically valid Basic challenge with a realm is required.
/// Every `Proxy-Authenticate` field is parsed strictly, including challenges
/// for other schemes. Field values are borrowed and are never included in
/// returned errors or diagnostics.
///
/// # Errors
///
/// Returns [`HttpConnectError`] when the response contains no supported Basic
/// challenge or any authentication challenge is malformed.
pub fn validate_basic_proxy_challenge(headers: &HeaderMap) -> Result<(), HttpConnectError> {
    validate_basic_challenge_values(
        headers
            .get_all(PROXY_AUTHENTICATE)
            .iter()
            .map(http::HeaderValue::as_bytes),
    )
}

fn validate_basic_challenge_values<'a>(
    values: impl IntoIterator<Item = &'a [u8]>,
) -> Result<(), HttpConnectError> {
    let challenges = super::challenge::parse(values)?;
    let mut supported = false;
    for challenge in challenges {
        if challenge.scheme.eq_ignore_ascii_case(b"Basic") {
            if challenge.token68.is_some() || challenge.parameter(b"realm").is_none() {
                return Err(HttpConnectError::MalformedAuthenticationChallenge);
            }
            if challenge
                .parameter(b"charset")
                .is_some_and(|value| !value.eq_ignore_ascii_case(b"UTF-8"))
            {
                return Err(HttpConnectError::MalformedAuthenticationChallenge);
            }
            supported = true;
        }
    }
    if supported {
        Ok(())
    } else {
        Err(HttpConnectError::UnsupportedAuthenticationChallenge)
    }
}
