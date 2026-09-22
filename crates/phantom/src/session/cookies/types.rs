use std::{error::Error as StdError, fmt, num::NonZeroUsize};

const DEFAULT_MAX_COOKIE_BYTES: NonZeroUsize = nonzero(4096);
// Chromium's CookieMonster::kDomainMaxCookies and kMaxCookies.
const DEFAULT_MAX_COOKIES_PER_DOMAIN: NonZeroUsize = nonzero(180);
const DEFAULT_MAX_COOKIES: NonZeroUsize = nonzero(3300);

const fn nonzero(value: usize) -> NonZeroUsize {
    match NonZeroUsize::new(value) {
        Some(value) => value,
        None => NonZeroUsize::MIN,
    }
}

/// Bounds applied to one in-memory cookie jar.
///
/// A `Set-Cookie` field above the byte bound is rejected. The count bounds
/// never reject a cookie: when an insert exceeds one, the jar evicts least
/// recently used cookies, non-`Secure` first, down to five sixths of the
/// per-domain bound or ten elevenths of the total bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CookieLimits {
    max_cookie_bytes: NonZeroUsize,
    max_cookies_per_domain: NonZeroUsize,
    max_cookies: NonZeroUsize,
}

impl CookieLimits {
    /// Creates cookie-field, per-registrable-domain, and total-count bounds.
    #[must_use]
    pub const fn new(
        max_cookie_bytes: NonZeroUsize,
        max_cookies_per_domain: NonZeroUsize,
        max_cookies: NonZeroUsize,
    ) -> Self {
        Self {
            max_cookie_bytes,
            max_cookies_per_domain,
            max_cookies,
        }
    }

    /// Returns the largest accepted `Set-Cookie` field in bytes.
    #[must_use]
    pub const fn max_cookie_bytes(self) -> NonZeroUsize {
        self.max_cookie_bytes
    }

    /// Returns the per-registrable-domain count above which cookies are evicted.
    #[must_use]
    pub const fn max_cookies_per_domain(self) -> NonZeroUsize {
        self.max_cookies_per_domain
    }

    /// Returns the total count above which cookies are evicted.
    #[must_use]
    pub const fn max_cookies(self) -> NonZeroUsize {
        self.max_cookies
    }
}

impl Default for CookieLimits {
    fn default() -> Self {
        Self::new(
            DEFAULT_MAX_COOKIE_BYTES,
            DEFAULT_MAX_COOKIES_PER_DOMAIN,
            DEFAULT_MAX_COOKIES,
        )
    }
}

/// Stable category of cookie input or policy failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CookieErrorKind {
    /// The associated URL was invalid or unsupported.
    InvalidUrl,
    /// The `Set-Cookie` field could not be parsed or applied.
    InvalidSetCookie,
    /// The field exceeded the configured byte limit.
    CookieTooLarge,
    /// The cookie targeted a public suffix.
    PublicSuffix,
    /// A cookie-name prefix requirement was not satisfied.
    InvalidPrefix,
    /// An insecure origin attempted to overlay an existing secure cookie.
    SecureOverlay,
    /// The cookie used a policy this client cannot model.
    UnsupportedPolicy,
    /// Retained for compatibility; count bounds now evict instead of
    /// rejecting, so the jar no longer returns this kind.
    Capacity,
}

/// Error returned by explicit cookie-jar operations.
#[derive(Debug)]
pub struct CookieError {
    kind: CookieErrorKind,
    message: &'static str,
    source: Option<Box<dyn StdError + Send + Sync>>,
}

impl CookieError {
    pub(super) fn new(kind: CookieErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            message,
            source: None,
        }
    }

    pub(super) fn with_source(
        kind: CookieErrorKind,
        message: &'static str,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            message,
            source: Some(Box::new(source)),
        }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> CookieErrorKind {
        self.kind
    }
}

impl fmt::Display for CookieError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl StdError for CookieError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}
