use std::{
    collections::{HashMap, HashSet},
    fmt,
};

use cookie_store::{Cookie, CookieDomain, CookieStore, RawCookie, StoreAction};
use http::{HeaderMap, header::SET_COOKIE};
use parking_lot::Mutex;
use psl::Psl;
use tracing::debug;
use url::{Host, Url};

mod types;

pub use types::{CookieError, CookieErrorKind, CookieLimits};

/// Bounded, thread-safe in-memory cookie jar.
///
/// The jar models domain, path, expiry, `Secure`, `HttpOnly`, public-suffix,
/// prefix, and deterministic request-order rules.
///
/// It has no request-site or top-level-site context, so it rejects rather than
/// stores `SameSite=Lax`, `SameSite=Strict`, and `Partitioned` cookies, as
/// well as `SameSite=None` without `Secure` and `Secure` cookies set by an
/// `http://` URL. [`Self::set_cookie`] reports these with
/// [`CookieErrorKind::UnsupportedPolicy`]; a rejected response `Set-Cookie`
/// field is ignored and never sent back.
pub struct CookieJar {
    limits: CookieLimits,
    state: Mutex<JarState>,
}

impl CookieJar {
    /// Creates an empty jar with caller-supplied bounds.
    #[must_use]
    pub fn with_limits(limits: CookieLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(JarState::default()),
        }
    }

    /// Applies one `Set-Cookie` field as if received from `url`.
    ///
    /// # Errors
    ///
    /// Returns [`CookieError`] for an invalid URL, malformed or unsupported
    /// cookie, public-suffix violation, or configured bound.
    pub fn set_cookie(&self, url: &str, set_cookie: &str) -> Result<(), CookieError> {
        let url = parse_url(url)?;
        self.state.lock().store(set_cookie, &url, self.limits)
    }

    /// Returns the exact request `Cookie` field value for `url`.
    ///
    /// # Errors
    ///
    /// Returns [`CookieError`] when `url` is invalid or unsupported.
    pub fn request_value(&self, url: &str) -> Result<Option<String>, CookieError> {
        let url = parse_url(url)?;
        Ok(self.state.lock().request_value(&url))
    }

    /// Removes every cookie from the jar.
    pub fn clear(&self) {
        self.state.lock().clear();
    }

    /// Returns the number of currently unexpired cookies.
    #[must_use]
    pub fn len(&self) -> usize {
        let mut state = self.state.lock();
        state.purge_expired_metadata();
        state.metadata.len()
    }

    /// Returns whether the jar contains no unexpired cookies.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(crate) fn request_value_for_url(&self, url: &Url) -> Option<String> {
        self.state.lock().request_value(url)
    }

    pub(crate) fn store_response_headers(&self, url: &Url, headers: &HeaderMap) {
        let mut state = self.state.lock();
        for value in headers.get_all(SET_COOKIE) {
            let result = value.to_str().map_err(|_| {
                CookieError::new(
                    CookieErrorKind::InvalidSetCookie,
                    "Set-Cookie field is not valid text",
                )
            });
            let result = result.and_then(|value| state.store(value, url, self.limits));
            if let Err(error) = result {
                debug!(
                    outcome = "ignored",
                    error_kind = ?error.kind(),
                    "response cookie ignored"
                );
            }
        }
    }
}

impl Default for CookieJar {
    fn default() -> Self {
        Self::with_limits(CookieLimits::default())
    }
}

impl fmt::Debug for CookieJar {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CookieJar")
            .field("limits", &self.limits)
            .field("cookie_count", &self.len())
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct JarState {
    host_store: CookieStore,
    domain_store: CookieStore,
    metadata: HashMap<CookieKey, CookieMetadata>,
    next_sequence: u64,
}

impl JarState {
    fn store(
        &mut self,
        set_cookie: &str,
        url: &Url,
        limits: CookieLimits,
    ) -> Result<(), CookieError> {
        if set_cookie.len() > limits.max_cookie_bytes().get() {
            return Err(CookieError::new(
                CookieErrorKind::CookieTooLarge,
                "Set-Cookie field exceeds the configured byte limit",
            ));
        }

        let mut raw = RawCookie::parse(set_cookie.to_owned()).map_err(|error| {
            CookieError::with_source(
                CookieErrorKind::InvalidSetCookie,
                "Set-Cookie field is malformed",
                error,
            )
        })?;
        validate_policy(&raw, url)?;
        let mut cookie = Cookie::try_from_raw_cookie(&raw, url).map_err(cookie_store_error)?;
        if is_public_suffix(&cookie.domain) {
            let host = url.host_str().unwrap_or_default();
            let domain = cookie.domain.as_cow().unwrap_or_default();
            if domain == host {
                raw.unset_domain();
                cookie = Cookie::try_from_raw_cookie(&raw, url).map_err(cookie_store_error)?;
            } else {
                return Err(CookieError::new(
                    CookieErrorKind::PublicSuffix,
                    "cookie Domain targets a public suffix",
                ));
            }
        }

        if url.scheme() != "https"
            && (overlays_secure_cookie(&cookie, &self.host_store)
                || overlays_secure_cookie(&cookie, &self.domain_store))
        {
            return Err(CookieError::new(
                CookieErrorKind::SecureOverlay,
                "insecure cookie would overlay an existing secure cookie",
            ));
        }

        self.purge_expired_metadata();
        let key = CookieKey::from_cookie(&cookie)?;
        let quota_domain = quota_domain(&key.domain);
        let is_new = !self.metadata.contains_key(&key) && !cookie.is_expired();
        if is_new {
            if self.metadata.len() >= limits.max_cookies().get() {
                return Err(CookieError::new(
                    CookieErrorKind::Capacity,
                    "cookie jar has reached its total cookie limit",
                ));
            }
            let domain_count = self
                .metadata
                .values()
                .filter(|metadata| metadata.quota_domain == quota_domain)
                .count();
            if domain_count >= limits.max_cookies_per_domain().get() {
                return Err(CookieError::new(
                    CookieErrorKind::Capacity,
                    "cookie jar has reached its per-domain cookie limit",
                ));
            }
        }

        let store = if key.host_only {
            &mut self.host_store
        } else {
            &mut self.domain_store
        };
        let action = match store.insert(cookie.into_owned(), url) {
            Ok(action) => action,
            Err(cookie_store::CookieError::Expired) => {
                self.metadata.remove(&key);
                return Ok(());
            }
            Err(error) => return Err(cookie_store_error(error)),
        };
        match action {
            StoreAction::Inserted => {
                let sequence = self.next_sequence;
                self.next_sequence = self.next_sequence.saturating_add(1);
                self.metadata.insert(
                    key,
                    CookieMetadata {
                        sequence,
                        quota_domain,
                    },
                );
            }
            StoreAction::UpdatedExisting => {
                self.metadata.entry(key).or_insert_with(|| {
                    let sequence = self.next_sequence;
                    self.next_sequence = self.next_sequence.saturating_add(1);
                    CookieMetadata {
                        sequence,
                        quota_domain,
                    }
                });
            }
            StoreAction::ExpiredExisting => {
                self.metadata.remove(&key);
            }
        }
        Ok(())
    }

    fn request_value(&mut self, url: &Url) -> Option<String> {
        self.purge_expired_metadata();
        let mut cookies = self.host_store.matches(url);
        cookies.extend(self.domain_store.matches(url));
        cookies.sort_by(|left, right| {
            right
                .path
                .len()
                .cmp(&left.path.len())
                .then_with(|| self.sequence(left).cmp(&self.sequence(right)))
                .then_with(|| left.name().cmp(right.name()))
        });
        if cookies.is_empty() {
            return None;
        }

        let mut value = String::new();
        for (index, cookie) in cookies.into_iter().enumerate() {
            if index != 0 {
                value.push_str("; ");
            }
            value.push_str(cookie.name());
            value.push('=');
            value.push_str(cookie.value());
        }
        Some(value)
    }

    fn sequence(&self, cookie: &Cookie<'_>) -> u64 {
        CookieKey::from_cookie(cookie)
            .ok()
            .and_then(|key| self.metadata.get(&key))
            .map_or(u64::MAX, |metadata| metadata.sequence)
    }

    fn purge_expired_metadata(&mut self) {
        let live = self
            .host_store
            .iter_unexpired()
            .chain(self.domain_store.iter_unexpired())
            .filter_map(|cookie| CookieKey::from_cookie(cookie).ok())
            .collect::<HashSet<_>>();
        self.metadata.retain(|key, _| live.contains(key));
    }

    fn clear(&mut self) {
        self.host_store.clear();
        self.domain_store.clear();
        self.metadata.clear();
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct CookieKey {
    domain: String,
    path: String,
    name: String,
    host_only: bool,
}

impl CookieKey {
    fn from_cookie(cookie: &Cookie<'_>) -> Result<Self, CookieError> {
        let domain = cookie.domain.as_cow().ok_or_else(|| {
            CookieError::new(
                CookieErrorKind::InvalidSetCookie,
                "cookie domain was not resolved",
            )
        })?;
        Ok(Self {
            domain: domain.into_owned(),
            path: cookie.path.to_string(),
            name: cookie.name().to_owned(),
            host_only: matches!(&cookie.domain, CookieDomain::HostOnly(_)),
        })
    }
}

struct CookieMetadata {
    sequence: u64,
    quota_domain: String,
}

fn parse_url(value: &str) -> Result<Url, CookieError> {
    let url = Url::parse(value).map_err(|error| {
        CookieError::with_source(CookieErrorKind::InvalidUrl, "invalid cookie URL", error)
    })?;
    if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
        return Err(CookieError::new(
            CookieErrorKind::InvalidUrl,
            "cookie URL must use HTTP or HTTPS and include a host",
        ));
    }
    Ok(url)
}

fn validate_policy(cookie: &RawCookie<'_>, url: &Url) -> Result<(), CookieError> {
    if cookie.partitioned() == Some(true) {
        return Err(CookieError::new(
            CookieErrorKind::UnsupportedPolicy,
            "Partitioned cookies require top-level-site context",
        ));
    }
    let secure_origin = url.scheme() == "https";
    let secure = cookie.secure() == Some(true);
    if has_ascii_prefix(cookie.name(), "__Secure-") && (!secure || !secure_origin) {
        return Err(CookieError::new(
            CookieErrorKind::InvalidPrefix,
            "__Secure- cookies require Secure and an HTTPS origin",
        ));
    }
    if has_ascii_prefix(cookie.name(), "__Host-")
        && (!secure || !secure_origin || cookie.path() != Some("/") || cookie.domain().is_some())
    {
        return Err(CookieError::new(
            CookieErrorKind::InvalidPrefix,
            "__Host- cookies require Secure, Path=/, HTTPS, and no Domain",
        ));
    }
    if secure && !secure_origin {
        return Err(CookieError::new(
            CookieErrorKind::UnsupportedPolicy,
            "Secure cookies require an HTTPS origin",
        ));
    }
    match cookie.same_site() {
        Some(cookie::SameSite::Strict | cookie::SameSite::Lax) => {
            return Err(CookieError::new(
                CookieErrorKind::UnsupportedPolicy,
                "SameSite Strict and Lax require request-site context",
            ));
        }
        Some(cookie::SameSite::None) if !secure => {
            return Err(CookieError::new(
                CookieErrorKind::UnsupportedPolicy,
                "SameSite=None cookies require Secure",
            ));
        }
        _ => {}
    }
    Ok(())
}

fn has_ascii_prefix(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
}

fn overlays_secure_cookie(cookie: &Cookie<'_>, store: &CookieStore) -> bool {
    let Some(cookie_domain) = cookie.domain.as_cow() else {
        return false;
    };
    store.iter_unexpired().any(|existing| {
        let Some(existing_domain) = existing.domain.as_cow() else {
            return false;
        };
        existing.name() == cookie.name()
            && existing.secure() == Some(true)
            && (domain_matches(&existing_domain, &cookie_domain)
                || domain_matches(&cookie_domain, &existing_domain))
            && path_matches(cookie.path.as_ref(), existing.path.as_ref())
    })
}

fn domain_matches(candidate: &str, domain: &str) -> bool {
    candidate == domain
        || (matches!(Host::parse(candidate), Ok(Host::Domain(_)))
            && candidate
                .strip_suffix(domain)
                .is_some_and(|prefix| prefix.ends_with('.')))
}

fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    request_path == cookie_path
        || request_path
            .strip_prefix(cookie_path)
            .is_some_and(|suffix| cookie_path.ends_with('/') || suffix.starts_with('/'))
}

fn is_public_suffix(domain: &CookieDomain) -> bool {
    let Some(domain) = domain.as_cow() else {
        return false;
    };
    psl::List
        .suffix(domain.as_bytes())
        .is_some_and(|suffix| suffix.is_known() && suffix == domain.as_bytes())
}

fn quota_domain(domain: &str) -> String {
    psl::domain_str(domain).unwrap_or(domain).to_owned()
}

fn cookie_store_error(error: cookie_store::CookieError) -> CookieError {
    CookieError::with_source(
        CookieErrorKind::InvalidSetCookie,
        "Set-Cookie field violates cookie storage rules",
        error,
    )
}

#[cfg(test)]
mod tests;
