use std::{collections::HashMap, fmt};

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
/// prefix, `SameSite`, `Partitioned`, eviction, and deterministic
/// request-order rules.
///
/// Every request is treated as a user-initiated top-level navigation to its
/// URL, as if typed into a browser's address bar. That context is same-site
/// for `SameSite` purposes and is its own top-level site for `Partitioned`
/// cookies, so matching `SameSite=Strict`, `SameSite=Lax`, `SameSite=None`,
/// and `Partitioned` cookies are all sent.
///
/// The jar rejects `SameSite=None` and `Partitioned` cookies without
/// `Secure`, and `Secure` cookies set by an `http://` URL.
/// [`Self::set_cookie`] reports these with
/// [`CookieErrorKind::UnsupportedPolicy`]; a rejected response `Set-Cookie`
/// field is ignored and never sent back.
///
/// When a new cookie takes a registrable domain or the whole jar past its
/// [`CookieLimits`] count, the least recently used cookies are evicted,
/// non-`Secure` cookies first.
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
    /// cookie, public-suffix violation, or byte limit.
    pub fn set_cookie(&self, url: &str, set_cookie: &str) -> Result<(), CookieError> {
        let url = parse_url(url)?;
        self.state.lock().store(set_cookie, &url, self.limits)
    }

    /// Returns the exact request `Cookie` field value for `url`.
    ///
    /// Inspecting the jar does not count as a use: unlike a request that
    /// sends the cookies, this call leaves the eviction order unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`CookieError`] when `url` is invalid or unsupported.
    pub fn request_value(&self, url: &str) -> Result<Option<String>, CookieError> {
        let url = parse_url(url)?;
        Ok(self
            .state
            .lock()
            .matching_value(&url)
            .map(|(value, _)| value))
    }

    /// Removes every cookie from the jar.
    pub fn clear(&self) {
        self.state.lock().clear();
    }

    /// Returns the number of currently unexpired cookies.
    #[must_use]
    pub fn len(&self) -> usize {
        let mut state = self.state.lock();
        state.purge_expired();
        state.metadata.len()
    }

    /// Returns whether the jar contains no unexpired cookies.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the `Cookie` field value for a request about to be sent to
    /// `url` and records the sent cookies as used.
    pub(crate) fn request_value_for_url(&self, url: &Url) -> Option<String> {
        self.state.lock().send_value(url)
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
    stores: Stores,
    metadata: HashMap<CookieKey, CookieMetadata>,
    next_sequence: u64,
    next_access: u64,
}

/// Cookie stores split by host-only flag and partition.
///
/// Partitioned cookies live apart so that a partitioned and an unpartitioned
/// cookie with the same name, domain, and path coexist, as in Chromium's
/// separate partitioned-cookie map.
#[derive(Default)]
struct Stores {
    host: CookieStore,
    domain: CookieStore,
    partitioned_host: CookieStore,
    partitioned_domain: CookieStore,
}

impl Stores {
    fn get_mut(&mut self, host_only: bool, partitioned: bool) -> &mut CookieStore {
        match (host_only, partitioned) {
            (true, false) => &mut self.host,
            (false, false) => &mut self.domain,
            (true, true) => &mut self.partitioned_host,
            (false, true) => &mut self.partitioned_domain,
        }
    }

    fn unpartitioned(&self) -> [&CookieStore; 2] {
        [&self.host, &self.domain]
    }

    fn all(&self) -> [(&CookieStore, bool); 4] {
        [
            (&self.host, false),
            (&self.domain, false),
            (&self.partitioned_host, true),
            (&self.partitioned_domain, true),
        ]
    }

    fn remove(&mut self, key: &CookieKey) {
        self.get_mut(key.host_only, key.partitioned)
            .remove(&key.domain, &key.path, &key.name);
    }

    fn clear(&mut self) {
        self.host.clear();
        self.domain.clear();
        self.partitioned_host.clear();
        self.partitioned_domain.clear();
    }
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
        let partitioned = raw.partitioned() == Some(true);
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
            && self
                .stores
                .unpartitioned()
                .into_iter()
                .any(|store| overlays_secure_cookie(&cookie, store))
        {
            return Err(CookieError::new(
                CookieErrorKind::SecureOverlay,
                "insecure cookie would overlay an existing secure cookie",
            ));
        }

        self.purge_expired();
        let key = CookieKey::from_cookie(&cookie, partitioned)?;
        let quota_domain = quota_domain(&key.domain);
        let secure = cookie.secure() == Some(true);
        let partition_site = partitioned.then(|| schemeful_site(url));

        let action = match self
            .stores
            .get_mut(key.host_only, key.partitioned)
            .insert(cookie.into_owned(), url)
        {
            Ok(action) => action,
            Err(cookie_store::CookieError::Expired) => {
                self.metadata.remove(&key);
                return Ok(());
            }
            Err(error) => return Err(cookie_store_error(error)),
        };
        if matches!(action, StoreAction::ExpiredExisting) {
            self.stores.remove(&key);
            self.metadata.remove(&key);
            return Ok(());
        }

        // A replacement keeps the old creation position (RFC 6265 Section
        // 5.3, step 11.3) and counts as an access for eviction.
        let last_access = self.next_access();
        let sequence = match self.metadata.get(&key) {
            Some(existing) => existing.sequence,
            None => {
                let sequence = self.next_sequence;
                self.next_sequence = self.next_sequence.saturating_add(1);
                sequence
            }
        };
        self.metadata.insert(
            key,
            CookieMetadata {
                sequence,
                last_access,
                quota_domain: quota_domain.clone(),
                secure,
                partition_site,
            },
        );
        self.evict(&quota_domain, limits);
        Ok(())
    }

    /// Applies Chromium's count-based garbage collection after an insert.
    ///
    /// `CookieMonster::GarbageCollect` purges a registrable domain above 180
    /// cookies down to 150, then the whole store above 3300 down to 3000,
    /// removing least recently accessed non-`Secure` cookies before `Secure`
    /// ones. The purge amounts here are the same fractions of the configured
    /// limits: one sixth and one eleventh.
    fn evict(&mut self, quota_domain: &str, limits: CookieLimits) {
        let domain_limit = limits.max_cookies_per_domain().get();
        let domain_count = self
            .metadata
            .values()
            .filter(|metadata| metadata.quota_domain == quota_domain)
            .count();
        if domain_count > domain_limit {
            self.evict_least_recent(
                domain_count - (domain_limit - domain_limit / 6),
                Some(quota_domain),
            );
        }

        let total_limit = limits.max_cookies().get();
        let total = self.metadata.len();
        if total > total_limit {
            self.evict_least_recent(total - (total_limit - total_limit / 11), None);
        }
    }

    fn evict_least_recent(&mut self, count: usize, quota_domain: Option<&str>) {
        let mut candidates = self
            .metadata
            .iter()
            .filter(|(_, metadata)| {
                quota_domain.is_none_or(|domain| metadata.quota_domain == domain)
            })
            .map(|(key, metadata)| (metadata.secure, metadata.last_access, key.clone()))
            .collect::<Vec<_>>();
        candidates.sort_unstable_by_key(|(secure, last_access, _)| (*secure, *last_access));
        for (_, _, key) in candidates.into_iter().take(count) {
            self.stores.remove(&key);
            self.metadata.remove(&key);
        }
    }

    /// Returns the `Cookie` field value for `url` and records its cookies as
    /// used for eviction.
    fn send_value(&mut self, url: &Url) -> Option<String> {
        let (value, sent) = self.matching_value(url)?;
        for key in sent {
            let last_access = self.next_access();
            if let Some(metadata) = self.metadata.get_mut(&key) {
                metadata.last_access = last_access;
            }
        }
        Some(value)
    }

    /// Returns the `Cookie` field value for `url` and the keys of the cookies
    /// in it, without recording a use.
    fn matching_value(&mut self, url: &Url) -> Option<(String, Vec<CookieKey>)> {
        self.purge_expired();
        let site = schemeful_site(url);
        let mut cookies = Vec::new();
        for (store, partitioned) in self.stores.all() {
            for cookie in store.matches(url) {
                let Ok(key) = CookieKey::from_cookie(cookie, partitioned) else {
                    continue;
                };
                let Some(metadata) = self.metadata.get(&key) else {
                    continue;
                };
                if metadata
                    .partition_site
                    .as_ref()
                    .is_some_and(|partition| *partition != site)
                {
                    continue;
                }
                cookies.push((metadata.sequence, key, cookie));
            }
        }
        if cookies.is_empty() {
            return None;
        }
        // Chromium's CookieMonster::CookieSorter: longer paths first, then
        // creation order.
        cookies.sort_by(|(left_sequence, left, _), (right_sequence, right, _)| {
            right
                .path
                .len()
                .cmp(&left.path.len())
                .then_with(|| left_sequence.cmp(right_sequence))
                .then_with(|| left.name.cmp(&right.name))
        });

        let mut value = String::new();
        let mut sent = Vec::with_capacity(cookies.len());
        for (index, (_, key, cookie)) in cookies.into_iter().enumerate() {
            if index != 0 {
                value.push_str("; ");
            }
            value.push_str(cookie.name());
            value.push('=');
            value.push_str(cookie.value());
            sent.push(key);
        }
        Some((value, sent))
    }

    fn next_access(&mut self) -> u64 {
        let access = self.next_access;
        self.next_access = self.next_access.saturating_add(1);
        access
    }

    /// Drops expired cookies from the stores and their metadata.
    fn purge_expired(&mut self) {
        let expired = self
            .stores
            .all()
            .into_iter()
            .flat_map(|(store, partitioned)| {
                store
                    .iter_any()
                    .filter(|cookie| cookie.is_expired())
                    .filter_map(move |cookie| CookieKey::from_cookie(cookie, partitioned).ok())
            })
            .collect::<Vec<_>>();
        for key in expired {
            self.stores.remove(&key);
            self.metadata.remove(&key);
        }
    }

    fn clear(&mut self) {
        self.stores.clear();
        self.metadata.clear();
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct CookieKey {
    domain: String,
    path: String,
    name: String,
    host_only: bool,
    partitioned: bool,
}

impl CookieKey {
    fn from_cookie(cookie: &Cookie<'_>, partitioned: bool) -> Result<Self, CookieError> {
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
            partitioned,
        })
    }
}

struct CookieMetadata {
    /// Creation order, kept when the cookie is replaced.
    sequence: u64,
    /// Order of the most recent store or send, used for eviction.
    last_access: u64,
    /// Registrable domain the per-domain limit counts against.
    quota_domain: String,
    secure: bool,
    /// Top-level site of a `Partitioned` cookie.
    partition_site: Option<String>,
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
    // Chromium excludes both: EXCLUDE_SAMESITE_NONE_INSECURE and
    // EXCLUDE_INVALID_PARTITIONED.
    if cookie.same_site() == Some(cookie::SameSite::None) && !secure {
        return Err(CookieError::new(
            CookieErrorKind::UnsupportedPolicy,
            "SameSite=None cookies require Secure",
        ));
    }
    if cookie.partitioned() == Some(true) && !secure {
        return Err(CookieError::new(
            CookieErrorKind::UnsupportedPolicy,
            "Partitioned cookies require Secure",
        ));
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

/// Returns whether `domain` is a public suffix, including an unlisted
/// top-level label.
///
/// Chromium's `GetCookieDomainWithString` requires a cookie domain to share
/// the host's registrable domain, and its registry lookup treats an unlisted
/// final label (`corp`, `lan`, `internal`) as a registry. A bare suffix has no
/// registrable domain, so it is accepted only as the exact host and becomes a
/// host-only cookie.
fn is_public_suffix(domain: &CookieDomain) -> bool {
    let Some(domain) = domain.as_cow() else {
        return false;
    };
    !is_ip_address(&domain)
        && psl::List
            .suffix(domain.as_bytes())
            .is_some_and(|suffix| suffix == domain.as_bytes())
}

/// Returns the registrable domain a cookie domain counts against, or the
/// domain itself for an IP address or a name without one.
///
/// This is Chromium's `CookieMonster::GetKey` (153.0.8010.48,
/// `net/cookies/cookie_monster.cc` lines 2641-2649): it falls back to the host
/// when `GetDomainAndRegistry` returns nothing, which it does for an IP
/// address, so each IP address host has its own limit.
fn quota_domain(domain: &str) -> String {
    if is_ip_address(domain) {
        return domain.to_owned();
    }
    psl::domain_str(domain).unwrap_or(domain).to_owned()
}

/// Returns the schemeful site of `url`: the partition key of a `Partitioned`
/// cookie that a top-level request to `url` sets.
fn schemeful_site(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    format!("{}://{}", url.scheme(), quota_domain(host))
}

fn is_ip_address(domain: &str) -> bool {
    matches!(Host::parse(domain), Ok(Host::Ipv4(_) | Host::Ipv6(_)))
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
