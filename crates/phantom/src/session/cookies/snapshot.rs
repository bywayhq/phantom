//! Caller-owned persistence of a cookie jar.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use cookie::time::OffsetDateTime;
use cookie_store::{CookieDomain, CookieExpiration};
use tracing::debug;
use url::Url;

use super::{
    Candidate, CookieErrorKind, CookieJar, CookieKey, CookieLimits, CookieMetadata, JarState,
    is_public_suffix, quota_domain,
};

/// Latest instant `OffsetDateTime::from_unix_timestamp` accepts, and the
/// latest expiry `cookie_store` keeps: 9999-12-31T23:59:59Z.
const MAX_EXPIRY_SECONDS: u64 = 253_402_300_799;

/// Cookies exported from one client, oldest first.
///
/// A snapshot holds each cookie's name, value, domain, path, attributes,
/// partition key, absolute expiry rounded down to a whole second, and the
/// scheme of the URL that set it. It holds no connection, TLS ticket, route,
/// or Alt-Svc state.
///
/// The entries are in creation order, which is the order the jar sends
/// cookies of equal path length in a `Cookie` field. An import keeps it.
///
/// A snapshot is a typed value, not a trusted one: import revalidates every
/// entry through the rules that govern a `Set-Cookie` field, so an edited or
/// caller-built snapshot can hold only what a response could have stored.
/// With the `serde` feature the snapshot implements `Serialize` and
/// `Deserialize`; that form carries cookie values, which are credentials, so
/// store it as such. Formatting with `Debug` omits names, values, domains,
/// paths, and partition keys.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CookieSnapshot {
    entries: Vec<CookieSnapshotEntry>,
}

impl CookieSnapshot {
    /// Creates a snapshot from entries ordered oldest first.
    ///
    /// Entries are validated when imported, not here.
    #[must_use]
    pub fn new(entries: Vec<CookieSnapshotEntry>) -> Self {
        Self { entries }
    }

    /// Returns the entries, oldest first.
    #[must_use]
    pub fn entries(&self) -> &[CookieSnapshotEntry] {
        &self.entries
    }

    /// Returns the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the snapshot has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The scheme of the URL that set a cookie.
///
/// With the domain, it decides whether the setter was a potentially
/// trustworthy origin, and it is the scheme of a `Partitioned` cookie's
/// partition key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum CookieSourceScheme {
    /// `http://`.
    Http,
    /// `https://`.
    Https,
}

impl CookieSourceScheme {
    pub(super) fn of(url: &Url) -> Self {
        if url.scheme() == "https" {
            Self::Https
        } else {
            Self::Http
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// A cookie's `SameSite` attribute.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum CookieSameSite {
    /// `SameSite=Strict`.
    Strict,
    /// `SameSite=Lax`.
    Lax,
    /// `SameSite=None`.
    None,
}

impl CookieSameSite {
    fn from_raw(value: cookie::SameSite) -> Self {
        match value {
            cookie::SameSite::Strict => Self::Strict,
            cookie::SameSite::Lax => Self::Lax,
            cookie::SameSite::None => Self::None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Lax => "Lax",
            Self::None => "None",
        }
    }
}

/// One cookie in a [`CookieSnapshot`].
#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CookieSnapshotEntry {
    source_scheme: CookieSourceScheme,
    name: Box<str>,
    value: Box<str>,
    domain: Box<str>,
    host_only: bool,
    path: Box<str>,
    secure: bool,
    http_only: bool,
    same_site: Option<CookieSameSite>,
    partition_key: Option<Box<str>>,
    expires_at: Option<SystemTime>,
}

impl CookieSnapshotEntry {
    /// Creates a host-only session cookie without attributes for later
    /// import.
    ///
    /// `domain` is the canonical lowercase ASCII host the cookie belongs to,
    /// such as `example.com`, `192.0.2.1`, or `[2001:db8::1]`, and `path`
    /// starts with `/`. The `with_` methods set the remaining attributes.
    /// Import revalidates every part.
    #[must_use]
    pub fn new(
        source_scheme: CookieSourceScheme,
        name: impl Into<Box<str>>,
        value: impl Into<Box<str>>,
        domain: impl Into<Box<str>>,
        path: impl Into<Box<str>>,
    ) -> Self {
        Self {
            source_scheme,
            name: name.into(),
            value: value.into(),
            domain: domain.into(),
            host_only: true,
            path: path.into(),
            secure: false,
            http_only: false,
            same_site: None,
            partition_key: None,
            expires_at: None,
        }
    }

    /// Sets whether the cookie matches only its exact host (`true`, the
    /// default) or also its subdomains, as a `Domain` attribute does.
    #[must_use]
    pub const fn with_host_only(mut self, host_only: bool) -> Self {
        self.host_only = host_only;
        self
    }

    /// Sets the `Secure` attribute.
    #[must_use]
    pub const fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Sets the `HttpOnly` attribute.
    #[must_use]
    pub const fn with_http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;
        self
    }

    /// Sets the `SameSite` attribute.
    #[must_use]
    pub const fn with_same_site(mut self, same_site: CookieSameSite) -> Self {
        self.same_site = Some(same_site);
        self
    }

    /// Marks the cookie `Partitioned` under a schemeful site, such as
    /// `https://example.com`.
    ///
    /// The jar keys a `Partitioned` cookie to the site of the URL that set
    /// it, so import accepts only the site of the source scheme and the
    /// domain's registrable domain.
    #[must_use]
    pub fn with_partition_key(mut self, site: impl Into<Box<str>>) -> Self {
        self.partition_key = Some(site.into());
        self
    }

    /// Sets the absolute wall-clock expiry; without one the cookie is a
    /// session cookie.
    #[must_use]
    pub const fn with_expires_at(mut self, expires_at: SystemTime) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Returns the scheme of the URL that set the cookie.
    #[must_use]
    pub const fn source_scheme(&self) -> CookieSourceScheme {
        self.source_scheme
    }

    /// Returns the cookie name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the cookie value, a credential for many sites.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns the canonical host or domain the cookie belongs to.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns whether the cookie matches only its exact host.
    #[must_use]
    pub const fn host_only(&self) -> bool {
        self.host_only
    }

    /// Returns the cookie path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns whether the cookie has the `Secure` attribute.
    #[must_use]
    pub const fn secure(&self) -> bool {
        self.secure
    }

    /// Returns whether the cookie has the `HttpOnly` attribute.
    #[must_use]
    pub const fn http_only(&self) -> bool {
        self.http_only
    }

    /// Returns the `SameSite` attribute, if the cookie has one.
    #[must_use]
    pub const fn same_site(&self) -> Option<CookieSameSite> {
        self.same_site
    }

    /// Returns the schemeful partition site of a `Partitioned` cookie.
    #[must_use]
    pub fn partition_key(&self) -> Option<&str> {
        self.partition_key.as_deref()
    }

    /// Returns the absolute wall-clock time after which the cookie is
    /// unusable, or `None` for a session cookie.
    #[must_use]
    pub const fn expires_at(&self) -> Option<SystemTime> {
        self.expires_at
    }

    /// Returns the `Set-Cookie` field, apart from its expiry, that a response
    /// from [`Self::source_url`] would send to store this cookie.
    fn set_cookie_field(&self) -> String {
        let mut field = format!("{}={}; Path={}", self.name, self.value, self.path);
        if !self.host_only {
            field.push_str("; Domain=");
            field.push_str(&self.domain);
        }
        if self.secure {
            field.push_str("; Secure");
        }
        if self.http_only {
            field.push_str("; HttpOnly");
        }
        if let Some(same_site) = self.same_site {
            field.push_str("; SameSite=");
            field.push_str(same_site.as_str());
        }
        if self.partition_key.is_some() {
            field.push_str("; Partitioned");
        }
        field
    }

    /// Returns the root URL of the cookie's host under its source scheme,
    /// when the domain is a canonical host.
    fn source_url(&self) -> Option<Url> {
        let url = Url::parse(&format!(
            "{}://{}/",
            self.source_scheme.as_str(),
            self.domain
        ))
        .ok()?;
        (url.host_str() == Some(&*self.domain) && url.path() == "/").then_some(url)
    }

    /// Revalidates the entry as a `Set-Cookie` field from its source URL.
    fn validate(&self, limits: CookieLimits) -> Result<ImportCandidate, CookieSnapshotErrorKind> {
        let url = self
            .source_url()
            .ok_or(CookieSnapshotErrorKind::InvalidCookie)?;
        // Storage turns a public-suffix `Domain` equal to the host into a
        // host-only cookie, so no stored domain cookie has one.
        if !self.host_only && is_public_suffix(&CookieDomain::Suffix(self.domain.to_string())) {
            return Err(CookieSnapshotErrorKind::PublicSuffix);
        }
        let candidate = Candidate::new(&self.set_cookie_field(), &url, limits)
            .map_err(|error| CookieSnapshotErrorKind::from_storage(error.kind()))?;
        if candidate.partition_site.as_deref() != self.partition_key.as_deref() {
            return Err(CookieSnapshotErrorKind::InvalidPartitionKey);
        }
        if !self.describes(&candidate) {
            return Err(CookieSnapshotErrorKind::InvalidCookie);
        }
        Ok(ImportCandidate {
            candidate,
            url,
            expires_at: self.expires_at,
        })
    }

    /// Returns whether the stored form of the synthesized field is exactly
    /// this entry, so no part was rewritten or injected by parsing.
    fn describes(&self, candidate: &Candidate) -> bool {
        let cookie = &candidate.cookie;
        cookie.name() == &*self.name
            && cookie.value() == &*self.value
            && cookie.domain.as_cow().as_deref() == Some(&*self.domain)
            && matches!(cookie.domain, CookieDomain::HostOnly(_)) == self.host_only
            && AsRef::<str>::as_ref(&cookie.path) == &*self.path
            && (cookie.secure() == Some(true)) == self.secure
            && (cookie.http_only() == Some(true)) == self.http_only
            && cookie.same_site().map(CookieSameSite::from_raw) == self.same_site
    }
}

impl fmt::Debug for CookieSnapshotEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CookieSnapshotEntry")
            .field("source_scheme", &self.source_scheme)
            .field("host_only", &self.host_only)
            .field("secure", &self.secure)
            .field("http_only", &self.http_only)
            .field("same_site", &self.same_site)
            .field("partitioned", &self.partition_key.is_some())
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Why [`Client::import_cookies`](crate::Client::import_cookies) rejected a snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CookieSnapshotErrorKind {
    /// The client was built without a cookie jar.
    Disabled,
    /// An entry's domain is not a canonical host, or its name, value, path,
    /// or attributes do not survive as a `Set-Cookie` field unchanged.
    InvalidCookie,
    /// An entry's `Set-Cookie` field would exceed the jar's byte limit.
    CookieTooLarge,
    /// A domain cookie's domain is a public suffix.
    PublicSuffix,
    /// A `__Secure-` or `__Host-` prefix requirement is not satisfied.
    InvalidPrefix,
    /// A `Secure` cookie from an origin that is not potentially trustworthy,
    /// or a `SameSite=None` or `Partitioned` cookie without `Secure`.
    UnsupportedPolicy,
    /// A `Partitioned` cookie's partition key is not the schemeful site of
    /// its source scheme and domain, or a partition key is set on a cookie
    /// storage would not partition.
    InvalidPartitionKey,
}

impl CookieSnapshotErrorKind {
    const fn from_storage(kind: CookieErrorKind) -> Self {
        match kind {
            CookieErrorKind::CookieTooLarge => Self::CookieTooLarge,
            CookieErrorKind::PublicSuffix => Self::PublicSuffix,
            CookieErrorKind::InvalidPrefix => Self::InvalidPrefix,
            CookieErrorKind::UnsupportedPolicy => Self::UnsupportedPolicy,
            CookieErrorKind::InvalidUrl
            | CookieErrorKind::InvalidSetCookie
            | CookieErrorKind::SecureOverlay
            | CookieErrorKind::Capacity => Self::InvalidCookie,
        }
    }
}

/// A rejected cookie snapshot import; the jar is unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CookieSnapshotError {
    kind: CookieSnapshotErrorKind,
    entry: Option<usize>,
}

impl CookieSnapshotError {
    pub(crate) const fn disabled() -> Self {
        Self {
            kind: CookieSnapshotErrorKind::Disabled,
            entry: None,
        }
    }

    const fn entry(kind: CookieSnapshotErrorKind, index: usize) -> Self {
        Self {
            kind,
            entry: Some(index),
        }
    }

    /// Returns the rejection category.
    #[must_use]
    pub const fn kind(&self) -> CookieSnapshotErrorKind {
        self.kind
    }

    /// Returns the index of the rejected entry, if one entry caused the error.
    #[must_use]
    pub const fn entry_index(&self) -> Option<usize> {
        self.entry
    }
}

impl fmt::Display for CookieSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            CookieSnapshotErrorKind::Disabled => "cookies are not enabled for this client",
            CookieSnapshotErrorKind::InvalidCookie => {
                "cookie snapshot entry is not a canonical cookie"
            }
            CookieSnapshotErrorKind::CookieTooLarge => {
                "cookie snapshot entry exceeds the configured byte limit"
            }
            CookieSnapshotErrorKind::PublicSuffix => {
                "cookie snapshot entry's domain is a public suffix"
            }
            CookieSnapshotErrorKind::InvalidPrefix => {
                "cookie snapshot entry violates its name prefix requirements"
            }
            CookieSnapshotErrorKind::UnsupportedPolicy => {
                "cookie snapshot entry violates the Secure, SameSite, or Partitioned rules"
            }
            CookieSnapshotErrorKind::InvalidPartitionKey => {
                "cookie snapshot entry's partition key is not its schemeful site"
            }
        };
        match self.entry {
            Some(index) => write!(formatter, "{message} (entry {index})"),
            None => formatter.write_str(message),
        }
    }
}

impl std::error::Error for CookieSnapshotError {}

/// A revalidated snapshot entry awaiting insertion.
struct ImportCandidate {
    candidate: Candidate,
    url: Url,
    expires_at: Option<SystemTime>,
}

impl CookieJar {
    pub(crate) fn export(&self) -> CookieSnapshot {
        self.state.lock().export()
    }

    /// Validates every entry, then adds unexpired cookies the jar does not
    /// already hold, created and used before every held cookie.
    pub(crate) fn import(&self, snapshot: &CookieSnapshot) -> Result<(), CookieSnapshotError> {
        let validated = snapshot
            .entries()
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                entry
                    .validate(self.limits)
                    .map_err(|kind| CookieSnapshotError::entry(kind, index))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let imported = self.state.lock().import(validated, self.limits);
        debug!(
            outcome = "imported",
            cookie_count = imported,
            "imported cookie jar state"
        );
        Ok(())
    }
}

impl JarState {
    fn export(&mut self) -> CookieSnapshot {
        self.purge_expired();
        let system_now = SystemTime::now();
        let mut cookies = Vec::with_capacity(self.metadata.len());
        for (store, partitioned) in self.stores.all() {
            for cookie in store.iter_unexpired() {
                let Ok(key) = CookieKey::from_cookie(cookie, partitioned) else {
                    continue;
                };
                let Some(metadata) = self.metadata.get(&key) else {
                    continue;
                };
                let expires_at = match &cookie.expires {
                    CookieExpiration::SessionEnd => None,
                    CookieExpiration::AtUtc(expires_at) => {
                        let Some(expires_at) = u64::try_from(expires_at.unix_timestamp())
                            .ok()
                            .and_then(|seconds| {
                                UNIX_EPOCH.checked_add(Duration::from_secs(seconds))
                            })
                            .filter(|expires_at| *expires_at > system_now)
                        else {
                            continue;
                        };
                        Some(expires_at)
                    }
                };
                cookies.push((
                    metadata.sequence,
                    CookieSnapshotEntry {
                        source_scheme: metadata.source_scheme,
                        name: cookie.name().into(),
                        value: cookie.value().into(),
                        domain: key.domain.as_str().into(),
                        host_only: key.host_only,
                        path: key.path.as_str().into(),
                        secure: cookie.secure() == Some(true),
                        http_only: cookie.http_only() == Some(true),
                        same_site: cookie.same_site().map(CookieSameSite::from_raw),
                        partition_key: metadata.partition_site.as_deref().map(Box::from),
                        expires_at,
                    },
                ));
            }
        }
        cookies.sort_unstable_by_key(|(sequence, _)| *sequence);
        CookieSnapshot::new(cookies.into_iter().map(|(_, entry)| entry).collect())
    }

    /// Adds `validated` entries, oldest first, and returns how many it added.
    ///
    /// Like the Alt-Svc import, this never displaces held state: a cookie the
    /// jar holds under the same key wins, the count bounds admit imports only
    /// up to the limit rather than evicting, and imported cookies take the
    /// oldest creation and use positions. A later entry with the same key
    /// wins over an earlier one, and capacity keeps the newest entries.
    fn import(&mut self, validated: Vec<ImportCandidate>, limits: CookieLimits) -> usize {
        self.purge_expired();
        let system_now = SystemTime::now();
        let now = OffsetDateTime::now_utc();
        let mut domain_counts = HashMap::<String, usize>::new();
        for metadata in self.metadata.values() {
            *domain_counts
                .entry(metadata.quota_domain.clone())
                .or_default() += 1;
        }
        let mut total = self.metadata.len();
        let mut seen = HashSet::new();
        let mut accepted = Vec::new();

        // Newest first: a later duplicate wins and capacity keeps the newest.
        for ImportCandidate {
            mut candidate,
            url,
            expires_at,
        } in validated.into_iter().rev()
        {
            if !seen.insert(candidate.key.clone()) {
                continue;
            }
            candidate.cookie.expires = match expires_at {
                None => CookieExpiration::SessionEnd,
                Some(expires_at) => match expiry_at_or_before(expires_at, system_now) {
                    Some(expires_at) => CookieExpiration::from(expires_at),
                    None => continue,
                },
            };
            if candidate.cookie.expires.expires_by(&now)
                || self.metadata.contains_key(&candidate.key)
                || candidate.overlays_held_secure_cookie(&self.stores)
            {
                continue;
            }
            let quota_domain = quota_domain(&candidate.key.domain);
            let domain_count = domain_counts.entry(quota_domain.clone()).or_default();
            if total >= limits.max_cookies().get()
                || *domain_count >= limits.max_cookies_per_domain().get()
            {
                continue;
            }
            *domain_count += 1;
            total += 1;
            accepted.push((candidate, url, quota_domain));
        }

        // Held cookies keep their relative order after every imported one.
        let offset = accepted.len() as u64;
        for metadata in self.metadata.values_mut() {
            metadata.sequence = metadata.sequence.saturating_add(offset);
            metadata.last_access = metadata.last_access.saturating_add(offset);
        }
        self.next_sequence = self.next_sequence.saturating_add(offset);
        self.next_access = self.next_access.saturating_add(offset);

        let mut imported = 0;
        for (position, (candidate, url, quota_domain)) in accepted.into_iter().rev().enumerate() {
            let Candidate {
                cookie,
                key,
                source_scheme,
                partition_site,
                ..
            } = candidate;
            let secure = cookie.secure() == Some(true);
            let inserted = self
                .stores
                .get_mut(key.host_only, key.partitioned)
                .insert(cookie, &url);
            if !matches!(
                inserted,
                Ok(cookie_store::StoreAction::Inserted
                    | cookie_store::StoreAction::UpdatedExisting)
            ) {
                continue;
            }
            let position = position as u64;
            self.metadata.insert(
                key,
                CookieMetadata {
                    sequence: position,
                    last_access: position,
                    quota_domain,
                    secure,
                    partition_site,
                    source_scheme,
                },
            );
            imported += 1;
        }
        imported
    }
}

/// Returns `expires_at` rounded down to a whole second and clamped to the
/// latest expiry storage keeps, or `None` when it is not after `now`.
fn expiry_at_or_before(expires_at: SystemTime, now: SystemTime) -> Option<OffsetDateTime> {
    if expires_at <= now {
        return None;
    }
    let seconds = expires_at
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs()
        .min(MAX_EXPIRY_SECONDS);
    OffsetDateTime::from_unix_timestamp(i64::try_from(seconds).ok()?).ok()
}

#[cfg(test)]
mod tests;
