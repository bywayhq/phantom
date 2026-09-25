use std::{
    fmt,
    future::Future,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use super::HttpBasicCredentials;

/// Maximum number of remembered proxy and credential pairs per cache.
///
/// Browsers bound their authentication caches too; Chromium keeps at most
/// 20 realm entries per partition. Phantom keys each entry by credential as
/// well, so a caller that rotates usernames on one proxy needs more room. An
/// evicted pair costs one extra `407` round trip the next time it is used.
pub const MAX_PROXY_CREDENTIAL_ENTRIES: usize = 128;

/// Scheme a client uses to reach an HTTP proxy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProxyScheme {
    /// Plaintext `http://` proxy.
    Http,
    /// TLS `https://` proxy.
    Https,
}

/// Per-client record of proxies that accepted HTTP Basic credentials.
///
/// After a proxy challenges a request with `407` and accepts the configured
/// credentials on the retry, the pair of proxy origin (scheme, host, port)
/// and credential is remembered. Later tunnels and forwarded requests to that
/// proxy with the same credential send `Proxy-Authorization` on the first
/// attempt, as browsers do with their authentication cache. A `407` to a
/// request that carried a remembered credential forgets the pair.
///
/// The record never supplies a credential: it only decides whether the
/// credential already configured for a route is sent before a challenge. A
/// route therefore never sends another route's credential, and an origin
/// never receives a proxy credential.
///
/// Clones share one record. It holds at most
/// [`MAX_PROXY_CREDENTIAL_ENTRIES`] pairs and forgets the least recently
/// used pair first. Its lock is never held across an `.await`.
#[derive(Clone, Default)]
pub struct ProxyCredentialCache {
    entries: Arc<Mutex<Entries>>,
}

#[derive(Default)]
struct Entries {
    entries: Vec<Entry>,
    clock: u64,
}

struct Entry {
    scheme: ProxyScheme,
    host: Box<str>,
    port: u16,
    authorization: Box<[u8]>,
    last_used: u64,
}

impl Entry {
    fn matches(
        &self,
        scheme: ProxyScheme,
        host: &str,
        port: u16,
        credentials: &HttpBasicCredentials,
    ) -> bool {
        self.scheme == scheme
            && self.port == port
            && self.host.eq_ignore_ascii_case(host)
            && *self.authorization == *credentials.authorization()
    }
}

impl ProxyCredentialCache {
    /// Creates an empty record.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reports whether this proxy accepted `credentials` after a challenge.
    ///
    /// Plumbing for the `phantom` facade's forwarding path only. Callers do
    /// not pre-seed or inspect the record; an entry exists only after a proxy
    /// accepted a challenged retry.
    #[doc(hidden)]
    #[must_use]
    pub fn contains(
        &self,
        scheme: ProxyScheme,
        host: &str,
        port: u16,
        credentials: &HttpBasicCredentials,
    ) -> bool {
        self.lock()
            .entries
            .iter()
            .any(|entry| entry.matches(scheme, host, port, credentials))
    }

    /// Records that this proxy accepted `credentials`, or marks the pair as
    /// recently used when it is already recorded.
    ///
    /// When the record is full, the least recently used pair is forgotten.
    ///
    /// Plumbing for the `phantom` facade's forwarding path only. Callers do
    /// not pre-seed or inspect the record; an entry exists only after a proxy
    /// accepted a challenged retry.
    #[doc(hidden)]
    pub fn insert(
        &self,
        scheme: ProxyScheme,
        host: &str,
        port: u16,
        credentials: &HttpBasicCredentials,
    ) {
        let mut state = self.lock();
        state.clock += 1;
        let now = state.clock;
        if let Some(entry) = state
            .entries
            .iter_mut()
            .find(|entry| entry.matches(scheme, host, port, credentials))
        {
            entry.last_used = now;
            return;
        }
        if state.entries.len() == MAX_PROXY_CREDENTIAL_ENTRIES
            && let Some(oldest) = state
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(index, _)| index)
        {
            state.entries.swap_remove(oldest);
        }
        state.entries.push(Entry {
            scheme,
            host: host.to_ascii_lowercase().into_boxed_str(),
            port,
            authorization: credentials.authorization().into(),
            last_used: now,
        });
    }

    /// Forgets that this proxy accepted `credentials`.
    ///
    /// Plumbing for the `phantom` facade's forwarding path only. Callers do
    /// not pre-seed or inspect the record; an entry exists only after a proxy
    /// accepted a challenged retry.
    #[doc(hidden)]
    pub fn remove(
        &self,
        scheme: ProxyScheme,
        host: &str,
        port: u16,
        credentials: &HttpBasicCredentials,
    ) {
        self.lock()
            .entries
            .retain(|entry| !entry.matches(scheme, host, port, credentials));
    }

    /// Returns the number of remembered pairs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    /// Reports whether no pair is remembered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> MutexGuard<'_, Entries> {
        // Every critical section leaves the entries valid, so a panic in
        // another thread cannot leave state that needs repair.
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl fmt::Debug for ProxyCredentialCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyCredentialCache")
            .field("entries", &self.len())
            .finish()
    }
}

/// One proxy exchange's use of the credential record.
///
/// Created before the first request, it decides whether that request carries
/// the credential and applies the outcome to the record afterwards.
pub(crate) struct BasicAuthPlan<'a> {
    cache: Option<&'a ProxyCredentialCache>,
    scheme: ProxyScheme,
    host: &'a str,
    port: u16,
    credentials: &'a HttpBasicCredentials,
    preemptive: bool,
}

impl<'a> BasicAuthPlan<'a> {
    pub(crate) fn new(
        cache: Option<&'a ProxyCredentialCache>,
        scheme: ProxyScheme,
        host: &'a str,
        port: u16,
        credentials: &'a HttpBasicCredentials,
    ) -> Self {
        let preemptive = cache.is_some_and(|cache| cache.contains(scheme, host, port, credentials));
        Self {
            cache,
            scheme,
            host,
            port,
            credentials,
            preemptive,
        }
    }

    /// Whether the first request carries the credential.
    pub(crate) const fn preemptive(&self) -> bool {
        self.preemptive
    }

    /// Runs one challenge-driven exchange: a first request, and at most one
    /// retry with the credential on a fresh proxy connection after a `407`.
    ///
    /// `attempt` opens a proxy connection and sends one request of the given
    /// kind. A first request reports a valid Basic `407` as
    /// [`AuthStep::Challenged`]; a retry reports a `407` as an error.
    /// `is_challenge` recognizes the errors a first request returns for an
    /// unusable `407` challenge. A retry that reports
    /// [`AuthStep::Challenged`] fails with `rejected()`.
    pub(crate) async fn run<T, E, A, F>(
        &self,
        mut attempt: A,
        is_challenge: fn(&E) -> bool,
        rejected: fn() -> E,
    ) -> Result<T, E>
    where
        A: FnMut(AuthAttempt) -> F,
        F: Future<Output = Result<AuthStep<T>, E>>,
    {
        let first = if self.preemptive {
            AuthAttempt::Preemptive
        } else {
            AuthAttempt::Anonymous
        };
        let outcome = attempt(first).await;
        if self.preemptive {
            match &outcome {
                Ok(AuthStep::Done(_)) => self.accepted(),
                // A 407 to a request that carried the credential forgets
                // it, so the next exchange starts without it again.
                Ok(AuthStep::Challenged) => self.forget(),
                Err(error) if is_challenge(error) => self.forget(),
                Err(_) => {}
            }
        }
        match outcome? {
            AuthStep::Done(value) => Ok(value),
            AuthStep::Challenged => match attempt(AuthAttempt::Retry).await? {
                AuthStep::Done(value) => {
                    self.accepted();
                    Ok(value)
                }
                AuthStep::Challenged => Err(rejected()),
            },
        }
    }

    /// Records a proxy that accepted a request carrying the credential.
    fn accepted(&self) {
        if let Some(cache) = self.cache {
            cache.insert(self.scheme, self.host, self.port, self.credentials);
        }
    }

    /// Forgets the credential after a `407` to a request that carried it.
    fn forget(&self) {
        if let Some(cache) = self.cache {
            cache.remove(self.scheme, self.host, self.port, self.credentials);
        }
    }
}

/// Kind of one proxy request in a challenge-driven exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthAttempt {
    /// First request, without the credential.
    Anonymous,
    /// First request, with a credential this proxy accepted before.
    Preemptive,
    /// The single retry with the credential after a `407`.
    Retry,
}

impl AuthAttempt {
    /// Whether this request carries the credential.
    pub(crate) const fn sends_credentials(self) -> bool {
        !matches!(self, Self::Anonymous)
    }

    /// Whether this request is the retry after a challenge.
    pub(crate) const fn is_retry(self) -> bool {
        matches!(self, Self::Retry)
    }
}

/// Outcome of one proxy request that did not fail.
pub(crate) enum AuthStep<T> {
    /// The proxy accepted the request.
    Done(T),
    /// A first request received a `407` with a valid Basic challenge.
    Challenged,
}
