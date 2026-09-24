//! HTTP/3 discovery from HTTPS DNS records (RFC 9460).
//!
//! Chromium 154.0.8037.58 starts a `DNS_ALPN_H3` job beside its main job
//! for a direct `https` request whose QUIC alternative is not broken
//! (`HttpStreamFactory::JobController::DoCreateJobs`,
//! `net/http/http_stream_factory_job_controller.cc` lines 926-935). The job
//! connects over QUIC to the origin's own host and port when a usable
//! ServiceMode record lists `h3` (`QuicSessionPool::DirectJob::DoAttemptSession`,
//! `net/quic/quic_session_pool_direct_job.cc` lines 191-231). This module
//! makes the same decision from Phantom's own lookup and caches it per
//! origin.

use std::{
    collections::VecDeque,
    net::IpAddr,
    num::NonZeroUsize,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use phantom_net::dns::{
    HttpsRecord, HttpsRecordAnswer, HttpsRecordLookup, HttpsRecordResolver, TargetName,
};
use tokio::sync::watch;
use tracing::{Instrument, debug, instrument::WithSubscriber};

use crate::authority::Endpoint;

/// How long a lookup result without a usable TTL is kept: a failed lookup,
/// or a negative answer without an SOA record.
///
/// Chromium keeps a failed HTTPS query as an empty result for as long as
/// the address records it was resolved with; Phantom's address lookups go
/// through the operating system and expose no TTL, so it uses a fixed
/// period instead.
const UNTIMED_RESULT_TTL: Duration = Duration::from_secs(60);

/// Longest time any result is kept: one day, the cap common to DNS caches.
const MAX_RESULT_TTL: u32 = 24 * 60 * 60;

/// ALPN of HTTP/3 (RFC 9114 section 3.1).
const H3_ALPN: &[u8] = b"h3";
/// SvcParamKeys whose meaning Phantom implements, as a `mandatory` entry
/// requires (RFC 9460 section 8): `alpn` through `ipv6hint`.
const SUPPORTED_KEYS: std::ops::RangeInclusive<u16> = 1..=6;

/// Per-client HTTPS-record lookups with a bounded, TTL-honoring cache.
///
/// Concurrent requests for one origin share one in-flight lookup. Each lookup
/// runs as its own task, so a request never waits for it unless it chose to,
/// and a finished lookup fills the cache even after its requests ended.
pub(crate) struct HttpsRecordDiscovery {
    resolver: HttpsRecordResolver,
    cache: Arc<Cache>,
}

struct Cache {
    capacity: NonZeroUsize,
    entries: Mutex<VecDeque<Entry>>,
    next_lookup: AtomicU64,
}

struct Entry {
    host: Box<str>,
    port: u16,
    state: EntryState,
}

enum EntryState {
    Pending {
        lookup: u64,
        result: watch::Receiver<Option<bool>>,
    },
    Ready {
        advertises_h3: bool,
        expires_at: Instant,
    },
}

/// What the cache knows about an origin's HTTPS records.
pub(crate) enum Discovery {
    /// A fresh result says the origin's records advertise `h3`.
    Advertised,
    /// A fresh result says they do not, or no lookup can run.
    NotAdvertised,
    /// A lookup is in flight.
    Pending(PendingLookup),
}

/// An in-flight lookup's eventual result.
pub(crate) struct PendingLookup(watch::Receiver<Option<bool>>);

impl PendingLookup {
    /// Waits for the lookup and returns whether the records advertise `h3`.
    ///
    /// A lookup that ends without a result, such as one whose runtime shut
    /// down, counts as no advertisement.
    pub(crate) async fn advertises_h3(mut self) -> bool {
        match self.0.wait_for(Option::is_some).await {
            Ok(result) => result.unwrap_or(false),
            Err(_) => false,
        }
    }
}

impl HttpsRecordDiscovery {
    pub(crate) fn new(resolver: HttpsRecordResolver, capacity: NonZeroUsize) -> Self {
        Self {
            resolver,
            cache: Arc::new(Cache {
                capacity,
                entries: Mutex::new(VecDeque::new()),
                next_lookup: AtomicU64::new(1),
            }),
        }
    }

    pub(crate) fn capacity(&self) -> NonZeroUsize {
        self.cache.capacity
    }

    /// Returns the cached result for `origin`, starting a shared lookup when
    /// there is none.
    ///
    /// An IP-literal host has no DNS name to query. Without a Tokio runtime to
    /// run the lookup on, nothing is started.
    pub(crate) fn discover(&self, origin: &Endpoint) -> Discovery {
        if origin.host().parse::<IpAddr>().is_ok() {
            return Discovery::NotAdvertised;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return Discovery::NotAdvertised;
        };
        let host = origin.host().to_ascii_lowercase();
        let port = origin.port();
        let now = Instant::now();
        let mut entries = self.cache.lock_entries();
        if let Some(position) = entries
            .iter()
            .position(|entry| *entry.host == *host && entry.port == port)
            && let Some(entry) = entries.remove(position)
        {
            match &entry.state {
                EntryState::Ready {
                    advertises_h3,
                    expires_at,
                } if *expires_at > now => {
                    let advertises_h3 = *advertises_h3;
                    entries.push_back(entry);
                    return if advertises_h3 {
                        Discovery::Advertised
                    } else {
                        Discovery::NotAdvertised
                    };
                }
                EntryState::Pending { result, .. } => {
                    let pending = PendingLookup(result.clone());
                    entries.push_back(entry);
                    return Discovery::Pending(pending);
                }
                // Expired: dropped here and looked up again below.
                EntryState::Ready { .. } => {}
            }
        }
        let lookup = self.cache.next_lookup_id();
        let (sender, receiver) = watch::channel(None);
        if entries.len() == self.cache.capacity.get() {
            entries.pop_front();
        }
        entries.push_back(Entry {
            host: host.clone().into_boxed_str(),
            port,
            state: EntryState::Pending {
                lookup,
                result: receiver.clone(),
            },
        });
        drop(entries);

        let resolver = self.resolver.clone();
        let cache = Arc::clone(&self.cache);
        let span = tracing::debug_span!("https_record.lookup");
        drop(
            runtime.spawn(
                async move {
                    let result = resolver.lookup(&host, port).await;
                    let (advertises_h3, ttl) = match &result {
                        Ok(records) => {
                            let answers = records
                                .answers()
                                .iter()
                                .map(|answer| (answer.owner(), answer.record()))
                                .collect::<Vec<_>>();
                            (advertises_h3(&answers, &host, port), result_ttl(records))
                        }
                        Err(error) => {
                            debug!(outcome = "failed", kind = ?error.kind(), "HTTPS record lookup failed");
                            (false, UNTIMED_RESULT_TTL)
                        }
                    };
                    debug!(
                        advertises_h3,
                        ttl_seconds = ttl.as_secs(),
                        "HTTPS record lookup finished"
                    );
                    cache.complete(&host, port, lookup, advertises_h3, ttl);
                    let _ = sender.send(Some(advertises_h3));
                }
                .instrument(span)
                .with_current_subscriber(),
            ),
        );
        Discovery::Pending(PendingLookup(receiver))
    }
}

impl Cache {
    fn lock_entries(&self) -> MutexGuard<'_, VecDeque<Entry>> {
        match self.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn next_lookup_id(&self) -> u64 {
        self.next_lookup.fetch_add(1, Ordering::Relaxed)
    }

    /// Stores a finished lookup unless its entry was evicted or replaced meanwhile.
    fn complete(&self, host: &str, port: u16, lookup: u64, advertises_h3: bool, ttl: Duration) {
        let mut entries = self.lock_entries();
        let Some(entry) = entries.iter_mut().find(|entry| {
            *entry.host == *host
                && entry.port == port
                && matches!(entry.state, EntryState::Pending { lookup: current, .. } if current == lookup)
        }) else {
            return;
        };
        let now = Instant::now();
        entry.state = EntryState::Ready {
            advertises_h3,
            expires_at: now.checked_add(ttl).unwrap_or(now),
        };
    }
}

/// Returns how long a successful lookup's result stays fresh.
///
/// Answers use the lowest TTL among them. A negative answer uses its SOA
/// negative TTL when present.
fn result_ttl(lookup: &HttpsRecordLookup) -> Duration {
    let seconds = match lookup.answers().iter().map(HttpsRecordAnswer::ttl).min() {
        Some(ttl) => Some(ttl),
        None => lookup.negative_ttl(),
    };
    seconds.map_or(UNTIMED_RESULT_TTL, |seconds| {
        Duration::from_secs(u64::from(seconds.min(MAX_RESULT_TTL)))
    })
}

/// Returns whether the records let a request to `host`:`port` use HTTP/3 at
/// the origin's own location, by Chromium 154's rules.
///
/// `ExtractHttpsResults` (`net/dns/dns_response_result_extractor.cc` lines
/// 479-628) ignores every record when any is in AliasMode, since Chromium
/// makes no follow-up query, and otherwise keeps a ServiceMode record only
/// when all its mandatory keys are supported, its TargetName is `.`, the
/// origin host, or the record's owner, and its `port`, if any, is the
/// request's port. A kept record supports `alpn` plus `http/1.1` unless
/// `no-default-alpn` is set, and one supporting nothing is dropped. When
/// every kept record sets `no-default-alpn`, all are ignored.
/// `QuicSessionPool::SelectQuicVersion` (`net/quic/quic_session_pool.cc`
/// lines 1656-1691) then needs a kept record listing `h3`.
///
/// Each answer is its owner name and record.
fn advertises_h3(answers: &[(&str, &HttpsRecord)], host: &str, port: u16) -> bool {
    if answers
        .iter()
        .any(|(_, record)| matches!(record, HttpsRecord::Alias(_)))
    {
        return false;
    }
    let mut default_alpn = false;
    let mut h3 = false;
    for (owner, record) in answers {
        let HttpsRecord::Service(service) = record else {
            continue;
        };
        let compatible = service
            .mandatory()
            .iter()
            .all(|key| SUPPORTED_KEYS.contains(key));
        let same_target = match service.target() {
            TargetName::Owner => true,
            TargetName::Name(name) => {
                name.eq_ignore_ascii_case(host) || name.eq_ignore_ascii_case(owner)
            }
        };
        let same_port = service.port().is_none_or(|record_port| record_port == port);
        if !compatible || !same_target || !same_port {
            continue;
        }
        // `no-default-alpn` without `alpn` supports no protocol at all.
        if service.no_default_alpn() && service.alpn().is_empty() {
            continue;
        }
        default_alpn |= !service.no_default_alpn();
        h3 |= service.alpn().iter().any(|id| **id == *H3_ALPN);
    }
    default_alpn && h3
}

#[cfg(test)]
mod tests;
