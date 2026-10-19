//! Whole completed answers for the encrypted session checkpoint.

use std::{
    collections::{HashSet, VecDeque},
    time::{Instant, SystemTime},
};

use phantom_net::dns::{HttpsRecordAnswer, HttpsRecordLookup};

use super::{
    ConfigurationFence, DestinationRecords, HttpsRecordDiscovery, MAX_RESULT_TTL, ReadyEntry,
    summarize,
};
use crate::{SessionSnapshotError, SessionSnapshotErrorKind as Kind};

mod rdata;
pub(crate) use rdata::encode_record;

pub(crate) const MAX_ENTRIES: usize = 65_535;
pub(crate) const MAX_RECORDS: usize = 65_535;
pub(crate) const MAX_RDATA: usize = 65_535;

pub(crate) struct HttpsRecordSnapshot {
    pub(crate) namespace: Box<str>,
    /// Least recently used first; records within an answer retain response order.
    pub(crate) entries: Vec<Entry>,
}

pub(crate) struct Entry {
    pub(crate) host: Box<str>,
    pub(crate) port: u16,
    pub(crate) expires_at: SystemTime,
    pub(crate) negative_ttl: Option<u32>,
    pub(crate) answers: Vec<HttpsRecordAnswer>,
}

fn invalid() -> SessionSnapshotError {
    SessionSnapshotError::new(Kind::InvalidSnapshot)
}

fn dns_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.bytes().all(|byte| byte.is_ascii_graphic())
        })
}

fn cache_key(host: &str, port: u16) -> bool {
    port != 0
        && dns_name(host)
        && url::Host::parse(host).is_ok_and(|parsed| {
            matches!(&parsed, url::Host::Domain(_)) && parsed.to_string() == host
        })
}

impl HttpsRecordDiscovery {
    fn checkpoint_namespace<'a>(
        &self,
        namespace: Option<&'a str>,
    ) -> Result<&'a str, SessionSnapshotError> {
        let namespace = namespace
            .filter(|value| {
                !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
            })
            .ok_or_else(|| SessionSnapshotError::new(Kind::Unsupported))?;
        match self.resolver.configuration_token() {
            Ok(None) => Ok(namespace),
            // A live generation or failed observer is never a portable identity.
            Ok(Some(_)) | Err(_) => Err(SessionSnapshotError::new(Kind::Unsupported)),
        }
    }

    pub(crate) fn export_checkpoint(
        &self,
        namespace: Option<&str>,
    ) -> Result<HttpsRecordSnapshot, SessionSnapshotError> {
        let namespace = self.checkpoint_namespace(namespace)?;
        let state = self.cache.lock_state();
        let now = Instant::now();
        let mut entries = Vec::new();
        let mut bytes = namespace.len();
        for ready in &state.ready {
            if ready.expires_at <= now {
                continue;
            }
            // Pending work and operational-error backoff have no answer to persist.
            let Some(DestinationRecords::Answer(answer)) = &ready.summary.destination else {
                continue;
            };
            if !matches!(&ready.summary.configuration, ConfigurationFence::Untracked) {
                return Err(SessionSnapshotError::new(Kind::Unsupported));
            }
            if !cache_key(&ready.host, ready.port) {
                return Err(SessionSnapshotError::new(Kind::Unsupported));
            }
            if entries.len() == MAX_ENTRIES || answer.answers().len() > MAX_RECORDS {
                return Err(SessionSnapshotError::new(Kind::TooLarge));
            }
            bytes = bytes
                .checked_add(ready.host.len() + 24)
                .ok_or_else(|| SessionSnapshotError::new(Kind::TooLarge))?;
            for answer in answer.answers() {
                if answer.owner().len() > 64 * 1024 {
                    return Err(SessionSnapshotError::new(Kind::TooLarge));
                }
                bytes = bytes
                    .checked_add(answer.owner().len() + encode_record(answer.record())?.len() + 12)
                    .filter(|bytes| *bytes <= crate::session::snapshot::MAX_BYTES)
                    .ok_or_else(|| SessionSnapshotError::new(Kind::TooLarge))?;
            }
            if bytes > crate::session::snapshot::MAX_BYTES {
                return Err(SessionSnapshotError::new(Kind::TooLarge));
            }
            entries
                .try_reserve(1)
                .map_err(|_| SessionSnapshotError::new(Kind::Allocation))?;
            let expires_at = ready.wall_expiry.ok_or_else(invalid)?;
            let mut answers = Vec::new();
            answers
                .try_reserve_exact(answer.answers().len())
                .map_err(|_| SessionSnapshotError::new(Kind::Allocation))?;
            answers.extend_from_slice(answer.answers());
            entries.push(Entry {
                host: ready.host.clone(),
                port: ready.port,
                expires_at,
                negative_ttl: answer.negative_ttl(),
                answers,
            });
        }
        Ok(HttpsRecordSnapshot {
            namespace: namespace.into(),
            entries,
        })
    }

    pub(crate) fn restore_checkpoint(
        &self,
        snapshot: &HttpsRecordSnapshot,
        namespace: Option<&str>,
    ) -> Result<(), SessionSnapshotError> {
        if self.checkpoint_namespace(namespace)? != &*snapshot.namespace {
            return Err(SessionSnapshotError::new(Kind::Incompatible));
        }
        if snapshot.entries.len() > MAX_ENTRIES {
            return Err(SessionSnapshotError::new(Kind::TooLarge));
        }
        // Sample Instant first so conversion subtracts time spent between reads.
        let now = Instant::now();
        let wall = SystemTime::now();
        let mut keys = HashSet::new();
        let mut ready = VecDeque::new();
        for entry in &snapshot.entries {
            if !cache_key(&entry.host, entry.port) || !keys.insert((&entry.host, entry.port)) {
                return Err(invalid());
            }
            if entry.answers.len() > MAX_RECORDS {
                return Err(SessionSnapshotError::new(Kind::TooLarge));
            }
            for answer in &entry.answers {
                // Owners are the native resolver's bounded strings. Preserve
                // callback values without changing live target matching.
                if answer.owner().len() > 64 * 1024 {
                    return Err(SessionSnapshotError::new(Kind::TooLarge));
                }
                // Revalidate represented record values, including unknown SvcParams.
                let _ = encode_record(answer.record())?;
            }
            let records = HttpsRecordLookup::new(entry.answers.clone(), entry.negative_ttl);
            if records.cache_deadline(MAX_RESULT_TTL).is_none() {
                return Err(invalid());
            }
            let remaining = match entry.expires_at.duration_since(wall) {
                Ok(remaining) if !remaining.is_zero() => remaining.min(MAX_RESULT_TTL),
                _ => continue,
            };
            let Some(deadline) = now.checked_add(remaining) else {
                return Err(invalid());
            };
            let records = records.with_cache_deadline(deadline);
            let Some(expires_at) = records.cache_deadline(MAX_RESULT_TTL) else {
                continue;
            };
            if ready.len() == self.cache.capacity.get() {
                return Err(SessionSnapshotError::new(Kind::Capacity));
            }
            let answers = records
                .answers()
                .iter()
                .map(|answer| (answer.owner(), answer.record()))
                .collect::<Vec<_>>();
            let mut summary = summarize(&answers, &entry.host, entry.port);
            summary.destination = Some(DestinationRecords::Answer(records));
            let wall_expiry = if expires_at < deadline {
                let sampled_wall = SystemTime::now();
                let remaining = expires_at
                    .checked_duration_since(Instant::now())
                    .ok_or_else(invalid)?;
                sampled_wall
                    .checked_add(remaining)
                    .ok_or_else(invalid)?
                    .min(entry.expires_at)
            } else {
                entry.expires_at
            };
            ready.push_back(ReadyEntry {
                host: entry.host.clone(),
                port: entry.port,
                summary: std::sync::Arc::new(summary),
                expires_at,
                wall_expiry: Some(wall_expiry),
            });
        }
        let mut state = self.cache.lock_state();
        if !state.ready.is_empty() || !state.pending.is_empty() {
            return Err(invalid());
        }
        state.ready = ready;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
