//! Client-local direct QUIC racing history, independent of ticket storage.

use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::time::Instant;

use super::{AltSvcRttDelay, AlternativeTarget};
use crate::{Route, authority::Endpoint};

const DEFAULT_DELAY_US: u64 = 300_000;
const MAX_DELAY_US: u64 = 3_000_000;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Key {
    origin_host: Box<str>,
    origin_port: u16,
    target_host: Box<str>,
    target_port: u16,
}

impl Key {
    fn new(origin: &Endpoint, host: &str, port: u16) -> Self {
        Self {
            origin_host: origin.host().to_ascii_lowercase().into(),
            origin_port: origin.port(),
            target_host: host.to_ascii_lowercase().into(),
            target_port: port,
        }
    }
}

struct Entry {
    key: Key,
    token: Arc<()>,
    sample: Option<(Duration, Instant)>,
}

struct State {
    generation: Arc<()>,
    entries: VecDeque<Entry>,
    success: Option<Instant>,
}

pub(crate) struct RttHistory {
    settings: AltSvcRttDelay,
    state: Mutex<State>,
}

impl RttHistory {
    pub(crate) fn new(settings: AltSvcRttDelay) -> Arc<Self> {
        Arc::new(Self {
            settings,
            state: Mutex::new(State {
                generation: Arc::new(()),
                entries: VecDeque::new(),
                success: None,
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub(crate) fn clear(&self) {
        let mut state = self.lock();
        state.generation = Arc::new(());
        state.entries.clear();
        state.success = None;
    }

    pub(crate) fn invalidate(&self, origin: &Endpoint, route: &Route, host: &str, port: u16) {
        if !matches!(route, Route::Direct) {
            return;
        }
        let key = Key::new(origin, host, port);
        self.lock().entries.retain(|entry| entry.key != key);
    }

    /// Captured once before new connection I/O, never for a reused connection.
    pub(crate) fn publication(
        self: &Arc<Self>,
        origin: &Endpoint,
        route: &Route,
        host: &str,
        port: u16,
        verified: bool,
    ) -> Option<Arc<Publication>> {
        if !verified || !matches!(route, Route::Direct) {
            return None;
        }
        let key = Key::new(origin, host, port);
        let mut state = self.lock();
        let token = if let Some(entry) = state.entries.iter().find(|entry| entry.key == key) {
            Arc::clone(&entry.token)
        } else {
            if state.entries.len() == self.settings.capacity().get() {
                state.entries.pop_front();
            }
            let token = Arc::new(());
            state.entries.push_back(Entry {
                key: key.clone(),
                token: Arc::clone(&token),
                sample: None,
            });
            token
        };
        Some(Arc::new(Publication {
            history: Arc::clone(self),
            generation: Arc::clone(&state.generation),
            key,
            token,
            published: AtomicBool::new(false),
        }))
    }

    pub(crate) fn delay(
        &self,
        origin: &Endpoint,
        route: &Route,
        alternatives: &[AlternativeTarget],
    ) -> Duration {
        if !matches!(route, Route::Direct) {
            return Duration::ZERO;
        }
        let Some(target) = alternatives.iter().find(|target| !target.is_broken()) else {
            return Duration::ZERO;
        };
        // Recent origin QUIC breakage retains Chromium's no-wait decision.
        if !target.allows_early_data() {
            return Duration::ZERO;
        }
        self.delay_for(
            &Key::new(origin, target.host(), target.port()),
            Instant::now(),
        )
    }

    fn delay_for(&self, key: &Key, now: Instant) -> Duration {
        let mut state = self.lock();
        if !state
            .success
            .is_some_and(|observed| fresh(observed, now, self.settings.max_age()))
        {
            return Duration::ZERO;
        }
        let sample = state
            .entries
            .iter()
            .position(|entry| &entry.key == key)
            .and_then(|index| {
                let entry = state.entries.remove(index)?;
                let sample = entry
                    .sample
                    .filter(|(_, observed)| fresh(*observed, now, self.settings.max_age()))
                    .map(|(rtt, _)| rtt);
                state.entries.push_back(entry);
                sample
            });
        scaled_delay(sample, self.settings.additional_delay())
    }
}

fn fresh(observed: Instant, now: Instant, max_age: Duration) -> bool {
    now.checked_duration_since(observed)
        .is_some_and(|age| age < max_age)
}

fn scaled_delay(sample: Option<Duration>, additional: Duration) -> Duration {
    let scaled = sample
        .and_then(|rtt| u64::try_from(rtt.as_micros()).ok())
        .and_then(|micros| micros.checked_mul(3))
        .map(|micros| micros / 2);
    let base = match (sample, scaled) {
        (Some(_), None) => MAX_DELAY_US,
        (_, Some(0) | None) => DEFAULT_DELAY_US,
        (_, Some(micros)) => micros,
    };
    let delay = u64::try_from(additional.as_micros())
        .ok()
        .and_then(|extra| base.checked_add(extra))
        .unwrap_or(MAX_DELAY_US);
    Duration::from_micros(delay.min(MAX_DELAY_US))
}

/// One actual connection's publication, shared by every lease of that slot.
/// Old generations and evicted or invalidated target tokens cannot reseed.
pub(crate) struct Publication {
    history: Arc<RttHistory>,
    generation: Arc<()>,
    key: Key,
    token: Arc<()>,
    published: AtomicBool,
}

impl Publication {
    pub(crate) fn record(&self, rtt: Option<Duration>) {
        let Some(rtt) = rtt else {
            return;
        };
        if self.published.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut state = self.history.lock();
        if !Arc::ptr_eq(&state.generation, &self.generation) {
            return;
        }
        let Some(index) = state
            .entries
            .iter()
            .position(|entry| entry.key == self.key && Arc::ptr_eq(&entry.token, &self.token))
        else {
            return;
        };
        if let Some(mut entry) = state.entries.remove(index) {
            let now = Instant::now();
            entry.sample = Some((rtt, now));
            state.entries.push_back(entry);
            state.success = Some(now);
        }
    }
}

#[cfg(test)]
mod tests;
