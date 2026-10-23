use std::time::Instant;

use phantom_net::{
    OrderedResponseHeaders,
    http2::{AltSvcFrameScope, AltSvcFrames},
};

use super::{
    AltSvcSelection, AltSvcStore, AltSvcValidationPublication, AlternativeTarget,
    MAX_ALTERNATIVES_PER_ORIGIN, MappingValidation, PendingAdvertisement, canonical_origin,
};
use crate::{Route, authority::Endpoint};

/// One advertisement-owned setup, never an origin HTTP request.
pub(crate) struct AltSvcValidationCandidate {
    target: AlternativeTarget,
    expires_at: Instant,
}

impl AltSvcValidationCandidate {
    pub(crate) const fn target(&self) -> &AlternativeTarget {
        &self.target
    }

    pub(crate) const fn expires_at(&self) -> Instant {
        self.expires_at
    }
}

#[cfg(test)]
pub(super) fn candidate_for_test(
    store: &AltSvcStore,
    origin: &Endpoint,
    value: &[u8],
) -> Option<AltSvcValidationCandidate> {
    store.learn_validating_fields_at(origin, &Route::Direct, [("alt-svc", value)], Instant::now())
}

impl AltSvcStore {
    pub(in crate::session) fn learn_for_validation(
        &self,
        origin: &Endpoint,
        route: &Route,
        headers: &OrderedResponseHeaders,
    ) -> Option<AltSvcValidationCandidate> {
        self.learn_validating_fields_at(
            origin,
            route,
            headers.iter().map(|field| (field.name(), field.value())),
            Instant::now(),
        )
    }

    pub(in crate::session) fn learn_frames_for_validation(
        &self,
        origin: &Endpoint,
        route: &Route,
        frames: &AltSvcFrames,
    ) -> Vec<AltSvcValidationCandidate> {
        let canonical = canonical_origin(origin);
        let now = Instant::now();
        frames
            .as_slice()
            .iter()
            .filter_map(|frame| {
                match frame.scope() {
                    AltSvcFrameScope::Connection(value)
                        if value.as_ref() == canonical.as_bytes() => {}
                    AltSvcFrameScope::Stream => {}
                    _ => return None,
                }
                self.learn_validating_fields_at(
                    origin,
                    route,
                    [("alt-svc", frame.field_value())],
                    now,
                )
            })
            .collect()
    }

    pub(in crate::session) fn get_validated_up_to(
        &self,
        origin: &Endpoint,
        route: &Route,
        max: usize,
    ) -> Vec<AltSvcSelection> {
        self.get_up_to(origin, route, MAX_ALTERNATIVES_PER_ORIGIN)
            .into_iter()
            .filter(|selection| selection.mapping_validated && !selection.broken)
            .take(max)
            .collect()
    }

    fn learn_validating_fields_at<'a>(
        &self,
        origin: &Endpoint,
        route: &Route,
        fields: impl IntoIterator<Item = (&'a str, &'a [u8])>,
        now: Instant,
    ) -> Option<AltSvcValidationCandidate> {
        let mut advertised = self.entry_from_fields(origin, route, fields, now)?;
        if advertised.alternatives.is_empty() {
            self.remove_key(&advertised.key);
            return None;
        }
        // Firefox selects one supported H3 alternative before validating it.
        advertised.alternatives.truncate(1);
        let mut entries = self.lock_entries();
        let mut held = entries
            .iter()
            .position(|entry| entry.key == advertised.key)
            .and_then(|position| entries.remove(position));
        if let Some(entry) = &mut held {
            entry.refresh_validated(now);
            let incoming = advertised.alternatives.first()?;
            if let Some(validated) = entry
                .alternatives
                .iter_mut()
                .find(|alternative| alternative.is_validated())
            {
                if validated.location == incoming.location {
                    validated.expires_at = incoming.expires_at;
                    entries.push_back(held?);
                    return None;
                }
                if incoming.expires_at < validated.expires_at {
                    entries.push_back(held?);
                    return None;
                }
                if entry
                    .pending()
                    .is_some_and(|pending| pending.alternative.location == incoming.location)
                {
                    entries.push_back(held?);
                    return None;
                }
                entry.validation = MappingValidation::Replacement(PendingAdvertisement {
                    alternative: advertised.alternatives.pop()?,
                    generation: advertised.generation,
                });
            } else if matches!(entry.validation, MappingValidation::Initial)
                && !entry.alternatives.is_empty()
            {
                entries.push_back(held?);
                return None;
            } else {
                *entry = advertised;
                entry.validation = MappingValidation::Initial;
            }
        } else {
            advertised.validation = MappingValidation::Initial;
            held = Some(advertised);
        }
        let entry = held?;
        let (alternative, generation) = match entry.pending() {
            Some(pending) => (&pending.alternative, pending.generation),
            None => (entry.alternatives.first()?, entry.generation),
        };
        let selection = AltSvcSelection {
            location: alternative.location.clone(),
            generation,
            mapping_validated: false,
            publication: Some(AltSvcValidationPublication {
                entries: std::sync::Arc::downgrade(&self.entries),
                key: entry.key.clone(),
                location: alternative.location.clone(),
                generation,
            }),
            broken: false,
            origin_quic_recently_broken: false,
        };
        let candidate = AltSvcValidationCandidate {
            target: AlternativeTarget::new(&selection),
            expires_at: alternative.expires_at,
        };
        if entries.len() == self.capacity.get() {
            entries.pop_front();
        }
        entries.push_back(entry);
        Some(candidate)
    }
}

impl AltSvcValidationPublication {
    /// Releases unfinished validation without changing a newer mapping.
    pub(crate) fn abandon(&self) {
        self.abandon_at(Instant::now());
    }

    fn abandon_at(&self, now: Instant) {
        let Some(owner) = self.entries.upgrade() else {
            return;
        };
        let mut entries = owner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(entry) = entries.iter_mut().find(|entry| entry.key == self.key) else {
            return;
        };
        if entry.pending().is_some_and(|pending| {
            pending.generation == self.generation
                && pending.alternative.location == self.location
                && !pending.alternative.is_validated()
        }) {
            entry.validation = MappingValidation::Idle;
        } else if entry.generation == self.generation {
            // Firefox's unfinished transaction destructor retries after two
            // seconds. A normally closed validation has a separate disposition.
            let retry_at = super::expiration_at(now, 2);
            for alternative in &mut entry.alternatives {
                if alternative.location == self.location && !alternative.is_validated() {
                    alternative.expires_at = alternative.expires_at.min(retry_at);
                }
            }
        }
    }

    pub(crate) fn same_mapping(&self, other: &Self) -> bool {
        std::sync::Weak::ptr_eq(&self.entries, &other.entries)
            && self.key == other.key
            && self.generation == other.generation
            && self.location == other.location
    }

    pub(crate) fn is_current(&self) -> bool {
        self.entries.upgrade().is_some_and(|owner| {
            let entries = owner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.current_confirmation(&entries, Instant::now())
                .is_some()
        })
    }
}

#[cfg(test)]
mod tests;
