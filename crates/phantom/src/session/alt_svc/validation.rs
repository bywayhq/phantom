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

impl AltSvcStore {
    pub(super) fn learn_for_validation(
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

    pub(super) fn learn_frames_for_validation(
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

    pub(super) fn get_validated_up_to(
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
                    .pending
                    .as_ref()
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
mod tests {
    use std::num::NonZeroUsize;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn origin() -> Result<Endpoint, crate::RequestError> {
        Endpoint::new("origin.example:443".parse().expect("static authority"), 443)
    }

    fn learn(
        store: &AltSvcStore,
        origin: &Endpoint,
        value: &[u8],
    ) -> Option<AltSvcValidationCandidate> {
        store.learn_validating_fields_at(
            origin,
            &Route::Direct,
            [("alt-svc", value)],
            Instant::now(),
        )
    }

    // Seed checked connection state to test mapping transitions independently
    // from the real connector authentication controls.
    fn seed_checked(store: &AltSvcStore, candidate: &AltSvcValidationCandidate) {
        let publication = candidate
            .target()
            .validation_publication()
            .expect("candidate publication");
        let mut entries = store.lock_entries();
        let entry = entries
            .iter_mut()
            .find(|entry| entry.key == publication.key)
            .expect("stored origin");
        match &mut entry.validation {
            MappingValidation::Replacement(pending)
                if pending.generation == publication.generation =>
            {
                pending.alternative.mapping_validated = true;
            }
            _ => {
                assert_eq!(entry.generation, publication.generation);
                entry.alternatives[0].mapping_validated = true;
            }
        }
    }

    #[test]
    fn advertisement_starts_once_and_stays_ineligible_until_checked() -> TestResult {
        let origin = origin()?;
        let store = AltSvcStore::new(NonZeroUsize::MIN);
        let candidate =
            learn(&store, &origin, b"h3=\":8443\"; ma=60").ok_or("missing candidate")?;
        assert!(
            candidate
                .target()
                .validation_publication()
                .ok_or("missing publication")?
                .is_current()
        );
        assert!(candidate.expires_at() > Instant::now());
        assert!(
            store
                .get_validated_up_to(&origin, &Route::Direct, 1)
                .is_empty()
        );
        assert!(learn(&store, &origin, b"h3=\":9443\"; ma=60").is_none());

        seed_checked(&store, &candidate);
        let selected = store.get_validated_up_to(&origin, &Route::Direct, 1);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].port(), 8443);
        Ok(())
    }

    #[test]
    fn validated_route_survives_pending_replacement_and_shorter_advertisements() -> TestResult {
        let origin = origin()?;
        let store = AltSvcStore::new(NonZeroUsize::MIN);
        let old = learn(&store, &origin, b"h3=\":8443\"; ma=120").ok_or("missing candidate")?;
        seed_checked(&store, &old);
        assert!(learn(&store, &origin, b"h3=\":9443\"; ma=60").is_none());
        let pending =
            learn(&store, &origin, b"h3=\":9443\"; ma=180").ok_or("missing replacement")?;
        assert!(learn(&store, &origin, b"h3=\":9443\"; ma=180").is_none());
        assert_eq!(
            store.get_validated_up_to(&origin, &Route::Direct, 1)[0].port(),
            8443
        );
        assert!(
            old.target()
                .validation_publication()
                .ok_or("missing old publication")?
                .is_current()
        );

        seed_checked(&store, &pending);
        assert_eq!(
            store.get_validated_up_to(&origin, &Route::Direct, 1)[0].port(),
            9443
        );
        assert!(
            !old.target()
                .validation_publication()
                .ok_or("missing old publication")?
                .is_current()
        );
        assert!(
            pending
                .target()
                .validation_publication()
                .ok_or("missing pending publication")?
                .is_current()
        );
        Ok(())
    }

    #[test]
    fn refresh_clear_and_capacity_keep_validation_tied_to_its_mapping() -> TestResult {
        let origin = origin()?;
        let store = AltSvcStore::new(NonZeroUsize::MIN);
        let original = learn(&store, &origin, b"h3=\":8443\"; ma=60").ok_or("missing candidate")?;
        seed_checked(&store, &original);
        assert!(learn(&store, &origin, b"h3=\":8443\"; ma=120").is_none());
        assert!(
            original
                .target()
                .validation_publication()
                .ok_or("missing publication")?
                .is_current()
        );
        let pending =
            learn(&store, &origin, b"h3=\":9443\"; ma=180").ok_or("missing replacement")?;
        let replacement =
            learn(&store, &origin, b"h3=\":10443\"; ma=180").ok_or("missing newer replacement")?;
        assert!(
            !pending
                .target()
                .validation_publication()
                .ok_or("missing pending publication")?
                .is_current()
        );
        assert!(
            replacement
                .target()
                .validation_publication()
                .ok_or("missing newer publication")?
                .is_current()
        );
        assert!(learn(&store, &origin, b"clear").is_none());
        assert!(
            !replacement
                .target()
                .validation_publication()
                .ok_or("missing newer publication")?
                .is_current()
        );
        assert!(
            store
                .get_validated_up_to(&origin, &Route::Direct, 1)
                .is_empty()
        );

        let candidate =
            learn(&store, &origin, b"h3=\":8443\"; ma=60").ok_or("missing candidate")?;
        let other = Endpoint::new("other.example:443".parse()?, 443)?;
        assert!(learn(&store, &other, b"h3=\":8443\"; ma=60").is_some());
        assert!(
            !candidate
                .target()
                .validation_publication()
                .ok_or("missing publication")?
                .is_current()
        );
        Ok(())
    }

    #[test]
    fn restored_unvalidated_mapping_requires_an_actual_advertisement() -> TestResult {
        let origin = origin()?;
        let source = AltSvcStore::new(NonZeroUsize::MIN);
        assert!(learn(&source, &origin, b"h3=\":8443\"; ma=120").is_some());
        let restored = AltSvcStore::new(NonZeroUsize::MIN);
        restored.import(&source.export())?;
        assert!(
            restored
                .get_validated_up_to(&origin, &Route::Direct, 1)
                .is_empty()
        );
        let candidate = learn(&restored, &origin, b"h3=\":8443\"; ma=120")
            .ok_or("restored state suppressed actual advertisement")?;
        assert!(
            restored
                .get_validated_up_to(&origin, &Route::Direct, 1)
                .is_empty()
        );
        seed_checked(&restored, &candidate);
        assert_eq!(
            restored.get_validated_up_to(&origin, &Route::Direct, 1)[0].port(),
            8443
        );
        Ok(())
    }

    #[test]
    fn expired_validation_cannot_replace_the_validated_route() -> TestResult {
        let origin = origin()?;
        let store = AltSvcStore::new(NonZeroUsize::MIN);
        let old = learn(&store, &origin, b"h3=\":8443\"; ma=120").ok_or("missing candidate")?;
        seed_checked(&store, &old);
        let pending =
            learn(&store, &origin, b"h3=\":9443\"; ma=180").ok_or("missing replacement")?;
        let publication = pending
            .target()
            .validation_publication()
            .ok_or("missing publication")?;
        let future = pending.expires_at() + std::time::Duration::from_secs(1);
        assert!(
            publication
                .current_confirmation(&store.lock_entries(), future)
                .is_none()
        );
        assert!(
            store
                .get_up_to_at(&origin, &Route::Direct, 1, future)
                .is_empty()
        );
        assert!(!publication.is_current());
        Ok(())
    }
}
