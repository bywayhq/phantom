use std::num::NonZeroUsize;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn origin() -> Result<Endpoint, Box<dyn std::error::Error>> {
    Ok(Endpoint::new("origin.example:443".parse()?, 443)?)
}

fn learn(
    store: &AltSvcStore,
    origin: &Endpoint,
    value: &[u8],
) -> Option<AltSvcValidationCandidate> {
    store.learn_validating_fields_at(origin, &Route::Direct, [("alt-svc", value)], Instant::now())
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
        MappingValidation::Replacement(pending) if pending.generation == publication.generation => {
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
    let candidate = learn(&store, &origin, b"h3=\":8443\"; ma=60").ok_or("missing candidate")?;
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
    let pending = learn(&store, &origin, b"h3=\":9443\"; ma=180").ok_or("missing replacement")?;
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
    let pending = learn(&store, &origin, b"h3=\":9443\"; ma=180").ok_or("missing replacement")?;
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

    let candidate = learn(&store, &origin, b"h3=\":8443\"; ma=60").ok_or("missing candidate")?;
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
    let pending = learn(&store, &origin, b"h3=\":9443\"; ma=180").ok_or("missing replacement")?;
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

#[test]
fn rejecting_old_generation_preserves_newer_pending_advertisement() -> TestResult {
    for remove_location in [false, true] {
        let origin = origin()?;
        let store = AltSvcStore::new(NonZeroUsize::MIN);
        let old = learn(&store, &origin, b"h3=\":8443\"; ma=120").ok_or("missing candidate")?;
        seed_checked(&store, &old);
        let pending =
            learn(&store, &origin, b"h3=\":9443\"; ma=180").ok_or("missing replacement")?;
        let generation = old.target().generation().ok_or("missing generation")?;
        if remove_location {
            store.remove_if_current(&origin, &Route::Direct, generation, old.target().location());
        } else {
            store.remove_origin_if_current(&origin, &Route::Direct, generation);
        }
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
                .ok_or("missing replacement publication")?
                .is_current()
        );
        assert!(
            store
                .get_validated_up_to(&origin, &Route::Direct, 1)
                .is_empty()
        );
        seed_checked(&store, &pending);
        assert_eq!(
            store.get_validated_up_to(&origin, &Route::Direct, 1)[0].port(),
            9443
        );
    }
    Ok(())
}

#[test]
fn unfinished_work_expires_promptly_without_erasing_validated_replacements() -> TestResult {
    let origin = origin()?;
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let initial = learn(&store, &origin, b"h3=\":8443\"; ma=120").ok_or("missing candidate")?;
    let publication = initial
        .target()
        .validation_publication()
        .ok_or("missing publication")?;
    let now = Instant::now();
    publication.abandon_at(now);
    assert!(
        publication
            .current_confirmation(&store.lock_entries(), now)
            .is_some()
    );
    assert!(
        publication
            .current_confirmation(
                &store.lock_entries(),
                now + std::time::Duration::from_secs(2)
            )
            .is_none()
    );
    assert!(
        store
            .get_up_to_at(
                &origin,
                &Route::Direct,
                1,
                now + std::time::Duration::from_secs(2)
            )
            .is_empty()
    );

    let current =
        learn(&store, &origin, b"h3=\":8443\"; ma=120").ok_or("missing current mapping")?;
    seed_checked(&store, &current);
    let pending = learn(&store, &origin, b"h3=\":9443\"; ma=180").ok_or("missing replacement")?;
    pending
        .target()
        .validation_publication()
        .ok_or("missing pending publication")?
        .abandon();
    assert!(
        !pending
            .target()
            .validation_publication()
            .ok_or("missing pending publication")?
            .is_current()
    );
    assert_eq!(
        store.get_validated_up_to(&origin, &Route::Direct, 1)[0].port(),
        8443
    );
    let newer =
        learn(&store, &origin, b"h3=\":10443\"; ma=180").ok_or("missing newer replacement")?;
    seed_checked(&store, &newer);
    publication.abandon();
    assert!(
        newer
            .target()
            .validation_publication()
            .ok_or("missing newer publication")?
            .is_current()
    );
    assert_eq!(
        store.get_validated_up_to(&origin, &Route::Direct, 1)[0].port(),
        10443
    );
    Ok(())
}
