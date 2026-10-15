use super::super::AltSvcValidationPublication;
use super::*;
use std::time::Instant;

fn target_at(
    store: &AltSvcStore,
    origin: &Endpoint,
    route: &Route,
    now: Instant,
) -> TestResult<AlternativeTarget> {
    Ok(AlternativeTarget::new(
        &store
            .get_at(origin, route, now)
            .ok_or("missing alternative")?,
    ))
}

fn publication_at(
    store: &AltSvcStore,
    origin: &Endpoint,
    route: &Route,
    target: &AlternativeTarget,
    now: Instant,
) -> TestResult<AltSvcValidationPublication> {
    let publication = target
        .validation_publication()
        .ok_or("missing publication")?;
    if publication.key != StoreKey::new(origin, route)
        || publication
            .current_confirmation(&store.lock_entries(), now)
            .is_none()
    {
        return Err("missing current publication".into());
    }
    Ok(publication.clone())
}

fn current(publication: &AltSvcValidationPublication, now: Instant) -> bool {
    publication.entries.upgrade().is_some_and(|entries| {
        let entries = entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        publication.current_confirmation(&entries, now).is_some()
    })
}

// Seed inherited checked state to test store transitions without a connection.
fn seed_validated(
    store: &AltSvcStore,
    publication: &AltSvcValidationPublication,
    now: Instant,
) -> bool {
    let mut entries = store.lock_entries();
    if publication.current_confirmation(&entries, now).is_none() {
        return false;
    }
    for entry in &mut *entries {
        if entry.key == publication.key && entry.generation == publication.generation {
            for alternative in &mut entry.alternatives {
                if alternative.location == publication.location {
                    alternative.mapping_validated = true;
                }
            }
        }
    }
    true
}

#[test]
fn checked_state_changes_only_later_request_plans() -> TestResult {
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let origin = endpoint("origin.example:443")?;
    let now = Instant::now();
    learn(&store, &origin, b"h3=\":8443\"; ma=60", now);
    let planned = target_at(&store, &origin, &DIRECT, now)?;
    let publication = publication_at(&store, &origin, &DIRECT, &planned, now)?;
    assert!(!planned.mapping_validated());
    assert_eq!(planned.alt_used(), Some("origin.example:8443"));
    assert!(seed_validated(&store, &publication, now));
    assert!(seed_validated(&store, &publication, now));
    assert!(!planned.mapping_validated());
    use phantom_profile::Http3AltUsed::{Append, Omit, ValidatedMapping};
    assert_eq!(planned.alt_used_for(Omit), None);
    assert_eq!(planned.alt_used_for(Append), Some("origin.example:8443"));
    assert_eq!(planned.alt_used_for(ValidatedMapping), None);
    let later = target_at(&store, &origin, &DIRECT, now)?;
    assert!(later.mapping_validated());
    assert_eq!(later.alt_used_for(Omit), None);
    assert_eq!(later.alt_used_for(Append), planned.alt_used_for(Append));
    assert_eq!(
        later.alt_used_for(ValidatedMapping),
        Some("origin.example:8443")
    );
    assert_eq!(planned.clone().alt_used_for(ValidatedMapping), None);
    assert_eq!(later.alt_used(), planned.alt_used());
    assert_eq!(later.location(), planned.location());
    Ok(())
}

#[test]
fn clear_and_removal_keep_old_completions_from_relearning_a_mapping() -> TestResult {
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let origin = endpoint("origin.example:443")?;
    let now = Instant::now();
    learn(&store, &origin, b"h3=\":8443\"; ma=60", now);
    let planned = target_at(&store, &origin, &DIRECT, now)?;
    let before_clear = publication_at(&store, &origin, &DIRECT, &planned, now)?;
    store.clear();
    assert!(!seed_validated(&store, &before_clear, now));
    learn(&store, &origin, b"h3=\":8443\"; ma=60", now);
    let relearned = target_at(&store, &origin, &DIRECT, now)?;
    assert!(!seed_validated(&store, &before_clear, now));
    assert!(!relearned.mapping_validated());
    let before_remove = publication_at(&store, &origin, &DIRECT, &relearned, now)?;
    store.remove_if_current(
        &origin,
        &DIRECT,
        relearned.generation().ok_or("missing generation")?,
        relearned.location(),
    );
    learn(&store, &origin, b"h3=\":8443\"; ma=60", now);
    assert!(!seed_validated(&store, &before_remove, now));
    assert!(!target_at(&store, &origin, &DIRECT, now)?.mapping_validated());
    Ok(())
}

#[test]
fn live_equivalent_refresh_keeps_validation_but_invalidates_old_tokens() -> TestResult {
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let origin = endpoint("origin.example:443")?;
    let now = Instant::now();
    learn(&store, &origin, b"h3=\":8443\"; ma=1", now);
    let original = target_at(&store, &origin, &DIRECT, now)?;
    let old = publication_at(&store, &origin, &DIRECT, &original, now)?;
    assert!(seed_validated(&store, &old, now));
    let refreshed_at = now + Duration::from_millis(500);
    learn(&store, &origin, b"h3=\":8443\"; ma=60", refreshed_at);
    assert!(!seed_validated(&store, &old, refreshed_at));
    assert!(target_at(&store, &origin, &DIRECT, now + Duration::from_secs(2))?.mapping_validated());
    assert!(publication_at(&store, &origin, &DIRECT, &original, refreshed_at).is_err());
    Ok(())
}

#[test]
fn refreshing_an_unvalidated_mapping_rejects_out_of_order_registration() -> TestResult {
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let origin = endpoint("origin.example:443")?;
    let now = Instant::now();
    learn(&store, &origin, b"h3=\":8443\"; ma=60", now);
    let original = target_at(&store, &origin, &DIRECT, now)?;
    let old = publication_at(&store, &origin, &DIRECT, &original, now)?;
    learn(&store, &origin, b"h3=\":8443\"; ma=120", now);
    assert!(!seed_validated(&store, &old, now));
    let refreshed = target_at(&store, &origin, &DIRECT, now)?;
    assert!(!refreshed.mapping_validated());
    let current_publication = publication_at(&store, &origin, &DIRECT, &refreshed, now)?;
    assert!(current(&current_publication, now));
    assert!(!current(&old, now));
    assert!(seed_validated(&store, &current_publication, now));
    Ok(())
}

#[test]
fn expired_and_changed_targets_do_not_inherit_validation() -> TestResult {
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let origin = endpoint("origin.example:443")?;
    let now = Instant::now();
    learn(&store, &origin, b"h3=\":8443\"; ma=1", now);
    let original = target_at(&store, &origin, &DIRECT, now)?;
    let old = publication_at(&store, &origin, &DIRECT, &original, now)?;
    assert!(seed_validated(&store, &old, now));
    let expired_at = now + Duration::from_secs(1);
    assert!(!seed_validated(&store, &old, expired_at));
    assert!(publication_at(&store, &origin, &DIRECT, &original, expired_at).is_err());
    learn(&store, &origin, b"h3=\":8443\"; ma=60", expired_at);
    let relearned = target_at(&store, &origin, &DIRECT, expired_at)?;
    assert!(!relearned.mapping_validated());
    assert!(!seed_validated(&store, &old, expired_at));
    let before_change = publication_at(&store, &origin, &DIRECT, &relearned, expired_at)?;
    assert!(seed_validated(&store, &before_change, expired_at));
    learn(&store, &origin, b"h3=\":9443\"; ma=60", expired_at);
    assert!(!seed_validated(&store, &before_change, expired_at));
    let changed = target_at(&store, &origin, &DIRECT, expired_at)?;
    assert_eq!(changed.port(), 9443);
    assert!(!changed.mapping_validated());
    Ok(())
}

#[test]
fn validation_is_scoped_to_origin_route_and_alternative_target() -> TestResult {
    let store = AltSvcStore::new(NonZeroUsize::new(3).ok_or("zero capacity")?);
    let origin = endpoint("origin.example:443")?;
    let other = endpoint("other.example:443")?;
    let proxy = socks5("socks5://proxy.example:1080")?;
    let now = Instant::now();
    let value = b"h3=\"alt.example:8443\"; ma=60, h3=\"later.example:9443\"; ma=60";
    learn(&store, &origin, value, now);
    learn_on(&store, &origin, &proxy, value, now);
    learn(&store, &other, value, now);
    let direct = target_at(&store, &origin, &DIRECT, now)?;
    assert!(publication_at(&store, &origin, &proxy, &direct, now).is_err());
    assert!(publication_at(&store, &other, &DIRECT, &direct, now).is_err());
    let publication = publication_at(&store, &origin, &DIRECT, &direct, now)?;
    assert!(seed_validated(&store, &publication, now));
    assert!(!target_at(&store, &origin, &proxy, now)?.mapping_validated());
    assert!(!target_at(&store, &other, &DIRECT, now)?.mapping_validated());
    let selections = store.get_up_to_at(&origin, &DIRECT, 2, now);
    assert_eq!(selections.len(), 2);
    let targets: Vec<_> = selections.iter().map(AlternativeTarget::new).collect();
    assert_eq!(targets[0].host(), "alt.example");
    assert_eq!(targets[1].host(), "later.example");
    assert!(targets[0].mapping_validated());
    assert!(!targets[1].mapping_validated());
    Ok(())
}

#[test]
fn validation_is_not_exported_or_restored_from_snapshot_fields() -> TestResult {
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let origin = endpoint("origin.example:443")?;
    let now = Instant::now();
    learn(&store, &origin, b"h3=\":8443\"; ma=60", now);
    let planned = target_at(&store, &origin, &DIRECT, now)?;
    let before = store.export();
    let publication = publication_at(&store, &origin, &DIRECT, &planned, now)?;
    assert!(seed_validated(&store, &publication, now));
    let after = store.export();
    let fields = |snapshot: &super::super::AltSvcSnapshot| {
        snapshot
            .entries()
            .iter()
            .map(|entry| {
                (
                    entry.origin().to_owned(),
                    entry.alternative_host().to_owned(),
                    entry.alternative_port(),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(fields(&after), fields(&before));
    let restored = AltSvcStore::new(NonZeroUsize::MIN);
    restored.import(&after)?;
    let imported = target_at(&restored, &origin, &DIRECT, Instant::now())?;
    assert!(!imported.mapping_validated());
    assert_eq!(imported.alt_used(), planned.alt_used());
    let restored_publication =
        publication_at(&restored, &origin, &DIRECT, &imported, Instant::now())?;
    assert!(seed_validated(
        &restored,
        &restored_publication,
        Instant::now()
    ));
    assert!(target_at(&restored, &origin, &DIRECT, Instant::now())?.mapping_validated());
    store.clear();
    store.import(&after)?;
    assert!(!current(&publication, Instant::now()));
    assert!(!target_at(&store, &origin, &DIRECT, Instant::now())?.mapping_validated());
    Ok(())
}

#[test]
fn eviction_and_store_drop_leave_completion_tokens_inert() -> TestResult {
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let origin = endpoint("origin.example:443")?;
    let other = endpoint("other.example:443")?;
    let now = Instant::now();
    learn(&store, &origin, b"h3=\":8443\"; ma=60", now);
    let planned = target_at(&store, &origin, &DIRECT, now)?;
    let evicted = publication_at(&store, &origin, &DIRECT, &planned, now)?;
    learn(&store, &other, b"h3=\":8443\"; ma=60", now);
    assert!(!seed_validated(&store, &evicted, now));
    let current_target = target_at(&store, &other, &DIRECT, now)?;
    let dropped = publication_at(&store, &other, &DIRECT, &current_target, now)?;
    drop(store);
    assert!(!current(&dropped, now));
    Ok(())
}
