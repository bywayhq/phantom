#[cfg(feature = "server")]
mod peer;

use super::*;
use btls::ssl::{PreparedSessionPolicyFreeze, SslContext, SslMethod, SslVerifyMode};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const NAME: &str = "peer.example";

fn cache() -> Result<SessionCache, Box<dyn std::error::Error>> {
    let mut context = SslContext::builder(SslMethod::tls())?;
    context.set_verify(SslVerifyMode::PEER);
    crate::QuicClientConfig::enable_session_resumption(&mut context)?;
    let cache = SessionCache::new(context.build(), true);
    let owner = cache.control().upgrade().ok_or("missing live owner")?;
    owner.bind_transfer_policy(
        NAME,
        SessionTransferPolicy::new(b"QUIC store test policy", &[0, 0], None, &[3; 32])?,
    )?;
    Ok(cache)
}

#[test]
fn empty_capture_preserves_source_generation_and_exact_optional_rtt() -> TestResult {
    let cache = cache()?;
    let owner = cache.control().upgrade().ok_or("missing owner")?;
    let old = cache.capture();
    let rtt = Duration::new(9, 123);
    cache.record_round_trip_time(NAME, rtt);
    let mut plan = QuicSessionTicketCacheOwner::prepare_captures(&[(&owner, NAME)])?
        .pop()
        .ok_or("missing capture plan")?;
    let binding = plan.binding().clone();
    let bindings = [&binding];
    let native_plan = PreparedSessionPolicyFreeze::new(&bindings)?;
    let frozen = owner.freeze();
    let native = native_plan.try_freeze()?;
    frozen.capture(&mut plan, &native)?;
    assert_eq!(frozen.retained_count(), 0);
    drop(native);
    drop(frozen);
    let export = plan.into_export()?;
    assert_eq!(export.header().record_count(), 0);
    assert_eq!(export.header().round_trip_time(), Some(rtt));
    assert!(export.into_records().is_empty());
    assert!(old.is_current());
    assert_eq!(cache.round_trip_time(NAME), Some(rtt));
    Ok(())
}

#[test]
fn capture_rejects_foreign_rtt_and_wrong_frozen_owner_without_changing_source() -> TestResult {
    let cache = cache()?;
    let other = self::cache()?;
    let owner = cache.control().upgrade().ok_or("missing owner")?;
    let other_owner = other.control().upgrade().ok_or("missing second owner")?;
    cache.record_round_trip_time("other.example", Duration::from_millis(7));
    let old = cache.capture();
    let mut plan = QuicSessionTicketCacheOwner::prepare_captures(&[(&owner, NAME)])?
        .pop()
        .ok_or("missing capture plan")?;
    let binding = plan.binding().clone();
    let bindings = [&binding];
    let native_plan = PreparedSessionPolicyFreeze::new(&bindings)?;
    let frozen = other_owner.freeze();
    let native = native_plan.try_freeze()?;
    assert!(matches!(
        frozen.capture(&mut plan, &native),
        Err(SessionTransferError::Policy)
    ));
    drop(native);
    drop(frozen);
    let native_plan = PreparedSessionPolicyFreeze::new(&bindings)?;
    let frozen = owner.freeze();
    let native = native_plan.try_freeze()?;
    assert!(matches!(
        frozen.capture(&mut plan, &native),
        Err(SessionTransferError::Policy)
    ));
    drop(native);
    drop(frozen);
    assert!(plan.into_export().is_err());
    assert!(old.is_current());
    assert_eq!(
        cache.round_trip_time("other.example"),
        Some(Duration::from_millis(7))
    );
    Ok(())
}

#[test]
fn capture_preparation_has_stable_internal_order_and_rejects_duplicate_aliases() -> TestResult {
    let a = cache()?;
    let b = cache()?;
    let left = a.control().upgrade().ok_or("missing left")?;
    let alias = a.control().upgrade().ok_or("missing alias")?;
    let right = b.control().upgrade().ok_or("missing right")?;
    assert!(matches!(
        QuicSessionTicketCacheOwner::prepare_captures(&[(&left, NAME), (&alias, NAME)]),
        Err(SessionTransferError::Policy)
    ));
    let forward = QuicSessionTicketCacheOwner::prepare_captures(&[(&left, NAME), (&right, NAME)])?;
    let reverse = QuicSessionTicketCacheOwner::prepare_captures(&[(&right, NAME), (&left, NAME)])?;
    assert_eq!(
        forward
            .iter()
            .map(PreparedQuicSessionCapture::original_index)
            .collect::<Vec<_>>(),
        reverse
            .iter()
            .map(|plan| 1 - plan.original_index())
            .collect::<Vec<_>>()
    );
    assert!(forward.iter().all(|plan| {
        plan.slots
            .iter()
            .all(|slot| slot.parameters.capacity() == 0)
    }));
    Ok(())
}

#[test]
fn empty_replacement_swaps_rtt_and_retires_old_publication_only_after_unlock() -> TestResult {
    let cache = cache()?;
    let owner = cache.control().upgrade().ok_or("missing owner")?;
    let old = cache.capture();
    cache.record_round_trip_time(NAME, Duration::from_millis(50));
    let application = ApplicationState::new();
    application.start(Some((cache.clone(), NAME.into())), None);
    let mut replacement = owner.prepare_replacement(
        Arc::from(NAME),
        QuicSessionStoreHeader::new(0, 0, Some(Duration::ZERO))?,
        Vec::new(),
    )?;
    let binding = replacement.binding().clone();
    let bindings = [&binding];
    let native_plan = PreparedSessionPolicyFreeze::new(&bindings)?;
    let mut frozen = owner.freeze();
    let native = native_plan.try_freeze()?;
    let validated = frozen.validate_replacement(&mut replacement, &native)?;
    let retired = validated.commit();
    drop(native);
    drop(frozen);
    assert!(!old.is_current());
    assert_eq!(cache.round_trip_time(NAME), Some(Duration::ZERO));
    assert!(application.lock().cache.is_some());
    assert_eq!(retired.finish(), 0);
    assert!(application.lock().cache.is_none());
    assert!(application.lock().refused);
    // A later live RTT observation remains supported after point-in-time replacement.
    cache.record_round_trip_time(NAME, Duration::from_millis(2));
    assert_eq!(cache.round_trip_time(NAME), Some(Duration::from_millis(2)));
    Ok(())
}

#[test]
fn dropped_or_wrong_owner_replacement_validation_leaves_all_state_unchanged() -> TestResult {
    let cache = cache()?;
    let other = self::cache()?;
    let owner = cache.control().upgrade().ok_or("missing owner")?;
    let other_owner = other.control().upgrade().ok_or("missing other owner")?;
    let old = cache.capture();
    cache.record_round_trip_time(NAME, Duration::from_millis(3));
    let mut replacement = owner.prepare_replacement(
        Arc::from(NAME),
        QuicSessionStoreHeader::new(0, 0, None)?,
        Vec::new(),
    )?;
    let binding = replacement.binding().clone();
    let bindings = [&binding];
    let native_plan = PreparedSessionPolicyFreeze::new(&bindings)?;
    let mut frozen = other_owner.freeze();
    let native = native_plan.try_freeze()?;
    assert!(matches!(
        frozen.validate_replacement(&mut replacement, &native),
        Err(SessionTransferError::Policy)
    ));
    drop(native);
    drop(frozen);
    let native_plan = PreparedSessionPolicyFreeze::new(&bindings)?;
    let mut frozen = owner.freeze();
    let native = native_plan.try_freeze()?;
    {
        let _validated = frozen.validate_replacement(&mut replacement, &native)?;
    }
    drop(native);
    drop(frozen);
    assert!(old.is_current());
    assert_eq!(cache.round_trip_time(NAME), Some(Duration::from_millis(3)));
    assert!(!replacement.committed);
    Ok(())
}

#[test]
fn every_present_remembered_parameter_block_uses_the_strict_actual_version_validator() {
    assert!(validate_parameters(QuicVersion::V1, None).is_ok());
    assert!(validate_parameters(QuicVersion::V2, Some(&[])).is_ok());
    assert!(validate_parameters(QuicVersion::V1, Some(&[0x11, 3, 0, 0, 1])).is_err());
    assert!(validate_parameters(QuicVersion::V2, Some(&[0x11, 4, 0, 0, 0, 1])).is_err());
    assert!(validate_parameters(QuicVersion::V2, Some(&[0x11, 4, 0x6b, 0x33, 0x43, 0xcf])).is_ok());
}

#[test]
fn unbound_store_order_remains_unbounded_while_capture_enforces_its_batch_bound() -> TestResult {
    let context = SslContext::builder(SslMethod::tls())?.build();
    let cache = SessionCache::new(context, true);
    let owner = cache.control().upgrade().ok_or("missing unbound owner")?;
    assert!(cache.state().transfer_binding.is_none());
    assert_eq!(
        QuicSessionTicketCacheOwner::ordered_store_indices(&[&owner])?,
        vec![0]
    );
    assert!(matches!(
        QuicSessionTicketCacheOwner::ordered_store_indices(&[&owner, &owner]),
        Err(SessionTransferError::Policy)
    ));
    let excessive = vec![(&owner, NAME); MAX_OWNERS + 1];
    assert!(matches!(
        QuicSessionTicketCacheOwner::prepare_captures(&excessive),
        Err(SessionTransferError::TooLarge)
    ));
    assert!(matches!(
        QuicSessionTicketCacheOwner::prepare_captures(&[(&owner, NAME)]),
        Err(SessionTransferError::Policy)
    ));
    assert_eq!(cache.control().clear(), 0);
    Ok(())
}

fn poison_store(cache: &SessionCache) -> TestResult {
    let inner = Arc::clone(&cache.inner);
    let worker = std::thread::Builder::new()
        .name("poison-quic-ticket-store".into())
        .spawn(move || {
            let _guard = inner.state.lock().unwrap_or_else(PoisonError::into_inner);
            panic!("poison the owned QUIC store after transfer preparation");
        })?;
    if worker.join().is_ok() {
        return Err("store poison worker did not panic".into());
    }
    Ok(())
}

#[test]
fn poison_after_capture_preparation_rejects_transfer_and_clear_recovers() -> TestResult {
    let cache = cache()?;
    let owner = cache.control().upgrade().ok_or("missing owner")?;
    let old = cache.capture();
    let rtt = Duration::from_millis(7);
    cache.record_round_trip_time(NAME, rtt);
    let application = ApplicationState::new();
    application.start(Some((cache.clone(), NAME.into())), None);
    let mut plan = QuicSessionTicketCacheOwner::prepare_captures(&[(&owner, NAME)])?
        .pop()
        .ok_or("missing capture plan")?;
    let binding = plan.binding().clone();
    let bindings = [&binding];
    let native_plan = PreparedSessionPolicyFreeze::new(&bindings)?;
    poison_store(&cache)?;
    let frozen = owner.freeze();
    let native = native_plan.try_freeze()?;
    let rejected = matches!(
        frozen.capture(&mut plan, &native),
        Err(SessionTransferError::Policy)
    );
    drop(native);
    drop(frozen);
    assert!(rejected);
    assert!(plan.into_export().is_err());
    assert!(old.is_current());
    assert_eq!(cache.round_trip_time(NAME), Some(rtt));
    assert!(application.lock().cache.is_some());
    assert_eq!(cache.control().clear(), 0);
    assert!(!old.is_current());
    assert_eq!(cache.round_trip_time(NAME), None);
    assert!(application.lock().cache.is_none());
    assert!(application.lock().refused);
    Ok(())
}

#[test]
fn poison_after_replacement_preparation_preserves_state_and_clear_recovers() -> TestResult {
    let cache = cache()?;
    let owner = cache.control().upgrade().ok_or("missing owner")?;
    let old = cache.capture();
    let rtt = Duration::from_millis(11);
    cache.record_round_trip_time(NAME, rtt);
    let application = ApplicationState::new();
    application.start(Some((cache.clone(), NAME.into())), None);
    let mut replacement = owner.prepare_replacement(
        Arc::from(NAME),
        QuicSessionStoreHeader::new(0, 0, Some(Duration::ZERO))?,
        Vec::new(),
    )?;
    let binding = replacement.binding().clone();
    let bindings = [&binding];
    let native_plan = PreparedSessionPolicyFreeze::new(&bindings)?;
    poison_store(&cache)?;
    let mut frozen = owner.freeze();
    let native = native_plan.try_freeze()?;
    let rejected = matches!(
        frozen.validate_replacement(&mut replacement, &native),
        Err(SessionTransferError::Policy)
    );
    drop(native);
    drop(frozen);
    assert!(rejected);
    assert!(!replacement.committed);
    assert!(old.is_current());
    assert_eq!(cache.round_trip_time(NAME), Some(rtt));
    assert!(application.lock().cache.is_some());
    assert_eq!(cache.control().clear(), 0);
    assert!(!old.is_current());
    assert_eq!(cache.round_trip_time(NAME), None);
    assert!(application.lock().cache.is_none());
    assert!(application.lock().refused);
    Ok(())
}
