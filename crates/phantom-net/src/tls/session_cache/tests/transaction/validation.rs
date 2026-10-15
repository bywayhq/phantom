use super::super::super::*;
use super::peer::{Fixture, arrivals};
use crate::tls::test_support::{TEST_SERVER_NAME as NAME, TestResult};
use btls::ssl::SslVersion;

#[tokio::test]
async fn a_permit_for_another_native_scope_cannot_replace_this_cache() -> TestResult<()> {
    let source = Fixture::new(TicketOrder::Newest, 2, SslVersion::TLS1_3)?;
    let authorized = Fixture::new(TicketOrder::Newest, 2, SslVersion::TLS1_3)?;
    let other = Fixture::new(TicketOrder::Newest, 2, SslVersion::TLS1_3)?;
    source.seed(1).await?;
    other.seed(1).await?;
    let before = arrivals(&other.cache);
    let (header, permits) = source.authorized(&authorized)?;
    let owner = other.cache.control().upgrade().ok_or("owner missing")?;
    assert!(matches!(
        owner.prepare_replacement(NAME.into(), header, permits),
        Err(SessionTransferError::Policy)
    ));
    let after = arrivals(&other.cache);
    assert_eq!(after.0, before.0);
    assert_eq!(after.1, before.1);
    assert!(Arc::ptr_eq(&after.2, &before.2));
    Ok(())
}

#[tokio::test]
async fn reverse_physical_record_order_is_rejected_without_store_mutation() -> TestResult<()> {
    let source = Fixture::new(TicketOrder::Oldest, 10, SslVersion::TLS1_3)?;
    let recipient = Fixture::new(TicketOrder::Oldest, 10, SslVersion::TLS1_3)?;
    source.seed(2).await?;
    recipient.seed(1).await?;
    let before = arrivals(&recipient.cache);
    let (header, mut permits) = source.authorized(&recipient)?;
    assert!(permits.len() >= 2);
    permits.reverse();
    let owner = recipient.cache.control().upgrade().ok_or("owner missing")?;
    assert!(matches!(
        owner.prepare_replacement(NAME.into(), header, permits),
        Err(SessionTransferError::Malformed)
    ));
    let after = arrivals(&recipient.cache);
    assert_eq!(after.0, before.0);
    assert_eq!(after.1, before.1);
    assert!(Arc::ptr_eq(&after.2, &before.2));
    Ok(())
}

#[test]
fn frozen_transfer_checks_actual_owner_even_for_empty_equivalent_policies() -> TestResult<()> {
    use btls::ssl::PreparedSessionPolicyFreeze;

    let first = Fixture::new(TicketOrder::Newest, 2, SslVersion::TLS1_3)?;
    let second = Fixture::new(TicketOrder::Newest, 2, SslVersion::TLS1_3)?;
    let first_owner = first
        .cache
        .control()
        .upgrade()
        .ok_or("first owner missing")?;
    let second_owner = second
        .cache
        .control()
        .upgrade()
        .ok_or("second owner missing")?;
    let before = arrivals(&second.cache);
    let mut capture = first_owner.prepare_capture(NAME, 7)?;
    assert_eq!(capture.original_index(), 7);
    let mut exports = TlsSessionOwner::capture_stores(&[(&first_owner, NAME)])?;
    let header = exports.pop().ok_or("empty source export missing")?.header();
    let mut replacement = first_owner.prepare_replacement(NAME.into(), header, Vec::new())?;
    let binding = capture.binding().clone();
    let bindings = [&binding, &second.binding];
    let native_plan = PreparedSessionPolicyFreeze::new(&bindings)?;
    let mut frozen = second_owner.freeze_transfer()?;
    let policies = native_plan.try_freeze()?;
    // Both installed bindings belong to the native transaction. Neither equal
    // policy bytes nor empty queues make a different cache the prepared owner.
    assert!(matches!(
        frozen.validate_capture(&mut capture, &policies, unix_time()),
        Err(SessionTransferError::Policy)
    ));
    assert!(matches!(
        frozen.validate_replacement(&mut replacement, &policies),
        Err(SessionTransferError::Policy)
    ));
    drop(policies);
    drop(frozen);
    let after = arrivals(&second.cache);
    assert_eq!(after.0, before.0);
    assert_eq!(after.1, before.1);
    assert!(Arc::ptr_eq(&after.2, &before.2));
    Ok(())
}

#[test]
fn poison_after_preparation_rejects_transfer_but_clear_still_retires_publication() -> TestResult<()>
{
    use btls::ssl::PreparedSessionPolicyFreeze;

    let fixture = Fixture::new(TicketOrder::Newest, 2, SslVersion::TLS1_3)?;
    let owner = fixture.cache.control().upgrade().ok_or("owner missing")?;
    let mut exports = TlsSessionOwner::capture_stores(&[(&owner, NAME)])?;
    let header = exports.pop().ok_or("empty source export missing")?.header();
    let mut capture_plan = owner.prepare_capture(NAME, 0)?;
    let mut replacement = owner.prepare_replacement(NAME.into(), header, Vec::new())?;
    let held_capture = fixture.cache.begin_handshake(NAME);
    let generation = Arc::clone(&held_capture.generation);
    let poisoned = Arc::clone(&fixture.cache.inner);
    let worker = std::thread::Builder::new()
        .name("poison-ticket-store".into())
        .spawn(move || {
            let _guard = poisoned
                .store
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            panic!("poison the owned store for the transfer control");
        })?;
    assert!(worker.join().is_err());
    assert!(matches!(
        owner.freeze_transfer(),
        Err(SessionTransferError::Policy)
    ));
    let binding = capture_plan.binding().clone();
    let bindings = [&binding];
    let native_plan = PreparedSessionPolicyFreeze::new(&bindings)?;
    let mut frozen = owner.freeze();
    let policies = native_plan.try_freeze()?;
    assert!(matches!(
        frozen.validate_capture(&mut capture_plan, &policies, unix_time()),
        Err(SessionTransferError::Policy)
    ));
    assert!(matches!(
        frozen.validate_replacement(&mut replacement, &policies),
        Err(SessionTransferError::Policy)
    ));
    drop(policies);
    assert!(Arc::ptr_eq(&generation, &frozen.store.generation));
    assert_eq!(frozen.retained_count(), 0);
    let retired = frozen.drain(Arc::new(()));
    drop(frozen);
    assert!(!held_capture.state().retired);
    assert_eq!(retired.finish(), 0);
    assert!(held_capture.state().retired);
    Ok(())
}

#[tokio::test]
async fn validated_commit_is_single_use_and_defers_old_sessions_and_capture_retirement()
-> TestResult<()> {
    use btls::ssl::PreparedSessionPolicyFreeze;

    let source = Fixture::new(TicketOrder::OldestConnection, 10, SslVersion::TLS1_3)?;
    let recipient = Fixture::new(TicketOrder::OldestConnection, 10, SslVersion::TLS1_3)?;
    source.seed(2).await?;
    recipient.seed(1).await?;
    let expected = arrivals(&source.cache);
    let old = arrivals(&recipient.cache);
    let pending = recipient.cache.begin_handshake(NAME);
    let mut replacement = source.prepare(&recipient)?;
    let owner = replacement.destination_owner();
    let binding = replacement.binding().clone();
    let bindings = [&binding];
    let native_plan = PreparedSessionPolicyFreeze::new(&bindings)?;
    let mut frozen = owner.freeze_transfer()?;
    let policies = native_plan.try_freeze()?;
    let token = frozen.validate_replacement(&mut replacement, &policies)?;
    assert_eq!(token.record_count(), expected.0.len());
    let retired = token.commit();
    let repeated_commit_rejected = matches!(
        frozen.validate_replacement(&mut replacement, &policies),
        Err(SessionTransferError::Policy)
    );
    drop(policies);
    drop(frozen);
    assert!(repeated_commit_rejected);
    let after = arrivals(&recipient.cache);
    assert_eq!(after.0, expected.0);
    assert_eq!(after.1, expected.1);
    assert!(!Arc::ptr_eq(&after.2, &old.2));
    assert!(!pending.state().retired);
    assert!(retired.finish() >= old.0.len());
    assert!(pending.state().retired);
    Ok(())
}

#[tokio::test]
async fn capture_preserves_input_order_and_physical_ordinals_without_consuming_sources()
-> TestResult<()> {
    let first = Fixture::new(TicketOrder::Oldest, 10, SslVersion::TLS1_3)?;
    let second = Fixture::new(TicketOrder::Newest, 2, SslVersion::TLS1_3)?;
    first.seed(2).await?;
    second.seed(1).await?;
    let before_first = arrivals(&first.cache);
    let before_second = arrivals(&second.cache);
    let first_owner = first
        .cache
        .control()
        .upgrade()
        .ok_or("first owner missing")?;
    let second_owner = second
        .cache
        .control()
        .upgrade()
        .ok_or("second owner missing")?;
    for inputs in [
        [(&first_owner, NAME), (&second_owner, NAME)],
        [(&second_owner, NAME), (&first_owner, NAME)],
    ] {
        let exports = TlsSessionOwner::capture_stores(&inputs)?;
        assert_eq!(exports.len(), 2);
        for ((owner, _), export) in inputs.into_iter().zip(exports) {
            let (expected_order, expected_arrivals) = if owner.same_cache(&first_owner) {
                (2, &before_first.0)
            } else {
                (0, &before_second.0)
            };
            let header = export.header();
            assert_eq!(header.order, expected_order);
            assert_eq!(usize::from(header.physical), expected_arrivals.len());
            let records = export.into_records();
            assert_eq!(records.len(), expected_arrivals.len());
            for (index, (record, expected)) in records.iter().zip(expected_arrivals).enumerate() {
                assert_eq!(usize::from(record.ordinal), index);
                assert_eq!(record.batch, expected.batch);
                assert_eq!(record.sequence, expected.sequence);
                assert_eq!(record.header, header);
            }
        }
    }
    for (cache, before) in [(&first.cache, before_first), (&second.cache, before_second)] {
        let after = arrivals(cache);
        assert_eq!(after.0, before.0);
        assert_eq!(after.1, before.1);
        assert!(Arc::ptr_eq(&after.2, &before.2));
    }
    Ok(())
}
