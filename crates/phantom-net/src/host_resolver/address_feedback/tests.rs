use std::{
    error::Error,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    num::NonZeroUsize,
    sync::{Arc, Barrier},
    thread,
};

use super::{AddressCursor, AddressRecord, FeedbackResourceError, ReportOutcome, SelectedAddress};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn address(last: u8, port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(127, 0, 0, last), port))
}

fn record(addresses: Vec<SocketAddr>, capacity: usize) -> TestResult<Arc<AddressRecord>> {
    let capacity = NonZeroUsize::new(capacity).ok_or("test requires a nonzero capacity")?;
    Ok(Arc::new(AddressRecord::new(addresses, capacity)))
}

fn selected(cursor: &mut AddressCursor) -> TestResult<SelectedAddress> {
    cursor
        .next()
        .ok_or_else(|| "expected a selected address".into())
}

#[test]
fn source_order_duplicates_and_complete_socket_addresses_are_preserved() -> TestResult {
    let scoped = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 17, 9));
    let addresses = vec![address(2, 443), scoped, address(2, 443), address(3, 8443)];
    let record = record(addresses.clone(), 4)?;
    let mut cursor = record.cursor();
    let actual: Vec<_> = std::iter::from_fn(|| cursor.next().map(|item| item.address())).collect();
    assert_eq!(actual, addresses);
    assert!(cursor.next().is_none());
    Ok(())
}

#[test]
fn failure_identity_ignores_port_scope_and_flow_but_preserves_ip_family() -> TestResult {
    let ip = "fe80::1".parse()?;
    let first = SocketAddr::V6(SocketAddrV6::new(ip, 443, 17, 2));
    let same_ip = SocketAddr::V6(SocketAddrV6::new(ip, 8443, 23, 3));
    let ipv4 = address(2, 443);
    let mapped = SocketAddr::V6(SocketAddrV6::new(
        Ipv4Addr::new(127, 0, 0, 2).to_ipv6_mapped(),
        443,
        0,
        0,
    ));
    let record = record(vec![first, same_ip, ipv4, address(2, 8443), mapped], 3)?;
    let mut cursor = record.cursor();
    let first_selected = selected(&mut cursor)?;
    assert_eq!(first_selected.address(), first);
    assert_eq!(
        record.report_unusable(&first_selected)?,
        ReportOutcome::Added
    );
    let next = selected(&mut cursor)?;
    assert_eq!(next.address(), ipv4);
    assert_eq!(record.report_unusable(&next)?, ReportOutcome::Added);
    assert_eq!(selected(&mut cursor)?.address(), mapped);
    assert_eq!(record.lock().unusable.len(), 2);
    Ok(())
}

#[test]
fn refresh_preserves_history_and_restarts_an_unexhausted_cursor() -> TestResult {
    let record = record(vec![address(2, 443), address(3, 443)], 3)?;
    let mut cursor = record.cursor();
    let failed = selected(&mut cursor)?;
    record.report_unusable(&failed)?;
    record.refresh(vec![address(2, 8443), address(4, 443), address(3, 443)])?;
    assert_eq!(selected(&mut cursor)?.address(), address(4, 443));
    assert_eq!(selected(&mut cursor)?.address(), address(3, 443));
    assert!(cursor.next().is_none());
    assert_eq!(record.lock().unusable, [address(2, 443).ip()]);
    Ok(())
}

#[test]
fn stale_generation_cannot_report_even_when_the_ip_remains_in_the_answer() -> TestResult {
    let record = record(vec![address(2, 443), address(3, 443)], 2)?;
    let old = selected(&mut record.cursor())?;
    record.refresh(vec![address(2, 8443), address(3, 443)])?;
    assert_eq!(record.report_unusable(&old)?, ReportOutcome::Stale);
    assert!(record.lock().unusable.is_empty());
    let current = selected(&mut record.cursor())?;
    assert_eq!(current.address(), address(2, 8443));
    assert_eq!(record.report_unusable(&current)?, ReportOutcome::Added);
    Ok(())
}

#[test]
fn an_exhausted_cursor_stays_exhausted_across_refresh() -> TestResult {
    let record = record(vec![address(2, 443)], 1)?;
    let mut cursor = record.cursor();
    selected(&mut cursor)?;
    assert!(cursor.next().is_none());
    record.refresh(vec![address(3, 443)])?;
    assert!(cursor.next().is_none());
    assert_eq!(selected(&mut record.cursor())?.address(), address(3, 443));
    Ok(())
}

#[test]
fn replacement_and_clear_isolate_old_owners_and_witnesses() -> TestResult {
    let old = record(vec![address(2, 443), address(3, 443)], 2)?;
    let mut old_cursor = old.cursor();
    let old_selected = selected(&mut old_cursor)?;
    let mut cache_slot = Some(Arc::clone(&old));
    let replacement = record(vec![address(2, 443), address(3, 443)], 2)?;
    let retired = cache_slot.replace(Arc::clone(&replacement));
    assert!(retired.is_some());
    assert_eq!(
        replacement.report_unusable(&old_selected)?,
        ReportOutcome::Stale
    );
    assert_eq!(old.report_unusable(&old_selected)?, ReportOutcome::Added);
    assert!(replacement.lock().unusable.is_empty());
    let replacement_selected = selected(&mut replacement.cursor())?;
    assert_eq!(replacement_selected.address(), address(2, 443));
    let cleared = cache_slot.take();
    assert!(cleared.is_some());
    let after_clear = record(vec![address(2, 443), address(3, 443)], 2)?;
    assert_eq!(
        after_clear.report_unusable(&replacement_selected)?,
        ReportOutcome::Stale
    );
    replacement.report_unusable(&replacement_selected)?;
    assert!(after_clear.lock().unusable.is_empty());
    assert_eq!(selected(&mut old_cursor)?.address(), address(3, 443));
    Ok(())
}

#[test]
fn a_dropped_record_witness_cannot_target_another_record() -> TestResult {
    let old = record(vec![address(2, 443)], 1)?;
    let witness = selected(&mut old.cursor())?;
    drop(old);
    assert!(witness.record.upgrade().is_none());
    let replacement = record(vec![address(2, 443)], 1)?;
    assert_eq!(replacement.report_unusable(&witness)?, ReportOutcome::Stale);
    assert!(replacement.lock().unusable.is_empty());
    Ok(())
}

#[test]
fn only_a_fresh_all_blocked_traversal_resets_shared_history() -> TestResult {
    let record = record(vec![address(2, 443), address(3, 443)], 2)?;
    let mut cursor = record.cursor();
    let first = selected(&mut cursor)?;
    record.report_unusable(&first)?;
    let second = selected(&mut cursor)?;
    record.report_unusable(&second)?;
    assert!(cursor.next().is_none());
    assert_eq!(record.lock().unusable.len(), 2);
    let mut fresh = record.cursor();
    assert_eq!(selected(&mut fresh)?.address(), address(2, 443));
    assert!(record.lock().unusable.is_empty());
    assert_eq!(selected(&mut fresh)?.address(), address(3, 443));
    assert!(cursor.next().is_none());
    Ok(())
}

#[test]
fn a_successful_unreported_selection_does_not_remove_prior_failures() -> TestResult {
    let record = record(vec![address(2, 443), address(3, 443)], 2)?;
    let mut cursor = record.cursor();
    let failed = selected(&mut cursor)?;
    record.report_unusable(&failed)?;
    let successful = selected(&mut cursor)?;
    assert_eq!(successful.address(), address(3, 443));
    drop(successful);
    assert_eq!(selected(&mut record.cursor())?.address(), address(3, 443));
    assert_eq!(record.lock().unusable, [address(2, 443).ip()]);
    Ok(())
}

#[test]
fn duplicate_reports_succeed_at_capacity_and_unique_overflow_preserves_history() -> TestResult {
    let record = record(vec![address(2, 443), address(3, 443)], 1)?;
    let mut cursor = record.cursor();
    let first = selected(&mut cursor)?;
    let second = selected(&mut cursor)?;
    assert_eq!(record.report_unusable(&first)?, ReportOutcome::Added);
    assert_eq!(record.report_unusable(&first)?, ReportOutcome::AlreadyKnown);
    let result = record.report_unusable(&second);
    assert!(
        matches!(result, Err(FeedbackResourceError::HistoryCapacity { limit }) if limit == NonZeroUsize::MIN)
    );
    assert_eq!(record.lock().unusable, [address(2, 443).ip()]);
    assert_eq!(record.lock().generation, 0);
    assert_eq!(selected(&mut record.cursor())?.address(), address(3, 443));
    assert!(cursor.next().is_none());
    Ok(())
}

#[test]
fn generation_exhaustion_leaves_answer_history_and_current_witness_intact() -> TestResult {
    let record = record(vec![address(2, 443), address(3, 443)], 2)?;
    record.lock().generation = u64::MAX;
    let mut cursor = record.cursor();
    let failed = selected(&mut cursor)?;
    record.report_unusable(&failed)?;
    let current = selected(&mut cursor)?;
    assert!(matches!(
        record.refresh(vec![address(4, 443)]),
        Err(FeedbackResourceError::GenerationExhausted)
    ));
    assert_eq!(record.lock().generation, u64::MAX);
    assert_eq!(record.lock().addresses, [address(2, 443), address(3, 443)]);
    assert_eq!(record.lock().unusable, [address(2, 443).ip()]);
    assert_eq!(record.report_unusable(&current)?, ReportOutcome::Added);
    Ok(())
}

#[test]
fn concurrent_cursors_share_deduplicated_history_without_changing_order() -> TestResult {
    let record = record(vec![address(2, 443), address(3, 443)], 2)?;
    let ready = Barrier::new(2);
    let results = thread::scope(|scope| {
        let run = || {
            let mut cursor = record.cursor();
            let first = cursor.next();
            ready.wait();
            let report = first.as_ref().map(|item| record.report_unusable(item));
            let second = cursor.next().map(|item| item.address());
            (first.map(|item| item.address()), report, second)
        };
        let first = thread::Builder::new().spawn_scoped(scope, run)?;
        let second = match thread::Builder::new().spawn_scoped(scope, run) {
            Ok(second) => second,
            Err(spawn_error) => {
                // The first worker must leave the two-party barrier before
                // scope cleanup can join it when the second cannot start.
                ready.wait();
                let cleanup = first.join();
                return Err::<_, Box<dyn Error>>(match cleanup {
                    Ok((_, Some(Err(error)), _)) => format!(
                        "second cursor worker could not start: {spawn_error}; first worker feedback failed: {error}"
                    )
                    .into(),
                    Ok(_) => spawn_error.into(),
                    Err(_) => format!(
                        "second cursor worker could not start: {spawn_error}; first worker panicked during cleanup"
                    )
                    .into(),
                });
            }
        };
        Ok([first.join(), second.join()])
    })?;
    let mut outcomes = Vec::new();
    for result in results {
        let (first, report, second) =
            result.map_err(|_| io::Error::other("cursor thread panicked"))?;
        assert_eq!(first, Some(address(2, 443)));
        outcomes.push(report.ok_or("missing report")??);
        assert_eq!(second, Some(address(3, 443)));
    }
    assert_eq!(
        outcomes
            .iter()
            .filter(|&&item| item == ReportOutcome::Added)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|&&item| item == ReportOutcome::AlreadyKnown)
            .count(),
        1
    );
    assert_eq!(record.lock().unusable, [address(2, 443).ip()]);
    Ok(())
}

#[test]
fn refresh_invalidates_a_report_held_by_another_thread() -> TestResult {
    let record = record(vec![address(2, 443)], 1)?;
    let witness = selected(&mut record.cursor())?;
    let ready = Barrier::new(2);
    let result = thread::scope(|scope| {
        let report = scope.spawn(|| {
            ready.wait();
            record.report_unusable(&witness)
        });
        let refresh = record.refresh(vec![address(2, 8443)]);
        ready.wait();
        (refresh, report.join())
    });
    result.0?;
    assert_eq!(
        result
            .1
            .map_err(|_| io::Error::other("report thread panicked"))??,
        ReportOutcome::Stale
    );
    assert!(record.lock().unusable.is_empty());
    Ok(())
}

#[test]
fn empty_records_exhaust_and_a_new_cursor_can_read_a_later_answer() -> TestResult {
    let record = record(Vec::new(), 1)?;
    let mut cursor = record.cursor();
    assert!(cursor.next().is_none());
    record.refresh(vec![address(2, 443)])?;
    assert!(cursor.next().is_none());
    assert_eq!(selected(&mut record.cursor())?.address(), address(2, 443));
    Ok(())
}

#[test]
fn allocation_errors_keep_the_original_cause_and_debug_omits_addresses() -> TestResult {
    // Capacity overflow exercises the same typed reservation error, without
    // exhausting process memory or claiming to simulate a real OOM.
    let mut bytes = Vec::<u8>::new();
    let reserve_error = match bytes.try_reserve(usize::MAX) {
        Err(error) => error,
        Ok(()) => return Err("capacity overflow unexpectedly succeeded".into()),
    };
    let error = FeedbackResourceError::Allocation(reserve_error);
    assert!(error.source().is_some());
    assert_eq!(
        error.to_string(),
        "could not allocate DNS address failure history"
    );
    let record = record(vec![address(2, 443)], 1)?;
    let cursor = record.cursor();
    let selected = selected(&mut record.cursor())?;
    for debug in [
        format!("{record:?}"),
        format!("{cursor:?}"),
        format!("{selected:?}"),
    ] {
        assert!(!debug.contains("127.0.0.2"));
    }
    Ok(())
}

#[test]
fn an_absent_family_preserves_an_all_blocked_records_history() -> TestResult {
    let ipv6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 443));
    let record = record(vec![ipv6], 1)?;
    let failed = selected(&mut record.cursor())?;
    assert_eq!(failed.report_unusable()?, ReportOutcome::Added);
    assert!(record.cursor().next_matching(SocketAddr::is_ipv4).is_none());
    assert_eq!(record.lock().unusable, [ipv6.ip()]);
    assert_eq!(failed.report_unusable()?, ReportOutcome::AlreadyKnown);
    assert_eq!(selected(&mut record.cursor())?.address(), ipv6);
    assert!(record.lock().unusable.is_empty());
    Ok(())
}

#[test]
fn a_source_filter_accepting_no_address_preserves_all_blocked_history() -> TestResult {
    let addresses = vec![address(2, 443), address(3, 443)];
    let record = record(addresses.clone(), 2)?;
    let mut initial = record.cursor();
    let first = selected(&mut initial)?;
    let second = selected(&mut initial)?;
    assert_eq!(first.report_unusable()?, ReportOutcome::Added);
    assert_eq!(second.report_unusable()?, ReportOutcome::Added);
    assert!(record.cursor().next_matching(|_| false).is_none());
    assert_eq!(
        record.lock().unusable,
        [addresses[0].ip(), addresses[1].ip()]
    );
    assert_eq!(first.report_unusable()?, ReportOutcome::AlreadyKnown);
    assert_eq!(second.report_unusable()?, ReportOutcome::AlreadyKnown);
    Ok(())
}
