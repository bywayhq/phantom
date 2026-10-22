use super::{TcpAddresses, TcpCandidate};
#[cfg(feature = "https-records")]
use crate::host_resolver::DnsConfigurationToken;
use crate::host_resolver::address_feedback::AddressRecord;
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    num::NonZeroUsize,
    sync::Arc,
};

#[cfg(feature = "https-records")]
use std::sync::atomic::{AtomicBool, Ordering};

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn a(last: u8) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::new(127, 0, 0, last).into(), 0)
}
fn record() -> Arc<AddressRecord> {
    Arc::new(AddressRecord::new(
        vec![a(1), a(1), a(2)],
        NonZeroUsize::MIN,
    ))
}
fn addresses(record: &Arc<AddressRecord>) -> TcpAddresses {
    TcpAddresses::cached(vec![a(1), a(1), a(2)], Some(Arc::clone(record)), 443, None)
}
fn first(addresses: &TcpAddresses) -> Result<TcpCandidate, io::Error> {
    addresses
        .cursor()
        .next()
        .ok_or_else(|| io::Error::other("no candidate"))
}

#[test]
fn every_selection_observes_shared_failures_and_keeps_order() -> TestResult {
    let record = record();
    let addresses = addresses(&record);
    let mut other = addresses.cursor();
    first(&addresses)?.failed_connect()?;
    assert_eq!(
        other.next().ok_or("no second address")?.address(),
        SocketAddr::new(a(2).ip(), 443)
    );
    assert!(other.next().is_none());
    Ok(())
}

#[test]
fn refresh_rejects_an_old_connect_report_even_when_ip_is_unchanged() -> TestResult {
    let record = record();
    let addresses = addresses(&record);
    let selected = first(&addresses)?;
    record.refresh(vec![a(1), a(2)])?;
    selected.failed_connect()?;
    assert_eq!(first(&addresses)?.address().ip(), a(1).ip());
    Ok(())
}

#[test]
fn selected_address_does_not_keep_its_dns_record_alive() -> TestResult {
    let record = record();
    let addresses = addresses(&record);
    let selected = first(&addresses)?;
    let weak = Arc::downgrade(&record);
    drop(addresses);
    drop(record);
    assert!(weak.upgrade().is_none());
    selected.failed_connect()?;
    Ok(())
}

#[test]
fn capacity_failure_does_not_forget_an_existing_failure() -> TestResult {
    let record = record();
    let addresses = addresses(&record);
    first(&addresses)?.failed_connect()?;
    let second = first(&addresses)?;
    let error = match second.failed_connect() {
        Err(error) => error,
        Ok(()) => return Err("capacity unexpectedly grew".into()),
    };
    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert_eq!(first(&addresses)?.address().ip(), a(2).ip());
    Ok(())
}

#[cfg(feature = "https-records")]
#[test]
fn changed_configuration_cannot_poison_a_record() -> TestResult {
    let record = record();
    let current = Arc::new(AtomicBool::new(true));
    let observed = Arc::clone(&current);
    let token = DnsConfigurationToken::new(move || Ok(observed.load(Ordering::Acquire)));
    let addresses = TcpAddresses::cached(
        vec![a(1), a(2)],
        Some(Arc::clone(&record)),
        443,
        Some(token),
    );
    let selected = first(&addresses)?;
    current.store(false, Ordering::Release);
    selected.failed_connect()?;
    assert_eq!(
        record.cursor().next().ok_or("empty record")?.address(),
        a(1)
    );
    Ok(())
}

#[cfg(feature = "https-records")]
#[test]
fn terminal_configuration_cannot_poison_a_record() -> TestResult {
    let record = record();
    let token = DnsConfigurationToken::new(|| {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "watch stopped"))
    });
    let addresses = TcpAddresses::cached(
        vec![a(1), a(2)],
        Some(Arc::clone(&record)),
        443,
        Some(token),
    );
    first(&addresses)?.failed_connect()?;
    assert_eq!(
        record.cursor().next().ok_or("empty record")?.address(),
        a(1)
    );
    Ok(())
}

#[test]
fn querying_an_absent_family_does_not_reset_other_family_history() -> TestResult {
    let v6 = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0);
    let record = Arc::new(AddressRecord::new(vec![a(1), v6], NonZeroUsize::MIN));
    let addresses = TcpAddresses::cached(vec![a(1), v6], Some(record), 443, None);
    first(&addresses)?.failed_connect()?;
    assert!(addresses.cursor().next_matching(Some(false)).is_none());
    assert!(first(&addresses)?.address().is_ipv6());
    Ok(())
}

#[test]
fn fresh_all_blocked_traversal_resets_but_exhausted_traversal_stays_done() -> TestResult {
    let record = Arc::new(AddressRecord::new(vec![a(1)], NonZeroUsize::MIN));
    let addresses = addresses(&record);
    let mut cursor = addresses.cursor();
    cursor.next().ok_or("empty record")?.failed_connect()?;
    assert!(cursor.next().is_none());
    assert_eq!(first(&addresses)?.address().ip(), a(1).ip());
    record.refresh(vec![a(2)])?;
    assert!(cursor.next().is_none());
    Ok(())
}

#[test]
fn caller_port_preserves_ipv6_scope_and_flow() -> TestResult {
    let scoped = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 7, 9));
    let record = Arc::new(AddressRecord::new(vec![scoped], NonZeroUsize::MIN));
    let addresses = TcpAddresses::cached(vec![scoped], Some(record), 8443, None);
    assert_eq!(
        first(&addresses)?.address(),
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8443, 7, 9))
    );
    Ok(())
}

#[test]
fn dropping_a_selection_without_connect_failure_leaves_history_untouched() -> TestResult {
    let record = record();
    let addresses = addresses(&record);
    drop(first(&addresses)?);
    assert_eq!(first(&addresses)?.address().ip(), a(1).ip());
    Ok(())
}

#[tokio::test]
async fn uncached_and_override_lookups_do_not_create_retained_failure_history() -> TestResult {
    use crate::host_resolver::{AddressResolver, HostResolver, resolve_tcp};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let resolver = HostResolver::new().with_resolver(AddressResolver::from_fn(move |_| {
        observed.fetch_add(1, Ordering::SeqCst);
        async { Ok(vec![a(1).ip(), a(2).ip()]) }
    }));
    for _ in 0..2 {
        let addresses = resolve_tcp(Some(&resolver), "origin.test", 443).await?;
        assert_eq!(first(&addresses)?.address().ip(), a(1).ip());
        first(&addresses)?.failed_connect()?;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let resolver = resolver.with_override("origin.test", [a(2).ip(), a(1).ip()]);
    for _ in 0..2 {
        let addresses = resolve_tcp(Some(&resolver), "origin.test", 443).await?;
        assert_eq!(first(&addresses)?.address().ip(), a(2).ip());
        first(&addresses)?.failed_connect()?;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[test]
fn policy_sees_actual_port_outside_record_lock_without_changing_dns_history() -> TestResult {
    let record = record();
    let observed = Arc::clone(&record);
    let policy = crate::DestinationPolicy::from_fn(move |address| {
        assert_eq!(address.port(), 443);
        // Taking another cursor needs the same record lock as selection.
        assert!(observed.cursor().next().is_some());
        address.ip() == a(2).ip()
    });
    let filtered = addresses(&record).with_destination_policy(Some(&policy));
    assert_eq!(first(&filtered)?.address().ip(), a(2).ip());
    assert!(filtered.admission().ok_or("no observation")?.denied());
    assert_eq!(first(&addresses(&record))?.address().ip(), a(1).ip());
    Ok(())
}

#[test]
fn policy_keeps_allowed_order_and_ipv6_scope() -> TestResult {
    let scoped = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8443, 7, 9));
    let policy = crate::DestinationPolicy::from_fn(move |address| address != a(1));
    let addresses =
        TcpAddresses::from(vec![a(1), scoped, a(2), a(3)]).with_destination_policy(Some(&policy));
    let mut cursor = addresses.cursor();
    assert_eq!(cursor.next().ok_or("no scoped address")?.address(), scoped);
    assert_eq!(cursor.next().ok_or("no second address")?.address(), a(2));
    assert_eq!(cursor.next().ok_or("no third address")?.address(), a(3));
    assert!(cursor.next().is_none());
    Ok(())
}

#[tokio::test]
async fn resolving_names_does_not_invoke_the_connection_policy() -> TestResult {
    use crate::host_resolver::{AddressResolver, HostResolver, resolve};
    let resolver = HostResolver::new()
        .with_destination_policy(crate::DestinationPolicy::from_fn(|_| {
            panic!("lookup applied connection admission")
        }))
        .with_resolver(AddressResolver::from_fn(|_| async { Ok(vec![a(2).ip()]) }))
        .with_override("override.test", [a(1).ip()]);
    assert_eq!(
        resolve(Some(&resolver), "override.test", 8443).await?,
        [SocketAddr::new(a(1).ip(), 8443)]
    );
    assert_eq!(
        resolve(Some(&resolver), "callback.test", 443).await?,
        [SocketAddr::new(a(2).ip(), 443)]
    );
    Ok(())
}
