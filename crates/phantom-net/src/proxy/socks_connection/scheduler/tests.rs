use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn address(value: &str) -> Result<Target, Box<dyn std::error::Error>> {
    Ok(Target::Address(value.parse()?))
}
fn collect(mut targets: Targets) -> Vec<(Option<bool>, Option<Duration>, bool)> {
    let mut observed = Vec::new();
    while let Some((target, timeout)) = targets.next() {
        observed.push((target.ipv6(), timeout, targets.switched));
    }
    observed
}
#[test]
fn unknown_family_preserves_primary_order_and_limits_backup_to_ipv4() -> TestResult {
    let (primary, backup) = plans(
        vec![
            address("[::1]:443")?,
            address("127.0.0.1:443")?,
            address("[::2]:443")?,
        ],
        None,
        Some(Duration::from_secs(1)),
    );
    assert_eq!(
        collect(primary),
        vec![
            (Some(true), None, false),
            (Some(false), None, false),
            (Some(true), None, false)
        ]
    );
    assert_eq!(collect(backup), vec![(Some(false), None, false)]);
    Ok(())
}
#[test]
fn remembered_family_timeout_covers_each_complete_backup_before_switch() -> TestResult {
    let timeout = Some(Duration::from_secs(1));
    let (primary, backup) = plans(
        vec![
            address("127.0.0.1:443")?,
            address("[::1]:443")?,
            address("[::2]:443")?,
        ],
        Some(AddressFamily::Ipv6),
        timeout,
    );
    assert_eq!(
        collect(primary),
        vec![
            (Some(true), None, false),
            (Some(true), None, false),
            (Some(false), None, true)
        ]
    );
    assert_eq!(
        collect(backup),
        vec![
            (Some(true), timeout, false),
            (Some(true), timeout, false),
            (Some(false), None, true)
        ]
    );
    Ok(())
}
#[test]
fn absent_remembered_family_switches_without_a_fake_attempt() -> TestResult {
    let (primary, backup) = plans(
        vec![address("127.0.0.1:443")?],
        Some(AddressFamily::Ipv6),
        Some(Duration::from_secs(1)),
    );
    let expected = vec![(Some(false), None, true)];
    assert_eq!(collect(primary), expected);
    assert_eq!(collect(backup), expected);
    Ok(())
}
#[test]
fn remote_targets_are_not_filtered_by_a_synthetic_family() {
    let (primary, backup) = plans(
        vec![Target::Remote("remote.test".into(), 443)],
        Some(AddressFamily::Ipv6),
        None,
    );
    assert_eq!(collect(primary), vec![(None, None, false)]);
    assert_eq!(collect(backup), vec![(None, None, false)]);
}
#[test]
fn recording_a_switched_target_replaces_only_the_logical_family() -> TestResult {
    let memory = AddressFamilyMemory::default();
    memory.remember(AddressFamily::Ipv6);
    memory.record_connection(&"127.0.0.1:443".parse()?, false);
    assert_eq!(memory.family(), Some(AddressFamily::Ipv6));
    memory.record_connection(&"127.0.0.1:443".parse()?, true);
    assert_eq!(memory.family(), Some(AddressFamily::Ipv4));
    Ok(())
}
