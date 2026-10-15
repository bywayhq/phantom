use super::*;
use phantom_profile::SystemDnsTtlPolicy;

#[test]
fn native_dns_ttl_policy_changes_the_ticket_binding() -> TestResult {
    let mut settings = chrome::v154_dns_cache();
    let mut previous = None;
    for policy in [
        SystemDnsTtlPolicy::Ignore,
        SystemDnsTtlPolicy::FirefoxWindows,
    ] {
        settings.system_ttl = policy;
        let mut encoder = Encoder::new();
        super::super::http::dns(&mut encoder, &settings)?;
        let current = encoder.finish();
        if let Some(previous) = previous {
            assert_ne!(previous, current);
        }
        previous = Some(current);
    }
    Ok(())
}
