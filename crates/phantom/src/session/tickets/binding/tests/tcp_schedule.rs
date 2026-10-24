use phantom_profile::{ClientProfile, TcpKeepalivePolicy, browser::firefox};

use super::{TestResult, profile};

#[test]
fn schedule_socket_setters_have_distinct_ticket_policies() -> TestResult {
    let mut policies = Vec::new();
    for (set_interval, set_probe_count) in
        [(false, false), (false, true), (true, false), (true, true)]
    {
        let mut tcp = firefox::v157_tcp();
        let TcpKeepalivePolicy::Schedule(mut schedule) = tcp.keepalive else {
            return Err("Firefox TCP policy must use scheduled keepalive".into());
        };
        schedule.set_interval = set_interval;
        schedule.set_probe_count = set_probe_count;
        tcp.keepalive = TcpKeepalivePolicy::Schedule(schedule);
        let recipe = ClientProfile::new(firefox::v157_tcp_tls()).with_tcp(tcp);
        let encoded = profile::encode(&recipe, None, None)?;

        assert!(policies.iter().all(|previous| previous != &encoded));
        policies.push(encoded);
    }
    assert_eq!(policies.len(), 4);
    Ok(())
}

#[test]
fn socks_proxy_dns_feedback_has_distinct_ticket_policies() -> TestResult {
    let mut tcp = firefox::v157_tcp();
    let encode = |settings| {
        profile::encode(
            &ClientProfile::new(firefox::v157_tcp_tls()).with_tcp(settings),
            None,
            None,
        )
    };
    let original = encode(tcp)?;
    let phantom_profile::TcpAddressSelection::Backup(ref mut backup) = tcp.address_selection else {
        return Err("Firefox TCP backup policy absent".into());
    };
    backup.socks_proxy_dns_feedback =
        phantom_profile::SocksProxyDnsFeedback::InitialConnectFailures;
    assert_ne!(original, encode(tcp)?);
    assert_eq!(firefox::v157_windows_r2().tcp(), Some(&firefox::v157_tcp()));
    assert_eq!(firefox::v157_windows().tcp(), Some(&tcp));
    Ok(())
}
