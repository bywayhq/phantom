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
