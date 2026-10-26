use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};

use super::DestinationPolicy;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn public_only_rejects_special_ipv4_ranges_and_mapped_forms() -> TestResult {
    let policy = DestinationPolicy::public_only();
    // First and last addresses of IANA special-purpose blocks, plus multicast.
    for (first, last) in [
        ("0.0.0.0", "0.255.255.255"),
        ("10.0.0.0", "10.255.255.255"),
        ("100.64.0.0", "100.127.255.255"),
        ("127.0.0.0", "127.255.255.255"),
        ("169.254.0.0", "169.254.255.255"),
        ("172.16.0.0", "172.31.255.255"),
        ("192.0.0.0", "192.0.0.255"),
        ("192.0.2.0", "192.0.2.255"),
        ("192.31.196.0", "192.31.196.255"),
        ("192.52.193.0", "192.52.193.255"),
        ("192.88.99.0", "192.88.99.255"),
        ("192.168.0.0", "192.168.255.255"),
        ("192.175.48.0", "192.175.48.255"),
        ("198.18.0.0", "198.19.255.255"),
        ("198.51.100.0", "198.51.100.255"),
        ("203.0.113.0", "203.0.113.255"),
        ("224.0.0.0", "239.255.255.255"),
        ("240.0.0.0", "255.255.255.255"),
    ] {
        for text in [first, last] {
            let address = text.parse::<std::net::Ipv4Addr>()?;
            assert!(
                !policy.permits(SocketAddr::new(address.into(), 443)),
                "{text}"
            );
            assert!(
                !policy.permits(SocketAddr::new(address.to_ipv6_mapped().into(), 443)),
                "mapped {text}"
            );
        }
    }
    Ok(())
}

#[test]
fn public_only_rejects_ipv6_special_transition_and_scoped_destinations() -> TestResult {
    let policy = DestinationPolicy::public_only();
    for text in [
        "::",
        "::1",
        "::127.0.0.1",
        "64:ff9b::7f00:1",
        "64:ff9b:1::1",
        "100::1",
        "100:0:0:1::1",
        "2001::1",
        "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff",
        "2001:db8::",
        "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
        "2002::",
        "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "2620:4f:8000::",
        "2620:4f:8000:ffff:ffff:ffff:ffff:ffff",
        "3fff::",
        "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff",
        "4000::",
        "5f00::1",
        "fc00::1",
        "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "fe80::1",
        "fec0::1",
        "ff02::1",
    ] {
        assert!(
            !policy.permits(SocketAddr::new(text.parse()?, 443)),
            "{text}"
        );
    }
    for ip in [
        "2606:4700:4700::1111".parse::<Ipv6Addr>()?,
        "::ffff:8.8.8.8".parse()?,
    ] {
        assert!(!policy.permits(SocketAddr::V6(SocketAddrV6::new(ip, 443, 0, 1))));
    }
    Ok(())
}

#[test]
fn public_only_permits_ordinary_public_addresses_on_either_transport_port() -> TestResult {
    let policy = DestinationPolicy::public_only();
    for text in [
        "1.1.1.1",
        "8.8.8.8",
        "100.63.255.255",
        "100.128.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "192.0.1.255",
        "192.0.3.0",
        "198.17.255.255",
        "198.20.0.0",
        "223.255.255.255",
        "2001:200::1",
        "2001:4860:4860::8888",
        "2606:4700:4700::1111",
        "3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "3fff:1000::1",
        "::ffff:8.8.8.8",
    ] {
        let address = text.parse::<IpAddr>()?;
        for port in [80, 443, 8443] {
            assert!(
                policy.permits(SocketAddr::new(address, port)),
                "{text}:{port}"
            );
        }
    }
    Ok(())
}
