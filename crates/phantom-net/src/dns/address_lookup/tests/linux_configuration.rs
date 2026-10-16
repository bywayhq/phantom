use super::*;
use crate::dns::{
    address_lookup::{Ipv6Route, SystemResolver},
    linux_configuration::LinuxDnsConfiguration,
};

fn configured(servers: Vec<SocketAddr>, rotate: bool) -> TestResult<AddressLookup> {
    let mut lookup = AddressLookup::from_linux_configuration(&LinuxDnsConfiguration {
        servers,
        search: vec!["missing.test".into(), "answer.test".into()],
        ndots: 2,
        attempts: 1,
        rotate,
    })?;
    lookup.hosts = Arc::new(hickory_resolver::Hosts::default());
    lookup.ipv6 = Arc::new(Ipv6Route::Fixed(false));
    lookup.system = SystemResolver::Fixed(vec![SYSTEM]);
    Ok(lookup)
}

#[tokio::test]
async fn linux_intake_applies_suffixes_and_server_order_to_each_udp_view() -> TestResult {
    let mut first = DnsServer::spawn(|query: &DnsQuery| {
        if query.name().ends_with("missing.test") {
            DnsReply::new(DnsAnswer::NoData {
                soa_minimum: Some(1),
            })
        } else {
            DnsReply::new(DnsAnswer::Records {
                ttl: 7,
                rdata: vec![V4.octets().to_vec()],
            })
        }
    })
    .await?;
    let mut second = DnsServer::spawn(records(7, 7)).await?;
    let lookup = configured(vec![first.address(), second.address()], false)?;
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        for lookup in [
            lookup.with_udp_settings(UdpSettings {
                port_randomization: false,
            }),
            lookup.with_udp_settings(UdpSettings {
                port_randomization: true,
            }),
            lookup,
        ] {
            let resolved = lookup.resolve("printer").await?;
            assert_eq!(ips(legacy_parts(&resolved).0), [IpAddr::V4(V4)]);
            assert_eq!(legacy_parts(&resolved).1, Some(Duration::from_secs(7)));
        }
        Ok::<_, Box<dyn Error>>(())
    })
    .await;
    let queries = first.queries();
    let unexpected = second.queries();
    first.finish().await?;
    second.finish().await?;
    result??;
    assert!(unexpected.is_empty());
    assert_eq!(
        queries.iter().map(DnsQuery::name).collect::<Vec<_>>(),
        ["printer.missing.test", "printer.answer.test"].repeat(3)
    );
    assert!(queries.iter().all(|query| query.record_type() == TYPE_A
        && query.flags() == 0x0100
        && query.counts() == [1, 0, 0, 0]));
    Ok(())
}

#[tokio::test]
async fn linux_rotate_uses_both_configured_servers_for_cold_queries() -> TestResult {
    let mut first = DnsServer::spawn(records(7, 7)).await?;
    let mut second = DnsServer::spawn(records(7, 7)).await?;
    let lookup = configured(vec![first.address(), second.address()], true)?;
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        for index in 0..8 {
            let resolved = lookup
                .resolve(&format!("cold{index}.example.test."))
                .await?;
            assert_eq!(
                ips(legacy_parts(&resolved).0),
                [IpAddr::V4(V4), IpAddr::V4(V4_OTHER)]
            );
        }
        Ok::<_, Box<dyn Error>>(())
    })
    .await;
    let counts = (first.queries().len(), second.queries().len());
    first.finish().await?;
    second.finish().await?;
    result??;
    assert_eq!(counts, (4, 4));
    Ok(())
}
