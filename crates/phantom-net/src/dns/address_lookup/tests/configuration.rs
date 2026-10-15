use super::*;
use crate::dns::address_lookup::SearchPolicy;

fn search(append: bool) -> SearchPolicy {
    SearchPolicy {
        suffixes: vec!["missing.test".into(), "answer.test".into()],
        ndots: 1,
        append_to_multi_label: append,
    }
}

fn names(policy: &SearchPolicy, host: &str) -> io::Result<Vec<String>> {
    Ok(policy
        .names(host)?
        .iter()
        .map(|name| name.to_ascii())
        .collect())
}

#[test]
fn search_order_preserves_ndots_append_and_absolute_name_rules() -> TestResult {
    assert_eq!(
        names(&search(false), "printer")?,
        ["printer.missing.test.", "printer.answer.test."]
    );
    assert_eq!(names(&search(false), "www.example")?, ["www.example."]);
    assert_eq!(
        names(&search(true), "www.example")?,
        [
            "www.example.",
            "www.example.missing.test.",
            "www.example.answer.test."
        ]
    );
    assert_eq!(names(&search(true), "printer.")?, ["printer."]);
    assert!(names(&search(true), "printer.local")?.is_empty());
    Ok(())
}

#[test]
fn invalid_search_combinations_are_skipped_without_changing_valid_order() -> TestResult {
    let mut policy = search(true);
    policy.suffixes.insert(1, "a".repeat(64));
    assert_eq!(
        names(&policy, "printer")?,
        ["printer.missing.test.", "printer.answer.test."]
    );
    assert!(names(&policy, &"a".repeat(64)).is_err());
    policy.suffixes.clear();
    assert!(names(&policy, "printer")?.is_empty());
    Ok(())
}

#[tokio::test]
async fn search_suffix_queries_retain_family_order_and_answer_ttl() -> TestResult {
    let mut server = DnsServer::spawn(|query: &DnsQuery| {
        if query.name() == "printer.missing.test" {
            DnsReply::new(DnsAnswer::NoData {
                soa_minimum: Some(1),
            })
        } else if query.record_type() == TYPE_AAAA {
            DnsReply::new(DnsAnswer::Records {
                ttl: 9,
                rdata: vec![V6.octets().to_vec()],
            })
        } else {
            DnsReply::new(DnsAnswer::Records {
                ttl: 7,
                rdata: vec![V4.octets().to_vec()],
            })
        }
    })
    .await?;
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let mut lookup = lookup(&server, true)?;
        lookup.search = Some(Arc::new(search(true)));
        Ok::<_, Box<dyn Error>>(lookup.resolve("printer").await?)
    })
    .await;
    let queries = server.queries();
    server.finish().await?;
    let resolved = result??;
    let (addresses, lifetime) = resolved.into_parts();
    assert_eq!(ips(&addresses?), [IpAddr::V6(V6), IpAddr::V4(V4)]);
    assert!(
        matches!(lifetime, crate::host_resolver::CacheLifetime::Legacy(Some(ttl)) if ttl == Duration::from_secs(7))
    );
    assert_eq!(
        queries
            .iter()
            .map(|query| (query.name(), query.record_type()))
            .collect::<Vec<_>>(),
        [
            ("printer.missing.test", TYPE_AAAA),
            ("printer.missing.test", TYPE_A),
            ("printer.answer.test", TYPE_AAAA),
            ("printer.answer.test", TYPE_A),
        ]
    );
    assert!(
        queries
            .iter()
            .all(|query| query.flags() == 0x0100 && query.counts() == [1, 0, 0, 0])
    );
    Ok(())
}

#[tokio::test]
async fn configured_local_ipv6_queries_aaaa_without_an_ipv6_route_probe() -> TestResult {
    let mut server = DnsServer::spawn(records(9, 7)).await?;
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let mut lookup = lookup(&server, false)?;
        lookup.use_local_ipv6 = true;
        Ok::<_, Box<dyn Error>>(lookup.resolve("origin.example.test").await?)
    })
    .await;
    let queries = server.queries();
    server.finish().await?;
    let resolved = result??;
    let (addresses, _) = resolved.into_parts();
    assert_eq!(
        ips(&addresses?),
        [IpAddr::V6(V6), IpAddr::V4(V4), IpAddr::V4(V4_OTHER)]
    );
    assert_eq!(
        queries
            .iter()
            .map(DnsQuery::record_type)
            .collect::<Vec<_>>(),
        [TYPE_AAAA, TYPE_A]
    );
    Ok(())
}
