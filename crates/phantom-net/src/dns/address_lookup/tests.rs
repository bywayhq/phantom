use std::{
    cell::RefCell,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

use phantom_profile::{DnsCacheSettings, UdpSettings, chromium};
use phantom_testkit::dns::{DnsAnswer, DnsQuery, DnsReply, DnsServer};

use super::{AddressLookup, MAX_FALLBACKS, probe_socket};
use crate::{address_cache::AddressCache, host_resolver::AddressResolver, udp::observed};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const V4_OTHER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 11);
const V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
const SYSTEM: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99));

/// Answers A and AAAA with fixed records and TTLs.
fn records(a_ttl: u32, aaaa_ttl: u32) -> impl Fn(&DnsQuery) -> DnsReply + Send + Sync + 'static {
    move |query| match query.record_type() {
        TYPE_A => DnsReply::new(DnsAnswer::Records {
            ttl: a_ttl,
            rdata: vec![V4.octets().to_vec(), V4_OTHER.octets().to_vec()],
        }),
        TYPE_AAAA => DnsReply::new(DnsAnswer::Records {
            ttl: aaaa_ttl,
            rdata: vec![V6.octets().to_vec()],
        }),
        _ => DnsReply::new(DnsAnswer::ServerFailure),
    }
}

fn lookup(server: &DnsServer, ipv6: bool) -> TestResult<AddressLookup> {
    Ok(AddressLookup::for_test(
        [server.address()],
        "",
        ipv6,
        vec![SYSTEM],
    )?)
}

fn ips(addresses: &[SocketAddr]) -> Vec<IpAddr> {
    addresses.iter().map(SocketAddr::ip).collect()
}

fn types(server: &DnsServer) -> Vec<u16> {
    server.queries().iter().map(DnsQuery::record_type).collect()
}

#[tokio::test]
async fn an_answer_lists_ipv6_first_and_carries_the_smallest_record_ttl() -> TestResult {
    let server = DnsServer::spawn(records(300, 120)).await?;

    let resolved = lookup(&server, true)?
        .resolve("origin.example.test")
        .await?;

    assert_eq!(
        ips(&resolved.addresses),
        [IpAddr::V6(V6), IpAddr::V4(V4), IpAddr::V4(V4_OTHER)]
    );
    assert_eq!(resolved.ttl, Some(Duration::from_secs(120)));
    // AAAA starts first, as in Chromium's transaction queue.
    assert_eq!(types(&server), [TYPE_AAAA, TYPE_A]);
    for query in server.queries() {
        assert_eq!(query.name(), "origin.example.test");
        // RD only, one question, and no OPT pseudo-record.
        assert_eq!(query.flags(), 0x0100);
        assert_eq!(query.counts(), [1, 0, 0, 0]);
    }
    Ok(())
}

#[tokio::test]
async fn without_a_global_ipv6_route_only_a_is_queried() -> TestResult {
    let server = DnsServer::spawn(records(300, 120)).await?;

    let resolved = lookup(&server, false)?
        .resolve("origin.example.test")
        .await?;

    assert_eq!(
        ips(&resolved.addresses),
        [IpAddr::V4(V4), IpAddr::V4(V4_OTHER)]
    );
    assert_eq!(resolved.ttl, Some(Duration::from_secs(300)));
    assert_eq!(types(&server), [TYPE_A]);
    Ok(())
}

/// Each lookup builds a new resolver, so neither query reuses a connection,
/// and the runtime runs hickory's tasks on several threads; the A query
/// still leaves only after the AAAA query.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aaaa_is_sent_before_a_on_every_cold_lookup() -> TestResult {
    let server = DnsServer::spawn(records(300, 300)).await?;

    for round in 0..50 {
        let lookup = lookup(&server, true)?;
        lookup.resolve(&format!("r{round}.example.test")).await?;
    }

    for round in 0..50 {
        let name = format!("r{round}.example.test");
        let order: Vec<u16> = server
            .queries()
            .iter()
            .filter(|query| query.name() == name)
            .map(DnsQuery::record_type)
            .collect();
        assert_eq!(order, [TYPE_AAAA, TYPE_A], "{name}");
    }
    Ok(())
}

/// The server holds the AAAA reply for 3 s, yet the A query arrives at
/// once: the A query is released by the AAAA datagram leaving, not by the
/// AAAA lookup ending.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_leaves_once_the_aaaa_query_is_sent_before_it_is_answered() -> TestResult {
    let answer = records(300, 300);
    let server = DnsServer::spawn(move |query: &DnsQuery| {
        let reply = answer(query);
        if query.record_type() == TYPE_AAAA {
            reply.delayed(Duration::from_secs(3))
        } else {
            reply
        }
    })
    .await?;
    let lookup = Arc::new(lookup(&server, true)?);

    let resolving = tokio::spawn({
        let lookup = Arc::clone(&lookup);
        async move { lookup.resolve("held.example.test").await }
    });
    let started = Instant::now();
    while !types(&server).contains(&TYPE_A) {
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            types(&server)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(types(&server).first(), Some(&TYPE_AAAA));
    let resolved = resolving.await??;
    assert_eq!(
        ips(&resolved.addresses),
        [IpAddr::V6(V6), IpAddr::V4(V4), IpAddr::V4(V4_OTHER)]
    );
    Ok(())
}

#[tokio::test]
async fn an_empty_family_counts_its_soa_ttl() -> TestResult {
    let server = DnsServer::spawn(|query: &DnsQuery| match query.record_type() {
        // Chromium takes the SOA record's TTL, not its MINIMUM field.
        TYPE_AAAA => DnsReply::new(DnsAnswer::NoDataWithSoa {
            ttl: 90,
            minimum: 30,
        }),
        _ => DnsReply::new(DnsAnswer::Records {
            ttl: 300,
            rdata: vec![V4.octets().to_vec()],
        }),
    })
    .await?;

    let resolved = lookup(&server, true)?
        .resolve("origin.example.test")
        .await?;

    assert_eq!(ips(&resolved.addresses), [IpAddr::V4(V4)]);
    assert_eq!(resolved.ttl, Some(Duration::from_secs(90)));
    Ok(())
}

#[tokio::test]
async fn localhost_names_resolve_to_loopback_without_a_query() -> TestResult {
    let server = DnsServer::spawn(records(300, 300)).await?;
    let lookup = lookup(&server, false)?;

    for host in ["localhost", "localhost.", "app.localhost"] {
        let resolved = lookup.resolve(host).await?;
        assert_eq!(
            ips(&resolved.addresses),
            [
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            ],
            "{host}"
        );
        assert_eq!(resolved.ttl, None);
    }
    assert!(server.queries().is_empty());
    Ok(())
}

#[tokio::test]
async fn single_label_and_local_names_go_to_the_system_resolver() -> TestResult {
    let server = DnsServer::spawn(records(300, 300)).await?;
    let lookup = lookup(&server, true)?;

    for host in ["intranet", "printer.local", "printer.local."] {
        let resolved = lookup.resolve(host).await?;
        assert_eq!(ips(&resolved.addresses), [SYSTEM], "{host}");
        assert_eq!(resolved.ttl, None);
    }
    assert!(server.queries().is_empty());
    Ok(())
}

/// Without a global IPv6 route Chromium asks the system resolver for IPv4
/// only, and for both families again when IPv4 gives only loopback.
#[tokio::test]
async fn without_an_ipv6_route_the_system_resolver_answers_ipv4() -> TestResult {
    let server = DnsServer::spawn(records(300, 300)).await?;
    let both = vec![IpAddr::V6(V6), IpAddr::V4(V4)];
    let loopback = vec![
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    ];
    let ipv6_only = vec![IpAddr::V6(V6)];

    let resolve = |system: Vec<IpAddr>, ipv6: bool| {
        let lookup = AddressLookup::for_test([server.address()], "", ipv6, system);
        async move { lookup?.resolve("intranet").await }
    };

    assert_eq!(
        ips(&resolve(both.clone(), false).await?.addresses),
        [IpAddr::V4(V4)]
    );
    assert_eq!(ips(&resolve(both.clone(), true).await?.addresses), both);
    assert_eq!(
        ips(&resolve(loopback.clone(), false).await?.addresses),
        loopback
    );
    assert!(resolve(ipv6_only, false).await.is_err());
    assert!(server.queries().is_empty());
    Ok(())
}

#[tokio::test]
async fn the_hosts_file_answers_without_a_query() -> TestResult {
    let server = DnsServer::spawn(records(300, 300)).await?;
    let lookup = AddressLookup::for_test(
        [server.address()],
        "192.0.2.50 pinned.example.test\n2001:db8::50 pinned.example.test\n",
        true,
        vec![SYSTEM],
    )?;

    let resolved = lookup.resolve("pinned.example.test").await?;

    assert_eq!(
        ips(&resolved.addresses),
        [
            "2001:db8::50".parse::<IpAddr>()?,
            "192.0.2.50".parse::<IpAddr>()?
        ]
    );
    assert_eq!(resolved.ttl, None);
    assert!(server.queries().is_empty());
    Ok(())
}

#[tokio::test]
async fn a_failed_or_empty_lookup_falls_back_to_the_system_resolver() -> TestResult {
    let server = DnsServer::spawn(|query: &DnsQuery| match query.name() {
        "empty.example.test" => DnsReply::new(DnsAnswer::NoData {
            soa_minimum: Some(60),
        }),
        _ => DnsReply::new(DnsAnswer::ServerFailure),
    })
    .await?;
    let lookup = lookup(&server, false)?;

    for host in ["failing.example.test", "empty.example.test"] {
        let resolved = lookup.resolve(host).await?;
        assert_eq!(ips(&resolved.addresses), [SYSTEM], "{host}");
        assert_eq!(resolved.ttl, None, "{host}");
    }
    Ok(())
}

#[tokio::test]
async fn sixteen_fallbacks_in_a_row_stop_the_dns_queries() -> TestResult {
    let server = DnsServer::spawn(|_: &DnsQuery| DnsReply::new(DnsAnswer::ServerFailure)).await?;
    let lookup = lookup(&server, false)?;

    for _ in 0..MAX_FALLBACKS {
        lookup.resolve("failing.example.test").await?;
    }
    let sent = server.queries().len();
    let resolved = lookup.resolve("other.example.test").await?;

    assert_eq!(ips(&resolved.addresses), [SYSTEM]);
    assert_eq!(server.queries().len(), sent);
    Ok(())
}

/// A client copies the resolver for its profile's UDP settings; the copy
/// keeps the original's fallback count, so it also stops querying.
#[tokio::test]
async fn copies_for_other_udp_settings_share_the_fallback_count() -> TestResult {
    let server = DnsServer::spawn(|_: &DnsQuery| DnsReply::new(DnsAnswer::ServerFailure)).await?;
    let plain = lookup(&server, false)?;
    let chromium = plain.with_udp_settings(chromium::v154_udp());

    for _ in 0..MAX_FALLBACKS {
        plain.resolve("failing.example.test").await?;
    }
    let sent = server.queries().len();
    let resolved = chromium.resolve("other.example.test").await?;

    assert_eq!(ips(&resolved.addresses), [SYSTEM]);
    assert_eq!(server.queries().len(), sent);
    Ok(())
}

/// A probe socket whose UDP settings are rejected is bound again without
/// them, as Chromium ignores the option's failure, so the probe still runs.
#[test]
fn a_rejected_probe_socket_option_binds_again_without_it() -> TestResult {
    let calls = RefCell::new(Vec::new());
    let bind = |udp: Option<UdpSettings>| {
        calls.borrow_mut().push(udp);
        match udp {
            Some(_) => Err(io::Error::from(io::ErrorKind::InvalidInput)),
            None => phantom_testkit::udp::bind((Ipv4Addr::LOCALHOST, 0).into()),
        }
    };

    assert!(probe_socket(Some(chromium::v154_udp()), bind).is_some());
    assert_eq!(*calls.borrow(), [Some(chromium::v154_udp()), None]);

    calls.borrow_mut().clear();
    let failing = |udp: Option<UdpSettings>| {
        calls.borrow_mut().push(udp);
        Err::<std::net::UdpSocket, _>(io::Error::from(io::ErrorKind::AddrNotAvailable))
    };
    assert!(probe_socket(None, failing).is_none());
    assert_eq!(*calls.borrow(), [None]);
    Ok(())
}

/// The bound and the record TTL rule of a profile's cache, through Phantom's
/// own queries: an answer is kept for its record TTL even when `ttl`, the
/// lifetime of an answer without one, keeps nothing.
#[tokio::test]
async fn the_address_cache_keeps_a_dns_answer_for_its_record_ttl() -> TestResult {
    let server = DnsServer::spawn(records(1, 1)).await?;
    let resolver = AddressResolver::from_dns(lookup(&server, false)?);
    let settings = DnsCacheSettings {
        max_entries: NonZeroUsize::MIN,
        ttl: Duration::ZERO,
        min_record_ttl: Duration::ZERO,
        negative_ttl: None,
    };
    let cache = AddressCache::with_resolver(settings, resolver);

    cache.lookup("origin.example.test", 443).await?;
    cache.lookup("origin.example.test", 443).await?;
    assert_eq!(server.queries().len(), 1);

    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let addresses = cache.lookup("origin.example.test", 443).await?;
    assert_eq!(server.queries().len(), 2);
    assert_eq!(addresses[0], SocketAddr::new(IpAddr::V4(V4), 443));
    Ok(())
}

#[tokio::test]
async fn the_address_cache_raises_a_short_record_ttl_to_the_minimum() -> TestResult {
    let server = DnsServer::spawn(records(0, 0)).await?;
    let resolver = AddressResolver::from_dns(lookup(&server, false)?);
    let cache = AddressCache::with_resolver(chromium::v154_dns_cache(), resolver);

    cache.lookup("origin.example.test", 443).await?;
    cache.lookup("origin.example.test", 8443).await?;

    assert_eq!(server.queries().len(), 1);
    Ok(())
}

/// Each query socket of a Chromium profile sets `SO_RANDOMIZE_PORT` before
/// it binds port 0, through the bind that retries a Windows reserved port
/// block; without UDP settings hickory binds a random port itself.
#[tokio::test]
async fn query_sockets_randomize_their_port_with_the_profiles_udp_settings() -> TestResult {
    let server = DnsServer::spawn(records(300, 300)).await?;
    let plain = lookup(&server, true)?;
    let chromium = plain.with_udp_settings(chromium::v154_udp());
    let off = plain.with_udp_settings(UdpSettings::default());
    assert_eq!(chromium.udp_settings(), Some(chromium::v154_udp()));
    assert_eq!(plain.udp_settings(), None);

    for (lookup, randomized) in [(&chromium, cfg!(windows)), (&off, false), (&plain, false)] {
        observed::take();
        lookup.resolve("origin.example.test").await?;
        let sockets = observed::take();
        assert_eq!(sockets.len(), 2);
        assert!(
            sockets
                .iter()
                .all(|socket| socket.random_port == randomized),
            "{sockets:?}"
        );
    }
    Ok(())
}
