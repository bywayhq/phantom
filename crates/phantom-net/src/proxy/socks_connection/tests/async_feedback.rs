use super::*;
use phantom_profile::{TcpAddressSelection, browser::firefox};

#[tokio::test]
async fn a_refused_socks_proxy_address_remains_first_for_the_next_setup() -> TestResult {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    let resolver = HostResolver::new()
        .with_resolver(AddressResolver::from_fn(move |host| {
            let count = Arc::clone(&count);
            async move {
                if host != "proxy.test" {
                    return Err(io::Error::other("remote SOCKS target was resolved locally"));
                }

                count.fetch_add(1, Ordering::Relaxed);
                Ok(vec![Ipv6Addr::LOCALHOST.into(), Ipv4Addr::LOCALHOST.into()])
            }
        }))
        .with_cache(firefox::v157_dns_cache());
    let family = AddressFamilyMemory::default();
    let policy = TcpBackupConnection {
        delay: Duration::from_secs(10),
        known_family_backup_timeout: None,
        socks_proxy_dns_feedback: phantom_profile::SocksProxyDnsFeedback::InitialConnectFailures,
    };
    let mut tcp = firefox::v157_tcp();
    tcp.address_selection = TcpAddressSelection::Backup(policy);
    let operation = async {
        let mut observations = Vec::new();
        for _ in 0..2 {
            let route = TcpRoute::Socks5 {
                proxy: Endpoint {
                    host: "proxy.test",
                    port,
                },
                target: Socks5Target::RemoteDns(Endpoint {
                    host: "remote.test",
                    port: 443,
                }),
                auth: Socks5Auth::None,
            };
            let (connection, slower) = connect_retaining(
                Dialer {
                    tcp: Some(tcp),
                    resolver: Some(&resolver),
                    ..Dialer::default()
                },
                route,
                &family,
                policy,
            )
            .await
            .map_err(|error| error.into_leg())?;
            let had_slower = slower.is_some();
            drop(slower);
            drop(connection);

            let first = crate::host_resolver::resolve_tcp(Some(&resolver), "proxy.test", port)
                .await?
                .cursor()
                .next()
                .ok_or("cached proxy record has no address")?
                .address();
            observations.push((first, family.family(), had_slower));
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(observations)
    };
    let peer = async {
        let mut requests = Vec::new();
        for _ in 0..2 {
            let (mut connection, _) = listener.accept().await?;
            requests.push(peer::five(&mut connection, None).await?);
            peer::reply(&mut connection, 0).await?;
            peer::closed(&mut connection).await?;
        }
        peer::no_connection(&listener);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(requests)
    };

    // Two refused Windows loopback connects can each take about two seconds.
    // The bound ends before either complete attempt can start its backup.
    // Both futures own their sockets; no peer task survives failure or timeout.
    let (operation, peer) = timeout(Duration::from_secs(8), async {
        tokio::join!(operation, peer)
    })
    .await?;
    let requests = peer?;
    let observations = operation?;

    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(requests.len(), 2);
    for request in requests {
        assert_eq!(request.host, Host::Domain("remote.test".into()));
        assert_eq!(request.port, 443);
    }
    assert_eq!(observations.len(), 2);
    for (first, remembered, had_slower) in observations {
        assert_eq!(first, SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port));
        assert_eq!(remembered, None);
        assert!(!had_slower, "the sequential setup started a backup");
    }
    Ok(())
}
