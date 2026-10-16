use super::*;
use phantom_profile::{DnsAddressFailurePolicy, browser::chrome};
use std::{num::NonZeroUsize, sync::Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
const REFUSED: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
const REACHED: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3));
async fn first(resolver: &HostResolver, host: &str, port: u16) -> TestResult<SocketAddr> {
    Ok(
        crate::host_resolver::resolve_tcp(Some(resolver), host, port)
            .await?
            .cursor()
            .next()
            .ok_or("empty candidate list")?
            .address(),
    )
}
#[tokio::test]
async fn refused_proxy_address_is_recorded_but_authentication_cannot_poison_the_target()
-> TestResult {
    failure(false).await
}
#[tokio::test]
async fn refused_proxy_address_is_recorded_but_a_malformed_reply_cannot_poison_the_target()
-> TestResult {
    failure(true).await
}
async fn failure(malformed: bool) -> TestResult {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let names = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&names);
        let mut cache = chrome::v154_dns_cache();
        cache.address_failure_policy = DnsAddressFailurePolicy::Record {
            max_unusable_addresses: NonZeroUsize::new(4).ok_or("zero bound")?,
        };
        let resolver = HostResolver::new()
            .with_resolver(AddressResolver::from_fn(move |host| {
                let result = log
                    .lock()
                    .map_err(|_| io::Error::other("name log poisoned"))
                    .map(|mut log| {
                        log.push(host.clone());
                        if host == "proxy.test" {
                            vec![REFUSED, REACHED]
                        } else {
                            vec![TARGET]
                        }
                    });
                async move { result }
            }))
            .with_cache(cache);
        let family = AddressFamilyMemory::default();
        let operation = async {
            let route = TcpRoute::Socks5 {
                proxy: Endpoint {
                    host: "proxy.test",
                    port,
                },
                target: Socks5Target::LocalDns(Endpoint {
                    host: "target.test",
                    port: 443,
                }),
                auth: Socks5Auth::None,
            };
            let result = connect_retaining(
                Dialer {
                    resolver: Some(&resolver),
                    ..Dialer::default()
                },
                route,
                &family,
                TcpBackupConnection {
                    delay: Duration::from_secs(3),
                    ..backup()
                },
            )
            .await;
            let Err(SocksConnectionError::Five(error)) = result else {
                return Err("terminal SOCKS category was lost".into());
            };
            assert_eq!(
                error.kind(),
                if malformed {
                    Socks5ErrorKind::Negotiation
                } else {
                    Socks5ErrorKind::Authentication
                }
            );
            assert_eq!(first(&resolver, "proxy.test", port).await?.ip(), REACHED);
            assert_eq!(first(&resolver, "target.test", 443).await?.ip(), TARGET);
            assert_eq!(family.family(), None);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let peer = async {
            let (mut stream, _) = listener.accept().await?;
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await?;
            assert_eq!(greeting, [5, 1, 0]);
            stream
                .write_all(if malformed { &[6, 0] } else { &[5, 255] })
                .await?;
            peer::closed(&mut stream).await?;
            peer::no_connection(&listener);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(operation, peer)?;
        assert_eq!(
            *names.lock().map_err(|_| "name log poisoned")?,
            ["target.test", "proxy.test"]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn the_known_family_backup_deadline_encloses_the_complete_socks_reply() -> TestResult {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let host = address.ip().to_string();
        let resolver = HostResolver::new().with_override(
            "local.test",
            [Ipv6Addr::LOCALHOST.into(), Ipv4Addr::LOCALHOST.into()],
        );
        let family = AddressFamilyMemory::default();
        family.remember(AddressFamily::Ipv6);
        let operation = async {
            let route = TcpRoute::Socks5 {
                proxy: Endpoint {
                    host: &host,
                    port: address.port(),
                },
                target: Socks5Target::LocalDns(Endpoint {
                    host: "local.test",
                    port: 443,
                }),
                auth: Socks5Auth::None,
            };
            let (winner, slower) =
                connect_retaining(dialer(Some(&resolver)), route, &family, backup())
                    .await
                    .map_err(|e| e.into_leg())?;
            assert_eq!(family.family(), Some(AddressFamily::Ipv4));
            let slower = slower.ok_or("primary complete negotiation was not retained")?;
            assert!(!slower.progress().has_connected());
            drop(slower);
            drop(winner);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let peer = async {
            let (mut primary, _) = listener.accept().await?;
            assert_eq!(
                peer::five(&mut primary, None).await?.host,
                Host::Ip(Ipv6Addr::LOCALHOST.into())
            );
            let (mut backup, _) = listener.accept().await?;
            assert_eq!(
                peer::five(&mut backup, None).await?.host,
                Host::Ip(Ipv6Addr::LOCALHOST.into())
            );
            // Both physical proxy TCP connections/authentications succeeded. Only
            // the complete-reply deadline can advance the backup to IPv4.
            let (mut switched, _) = listener.accept().await?;
            assert_eq!(
                peer::five(&mut switched, None).await?.host,
                Host::Ip(Ipv4Addr::LOCALHOST.into())
            );
            peer::reply(&mut switched, 0).await?;
            peer::closed(&mut backup).await?;
            peer::closed(&mut primary).await?;
            peer::closed(&mut switched).await?;
            peer::no_connection(&listener);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(operation, peer)?;
        Ok(())
    })
    .await
}

#[test]
fn only_physical_refusal_or_timeout_can_leave_a_started_sibling_alive() {
    for kind in [
        io::ErrorKind::ConnectionRefused,
        io::ErrorKind::TimedOut,
        io::ErrorKind::HostUnreachable,
    ] {
        let error = SocksConnectionError::Five(Socks5Error::connect(io::Error::new(
            kind,
            "physical connect",
        )));
        assert!(!error.terminal());
        assert!(!error.retry_target());
    }
    for kind in [
        io::ErrorKind::InvalidInput,
        io::ErrorKind::Unsupported,
        io::ErrorKind::Other,
    ] {
        let error = SocksConnectionError::Five(Socks5Error::connect(io::Error::new(
            kind,
            "configuration, DNS or feedback capacity",
        )));
        assert!(error.terminal());
        assert!(!error.retry_target());
    }
    for kind in [
        io::ErrorKind::ConnectionRefused,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::AddrNotAvailable,
    ] {
        let before = SocksConnectionError::BeforeConnect {
            four: false,
            source: io::Error::new(kind, "DNS or socket preparation failure"),
        };
        assert!(before.terminal());
        assert!(!before.retry_target());
    }
    let error = SocksConnectionError::Four(Socks4Error::io(
        Socks4ErrorKind::Connect,
        io::Error::other("feedback capacity"),
    ));
    assert!(error.terminal());
    assert!(!error.retry_target());
}

#[tokio::test]
async fn a_proxy_dns_failure_cancels_an_already_started_complete_sibling() -> TestResult {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&calls);
        let resolver = HostResolver::new().with_resolver(AddressResolver::from_fn(move |host| {
            assert_eq!(host, "proxy.test");
            let first = count.fetch_add(1, Ordering::Relaxed) == 0;
            let barrier = Arc::clone(&barrier);
            async move {
                barrier.wait().await;
                if first {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "proxy DNS failure",
                    ))
                } else {
                    Ok(vec![REACHED])
                }
            }
        }));
        let family = AddressFamilyMemory::default();
        let route = TcpRoute::Socks5 {
            proxy: Endpoint {
                host: "proxy.test",
                port,
            },
            target: Socks5Target::LocalDns(Endpoint {
                host: "127.0.0.1",
                port: 443,
            }),
            auth: Socks5Auth::None,
        };
        let result = connect_retaining(
            Dialer {
                resolver: Some(&resolver),
                ..Dialer::default()
            },
            route,
            &family,
            backup(),
        )
        .await;
        let Err(error) = result else {
            return Err("DNS failure was hidden behind a pending sibling".into());
        };
        assert!(matches!(&error, SocksConnectionError::BeforeConnect { .. }));
        let crate::connection_leg::ConnectionLegError::Socks5(error) = error.into_leg() else {
            return Err("DNS category changed".into());
        };
        assert_eq!(error.kind(), Socks5ErrorKind::Connect);
        assert!(
            std::error::Error::source(&error)
                .is_some_and(|source| source.to_string() == "proxy DNS failure")
        );
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert_eq!(family.family(), None);
        Ok(())
    })
    .await
}
