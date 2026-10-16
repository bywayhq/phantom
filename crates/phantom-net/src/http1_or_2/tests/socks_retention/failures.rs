use super::*;
use crate::{
    http1_or_2::{Http1Or2TlsError, Http1Or2TlsErrorKind},
    http2::{Http2TlsError, Http2TlsErrorKind},
    proxy::{Socks4UserId, Socks5Auth},
    route::{DirectTlsSetup, Endpoint, OriginRoute, Socks4Target, TcpRoute},
};

fn no_connection(listener: &TcpListener) {
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(listener.poll_accept(&mut context).is_pending());
}

#[tokio::test]
async fn non_socks_and_direct_only_setups_fail_before_any_lookup_or_proxy_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    let resolver = HostResolver::new().with_resolver(AddressResolver::from_fn(move |_| {
        count.fetch_add(1, Ordering::Relaxed);
        async { Err(io::Error::other("invalid route reached lookup")) }
    }));
    let connectors = Connectors::new(&identity, false)?.with_resolver(resolver)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let host = address.ip().to_string();
    let family = AddressFamilyMemory::new();
    for exact in [false, true] {
        let route = OriginRoute::Tls {
            tcp: TcpRoute::Direct(Endpoint {
                host: "invalid.test",
                port: 443,
            }),
            server_name: "invalid.test",
            setup: DirectTlsSetup::Default,
        };
        assert!(connectors.connect(exact, route, &family).await.is_err());
        let mut route = origin(&host, address.port(), false);
        if let OriginRoute::Tls { setup, .. } = &mut route {
            *setup = DirectTlsSetup::KeepSlower(&family);
        }
        assert!(connectors.connect(exact, route, &family).await.is_err());
    }
    no_connection(&listener);
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert_eq!(family.family(), None);
    Ok(())
}

#[tokio::test]
async fn local_target_dns_failure_is_typed_and_never_opens_the_proxy() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    let resolver = HostResolver::new().with_resolver(AddressResolver::from_fn(move |host| {
        assert_eq!(host, "missing-target.test");
        count.fetch_add(1, Ordering::Relaxed);
        async {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "target unavailable",
            ))
        }
    }));
    let connectors = Connectors::new(&identity, false)?.with_resolver(resolver)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let host = address.ip().to_string();
    let family = AddressFamilyMemory::new();
    for exact in [false, true] {
        let mut route = origin(&host, address.port(), false);
        if let OriginRoute::Tls {
            tcp: TcpRoute::Socks5 { target, .. },
            ..
        } = &mut route
        {
            *target = crate::route::Socks5Target::LocalDns(Endpoint {
                host: "missing-target.test",
                port: 443,
            });
        }
        let error = connectors
            .connect(exact, route, &family)
            .await
            .err()
            .ok_or("DNS failure accepted")?;
        if exact {
            assert_eq!(
                error
                    .downcast_ref::<Http2TlsError>()
                    .ok_or("wrong exact error type")?
                    .kind(),
                Http2TlsErrorKind::Socks5Proxy
            );
        } else {
            assert_eq!(
                error
                    .downcast_ref::<Http1Or2TlsError>()
                    .ok_or("wrong negotiated error type")?
                    .kind(),
                Http1Or2TlsErrorKind::Socks5Proxy
            );
        }
    }
    no_connection(&listener);
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert_eq!(family.family(), None);
    Ok(())
}

#[tokio::test]
async fn rejected_socks_authentication_never_reaches_origin_tls_or_learns_a_family()
-> TestResult<()> {
    for exact in [false, true] {
        timeout(WAIT, async {
            let identity = TestIdentity::generate()?;
            let connectors = Connectors::new(&identity, false)?;
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let host = address.ip().to_string();
            let family = AddressFamilyMemory::new();
            let peer = async {
                let (mut stream, _) = listener.accept().await?;
                let mut greeting = [0; 4];
                stream.read_exact(&mut greeting).await?;
                assert_eq!(greeting, [5, 2, 0, 2]);
                stream.write_all(&[5, 2]).await?;
                let mut auth = [0; 13];
                stream.read_exact(&mut auth).await?;
                assert_eq!(&auth, b"\x01\x04user\x06secret");
                stream.write_all(&[1, 1]).await?;
                closed(&mut stream).await
            };
            let caller = async {
                let mut route = origin(&host, address.port(), false);
                if let OriginRoute::Tls {
                    tcp: TcpRoute::Socks5 { auth, .. },
                    ..
                } = &mut route
                {
                    *auth = Socks5Auth::UsernamePassword {
                        username: "user",
                        password: "secret",
                    };
                }
                let error = connectors
                    .connect(exact, route, &family)
                    .await
                    .err()
                    .ok_or("failed authentication accepted")?;
                if exact {
                    assert_eq!(
                        error
                            .downcast_ref::<Http2TlsError>()
                            .ok_or("wrong exact error type")?
                            .kind(),
                        Http2TlsErrorKind::Socks5Proxy
                    );
                } else {
                    assert_eq!(
                        error
                            .downcast_ref::<Http1Or2TlsError>()
                            .ok_or("wrong negotiated error type")?
                            .kind(),
                        Http1Or2TlsErrorKind::Socks5Proxy
                    );
                }
                assert!(!error.to_string().contains("secret"));
                assert_eq!(family.family(), None);
                TestResult::Ok(())
            };
            tokio::try_join!(caller, peer)?;
            TestResult::Ok(())
        })
        .await??;
    }
    Ok(())
}

#[tokio::test]
async fn canceling_either_connector_drops_the_actual_inflight_socks_negotiation() -> TestResult<()>
{
    for exact in [false, true] {
        timeout(WAIT, async {
            let identity = TestIdentity::generate()?;
            let connectors = Connectors::new(&identity, false)?;
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let host = address.ip().to_string();
            let family = AddressFamilyMemory::new();
            let (accepted, observed) = oneshot::channel();
            let peer = async {
                let mut stream = negotiate(&listener, false).await?;
                accepted.send(()).map_err(|_| "opening canceled before negotiation")?;
                closed(&mut stream).await
            };
            let caller = async {
                let mut opening = Box::pin(connectors.connect(exact, origin(&host, address.port(), false), &family));
                tokio::select! {
                    biased;
                    result = &mut opening => return Err(format!("held SOCKS completed: {result:?}").into()),
                    accepted = observed => accepted?,
                }
                drop(opening);
                assert_eq!(family.family(), None);
                TestResult::Ok(())
            };
            tokio::try_join!(caller, peer)?;
            TestResult::Ok(())
        }).await??;
    }
    Ok(())
}

#[tokio::test]
async fn socks4_local_ipv6_is_not_reinterpreted_as_another_route() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connectors = Connectors::new(&identity, false)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let host = address.ip().to_string();
    let family = AddressFamilyMemory::new();
    for exact in [false, true] {
        let route = OriginRoute::Tls {
            tcp: TcpRoute::Socks4 {
                proxy: Endpoint {
                    host: &host,
                    port: address.port(),
                },
                target: Socks4Target::LocalDns(Endpoint {
                    host: "::1",
                    port: 443,
                }),
                user_id: Socks4UserId::default(),
            },
            server_name: "server.phantom.test",
            setup: DirectTlsSetup::Default,
        };
        assert!(connectors.connect(exact, route, &family).await.is_err());
    }
    no_connection(&listener);
    assert_eq!(family.family(), None);
    Ok(())
}
