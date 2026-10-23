use std::{
    error::Error as _,
    future::Future as _,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};

use phantom_profile::{Http3ConnectionReuse, browser::chrome};
use tokio::{sync::oneshot, time::timeout};

use super::{TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, server_endpoint};
use crate::{
    DestinationDenied, DestinationPolicy,
    host_resolver::{AddressResolver, HostResolver},
    http3::{Http3Connector, Http3ConnectorErrorKind},
    route::{DatagramRoute, Endpoint},
};

const SECOND: &str = "second.phantom.test";

#[tokio::test(flavor = "current_thread")]
async fn reuse_requires_profile_permission_verified_name_and_current_dns() -> TestResult<()> {
    let identity = TestIdentity::generate_for_names(&[
        TEST_SERVER_NAME,
        SECOND,
        "changed.phantom.test",
        "127.0.0.1",
    ])?;
    for policy in [
        Http3ConnectionReuse::SameOrigin,
        Http3ConnectionReuse::AuthorizedOrigins,
    ] {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&seen);
        let resolver = HostResolver::new()
            .with_override(SECOND, [Ipv4Addr::LOCALHOST.into()])
            .with_override("wrong.phantom.test", [Ipv4Addr::LOCALHOST.into()])
            .with_override("changed.phantom.test", [Ipv4Addr::new(127, 0, 0, 2).into()])
            .with_destination_policy(DestinationPolicy::from_fn(move |peer| {
                observed.lock().unwrap().push(peer);
                true
            }));
        let connector = build_connector(&identity, policy)?.with_host_resolver(resolver);
        let (address, endpoint) = server_endpoint(&identity)?;
        let (done, finished) = oneshot::channel();
        let result = timeout(TEST_TIMEOUT, async {
            let peer = async {
                let connection = endpoint.accept().await.ok_or("endpoint closed")?.await?;
                let _session: h3::server::Connection<_, bytes::Bytes> =
                    h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?;
                finished.await?;
                TestResult::Ok(())
            };
            let caller = async {
                let result = async {
                    let connection = connector
                        .connect(
                            DatagramRoute::Direct(Endpoint {
                                host: &address.ip().to_string(),
                                port: address.port(),
                            }),
                            TEST_SERVER_NAME,
                        )
                        .await?;
                    let prepared = connector
                        .resolve_origin_for_reuse("SECOND.PHANTOM.TEST", 443)
                        .await?;
                    assert_eq!(prepared.host(), SECOND);
                    assert_eq!(prepared.port(), 443);
                    seen.lock().unwrap().clear();
                    let allowed = policy == Http3ConnectionReuse::AuthorizedOrigins;
                    assert_eq!(
                        connector.can_reuse_for_origin(&connection, &prepared)?,
                        allowed
                    );
                    assert_eq!(
                        &*seen.lock().unwrap(),
                        if allowed { &[address][..] } else { &[][..] }
                    );
                    for host in ["wrong.phantom.test", "changed.phantom.test"] {
                        let prepared = connector.resolve_origin_for_reuse(host, 443).await?;
                        assert!(!connector.can_reuse_for_origin(&connection, &prepared)?);
                    }
                    let ip = connector.resolve_origin_for_reuse("127.0.0.1", 443).await?;
                    assert_eq!(connector.can_reuse_for_origin(&connection, &ip)?, allowed);
                    let shared = connector.without_ticket_offers();
                    assert_eq!(
                        shared.can_reuse_for_origin(&connection, &prepared)?,
                        allowed
                    );
                    let changed = connector.with_host_resolver(
                        HostResolver::new()
                            .with_override(SECOND, [Ipv4Addr::new(127, 0, 0, 2).into()]),
                    );
                    assert!(changed.can_reuse_now(&connection));
                    assert!(!changed.can_reuse_for_origin(&connection, &prepared)?);
                    let changed_answer = changed.resolve_origin_for_reuse(SECOND, 443).await?;
                    assert!(!connector.can_reuse_for_origin(&connection, &changed_answer)?);
                    let other = build_connector(&identity, policy)?.with_host_resolver(
                        HostResolver::new().with_override(SECOND, [Ipv4Addr::LOCALHOST.into()]),
                    );
                    let foreign = other.resolve_origin_for_reuse(SECOND, 443).await?;
                    assert!(!connector.can_reuse_for_origin(&connection, &foreign)?);
                    assert!(!other.can_reuse_for_origin(&connection, &prepared)?);
                    TestResult::Ok(())
                }
                .await;
                // Signal the owned peer before returning an operation failure.
                let _ = done.send(());
                result
            };
            tokio::try_join!(caller, peer).map(|_| ())
        })
        .await;
        endpoint.close(0_u32.into(), b"test complete");
        result??;
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn destination_denial_keeps_its_typed_cause_and_uses_the_actual_peer() -> TestResult<()> {
    let identity = TestIdentity::generate_for_names(&[TEST_SERVER_NAME, SECOND])?;
    let connector = build_connector(&identity, Http3ConnectionReuse::AuthorizedOrigins)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (done, finished) = oneshot::channel();
    let result = timeout(TEST_TIMEOUT, async {
        let peer = async {
            let connection = endpoint.accept().await.ok_or("endpoint closed")?.await?;
            let _session: h3::server::Connection<_, bytes::Bytes> =
                h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?;
            finished.await?;
            TestResult::Ok(())
        };
        let caller = async {
            let result = async {
                let connection = connector
                    .connect(
                        DatagramRoute::Direct(Endpoint {
                            host: &address.ip().to_string(),
                            port: address.port(),
                        }),
                        TEST_SERVER_NAME,
                    )
                    .await?;
                let connector = connector.with_host_resolver(
                    HostResolver::new()
                        .with_override(SECOND, [Ipv4Addr::LOCALHOST.into()])
                        .with_destination_policy(DestinationPolicy::from_fn(move |peer| {
                            assert_eq!(peer, address);
                            false
                        })),
                );
                let prepared = connector.resolve_origin_for_reuse(SECOND, 443).await?;
                let error = connector
                    .can_reuse_for_origin(&connection, &prepared)
                    .err()
                    .ok_or("denied peer was admitted")?;
                assert_eq!(error.kind(), Http3ConnectorErrorKind::Connect);
                assert!(
                    error
                        .source()
                        .is_some_and(|source| source.is::<DestinationDenied>())
                );
                assert!(!error.to_string().contains(&address.to_string()));
                assert!(
                    connector.can_reuse_now(&connection),
                    "admission changed connection health"
                );
                TestResult::Ok(())
            }
            .await;
            let _ = done.send(());
            result
        };
        tokio::try_join!(caller, peer).map(|_| ())
    })
    .await;
    endpoint.close(0_u32.into(), b"test complete");
    result??;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn configured_client_identity_stays_ineligible_when_the_peer_does_not_request_it()
-> TestResult<()> {
    let identity = TestIdentity::generate_for_names(&[TEST_SERVER_NAME, SECOND])?;
    let key = rcgen::KeyPair::generate()?;
    let certificate = rcgen::CertificateParams::new(Vec::<String>::new())?.self_signed(&key)?;
    let certificate = crate::tls::ClientCertificate::from_der(
        [certificate.der().as_ref()],
        &key.serialize_der(),
    )?;
    let connector = build_connector(&identity, Http3ConnectionReuse::AuthorizedOrigins)?
        .with_host_resolver(HostResolver::new().with_override(SECOND, [Ipv4Addr::LOCALHOST.into()]))
        .with_client_certificate(&certificate);
    // The existing rustls peer uses with_no_client_auth, so no certificate is requested.
    let (address, endpoint) = server_endpoint(&identity)?;
    let (done, finished) = oneshot::channel();
    let result = timeout(TEST_TIMEOUT, async {
        let peer = async {
            let connection = endpoint.accept().await.ok_or("endpoint closed")?.await?;
            let _session: h3::server::Connection<_, bytes::Bytes> =
                h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?;
            finished.await?;
            TestResult::Ok(())
        };
        let caller = async {
            let result = async {
                let connection = connector
                    .connect(
                        DatagramRoute::Direct(Endpoint {
                            host: &address.ip().to_string(),
                            port: address.port(),
                        }),
                        TEST_SERVER_NAME,
                    )
                    .await?;
                assert!(connector.can_reuse_now(&connection));
                for derived in [
                    connector.with_isolated_session_cache(),
                    connector.without_ticket_offers(),
                    connector.with_early_data(),
                    connector.without_early_data(),
                    connector.with_host_resolver(
                        HostResolver::new().with_override(SECOND, [Ipv4Addr::LOCALHOST.into()]),
                    ),
                ] {
                    let prepared = derived.resolve_origin_for_reuse(SECOND, 443).await?;
                    assert!(!derived.can_reuse_for_origin(&connection, &prepared)?);
                }
                TestResult::Ok(())
            }
            .await;
            let _ = done.send(());
            result
        };
        tokio::try_join!(caller, peer).map(|_| ())
    })
    .await;
    endpoint.close(0_u32.into(), b"test complete");
    result??;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn origin_lookup_preserves_dns_failure_empty_answer_and_cancellation() -> TestResult<()> {
    struct PendingLookup(Arc<AtomicUsize>);
    impl Drop for PendingLookup {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let identity = TestIdentity::generate()?;
    let dropped = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&dropped);
    let connector = build_connector(&identity, Http3ConnectionReuse::AuthorizedOrigins)?
        .with_host_resolver(HostResolver::new().with_resolver(AddressResolver::from_fn(
            move |host| {
                let observed = Arc::clone(&observed);
                async move {
                    match host.as_str() {
                        "failure.phantom.test" => Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "resolver denied lookup",
                        )),
                        "empty.phantom.test" => Ok(Vec::<IpAddr>::new()),
                        _ => {
                            let _owned = PendingLookup(observed);
                            std::future::pending().await
                        }
                    }
                }
            },
        )));
    let error = connector
        .resolve_origin_for_reuse("failure.phantom.test", 443)
        .await
        .err()
        .ok_or("DNS failure became an answer")?;
    assert_eq!(error.kind(), Http3ConnectorErrorKind::Resolve);
    assert_eq!(
        error
            .source()
            .and_then(|s| s.downcast_ref::<io::Error>())
            .map(io::Error::kind),
        Some(io::ErrorKind::PermissionDenied)
    );
    let error = connector
        .resolve_origin_for_reuse("empty.phantom.test", 443)
        .await
        .err()
        .ok_or("empty DNS answer was accepted")?;
    assert_eq!(error.kind(), Http3ConnectorErrorKind::Resolve);
    {
        let future = connector.resolve_origin_for_reuse("pending.phantom.test", 443);
        tokio::pin!(future);
        assert!(matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ));
    }
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn peer_address_matching_preserves_family_and_ipv6_scope_but_not_port() -> TestResult<()> {
    for (candidate, peer, expected) in [
        ("127.0.0.1:443", "127.0.0.1:8443", true),
        ("127.0.0.2:443", "127.0.0.1:8443", false),
        ("[fe80::1%2]:443", "[fe80::1%2]:8443", true),
        ("[fe80::1%3]:443", "[fe80::1%2]:8443", false),
        ("[::ffff:127.0.0.1]:443", "127.0.0.1:8443", false),
    ] {
        let candidate = candidate.parse::<SocketAddr>()?;
        let identity = TestIdentity::generate()?;
        let connector = build_connector(&identity, Http3ConnectionReuse::AuthorizedOrigins)?
            .with_host_resolver(HostResolver::new().with_resolver(
                AddressResolver::from_resolved_fn(move |_| {
                    Box::pin(async move {
                        Ok(crate::host_resolver::Resolved::Legacy {
                            addresses: vec![candidate],
                            ttl: None,
                        })
                    })
                }),
            ));
        let prepared = connector
            .resolve_origin_for_reuse(SECOND, candidate.port())
            .await?;
        assert_eq!(prepared.contains_peer(peer.parse()?), expected);
    }
    Ok(())
}

fn build_connector(
    identity: &TestIdentity,
    policy: Http3ConnectionReuse,
) -> TestResult<Http3Connector> {
    let mut settings = chrome::v154_http3();
    settings.connection_reuse = policy;
    Ok(Http3Connector::new_with_additional_roots(
        &chrome::v154_quic_tls(),
        &chrome::v154_quic(),
        &settings,
        &chrome::v154_http3_request(),
        [identity.root_der()],
    )?)
}
