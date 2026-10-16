//! Family state belongs to the bounded physical proxy route, not an inner origin.

use bytes::Bytes;
use http::{Method, Response};
use phantom_profile::browser::firefox;
use std::{
    io,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};
use tokio::{io::AsyncReadExt, sync::oneshot, time::timeout};

use super::{ConnectionSettingsId, Http2ProxyPool, TestResult, connection, key, poll_once};
use crate::{
    host_resolver::{AddressResolver, HostResolver},
    proxy::{
        HttpBasicCredentials, HttpConnectError, HttpConnectHeader, HttpProxyAuthentication,
        HttpsProxyConnector, HttpsProxyProtocol, MAX_HTTP2_PROXY_POOL_ROUTES, http2_pool::RouteKey,
    },
    tcp::AddressFamily,
    tls::test_support::{
        TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestServerAlpn, accept_tls, loopback_listener,
    },
};

#[tokio::test]
async fn a_forwarding_handle_outlives_retirement_without_forgetting_family() -> TestResult {
    let pool = Http2ProxyPool::new();
    let settings = ConnectionSettingsId::default();
    let peers = std::sync::Mutex::new(Vec::new());
    let first = pool
        .acquire(key(&settings), |family| {
            assert_eq!(family.family(), None);
            family.remember(AddressFamily::Ipv4);
            connection(&peers)
        })
        .await?;
    first.retire();
    let (forwarding, counted) = first.into_tunnel();
    drop(counted);
    let second = pool
        .acquire(key(&settings), |family| {
            assert_eq!(family.family(), Some(AddressFamily::Ipv4));
            connection(&peers)
        })
        .await?;
    assert!(!second.reused);
    assert!(
        forwarding.is_reusable(),
        "pool retirement closed a caller handle"
    );
    assert_eq!(
        pool.route(key(&settings)).family.family(),
        Some(AddressFamily::Ipv4)
    );
    Ok(())
}

#[tokio::test]
async fn cancellation_does_not_forget_a_still_owned_routes_family() -> TestResult {
    let pool = Http2ProxyPool::new();
    let settings = ConnectionSettingsId::default();
    let peers = std::sync::Mutex::new(Vec::new());
    let mut pending = Box::pin(pool.acquire(key(&settings), |family| async move {
        family.remember(AddressFamily::Ipv6);
        std::future::pending::<Result<crate::http2::Http2Connection, HttpConnectError>>().await
    }));
    assert!(!poll_once(&mut pending).await);
    drop(pending);
    let next = pool
        .acquire(key(&settings), |family| {
            assert_eq!(family.family(), Some(AddressFamily::Ipv6));
            connection(&peers)
        })
        .await?;
    assert!(!next.reused);
    Ok(())
}

#[tokio::test]
async fn settings_credentials_and_proxy_identity_keep_families_apart() -> TestResult {
    let pool = Http2ProxyPool::new();
    let settings = ConnectionSettingsId::default();
    let original = key(&settings);
    pool.route(original.clone())
        .family
        .remember(AddressFamily::Ipv4);
    let credentials = HttpBasicCredentials::new("fixture", "first")?;
    let changed_credentials = HttpBasicCredentials::new("fixture", "second")?;
    for different in [
        key(&ConnectionSettingsId::default()),
        RouteKey::new(&settings, "different.test", 443, "proxy.test", None),
        RouteKey::new(&settings, "proxy.test", 444, "proxy.test", None),
        RouteKey::new(&settings, "proxy.test", 443, "different.test", None),
        RouteKey::new(
            &settings,
            "proxy.test",
            443,
            "proxy.test",
            Some(HttpProxyAuthentication::Basic(&credentials)),
        ),
        RouteKey::new(
            &settings,
            "proxy.test",
            443,
            "proxy.test",
            Some(HttpProxyAuthentication::Basic(&changed_credentials)),
        ),
    ] {
        let route = pool.route(different);
        assert_eq!(route.family.family(), None);
        route.family.remember(AddressFamily::Ipv6);
    }
    assert_eq!(
        pool.route(original).family.family(),
        Some(AddressFamily::Ipv4)
    );
    Ok(())
}

#[test]
fn a_different_runtime_has_a_distinct_family() -> TestResult {
    let pool = Http2ProxyPool::new();
    let settings = ConnectionSettingsId::default();
    let first = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let other = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    first.block_on(async {
        pool.route(key(&settings))
            .family
            .remember(AddressFamily::Ipv4);
    });
    other.block_on(async {
        let route = pool.route(key(&settings));
        assert_eq!(route.family.family(), None);
        route.family.remember(AddressFamily::Ipv6);
    });
    first.block_on(async {
        assert_eq!(
            pool.route(key(&settings)).family.family(),
            Some(AddressFamily::Ipv4)
        );
    });
    Ok(())
}

#[tokio::test]
async fn eviction_resets_new_route_memory_without_changing_an_active_lease() -> TestResult {
    let pool = Http2ProxyPool::new();
    let settings = ConnectionSettingsId::default();
    let peers = std::sync::Mutex::new(Vec::new());
    let first = pool
        .acquire(key(&settings), |family| {
            family.remember(AddressFamily::Ipv4);
            connection(&peers)
        })
        .await?;
    let old_route = Arc::clone(&first.tunnel.route);
    for _ in 0..MAX_HTTP2_PROXY_POOL_ROUTES {
        pool.route(key(&ConnectionSettingsId::default()));
    }
    assert_eq!(pool.lock().entries.len(), MAX_HTTP2_PROXY_POOL_ROUTES);
    let replacement = pool.route(key(&settings));
    assert!(!Arc::ptr_eq(&old_route, &replacement));
    assert_eq!(replacement.family.family(), None);
    assert_eq!(old_route.family.family(), Some(AddressFamily::Ipv4));
    assert!(first.connection.is_reusable());
    Ok(())
}

#[tokio::test]
async fn the_actual_pooled_dial_learns_the_proxy_family_without_resolving_the_target()
-> crate::tls::test_support::TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let pool = Http2ProxyPool::new();
        let resolver = HostResolver::new().with_resolver(AddressResolver::from_fn(|host| async move {
            if host != "proxy.test" {
                return Err(io::Error::other("the inner target was resolved locally"));
            }
            Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
        }));
        let connector = HttpsProxyConnector::new_with_additional_roots(&firefox::v157_tcp_tls(), [identity.root_der()])?
            .with_http2_settings(&firefox::v157_http2())
            .with_tcp_settings(&firefox::v157_tcp())
            .with_host_resolver(resolver)
            .with_http2_proxy_pool(pool.clone())
            .with_protocol(HttpsProxyProtocol::Http2);
        let route = pool.route(RouteKey::new(connector.connect_udp_settings(), "proxy.test", address.port(), TEST_SERVER_NAME, None));
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let (done, finished) = oneshot::channel();
        let client = async {
            let mut tunnel = connector.connect_tunnel("proxy.test", address.port(), TEST_SERVER_NAME, "unresolvable.invalid:443", &[HttpConnectHeader::authority("Host")]).await?;
            let mut prefix = [0; 2];
            tunnel.read_exact(&mut prefix).await?;
            assert_eq!(&prefix, b"ok");
            assert_eq!(route.family.family(), Some(AddressFamily::Ipv4));
            drop(tunnel);
            done.send(()).map_err(|_| "proxy peer stopped early")?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let peer = async {
            let (stream, _) = accept_tls(listener, acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut respond) = connection.accept().await.ok_or("no proxy CONNECT")??;
            assert_eq!(request.method(), Method::CONNECT);
            assert_eq!(request.uri().authority().map(|value| value.as_str()), Some("unresolvable.invalid:443"));
            let mut send = respond.send_response(Response::new(()), false)?;
            send.send_data(Bytes::from_static(b"ok"), true)?;
            tokio::select! {
                result = finished => result.map_err(|_| "client failed before its response")?,
                extra = connection.accept() => return Err(format!("unexpected proxy request or closure: {}", extra.is_some()).into()),
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(client, peer)?;
        Ok(())
    }).await.map_err(|_| "physical proxy family control exceeded its deadline")?
}
