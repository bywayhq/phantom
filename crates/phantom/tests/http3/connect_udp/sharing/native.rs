//! Concurrent origins retain independently owned tunnels on one outer session.

use super::super::*;

pub(super) async fn fetch(client: &Client, uri: &str, expected: &str) -> TestResult<()> {
    let response = client.get(HttpProtocol::Http3, uri)?.send().await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.into_body().collect().await?.to_bytes(), expected);
    Ok(())
}

#[tokio::test]
async fn two_inner_origins_share_one_h3_outer_connection() -> TestResult<()> {
    shared_h3(false).await
}

#[tokio::test]
async fn challenged_h3_outer_is_published_only_after_valid_basic_retry() -> TestResult<()> {
    shared_h3(true).await
}

async fn shared_h3(challenge: bool) -> TestResult<()> {
    let (origin_identity, proxy_identity) = identities()?;
    let one = Origin::spawn(&origin_identity)?;
    let two = Origin::spawn(&origin_identity)?;
    let mode = if challenge {
        ProxyMode::SharingChallenge
    } else {
        ProxyMode::Sharing
    };
    let mut proxy = MasqueProxy::spawn(&proxy_identity, mode)?;
    let result = super::checked(bounded(async {
        let mut route = ConnectUdpProxy::new(&proxy.template())?;
        if challenge {
            route = route.with_basic_auth("user", "pass")?;
        }
        let client = leg_client(&origin_identity, &proxy_identity, route)?;
        let one_uri = one.uri("/one");
        let two_uri = two.uri("/two");
        tokio::try_join!(
            fetch(&client, &one_uri, "/one"),
            fetch(&client, &two_uri, "/two")
        )?;
        assert_eq!(one.connections(), 1);
        assert_eq!(two.connections(), 1);
        assert_eq!(proxy.connections(), if challenge { 2 } else { 1 });
        let streams = proxy.stream_ids();
        let accepted = if challenge {
            &streams[1..]
        } else {
            &streams[..]
        };
        assert_eq!(accepted.len(), 2);
        assert_eq!(accepted[0].0, accepted[1].0);
        assert_ne!(accepted[0].1, accepted[1].1);
        if challenge {
            let requests = proxy.requests();
            assert_eq!(requests.len(), 3);
            assert!(
                !requests[0]
                    .fields
                    .iter()
                    .any(|(n, _)| n == "proxy-authorization")
            );
            assert!(requests[1..].iter().all(|r| {
                r.fields
                    .iter()
                    .any(|(n, v)| n == "proxy-authorization" && v == b"Basic dXNlcjpwYXNz")
            }));
        }
        Ok(())
    }))
    .await;
    let result = finish_with_cleanup(result, proxy.finish().await);
    let result = finish_with_cleanup(result, one.finish().await);
    finish_with_cleanup(result, two.finish().await)
}

#[tokio::test]
async fn two_inner_origins_share_one_h2_outer_connection() -> TestResult<()> {
    shared_h2(false).await
}

#[tokio::test]
async fn challenged_h2_outer_is_published_only_after_valid_basic_retry() -> TestResult<()> {
    shared_h2(true).await
}

async fn shared_h2(challenge: bool) -> TestResult<()> {
    let (origin_identity, proxy_identity) = identities()?;
    let one = Origin::spawn(&origin_identity)?;
    let two = Origin::spawn(&origin_identity)?;
    let mode = if challenge {
        StreamMode::SharingChallenge
    } else {
        StreamMode::Sharing
    };
    let mut proxy = MasqueStreamProxy::spawn(&proxy_identity, StreamLeg::Http2, mode).await?;
    let primary = super::checked(bounded(async {
        let mut route = ConnectUdpProxy::new(&proxy.template())?.with_http2_transport();
        if challenge {
            route = route.with_basic_auth("user", "pass")?;
        }
        let client = leg_client(&origin_identity, &proxy_identity, route)?;
        let one_uri = one.uri("/one");
        let two_uri = two.uri("/two");
        tokio::try_join!(
            fetch(&client, &one_uri, "/one"),
            fetch(&client, &two_uri, "/two")
        )?;
        assert_eq!(one.connections(), 1);
        assert_eq!(two.connections(), 1);
        assert_eq!(proxy.connections(), if challenge { 2 } else { 1 });
        let streams = proxy.stream_ids();
        let accepted = if challenge {
            &streams[1..]
        } else {
            &streams[..]
        };
        assert_eq!(accepted.len(), 2);
        assert_eq!(accepted[0].0, accepted[1].0);
        assert_ne!(accepted[0].1, accepted[1].1);
        if challenge {
            let requests = proxy.requests();
            assert_eq!(requests.len(), 3);
            assert!(
                !requests[0]
                    .fields
                    .iter()
                    .any(|(n, _)| n == "proxy-authorization")
            );
            assert!(requests[1..].iter().all(|request| {
                request
                    .fields
                    .iter()
                    .any(|(n, v)| n == "proxy-authorization" && v == b"Basic dXNlcjpwYXNz")
            }));
        }
        Ok(())
    }))
    .await;
    let result = finish_with_cleanup(primary, proxy.shutdown().await);
    let result = finish_with_cleanup(result, one.finish().await);
    finish_with_cleanup(result, two.finish().await)
}

#[tokio::test]
async fn closing_one_inner_origin_does_not_close_the_other_h3_tunnel() -> TestResult<()> {
    let (origin_identity, proxy_identity) = identities()?;
    let one = Origin::spawn(&origin_identity)?;
    let two = Origin::spawn(&origin_identity)?;
    let mut proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::Sharing)?;
    let client = leg_client(
        &origin_identity,
        &proxy_identity,
        ConnectUdpProxy::new(&proxy.template())?,
    )?;
    let primary = super::checked(bounded(async {
        fetch(&client, &one.uri("/one"), "/one").await?;
        fetch(&client, &two.uri("/two"), "/two").await?;
        assert_eq!(proxy.connections(), 1);
        Ok(())
    }))
    .await;
    let result = finish_with_cleanup(primary, one.finish().await);
    let primary = if result.is_ok() {
        super::checked(bounded(fetch(
            &client,
            &two.uri("/still-open"),
            "/still-open",
        )))
        .await
    } else {
        result
    };
    let assertion = super::checked(async {
        assert_eq!(proxy.connections(), 1);
        Ok(())
    })
    .await;
    let primary = finish_with_cleanup(primary, assertion);
    drop(client);
    let result = finish_with_cleanup(primary, proxy.finish().await);
    finish_with_cleanup(result, two.finish().await)
}

#[tokio::test]
async fn independent_routes_do_not_share_outer_h3_connections() -> TestResult<()> {
    let (origin_identity, proxy_identity) = identities()?;
    let one = Origin::spawn(&origin_identity)?;
    let two = Origin::spawn(&origin_identity)?;
    let mut proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::Sharing)?;
    let primary = super::checked(bounded(async {
        let first = leg_client(
            &origin_identity,
            &proxy_identity,
            ConnectUdpProxy::new(&proxy.template())?,
        )?;
        let second = leg_client(
            &origin_identity,
            &proxy_identity,
            ConnectUdpProxy::new(&proxy.template())?,
        )?;
        fetch(&first, &one.uri("/one"), "/one").await?;
        fetch(&second, &two.uri("/two"), "/two").await?;
        assert_eq!(proxy.connections(), 2);
        Ok(())
    }))
    .await;
    let result = finish_with_cleanup(primary, proxy.finish().await);
    let result = finish_with_cleanup(result, one.finish().await);
    finish_with_cleanup(result, two.finish().await)
}

#[test]
fn excessive_route_limits_are_recoverable() -> TestResult<()> {
    let route = ConnectUdpProxy::new(
        "https://localhost/.well-known/masque/udp/{target_host}/{target_port}/",
    )?;
    assert_eq!(
        route
            .with_tunnel_limits(NonZeroUsize::MAX, NonZeroUsize::MIN)
            .err()
            .map(|e| e.kind()),
        Some(phantom::ConnectUdpProxyConfigErrorKind::InvalidLimits)
    );
    Ok(())
}

#[tokio::test]
async fn a_reset_h3_tunnel_does_not_retire_the_shared_outer() -> TestResult<()> {
    let (origin_identity, proxy_identity) = identities()?;
    let failed = Origin::spawn(&origin_identity)?;
    let healthy = Origin::spawn(&origin_identity)?;
    let mut proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::SharingResetFirst)?;
    let client = leg_client(
        &origin_identity,
        &proxy_identity,
        ConnectUdpProxy::new(&proxy.template())?,
    )?;
    let primary = super::checked(bounded(async {
        let error = client
            .get(HttpProtocol::Http3, &failed.uri("/reset"))?
            .send()
            .await
            .err()
            .ok_or("reset tunnel succeeded")?;
        assert!(matches!(
            error.kind(),
            RequestErrorKind::Proxy | RequestErrorKind::Connect | RequestErrorKind::Tls
        ));
        fetch(&client, &healthy.uri("/healthy"), "/healthy").await?;
        assert_eq!(proxy.connections(), 1);
        assert_eq!(proxy.requests().len(), 2);
        assert_eq!(healthy.connections(), 1);
        Ok(())
    }))
    .await;
    drop(client);
    let result = finish_with_cleanup(primary, proxy.finish().await);
    let result = finish_with_cleanup(result, failed.finish().await);
    finish_with_cleanup(result, healthy.finish().await)
}

#[tokio::test]
async fn a_reset_h2_tunnel_does_not_retire_the_shared_outer() -> TestResult<()> {
    let (origin_identity, proxy_identity) = identities()?;
    let failed = Origin::spawn(&origin_identity)?;
    let healthy = Origin::spawn(&origin_identity)?;
    let mut proxy = MasqueStreamProxy::spawn(
        &proxy_identity,
        StreamLeg::Http2,
        StreamMode::SharingResetFirst,
    )
    .await?;
    let primary = super::checked(bounded(async {
        let client = leg_client(
            &origin_identity,
            &proxy_identity,
            ConnectUdpProxy::new(&proxy.template())?.with_http2_transport(),
        )?;
        let error = client
            .get(HttpProtocol::Http3, &failed.uri("/reset"))?
            .send()
            .await
            .err()
            .ok_or("reset tunnel succeeded")?;
        assert!(matches!(
            error.kind(),
            RequestErrorKind::Proxy | RequestErrorKind::Connect | RequestErrorKind::Tls
        ));
        fetch(&client, &healthy.uri("/healthy"), "/healthy").await?;
        assert_eq!(proxy.connections(), 1);
        assert_eq!(proxy.requests().len(), 2);
        assert_eq!(healthy.connections(), 1);
        Ok(())
    }))
    .await;
    let result = finish_with_cleanup(primary, proxy.shutdown().await);
    let result = finish_with_cleanup(result, failed.finish().await);
    finish_with_cleanup(result, healthy.finish().await)
}

#[tokio::test]
async fn shared_route_overflow_reaches_the_public_capacity_error() -> TestResult<()> {
    let (origin_identity, proxy_identity) = identities()?;
    let active = Origin::spawn(&origin_identity)?;
    let pending = Origin::spawn(&origin_identity)?;
    let overflow = Origin::spawn(&origin_identity)?;
    let mut proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::Sharing)?;
    let client = leg_client(
        &origin_identity,
        &proxy_identity,
        ConnectUdpProxy::new(&proxy.template())?
            .with_tunnel_limits(NonZeroUsize::MIN, NonZeroUsize::MIN)?,
    )?;
    let mut tasks = tokio::task::JoinSet::new();
    let primary = super::checked(bounded(async {
        fetch(&client, &active.uri("/active"), "/active").await?;
        for uri in [pending.uri("/pending"), overflow.uri("/overflow")] {
            let client = client.clone();
            tasks.spawn(async move { client.get(HttpProtocol::Http3, &uri)?.send().await });
        }
        let completed = timeout(TEST_TIMEOUT, tasks.join_next())
            .await?
            .ok_or("overflow task absent")??;
        let error = completed
            .err()
            .ok_or("full active pool opened another tunnel")?;
        assert_eq!(error.kind(), RequestErrorKind::Capacity);
        assert_eq!(
            connect_udp_error(&error)
                .ok_or("capacity source lost")?
                .kind(),
            ConnectUdpErrorKind::Capacity
        );
        assert_eq!(proxy.connections(), 1);
        assert_eq!(proxy.requests().len(), 1);
        Ok(())
    }))
    .await;
    tasks.abort_all();
    let cleanup = bounded(async {
        let mut result = Ok(());
        while let Some(completed) = tasks.join_next().await {
            let assertion = super::checked(async {
                assert!(completed.err().is_some_and(|e| e.is_cancelled()));
                Ok(())
            })
            .await;
            result = finish_with_cleanup(result, assertion);
        }
        result
    })
    .await;
    let primary = finish_with_cleanup(primary, cleanup);
    drop(client);
    let result = finish_with_cleanup(primary, proxy.finish().await);
    let result = finish_with_cleanup(result, active.finish().await);
    let result = finish_with_cleanup(result, pending.finish().await);
    finish_with_cleanup(result, overflow.finish().await)
}

#[test]
fn route_clones_keep_scope_while_independent_routes_and_mutations_do_not() -> TestResult<()> {
    let template = "https://localhost/.well-known/masque/udp/{target_host}/{target_port}/";
    let route = ConnectUdpProxy::new(template)?;
    assert_eq!(route, route.clone());
    assert_ne!(route, ConnectUdpProxy::new(template)?);
    assert_ne!(route, route.clone().with_http2_transport());
    assert_ne!(
        route,
        route
            .clone()
            .header(RequestHeader::new("x-scope", "changed"))
    );
    assert_ne!(route, route.clone().with_basic_auth("user", "pass")?);
    Ok(())
}

#[tokio::test]
async fn per_request_independent_route_scope_prevents_inner_connection_reuse() -> TestResult<()> {
    let (origin_identity, proxy_identity) = identities()?;
    let origin = Origin::spawn(&origin_identity)?;
    let mut proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::Sharing)?;
    let first = ConnectUdpProxy::new(&proxy.template())?;
    let second = ConnectUdpProxy::new(&proxy.template())?;
    let client = leg_client(&origin_identity, &proxy_identity, first.clone())?;
    let primary = super::checked(bounded(async {
        fetch(&client, &origin.uri("/first"), "/first").await?;
        let response = client
            .get(HttpProtocol::Http3, &origin.uri("/second"))?
            .route(Route::connect_udp(second))
            .send()
            .await?;
        assert_eq!(response.into_body().collect().await?.to_bytes(), "/second");
        fetch(&client, &origin.uri("/clone"), "/clone").await?;
        assert_eq!(proxy.connections(), 2);
        assert_eq!(origin.connections(), 2);
        assert_eq!(proxy.requests().len(), 2);
        Ok(())
    }))
    .await;
    drop(client);
    let result = finish_with_cleanup(primary, proxy.finish().await);
    finish_with_cleanup(result, origin.finish().await)
}
