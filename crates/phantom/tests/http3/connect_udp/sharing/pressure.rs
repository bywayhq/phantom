//! Cancellation frees a real pending admission without disturbing siblings.

use super::super::*;
use phantom_net::{
    http3::{Http3Connection, Http3Connector, Http3ConnectorError, Http3ConnectorErrorKind},
    proxy::ConnectUdpProxyPool,
    request::OriginForm,
    route::{ConnectUdpRoute, ConnectUdpTransport, DatagramRoute, Endpoint},
};
use std::{future::poll_fn, task::Poll};

fn connector(identity: &TestIdentity) -> TestResult<Http3Connector> {
    let settings = masque_client_settings();
    Ok(Http3Connector::new_with_additional_roots(
        settings.tls(),
        settings.quic_transport(),
        settings.http3(),
        settings.request(),
        [identity.root_der.as_slice()],
    )?)
}

async fn open(
    origin: &Http3Connector,
    proxy: &Http3Connector,
    pool: &ConnectUdpProxyPool,
    proxy_address: SocketAddr,
    target: SocketAddr,
) -> TestResult<Http3Connection> {
    let authority = proxy_address.to_string();
    let path = format!("/.well-known/masque/udp/127.0.0.1/{}/", target.port());
    Ok(origin
        .connect(
            DatagramRoute::ConnectUdp(ConnectUdpRoute {
                proxy: Endpoint {
                    host: "127.0.0.1",
                    port: proxy_address.port(),
                },
                transport: ConnectUdpTransport::Http3(proxy),
                authority: &authority,
                path: OriginForm::parse(&path)?,
                headers: Vec::new(),
                credentials: None,
                pool: Some(pool),
                prepared_outer: None,
            }),
            "127.0.0.1",
        )
        .await?)
}

async fn marker(
    connector: &Http3Connector,
    connection: &Http3Connection,
    origin: &Origin,
    path: &str,
) -> TestResult<()> {
    let response = connector
        .send_get_on(
            connection,
            &origin.address.to_string(),
            OriginForm::parse(path)?,
            Vec::new(),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.into_body().collect().await?.to_bytes(), path);
    Ok(())
}

fn require_capacity(result: TestResult<Http3Connection>) -> TestResult<()> {
    let error = result
        .err()
        .ok_or("full CONNECT-UDP admission opened a tunnel")?;
    let connector = error
        .downcast_ref::<Http3ConnectorError>()
        .ok_or("capacity lost its HTTP/3 connector error")?;
    assert_eq!(connector.kind(), Http3ConnectorErrorKind::Proxy);
    let source = connector
        .source()
        .and_then(|source| source.downcast_ref::<ConnectUdpError>())
        .ok_or("capacity lost its CONNECT-UDP source")?;
    assert_eq!(source.kind(), ConnectUdpErrorKind::Capacity);
    Ok(())
}

#[tokio::test]
async fn canceling_pending_h3_tunnel_reclaims_admission_and_preserves_accepted_sibling()
-> TestResult<()> {
    let (origin_identity, proxy_identity) = identities()?;
    let origin_connector = connector(&origin_identity)?;
    let proxy_connector = connector(&proxy_identity)?;
    let one = Origin::spawn(&origin_identity)?;
    let two = Origin::spawn(&origin_identity)?;
    let three = Origin::spawn(&origin_identity)?;
    let mut proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::Sharing)?;
    let active = NonZeroUsize::new(2).ok_or("active limit cannot be zero")?;
    let pool = ConnectUdpProxyPool::with_limits(active, NonZeroUsize::MIN)?;
    let mut connections = Vec::new();
    let primary = super::checked(bounded(async {
        connections.push(
            open(
                &origin_connector,
                &proxy_connector,
                &pool,
                proxy.address,
                one.address,
            )
            .await?,
        );
        connections.push(
            open(
                &origin_connector,
                &proxy_connector,
                &pool,
                proxy.address,
                two.address,
            )
            .await?,
        );
        marker(&origin_connector, &connections[0], &one, "/first-accepted").await?;
        marker(&origin_connector, &connections[1], &two, "/second-accepted").await?;
        let initial = proxy.stream_ids();
        assert_eq!(initial.len(), 2);
        assert_eq!(initial[0].0, initial[1].0);
        assert_eq!((initial[0].1, initial[1].1), (0, 4));
        assert_eq!(proxy.connections(), 1);

        // This public connect's first pooled await is actual admission.
        // Poll with the Tokio task's waker instead of yielding or sleeping.
        let mut canceled = Box::pin(open(
            &origin_connector,
            &proxy_connector,
            &pool,
            proxy.address,
            three.address,
        ));
        let observed = poll_fn(|context| Poll::Ready(canceled.as_mut().poll(context))).await;
        assert!(observed.is_pending());
        require_capacity(
            open(
                &origin_connector,
                &proxy_connector,
                &pool,
                proxy.address,
                three.address,
            )
            .await,
        )?;
        assert_eq!(proxy.stream_ids(), initial);
        assert_eq!(proxy.requests().len(), 2);
        assert_eq!(three.connections(), 0);
        drop(canceled);

        // The canceled future releases the sole pending slot. A replacement
        // waits, and an additional open still returns the original typed error.
        let mut replacement = Box::pin(open(
            &origin_connector,
            &proxy_connector,
            &pool,
            proxy.address,
            three.address,
        ));
        let observed = poll_fn(|context| Poll::Ready(replacement.as_mut().poll(context))).await;
        assert!(observed.is_pending());
        require_capacity(
            open(
                &origin_connector,
                &proxy_connector,
                &pool,
                proxy.address,
                three.address,
            )
            .await,
        )?;
        marker(
            &origin_connector,
            &connections[0],
            &one,
            "/sibling-during-pressure",
        )
        .await?;
        assert_eq!(proxy.stream_ids(), initial);
        assert_eq!(three.connections(), 0);

        // Release an accepted tunnel, then await real permit-driven progress.
        // No retry or timer assertion substitutes for the actual CONNECT.
        drop(connections.pop().ok_or("second accepted tunnel absent")?);
        connections.push(replacement.await?);
        marker(
            &origin_connector,
            &connections[1],
            &three,
            "/replacement-accepted",
        )
        .await?;
        marker(
            &origin_connector,
            &connections[0],
            &one,
            "/sibling-after-cancel",
        )
        .await?;
        let accepted = proxy.stream_ids();
        assert_eq!(accepted.len(), 3);
        assert_eq!(&accepted[..2], initial.as_slice());
        assert_eq!(accepted[2].0, initial[0].0);
        assert_eq!(accepted[2].1, 8);
        assert_eq!(proxy.connections(), 1);
        let paths: Vec<_> = proxy
            .requests()
            .iter()
            .map(|request| request.path.clone())
            .collect();
        assert_eq!(
            paths,
            [one.address, two.address, three.address]
                .map(|target| format!("/.well-known/masque/udp/127.0.0.1/{}/", target.port()))
        );
        assert_eq!(
            (one.connections(), two.connections(), three.connections()),
            (1, 1, 1)
        );
        Ok(())
    }))
    .await;

    // All pending futures are stack-owned by the bounded body and dropped
    // on failure/cancellation. Release every accepted tunnel before peer joins.
    connections.clear();
    pool.clear();
    drop(pool);
    drop(origin_connector);
    drop(proxy_connector);
    let result = finish_with_cleanup(primary, proxy.finish().await);
    let result = finish_with_cleanup(result, one.finish().await);
    let result = finish_with_cleanup(result, two.finish().await);
    finish_with_cleanup(result, three.finish().await)
}
