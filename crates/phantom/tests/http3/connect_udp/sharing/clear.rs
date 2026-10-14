//! Clearing a real pending outer never republishes its retired generation.

use super::super::*;
use phantom_net::{
    http3::{Http3Connection, Http3Connector},
    proxy::ConnectUdpProxyPool,
    request::OriginForm,
    route::{ConnectUdpRoute, ConnectUdpTransport, DatagramRoute, Endpoint},
};
use tokio::{sync::oneshot, task::JoinSet};

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

#[tokio::test]
async fn clear_during_held_h3_setup_keeps_active_tunnels_and_retires_late_publication()
-> TestResult<()> {
    let (origin_identity, proxy_identity) = identities()?;
    let origin_connector = Arc::new(connector(&origin_identity)?);
    let proxy_connector = Arc::new(connector(&proxy_identity)?);
    let one = Origin::spawn(&origin_identity)?;
    let two = Origin::spawn(&origin_identity)?;
    let three = Origin::spawn(&origin_identity)?;
    let mut proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::Sharing)?;
    let pool = ConnectUdpProxyPool::new();
    let mut connections = Vec::new();
    let mut tasks = JoinSet::new();
    let mut release: Option<oneshot::Sender<()>> = None;
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
        marker(&origin_connector, &connections[0], &one, "/before-clear").await?;
        assert_eq!(proxy.connections(), 1);

        // Make the next actual CONNECT own a fresh setup, keeping the first
        // inner connection alive on the retired outer.
        pool.clear();
        let control = proxy.hold_next_setup()?;
        release = Some(control.release);
        let origin = Arc::clone(&origin_connector);
        let outer = Arc::clone(&proxy_connector);
        let pending_pool = pool.clone();
        let proxy_address = proxy.address;
        let target = two.address;
        tasks.spawn(
            async move { open(&origin, &outer, &pending_pool, proxy_address, target).await },
        );
        let held = control.observed.await?;
        let streams = proxy.stream_ids();
        assert_eq!(streams.len(), 2);
        assert_eq!(held, streams[1]);
        assert_ne!(streams[0].0, held.0);
        assert_eq!(proxy.connections(), 2);
        assert_eq!(two.connections(), 0);

        // This clear happens after the real CONNECT reaches the peer but
        // before the successful response can publish its SetupLease.
        pool.clear();
        marker(&origin_connector, &connections[0], &one, "/while-held").await?;
        assert_eq!(proxy.connections(), 2);
        release
            .take()
            .ok_or("held setup release absent")?
            .send(())
            .map_err(|_| "held setup peer disappeared")?;
        let completed = tasks.join_next().await.ok_or("held setup task absent")??;
        connections.push(completed?);
        marker(&origin_connector, &connections[1], &two, "/late-accepted").await?;
        assert_eq!(proxy.connections(), 2);

        // Late success is usable by its caller, but the next target must
        // dial one new outer instead of retaining that retired generation.
        connections.push(
            open(
                &origin_connector,
                &proxy_connector,
                &pool,
                proxy.address,
                three.address,
            )
            .await?,
        );
        marker(&origin_connector, &connections[2], &three, "/fresh-outer").await?;
        marker(
            &origin_connector,
            &connections[0],
            &one,
            "/first-still-active",
        )
        .await?;
        marker(
            &origin_connector,
            &connections[1],
            &two,
            "/second-still-active",
        )
        .await?;
        assert_eq!(proxy.connections(), 3);
        let streams = proxy.stream_ids();
        assert_eq!(streams.len(), 3);
        assert_ne!(streams[0].0, streams[1].0);
        assert_ne!(streams[0].0, streams[2].0);
        assert_ne!(streams[1].0, streams[2].0);
        assert_eq!(proxy.requests().len(), 3);
        assert_eq!(
            (one.connections(), two.connections(), three.connections()),
            (1, 1, 1)
        );
        Ok(())
    }))
    .await;

    // Own every setup task and every tunnel even when the body or deadline
    // fails. Release the peer before collecting failures from its workers.
    let mut result = primary;
    if let Some(release) = release.take()
        && release.send(()).is_err()
    {
        result = finish_with_cleanup(
            result,
            Err("held setup peer disappeared during cleanup".into()),
        );
    }
    tasks.abort_all();
    while let Some(completed) = tasks.join_next().await {
        let cleanup = match completed {
            Ok(Ok(connection)) => {
                drop(connection);
                Ok(())
            }
            Ok(Err(error)) => Err(error),
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error.into()),
        };
        result = finish_with_cleanup(result, cleanup);
    }
    connections.clear();
    pool.clear();
    drop(pool);
    drop(origin_connector);
    drop(proxy_connector);
    result = finish_with_cleanup(result, proxy.finish().await);
    result = finish_with_cleanup(result, one.finish().await);
    result = finish_with_cleanup(result, two.finish().await);
    finish_with_cleanup(result, three.finish().await)
}
