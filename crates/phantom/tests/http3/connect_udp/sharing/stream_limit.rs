//! An actual QUIC stream limit keeps another CONNECT pending on one outer.

use super::super::*;
use phantom_net::{
    http3::{Http3Connection, Http3Connector},
    proxy::ConnectUdpProxyPool,
    request::OriginForm,
    route::{ConnectUdpRoute, ConnectUdpTransport, DatagramRoute, Endpoint},
};
use std::{future::poll_fn, pin::Pin, task::Poll};

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

async fn must_wait<F>(mut future: Pin<&mut F>) -> TestResult<()>
where
    F: Future<Output = TestResult<Http3Connection>>,
{
    poll_fn(|context| match future.as_mut().poll(context) {
        Poll::Pending => Poll::Ready(Ok(())),
        Poll::Ready(Ok(connection)) => {
            drop(connection);
            Poll::Ready(Err(
                "peer limit allowed a second CONNECT while the first was held".into(),
            ))
        }
        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
    })
    .await
}

#[tokio::test]
async fn peer_bidi_limit_waits_on_one_outer_and_closing_a_tunnel_releases_it() -> TestResult<()> {
    let (origin_identity, proxy_identity) = identities()?;
    let origin_connector = connector(&origin_identity)?;
    let proxy_connector = connector(&proxy_identity)?;
    let one = Origin::spawn(&origin_identity)?;
    let two = Origin::spawn(&origin_identity)?;
    let mut proxy = MasqueProxy::spawn_with_single_bidi_stream(&proxy_identity)?;
    let pool = ConnectUdpProxyPool::new();
    let mut first = None;
    let mut second = None;
    let primary = super::checked(bounded(async {
        first = Some(
            open(
                &origin_connector,
                &proxy_connector,
                &pool,
                proxy.address,
                one.address,
            )
            .await?,
        );
        marker(
            &origin_connector,
            first.as_ref().ok_or("first tunnel absent")?,
            &one,
            "/first",
        )
        .await?;
        assert_eq!(proxy.connections(), 1);
        assert_eq!(proxy.requests().len(), 1);
        let original_stream = proxy.stream_ids()[0];

        let pending = open(
            &origin_connector,
            &proxy_connector,
            &pool,
            proxy.address,
            two.address,
        );
        tokio::pin!(pending);
        must_wait(pending.as_mut()).await?;
        // Progress an actual inner request while the only outer stream stays held.
        marker(
            &origin_connector,
            first.as_ref().ok_or("first tunnel absent")?,
            &one,
            "/while-second-waits",
        )
        .await?;
        must_wait(pending.as_mut()).await?;
        assert_eq!(proxy.connections(), 1);
        assert_eq!(proxy.requests().len(), 1);
        assert_eq!(proxy.stream_ids(), [original_stream]);
        assert_eq!(two.connections(), 0);

        // Last ownership of the first inner connection closes its CONNECT stream.
        drop(first.take());
        second = Some(pending.await?);
        marker(
            &origin_connector,
            second.as_ref().ok_or("second tunnel absent")?,
            &two,
            "/after-stream-credit",
        )
        .await?;
        marker(
            &origin_connector,
            second.as_ref().ok_or("second tunnel absent")?,
            &two,
            "/second-still-open",
        )
        .await?;
        assert_eq!(proxy.connections(), 1);
        assert_eq!(proxy.requests().len(), 2);
        let streams = proxy.stream_ids();
        assert_eq!(streams.len(), 2);
        assert_eq!(streams[0], original_stream);
        assert_eq!(streams[1], (original_stream.0, original_stream.1 + 4));
        assert_eq!(two.connections(), 1);
        Ok(())
    }))
    .await;

    // Cancel any pending open before cleanup, and collect every owned peer.
    drop(first.take());
    drop(second.take());
    pool.clear();
    drop(pool);
    drop(origin_connector);
    drop(proxy_connector);
    let result = finish_with_cleanup(primary, proxy.finish().await);
    let result = finish_with_cleanup(result, one.finish().await);
    finish_with_cleanup(result, two.finish().await)
}
