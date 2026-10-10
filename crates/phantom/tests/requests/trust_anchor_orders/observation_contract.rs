use std::net::{Ipv4Addr, SocketAddr};

use phantom::{
    Client, HttpProtocol, HttpProxy, Route,
    profile::{
        ClientProfile,
        browser::{chrome, opera},
    },
};
use tokio::{net::TcpListener, sync::mpsc, time::timeout};

use super::{
    CapturedOrder, Connector, ConnectorObservations, TEST_TIMEOUT, capture_orders, drain_orders,
    expected_connectors, observed_client_order,
};
use crate::support::{
    tls::TestResult,
    tunnel_proxy::{self, ConnectionPeer, finish_with_cleanup},
};

#[tokio::test]
async fn real_connector_batches_keep_one_recipe_order() -> TestResult<()> {
    let (observations, recipe_orders) = real_connector_observations().await?;
    assert_named_batches(&observations, &recipe_orders)?;

    let order = observed_client_order(&observations, expected_connectors(), &recipe_orders)?;
    assert_eq!(order, observations[0].orders[0]);
    Ok(())
}

#[tokio::test]
async fn duplicate_http1_observations_cannot_replace_http2_observations() -> TestResult<()> {
    let (observations, recipe_orders) = real_connector_observations().await?;
    assert_named_batches(&observations, &recipe_orders)?;
    observed_client_order(&observations, expected_connectors(), &recipe_orders)?;

    let mut replacement = observations.clone();
    let http1 = observations
        .iter()
        .find(|batch| batch.connector == Connector::Http1)
        .ok_or("missing actual HTTP/1 capture batch")?;
    let http2 = replacement
        .iter_mut()
        .find(|batch| batch.connector == Connector::Http2)
        .ok_or("missing actual HTTP/2 capture batch")?;
    http2.connector = Connector::Http1;
    http2.orders = vec![http1.orders[0].clone(); http2.orders.len()];

    assert_eq!(capture_count(&replacement), capture_count(&observations));
    assert!(
        !replacement
            .iter()
            .any(|batch| batch.connector == Connector::Http2)
    );
    assert_eq!(
        replacement
            .iter()
            .filter(|batch| batch.connector == Connector::Http1)
            .count(),
        2
    );

    let result = observed_client_order(&replacement, expected_connectors(), &recipe_orders);
    assert!(
        result.is_err(),
        "trust-anchor observer accepted duplicate HTTP/1 captures in place of HTTP/2"
    );
    Ok(())
}

async fn real_connector_observations()
-> TestResult<(Vec<ConnectorObservations>, Vec<CapturedOrder>)> {
    let tls = opera::v136_tcp_tls();
    let recipe_orders = tls
        .requested_trust_anchor_ids
        .as_ref()
        .ok_or("Opera 136 recipe omitted trust-anchor IDs")?
        .orders()
        .iter()
        .map(|order| {
            order
                .as_slice()
                .iter()
                .map(|id| id.to_vec())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let profile = ClientProfile::new(tls).with_http2(chrome::v154_http2());
    #[cfg(feature = "websocket")]
    let profile = profile.with_websocket(chrome::v154_websocket());
    let client = Client::builder(profile).build()?;

    let observations = vec![
        capture_connector(&client, Connector::Http1).await?,
        capture_connector(&client, Connector::Http2).await?,
        capture_connector(&client, Connector::HttpsProxy).await?,
        capture_connector(&client, Connector::ProxyTunnel).await?,
    ];
    #[cfg(feature = "websocket")]
    let observations = {
        let mut observations = observations;
        observations.push(capture_connector(&client, Connector::WebSocket).await?);
        observations
    };
    // Keep the same client alive until each capture and tunnel owner has joined.
    drop(client);
    Ok((observations, recipe_orders))
}

async fn capture_connector(
    client: &Client,
    connector: Connector,
) -> TestResult<ConnectorObservations> {
    let listener = timeout(TEST_TIMEOUT, TcpListener::bind((Ipv4Addr::LOCALHOST, 0))).await??;
    let address = listener.local_addr()?;
    let (sender, mut receiver) = mpsc::unbounded_channel();
    let server = ConnectionPeer::spawn(capture_orders(listener, sender));

    let primary = perform_connector(client, connector, address).await;
    finish_with_cleanup(primary, server.stop().await)?;
    let batch = drain_orders(connector, &mut receiver)?;
    if batch.orders.is_empty() {
        return Err("actual connector produced no captured ClientHello".into());
    }
    Ok(batch)
}

async fn perform_connector(
    client: &Client,
    connector: Connector,
    address: SocketAddr,
) -> TestResult<()> {
    let url = format!("https://{address}/");
    match connector {
        Connector::Http1 | Connector::Http2 => {
            let protocol = if connector == Connector::Http1 {
                HttpProtocol::Http1
            } else {
                HttpProtocol::Http2
            };
            let result = timeout(TEST_TIMEOUT, client.get(protocol, &url)?.send()).await?;
            if result.is_ok() {
                return Err("capture-only origin unexpectedly returned a response".into());
            }
        }
        Connector::HttpsProxy => {
            let route = Route::http_proxy(HttpProxy::new(&format!("https://{address}"))?);
            let result = timeout(
                TEST_TIMEOUT,
                client.get(HttpProtocol::Http1, &url)?.route(route).send(),
            )
            .await?;
            if result.is_ok() {
                return Err("capture-only HTTPS proxy unexpectedly returned a response".into());
            }
        }
        Connector::ProxyTunnel => perform_tunnel(client, &url, address).await?,
        #[cfg(feature = "websocket")]
        Connector::WebSocket => {
            let result = timeout(
                TEST_TIMEOUT,
                client
                    .websocket_with_profile_policy(&format!("wss://{address}/"))?
                    .connect(),
            )
            .await?;
            if result.is_ok() {
                return Err(
                    "capture-only WebSocket origin unexpectedly returned a response".into(),
                );
            }
        }
    }
    Ok(())
}

async fn perform_tunnel(client: &Client, url: &str, address: SocketAddr) -> TestResult<()> {
    let listener = timeout(TEST_TIMEOUT, TcpListener::bind((Ipv4Addr::LOCALHOST, 0))).await??;
    let route = Route::http_proxy(HttpProxy::new(&format!(
        "http://{}",
        listener.local_addr()?
    ))?);
    let mut proxy = ConnectionPeer::spawn(tunnel_proxy::http1_connect(listener, address));
    let primary: TestResult<()> = async {
        let result = timeout(
            TEST_TIMEOUT,
            client.get(HttpProtocol::Http1, url)?.route(route).send(),
        )
        .await?;
        if result.is_ok() {
            return Err("capture-only tunneled origin unexpectedly returned a response".into());
        }
        Ok(())
    }
    .await;

    let cleanup = match timeout(TEST_TIMEOUT, &mut proxy).await {
        Ok(Ok(Ok(tunnel))) => {
            let head = match tunnel.cancel().await {
                Ok(head) => head,
                Err(error) => return finish_with_cleanup(primary, Err(error)),
            };
            let expected = format!("CONNECT {address} HTTP/1.1\r\n");
            if head.starts_with(expected.as_bytes()) {
                Ok(())
            } else {
                Err("actual proxy omitted the expected CONNECT request".into())
            }
        }
        Ok(Ok(Err(error))) => Err(error),
        Ok(Err(error)) => Err(error.into()),
        Err(elapsed) => finish_with_cleanup(Err(elapsed.into()), proxy.stop().await),
    };
    finish_with_cleanup(primary, cleanup)
}

fn assert_named_batches(
    observations: &[ConnectorObservations],
    recipe_orders: &[CapturedOrder],
) -> TestResult<()> {
    assert_eq!(
        observations
            .iter()
            .map(|batch| batch.connector)
            .collect::<Vec<_>>(),
        [
            Connector::Http1,
            Connector::Http2,
            Connector::HttpsProxy,
            Connector::ProxyTunnel,
            #[cfg(feature = "websocket")]
            Connector::WebSocket,
        ]
    );
    for batch in observations {
        if batch.orders.is_empty() {
            return Err("named connector has no actual captured order".into());
        }

        for order in &batch.orders {
            assert!(!order.is_empty());
            assert!(recipe_orders.contains(order));
        }
    }
    Ok(())
}

fn capture_count(observations: &[ConnectorObservations]) -> usize {
    observations.iter().map(|batch| batch.orders.len()).sum()
}
