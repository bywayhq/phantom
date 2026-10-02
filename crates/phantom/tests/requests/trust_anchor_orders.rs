//! A client draws a per-client trust anchor ID order once, for all of its
//! TCP connections, and rejects a per-client list it cannot draw from.

use std::{net::Ipv4Addr, time::Duration};

use phantom::{
    BuildErrorKind, Client, HttpProtocol, HttpProxy, Route,
    profile::{ClientProfile, Http3ClientSettings, TrustAnchorIds, chromium, opera},
};
use phantom_testkit::tls::{CaptureLimits, ClientHelloSummary, capture_client_hello};
use tokio::{net::TcpListener, sync::mpsc, time::timeout};

use crate::support::{tls::TestResult, tunnel_proxy};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Opera 136 sends one trust-anchor order on every TCP connection of a
/// process. A client stands for the process: its HTTP/1.1, HTTP/2, HTTPS
/// proxy, proxy tunnel, and WebSocket connections share one drawn order, and
/// separate clients draw different ones from the recipe's retained orders.
#[tokio::test]
async fn opera_136_client_keeps_one_tcp_trust_anchor_order_across_connectors() -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let capture_address = listener.local_addr()?;
    let url = format!("https://{capture_address}/");
    let (orders_sender, mut orders_receiver) = mpsc::unbounded_channel();
    // The capture drops each stream after its ClientHello, which fails the
    // request; the order is sent before the drop, so it is queued when the
    // request returns.
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await?;
            let capture = capture_client_hello(
                &mut stream,
                tokio::time::Instant::now() + TEST_TIMEOUT,
                CaptureLimits::new(64 * 1024, 64 * 1024, 8),
            )
            .await?;
            let order = ClientHelloSummary::from_handshake_bytes(capture.handshake_bytes())?
                .requested_trust_anchor_ids()
                .map(<[_]>::to_vec);
            if orders_sender.send(order).is_err() {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
        }
    });

    let recipe_orders = opera::v136_tls()
        .requested_trust_anchor_ids
        .ok_or("Opera 136 recipe omitted trust-anchor IDs")?
        .orders()
        .iter()
        .map(|order| order.iter().map(|id| id.to_vec()).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let mut drawn = Vec::new();
    for _ in 0..12 {
        let profile = ClientProfile::new(opera::v136_tls()).with_http2(chromium::v154_http2());
        #[cfg(feature = "websocket")]
        let profile = profile.with_websocket(chromium::v154_websocket());
        let client = Client::builder(profile).build()?;
        let mut client_orders = Vec::new();
        let mut connections = 0;

        for protocol in [HttpProtocol::Http1, HttpProtocol::Http2] {
            let request = client.get(protocol, &url)?.send();
            assert!(timeout(TEST_TIMEOUT, request).await?.is_err());
            connections += 1;
        }

        // The capture server stands in for an HTTPS proxy, so it records
        // the ClientHello the client sends to the proxy.
        let https_proxy = Route::http_proxy(HttpProxy::new(&format!("https://{capture_address}"))?);
        let request = client
            .get(HttpProtocol::Http1, &url)?
            .route(https_proxy)
            .send();
        assert!(timeout(TEST_TIMEOUT, request).await?.is_err());
        connections += 1;

        // A plaintext proxy tunnels to the capture server, which records
        // the origin ClientHello sent through the tunnel.
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let tunnel = Route::http_proxy(HttpProxy::new(&format!(
            "http://{}",
            proxy_listener.local_addr()?
        ))?);
        let proxy = tokio::spawn(tunnel_proxy::http1_connect(proxy_listener, capture_address));
        let request = client.get(HttpProtocol::Http1, &url)?.route(tunnel).send();
        assert!(timeout(TEST_TIMEOUT, request).await?.is_err());
        timeout(TEST_TIMEOUT, proxy).await???;
        connections += 1;

        #[cfg(feature = "websocket")]
        {
            let websocket = client
                .websocket_with_profile_policy(&format!("wss://{capture_address}/"))?
                .connect();
            assert!(timeout(TEST_TIMEOUT, websocket).await?.is_err());
            connections += 1;
        }

        while let Ok(order) = orders_receiver.try_recv() {
            client_orders.push(order.ok_or("Opera 136 client omitted trust-anchor IDs")?);
        }
        assert!(client_orders.len() >= connections);
        client_orders.dedup();
        let [order] = client_orders.as_slice() else {
            return Err("one client sent more than one trust-anchor order".into());
        };
        assert!(recipe_orders.contains(order));
        drawn.push(order.clone());
    }
    server.abort();

    // The most frequent of the 29 listed orders appears 5 times, so twelve
    // alike draws have a probability below 10^-9.
    drawn.sort_unstable();
    drawn.dedup();
    assert!(drawn.len() > 1);
    Ok(())
}

/// A per-client list whose orders hold different IDs cannot be drawn from,
/// so building a client with one in its HTTP/3 TLS settings fails instead of
/// fixing one of its orders.
#[test]
fn http3_per_client_orders_with_different_ids_fail_the_build() -> TestResult<()> {
    let mut tls = opera::v136_http3_tls();
    let order = tls
        .requested_trust_anchor_ids
        .as_ref()
        .ok_or("Opera 136 H3 recipe omitted trust-anchor IDs")?
        .orders()
        .first()
        .cloned()
        .ok_or("Opera 136 H3 recipe listed no trust-anchor order")?;
    let mut shorter = order.clone();
    shorter.pop();
    tls.requested_trust_anchor_ids = Some(TrustAnchorIds::PerClient(vec![order, shorter]));
    let http3 = Http3ClientSettings::new(
        tls,
        chromium::v154_quic(),
        chromium::v154_http3(),
        chromium::v154_http3_request(),
    );
    let profile = ClientProfile::new(opera::v136_tls()).with_http3(http3);

    let error = match Client::builder(profile).build() {
        Ok(_) => return Err("an undrawable HTTP/3 per-client list was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), BuildErrorKind::InvalidProfile);
    // The HTTP/3 connector rejects the list, not the client's draw.
    assert!(error.to_string().starts_with("failed to configure HTTP/3"));
    Ok(())
}
