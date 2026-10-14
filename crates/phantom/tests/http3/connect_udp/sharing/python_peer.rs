use super::super::*;
use super::native::fetch;

#[tokio::test]
#[ignore = "requires PHANTOM_CONNECT_UDP_PYTHON with the pinned peer packages"]
async fn aioquic_1_3_0_shares_one_h3_outer_after_basic_authentication() -> TestResult<()> {
    named_peer("h3").await
}

#[tokio::test]
#[ignore = "requires PHANTOM_CONNECT_UDP_PYTHON with the pinned peer packages"]
async fn python_h2_4_4_1_shares_one_h2_outer_after_basic_authentication() -> TestResult<()> {
    named_peer("h2").await
}

async fn named_peer(leg: &str) -> TestResult<()> {
    let (origin_identity, proxy_identity) = identities()?;
    let one = Origin::spawn(&origin_identity)?;
    let two = Origin::spawn(&origin_identity)?;
    let mut peer =
        masque_support::python_peer::PythonPeer::spawn(&proxy_identity, leg, true).await?;
    let primary = bounded(async {
        let mut route = ConnectUdpProxy::new(&peer.template())?.with_basic_auth("user", "pass")?;
        if leg == "h2" {
            route = route.with_http2_transport();
        }
        let client = leg_client(&origin_identity, &proxy_identity, route)?;
        let one_uri = one.uri("/one");
        let two_uri = two.uri("/two");
        tokio::try_join!(
            fetch(&client, &one_uri, "/one"),
            fetch(&client, &two_uri, "/two")
        )?;
        let stats = peer.stats()?;
        assert_eq!(stats["connections"], 2);
        let requests = stats["requests"]
            .as_array()
            .ok_or("missing peer requests")?;
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0]["authorized"], false);
        assert_eq!(requests[1]["authorized"], true);
        assert_eq!(requests[2]["authorized"], true);
        assert_eq!(requests[1]["connection"], requests[2]["connection"]);
        assert_ne!(requests[1]["stream"], requests[2]["stream"]);
        assert_eq!(one.connections(), 1);
        assert_eq!(two.connections(), 1);
        assert_eq!(stats["failures"], serde_json::json!([]));
        Ok(())
    })
    .await;
    let result = finish_with_cleanup(primary, peer.finish().await);
    let result = finish_with_cleanup(result, one.finish().await);
    finish_with_cleanup(result, two.finish().await)
}
