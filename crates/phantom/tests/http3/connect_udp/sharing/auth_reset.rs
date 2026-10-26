//! A reset retry never proves that the peer accepted configured credentials.

use super::super::*;
use super::native::fetch;

fn authorizations<'a>(fields: impl Iterator<Item = &'a [(String, Vec<u8>)]>) -> Vec<bool> {
    fields
        .map(|fields| {
            fields.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("proxy-authorization") && value == b"Basic dXNlcjpwYXNz"
            })
        })
        .collect()
}

fn assert_outer_sequence(streams: &[(usize, u64)]) {
    assert_eq!(streams.len(), 5);
    assert_ne!(streams[0].0, streams[1].0);
    assert_eq!(streams[1].0, streams[2].0);
    assert_ne!(streams[2].0, streams[3].0);
    assert_ne!(streams[0].0, streams[3].0);
    assert_eq!(streams[3].0, streams[4].0);
    assert_ne!(streams[1].1, streams[2].1);
    assert_ne!(streams[3].1, streams[4].1);
}

#[tokio::test]
async fn reset_authenticated_h3_retry_requires_a_new_challenge_before_shared_reuse()
-> TestResult<()> {
    let (origin_identity, proxy_identity) = identities()?;
    let failed = Origin::spawn(&origin_identity)?;
    let healthy = Origin::spawn(&origin_identity)?;
    let sibling = Origin::spawn(&origin_identity)?;
    let mut proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::SharingChallengeResetOnce)?;
    let primary = super::checked(bounded(async {
        let route = ConnectUdpProxy::new(&proxy.template())?.with_basic_auth("user", "pass")?;
        let client = leg_client(&origin_identity, &proxy_identity, route)?;
        let error = client
            .get_with_protocol(HttpProtocol::Http3, &failed.uri("/reset"))?
            .send()
            .await
            .err()
            .ok_or("authenticated reset succeeded")?;
        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        assert_eq!(
            connect_udp_kind(&error),
            Some(ConnectUdpErrorKind::Protocol)
        );
        assert_eq!(failed.connections(), 0);
        assert!(failed.requests().is_empty());
        fetch(&client, &healthy.uri("/healthy"), "/healthy").await?;
        fetch(&client, &sibling.uri("/sibling"), "/sibling").await?;
        assert_eq!(proxy.connections(), 3);
        assert_eq!(healthy.connections(), 1);
        assert_eq!(sibling.connections(), 1);
        assert_eq!(
            authorizations(
                proxy
                    .requests()
                    .iter()
                    .map(|request| request.fields.as_slice())
            ),
            [false, true, false, true, true]
        );
        assert_outer_sequence(&proxy.stream_ids());
        Ok(())
    }))
    .await;
    let result = finish_with_cleanup(primary, proxy.finish().await);
    let result = finish_with_cleanup(result, failed.finish().await);
    let result = finish_with_cleanup(result, healthy.finish().await);
    finish_with_cleanup(result, sibling.finish().await)
}

#[tokio::test]
async fn reset_authenticated_h2_retry_requires_a_new_challenge_before_shared_reuse()
-> TestResult<()> {
    let (origin_identity, proxy_identity) = identities()?;
    let failed = Origin::spawn(&origin_identity)?;
    let healthy = Origin::spawn(&origin_identity)?;
    let sibling = Origin::spawn(&origin_identity)?;
    let mut proxy = MasqueStreamProxy::spawn(
        &proxy_identity,
        StreamLeg::Http2,
        StreamMode::SharingChallengeResetOnce,
    )
    .await?;
    let primary = super::checked(bounded(async {
        let route = ConnectUdpProxy::new(&proxy.template())?
            .with_http2_transport()
            .with_basic_auth("user", "pass")?;
        let client = leg_client(&origin_identity, &proxy_identity, route)?;
        let error = client
            .get_with_protocol(HttpProtocol::Http3, &failed.uri("/reset"))?
            .send()
            .await
            .err()
            .ok_or("authenticated reset succeeded")?;
        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        assert_eq!(
            connect_udp_kind(&error),
            Some(ConnectUdpErrorKind::Protocol)
        );
        assert_eq!(failed.connections(), 0);
        assert!(failed.requests().is_empty());
        fetch(&client, &healthy.uri("/healthy"), "/healthy").await?;
        fetch(&client, &sibling.uri("/sibling"), "/sibling").await?;
        assert_eq!(proxy.connections(), 3);
        assert_eq!(healthy.connections(), 1);
        assert_eq!(sibling.connections(), 1);
        assert_eq!(
            authorizations(
                proxy
                    .requests()
                    .iter()
                    .map(|request| request.fields.as_slice())
            ),
            [false, true, false, true, true]
        );
        assert_outer_sequence(&proxy.stream_ids());
        Ok(())
    }))
    .await;
    let result = finish_with_cleanup(primary, proxy.shutdown().await);
    let result = finish_with_cleanup(result, failed.finish().await);
    let result = finish_with_cleanup(result, healthy.finish().await);
    finish_with_cleanup(result, sibling.finish().await)
}
