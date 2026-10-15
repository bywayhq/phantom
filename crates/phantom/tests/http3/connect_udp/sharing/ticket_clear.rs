//! Clearing a client's shared H2 outer tickets affects its next TLS handshake.

use super::super::*;
use super::native::fetch;

#[tokio::test]
async fn clear_removes_shared_h2_outer_tickets_and_later_handshakes_resume() -> TestResult<()> {
    let (origin_identity, proxy_identity) = identities()?;
    let mut origins = Vec::new();
    for _ in 0..6 {
        origins.push(Origin::spawn(&origin_identity)?);
    }
    let mut proxy =
        MasqueStreamProxy::spawn(&proxy_identity, StreamLeg::Http2, StreamMode::Sharing).await?;
    let result = super::checked(bounded(async {
        let client = leg_client(
            &origin_identity,
            &proxy_identity,
            ConnectUdpProxy::new(&proxy.template())?.with_http2_transport(),
        )?;
        for (round, pair) in origins.as_chunks::<2>().0.iter().enumerate() {
            // Fresh inner origins require new tunnels without waiting for a
            // previously relayed QUIC connection to detect the deliberate close.
            let one = pair[0].uri("/one");
            let two = pair[1].uri("/two");
            tokio::try_join!(fetch(&client, &one, "/one"), fetch(&client, &two, "/two")).map_err(
                |error| {
                    let mut message = format!("outer round {round}: {error}");
                    let mut source = error.source();
                    while let Some(cause) = source {
                        message.push_str(&format!("; {cause}"));
                        source = cause.source();
                    }
                    std::io::Error::other(message)
                },
            )?;
            assert_eq!(pair[0].connections(), 1);
            assert_eq!(pair[1].connections(), 1);
            assert_eq!(proxy.connections(), round + 1);
            let streams = proxy.stream_ids();
            assert_eq!(streams.len(), 2 * (round + 1));
            let current = &streams[2 * round..];
            assert_eq!(current[0].0, current[1].0);
            assert_ne!(current[0].1, current[1].1);
            assert_eq!(proxy.resumed_handshakes(), [false, false, true][..=round]);

            if round == 0 {
                assert!(client.clone().clear_session_tickets()? > 0);
                assert_eq!(client.clear_session_tickets()?, 0);
            }
            if round < 2 {
                proxy.close_connections_and_wait().await?;
            }
        }
        Ok(())
    }))
    .await;
    let mut result = finish_with_cleanup(result, proxy.shutdown().await);
    for origin in origins {
        result = finish_with_cleanup(result, origin.finish().await);
    }
    result
}
