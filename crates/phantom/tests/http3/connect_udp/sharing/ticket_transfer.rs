//! Imported outer TLS tickets survive sharing and leave the source cache intact.

use super::super::*;
use super::native::fetch;

const KEY: [u8; 32] = [7; 32];

#[tokio::test]
async fn cold_import_resumes_a_shared_h2_outer_without_consuming_source_tickets() -> TestResult<()>
{
    let mut origins = Vec::new();
    let mut proxy_owner = None;
    let result = super::checked(bounded(async {
        let (origin_identity, proxy_identity) = identities()?;
        for _ in 0..6 {
            origins.push(Origin::spawn(&origin_identity)?);
        }
        let proxy = proxy_owner.insert(
            MasqueStreamProxy::spawn(&proxy_identity, StreamLeg::Http2, StreamMode::Sharing)
                .await?,
        );
        let configured_route = ConnectUdpProxy::new(&proxy.template())?.with_http2_transport();
        let route = Route::connect_udp(configured_route.clone());
        let source = leg_client(&origin_identity, &proxy_identity, configured_route.clone())?;
        let recipient = leg_client(&origin_identity, &proxy_identity, configured_route)?;

        for (round, pair) in origins.as_chunks::<2>().0.iter().enumerate() {
            // Fresh inner origins force new tunnels after each deliberate outer
            // close, without waiting for earlier QUIC connections to notice it.
            let client = if round == 1 { &recipient } else { &source };
            let one = pair[0].uri("/one");
            let two = pair[1].uri("/two");
            tokio::try_join!(fetch(client, &one, "/one"), fetch(client, &two, "/two")).map_err(
                |error| {
                    let mut message = format!("outer import round {round}: {error}");
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
            assert_eq!(proxy.resumed_handshakes(), [false, true, true][..=round]);

            if round == 0 {
                let snapshot = source.export_session_tickets(&KEY)?;
                proxy.close_connections_and_wait().await?;
                // The recipient has made no requests. The snapshot includes the
                // shared proxy owner and the source's two inner origin owners.
                recipient.import_session_tickets(&snapshot, &KEY, std::slice::from_ref(&route))?;
            } else if round == 1 {
                // Return to the source after the recipient's imported resumption.
                // Its next actual handshake must still offer a usable ticket.
                proxy.close_connections_and_wait().await?;
            }
        }
        Ok(())
    }))
    .await;

    let mut result = match proxy_owner.as_mut() {
        Some(proxy) => finish_with_cleanup(result, proxy.shutdown().await),
        None => result,
    };
    for origin in origins {
        result = finish_with_cleanup(result, origin.finish().await);
    }
    result
}
