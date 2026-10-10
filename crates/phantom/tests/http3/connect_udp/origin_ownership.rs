use std::{sync::Arc, time::Duration};

use http_body_util::BodyExt;
use tokio::time::timeout;

use super::{HttpProtocol, Origin, TestResult, bounded, client_builder, identities};

const DEADLINE: Duration = Duration::from_secs(5);

#[tokio::test]
async fn dropping_a_stalled_origin_releases_its_connection_observations() -> TestResult<()> {
    bounded(async {
        let (identity, proxy_identity) = identities()?;
        let origin = Origin::spawn(&identity)?;
        let client = client_builder(&identity, &proxy_identity).build()?;
        let response = client
            .get(HttpProtocol::Http3, &origin.uri("/stall"))?
            .send()
            .await?;
        let mut body = response.into_body();
        let first = body.frame().await.ok_or("stalled body ended early")??;
        assert_eq!(first.into_data().map_err(|_| "expected DATA")?, "partial");
        assert_eq!(origin.connections(), 1);
        assert_eq!(origin.requests(), ["/stall"]);
        let observations = Arc::downgrade(&origin.requests);

        drop(origin);
        let released = timeout(DEADLINE, async {
            while observations.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await;
        drop(body);
        drop(client);

        assert!(
            released.is_ok(),
            "origin connection still owns observations"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn dropping_a_stalled_origin_ends_its_open_response() -> TestResult<()> {
    bounded(async {
        let (identity, proxy_identity) = identities()?;
        let origin = Origin::spawn(&identity)?;
        let client = client_builder(&identity, &proxy_identity).build()?;
        let response = client
            .get(HttpProtocol::Http3, &origin.uri("/stall"))?
            .send()
            .await?;
        let mut body = response.into_body();
        let first = body.frame().await.ok_or("stalled body ended early")??;
        assert_eq!(first.into_data().map_err(|_| "expected DATA")?, "partial");
        assert_eq!(origin.connections(), 1);
        assert_eq!(origin.requests(), ["/stall"]);

        drop(origin);
        let ended = timeout(DEADLINE, body.frame()).await;
        drop(body);
        drop(client);

        assert!(ended.is_ok(), "origin response outlived its fixture");
        assert!(
            matches!(ended?, None | Some(Err(_))),
            "stalled response continued"
        );
        Ok(())
    })
    .await
}
