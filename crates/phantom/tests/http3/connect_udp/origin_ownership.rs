use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

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

#[tokio::test]
async fn dropping_a_stalled_origin_destroys_its_response_task() -> TestResult<()> {
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
        assert_eq!(origin.requests(), ["/stall"]);
        let responses = Arc::clone(&origin.responses);
        assert_eq!(responses.load(Ordering::SeqCst), 1);

        drop(origin);
        let stopped = timeout(DEADLINE, async {
            while responses.load(Ordering::SeqCst) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        drop(body);
        drop(client);

        assert!(
            stopped.is_ok(),
            "stalled response task outlived its fixture"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn an_ordinary_response_releases_its_task_witness() -> TestResult<()> {
    bounded(async {
        let (identity, proxy_identity) = identities()?;
        let origin = Origin::spawn(&identity)?;
        let client = client_builder(&identity, &proxy_identity).build()?;
        let response = client
            .get(HttpProtocol::Http3, &origin.uri("/complete"))?
            .send()
            .await?;
        assert_eq!(
            response.into_body().collect().await?.to_bytes(),
            "/complete"
        );
        assert_eq!(origin.requests(), ["/complete"]);

        timeout(DEADLINE, async {
            while origin.responses.load(Ordering::SeqCst) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    })
    .await
}
