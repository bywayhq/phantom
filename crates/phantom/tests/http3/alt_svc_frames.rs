//! Public learning of HTTP/2 ALTSVC frames (RFC 7838 section 4).

use crate::support::h3 as h3_support;
use crate::support::http3_upgrade as http3_upgrade_support;
use crate::support::tls as tls_support;

use std::{future::Future, num::NonZeroUsize, time::Duration};

use http::{HeaderValue, StatusCode};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, ResponseInfo,
    profile::{ClientProfile, chromium},
};
use tokio::time::timeout;

use h3_support::client_settings;
use http3_upgrade_support::{
    AlternativeBehavior, Http3UpgradeFixture, PlannedAltSvcFrame, PlannedResponse, UpgradeScript,
};
use tls_support::{TestIdentity, TestResult, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const ORIGIN_NAME: &str = "127.0.0.1";

#[tokio::test]
async fn h2_altsvc_frame_on_stream_zero_upgrades_next_negotiated_request() -> TestResult<()> {
    assert_second_request_upgrades(PlannedAltSvcFrame::CanonicalOrigin).await
}

#[tokio::test]
async fn h2_altsvc_frame_on_request_stream_upgrades_next_negotiated_request() -> TestResult<()> {
    assert_second_request_upgrades(PlannedAltSvcFrame::RequestStream).await
}

#[tokio::test]
async fn altsvc_frame_for_another_origin_is_ignored() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        // The same host on the default port is a different origin.
        let first = PlannedResponse::new(StatusCode::OK)
            .altsvc_frame(PlannedAltSvcFrame::Origin("https://other.example".into()))
            .altsvc_frame(PlannedAltSvcFrame::Origin(format!("https://{ORIGIN_NAME}")));
        let fixture = spawn(&identity, [first, PlannedResponse::new(StatusCode::OK)], 0).await?;
        let client = client(&identity, true)?;

        assert_eq!(
            negotiated(&client, &fixture, "/first").await?,
            HttpProtocol::Http2
        );
        assert_eq!(
            negotiated(&client, &fixture, "/second").await?,
            HttpProtocol::Http2
        );

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_request_count, 2);
        assert!(observed.alternative_requests.is_empty());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn altsvc_frames_are_ignored_when_alt_svc_is_disabled() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let first = PlannedResponse::new(StatusCode::OK)
            .altsvc_frame(PlannedAltSvcFrame::CanonicalOrigin)
            .altsvc_frame(PlannedAltSvcFrame::RequestStream);
        let fixture = spawn(&identity, [first, PlannedResponse::new(StatusCode::OK)], 0).await?;
        let client = client(&identity, false)?;

        assert_eq!(
            negotiated(&client, &fixture, "/first").await?,
            HttpProtocol::Http2
        );
        assert_eq!(
            negotiated(&client, &fixture, "/second").await?,
            HttpProtocol::Http2
        );

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_request_count, 2);
        assert!(observed.alternative_requests.is_empty());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn exact_http2_requests_do_not_learn_altsvc_frames() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let exact = PlannedResponse::new(StatusCode::OK)
            .altsvc_frame(PlannedAltSvcFrame::CanonicalOrigin)
            .altsvc_frame(PlannedAltSvcFrame::RequestStream);
        let fixture = spawn(&identity, [exact, PlannedResponse::new(StatusCode::OK)], 0).await?;
        let client = client(&identity, true)?;

        let response = client
            .get(HttpProtocol::Http2, &fixture.origin_url("/exact"))?
            .send()
            .await?;
        assert_eq!(protocol(&response)?, HttpProtocol::Http2);
        drain(response).await?;
        assert_eq!(
            negotiated(&client, &fixture, "/second").await?,
            HttpProtocol::Http2
        );

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_request_count, 2);
        assert!(observed.alternative_requests.is_empty());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn frame_then_field_on_one_response_applies_in_arrival_order() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        // The frame advertises the alternative; the later `clear` field wins.
        let first = PlannedResponse::new(StatusCode::OK)
            .altsvc_frame(PlannedAltSvcFrame::RequestStream)
            .header(http::header::ALT_SVC, HeaderValue::from_static("clear"));
        let fixture = spawn(&identity, [first, PlannedResponse::new(StatusCode::OK)], 0).await?;
        let client = client(&identity, true)?;

        assert_eq!(
            negotiated(&client, &fixture, "/first").await?,
            HttpProtocol::Http2
        );
        assert_eq!(
            negotiated(&client, &fixture, "/second").await?,
            HttpProtocol::Http2
        );

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_request_count, 2);
        assert!(observed.alternative_requests.is_empty());
        Ok(())
    })
    .await
}

async fn assert_second_request_upgrades(frame: PlannedAltSvcFrame) -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let first = PlannedResponse::new(StatusCode::OK).altsvc_frame(frame);
        let fixture = spawn(&identity, [first], 1).await?;
        let client = client(&identity, true)?;

        assert_eq!(
            negotiated(&client, &fixture, "/learn").await?,
            HttpProtocol::Http2
        );
        assert_eq!(
            negotiated(&client, &fixture, "/upgrade").await?,
            HttpProtocol::Http3
        );

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_request_count, 1);
        assert_eq!(observed.alternative_requests.len(), 1);
        assert_eq!(
            observed.alternative_requests[0].path_and_query.as_deref(),
            Some("/upgrade")
        );
        Ok(())
    })
    .await
}

async fn spawn(
    identity: &TestIdentity,
    origin_responses: impl IntoIterator<Item = PlannedResponse>,
    alternative_responses: usize,
) -> TestResult<Http3UpgradeFixture> {
    Http3UpgradeFixture::spawn(
        identity,
        ORIGIN_NAME,
        UpgradeScript::new(
            origin_responses,
            AlternativeBehavior::responses(
                (0..alternative_responses).map(|_| PlannedResponse::new(StatusCode::OK)),
            ),
        ),
    )
    .await
}

async fn negotiated(
    client: &Client,
    fixture: &Http3UpgradeFixture,
    path: &str,
) -> TestResult<HttpProtocol> {
    let response = client
        .get_negotiated(&fixture.origin_url(path))?
        .send()
        .await?;
    let protocol = protocol(&response)?;
    drain(response).await?;
    Ok(protocol)
}

fn client(identity: &TestIdentity, alt_svc: bool) -> TestResult<Client> {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(chromium::v154_http2())
        .with_http3(client_settings());
    let builder = Client::builder(profile).add_root_certificate_der(identity.root_der.clone());
    let builder = if alt_svc {
        builder.alt_svc(NonZeroUsize::new(8).ok_or("Alt-Svc test capacity was zero")?)
    } else {
        builder
    };
    Ok(builder.build()?)
}

fn protocol<B>(response: &http::Response<B>) -> TestResult<HttpProtocol> {
    response
        .extensions()
        .get::<ResponseInfo>()
        .map(ResponseInfo::protocol)
        .ok_or_else(|| "response omitted protocol metadata".into())
}

async fn drain(response: http::Response<phantom::ResponseBody>) -> TestResult<()> {
    response.into_body().collect().await?;
    Ok(())
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "ALTSVC frame integration test exceeded its deadline")?
}
