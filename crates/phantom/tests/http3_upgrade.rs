//! Public Alt-Svc to HTTP/3 upgrade integration tests.

#[allow(dead_code)]
#[path = "support/h3.rs"]
mod h3_support;
#[path = "support/http3_upgrade.rs"]
mod http3_upgrade_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr},
    num::NonZeroUsize,
    time::Duration,
};

use http::StatusCode;
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, RequestErrorKind, ResponseInfo,
    profile::{ClientProfile, chromium},
};
use tokio::time::timeout;

use h3_support::client_settings;
use http3_upgrade_support::{
    AltSvcAdvertisement, AlternativeBehavior, Http3UpgradeFixture, PlannedResponse, UpgradeScript,
};
use tls_support::{TestIdentity, TestResult, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const ORIGIN_NAME: &str = "127.0.0.1";

#[tokio::test]
async fn opt_in_alt_svc_preserves_origin_identity_while_upgrading_to_http3() -> TestResult<()> {
    bounded(async {
        let identity =
            TestIdentity::generate_for_ip_and_dns(IpAddr::V4(Ipv4Addr::LOCALHOST), "localhost")?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            "localhost",
            UpgradeScript::new(
                [PlannedResponse::new(StatusCode::OK)
                    .body("origin")
                    .advertise_alternative()],
                AlternativeBehavior::responses([
                    PlannedResponse::new(StatusCode::OK).body("alternative")
                ]),
            )
            .advertisement(AltSvcAdvertisement::default().host(ORIGIN_NAME)),
        )
        .await?;
        let origin_authority = format!("localhost:{}", fixture.origin_address().port());
        assert_ne!(fixture.origin_address(), fixture.alternative_address());
        let client = upgrade_client(&identity)?;

        let first = client
            .get_negotiated(&fixture.origin_url("/learn"))?
            .send()
            .await?;
        assert_eq!(protocol(&first)?, HttpProtocol::Http2);
        assert_eq!(first.into_body().collect().await?.to_bytes(), "origin");

        let second = client
            .get_negotiated(&fixture.origin_url("/upgrade"))?
            .send()
            .await?;
        assert_eq!(protocol(&second)?, HttpProtocol::Http3);
        assert_eq!(
            second.into_body().collect().await?.to_bytes(),
            "alternative"
        );

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_requests.len(), 1);
        assert_eq!(observed.alternative_requests.len(), 1);
        assert_eq!(
            observed.alternative_requests[0].authority.as_deref(),
            Some(origin_authority.as_str())
        );
        assert_eq!(
            observed.alternative_requests[0].path_and_query.as_deref(),
            Some("/upgrade")
        );
        assert_eq!(
            observed.alternative_requests[0].server_name.as_deref(),
            Some("localhost")
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn alt_svc_is_disabled_by_default() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            ORIGIN_NAME,
            UpgradeScript::new(
                [
                    PlannedResponse::new(StatusCode::OK).advertise_alternative(),
                    PlannedResponse::new(StatusCode::OK),
                ],
                AlternativeBehavior::responses([]),
            ),
        )
        .await?;
        let client = upgrade_client_builder(&identity).build()?;

        drain(
            client
                .get_negotiated(&fixture.origin_url("/first"))?
                .send()
                .await?,
        )
        .await?;
        let second = client
            .get_negotiated(&fixture.origin_url("/second"))?
            .send()
            .await?;
        assert_eq!(protocol(&second)?, HttpProtocol::Http2);
        drain(second).await?;

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_requests.len(), 2);
        assert!(observed.alternative_requests.is_empty());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn alternative_setup_failure_is_terminal_and_evicts_the_advertisement() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            ORIGIN_NAME,
            UpgradeScript::new(
                [
                    PlannedResponse::new(StatusCode::OK).advertise_alternative(),
                    PlannedResponse::new(StatusCode::OK),
                ],
                AlternativeBehavior::close_after_handshake(0x100, b"planned failure".to_vec()),
            ),
        )
        .await?;
        let client = upgrade_client(&identity)?;

        drain(
            client
                .get_negotiated(&fixture.origin_url("/learn"))?
                .send()
                .await?,
        )
        .await?;
        let error = client
            .get_negotiated(&fixture.origin_url("/fails"))?
            .send()
            .await
            .err()
            .ok_or("failed alternative unexpectedly returned a response")?;
        assert_eq!(error.kind(), RequestErrorKind::Http3);
        assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
        assert_eq!(fixture.snapshot()?.origin_requests.len(), 1);

        let recovered = client
            .get_negotiated(&fixture.origin_url("/origin-again"))?
            .send()
            .await?;
        assert_eq!(protocol(&recovered)?, HttpProtocol::Http2);
        drain(recovered).await?;

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_requests.len(), 2);
        assert!(observed.alternative_requests.is_empty());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn misdirected_alternative_is_visible_and_evicts_its_state() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            ORIGIN_NAME,
            UpgradeScript::new(
                [
                    PlannedResponse::new(StatusCode::OK).advertise_alternative(),
                    PlannedResponse::new(StatusCode::OK),
                ],
                AlternativeBehavior::responses([PlannedResponse::new(
                    StatusCode::MISDIRECTED_REQUEST,
                )]),
            ),
        )
        .await?;
        let client = upgrade_client(&identity)?;

        drain(
            client
                .get_negotiated(&fixture.origin_url("/learn"))?
                .send()
                .await?,
        )
        .await?;
        let misdirected = client
            .get_negotiated(&fixture.origin_url("/misdirected"))?
            .send()
            .await?;
        assert_eq!(misdirected.status(), StatusCode::MISDIRECTED_REQUEST);
        assert_eq!(protocol(&misdirected)?, HttpProtocol::Http3);
        drain(misdirected).await?;

        let recovered = client
            .get_negotiated(&fixture.origin_url("/origin-again"))?
            .send()
            .await?;
        assert_eq!(protocol(&recovered)?, HttpProtocol::Http2);
        drain(recovered).await?;

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_requests.len(), 2);
        assert_eq!(observed.alternative_requests.len(), 1);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn clearing_alt_svc_forces_the_next_request_back_to_the_origin() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            ORIGIN_NAME,
            UpgradeScript::new(
                [
                    PlannedResponse::new(StatusCode::OK).advertise_alternative(),
                    PlannedResponse::new(StatusCode::OK),
                ],
                AlternativeBehavior::responses([]),
            ),
        )
        .await?;
        let client = upgrade_client(&identity)?;

        drain(
            client
                .get_negotiated(&fixture.origin_url("/learn"))?
                .send()
                .await?,
        )
        .await?;
        client.clear_alt_svc();
        let response = client
            .get_negotiated(&fixture.origin_url("/after-clear"))?
            .send()
            .await?;
        assert_eq!(protocol(&response)?, HttpProtocol::Http2);
        drain(response).await?;

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_requests.len(), 2);
        assert!(observed.alternative_requests.is_empty());
        Ok(())
    })
    .await
}

fn upgrade_client(identity: &TestIdentity) -> TestResult<Client> {
    let maximum_origins = NonZeroUsize::new(8).ok_or("Alt-Svc test capacity was zero")?;
    Ok(upgrade_client_builder(identity)
        .alt_svc(maximum_origins)
        .build()?)
}

fn upgrade_client_builder(identity: &TestIdentity) -> phantom::ClientBuilder {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(chromium::v152_macos_http2())
        .with_http3(client_settings());
    Client::builder(profile).add_root_certificate_der(identity.root_der.clone())
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
        .map_err(|_| "Alt-Svc HTTP/3 integration test exceeded its deadline")?
}
