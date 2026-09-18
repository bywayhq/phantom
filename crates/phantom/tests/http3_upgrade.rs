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
    convert::Infallible,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::{HeaderValue, Method, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, RequestErrorKind, RequestHeader, RequestTrailerName, ResponseInfo,
    profile::{ClientHint, ClientHintDelivery, ClientHintSettings, ClientProfile, chromium},
};
use tokio::time::timeout;

use h3_support::client_settings;
use http3_upgrade_support::{
    AltSvcAdvertisement, AlternativeBehavior, Http3UpgradeFixture, ObservedRequest,
    PlannedResponse, UpgradeScript,
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
        let alternative_authority = format!("127.0.0.1:{}", fixture.alternative_address().port());
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
            .headers(vec![
                RequestHeader::new("x-before", "first"),
                RequestHeader::new("x-after", "second"),
            ])
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
        assert!(header_values(&observed.origin_requests[0], "alt-used").is_empty());
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
        assert_eq!(
            field_pairs(&observed.alternative_requests[0]),
            [
                ("x-before", b"first".as_slice()),
                ("x-after", b"second".as_slice()),
                ("alt-used", alternative_authority.as_bytes()),
            ]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn exact_http3_does_not_emit_alt_used() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            ORIGIN_NAME,
            UpgradeScript::new(
                [],
                AlternativeBehavior::responses([PlannedResponse::new(StatusCode::OK)]),
            ),
        )
        .await?;
        let client = upgrade_client(&identity)?;
        let response = client
            .get(
                HttpProtocol::Http3,
                &format!("https://{}/exact", fixture.alternative_address()),
            )?
            .header(RequestHeader::new("x-exact", "only"))
            .send()
            .await?;
        assert_eq!(protocol(&response)?, HttpProtocol::Http3);
        drain(response).await?;

        drop(client);
        let observed = fixture.finish().await?;
        assert!(observed.origin_requests.is_empty());
        assert_eq!(observed.alternative_requests.len(), 1);
        assert_eq!(
            field_pairs(&observed.alternative_requests[0]),
            [("x-exact", b"only".as_slice())]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn caller_supplied_alt_used_fields_and_trailers_are_rejected_before_io() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            ORIGIN_NAME,
            UpgradeScript::new([], AlternativeBehavior::responses([])),
        )
        .await?;
        let client = upgrade_client(&identity)?;
        let error = client
            .get_negotiated(&fixture.origin_url("/rejected"))?
            .header(RequestHeader::new("Alt-Used", "caller.invalid:443"))
            .send()
            .await
            .err()
            .ok_or("caller-supplied Alt-Used unexpectedly succeeded")?;
        assert_eq!(error.kind(), RequestErrorKind::InvalidHeader);

        let error = client
            .request_negotiated(Method::POST, &fixture.origin_url("/static-trailer"))?
            .body("payload")
            .trailers(vec![RequestHeader::new("Alt-Used", "caller.invalid:443")])
            .send()
            .await
            .err()
            .ok_or("caller-supplied static Alt-Used trailer unexpectedly succeeded")?;
        assert_eq!(error.kind(), RequestErrorKind::InvalidHeader);

        let body_polls = Arc::new(AtomicUsize::new(0));
        let error = client
            .request_negotiated(Method::POST, &fixture.origin_url("/dynamic-trailer"))?
            .streaming_body_with_trailers(
                PollCountingBody::new(Arc::clone(&body_polls)),
                vec![RequestTrailerName::new("alt-used")],
            )
            .send()
            .await
            .err()
            .ok_or("declared body-produced Alt-Used trailer unexpectedly succeeded")?;
        assert_eq!(error.kind(), RequestErrorKind::InvalidHeader);
        assert_eq!(body_polls.load(Ordering::SeqCst), 0);

        let snapshot = fixture.snapshot()?;
        assert_eq!(snapshot.origin_connections, 0);
        assert_eq!(snapshot.alternative_connections, 0);

        drop(client);
        let observed = fixture.finish().await?;
        assert!(observed.origin_requests.is_empty());
        assert!(observed.alternative_requests.is_empty());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn ipv6_alternative_uses_bracketed_canonical_alt_used_authority() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns("localhost")?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            "localhost",
            UpgradeScript::new(
                [PlannedResponse::new(StatusCode::OK).advertise_alternative()],
                AlternativeBehavior::responses([PlannedResponse::new(StatusCode::OK)]),
            )
            .alternative_ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
            .advertisement(AltSvcAdvertisement::default().host("[::1]")),
        )
        .await?;
        let expected = format!("[::1]:{}", fixture.alternative_address().port());
        let client = upgrade_client(&identity)?;

        drain(
            client
                .get_negotiated(&fixture.origin_url("/learn"))?
                .send()
                .await?,
        )
        .await?;
        drain(
            client
                .get_negotiated(&fixture.origin_url("/ipv6"))?
                .send()
                .await?,
        )
        .await?;

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.alternative_requests.len(), 1);
        assert_eq!(
            header_values(&observed.alternative_requests[0], "alt-used"),
            [expected.as_bytes()]
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
async fn misdirected_alternative_ignores_conflicting_alt_svc_and_evicts_state() -> TestResult<()> {
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
                )
                .header(
                    http::header::ALT_SVC,
                    HeaderValue::from_static("h3=\":1\"; ma=86400"),
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
        assert!(header_values(&observed.origin_requests[1], "alt-used").is_empty());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn critical_ch_replay_keeps_one_stable_alt_used_field() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            ORIGIN_NAME,
            UpgradeScript::new(
                [PlannedResponse::new(StatusCode::OK).advertise_alternative()],
                AlternativeBehavior::responses([
                    PlannedResponse::new(StatusCode::OK)
                        .header("accept-ch", HeaderValue::from_static("Sec-CH-UA-Arch"))
                        .header("critical-ch", HeaderValue::from_static("Sec-CH-UA-Arch"))
                        .header(
                            http::header::ALT_SVC,
                            HeaderValue::from_static("h3=\":1\"; ma=86400"),
                        ),
                    PlannedResponse::new(StatusCode::NO_CONTENT),
                ]),
            ),
        )
        .await?;
        let expected = format!("127.0.0.1:{}", fixture.alternative_address().port());
        let maximum_origins = NonZeroUsize::new(8).ok_or("Alt-Svc test capacity was zero")?;
        let profile = ClientProfile::new(tls_settings())
            .with_http2(chromium::v152_macos_http2())
            .with_http3(client_settings())
            .with_client_hints(ClientHintSettings::new(vec![ClientHint::new(
                "sec-ch-ua-arch",
                "\"arm\"",
                ClientHintDelivery::AcceptCh,
            )]));
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .alt_svc(maximum_origins)
            .build()?;

        drain(
            client
                .get_negotiated(&fixture.origin_url("/learn"))?
                .send()
                .await?,
        )
        .await?;
        let response = client
            .get_negotiated(&fixture.origin_url("/critical"))?
            .header(RequestHeader::new("x-stable", "caller"))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        drain(response).await?;

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.alternative_requests.len(), 2);
        assert_eq!(
            field_pairs(&observed.alternative_requests[0]),
            [
                ("x-stable", b"caller".as_slice()),
                ("alt-used", expected.as_bytes()),
            ]
        );
        assert_eq!(
            field_pairs(&observed.alternative_requests[1]),
            [
                ("sec-ch-ua-arch", b"\"arm\"".as_slice()),
                ("x-stable", b"caller".as_slice()),
                ("alt-used", expected.as_bytes()),
            ]
        );
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

fn header_values<'a>(request: &'a ObservedRequest, name: &str) -> Vec<&'a [u8]> {
    request
        .fields
        .iter()
        .filter(|field| field.name == name)
        .map(|field| field.value.as_slice())
        .collect()
}

fn field_pairs(request: &ObservedRequest) -> Vec<(&str, &[u8])> {
    request
        .fields
        .iter()
        .map(|field| (field.name.as_str(), field.value.as_slice()))
        .collect()
}

struct PollCountingBody {
    polls: Arc<AtomicUsize>,
}

impl PollCountingBody {
    fn new(polls: Arc<AtomicUsize>) -> Self {
        Self { polls }
    }
}

impl Body for PollCountingBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(None)
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "Alt-Svc HTTP/3 integration test exceeded its deadline")?
}
