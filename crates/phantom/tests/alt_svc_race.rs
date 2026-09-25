//! Public opt-in racing of a learned HTTP/3 alternative against its origin.

#[allow(dead_code)]
#[path = "support/h3.rs"]
mod h3_support;
#[path = "support/http3_upgrade.rs"]
mod http3_upgrade_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{
    collections::HashSet,
    convert::Infallible,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime},
};

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use phantom::{
    AltSvcBrokenBackoff, AltSvcPolicy, AltSvcRace, AltSvcSnapshot, AltSvcSnapshotEntry, Client,
    HttpProtocol, PreparedRequestTemplate, RequestErrorKind, RequestHeader, RequestTimeouts,
    ResponseInfo, Route, Socks5Proxy, TimeoutPhase,
    profile::{ClientProfile, chromium},
};
use tokio::{
    net::{TcpListener, UdpSocket},
    task::JoinHandle,
    time::timeout,
};

use h3_support::client_settings;
use http3_upgrade_support::{
    AltSvcAdvertisement, AlternativeBehavior, Http3UpgradeFixture, PlannedResponse, UpgradeScript,
};
use tls_support::{TestIdentity, TestResult, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const ORIGIN_NAME: &str = "localhost";
const ALTERNATIVE_HOST: &str = "127.0.0.1";

#[tokio::test]
async fn race_is_disabled_by_default_and_sequential_failure_stays_terminal() -> TestResult<()> {
    bounded(async {
        assert_eq!(AltSvcPolicy::default(), AltSvcPolicy::sequential());
        assert_eq!(AltSvcPolicy::default().race_settings(), None);
        let identity = identity()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            ORIGIN_NAME,
            UpgradeScript::new(
                [
                    PlannedResponse::new(StatusCode::OK).advertise_alternative(),
                    PlannedResponse::new(StatusCode::OK).body("origin"),
                ],
                AlternativeBehavior::close_after_handshake(0x100, b"closed".to_vec()),
            )
            .advertisement(AltSvcAdvertisement::default().host(ALTERNATIVE_HOST)),
        )
        .await?;
        let client = client_builder(&identity)?.build()?;

        let learned = client
            .get_negotiated(&fixture.origin_url("/learn"))?
            .send()
            .await?;
        assert_eq!(protocol(&learned)?, HttpProtocol::Http2);
        drain(learned).await?;

        let error = client
            .get_negotiated(&fixture.origin_url("/terminal"))?
            .send()
            .await
            .err()
            .ok_or("the failed alternative must not fall back to the origin")?;
        assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
        assert_eq!(fixture.snapshot()?.origin_request_count, 1);

        // Sequential use evicts the failed advertisement, so the next request
        // is an ordinary origin request.
        let recovered = client
            .get_negotiated(&fixture.origin_url("/recovered"))?
            .send()
            .await?;
        assert_eq!(protocol(&recovered)?, HttpProtocol::Http2);
        drain(recovered).await?;

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_request_count, 2);
        assert_eq!(observed.alternative_connections, 1);
        assert!(observed.alternative_requests.is_empty());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn race_dispatches_request_on_exactly_one_connection() -> TestResult<()> {
    bounded(async {
        let identity = identity()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            ORIGIN_NAME,
            UpgradeScript::new(
                [
                    PlannedResponse::new(StatusCode::OK).advertise_alternative(),
                    PlannedResponse::new(StatusCode::OK).body("origin"),
                ],
                AlternativeBehavior::responses([
                    PlannedResponse::new(StatusCode::OK).body("alternative")
                ]),
            )
            .advertisement(AltSvcAdvertisement::default().host(ALTERNATIVE_HOST)),
        )
        .await?;
        let client = client_builder(&identity)?
            .alt_svc_policy(race_policy(Duration::ZERO)?)
            .build()?;

        let learned = client
            .get_negotiated(&fixture.origin_url("/learn"))?
            .send()
            .await?;
        drain(learned).await?;

        // The learning H2 connection is still pooled, so the origin candidate
        // is ready at once and carries the request; alternative setup goes on.
        let raced = client
            .get_negotiated(&fixture.origin_url("/raced"))?
            .send()
            .await?;
        assert_eq!(protocol(&raced)?, HttpProtocol::Http2);
        assert_eq!(raced.into_body().collect().await?.to_bytes(), "origin");
        let after_origin = fixture.snapshot()?;
        assert_eq!(after_origin.origin_request_count, 2);
        assert!(after_origin.alternative_requests.is_empty());

        // The unfinished alternative connects in the background and is pooled,
        // so the next race finds it ready and it carries the request.
        wait_until(|| Ok(fixture.snapshot()?.alternative_connections == 1)).await?;
        let pooled = client
            .get_negotiated(&fixture.origin_url("/pooled"))?
            .send()
            .await?;
        assert_eq!(protocol(&pooled)?, HttpProtocol::Http3);
        assert_eq!(
            pooled.into_body().collect().await?.to_bytes(),
            "alternative"
        );

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_request_count, 2);
        assert_eq!(observed.origin_connections, 1);
        assert_eq!(observed.alternative_connections, 1);
        let paths: Vec<_> = observed
            .alternative_requests
            .iter()
            .filter_map(|request| request.path_and_query.as_deref())
            .collect();
        assert_eq!(paths, ["/pooled"]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn one_shot_streaming_body_is_polled_only_by_the_winner() -> TestResult<()> {
    bounded(async {
        let identity = identity()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            ORIGIN_NAME,
            UpgradeScript::new(
                [],
                AlternativeBehavior::responses([
                    PlannedResponse::new(StatusCode::OK).body("alternative")
                ]),
            ),
        )
        .await?;
        // A long origin delay lets the alternative win deterministically.
        let client = client_builder(&identity)?
            .alt_svc_policy(race_policy(Duration::from_secs(30))?)
            .build()?;
        import_alternative(&client, &fixture, fixture.alternative_address().port())?;

        let polls = Arc::new(AtomicUsize::new(0));
        let response = client
            .request_negotiated(Method::POST, &fixture.origin_url("/upload"))?
            .streaming_body(ChunkedBody::new(Arc::clone(&polls), &["one", "two"]))
            .send()
            .await?;
        assert_eq!(protocol(&response)?, HttpProtocol::Http3);
        drain(response).await?;
        // Two data frames and the end of the body: one pass by one attempt.
        assert_eq!(polls.load(Ordering::SeqCst), 3);

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_connections, 0);
        assert_eq!(observed.origin_request_count, 0);
        assert_eq!(observed.alternative_requests.len(), 1);
        assert_eq!(observed.alternative_requests[0].method, Method::POST);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn blackholed_quic_loses_after_configured_delay_and_marks_alternative_broken()
-> TestResult<()> {
    bounded(async {
        let identity = identity()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            // An IP origin avoids a slow refused `::1` attempt on Windows.
            ALTERNATIVE_HOST,
            UpgradeScript::new(
                [
                    PlannedResponse::new(StatusCode::OK).body("first"),
                    PlannedResponse::new(StatusCode::OK).body("second"),
                ],
                AlternativeBehavior::responses([]),
            ),
        )
        .await?;
        let blackhole = Blackhole::bind().await?;
        let origin_delay = Duration::from_millis(150);
        let client = client_builder(&identity)?
            .alt_svc_policy(race_policy(origin_delay)?)
            .request_timeouts(RequestTimeouts::new().connect(Duration::from_millis(600)))
            .build()?;
        import_alternative_for(&client, ALTERNATIVE_HOST, &fixture, blackhole.port)?;

        let started = Instant::now();
        let first = client
            .get_negotiated(&fixture.origin_url("/first"))?
            .send()
            .await?;
        let elapsed = started.elapsed();
        assert_eq!(protocol(&first)?, HttpProtocol::Http2);
        assert_eq!(first.into_body().collect().await?.to_bytes(), "first");
        // QUIC went first and the origin started only after the delay.
        assert!(blackhole.datagrams() > 0);
        assert!(elapsed >= origin_delay, "origin won after {elapsed:?}");

        // The unfinished alternative fails its connect deadline in the
        // background and is marked broken; its datagrams stop.
        wait_until(|| Ok(started.elapsed() > Duration::from_millis(900))).await?;
        let after_failure = blackhole.datagrams();
        let second = client
            .get_negotiated(&fixture.origin_url("/second"))?
            .send()
            .await?;
        assert_eq!(protocol(&second)?, HttpProtocol::Http2);
        assert_eq!(second.into_body().collect().await?.to_bytes(), "second");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(blackhole.datagrams(), after_failure);

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_request_count, 2);
        assert_eq!(observed.alternative_connections, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn blackholed_alternative_connects_once_and_is_not_raced_after_its_limit() -> TestResult<()> {
    bounded(async {
        let identity = identity()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            ALTERNATIVE_HOST,
            UpgradeScript::new(
                [
                    PlannedResponse::new(StatusCode::OK).body("first"),
                    PlannedResponse::new(StatusCode::OK).body("second"),
                    PlannedResponse::new(StatusCode::OK).body("third"),
                ],
                AlternativeBehavior::responses([]),
            ),
        )
        .await?;
        let blackhole = Blackhole::bind().await?;
        // Default request timeouts: only the alternative's own setup limit
        // ends the blackholed QUIC attempt.
        let client = client_builder(&identity)?
            .alt_svc_policy(race_policy(Duration::from_millis(150))?)
            .build()?;
        import_alternative_for(&client, ALTERNATIVE_HOST, &fixture, blackhole.port)?;

        let started = Instant::now();
        let first = client
            .get_negotiated(&fixture.origin_url("/first"))?
            .send()
            .await?;
        assert_eq!(protocol(&first)?, HttpProtocol::Http2);
        drain(first).await?;
        // A second race while the first setup still connects waits for that
        // location's connect turn, loses at once to the pooled H2
        // connection, and is cancelled instead of connecting later.
        let second = client
            .get_negotiated(&fixture.origin_url("/second"))?
            .send()
            .await?;
        assert_eq!(protocol(&second)?, HttpProtocol::Http2);
        drain(second).await?;

        // Chrome's orphaned QUIC job fails after 4 s (`udp-blackhole`).
        wait_until(|| Ok(started.elapsed() > Duration::from_millis(4_500))).await?;
        let after_limit = blackhole.datagrams();
        assert!(after_limit > 0);
        let third = client
            .get_negotiated(&fixture.origin_url("/third"))?
            .send()
            .await?;
        assert_eq!(protocol(&third)?, HttpProtocol::Http2);
        drain(third).await?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        // Only one QUIC connection was ever attempted: the queued second
        // setup never connected, and the alternative abandoned at its limit
        // is broken, so the third request does not race it.
        assert_eq!(blackhole.datagrams(), after_limit);
        assert_eq!(blackhole.peers(), 1);

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_request_count, 3);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn configured_alternative_setup_limit_abandons_a_blackholed_alternative_sooner()
-> TestResult<()> {
    bounded(async {
        let identity = identity()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            ALTERNATIVE_HOST,
            UpgradeScript::new(
                [
                    PlannedResponse::new(StatusCode::OK).body("first"),
                    PlannedResponse::new(StatusCode::OK).body("second"),
                ],
                AlternativeBehavior::responses([]),
            ),
        )
        .await?;
        let blackhole = Blackhole::bind().await?;
        let limit = Duration::from_millis(300);
        let race = race_policy(Duration::from_millis(50))?
            .race_settings()
            .ok_or("the race policy has no race settings")?
            .with_alternative_setup_limit(limit);
        assert_eq!(race.alternative_setup_limit(), limit);
        let client = client_builder(&identity)?
            .alt_svc_policy(AltSvcPolicy::race(race))
            .build()?;
        import_alternative_for(&client, ALTERNATIVE_HOST, &fixture, blackhole.port)?;

        let first = client
            .get_negotiated(&fixture.origin_url("/first"))?
            .send()
            .await?;
        assert_eq!(protocol(&first)?, HttpProtocol::Http2);
        drain(first).await?;
        // Well before the default 4 s, the attempt has stopped sending.
        tokio::time::sleep(Duration::from_millis(900)).await;
        let after_limit = blackhole.datagrams();
        assert!(after_limit > 0);
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(blackhole.datagrams(), after_limit);

        // The abandoned alternative is broken, so it is not raced again.
        let second = client
            .get_negotiated(&fixture.origin_url("/second"))?
            .send()
            .await?;
        assert_eq!(protocol(&second)?, HttpProtocol::Http2);
        drain(second).await?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(blackhole.datagrams(), after_limit);
        assert_eq!(blackhole.peers(), 1);

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_request_count, 2);
        Ok(())
    })
    .await
}

#[test]
fn alternative_setup_limit_defaults_to_chrome_s_four_seconds() -> TestResult<()> {
    let race = race_policy(Duration::ZERO)?
        .race_settings()
        .ok_or("the race policy has no race settings")?;
    assert_eq!(race.alternative_setup_limit(), Duration::from_secs(4));
    Ok(())
}

#[tokio::test]
async fn exact_http3_is_not_delayed_by_a_background_alternative_setup() -> TestResult<()> {
    bounded(async {
        let identity = identity()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            ALTERNATIVE_HOST,
            UpgradeScript::new(
                [PlannedResponse::new(StatusCode::OK).body("origin")],
                AlternativeBehavior::responses([]),
            )
            .origin_http3([PlannedResponse::new(StatusCode::OK).body("exact")]),
        )
        .await?;
        let blackhole = Blackhole::bind().await?;
        let client = client_builder(&identity)?
            .alt_svc_policy(race_policy(Duration::from_millis(100))?)
            .build()?;
        import_alternative_for(&client, ALTERNATIVE_HOST, &fixture, blackhole.port)?;

        let raced = client
            .get_negotiated(&fixture.origin_url("/raced"))?
            .send()
            .await?;
        assert_eq!(protocol(&raced)?, HttpProtocol::Http2);
        drain(raced).await?;

        // The losing alternative keeps connecting for up to 4 s; exact H3 to
        // the origin's own location in the same pool entry does not wait.
        let started = Instant::now();
        let exact = client
            .get(HttpProtocol::Http3, &fixture.origin_url("/exact"))?
            .send()
            .await?;
        let elapsed = started.elapsed();
        assert_eq!(protocol(&exact)?, HttpProtocol::Http3);
        assert_eq!(exact.into_body().collect().await?.to_bytes(), "exact");
        assert!(
            elapsed < Duration::from_secs(2),
            "exact H3 took {elapsed:?}"
        );
        assert!(blackhole.datagrams() > 0);

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_http3_requests.len(), 1);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn available_http2_connection_skips_the_origin_delay() -> TestResult<()> {
    bounded(async {
        let identity = identity()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            ALTERNATIVE_HOST,
            UpgradeScript::new(
                [
                    PlannedResponse::new(StatusCode::OK).body("first"),
                    PlannedResponse::new(StatusCode::OK).body("second"),
                ],
                AlternativeBehavior::responses([]),
            ),
        )
        .await?;
        let blackhole = Blackhole::bind().await?;
        let client = client_builder(&identity)?
            .alt_svc_policy(race_policy(Duration::from_secs(5))?)
            .build()?;
        // Without an alternative the request leaves an idle H2 connection.
        let first = client
            .get_negotiated(&fixture.origin_url("/first"))?
            .send()
            .await?;
        assert_eq!(protocol(&first)?, HttpProtocol::Http2);
        drain(first).await?;
        import_alternative_for(&client, ALTERNATIVE_HOST, &fixture, blackhole.port)?;

        // Like Chrome's `existing-h2-session` capture, the origin candidate
        // uses the available H2 connection at once while QUIC setup goes on.
        let started = Instant::now();
        let second = client
            .get_negotiated(&fixture.origin_url("/second"))?
            .send()
            .await?;
        let elapsed = started.elapsed();
        assert_eq!(protocol(&second)?, HttpProtocol::Http2);
        assert_eq!(second.into_body().collect().await?.to_bytes(), "second");
        assert!(
            elapsed < Duration::from_secs(2),
            "origin waited {elapsed:?}"
        );
        wait_until(|| Ok(blackhole.datagrams() > 0)).await?;

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_connections, 1);
        assert_eq!(observed.origin_request_count, 2);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn raced_setup_releases_admission_after_cancel_and_abandon() -> TestResult<()> {
    bounded(async {
        let identity = identity()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            ALTERNATIVE_HOST,
            UpgradeScript::new(
                [
                    PlannedResponse::new(StatusCode::OK).body("raced"),
                    PlannedResponse::new(StatusCode::OK).body("queued"),
                    PlannedResponse::new(StatusCode::OK).body("broken"),
                ],
                AlternativeBehavior::responses([]),
            )
            .origin_http3([
                PlannedResponse::new(StatusCode::OK).body("after-cancel"),
                PlannedResponse::new(StatusCode::OK).body("after-abandon"),
            ]),
        )
        .await?;
        let blackhole = Blackhole::bind().await?;
        // One H3 request may run per origin and route, so a leaked admission
        // permit makes the next exact-H3 request time out in admission.
        let client = single_http3_admission_client(&identity, Duration::from_millis(500))?;
        import_alternative_for(&client, ALTERNATIVE_HOST, &fixture, blackhole.port)?;

        // Cancel a raced request while its alternative connects.
        let cancelled = tokio::spawn({
            let client = client.clone();
            let url = fixture.origin_url("/cancelled");
            async move { client.get_negotiated(&url)?.send().await }
        });
        wait_until(|| Ok(blackhole.datagrams() > 0)).await?;
        cancelled.abort();
        assert!(cancelled.await.is_err_and(|error| error.is_cancelled()));
        assert_eq!(
            send_exact(&client, &fixture, "/after-cancel").await?,
            "after-cancel"
        );

        // The losing alternative holds its permit while it connects.
        let started = Instant::now();
        let raced = client
            .get_negotiated(&fixture.origin_url("/raced"))?
            .send()
            .await?;
        assert_eq!(protocol(&raced)?, HttpProtocol::Http2);
        drain(raced).await?;
        let blocked = send_exact(&client, &fixture, "/blocked")
            .await
            .err()
            .ok_or("the background setup must hold the only H3 permit")?;
        assert!(blocked.contains("pool admission"), "{blocked}");
        // A race still waiting for admission loses to the pooled H2
        // connection and gives its place back.
        let queued = client
            .get_negotiated(&fixture.origin_url("/queued"))?
            .send()
            .await?;
        assert_eq!(protocol(&queued)?, HttpProtocol::Http2);
        drain(queued).await?;

        // The abandoned setup releases the permit at its 4 s limit.
        let released = loop {
            if let Ok(body) = send_exact(&client, &fixture, "/after-abandon").await {
                break body;
            }
        };
        assert_eq!(released, "after-abandon");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_secs(4),
            "released after {elapsed:?}"
        );
        // Reaching the limit marked the alternative broken, so this request
        // is not raced; an unmarked alternative would open a third QUIC
        // connection beside the cancelled and the abandoned ones.
        let broken = client
            .get_negotiated(&fixture.origin_url("/broken"))?
            .send()
            .await?;
        assert_eq!(protocol(&broken)?, HttpProtocol::Http2);
        drain(broken).await?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(blackhole.peers(), 2);

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_request_count, 3);
        assert_eq!(observed.origin_http3_requests.len(), 2);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn winning_alternative_releases_http3_admission() -> TestResult<()> {
    bounded(async {
        let identity = identity()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            ALTERNATIVE_HOST,
            UpgradeScript::new(
                [],
                AlternativeBehavior::responses([
                    PlannedResponse::new(StatusCode::OK).body("alternative")
                ]),
            )
            .origin_http3([PlannedResponse::new(StatusCode::OK).body("exact")]),
        )
        .await?;
        let client = single_http3_admission_client(&identity, Duration::from_secs(30))?;
        import_alternative_for(
            &client,
            ALTERNATIVE_HOST,
            &fixture,
            fixture.alternative_address().port(),
        )?;

        let raced = client
            .get_negotiated(&fixture.origin_url("/raced"))?
            .send()
            .await?;
        assert_eq!(protocol(&raced)?, HttpProtocol::Http3);
        assert_eq!(raced.into_body().collect().await?.to_bytes(), "alternative");
        assert_eq!(send_exact(&client, &fixture, "/exact").await?, "exact");

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_connections, 0);
        assert_eq!(observed.alternative_requests.len(), 1);
        assert_eq!(observed.origin_http3_requests.len(), 1);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn race_never_changes_route() -> TestResult<()> {
    bounded(async {
        let identity = identity()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            ORIGIN_NAME,
            UpgradeScript::new(
                [],
                AlternativeBehavior::responses([
                    PlannedResponse::new(StatusCode::OK).body("alternative")
                ]),
            ),
        )
        .await?;
        let blackhole = Blackhole::bind().await?;
        let client = client_builder(&identity)?
            .alt_svc_policy(race_policy(Duration::ZERO)?)
            .build()?;
        import_alternative(&client, &fixture, fixture.alternative_address().port())?;

        // A negotiated request on a SOCKS5 route never falls back to a direct
        // connection: the blackhole is UDP-only, so the proxy's TCP connect is
        // refused and the request fails on the proxy leg with neither the
        // origin nor the alternative contacted. Route-keying of the store
        // itself is covered by the `session::alt_svc` unit tests.
        let proxy = Route::socks5(Socks5Proxy::new(&format!(
            "socks5://127.0.0.1:{}",
            blackhole.port
        ))?);
        let error = client
            .get_negotiated(&fixture.origin_url("/proxied"))?
            .route(proxy)
            .send()
            .await
            .err()
            .ok_or("a raced request must keep its proxy route")?;
        // A refused SOCKS5 connect is a proxy failure. `Connect` is the
        // direct-transport category and would mean the fallback this test
        // forbids.
        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        assert_eq!(fixture.snapshot()?.alternative_connections, 0);
        assert_eq!(fixture.snapshot()?.origin_connections, 0);

        // On the direct route the winning alternative keeps the origin's
        // authority and TLS name; only the QUIC location differs.
        let response = client
            .get_negotiated(&fixture.origin_url("/direct"))?
            .send()
            .await?;
        assert_eq!(protocol(&response)?, HttpProtocol::Http3);
        drain(response).await?;

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(blackhole.datagrams(), 0);
        let authority = format!("{ORIGIN_NAME}:{}", fixture_port(&observed)?);
        let request = observed
            .alternative_requests
            .first()
            .ok_or("the alternative saw no request")?;
        assert_eq!(request.authority.as_deref(), Some(authority.as_str()));
        assert_eq!(request.server_name.as_deref(), Some(ORIGIN_NAME));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn race_refuses_an_unplaceable_requested_hint_before_either_candidate_connects()
-> TestResult<()> {
    bounded(async {
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_port = origin.local_addr()?.port();
        let origin_connections = Arc::new(AtomicUsize::new(0));
        let accepted = Arc::clone(&origin_connections);
        let origin_task = tokio::spawn(async move {
            while origin.accept().await.is_ok() {
                accepted.fetch_add(1, Ordering::SeqCst);
            }
        });
        let alternative = Blackhole::bind().await?;
        let maximum_origins = NonZeroUsize::new(8).ok_or("Alt-Svc test capacity was zero")?;
        let client =
            Client::builder(profile().with_client_hints(chromium::v154_windows_client_hints()))
                .alt_svc(maximum_origins)
                .alt_svc_policy(race_policy(Duration::ZERO)?)
                .build()?;
        client.import_alt_svc(&AltSvcSnapshot::new(vec![AltSvcSnapshotEntry::new(
            format!("https://{ORIGIN_NAME}:{origin_port}"),
            ALTERNATIVE_HOST,
            alternative.port,
            SystemTime::now() + Duration::from_secs(3600),
        )]))?;

        // The template has a list for every protocol the race may use but no
        // captured position for a requested hint.
        let mut template = chromium::v154_windows_navigation_template();
        template.requested_client_hint_placement = false;
        let error = client
            .get_negotiated(&format!("https://{ORIGIN_NAME}:{origin_port}/refused"))?
            .template(&PreparedRequestTemplate::new(template)?)
            .header(RequestHeader::new("sec-ch-ua-arch", "\"x86\""))
            .send()
            .await
            .err()
            .ok_or("a requested hint was sent at an uncaptured position")?;
        assert_eq!(error.kind(), RequestErrorKind::RequestTemplate);

        drop(client);
        origin_task.abort();
        assert_eq!(origin_connections.load(Ordering::SeqCst), 0);
        assert_eq!(alternative.datagrams(), 0);
        Ok(())
    })
    .await
}

#[test]
fn racing_requires_an_alt_svc_store_and_a_valid_backoff() -> TestResult<()> {
    assert!(AltSvcBrokenBackoff::new(Duration::ZERO, Duration::from_secs(1)).is_err());
    assert!(AltSvcBrokenBackoff::new(Duration::from_secs(2), Duration::from_secs(1)).is_err());
    let identity = identity()?;
    let error = Client::builder(profile())
        .add_root_certificate_der(identity.root_der.clone())
        .alt_svc_policy(race_policy(Duration::ZERO)?)
        .build()
        .err()
        .ok_or("racing without an Alt-Svc store must be rejected")?;
    assert_eq!(error.kind(), phantom::BuildErrorKind::InvalidPolicy);
    Ok(())
}

#[test]
fn chromium_broken_backoff_matches_captured_and_sourced_values() {
    let backoff = AltSvcBrokenBackoff::CHROMIUM_153;
    assert_eq!(backoff.period(0), Duration::from_secs(300));
    assert_eq!(backoff.period(1), Duration::from_secs(600));
    assert_eq!(backoff.period(9), Duration::from_secs(153_600));
    assert_eq!(backoff.period(10), Duration::from_secs(172_800));
    assert_eq!(backoff.period(u32::MAX), Duration::from_secs(172_800));
}

fn identity() -> TestResult<TestIdentity> {
    TestIdentity::generate_for_ip_and_dns(IpAddr::V4(Ipv4Addr::LOCALHOST), ORIGIN_NAME)
}

fn profile() -> ClientProfile {
    ClientProfile::new(tls_settings())
        .with_http2(chromium::v154_http2())
        .with_http3(client_settings())
}

fn client_builder(identity: &TestIdentity) -> TestResult<phantom::ClientBuilder> {
    let maximum_origins = NonZeroUsize::new(8).ok_or("Alt-Svc test capacity was zero")?;
    Ok(Client::builder(profile())
        .add_root_certificate_der(identity.root_der.clone())
        .alt_svc(maximum_origins))
}

fn race_policy(origin_delay: Duration) -> TestResult<AltSvcPolicy> {
    let backoff = AltSvcBrokenBackoff::new(Duration::from_secs(60), Duration::from_secs(600))?;
    Ok(AltSvcPolicy::race(AltSvcRace::new(origin_delay, backoff)))
}

/// Seeds the alternative without an origin request, so no H2 connection is
/// pooled before the race.
fn import_alternative(client: &Client, fixture: &Http3UpgradeFixture, port: u16) -> TestResult<()> {
    import_alternative_for(client, ORIGIN_NAME, fixture, port)
}

fn import_alternative_for(
    client: &Client,
    origin_name: &str,
    fixture: &Http3UpgradeFixture,
    port: u16,
) -> TestResult<()> {
    let origin = format!("https://{origin_name}:{}", fixture.origin_address().port());
    let expires_at = SystemTime::now() + Duration::from_secs(3600);
    client.import_alt_svc(&AltSvcSnapshot::new(vec![AltSvcSnapshotEntry::new(
        origin,
        ALTERNATIVE_HOST,
        port,
        expires_at,
    )]))?;
    Ok(())
}

/// A racing client that admits one H3 request per origin and route and
/// waits at most 300 ms for admission.
fn single_http3_admission_client(
    identity: &TestIdentity,
    origin_delay: Duration,
) -> TestResult<Client> {
    Ok(client_builder(identity)?
        .alt_svc_policy(race_policy(origin_delay)?)
        .max_concurrent_http3_requests_per_origin(NonZeroUsize::MIN)
        .max_pending_http3_requests_per_origin(NonZeroUsize::MIN)
        .request_timeouts(RequestTimeouts::new().pool_admission(Duration::from_millis(300)))
        .build()?)
}

/// Sends exact H3 to the origin and returns the body, or a description of
/// the failure; a pool-admission timeout is reported as `pool admission`.
async fn send_exact(
    client: &Client,
    fixture: &Http3UpgradeFixture,
    path: &str,
) -> Result<Bytes, String> {
    let response = client
        .get(HttpProtocol::Http3, &fixture.origin_url(path))
        .map_err(|error| error.to_string())?
        .send()
        .await
        .map_err(|error| {
            if error.timeout_phase() == Some(TimeoutPhase::PoolAdmission) {
                "pool admission timed out".to_owned()
            } else {
                error.to_string()
            }
        })?;
    response
        .into_body()
        .collect()
        .await
        .map(|body| body.to_bytes())
        .map_err(|error| error.to_string())
}

fn fixture_port(observed: &http3_upgrade_support::UpgradeObservations) -> TestResult<u16> {
    observed
        .alternative_requests
        .first()
        .and_then(|request| request.authority.as_deref())
        .and_then(|authority| authority.rsplit_once(':'))
        .and_then(|(_, port)| port.parse().ok())
        .ok_or_else(|| "the alternative request had no authority port".into())
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

async fn wait_until(mut condition: impl FnMut() -> TestResult<bool>) -> TestResult<()> {
    while !condition()? {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "Alt-Svc race integration test exceeded its deadline")?
}

/// A UDP socket that counts and drops every datagram.
struct Blackhole {
    port: u16,
    datagrams: Arc<AtomicUsize>,
    peers: Arc<Mutex<HashSet<SocketAddr>>>,
    task: JoinHandle<()>,
}

impl Blackhole {
    async fn bind() -> TestResult<Self> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = socket.local_addr()?.port();
        let datagrams = Arc::new(AtomicUsize::new(0));
        let peers = Arc::new(Mutex::new(HashSet::new()));
        let counter = Arc::clone(&datagrams);
        let sources = Arc::clone(&peers);
        let task = tokio::spawn(async move {
            let mut buffer = [0_u8; 2048];
            // Windows reports ICMP port-unreachable for earlier sends as a
            // receive error; the blackhole ignores it and keeps listening.
            loop {
                if let Ok((_, peer)) = socket.recv_from(&mut buffer).await {
                    if let Ok(mut sources) = sources.lock() {
                        sources.insert(peer);
                    }
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        Ok(Self {
            port,
            datagrams,
            peers,
            task,
        })
    }

    fn datagrams(&self) -> usize {
        self.datagrams.load(Ordering::SeqCst)
    }

    /// Returns how many distinct client sockets sent datagrams.
    fn peers(&self) -> usize {
        self.peers.lock().map_or(0, |peers| peers.len())
    }
}

impl Drop for Blackhole {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A one-shot body that yields `chunks` and counts every poll.
struct ChunkedBody {
    polls: Arc<AtomicUsize>,
    chunks: Vec<Bytes>,
}

impl ChunkedBody {
    fn new(polls: Arc<AtomicUsize>, chunks: &[&'static str]) -> Self {
        Self {
            polls,
            chunks: chunks
                .iter()
                .rev()
                .map(|chunk| Bytes::from(*chunk))
                .collect(),
        }
    }
}

impl Body for ChunkedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(self.chunks.pop().map(|chunk| Ok(Frame::data(chunk))))
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}
