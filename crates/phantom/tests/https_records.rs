//! HTTP/3 discovery from HTTPS DNS records, against a loopback resolver.

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
    time::{Duration, Instant},
};

use http::StatusCode;
use http_body_util::BodyExt;
use phantom::{
    AltSvcBrokenBackoff, AltSvcPolicy, AltSvcRace, Client, ClientBuilder, HttpProtocol, HttpProxy,
    RequestErrorKind, ResponseInfo, Route, Socks5Proxy,
    dns::HttpsRecordResolver,
    profile::{ClientProfile, chromium},
};
use phantom_testkit::dns::{DnsAnswer, DnsQuery, DnsReply, DnsServer};
use tokio::time::timeout;

use h3_support::client_settings;
use http3_upgrade_support::{
    AlternativeBehavior, Http3UpgradeFixture, ObservedRequest, PlannedResponse, UpgradeScript,
};
use tls_support::{TestIdentity, TestResult, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(20);
const ORIGIN_NAME: &str = "localhost";
/// The name the loopback DNS server is asked about for [`ORIGIN_NAME`].
const STAND_IN_NAME: &str = "origin.test";

/// RDATA of a ServiceMode record at the owner name listing `h3` and `h2`.
const H3_RECORD: &[u8] = b"\x00\x01\x00\x00\x01\x00\x06\x02h3\x02h2";
/// RDATA of a ServiceMode record at the owner name listing only `h2`.
const H2_RECORD: &[u8] = b"\x00\x01\x00\x00\x01\x00\x03\x02h2";

fn records(rdata: &'static [u8]) -> impl Fn(&DnsQuery) -> DnsReply + Send + Sync + 'static {
    move |_| {
        DnsReply::new(DnsAnswer::Records {
            ttl: 300,
            rdata: vec![rdata.to_vec()],
        })
    }
}

async fn spawn_fixture(
    identity: &TestIdentity,
    origin: usize,
    origin_http3: usize,
) -> TestResult<Http3UpgradeFixture> {
    let ok = || PlannedResponse::new(StatusCode::OK);
    Http3UpgradeFixture::spawn(
        identity,
        ORIGIN_NAME,
        UpgradeScript::new(
            (0..origin).map(|_| ok().body("origin")),
            AlternativeBehavior::responses([]),
        )
        .origin_http3((0..origin_http3).map(|_| ok().body("http3"))),
    )
    .await
}

#[tokio::test]
async fn sequential_client_uses_http3_once_the_https_record_is_known() -> TestResult<()> {
    bounded(async {
        let identity = identity()?;
        let fixture = spawn_fixture(&identity, 1, 1).await?;
        let dns = DnsServer::spawn(records(H3_RECORD)).await?;
        let client = client_builder(&identity)
            .https_record_discovery(resolver(&dns)?)
            .build()?;

        // The first request does not wait for the lookup it starts.
        let first = client
            .get_negotiated(&fixture.origin_url("/first"))?
            .send()
            .await?;
        assert_eq!(protocol(&first)?, HttpProtocol::Http2);
        drain(first).await?;
        wait_for_lookup().await;

        let second = client
            .get_negotiated(&fixture.origin_url("/second"))?
            .send()
            .await?;
        assert_eq!(protocol(&second)?, HttpProtocol::Http3);
        assert_eq!(second.into_body().collect().await?.to_bytes(), "http3");

        drop(client);
        let observed = fixture.finish().await?;
        let queries = dns.queries();
        assert_eq!(queries.len(), 1);
        let port = fixture_port(&observed.origin_http3_requests[0])?;
        assert_eq!(queries[0].name(), format!("_{port}._https.{STAND_IN_NAME}"));
        assert_eq!(queries[0].record_type(), 65);

        let request = &observed.origin_http3_requests[0];
        assert_eq!(
            request.authority.as_deref(),
            Some(format!("localhost:{port}").as_str())
        );
        assert_eq!(request.server_name.as_deref(), Some("localhost"));
        assert!(
            request.fields.iter().all(|field| field.name != "alt-used"),
            "an HTTPS-record request named an alternative service"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn misdirected_http3_marks_the_https_record_location_broken() -> TestResult<()> {
    bounded(async {
        let identity = identity()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            ORIGIN_NAME,
            UpgradeScript::new(
                [
                    PlannedResponse::new(StatusCode::OK),
                    PlannedResponse::new(StatusCode::OK),
                ],
                AlternativeBehavior::responses([]),
            )
            .origin_http3([PlannedResponse::new(StatusCode::MISDIRECTED_REQUEST)]),
        )
        .await?;
        let dns = DnsServer::spawn(records(H3_RECORD)).await?;
        let client = client_builder(&identity)
            .https_record_discovery(resolver(&dns)?)
            .build()?;

        let mut protocols = Vec::new();
        for path in ["/learn", "/misdirected", "/after"] {
            let response = client
                .get_negotiated(&fixture.origin_url(path))?
                .send()
                .await?;
            protocols.push((protocol(&response)?, response.status()));
            drain(response).await?;
            wait_for_lookup().await;
        }
        // An HTTPS record cannot be evicted, so its location is marked broken
        // and the next request goes to the origin.
        assert_eq!(
            protocols,
            [
                (HttpProtocol::Http2, StatusCode::OK),
                (HttpProtocol::Http3, StatusCode::MISDIRECTED_REQUEST),
                (HttpProtocol::Http2, StatusCode::OK),
            ]
        );
        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_requests.len(), 2);
        assert_eq!(observed.origin_http3_requests.len(), 1);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn delayed_https_record_does_not_delay_the_request() -> TestResult<()> {
    bounded(async {
        // Under hickory's five-second query timeout, and above the time the
        // origin request needs.
        const DNS_DELAY: Duration = Duration::from_millis(4_500);
        let identity = identity()?;
        for (policy, later_http3) in [
            (AltSvcPolicy::sequential(), true),
            // An origin delay that would dominate if the lookup applied it.
            // A later racing request would reuse the pooled HTTP/2
            // connection, so only the sequential pass checks the cache.
            (
                AltSvcPolicy::race(AltSvcRace::new(
                    Duration::from_secs(10),
                    AltSvcBrokenBackoff::CHROMIUM_153,
                )),
                false,
            ),
        ] {
            let fixture = spawn_fixture(&identity, 1, usize::from(later_http3)).await?;
            let dns =
                DnsServer::spawn(|query| records(H3_RECORD)(query).delayed(DNS_DELAY)).await?;
            let client = client_builder(&identity)
                .alt_svc_policy(policy)
                .https_record_discovery(resolver(&dns)?)
                .build()?;

            let started = Instant::now();
            let response = client
                .get_negotiated(&fixture.origin_url("/first"))?
                .send()
                .await?;
            let elapsed = started.elapsed();
            assert_eq!(protocol(&response)?, HttpProtocol::Http2, "{policy:?}");
            drain(response).await?;
            assert!(
                elapsed < DNS_DELAY,
                "{policy:?}: the request took {elapsed:?}, waiting for the HTTPS record"
            );
            assert_eq!(query_ids(&dns), [query_ids(&dns)[0]], "{policy:?}");

            if later_http3 {
                // The late record still reaches the cache for later requests.
                tokio::time::sleep_until((started + DNS_DELAY).into()).await;
                wait_for_lookup().await;
                let later = client
                    .get_negotiated(&fixture.origin_url("/later"))?
                    .send()
                    .await?;
                assert_eq!(protocol(&later)?, HttpProtocol::Http3, "{policy:?}");
                drain(later).await?;
            }
            drop(client);
            fixture.finish().await?;
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn failed_lookup_leaves_the_request_on_the_origin() -> TestResult<()> {
    bounded(async {
        let identity = identity()?;
        let fixture = spawn_fixture(&identity, 2, 0).await?;
        let dns = DnsServer::spawn(|_| DnsReply::new(DnsAnswer::ServerFailure)).await?;
        let client = client_builder(&identity)
            .https_record_discovery(resolver(&dns)?)
            .build()?;
        let mut queries = Vec::new();
        for path in ["/first", "/second"] {
            let response = client
                .get_negotiated(&fixture.origin_url(path))?
                .send()
                .await?;
            assert_eq!(protocol(&response)?, HttpProtocol::Http2);
            drain(response).await?;
            wait_for_lookup().await;
            queries.push(dns.queries().len());
        }
        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_requests.len(), 2);
        // The failure is cached, so the second request sends no query.
        assert!(queries[0] > 0);
        assert_eq!(queries[0], queries[1]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn disabled_discovery_leaves_requests_unchanged() -> TestResult<()> {
    bounded(async {
        let identity = identity()?;
        let dns = DnsServer::spawn(records(H2_RECORD)).await?;
        let mut observed = Vec::new();
        for discovery in [false, true] {
            let fixture = spawn_fixture(&identity, 2, 0).await?;
            let mut builder = client_builder(&identity);
            if discovery {
                builder = builder.https_record_discovery(resolver(&dns)?);
            }
            let client = builder.build()?;
            for path in ["/first", "/second"] {
                let response = client
                    .get_negotiated(&fixture.origin_url(path))?
                    .send()
                    .await?;
                assert_eq!(protocol(&response)?, HttpProtocol::Http2);
                drain(response).await?;
                wait_for_lookup().await;
            }
            drop(client);
            let requests = fixture.finish().await?.origin_requests;
            observed.push(
                requests
                    .into_iter()
                    .map(|request| (request.method, request.path_and_query, request.fields))
                    .collect::<Vec<_>>(),
            );
            let expected_queries = usize::from(discovery);
            assert_eq!(
                dns.queries().len(),
                expected_queries,
                "discovery {discovery}"
            );
        }
        // The same requests, field for field, whether or not a lookup ran.
        assert_eq!(observed[0], observed[1]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn routes_without_direct_dns_send_no_https_query() -> TestResult<()> {
    bounded(async {
        let identity = identity()?;
        let dns = DnsServer::spawn(records(H3_RECORD)).await?;
        // Like Chromium, where proxied connections perform DNS on the proxy,
        // a proxy route never queries HTTPS records. Nothing listens on the
        // discard port, so each request fails at the proxy.
        for route in [
            Route::http_proxy(HttpProxy::new("http://127.0.0.1:9")?),
            Route::http_proxy(HttpProxy::new("https://127.0.0.1:9")?),
            Route::socks5(Socks5Proxy::new("socks5h://127.0.0.1:9")?),
        ] {
            let client = client_builder(&identity)
                .route(route)
                .https_record_discovery(resolver(&dns)?)
                .build()?;
            let error = client
                .get_negotiated("https://localhost:8443/")?
                .send()
                .await
                .err()
                .ok_or("a proxied negotiated request succeeded")?;
            assert_eq!(error.kind(), RequestErrorKind::Proxy);
        }
        assert!(dns.queries().is_empty());
        Ok(())
    })
    .await
}

#[test]
fn discovery_requires_an_alt_svc_store() -> TestResult<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let dns = runtime.block_on(DnsServer::spawn(records(H3_RECORD)))?;
    let identity = identity()?;
    let error = profile_builder(&identity)
        .https_record_discovery(resolver(&dns)?)
        .build()
        .err()
        .ok_or("discovery without an Alt-Svc store was accepted")?;
    assert_eq!(error.kind(), phantom::BuildErrorKind::InvalidPolicy);
    Ok(())
}

fn identity() -> TestResult<TestIdentity> {
    TestIdentity::generate_for_ip_and_dns(IpAddr::V4(Ipv4Addr::LOCALHOST), ORIGIN_NAME)
}

/// Queries the loopback DNS server for `origin.test` in place of `localhost`.
///
/// A resolver answers `localhost` names itself (RFC 6761), and only
/// `localhost` reaches the loopback fixture through the system resolver, so
/// the query is renamed on its way to a real DNS exchange.
fn resolver(dns: &DnsServer) -> TestResult<HttpsRecordResolver> {
    let upstream = HttpsRecordResolver::with_nameservers([dns.address()])?;
    Ok(HttpsRecordResolver::from_fn(move |host, port| {
        let upstream = upstream.clone();
        async move {
            assert_eq!(host, ORIGIN_NAME);
            upstream.lookup(STAND_IN_NAME, port).await
        }
    }))
}

fn profile_builder(identity: &TestIdentity) -> ClientBuilder {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(chromium::v154_http2())
        .with_http3(client_settings());
    Client::builder(profile).add_root_certificate_der(identity.root_der.clone())
}

fn client_builder(identity: &TestIdentity) -> ClientBuilder {
    profile_builder(identity).alt_svc(NonZeroUsize::MIN.saturating_add(7))
}

/// Lets a spawned lookup finish and store its result.
///
/// The loopback resolver answers within milliseconds unless a test delays it.
async fn wait_for_lookup() {
    tokio::time::sleep(Duration::from_millis(200)).await;
}

/// Returns the distinct DNS message IDs received, in arrival order.
///
/// The resolver resends an unanswered UDP query with the same ID, so one
/// lookup can arrive more than once.
fn query_ids(dns: &DnsServer) -> Vec<[u8; 2]> {
    let mut ids = Vec::new();
    for query in dns.queries() {
        let id = [query.wire_bytes()[0], query.wire_bytes()[1]];
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    ids
}

fn fixture_port(request: &ObservedRequest) -> TestResult<u16> {
    let authority = request
        .authority
        .as_deref()
        .ok_or("request had no authority")?;
    let (_, port) = authority.rsplit_once(':').ok_or("authority had no port")?;
    Ok(port.parse()?)
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
        .map_err(|_| "HTTPS-record discovery test exceeded its deadline")?
}
