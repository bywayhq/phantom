//! Caller-owned export and import of learned Alt-Svc alternatives.

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
    net::Ipv4Addr,
    num::NonZeroUsize,
    time::{Duration, SystemTime},
};

use http::StatusCode;
use http_body_util::BodyExt;
use phantom::{
    AltSvcSnapshot, AltSvcSnapshotEntry, AltSvcSnapshotErrorKind, Client, HttpProtocol,
    ResponseInfo,
    profile::{ClientProfile, chromium},
};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

use h3_support::client_settings;
use http3_upgrade_support::{
    AltSvcAdvertisement, AlternativeBehavior, Http3UpgradeFixture, PlannedResponse, UpgradeScript,
};
use tls_support::{TestIdentity, TestResult, read_head, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const ORIGIN_NAME: &str = "127.0.0.1";
const HOUR: Duration = Duration::from_secs(60 * 60);

#[tokio::test]
async fn exported_snapshot_preserves_remaining_lifetime() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let fixture =
            learning_fixture(&identity, 0, AltSvcAdvertisement::default().max_age(3600)).await?;
        let client = client(&identity, 8)?;
        let before = SystemTime::now();
        assert_eq!(
            negotiated(&client, &fixture, "/learn").await?,
            HttpProtocol::Http2
        );

        let snapshot = client
            .export_alt_svc()
            .ok_or("Alt-Svc export was disabled")?;
        let after = SystemTime::now();
        let [entry] = snapshot.entries() else {
            return Err("expected exactly one exported alternative".into());
        };
        assert_eq!(
            entry.origin(),
            format!("https://{ORIGIN_NAME}:{}", fixture.origin_address().port())
        );
        assert_eq!(entry.alternative_host(), ORIGIN_NAME);
        assert_eq!(
            entry.alternative_port(),
            fixture.alternative_address().port()
        );
        // Rounded down to a whole second and never beyond the advertised `ma`.
        assert!(entry.expires_at() <= after + HOUR);
        assert!(entry.expires_at() + Duration::from_secs(2) > before + HOUR);

        drop(client);
        fixture.finish().await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn import_drops_expired_entries() -> TestResult<()> {
    let client = client(&TestIdentity::generate()?, 8)?;
    let now = SystemTime::now();
    client.import_alt_svc(&AltSvcSnapshot::new(vec![
        entry("https://expired.example", now - Duration::from_secs(1)),
        entry("https://fresh.example", now + HOUR),
        entry("https://now.example", now),
    ]))?;

    assert_eq!(origins(&client)?, ["https://fresh.example"]);
    Ok(())
}

#[tokio::test]
async fn repeated_round_trips_never_extend_lifetime() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut snapshot = AltSvcSnapshot::new(vec![entry(
        "https://origin.example:8443",
        SystemTime::now() + HOUR,
    )]);
    let mut previous = snapshot.entries()[0].expires_at();
    for _ in 0..5 {
        let client = client(&identity, 8)?;
        client.import_alt_svc(&snapshot)?;
        snapshot = client
            .export_alt_svc()
            .ok_or("Alt-Svc export was disabled")?;
        let [entry] = snapshot.entries() else {
            return Err("round trip lost the alternative".into());
        };
        assert!(entry.expires_at() <= previous);
        previous = entry.expires_at();
    }
    // Far-future expiries are clamped to the largest delta-seconds lifetime.
    let client = client(&identity, 8)?;
    client.import_alt_svc(&AltSvcSnapshot::new(vec![entry(
        "https://far.example",
        SystemTime::now()
            .checked_add(Duration::from_secs(1 << 32))
            .ok_or("far-future expiry overflowed")?,
    )]))?;
    let clamped = client
        .export_alt_svc()
        .ok_or("Alt-Svc export was disabled")?;
    assert!(clamped.entries()[0].expires_at() <= SystemTime::now() + Duration::from_secs(1 << 31));
    Ok(())
}

#[tokio::test]
async fn import_keeps_most_recent_entries_within_capacity() -> TestResult<()> {
    let client = client(&TestIdentity::generate()?, 2)?;
    let expires_at = SystemTime::now() + HOUR;
    client.import_alt_svc(&AltSvcSnapshot::new(vec![
        entry("https://first.example", expires_at),
        entry("https://second.example", expires_at),
        entry("https://third.example", expires_at),
    ]))?;
    assert_eq!(
        origins(&client)?,
        ["https://second.example", "https://third.example"]
    );

    // Held alternatives win over imported ones and keep their LRU position.
    client.import_alt_svc(&AltSvcSnapshot::new(vec![entry(
        "https://fourth.example",
        expires_at,
    )]))?;
    assert_eq!(
        origins(&client)?,
        ["https://second.example", "https://third.example"]
    );
    Ok(())
}

#[tokio::test]
async fn import_rejects_noncanonical_origin_with_typed_error() -> TestResult<()> {
    let client = client(&TestIdentity::generate()?, 8)?;
    let expires_at = SystemTime::now() + HOUR;
    for origin in [
        "https://Example.com",
        "https://example.com:443",
        "https://example.com/",
        "http://example.com",
        "https://user@example.com",
        "https://[0:0::1]",
        "example.com",
    ] {
        let error = client
            .import_alt_svc(&AltSvcSnapshot::new(vec![
                entry("https://valid.example", expires_at),
                entry(origin, expires_at),
            ]))
            .err()
            .ok_or_else(|| format!("{origin} was accepted"))?;
        assert_eq!(error.kind(), AltSvcSnapshotErrorKind::NoncanonicalOrigin);
        assert_eq!(error.entry_index(), Some(1));
    }
    for (host, port) in [("ALT.example", 443), ("[::1]", 443), ("alt.example", 0)] {
        let error = client
            .import_alt_svc(&AltSvcSnapshot::new(vec![AltSvcSnapshotEntry::new(
                "https://valid.example",
                host,
                port,
                expires_at,
            )]))
            .err()
            .ok_or_else(|| format!("{host}:{port} was accepted"))?;
        assert_eq!(error.kind(), AltSvcSnapshotErrorKind::InvalidAlternative);
    }
    // A rejected snapshot changes nothing.
    assert!(origins(&client)?.is_empty());
    Ok(())
}

#[test]
fn snapshot_debug_omits_hosts() {
    let snapshot = AltSvcSnapshot::new(vec![AltSvcSnapshotEntry::new(
        "https://secret-origin.example",
        "secret-alternative.example",
        8443,
        SystemTime::UNIX_EPOCH,
    )]);
    let debug = format!("{snapshot:?}");
    assert!(!debug.contains("secret"), "{debug}");
    assert!(debug.contains("8443"), "{debug}");
}

#[tokio::test]
async fn imported_alternative_upgrades_first_negotiated_request() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let fixture = learning_fixture(&identity, 1, AltSvcAdvertisement::default()).await?;
        let learner = client(&identity, 8)?;
        assert_eq!(
            negotiated(&learner, &fixture, "/learn").await?,
            HttpProtocol::Http2
        );
        let snapshot = learner
            .export_alt_svc()
            .ok_or("Alt-Svc export was disabled")?;
        drop(learner);

        let restored = client(&identity, 8)?;
        restored.import_alt_svc(&snapshot)?;
        assert_eq!(
            negotiated(&restored, &fixture, "/restored").await?,
            HttpProtocol::Http3
        );

        drop(restored);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_request_count, 1);
        assert_eq!(observed.alternative_requests.len(), 1);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn independent_clients_share_no_alternatives_without_import() -> TestResult<()> {
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
        let learner = client(&identity, 8)?;
        let independent = client(&identity, 8)?;
        assert_eq!(
            negotiated(&learner, &fixture, "/learn").await?,
            HttpProtocol::Http2
        );
        assert_eq!(
            learner.export_alt_svc().map(|snapshot| snapshot.len()),
            Some(1)
        );
        assert_eq!(
            independent.export_alt_svc().map(|snapshot| snapshot.len()),
            Some(0)
        );
        assert_eq!(
            negotiated(&independent, &fixture, "/independent").await?,
            HttpProtocol::Http2
        );

        drop((learner, independent));
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_request_count, 2);
        assert!(observed.alternative_requests.is_empty());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn import_requires_alt_svc_enabled() -> TestResult<()> {
    let client = upgrade_builder(&TestIdentity::generate()?).build()?;
    assert!(client.export_alt_svc().is_none());
    let error = client
        .import_alt_svc(&AltSvcSnapshot::default())
        .err()
        .ok_or("import succeeded without Alt-Svc")?;
    assert_eq!(error.kind(), AltSvcSnapshotErrorKind::Disabled);
    Ok(())
}

#[tokio::test]
async fn negotiated_plaintext_response_teaches_no_alternative() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            read_head(&mut stream).await?;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nAlt-Svc: h3=\":443\"; ma=3600\r\nContent-Length: 0\r\n\r\n",
                )
                .await?;
            stream.flush().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let client = client(&identity, 8)?;
        let response = client
            .get_negotiated(&format!("http://{address}/advertises"))?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let protocol = response
            .extensions()
            .get::<ResponseInfo>()
            .map(ResponseInfo::protocol);
        assert_eq!(protocol, Some(HttpProtocol::Http1));
        response.into_body().collect().await?;
        server.await??;

        assert_eq!(
            client.export_alt_svc().map(|snapshot| snapshot.len()),
            Some(0)
        );
        Ok(())
    })
    .await
}

async fn learning_fixture(
    identity: &TestIdentity,
    alternative_responses: usize,
    advertisement: AltSvcAdvertisement,
) -> TestResult<Http3UpgradeFixture> {
    Http3UpgradeFixture::spawn(
        identity,
        ORIGIN_NAME,
        UpgradeScript::new(
            [PlannedResponse::new(StatusCode::OK).advertise_alternative()],
            AlternativeBehavior::responses(
                (0..alternative_responses).map(|_| PlannedResponse::new(StatusCode::OK)),
            ),
        )
        .advertisement(advertisement.host(ORIGIN_NAME)),
    )
    .await
}

fn entry(origin: &str, expires_at: SystemTime) -> AltSvcSnapshotEntry {
    AltSvcSnapshotEntry::new(origin, "alt.example", 8443, expires_at)
}

fn origins(client: &Client) -> TestResult<Vec<String>> {
    Ok(client
        .export_alt_svc()
        .ok_or("Alt-Svc export was disabled")?
        .entries()
        .iter()
        .map(|entry| entry.origin().to_owned())
        .collect())
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
    let protocol = response
        .extensions()
        .get::<ResponseInfo>()
        .map(ResponseInfo::protocol)
        .ok_or("response omitted protocol metadata")?;
    response.into_body().collect().await?;
    Ok(protocol)
}

fn client(identity: &TestIdentity, maximum_origins: usize) -> TestResult<Client> {
    let maximum_origins = NonZeroUsize::new(maximum_origins).ok_or("zero Alt-Svc capacity")?;
    Ok(upgrade_builder(identity).alt_svc(maximum_origins).build()?)
}

fn upgrade_builder(identity: &TestIdentity) -> phantom::ClientBuilder {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(chromium::v154_http2())
        .with_http3(client_settings());
    Client::builder(profile).add_root_certificate_der(identity.root_der.clone())
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "Alt-Svc persistence integration test exceeded its deadline")?
}
