//! Encrypted Client Hello from an HTTPS DNS record on HTTP/3 connections,
//! through the client facade, against a loopback BoringSSL QUIC origin that
//! decrypts ECH.
//!
//! The origin closes each connection after its response, so every request
//! opens a new one. The first request may start before the record's lookup
//! finishes; later ones find it cached.

#![cfg(feature = "https-records")]

#[allow(dead_code)]
#[path = "support/ech.rs"]
mod ech_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{net::Ipv4Addr, num::NonZeroUsize, sync::Arc, time::Duration};

use btls::{hpke::HpkeKey, ssl::SslEchKeys};
use bytes::Bytes;
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, RequestErrorKind, ResponseInfo,
    dns::HttpsRecordResolver,
    profile::{ClientProfile, Http3ClientSettings, chromium},
};
use phantom_quic_btls::{QuicServerConfig, ServerHandshakeData};
use phantom_testkit::{
    dns::DnsServer,
    tls::{ClientHelloSummary, EchTestKey, TEST_ECH_KEYS, ech_config, ech_config_list},
};
use tokio::{sync::oneshot, task::JoinHandle, time::timeout};

use ech_support::{
    ORIGIN_NAME, PUBLIC_NAME, STAND_IN_NAME, TEST_TIMEOUT, https_rdata_with_alpn, origin_identity,
    record_server,
};
use tls_support::{TestIdentity, TestResult};

const H3_ALPN: &[u8] = b"\x02h3";
/// The QUIC `CRYPTO_ERROR` for the TLS `ech_required` alert (121).
const ECH_REQUIRED: u64 = 0x179;
/// Time for a spawned lookup to finish and a closed connection to be seen.
const SETTLE: Duration = Duration::from_millis(200);

/// What the origin saw on one QUIC connection.
#[derive(Debug)]
struct Observed {
    outer_server_name: Option<String>,
    ech_accepted: bool,
    server_name: Option<String>,
    closed_with: Option<u64>,
}

/// A loopback HTTP/3 origin that records each connection's handshake and
/// answers one request on each completed connection, then closes it.
struct QuicOrigin {
    port: u16,
    stop: oneshot::Sender<()>,
    task: JoinHandle<TestResult<Vec<Observed>>>,
}

impl QuicOrigin {
    fn spawn(identity: &TestIdentity, config_id: u8, key: &EchTestKey) -> TestResult<Self> {
        let builder = identity.acceptor_builder(H3_ALPN)?;
        let mut keys = SslEchKeys::builder()?;
        keys.add_key(
            true,
            &ech_config(config_id, key, PUBLIC_NAME),
            HpkeKey::dhkem_p256_sha256(&key.private_key)?,
        )?;
        builder.set_ech_keys(&keys.build())?;
        let crypto = QuicServerConfig::new(builder.build().into_context());
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(crypto)),
            (Ipv4Addr::LOCALHOST, 0).into(),
        )?;
        let port = endpoint.local_addr()?.port();
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut observed = Vec::new();
            let mut serving = Vec::new();
            loop {
                let incoming = tokio::select! {
                    incoming = endpoint.accept() => incoming.ok_or("endpoint closed")?,
                    _ = &mut stopped => break,
                };
                let (seen, connection) = observe(incoming).await?;
                observed.push(seen);
                if let Some(connection) = connection {
                    serving.push(tokio::spawn(serve_one(connection)));
                }
            }
            for task in serving {
                task.abort();
            }
            Ok(observed)
        });
        Ok(Self { port, stop, task })
    }

    fn url(&self, path: &str) -> String {
        format!("https://{ORIGIN_NAME}:{}{path}", self.port)
    }

    async fn finish(self) -> TestResult<Vec<Observed>> {
        let _ = self.stop.send(());
        self.task.await?
    }
}

async fn observe(incoming: quinn::Incoming) -> TestResult<(Observed, Option<quinn::Connection>)> {
    let mut connecting = incoming.accept()?;
    let data = timeout(TEST_TIMEOUT, connecting.handshake_data())
        .await??
        .downcast::<ServerHandshakeData>()
        .map_err(|_| "unexpected server handshake data")?;
    let outer_server_name = ClientHelloSummary::from_handshake_bytes(data.client_hello())?
        .server_name()
        .map(|name| String::from_utf8_lossy(name).into_owned());
    let (closed_with, connection) = match timeout(TEST_TIMEOUT, connecting).await? {
        Ok(connection) => (None, Some(connection)),
        Err(quinn::ConnectionError::ConnectionClosed(close)) => {
            (Some(u64::from(close.error_code)), None)
        }
        Err(error) => return Err(error.into()),
    };
    Ok((
        Observed {
            outer_server_name,
            ech_accepted: data.ech_accepted(),
            server_name: data.server_name().map(str::to_owned),
            closed_with,
        },
        connection,
    ))
}

async fn serve_one(connection: quinn::Connection) -> TestResult<()> {
    let mut h3 =
        h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection.clone()))
            .await?;
    let resolver = h3.accept().await?.ok_or("client closed before a request")?;
    let (_, mut stream) = resolver.resolve_request().await?;
    stream
        .send_response(http::Response::builder().status(200).body(())?)
        .await?;
    stream.send_data(Bytes::from_static(b"ok")).await?;
    stream.finish().await?;
    // Closing lets the next request find no pooled connection.
    tokio::time::sleep(Duration::from_millis(50)).await;
    connection.close(0_u32.into(), b"done");
    Ok(())
}

/// A DNS server whose record lists `h3` and `h2` and publishes
/// configuration 1 under the first key.
async fn published_record() -> TestResult<DnsServer> {
    let config = ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME);
    record_server(vec![https_rdata_with_alpn(
        &[b"h3", b"h2"],
        &ech_config_list(&[config]),
    )])
    .await
}

/// Chrome 154's HTTP/3 recipe, with `ech_from_https_records` as given.
fn profile(ech_from_https_records: bool) -> ClientProfile {
    let mut tls = chromium::v154_http3_tls();
    tls.ech_from_https_records = ech_from_https_records;
    ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_http3(Http3ClientSettings::new(
            tls,
            chromium::v154_quic(),
            chromium::v154_http3(),
            chromium::v154_http3_request(),
        ))
}

/// A client whose HTTPS record lookups go to `dns` for the stand-in name,
/// and which reaches `localhost` on the IPv4 loopback the origin listens on.
fn client(identity: &TestIdentity, dns: &DnsServer, profile: ClientProfile) -> TestResult<Client> {
    let upstream = HttpsRecordResolver::with_nameservers([dns.address()])?;
    let records = HttpsRecordResolver::from_fn(move |_, port| {
        let upstream = upstream.clone();
        async move { upstream.lookup(STAND_IN_NAME, port).await }
    });
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .alt_svc(NonZeroUsize::MIN.saturating_add(7))
        .https_record_discovery(records)
        .resolve(ORIGIN_NAME, [Ipv4Addr::LOCALHOST.into()])
        .build()?)
}

fn assert_accepted(connection: &Observed) {
    assert_eq!(connection.outer_server_name.as_deref(), Some(PUBLIC_NAME));
    assert!(connection.ech_accepted, "{connection:?}");
    assert_eq!(connection.server_name.as_deref(), Some(ORIGIN_NAME));
}

async fn bounded(test: impl Future<Output = TestResult<()>>) -> TestResult<()> {
    timeout(TEST_TIMEOUT, test)
        .await
        .map_err(|_| "ECH test exceeded its deadline")?
}

async fn get(client: &Client, protocol: Option<HttpProtocol>, url: &str) -> TestResult<()> {
    let response = match protocol {
        Some(protocol) => client.get(protocol, url)?.send().await?,
        None => client.get_negotiated(url)?.send().await?,
    };
    let info = response
        .extensions()
        .get::<ResponseInfo>()
        .ok_or("response omitted protocol metadata")?;
    assert_eq!(info.protocol(), HttpProtocol::Http3);
    response.into_body().collect().await?;
    Ok(())
}

#[tokio::test]
async fn exact_http3_offers_the_records_ech() -> TestResult<()> {
    bounded(async {
        let identity = origin_identity()?;
        let dns = published_record().await?;
        let origin = QuicOrigin::spawn(&identity, 1, &TEST_ECH_KEYS[0])?;
        let client = client(&identity, &dns, profile(true))?;

        for path in ["/first", "/second"] {
            get(&client, Some(HttpProtocol::Http3), &origin.url(path)).await?;
            tokio::time::sleep(SETTLE).await;
        }

        let observed = origin.finish().await?;
        assert_eq!(observed.len(), 2, "{observed:?}");
        assert_accepted(&observed[1]);
        Ok(())
    })
    .await
}

/// Once an exact request has cached the record, a negotiated request takes
/// the HTTP/3 alternative the record advertises and offers its `ech`.
#[tokio::test]
async fn https_record_alternative_offers_the_records_ech() -> TestResult<()> {
    bounded(async {
        let identity = origin_identity()?;
        let dns = published_record().await?;
        let origin = QuicOrigin::spawn(&identity, 1, &TEST_ECH_KEYS[0])?;
        let client = client(&identity, &dns, profile(true))?;

        get(&client, Some(HttpProtocol::Http3), &origin.url("/first")).await?;
        tokio::time::sleep(SETTLE).await;
        get(&client, None, &origin.url("/second")).await?;

        let observed = origin.finish().await?;
        assert_eq!(observed.len(), 2, "{observed:?}");
        assert_accepted(&observed[1]);
        assert_eq!(dns.queries().len(), 1);
        Ok(())
    })
    .await
}

/// The origin holds configuration 2 under another key. A request whose
/// connection offers the published configuration fails, and the client
/// opens no other QUIC connection for it, as Chrome 154 opened none.
#[tokio::test]
async fn exact_http3_rejection_fails_without_a_quic_retry() -> TestResult<()> {
    bounded(async {
        let identity = origin_identity()?;
        let dns = published_record().await?;
        let origin = QuicOrigin::spawn(&identity, 2, &TEST_ECH_KEYS[1])?;
        let client = client(&identity, &dns, profile(true))?;

        // The first connection may start before the lookup ends and send
        // GREASE; the second finds the record cached.
        let first = get(&client, Some(HttpProtocol::Http3), &origin.url("/first")).await;
        tokio::time::sleep(SETTLE).await;
        let second = client
            .get(HttpProtocol::Http3, &origin.url("/second"))?
            .send()
            .await
            .err()
            .ok_or("a rejected ECH offer connected")?;
        assert_eq!(second.kind(), RequestErrorKind::Tls);
        tokio::time::sleep(SETTLE).await;

        let observed = origin.finish().await?;
        let rejected = observed
            .iter()
            .filter(|seen| seen.closed_with == Some(ECH_REQUIRED))
            .collect::<Vec<_>>();
        // Every connection with ECH was rejected once and not repeated.
        let expected = if first.is_ok() { 1 } else { 2 };
        assert_eq!(rejected.len(), expected, "{observed:?}");
        assert_eq!(observed.len(), 2, "{observed:?}");
        for seen in rejected {
            assert_eq!(seen.outer_server_name.as_deref(), Some(PUBLIC_NAME));
            assert!(!seen.ech_accepted);
        }
        Ok(())
    })
    .await
}

/// With the field unset, the client makes no HTTPS query for an exact
/// HTTP/3 request, and the connection sends GREASE with the true name.
#[tokio::test]
async fn exact_http3_without_the_field_keeps_grease() -> TestResult<()> {
    bounded(async {
        let identity = origin_identity()?;
        let dns = published_record().await?;
        let origin = QuicOrigin::spawn(&identity, 1, &TEST_ECH_KEYS[0])?;
        let client = client(&identity, &dns, profile(false))?;

        get(&client, Some(HttpProtocol::Http3), &origin.url("/first")).await?;
        tokio::time::sleep(SETTLE).await;

        let observed = origin.finish().await?;
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].outer_server_name.as_deref(), Some(ORIGIN_NAME));
        assert!(!observed[0].ech_accepted);
        assert!(dns.queries().is_empty());
        Ok(())
    })
    .await
}
