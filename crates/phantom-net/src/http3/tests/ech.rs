//! Real Encrypted Client Hello on direct QUIC connections, against a loopback
//! BoringSSL QUIC server that decrypts ECH.

use std::{
    future::Future,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use btls::{
    hpke::HpkeKey,
    ssl::{AlpnError, SslEchKeys, select_next_proto},
};
use phantom_profile::{TlsSettings, brave, chromium, edge};
use phantom_quic_btls::{QuicServerConfig, ServerHandshakeData};
use phantom_testkit::tls::{
    ClientHelloSummary, EchOuterExtension, EchTestKey, TEST_ECH_KEYS, ech_config, ech_config_list,
    is_grease,
};
use tokio::time::timeout;

use super::super::{Http3Connection, Http3Connector, Http3ConnectorError, Http3ConnectorErrorKind};
use super::{TEST_TIMEOUT, TestResult};
use crate::{dns::EchConfigList, tls::EchFailure, tls::test_support::TestIdentity};

const INNER_NAME: &str = "inner.phantom.test";
const PUBLIC_NAME: &str = "public.phantom.test";
const H3_ALPN_WIRE: &[u8] = b"\x02h3";
/// The QUIC `CRYPTO_ERROR` for the TLS `ech_required` alert (121).
const ECH_REQUIRED: u64 = 0x179;
/// How long the server waits for a connection that must not come.
const QUIET_PERIOD: Duration = Duration::from_millis(300);

const CHROME_ACCEPT: &str = include_str!(
    "../../../../../fixtures/tls/chrome/154.0.8037.58/windows-11-26200/ech-quic-accept.txt"
);
const CHROME_REJECT: &str = include_str!(
    "../../../../../fixtures/tls/chrome/154.0.8037.58/windows-11-26200/ech-quic-reject.txt"
);
const EDGE_ACCEPT: &str = include_str!(
    "../../../../../fixtures/tls/edge/153.0.4234.48/windows-11-26200/ech-quic-accept.txt"
);
const BRAVE_ACCEPT: &str = include_str!(
    "../../../../../fixtures/tls/brave/154.1.96.59/windows-11-26200/ech-quic-accept.txt"
);

/// What the server saw on one QUIC connection.
#[derive(Debug)]
struct Observed {
    client_hello: Vec<u8>,
    ech_accepted: bool,
    server_name: Option<String>,
    /// The client's close code when the handshake failed.
    closed_with: Option<u64>,
    /// Held so the server does not close a completed connection first.
    _connection: Option<quinn::Connection>,
}

impl Observed {
    fn summary(&self) -> TestResult<ClientHelloSummary> {
        Ok(ClientHelloSummary::from_handshake_bytes(
            &self.client_hello,
        )?)
    }

    fn outer_server_name(&self) -> TestResult<Option<String>> {
        Ok(self
            .summary()?
            .server_name()
            .map(|name| String::from_utf8_lossy(name).into_owned()))
    }

    fn ech(&self) -> TestResult<Option<EchOuterExtension>> {
        Ok(self
            .summary()?
            .encrypted_client_hello()
            .and_then(EchOuterExtension::parse))
    }
}

/// A loopback QUIC server holding `key`'s ECH key under its config ID.
fn server(
    identity: &TestIdentity,
    key: Option<(u8, &EchTestKey, &str)>,
) -> TestResult<(SocketAddr, quinn::Endpoint)> {
    let mut builder = identity.acceptor_builder()?;
    builder.set_alpn_select_callback(|_, offered| {
        select_next_proto(H3_ALPN_WIRE, offered).ok_or(AlpnError::NOACK)
    });
    if let Some((config_id, key, public_name)) = key {
        let mut keys = SslEchKeys::builder()?;
        keys.add_key(
            true,
            &ech_config(config_id, key, public_name),
            HpkeKey::dhkem_p256_sha256(&key.private_key)?,
        )?;
        builder.set_ech_keys(&keys.build())?;
    }
    let crypto = QuicServerConfig::new(builder.build().into_context());
    let config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse()?)?;
    Ok((endpoint.local_addr()?, endpoint))
}

/// Accepts the next connection and reports what its handshake showed.
async fn observe(endpoint: &quinn::Endpoint) -> TestResult<Observed> {
    let incoming = timeout(TEST_TIMEOUT, endpoint.accept())
        .await?
        .ok_or("test endpoint closed")?;
    let mut connecting = incoming.accept()?;
    let data = timeout(TEST_TIMEOUT, connecting.handshake_data())
        .await??
        .downcast::<ServerHandshakeData>()
        .map_err(|_| "unexpected server handshake data")?;
    let (closed_with, connection) = match timeout(TEST_TIMEOUT, connecting).await? {
        Ok(connection) => (None, Some(connection)),
        Err(quinn::ConnectionError::ConnectionClosed(close)) => {
            (Some(u64::from(close.error_code)), None)
        }
        Err(error) => return Err(error.into()),
    };
    Ok(Observed {
        client_hello: data.client_hello().to_vec(),
        ech_accepted: data.ech_accepted(),
        server_name: data.server_name().map(str::to_owned),
        closed_with,
        _connection: connection,
    })
}

/// Fails if another connection arrives within [`QUIET_PERIOD`].
async fn assert_no_other_connection(endpoint: &quinn::Endpoint) -> TestResult<()> {
    match timeout(QUIET_PERIOD, endpoint.accept()).await {
        Err(_) => Ok(()),
        Ok(_) => Err("the client opened another QUIC connection".into()),
    }
}

fn connector_with(settings: &TlsSettings, identity: &TestIdentity) -> TestResult<Http3Connector> {
    Ok(Http3Connector::new_with_additional_roots(
        settings,
        &chromium::v154_quic(),
        &chromium::v154_http3(),
        &chromium::v154_http3_request(),
        [identity.root_der()],
    )?)
}

fn identity() -> TestResult<TestIdentity> {
    TestIdentity::generate_for_names(&[INNER_NAME, PUBLIC_NAME])
}

fn published(config_id: u8, key: &EchTestKey) -> EchConfigList {
    EchConfigList::new(ech_config_list(&[ech_config(config_id, key, PUBLIC_NAME)]))
}

async fn connect(
    connector: &Http3Connector,
    host: &str,
    address: SocketAddr,
    server_name: &str,
    ech: impl Future<Output = Option<EchConfigList>>,
) -> TestResult<Result<Http3Connection, Http3ConnectorError>> {
    Ok(timeout(
        TEST_TIMEOUT,
        connector.connect_direct_with_ech(host, address.port(), server_name, ech),
    )
    .await?)
}

#[tokio::test]
async fn accepted_ech_carries_the_origin_inside_the_quic_client_hello() -> TestResult<()> {
    let identity = identity()?;
    let (address, endpoint) = server(&identity, Some((1, &TEST_ECH_KEYS[0], PUBLIC_NAME)))?;
    let mut settings = chromium::v154_http3_tls();
    settings.ech_from_https_records = true;
    let connector = connector_with(&settings, &identity)?;
    assert!(connector.ech_from_https_records());

    let (connection, observed) = tokio::join!(
        connect(&connector, "127.0.0.1", address, INNER_NAME, async {
            Some(published(1, &TEST_ECH_KEYS[0]))
        }),
        observe(&endpoint),
    );
    let _connection = connection??;
    let observed = observed?;
    assert_eq!(observed.outer_server_name()?.as_deref(), Some(PUBLIC_NAME));
    let ech = observed.ech()?.ok_or("the outer ClientHello lacks ECH")?;
    assert_eq!((ech.kdf_id, ech.config_id, ech.enc_length), (1, 1, 32));
    assert!(observed.ech_accepted);
    assert_eq!(observed.server_name.as_deref(), Some(INNER_NAME));
    Ok(())
}

/// Chrome 154 closed a rejected QUIC connection with `ech_required` and
/// never opened another QUIC connection with the retry configurations; the
/// connector does the same and reports the rejection.
#[tokio::test]
async fn a_rejection_fails_without_another_quic_connection() -> TestResult<()> {
    let identity = identity()?;
    let (address, endpoint) = server(&identity, Some((2, &TEST_ECH_KEYS[1], PUBLIC_NAME)))?;
    let connector = connector_with(&chromium::v154_http3_tls(), &identity)?;

    let (result, observed) = tokio::join!(
        connect(&connector, "127.0.0.1", address, INNER_NAME, async {
            Some(published(1, &TEST_ECH_KEYS[0]))
        }),
        observe(&endpoint),
    );
    let error = result?.err().ok_or("a rejected ECH offer connected")?;
    assert_eq!(error.ech_failure(), Some(EchFailure::Rejected));
    assert_eq!(error.kind(), Http3ConnectorErrorKind::Handshake);
    let observed = observed?;
    assert_eq!(observed.closed_with, Some(ECH_REQUIRED));
    assert!(!observed.ech_accepted);
    assert_eq!(observed.server_name.as_deref(), Some(PUBLIC_NAME));
    assert_no_other_connection(&endpoint).await
}

#[tokio::test]
async fn a_malformed_list_fails_before_any_packet() -> TestResult<()> {
    let identity = identity()?;
    let (address, endpoint) = server(&identity, None)?;
    let connector = connector_with(&chromium::v154_http3_tls(), &identity)?;

    let error = connect(&connector, "127.0.0.1", address, INNER_NAME, async {
        Some(EchConfigList::new(vec![0x00, 0x03, 0xfe, 0x0d, 0x00]))
    })
    .await?
    .err()
    .ok_or("a malformed list connected")?;
    assert_eq!(error.ech_failure(), Some(EchFailure::InvalidConfigList));
    assert_no_other_connection(&endpoint).await
}

fn slow_resolver(delay: Duration) -> crate::host_resolver::HostResolver {
    let settings = phantom_profile::DnsCacheSettings {
        max_entries: std::num::NonZeroUsize::MIN,
        ttl: Duration::from_secs(60),
        negative_ttl: None,
    };
    let cache = crate::address_cache::AddressCache::with_lookup(settings, move |_| {
        // The lookup runs on a thread of its own without a timer driver.
        Box::pin(async move {
            std::thread::sleep(delay);
            Ok(vec![SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0))])
        })
    });
    crate::host_resolver::HostResolver::new().with_address_cache(cache)
}

/// A lookup that finishes within the bounded wait after a slow address
/// resolution is used; one far past it is not waited for.
#[tokio::test]
async fn the_connection_waits_for_a_lookup_only_within_the_bound() -> TestResult<()> {
    let identity = identity()?;
    let (address, endpoint) = server(&identity, Some((1, &TEST_ECH_KEYS[0], PUBLIC_NAME)))?;

    // 250 ms of resolution allows 50 ms more; the record arrives 5 ms after
    // the addresses. Started now, as the client's lookup starts with the
    // request.
    let connector = connector_with(&chromium::v154_http3_tls(), &identity)?
        .with_host_resolver(slow_resolver(Duration::from_millis(250)));
    let lookup = tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(255)).await;
        published(1, &TEST_ECH_KEYS[0])
    });
    let (connection, observed) = tokio::join!(
        connect(&connector, "origin.test", address, INNER_NAME, async {
            lookup.await.ok()
        }),
        observe(&endpoint),
    );
    let _connection = connection??;
    let observed = observed?;
    assert_eq!(observed.outer_server_name()?.as_deref(), Some(PUBLIC_NAME));
    assert!(observed.ech_accepted);

    // The wait ends 50 ms after the addresses; this record comes 150 ms
    // later, so the ClientHello carries ECH GREASE and the true name.
    let connector = connector_with(&chromium::v154_http3_tls(), &identity)?
        .with_host_resolver(slow_resolver(Duration::from_millis(250)));
    let lookup = tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(450)).await;
        published(1, &TEST_ECH_KEYS[0])
    });
    let started = Instant::now();
    let (connection, observed) = tokio::join!(
        connect(&connector, "origin.test", address, INNER_NAME, async {
            lookup.await.ok()
        }),
        observe(&endpoint),
    );
    let _connection = connection??;
    let observed = observed?;
    assert!(started.elapsed() < Duration::from_millis(450));
    assert_eq!(observed.outer_server_name()?.as_deref(), Some(INNER_NAME));
    assert!(observed.ech()?.is_some());
    assert!(!observed.ech_accepted);
    Ok(())
}

fn fixture_value<'a>(fixture: &'a str, field: &str) -> TestResult<&'a str> {
    fixture
        .lines()
        .find_map(|line| line.strip_prefix(field)?.strip_prefix('='))
        .ok_or_else(|| format!("fixture lacks {field}").into())
}

fn decode_hex(text: &str) -> TestResult<Vec<u8>> {
    (0..text.len())
        .step_by(2)
        .map(|index| {
            Ok(u8::from_str_radix(
                text.get(index..index + 2).ok_or("odd hex")?,
                16,
            )?)
        })
        .collect()
}

/// Extension types with every GREASE value folded into one, sorted: the
/// browsers permute the order on each connection.
fn extension_set(types: &[u16]) -> Vec<u16> {
    let mut set = types
        .iter()
        .map(|&kind| if is_grease(kind) { 0x0a0a } else { kind })
        .collect::<Vec<_>>();
    set.sort_unstable();
    set
}

/// The fixture's `ech_outer` line for one outer extension.
fn ech_outer_line(ech: Option<&EchOuterExtension>) -> String {
    ech.map_or_else(
        || "absent".to_owned(),
        |ech| {
            format!(
                "kdf={:#06x},aead={:#06x},config_id={},enc_length={},payload_length={}",
                ech.kdf_id, ech.aead_id, ech.config_id, ech.enc_length, ech.payload_length
            )
        },
    )
}

/// Connects once with `settings` to a server holding the key of `fixture`'s
/// scenario and returns the result and what the server saw.
async fn replay(
    fixture: &str,
    settings: &TlsSettings,
    key: &EchTestKey,
) -> TestResult<(
    Result<Http3Connection, Http3ConnectorError>,
    Observed,
    quinn::Endpoint,
)> {
    let origin = fixture_value(fixture, "hostname")?;
    let public = fixture_value(fixture, "public_name")?;
    let list = decode_hex(fixture_value(fixture, "dns_ech_config_list_hex")?)?;
    let server_config = decode_hex(fixture_value(fixture, "server_ech_config_hex")?)?;
    let config_id = *server_config.get(4).ok_or("short server ECHConfig")?;
    let identity = TestIdentity::generate_for_names(&[origin, public])?;
    let (address, endpoint) = server(&identity, Some((config_id, key, public)))?;
    let connector = connector_with(settings, &identity)?;
    let (result, observed) = tokio::join!(
        connect(&connector, "127.0.0.1", address, origin, async {
            Some(EchConfigList::new(list))
        }),
        observe(&endpoint),
    );
    Ok((result?, observed?, endpoint))
}

/// Checks Phantom's QUIC outer ClientHello against the first QUIC connection
/// of an `accept` capture: server name, ECH extension fields, and extension
/// set.
async fn assert_accept_replays(fixture: &str, settings: &TlsSettings) -> TestResult<()> {
    let browser = ClientHelloSummary::from_handshake_bytes(&decode_hex(fixture_value(
        fixture,
        "quic_connection_0_client_hello_hex",
    )?)?)?;
    let (connection, phantom, _endpoint) = replay(fixture, settings, &TEST_ECH_KEYS[0]).await?;
    let _connection = connection?;

    assert!(phantom.ech_accepted);
    assert_eq!(
        phantom.server_name.as_deref(),
        Some(fixture_value(
            fixture,
            "quic_connection_0_inner_server_name"
        )?)
    );
    assert_eq!(
        phantom.outer_server_name()?.as_deref().map(str::as_bytes),
        browser.server_name()
    );
    assert_eq!(
        ech_outer_line(phantom.ech()?.as_ref()),
        fixture_value(fixture, "quic_connection_0_ech_outer")?
    );
    assert_eq!(
        extension_set(phantom.summary()?.extension_types()),
        extension_set(browser.extension_types())
    );
    Ok(())
}

#[tokio::test]
async fn quic_outer_client_hello_has_the_shape_chrome_154_sent() -> TestResult<()> {
    assert_accept_replays(CHROME_ACCEPT, &chromium::v154_http3_tls()).await
}

#[tokio::test]
async fn quic_outer_client_hello_has_the_shape_edge_153_sent() -> TestResult<()> {
    assert_accept_replays(EDGE_ACCEPT, &edge::v154_http3_tls()).await
}

#[tokio::test]
async fn quic_outer_client_hello_has_the_shape_brave_154_sent() -> TestResult<()> {
    assert_accept_replays(BRAVE_ACCEPT, &brave::v154_http3_tls()).await
}

/// Every QUIC connection in Chrome's `reject` capture offered the record's
/// configuration and closed with `ech_required`; none used the retry
/// configuration, which only Chrome's TCP connection did.
#[tokio::test]
async fn chrome_154_quic_rejection_is_not_retried_as_chrome_did_not_retry_it() -> TestResult<()> {
    let count = fixture_value(CHROME_REJECT, "quic_connection_count")?.parse::<usize>()?;
    for index in 0..count {
        let field =
            |name: &str| fixture_value(CHROME_REJECT, &format!("quic_connection_{index}_{name}"));
        assert!(field("ech_outer")?.contains("config_id=1,"));
        assert_eq!(field("handshake")?, "failed: client closed with 0x179");
    }
    let (result, phantom, endpoint) = replay(
        CHROME_REJECT,
        &chromium::v154_http3_tls(),
        &TEST_ECH_KEYS[1],
    )
    .await?;
    let error = result.err().ok_or("a rejected ECH offer connected")?;
    assert_eq!(error.ech_failure(), Some(EchFailure::Rejected));
    let field = |name: &str| fixture_value(CHROME_REJECT, &format!("quic_connection_0_{name}"));
    assert_eq!(
        phantom.outer_server_name()?.as_deref(),
        Some(field("outer_server_name")?)
    );
    assert_eq!(ech_outer_line(phantom.ech()?.as_ref()), field("ech_outer")?);
    assert_eq!(phantom.ech_accepted.to_string(), field("ech_accepted")?);
    assert_eq!(
        phantom.server_name.as_deref(),
        Some(field("inner_server_name")?)
    );
    assert_eq!(phantom.closed_with, Some(ECH_REQUIRED));
    assert_no_other_connection(&endpoint).await
}
