//! Real Encrypted Client Hello on the direct negotiated connect, against a
//! loopback server that decrypts ECH.

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use btls::{
    hpke::HpkeKey,
    ssl::{AlpnError, NameType, Ssl, SslAcceptor, SslEchKeys, select_next_proto},
};
use phantom_profile::{
    TlsSettings,
    chromium::{v154_http2, v154_tls},
    edge,
};
use phantom_testkit::tls::{
    CaptureLimits, ClientHelloSummary, EchOuterExtension, EchTestKey, TEST_ECH_KEYS,
    capture_client_hello, ech_config, ech_config_list, is_grease,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_btls::SslStream;

use crate::{
    direct::https_record_extra_time,
    dns::EchConfigList,
    http1_or_2::{EchFailure, Http1Or2Connection, Http1Or2TlsConnector, Http1Or2TlsError},
    tls::{
        TlsErrorKind,
        test_support::{TEST_TIMEOUT, TestIdentity, TestResult},
    },
};

const INNER_NAME: &str = "inner.phantom.test";
const PUBLIC_NAME: &str = "public.phantom.test";
const HTTP1_ALPN_WIRE: &[u8] = b"\x08http/1.1";

/// What the server saw on one connection.
#[derive(Debug)]
struct Observed {
    outer_server_name: Option<String>,
    ech: Option<EchOuterExtension>,
    extension_types: Vec<u16>,
    handshake_completed: bool,
    ech_accepted: bool,
    inner_server_name: Option<String>,
}

/// One server key: the configuration the server holds and marks for retry.
struct ServerKey {
    config: Vec<u8>,
    key: EchTestKey,
}

fn server_key(config_id: u8, key: EchTestKey) -> ServerKey {
    ServerKey {
        config: ech_config(config_id, &key, PUBLIC_NAME),
        key,
    }
}

fn published(config_id: u8, key: &EchTestKey) -> EchConfigList {
    EchConfigList::new(ech_config_list(&[ech_config(config_id, key, PUBLIC_NAME)]))
}

fn acceptor(identity: &TestIdentity, key: Option<&ServerKey>) -> TestResult<SslAcceptor> {
    let mut builder = identity.acceptor_builder()?;
    builder.set_alpn_select_callback(|_, offered| {
        select_next_proto(HTTP1_ALPN_WIRE, offered).ok_or(AlpnError::NOACK)
    });
    if let Some(server) = key {
        let mut keys = SslEchKeys::builder()?;
        keys.add_key(
            true,
            &server.config,
            HpkeKey::dhkem_p256_sha256(&server.key.private_key)?,
        )?;
        builder.set_ech_keys(&keys.build())?;
    }
    Ok(builder.build())
}

/// Serves one connection per acceptor, in order, and reports what each saw.
async fn serve(
    acceptors: Vec<SslAcceptor>,
) -> TestResult<(SocketAddr, JoinHandle<TestResult<Vec<Observed>>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let mut observed = Vec::new();
        for acceptor in acceptors {
            let (tcp, _) = tokio::time::timeout(TEST_TIMEOUT, listener.accept()).await??;
            observed.push(observe(tcp, &acceptor).await?);
        }
        Ok(observed)
    });
    Ok((address, task))
}

async fn observe(mut tcp: TcpStream, acceptor: &SslAcceptor) -> TestResult<Observed> {
    let capture = capture_client_hello(
        &mut tcp,
        tokio::time::Instant::now() + TEST_TIMEOUT,
        CaptureLimits::new(64 * 1024, 64 * 1024, 8),
    )
    .await?;
    let summary = capture.summary()?;
    let prefix = capture
        .records()
        .iter()
        .flat_map(|record| record.wire_bytes().iter().copied())
        .collect::<Vec<_>>();
    let mut tls = SslStream::new(
        Ssl::new(acceptor.context())?,
        Replayed {
            prefix,
            offset: 0,
            inner: tcp,
        },
    )?;
    let handshake_completed = tokio::time::timeout(TEST_TIMEOUT, Pin::new(&mut tls).accept())
        .await?
        .is_ok();
    Ok(Observed {
        outer_server_name: summary
            .server_name()
            .map(|name| String::from_utf8_lossy(name).into_owned()),
        ech: summary
            .encrypted_client_hello()
            .and_then(EchOuterExtension::parse),
        extension_types: summary.extension_types().to_vec(),
        handshake_completed,
        ech_accepted: handshake_completed && tls.ssl().ech_accepted(),
        inner_server_name: handshake_completed
            .then(|| tls.ssl().servername(NameType::HOST_NAME).map(str::to_owned))
            .flatten(),
    })
}

/// Replays the captured ClientHello records before reading the socket.
struct Replayed {
    prefix: Vec<u8>,
    offset: usize,
    inner: TcpStream,
}

impl AsyncRead for Replayed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() {
            let count = (self.prefix.len() - self.offset).min(buffer.remaining());
            let start = self.offset;
            buffer.put_slice(&self.prefix[start..start + count]);
            self.offset += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for Replayed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

fn connector(identity: &TestIdentity) -> TestResult<Http1Or2TlsConnector> {
    connector_with(&v154_tls(), identity)
}

fn connector_with(
    settings: &TlsSettings,
    identity: &TestIdentity,
) -> TestResult<Http1Or2TlsConnector> {
    assert!(settings.ech_from_https_records);
    Ok(Http1Or2TlsConnector::new_with_additional_roots(
        settings,
        &v154_http2(),
        [identity.root_der()],
    )?)
}

async fn connect(
    identity: &TestIdentity,
    address: SocketAddr,
    ech: impl Future<Output = Option<EchConfigList>>,
) -> TestResult<Result<Http1Or2Connection, Http1Or2TlsError>> {
    let connector = connector(identity)?;
    Ok(tokio::time::timeout(
        TEST_TIMEOUT,
        connector.connect_direct_with_ech("127.0.0.1", address.port(), INNER_NAME, ech),
    )
    .await?)
}

fn identity() -> TestResult<TestIdentity> {
    TestIdentity::generate_for_names(&[INNER_NAME, PUBLIC_NAME])
}

#[tokio::test]
async fn accepted_ech_sends_the_public_name_outside_and_the_origin_inside() -> TestResult<()> {
    let identity = identity()?;
    let key = server_key(1, TEST_ECH_KEYS[0]);
    let (address, server) = serve(vec![acceptor(&identity, Some(&key))?]).await?;

    let connection = connect(&identity, address, async {
        Some(published(1, &TEST_ECH_KEYS[0]))
    })
    .await??;

    assert!(matches!(connection, Http1Or2Connection::Http1(_)));
    let observed = server.await??;
    let [only] = &observed[..] else {
        return Err(format!("expected one connection, saw {observed:?}").into());
    };
    assert_eq!(only.outer_server_name.as_deref(), Some(PUBLIC_NAME));
    let ech = only.ech.as_ref().ok_or("ClientHelloOuter omitted ECH")?;
    assert_eq!((ech.kdf_id, ech.config_id, ech.enc_length), (1, 1, 32));
    assert!(only.ech_accepted);
    assert_eq!(only.inner_server_name.as_deref(), Some(INNER_NAME));
    Ok(())
}

#[tokio::test]
async fn rejection_retries_once_with_the_servers_retry_configurations() -> TestResult<()> {
    let identity = identity()?;
    let key = server_key(2, TEST_ECH_KEYS[1]);
    let (address, server) = serve(vec![
        acceptor(&identity, Some(&key))?,
        acceptor(&identity, Some(&key))?,
    ])
    .await?;

    connect(&identity, address, async {
        Some(published(1, &TEST_ECH_KEYS[0]))
    })
    .await??;

    let observed = server.await??;
    let [rejected, retried] = &observed[..] else {
        return Err(format!("expected two connections, saw {observed:?}").into());
    };
    assert_eq!(rejected.outer_server_name.as_deref(), Some(PUBLIC_NAME));
    assert_eq!(rejected.ech.as_ref().map(|ech| ech.config_id), Some(1));
    assert!(!rejected.ech_accepted);
    assert_eq!(retried.outer_server_name.as_deref(), Some(PUBLIC_NAME));
    assert_eq!(retried.ech.as_ref().map(|ech| ech.config_id), Some(2));
    assert!(retried.ech_accepted);
    assert_eq!(retried.inner_server_name.as_deref(), Some(INNER_NAME));
    Ok(())
}

#[tokio::test]
async fn rejection_without_retry_configurations_retries_with_grease() -> TestResult<()> {
    let identity = identity()?;
    let (address, server) =
        serve(vec![acceptor(&identity, None)?, acceptor(&identity, None)?]).await?;

    connect(&identity, address, async {
        Some(published(1, &TEST_ECH_KEYS[0]))
    })
    .await??;

    let observed = server.await??;
    let [rejected, retried] = &observed[..] else {
        return Err(format!("expected two connections, saw {observed:?}").into());
    };
    assert_eq!(rejected.outer_server_name.as_deref(), Some(PUBLIC_NAME));
    assert_eq!(retried.outer_server_name.as_deref(), Some(INNER_NAME));
    // Chrome keeps ECH GREASE on the retry (`net/base/ech_mode.h`).
    assert!(retried.ech.is_some());
    assert!(retried.handshake_completed);
    assert!(!retried.ech_accepted);
    Ok(())
}

#[tokio::test]
async fn a_second_rejection_fails_with_a_typed_error() -> TestResult<()> {
    let identity = identity()?;
    let key = server_key(2, TEST_ECH_KEYS[1]);
    // The retry offers configuration 2, which the second server cannot
    // decrypt either.
    let other = server_key(3, TEST_ECH_KEYS[0]);
    let (address, server) = serve(vec![
        acceptor(&identity, Some(&key))?,
        acceptor(&identity, Some(&other))?,
    ])
    .await?;

    let result = connect(&identity, address, async {
        Some(published(1, &TEST_ECH_KEYS[0]))
    })
    .await?;

    let error = result.err().ok_or("a second rejection was accepted")?;
    assert_eq!(error.ech_failure(), Some(EchFailure::Rejected));
    assert_eq!(server.await??.len(), 2);
    Ok(())
}

#[tokio::test]
async fn a_malformed_list_fails_before_any_tls_byte() -> TestResult<()> {
    let identity = identity()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await?;
        let mut byte = [0_u8; 1];
        let read = tokio::io::AsyncReadExt::read(&mut tcp, &mut byte).await;
        Ok::<_, io::Error>(read.unwrap_or(0))
    });

    let result = connect(&identity, address, async {
        Some(EchConfigList::new(vec![0x00, 0x05, 0xfe, 0x0d, 0x00]))
    })
    .await?;

    let error = result.err().ok_or("a malformed list was accepted")?;
    assert_eq!(error.ech_failure(), Some(EchFailure::InvalidConfigList));
    assert_eq!(tokio::time::timeout(TEST_TIMEOUT, server).await???, 0);
    Ok(())
}

#[tokio::test]
async fn a_lookup_still_running_is_abandoned_after_the_bounded_wait() -> TestResult<()> {
    let identity = identity()?;
    let (address, server) = serve(vec![acceptor(&identity, None)?]).await?;

    let started = Instant::now();
    connect(&identity, address, std::future::pending()).await??;
    let elapsed = started.elapsed();

    // The wait is at most 50 ms; the rest is loopback TCP and TLS.
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    let observed = server.await??;
    assert_eq!(observed[0].outer_server_name.as_deref(), Some(INNER_NAME));
    assert!(observed[0].ech.is_some());
    Ok(())
}

#[test]
fn the_wait_is_a_fifth_of_address_resolution_within_5_to_50_ms() {
    for (resolution, wait) in [(0, 5), (10, 5), (25, 5), (100, 20), (250, 50), (5_000, 50)] {
        assert_eq!(
            https_record_extra_time(Duration::from_millis(resolution)),
            Duration::from_millis(wait),
            "{resolution} ms"
        );
    }
}

/// Chrome 154's ClientHelloOuter from `ech-accept.txt`, captured against
/// the same configuration, public name, and origin name.
const CHROME_ACCEPT: &str = include_str!(
    "../../../../../fixtures/tls/chrome/154.0.8037.58/windows-11-26200/ech-accept.txt"
);
/// Edge 153's captures of the same two scenarios.
const EDGE_ACCEPT: &str =
    include_str!("../../../../../fixtures/tls/edge/153.0.4234.48/windows-11-26200/ech-accept.txt");
const EDGE_REJECT: &str =
    include_str!("../../../../../fixtures/tls/edge/153.0.4234.48/windows-11-26200/ech-reject.txt");
/// Brave 154's ClientHelloOuter from `ech-accept.txt`, captured the same way.
const BRAVE_ACCEPT: &str =
    include_str!("../../../../../fixtures/tls/brave/154.1.96.59/windows-11-26200/ech-accept.txt");

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

/// Extension types with every GREASE value folded into one, sorted: Chrome
/// permutes the order on each connection.
fn extension_set(types: &[u16]) -> Vec<u16> {
    let mut set = types
        .iter()
        .map(|&kind| if is_grease(kind) { 0x0a0a } else { kind })
        .collect::<Vec<_>>();
    set.sort_unstable();
    set
}

/// Connects with `settings` to origins that hold the key of `fixture`'s
/// scenario, once per origin, and returns what each saw.
async fn replay(
    fixture: &str,
    settings: &TlsSettings,
    server_key: EchTestKey,
    connections: usize,
) -> TestResult<Vec<Observed>> {
    let origin = fixture_value(fixture, "hostname")?;
    let public = fixture_value(fixture, "public_name")?;
    let list = decode_hex(fixture_value(fixture, "dns_ech_config_list_hex")?)?;
    let key = ServerKey {
        config: decode_hex(fixture_value(fixture, "server_ech_config_hex")?)?,
        key: server_key,
    };
    let identity = TestIdentity::generate_for_names(&[origin, public])?;
    let acceptors = (0..connections)
        .map(|_| acceptor(&identity, Some(&key)))
        .collect::<TestResult<Vec<_>>>()?;
    let (address, server) = serve(acceptors).await?;
    let connector = connector_with(settings, &identity)?;
    tokio::time::timeout(
        TEST_TIMEOUT,
        connector.connect_direct_with_ech("127.0.0.1", address.port(), origin, async {
            Some(EchConfigList::new(list))
        }),
    )
    .await??;
    server.await?
}

/// Checks the first connection of an `accept` capture against Phantom's.
async fn assert_accept_replays(fixture: &str, settings: &TlsSettings) -> TestResult<()> {
    let record = decode_hex(fixture_value(fixture, "connection_0_record_0_hex")?)?;
    let browser = ClientHelloSummary::from_handshake_bytes(record.get(5..).ok_or("short record")?)?;
    let browser_ech = browser
        .encrypted_client_hello()
        .and_then(EchOuterExtension::parse)
        .ok_or("the captured ClientHelloOuter lacks ECH")?;
    let observed = replay(fixture, settings, TEST_ECH_KEYS[0], 1).await?;
    let phantom = &observed[0];

    assert!(phantom.ech_accepted);
    assert_eq!(
        phantom.outer_server_name.as_deref().map(str::as_bytes),
        browser.server_name()
    );
    assert_eq!(phantom.ech.as_ref(), Some(&browser_ech));
    assert_eq!(
        extension_set(&phantom.extension_types),
        extension_set(browser.extension_types())
    );
    Ok(())
}

#[tokio::test]
async fn outer_client_hello_has_the_shape_chrome_154_sent() -> TestResult<()> {
    assert_accept_replays(CHROME_ACCEPT, &v154_tls()).await
}

#[tokio::test]
async fn outer_client_hello_has_the_shape_edge_153_sent() -> TestResult<()> {
    assert_accept_replays(EDGE_ACCEPT, &edge::v153_tls()).await
}

/// Brave sends Chrome's outer shape without the trust-anchor IDs extension,
/// which its recipe also omits.
#[tokio::test]
async fn outer_client_hello_has_the_shape_brave_154_sent() -> TestResult<()> {
    assert_accept_replays(BRAVE_ACCEPT, &phantom_profile::brave::v154_tls()).await
}

/// The fixture's `ech_outer` line for one observed connection.
fn ech_outer_line(observed: &Observed) -> String {
    observed.ech.as_ref().map_or_else(
        || "absent".to_owned(),
        |ech| {
            format!(
                "kdf={:#06x},aead={:#06x},config_id={},enc_length={},payload_length={}",
                ech.kdf_id, ech.aead_id, ech.config_id, ech.enc_length, ech.payload_length
            )
        },
    )
}

#[tokio::test]
async fn edge_153_rejection_is_retried_as_edge_retried_it() -> TestResult<()> {
    // Edge's first two connections, the navigation and a preconnect, were
    // rejected and the next two were their retries. Each pair is identical,
    // so the first of each stands for both.
    let observed = replay(EDGE_REJECT, &edge::v153_tls(), TEST_ECH_KEYS[1], 2).await?;
    let [rejected, retried] = &observed[..] else {
        return Err(format!("expected two connections, saw {observed:?}").into());
    };
    for (phantom, edge) in [(rejected, 0), (retried, 2)] {
        let field = |name: &str| fixture_value(EDGE_REJECT, &format!("connection_{edge}_{name}"));
        assert_eq!(
            phantom.outer_server_name.as_deref(),
            Some(field("outer_server_name")?)
        );
        assert_eq!(ech_outer_line(phantom), field("ech_outer")?);
        assert_eq!(phantom.ech_accepted.to_string(), field("ech_accepted")?);
        assert_eq!(
            phantom.inner_server_name.as_deref(),
            Some(field("inner_server_name")?)
        );
    }
    Ok(())
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
/// resolution is used.
#[tokio::test]
async fn a_resolved_address_waits_for_a_lookup_within_the_bound() -> TestResult<()> {
    let identity = identity()?;
    let key = server_key(1, TEST_ECH_KEYS[0]);
    let (address, server) = serve(vec![acceptor(&identity, Some(&key))?]).await?;
    let connector =
        connector(&identity)?.with_host_resolver(slow_resolver(Duration::from_millis(250)));

    // 250 ms of resolution allows 50 ms more; the record arrives 5 ms after
    // the addresses. Started now, as the client's lookup starts with the
    // request.
    let lookup = tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(255)).await;
        published(1, &TEST_ECH_KEYS[0])
    });
    let ech = async { lookup.await.ok() };
    tokio::time::timeout(
        TEST_TIMEOUT,
        connector.connect_direct_with_ech("origin.test", address.port(), INNER_NAME, ech),
    )
    .await??;

    let observed = server.await??;
    assert_eq!(observed[0].outer_server_name.as_deref(), Some(PUBLIC_NAME));
    assert!(observed[0].ech_accepted);
    Ok(())
}

/// Addresses from the cache give the lookup no extra time, as Chromium's
/// cache hit finalizes its request at once.
#[tokio::test]
async fn a_cached_address_does_not_wait_for_the_lookup() -> TestResult<()> {
    let identity = identity()?;
    let key = server_key(1, TEST_ECH_KEYS[0]);
    let (address, server) = serve(vec![
        acceptor(&identity, Some(&key))?,
        acceptor(&identity, Some(&key))?,
    ])
    .await?;
    let connector =
        connector(&identity)?.with_host_resolver(slow_resolver(Duration::from_millis(250)));

    tokio::time::timeout(
        TEST_TIMEOUT,
        connector
            .connect_direct_with_ech("origin.test", address.port(), INNER_NAME, async { None }),
    )
    .await??;
    // Started now, as the client's lookup starts with the request. Any wait
    // is at most 50 ms, so a record a second away is never waited for, even
    // when a loaded host delays the ClientHello by tens of milliseconds.
    let lookup = tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        published(1, &TEST_ECH_KEYS[0])
    });
    let ech = async { lookup.await.ok() };
    tokio::time::timeout(
        TEST_TIMEOUT,
        connector.connect_direct_with_ech("origin.test", address.port(), INNER_NAME, ech),
    )
    .await??;

    let observed = server.await??;
    assert_eq!(observed[1].outer_server_name.as_deref(), Some(INNER_NAME));
    assert!(!observed[1].ech_accepted);
    Ok(())
}

/// An overridden name counts as resolved at once, so the record gets only
/// the 5 ms minimum: a record that is ready is used, and one 40 ms later is
/// not waited for.
#[tokio::test]
async fn an_overridden_name_waits_only_the_minimum_for_the_lookup() -> TestResult<()> {
    let identity = identity()?;
    let key = server_key(1, TEST_ECH_KEYS[0]);
    let (address, server) = serve(vec![
        acceptor(&identity, Some(&key))?,
        acceptor(&identity, Some(&key))?,
    ])
    .await?;
    let resolver = crate::host_resolver::HostResolver::new().with_override(
        "origin.test",
        [std::net::IpAddr::from(std::net::Ipv4Addr::LOCALHOST)],
    );
    let connector = connector(&identity)?.with_host_resolver(resolver);

    tokio::time::timeout(
        TEST_TIMEOUT,
        connector.connect_direct_with_ech("origin.test", address.port(), INNER_NAME, async {
            Some(published(1, &TEST_ECH_KEYS[0]))
        }),
    )
    .await??;
    // Started now, as the client's lookup starts with the request.
    let lookup = tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(40)).await;
        published(1, &TEST_ECH_KEYS[0])
    });
    let ech = async { lookup.await.ok() };
    tokio::time::timeout(
        TEST_TIMEOUT,
        connector.connect_direct_with_ech("origin.test", address.port(), INNER_NAME, ech),
    )
    .await??;

    let observed = server.await??;
    assert_eq!(observed[0].outer_server_name.as_deref(), Some(PUBLIC_NAME));
    assert!(observed[0].ech_accepted);
    assert_eq!(observed[1].outer_server_name.as_deref(), Some(INNER_NAME));
    assert!(!observed[1].ech_accepted);
    Ok(())
}

/// A record that arrives well after the bounded wait is not waited for.
#[tokio::test]
async fn a_lookup_past_the_bound_leaves_grease() -> TestResult<()> {
    let identity = identity()?;
    let key = server_key(1, TEST_ECH_KEYS[0]);
    let (address, server) = serve(vec![acceptor(&identity, Some(&key))?]).await?;
    let connector =
        connector(&identity)?.with_host_resolver(slow_resolver(Duration::from_millis(250)));

    // The wait ends 50 ms after the addresses; the record comes 150 ms later.
    let lookup = tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(450)).await;
        published(1, &TEST_ECH_KEYS[0])
    });
    let ech = async { lookup.await.ok() };
    tokio::time::timeout(
        TEST_TIMEOUT,
        connector.connect_direct_with_ech("origin.test", address.port(), INNER_NAME, ech),
    )
    .await??;

    let observed = server.await??;
    assert_eq!(observed[0].outer_server_name.as_deref(), Some(INNER_NAME));
    assert!(observed[0].ech.is_some());
    assert!(!observed[0].ech_accepted);
    Ok(())
}

/// A rejection is retried only when the server authenticates as the public
/// name; otherwise certificate verification fails the one connection, as
/// in Chrome, where the error is `ERR_ECH_FALLBACK_CERTIFICATE_INVALID`.
#[tokio::test]
async fn a_rejection_without_a_public_name_certificate_is_not_retried() -> TestResult<()> {
    let identity = TestIdentity::generate_for_names(&[INNER_NAME])?;
    let key = server_key(2, TEST_ECH_KEYS[1]);
    let (address, server) = serve(vec![acceptor(&identity, Some(&key))?]).await?;

    let result = connect(&identity, address, async {
        Some(published(1, &TEST_ECH_KEYS[0]))
    })
    .await?;

    let error = result
        .err()
        .ok_or("a rejection without a valid certificate was accepted")?;
    assert_eq!(error.ech_failure(), None);
    // A retry would have found no listener and failed to connect instead.
    assert!(
        matches!(&error, Http1Or2TlsError::Tls(tls) if tls.kind() == TlsErrorKind::Handshake),
        "{error:?}"
    );
    let observed = server.await??;
    assert_eq!(observed.len(), 1);
    assert!(!observed[0].handshake_completed);
    Ok(())
}
