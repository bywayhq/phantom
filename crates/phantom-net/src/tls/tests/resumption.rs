//! TLS 1.3 resumption over TCP, compared with the browser resumption captures.

use std::{
    io,
    sync::{Arc, Mutex},
    time::Duration,
};

use phantom_profile::{TlsSettings, TrustAnchorIds, brave, chromium, edge, firefox, opera};
use phantom_testkit::tls::{
    CaptureLimits, ClientHelloCapture, ClientHelloSummary, capture_client_hello,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::Instant,
};

use super::client_hello_fixture;
use crate::tls::{
    TlsConnector,
    test_support::{
        TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, TestServerAlpn,
        accept_tls_with_early_data, connect_local, loopback_listener, nss_ech_grease,
    },
};

const SESSION_TICKET: u16 = 0x0023;
const KEY_SHARE: u16 = 0x0033;
const PRE_SHARED_KEY: u16 = 0x0029;
const EARLY_DATA: u16 = 0x002a;
const PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

/// The length of the ticket in every resumed ClientHello of Firefox's TCP
/// resumption captures, which the capture server issued.
const FIREFOX_CAPTURE_TICKET_LENGTH: usize = 64;
/// Firefox's ECH GREASE `maximum_name_length`, `security.tls.ech.grease_size`.
const FIREFOX_ECH_MAXIMUM_NAME_LENGTH: usize = 100;

/// The loopback server that issues the ticket.
#[derive(Clone, Copy)]
enum Tickets {
    /// A BoringSSL server whose tickets do not permit early data.
    WithoutEarlyData,
    /// A BoringSSL server whose tickets permit early data.
    PermittingEarlyData,
    /// A rustls server whose tickets are this many bytes long and do not
    /// permit early data. A BoringSSL ticket carries the encrypted session
    /// and is longer than any capture server's.
    FixedLength(usize),
}

/// Whether [`normalized_client_hello`] keeps the length of the ECH GREASE
/// payload, which NSS derives from the ClientHello and so from the ticket.
#[derive(Clone, Copy)]
enum EchPayloadLength {
    Kept,
    Cleared,
}

macro_rules! fixture {
    ($browser:literal, $version:literal, $name:literal) => {
        fixture!($browser, $version, "windows-11-26200", $name)
    };
    ($browser:literal, $version:literal, $host:literal, $name:literal) => {
        include_str!(concat!(
            "../../../../../fixtures/tls/",
            $browser,
            "/",
            $version,
            "/",
            $host,
            "/resumption-",
            $name,
            ".txt"
        ))
    };
}

const CHROME_SEQUENTIAL: &str = fixture!("chrome", "154.0.8037.58", "sequential");
const EDGE_SEQUENTIAL: &str = fixture!("edge", "154.0.4258.37", "sequential");
const BRAVE_SEQUENTIAL: &str = fixture!("brave", "154.1.96.59", "sequential");
const OPERA_SEQUENTIAL: &str = fixture!("opera", "136.0.6008.52", "sequential");
const FIREFOX_SEQUENTIAL: &str = fixture!("firefox", "157.0", "sequential");
const FIREFOX_NO_EARLY_DATA: &str = fixture!("firefox", "157.0", "no-early-data");
const CHROME_MACOS_SEQUENTIAL: &str =
    fixture!("chrome", "154.0.8037.95", "macos-15.5-arm64", "sequential");
const EDGE_MACOS_SEQUENTIAL: &str =
    fixture!("edge", "154.0.4258.48", "macos-15.5-arm64", "sequential");
const OPERA_MACOS_SEQUENTIAL: &str =
    fixture!("opera", "136.0.6008.52", "macos-15.5-arm64", "sequential");
const FIREFOX_MACOS_SEQUENTIAL: &str =
    fixture!("firefox", "157.0", "macos-15.5-arm64", "sequential");

#[tokio::test]
async fn chromium_resumed_client_hellos_match_the_tcp_resumption_captures() -> TestResult<()> {
    for (settings, fixture) in [
        (chromium::v154_tls(), CHROME_SEQUENTIAL),
        (edge::v154_tls(), EDGE_SEQUENTIAL),
        (brave::v154_tls(), BRAVE_SEQUENTIAL),
        (opera::v136_tls(), OPERA_SEQUENTIAL),
        // One macOS 15.5 arm64 run per browser.
        (chromium::v154_tls(), CHROME_MACOS_SEQUENTIAL),
        (edge::v154_tls(), EDGE_MACOS_SEQUENTIAL),
        (opera::v136_tls(), OPERA_MACOS_SEQUENTIAL),
    ] {
        let (fresh, resumed) =
            fresh_and_resumed_client_hellos(&settings, Tickets::WithoutEarlyData).await?;
        let captured = resumed_client_hellos(fixture)?;
        assert!(!captured.is_empty());
        for expected in &captured {
            assert_same_resumed_shape(resumed.handshake_bytes(), expected, &settings)?;
        }
        // Chromium permutes extensions per connection, so compare sets: the
        // resumed ClientHello adds `pre_shared_key` and nothing else.
        let mut fresh_types = without_grease(fresh.summary()?.extension_types());
        let mut resumed_types = without_grease(resumed.summary()?.extension_types());
        assert_eq!(resumed_types.pop(), Some(PRE_SHARED_KEY));
        fresh_types.sort_unstable();
        resumed_types.sort_unstable();
        assert_eq!(resumed_types, fresh_types);
    }
    Ok(())
}

/// The Chromium-family browsers never offered early data over TCP, even with
/// tickets that permit it, and neither do their recipes.
#[tokio::test]
async fn chromium_recipes_never_offer_early_data_over_tcp() -> TestResult<()> {
    for settings in [
        chromium::v154_tls(),
        edge::v154_tls(),
        brave::v154_tls(),
        opera::v136_tls(),
    ] {
        assert!(!settings.tcp_early_data);
        let (_, resumed) =
            fresh_and_resumed_client_hellos(&settings, Tickets::PermittingEarlyData).await?;
        let resumed_types = resumed.summary()?.extension_types().to_vec();
        assert_eq!(resumed_types.last(), Some(&PRE_SHARED_KEY));
        assert!(!resumed_types.contains(&EARLY_DATA));
    }
    Ok(())
}

#[tokio::test]
async fn firefox_resumed_client_hello_matches_the_capture_without_early_data() -> TestResult<()> {
    let settings = firefox::v157_tls();
    let (fresh, resumed) = fresh_and_resumed_client_hellos(
        &settings,
        Tickets::FixedLength(FIREFOX_CAPTURE_TICKET_LENGTH),
    )
    .await?;
    let captured = resumed_client_hellos(FIREFOX_NO_EARLY_DATA)?;
    assert!(!captured.is_empty());
    let resumed_types = resumed.summary()?.extension_types().to_vec();
    let actual = normalized_client_hello(resumed.handshake_bytes(), EchPayloadLength::Kept)?;
    assert_eq!(
        nss_ech_grease::ticket_length(resumed.handshake_bytes())?,
        FIREFOX_CAPTURE_TICKET_LENGTH
    );
    // With a ticket as long as the capture server's, the ECH GREASE payload
    // is Firefox's 368 bytes, so the ClientHellos match byte for byte apart
    // from per-connection values.
    assert_eq!(
        nss_ech_grease::sent_payload_length(resumed.handshake_bytes())?,
        368
    );
    for expected in &captured {
        assert_same_resumed_shape(resumed.handshake_bytes(), expected, &settings)?;
        assert_eq!(
            resumed_types,
            ClientHelloSummary::from_handshake_bytes(expected)?.extension_types()
        );
        assert_eq!(
            nss_ech_grease::ticket_length(expected)?,
            FIREFOX_CAPTURE_TICKET_LENGTH
        );
        assert_eq!(
            actual,
            normalized_client_hello(expected, EchPayloadLength::Kept)?
        );
    }
    // Firefox's fixed order, less the empty `session_ticket`, plus the PSK.
    let mut expected_types = fresh.summary()?.extension_types().to_vec();
    expected_types.retain(|&extension| extension != SESSION_TICKET);
    expected_types.push(PRE_SHARED_KEY);
    assert_eq!(resumed_types, expected_types);
    Ok(())
}

/// With a ticket that permits early data, the resumed ClientHello equals every
/// resumed ClientHello of Firefox's `resumption-sequential.txt`, all of which
/// offer `early_data`, byte for byte apart from per-connection values and the
/// ECH GREASE payload length. That length follows the ticket, which only a
/// BoringSSL loopback server here issues with early data, and a BoringSSL
/// ticket is longer than the capture server's; NSS's rule, applied to the
/// same ClientHello with the captured `pre_shared_key` length, gives
/// Firefox's 368.
#[tokio::test]
async fn firefox_resumed_client_hello_with_early_data_matches_the_capture() -> TestResult<()> {
    let settings = firefox::v157_tls();
    let (fresh, resumed) =
        fresh_and_resumed_client_hellos(&settings, Tickets::PermittingEarlyData).await?;
    let resumed_types = resumed.summary()?.extension_types().to_vec();
    // The Windows runs and one macOS 15.5 arm64 run.
    let mut captured = resumed_client_hellos(FIREFOX_SEQUENTIAL)?;
    captured.extend(resumed_client_hellos(FIREFOX_MACOS_SEQUENTIAL)?);
    assert!(!captured.is_empty());
    let actual = normalized_client_hello(resumed.handshake_bytes(), EchPayloadLength::Cleared)?;
    let resumed = resumed.handshake_bytes();
    assert_eq!(
        nss_ech_grease::sent_payload_length(resumed)?,
        nss_ech_grease::payload_length(resumed, FIREFOX_ECH_MAXIMUM_NAME_LENGTH, None)?
    );
    for expected in &captured {
        assert_same_resumed_shape(resumed, expected, &settings)?;
        assert_eq!(
            resumed_types,
            ClientHelloSummary::from_handshake_bytes(expected)?.extension_types()
        );
        assert_eq!(
            actual,
            normalized_client_hello(expected, EchPayloadLength::Cleared)?
        );
        assert_eq!(
            client_hello_fixture::extension_payload(expected, EARLY_DATA)?,
            b""
        );
        // The ticket makes Firefox's payload 128 bytes longer than the fresh
        // 240, and the rule gives the same length for Phantom's ClientHello
        // with the captured ticket.
        assert_eq!(
            nss_ech_grease::ticket_length(expected)?,
            FIREFOX_CAPTURE_TICKET_LENGTH
        );
        assert_eq!(nss_ech_grease::sent_payload_length(expected)?, 368);
        assert_eq!(
            nss_ech_grease::payload_length(expected, FIREFOX_ECH_MAXIMUM_NAME_LENGTH, None)?,
            368
        );
        assert_eq!(
            nss_ech_grease::payload_length_with_pre_shared_key(
                resumed,
                FIREFOX_ECH_MAXIMUM_NAME_LENGTH,
                None,
                nss_ech_grease::pre_shared_key_length(expected)?
            )?,
            368
        );
    }
    assert_eq!(
        nss_ech_grease::sent_payload_length(fresh.handshake_bytes())?,
        240
    );
    // Firefox's fixed order, less the empty `session_ticket`, with
    // `early_data` between `key_share` and `supported_versions` and the PSK
    // last.
    let mut expected_types = fresh.summary()?.extension_types().to_vec();
    expected_types.retain(|&extension| extension != SESSION_TICKET);
    let key_share = expected_types
        .iter()
        .position(|&extension| extension == KEY_SHARE)
        .ok_or("the fresh ClientHello has no key_share")?;
    expected_types.insert(key_share + 1, EARLY_DATA);
    expected_types.push(PRE_SHARED_KEY);
    assert_eq!(resumed_types, expected_types);
    Ok(())
}

/// A BoringSSL server issues two tickets per connection. After a resumed
/// connection, Chrome's recipe keeps the two newest; Firefox's keeps all
/// three. Three connections opened together then take one ticket each.
#[tokio::test]
async fn concurrent_connections_resume_up_to_the_recipes_tickets_per_origin() -> TestResult<()> {
    for (settings, expected) in [
        (chromium::v154_tls(), [true, true, false]),
        (firefox::v157_tls(), [true, true, true]),
    ] {
        let identity = TestIdentity::generate()?;
        let connector = TlsConnector::new_with_roots(&settings, [identity.root_der()])?
            .with_isolated_session_cache();
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let (address, listener) = loopback_listener().await?;
        let server = tokio::spawn(async move {
            let mut resumed = Vec::new();
            for _ in 0..5 {
                let (tcp, _) = listener.accept().await?;
                let ssl = btls::ssl::Ssl::new(acceptor.context())?;
                let mut stream = tokio_btls::SslStream::new(ssl, tcp)?;
                std::pin::Pin::new(&mut stream).accept().await?;
                resumed.push(stream.ssl().session_reused());
                stream.write_all(b"x").await?;
                stream.flush().await?;
                tokio::spawn(async move {
                    let mut rest = Vec::new();
                    let _ = stream.read_to_end(&mut rest).await;
                });
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(resumed)
        });

        for resumed in [false, true] {
            let mut stream = connect_local(&connector, address, TEST_SERVER_NAME).await??;
            assert_eq!(stream.session_reused(), resumed);
            let mut byte = [0_u8; 1];
            tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut byte)).await??;
        }
        let (first, second, third) = tokio::join!(
            connect_local(&connector, address, TEST_SERVER_NAME),
            connect_local(&connector, address, TEST_SERVER_NAME),
            connect_local(&connector, address, TEST_SERVER_NAME),
        );
        let mut concurrent = [
            first??.session_reused(),
            second??.session_reused(),
            third??.session_reused(),
        ];
        concurrent.sort_unstable_by(|left, right| right.cmp(left));
        assert_eq!(concurrent, expected);
        let server_resumed = tokio::time::timeout(TEST_TIMEOUT, server).await???;
        assert_eq!(server_resumed.iter().filter(|&&resumed| resumed).count(), {
            1 + expected.iter().filter(|&&resumed| resumed).count()
        });
    }
    Ok(())
}

/// Learns one TLS 1.3 ticket from a loopback server, then captures the fresh
/// and the resumed ClientHello the same connector sends on a direct
/// connection, which offers early data when the recipe and ticket allow it.
async fn fresh_and_resumed_client_hellos(
    settings: &TlsSettings,
    tickets: Tickets,
) -> TestResult<(ClientHelloCapture, ClientHelloCapture)> {
    let identity = TestIdentity::generate()?;
    let connector = TlsConnector::new_with_roots(settings, [identity.root_der()])?
        .with_isolated_session_cache();
    let fresh = capture_offering_early_data(&connector).await?;

    let (address, listener) = loopback_listener().await?;
    let server = match tickets {
        Tickets::WithoutEarlyData | Tickets::PermittingEarlyData => {
            let acceptor = identity.acceptor(TestServerAlpn::H2)?;
            tokio::spawn(async move {
                let early_data = matches!(tickets, Tickets::PermittingEarlyData);
                let mut stream =
                    accept_tls_with_early_data(&listener, &acceptor, early_data, Duration::ZERO)
                        .await?;
                stream.write_all(b"x").await?;
                stream.flush().await?;
                let _ = stream.read_to_end(&mut Vec::new()).await;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            })
        }
        Tickets::FixedLength(length) => {
            let config = fixed_length_ticket_server_config(&identity, length)?;
            tokio::spawn(async move {
                let (tcp, _) = listener.accept().await?;
                let tcp = tcp.into_std()?;
                tcp.set_nonblocking(false)?;
                tokio::task::spawn_blocking(move || serve_one_byte(config, tcp)).await??;
                Ok(())
            })
        }
    };
    let mut stream = connect_local(&connector, address, TEST_SERVER_NAME).await??;
    // Reading the server's first byte processes the tickets sent before it.
    let mut byte = [0_u8; 1];
    tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut byte)).await??;
    drop(stream);
    tokio::time::timeout(TEST_TIMEOUT, server).await???;

    let resumed = capture_offering_early_data(&connector).await?;
    Ok((fresh, resumed))
}

/// A rustls ticketer whose tickets are opaque handles of a fixed length,
/// standing for the sessions it keeps.
#[derive(Debug)]
struct FixedLengthTickets {
    length: usize,
    sessions: Mutex<Vec<Vec<u8>>>,
}

impl rustls::server::ProducesTickets for FixedLengthTickets {
    fn enabled(&self) -> bool {
        true
    }

    fn lifetime(&self) -> u32 {
        3_600
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        let mut sessions = self.sessions.lock().ok()?;
        let mut handle = vec![0; self.length];
        handle
            .get_mut(..8)?
            .copy_from_slice(&u64::try_from(sessions.len()).ok()?.to_be_bytes());
        sessions.push(plain.to_vec());
        Some(handle)
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        let index = usize::try_from(u64::from_be_bytes(*cipher.first_chunk::<8>()?)).ok()?;
        self.sessions.lock().ok()?.get(index).cloned()
    }
}

/// A TLS 1.3 rustls server for `h2` whose tickets are `ticket_length` bytes.
fn fixed_length_ticket_server_config(
    identity: &TestIdentity,
    ticket_length: usize,
) -> TestResult<Arc<rustls::ServerConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(
                identity.leaf_der().to_vec(),
            )],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                identity.private_key_der().to_vec(),
            )),
        )?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.ticketer = Arc::new(FixedLengthTickets {
        length: ticket_length,
        sessions: Mutex::default(),
    });
    Ok(Arc::new(config))
}

/// Completes one handshake, which sends the tickets, writes one byte, and
/// holds the connection until the client closes it.
fn serve_one_byte(config: Arc<rustls::ServerConfig>, tcp: std::net::TcpStream) -> io::Result<()> {
    use std::io::{Read, Write};

    let connection = rustls::ServerConnection::new(config).map_err(io::Error::other)?;
    let mut stream = rustls::StreamOwned::new(connection, tcp);
    stream.write_all(b"x")?;
    stream.flush()?;
    let _ = stream.read_to_end(&mut Vec::new());
    Ok(())
}

/// Captures the ClientHello of a direct connection. A ClientHello that offers
/// early data completes the client's side of the handshake at once, so the
/// connection is kept until the capture ends.
async fn capture_offering_early_data(connector: &TlsConnector) -> TestResult<ClientHelloCapture> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let capture = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        capture_client_hello(
            &mut stream,
            Instant::now() + TEST_TIMEOUT,
            CaptureLimits::new(32 * 1024, 40 * 1024, 4),
        )
        .await
        .map_err(io::Error::other)
    });
    let tcp = tokio::time::timeout(TEST_TIMEOUT, tokio::net::TcpStream::connect(address)).await??;
    let (handshake, capture) = tokio::join!(
        tokio::time::timeout(
            TEST_TIMEOUT,
            connector.connect_offering_early_data(TEST_SERVER_NAME, tcp)
        ),
        tokio::time::timeout(TEST_TIMEOUT, capture),
    );
    let capture = capture???;
    drop(handshake?);
    Ok(capture)
}

/// Returns the ClientHello with its per-connection values cleared: the random,
/// the session ID, the key-share keys, the ECH GREASE AEAD, configuration ID,
/// encapsulated key, and payload, and the PSK identities, ticket ages, and
/// binders, of which only the counts and binder lengths stay. Every other
/// byte stays, in order, with each extension's type and body.
fn normalized_client_hello(
    handshake: &[u8],
    ech_payload_length: EchPayloadLength,
) -> TestResult<Vec<u8>> {
    let body = handshake.get(4..).ok_or("truncated ClientHello")?;
    let mut reader = Reader(body);
    let mut normalized = Vec::new();
    normalized.extend_from_slice(reader.take(2)?);
    reader.take(32)?;
    normalized.extend_from_slice(&[0; 32]);
    let session_id = reader.vector8()?;
    normalized.push(u8::try_from(session_id.len())?);
    normalized.resize(normalized.len() + session_id.len(), 0);
    let cipher_suites = reader.vector16()?;
    normalized.extend_from_slice(&u16::try_from(cipher_suites.len())?.to_be_bytes());
    normalized.extend_from_slice(cipher_suites);
    let compression = reader.vector8()?;
    normalized.push(u8::try_from(compression.len())?);
    normalized.extend_from_slice(compression);
    let mut extensions = Reader(reader.vector16()?);
    if !reader.0.is_empty() {
        return Err("trailing bytes after the ClientHello extensions".into());
    }
    while !extensions.0.is_empty() {
        let extension_type = extensions.take(2)?;
        let extension_type = u16::from_be_bytes([extension_type[0], extension_type[1]]);
        let body = extensions.vector16()?;
        let body = match extension_type {
            KEY_SHARE => normalized_key_share(body)?,
            ENCRYPTED_CLIENT_HELLO => normalized_ech(body, ech_payload_length)?,
            PRE_SHARED_KEY => {
                let (identities, binders) = psk_shape(body)?;
                let mut shape = vec![u8::try_from(identities)?];
                for binder in binders {
                    shape.push(u8::try_from(binder)?);
                }
                shape
            }
            _ => body.to_vec(),
        };
        normalized.extend_from_slice(&extension_type.to_be_bytes());
        normalized.extend_from_slice(&u16::try_from(body.len())?.to_be_bytes());
        normalized.extend_from_slice(&body);
    }
    Ok(normalized)
}

fn normalized_key_share(body: &[u8]) -> TestResult<Vec<u8>> {
    let mut normalized = body.to_vec();
    let mut entries = Reader(Reader(body).vector16()?);
    let mut offset = 2;
    while !entries.0.is_empty() {
        entries.take(2)?;
        let key = entries.vector16()?;
        offset += 4;
        normalized[offset..offset + key.len()].fill(0);
        offset += key.len();
    }
    Ok(normalized)
}

/// Keeps the ECH outer type, KDF, the encapsulated key length, and the
/// payload length unless `payload_length` clears it. The AEAD and
/// configuration ID are drawn per connection, and the key and payload are
/// random.
fn normalized_ech(body: &[u8], payload_length: EchPayloadLength) -> TestResult<Vec<u8>> {
    let mut reader = Reader(body);
    let mut normalized = reader.take(3)?.to_vec();
    reader.take(3)?;
    normalized.extend_from_slice(&[0; 3]);
    let encapsulated_key = reader.vector16()?;
    normalized.extend_from_slice(&u16::try_from(encapsulated_key.len())?.to_be_bytes());
    normalized.resize(normalized.len() + encapsulated_key.len(), 0);
    let payload = reader.vector16()?;
    if let EchPayloadLength::Kept = payload_length {
        normalized.extend_from_slice(&u16::try_from(payload.len())?.to_be_bytes());
        normalized.resize(normalized.len() + payload.len(), 0);
    }
    if !reader.0.is_empty() {
        return Err("trailing bytes in the ECH extension".into());
    }
    Ok(normalized)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> TestResult<&'a [u8]> {
        let (taken, rest) = self
            .0
            .split_at_checked(count)
            .ok_or("truncated ClientHello field")?;
        self.0 = rest;
        Ok(taken)
    }

    fn vector8(&mut self) -> TestResult<&'a [u8]> {
        let length = usize::from(self.take(1)?[0]);
        self.take(length)
    }

    fn vector16(&mut self) -> TestResult<&'a [u8]> {
        let length = self.take(2)?;
        self.take(usize::from(u16::from_be_bytes([length[0], length[1]])))
    }
}

/// Returns the fixture's retained ClientHellos that offer a PSK.
fn resumed_client_hellos(fixture: &str) -> TestResult<Vec<Vec<u8>>> {
    let mut hellos = Vec::new();
    for line in fixture.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.ends_with("_client_hello_hex") {
            let hello = client_hello_fixture::decode_hex(value)?;
            if client_hello_fixture::extension_payload(&hello, PRE_SHARED_KEY).is_ok() {
                hellos.push(hello);
            }
        }
    }
    Ok(hellos)
}

/// Compares everything but per-connection randomness (GREASE values, key
/// shares, the ticket itself) and extension order.
fn assert_same_resumed_shape(
    actual: &[u8],
    expected: &[u8],
    settings: &TlsSettings,
) -> TestResult<()> {
    let actual_summary = ClientHelloSummary::from_handshake_bytes(actual)?;
    let expected_summary = ClientHelloSummary::from_handshake_bytes(expected)?;
    assert_eq!(
        without_grease(actual_summary.cipher_suites()),
        without_grease(expected_summary.cipher_suites())
    );
    assert_eq!(
        without_grease(actual_summary.supported_groups()),
        without_grease(expected_summary.supported_groups())
    );
    assert_eq!(
        without_grease(actual_summary.key_share_groups()),
        without_grease(expected_summary.key_share_groups())
    );
    assert_eq!(
        without_grease(actual_summary.signature_algorithms()),
        without_grease(expected_summary.signature_algorithms())
    );
    assert_eq!(
        without_grease(actual_summary.supported_versions()),
        without_grease(expected_summary.supported_versions())
    );
    assert_eq!(
        actual_summary.alpn_protocols(),
        expected_summary.alpn_protocols()
    );
    // Chrome 154 sends one sorted trust-anchor list, so a fixed recipe list
    // compares in order. Opera 136 draws an order per process, so its
    // emitted order must be one the recipe draws from, and the captured
    // order, from a process the recipe may not list, compares as a set.
    match &settings.requested_trust_anchor_ids {
        None | Some(TrustAnchorIds::Fixed(_)) => assert_eq!(
            actual_summary.requested_trust_anchor_ids(),
            expected_summary.requested_trust_anchor_ids()
        ),
        Some(ids) => {
            let emitted = actual_summary
                .requested_trust_anchor_ids()
                .ok_or("recipe omitted trust-anchor IDs")?;
            assert!(ids.orders().iter().any(|order| {
                order
                    .iter()
                    .map(AsRef::as_ref)
                    .eq(emitted.iter().map(Vec::as_slice))
            }));
            let sorted_ids = |summary: &ClientHelloSummary| {
                summary.requested_trust_anchor_ids().map(|ids| {
                    let mut ids = ids.to_vec();
                    ids.sort_unstable();
                    ids
                })
            };
            assert_eq!(sorted_ids(&actual_summary), sorted_ids(&expected_summary));
        }
    }
    assert_eq!(
        actual_summary.extension_types().last(),
        Some(&PRE_SHARED_KEY)
    );
    assert_eq!(
        expected_summary.extension_types().last(),
        Some(&PRE_SHARED_KEY)
    );
    let mut actual_types = without_grease(actual_summary.extension_types());
    let mut expected_types = without_grease(expected_summary.extension_types());
    actual_types.sort_unstable();
    expected_types.sort_unstable();
    assert_eq!(actual_types, expected_types);
    assert_eq!(
        actual_types.contains(&SESSION_TICKET),
        settings.session_ticket_extension_when_resuming
    );
    assert_eq!(
        client_hello_fixture::extension_payload(actual, PSK_KEY_EXCHANGE_MODES)?,
        client_hello_fixture::extension_payload(expected, PSK_KEY_EXCHANGE_MODES)?
    );
    // One identity and one SHA-256 binder in both; the identity is the
    // server's opaque ticket, so only the counts and binder length compare.
    for hello in [actual, expected] {
        let (identities, binders) = psk_shape(client_hello_fixture::extension_payload(
            hello,
            PRE_SHARED_KEY,
        )?)?;
        assert_eq!(identities, 1);
        assert_eq!(binders, [32]);
    }
    Ok(())
}

/// Counts the offered identities and returns each binder's length.
fn psk_shape(body: &[u8]) -> TestResult<(usize, Vec<usize>)> {
    let identities_length = usize::from(u16::from_be_bytes(
        *body.first_chunk::<2>().ok_or("truncated pre_shared_key")?,
    ));
    let mut offset = 2;
    let end = offset + identities_length;
    let mut identities = 0;
    while offset < end {
        let length = usize::from(u16::from_be_bytes([body[offset], body[offset + 1]]));
        offset += 2 + length + 4;
        identities += 1;
    }
    let binders_length = usize::from(u16::from_be_bytes([body[offset], body[offset + 1]]));
    offset += 2;
    let end = offset + binders_length;
    let mut binders = Vec::new();
    while offset < end {
        let length = usize::from(body[offset]);
        binders.push(length);
        offset += 1 + length;
    }
    if offset != body.len() {
        return Err("pre_shared_key has trailing bytes".into());
    }
    Ok((identities, binders))
}

fn without_grease(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .copied()
        .filter(|&value| value & 0x0f0f != 0x0a0a || value >> 8 != value & 0xff)
        .collect()
}
