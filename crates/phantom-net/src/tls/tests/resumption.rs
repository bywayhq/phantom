//! TLS 1.3 resumption over TCP, compared with the browser resumption captures.

use std::io;

use phantom_profile::{TlsSettings, brave, chromium, edge, firefox, opera};
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
        TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, TestServerAlpn, accept_tls,
        connect_local, loopback_listener,
    },
};

const SESSION_TICKET: u16 = 0x0023;
const PRE_SHARED_KEY: u16 = 0x0029;
const EARLY_DATA: u16 = 0x002a;
const PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;

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
const OPERA_SEQUENTIAL: &str = fixture!("opera", "135.0.5973.92", "sequential");
const FIREFOX_SEQUENTIAL: &str = fixture!("firefox", "156.0", "sequential");
const FIREFOX_NO_EARLY_DATA: &str = fixture!("firefox", "156.0", "no-early-data");
const CHROME_MACOS_SEQUENTIAL: &str =
    fixture!("chrome", "154.0.8037.58", "macos-15.5-arm64", "sequential");
const EDGE_MACOS_SEQUENTIAL: &str =
    fixture!("edge", "154.0.4258.37", "macos-15.5-arm64", "sequential");
const OPERA_MACOS_SEQUENTIAL: &str =
    fixture!("opera", "135.0.5973.92", "macos-15.5-arm64", "sequential");
const FIREFOX_MACOS_SEQUENTIAL: &str =
    fixture!("firefox", "156.0", "macos-15.5-arm64", "sequential");

#[tokio::test]
async fn chromium_resumed_client_hellos_match_the_tcp_resumption_captures() -> TestResult<()> {
    for (settings, fixture) in [
        (chromium::v154_tls(), CHROME_SEQUENTIAL),
        (edge::v154_tls(), EDGE_SEQUENTIAL),
        (brave::v154_tls(), BRAVE_SEQUENTIAL),
        (opera::v135_tls(), OPERA_SEQUENTIAL),
        // One macOS 15.5 arm64 run per browser.
        (chromium::v154_tls(), CHROME_MACOS_SEQUENTIAL),
        (edge::v154_tls(), EDGE_MACOS_SEQUENTIAL),
        (opera::v135_tls(), OPERA_MACOS_SEQUENTIAL),
    ] {
        let (fresh, resumed) = fresh_and_resumed_client_hellos(&settings).await?;
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

#[tokio::test]
async fn firefox_resumed_client_hello_matches_the_capture_without_early_data() -> TestResult<()> {
    let settings = firefox::v156_tls();
    let (fresh, resumed) = fresh_and_resumed_client_hellos(&settings).await?;
    let captured = resumed_client_hellos(FIREFOX_NO_EARLY_DATA)?;
    assert!(!captured.is_empty());
    let resumed_types = resumed.summary()?.extension_types().to_vec();
    for expected in &captured {
        assert_same_resumed_shape(resumed.handshake_bytes(), expected, &settings)?;
        assert_eq!(
            resumed_types,
            ClientHelloSummary::from_handshake_bytes(expected)?.extension_types()
        );
    }
    // Firefox's fixed order, less the empty `session_ticket`, plus the PSK.
    let mut expected_types = fresh.summary()?.extension_types().to_vec();
    expected_types.retain(|&extension| extension != SESSION_TICKET);
    expected_types.push(PRE_SHARED_KEY);
    assert_eq!(resumed_types, expected_types);
    Ok(())
}

/// Firefox 156 offers `early_data` over TCP when the ticket permits it;
/// Phantom never offers early data over TCP. This pins that one difference.
#[tokio::test]
async fn firefox_resumed_client_hello_lacks_only_the_early_data_firefox_offers() -> TestResult<()> {
    let settings = firefox::v156_tls();
    let (_, resumed) = fresh_and_resumed_client_hellos(&settings).await?;
    let resumed_types = resumed.summary()?.extension_types().to_vec();
    // The Windows runs and one macOS 15.5 arm64 run.
    let mut captured = resumed_client_hellos(FIREFOX_SEQUENTIAL)?;
    captured.extend(resumed_client_hellos(FIREFOX_MACOS_SEQUENTIAL)?);
    assert!(!captured.is_empty());
    for expected in &captured {
        let mut expected_types = ClientHelloSummary::from_handshake_bytes(expected)?
            .extension_types()
            .to_vec();
        let early_data = expected_types
            .iter()
            .position(|&extension| extension == EARLY_DATA)
            .ok_or("the Firefox capture did not offer early data")?;
        expected_types.remove(early_data);
        assert_eq!(resumed_types, expected_types);
    }
    Ok(())
}

/// A BoringSSL server issues two tickets per connection. After a resumed
/// connection, Chrome's recipe keeps the two newest; Firefox's keeps all
/// three. Three connections opened together then take one ticket each.
#[tokio::test]
async fn concurrent_connections_resume_up_to_the_recipes_tickets_per_origin() -> TestResult<()> {
    for (settings, expected) in [
        (chromium::v154_tls(), [true, true, false]),
        (firefox::v156_tls(), [true, true, true]),
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
/// and the resumed ClientHello the same connector sends.
async fn fresh_and_resumed_client_hellos(
    settings: &TlsSettings,
) -> TestResult<(ClientHelloCapture, ClientHelloCapture)> {
    let identity = TestIdentity::generate()?;
    let connector = TlsConnector::new_with_roots(settings, [identity.root_der()])?
        .with_isolated_session_cache();
    let fresh = capture_one(&connector).await?;

    let acceptor = identity.acceptor(TestServerAlpn::H2)?;
    let (address, listener) = loopback_listener().await?;
    let server = tokio::spawn(async move {
        let (mut stream, _) = accept_tls(listener, acceptor).await?;
        stream.write_all(b"x").await?;
        stream.flush().await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let mut stream = connect_local(&connector, address, TEST_SERVER_NAME).await??;
    // Reading the server's first byte processes the tickets sent before it.
    let mut byte = [0_u8; 1];
    tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut byte)).await??;
    tokio::time::timeout(TEST_TIMEOUT, server).await???;
    drop(stream);

    let resumed = capture_one(&connector).await?;
    Ok((fresh, resumed))
}

async fn capture_one(connector: &TlsConnector) -> TestResult<ClientHelloCapture> {
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
    let handshake = connect_local(connector, address, TEST_SERVER_NAME).await?;
    if handshake.is_ok() {
        return Err("capture peer unexpectedly completed TLS".into());
    }
    Ok(tokio::time::timeout(TEST_TIMEOUT, capture).await???)
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
    assert_eq!(
        actual_summary.requested_trust_anchor_ids(),
        expected_summary.requested_trust_anchor_ids()
    );
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
