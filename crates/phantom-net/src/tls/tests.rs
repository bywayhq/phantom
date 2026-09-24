use std::{io, net::SocketAddr};

use phantom_profile::{CipherSuite, TlsSettings, TlsVersion, chromium::v154_tls};
use phantom_testkit::tls::{CaptureLimits, ClientHelloCapture, capture_client_hello};
use tokio::{net::TcpListener, task::JoinHandle, time::Instant};

use super::{
    TlsConnector, TlsErrorKind, encode_trust_anchor_ids, require_supported,
    test_support::{
        TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, TestServerAlpn, accept_tls,
        connect_local, loopback_listener,
    },
};

mod alps;
mod capabilities;
mod chrome;
mod client_hello_fixture;
mod ech;
mod firefox;
mod hello_retry;
mod record_size_limit;
mod session_cache;
mod tracing;

#[test]
fn trust_anchor_ids_are_length_prefixed_for_boringssl() {
    let ids = [Box::from(&b"a"[..]), Box::from(&b"bc"[..])];

    assert_eq!(encode_trust_anchor_ids(&ids).as_ref(), b"\x01a\x02bc");
}

#[tokio::test]
async fn tls_12_client_hello_omits_key_share_extension() -> TestResult<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let capture_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        capture_client_hello(
            &mut stream,
            Instant::now() + TEST_TIMEOUT,
            CaptureLimits::new(32 * 1024, 40 * 1024, 4),
        )
        .await
        .map_err(io::Error::other)
    });

    let mut settings = v154_tls();
    settings.max_version = TlsVersion::Tls12;
    settings.alps = None;
    settings.key_shares.clear();
    settings.certificate_compression.clear();
    settings.ech_grease = false;
    settings.requested_trust_anchor_ids = None;
    let connector = TlsConnector::new(&settings)?;
    let tcp = tokio::time::timeout(TEST_TIMEOUT, tokio::net::TcpStream::connect(address)).await??;
    let handshake = tokio::time::timeout(TEST_TIMEOUT, connector.connect("example.test", tcp));
    assert!(handshake.await?.is_err());

    let capture = tokio::time::timeout(TEST_TIMEOUT, capture_task).await???;
    let summary = capture.summary()?;
    assert!(summary.key_share_groups().is_empty());
    assert!(!summary.extension_types().contains(&51));
    Ok(())
}

#[test]
fn unmapped_backend_setting_is_actionable() -> TestResult<()> {
    let error = match require_supported("cipher_suites", "future cipher", None::<&'static str>) {
        Ok(_) => return Err("unmapped backend setting unexpectedly succeeded".into()),
        Err(error) => error,
    };

    assert_eq!(error.kind(), TlsErrorKind::UnsupportedSetting);
    assert!(error.to_string().contains("future cipher"));
    assert!(error.to_string().contains("BoringSSL adapter"));
    Ok(())
}

async fn capture_client_hello_from(settings: &TlsSettings) -> TestResult<ClientHelloCapture> {
    capture_client_hello_from_server_name(settings, TEST_SERVER_NAME).await
}

async fn capture_client_hello_from_server_name(
    settings: &TlsSettings,
    server_name: &str,
) -> TestResult<ClientHelloCapture> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let capture_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        capture_client_hello(
            &mut stream,
            Instant::now() + TEST_TIMEOUT,
            CaptureLimits::new(32 * 1024, 40 * 1024, 4),
        )
        .await
        .map_err(io::Error::other)
    });

    let connector = TlsConnector::new(settings)?;
    let tcp = tokio::time::timeout(TEST_TIMEOUT, tokio::net::TcpStream::connect(address)).await??;
    let handshake = tokio::time::timeout(TEST_TIMEOUT, connector.connect(server_name, tcp));
    if handshake.await?.is_ok() {
        return Err("capture peer unexpectedly completed TLS".into());
    }

    Ok(tokio::time::timeout(TEST_TIMEOUT, capture_task).await???)
}

/// Captures one ClientHello from each of `connections` handshakes made by a
/// single connector, so the samples expose its per-connection choices.
async fn capture_client_hellos_from(
    settings: &TlsSettings,
    server_name: &str,
    connections: usize,
) -> TestResult<Vec<ClientHelloCapture>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let connector = TlsConnector::new(settings)?;
    let mut captures = Vec::with_capacity(connections);
    for _ in 0..connections {
        // The capture drops its stream after the ClientHello, which ends the
        // client handshake.
        let capture = async {
            let (mut stream, _) = listener.accept().await?;
            capture_client_hello(
                &mut stream,
                Instant::now() + TEST_TIMEOUT,
                CaptureLimits::new(32 * 1024, 40 * 1024, 4),
            )
            .await
            .map_err(io::Error::other)
        };
        let handshake = async {
            let tcp = tokio::net::TcpStream::connect(address).await?;
            Ok::<_, io::Error>(connector.connect(server_name, tcp).await.is_ok())
        };
        let (capture, completed) =
            tokio::time::timeout(TEST_TIMEOUT, async { tokio::join!(capture, handshake) }).await?;
        if completed? {
            return Err("capture peer unexpectedly completed TLS".into());
        }
        captures.push(capture?);
    }
    Ok(captures)
}

#[test]
fn invalid_settings_fail_before_stream_io() -> TestResult<()> {
    let mut settings = v154_tls();
    settings.alpn_protocols = vec![Box::default()];

    let error = match TlsConnector::new(&settings) {
        Ok(_) => return Err("empty ALPN unexpectedly built a connector".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), TlsErrorKind::InvalidConfiguration);
    assert!(error.to_string().contains("alpn_protocols"));
    Ok(())
}

#[test]
fn connector_debug_reports_alps_metadata_without_payload() -> TestResult<()> {
    const OPAQUE_ALPS_PAYLOAD: &[u8] = b"opaque-alps-marker-7f3c";

    let mut settings = v154_tls();
    settings
        .alps
        .as_mut()
        .ok_or("Chrome profile omitted ALPS")?
        .settings = OPAQUE_ALPS_PAYLOAD.into();
    let connector = TlsConnector::new_with_roots(&settings, std::iter::empty::<&[u8]>())?;

    let debug = format!("{connector:?}");
    assert_eq!(
        debug,
        "TlsConnector { server_authentication: WebPki, alpn_protocol_count: 2, \
         alps_protocol: Some(\"h2\"), alps_settings_len: Some(23), \
         alps_use_new_codepoint: Some(true), tls13_key_shares: \
         Some([X25519MlKem768, X25519]), ech_grease: true, \
         ech_grease_payload_length: None, ech_grease_aeads: [], .. }"
    );
    assert!(!debug.contains("opaque-alps-marker-7f3c"));
    Ok(())
}

#[tokio::test]
async fn trusted_chain_succeeds_and_reports_alpn_and_sni() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, server_task) = start_server(&identity, true).await?;
    let connector = TlsConnector::new_with_roots(&v154_tls(), [identity.root_der()])?;

    let stream = connect_local(&connector, address, TEST_SERVER_NAME).await??;
    assert_eq!(stream.negotiated_alpn(), Some(&b"h2"[..]));
    assert_eq!(stream.negotiated_tls_version(), Some(TlsVersion::Tls13));
    assert!(matches!(
        stream.negotiated_cipher_suite(),
        Some(
            CipherSuite::Aes128GcmSha256
                | CipherSuite::Aes256GcmSha384
                | CipherSuite::Chacha20Poly1305Sha256
        )
    ));

    let observed_sni = tokio::time::timeout(TEST_TIMEOUT, server_task).await???;
    assert_eq!(observed_sni.as_deref(), Some(TEST_SERVER_NAME));
    Ok(())
}

#[tokio::test]
async fn successful_handshake_without_alpn_reports_none() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, server_task) = start_server(&identity, false).await?;
    let connector = TlsConnector::new_with_roots(&v154_tls(), [identity.root_der()])?;

    let stream = connect_local(&connector, address, TEST_SERVER_NAME).await??;
    assert_eq!(stream.negotiated_alpn(), None);
    let observed_sni = tokio::time::timeout(TEST_TIMEOUT, server_task).await???;
    assert_eq!(observed_sni.as_deref(), Some(TEST_SERVER_NAME));
    Ok(())
}

#[tokio::test]
async fn wrong_hostname_fails() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, server_task) = start_server(&identity, true).await?;
    let connector = TlsConnector::new_with_roots(&v154_tls(), [identity.root_der()])?
        .with_isolated_session_cache();

    let result = connect_local(&connector, address, "wrong.phantom.test").await?;
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(TlsErrorKind::Handshake)
    );
    assert_eq!(
        connector.session_cache.as_ref().map(|cache| cache.len()),
        Some(0)
    );

    let server_result = tokio::time::timeout(TEST_TIMEOUT, server_task).await??;
    assert!(server_result.is_err());
    Ok(())
}

#[tokio::test]
async fn untrusted_root_fails() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, server_task) = start_server(&identity, true).await?;
    let connector = TlsConnector::new_with_roots(&v154_tls(), std::iter::empty())?;

    let result = connect_local(&connector, address, TEST_SERVER_NAME).await?;
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(TlsErrorKind::Handshake)
    );

    let server_result = tokio::time::timeout(TEST_TIMEOUT, server_task).await??;
    assert!(server_result.is_err());
    Ok(())
}

async fn start_server(
    identity: &TestIdentity,
    select_h2: bool,
) -> TestResult<(SocketAddr, JoinHandle<TestResult<Option<String>>>)> {
    let alpn = if select_h2 {
        TestServerAlpn::H2
    } else {
        TestServerAlpn::None
    };
    let acceptor = identity.acceptor(alpn)?;
    let (address, listener) = loopback_listener().await?;
    let task = tokio::spawn(async move {
        let (_stream, sni) = accept_tls(listener, acceptor).await?;
        Ok(sni)
    });
    Ok((address, task))
}
