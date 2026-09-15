use std::{error::Error, io, net::SocketAddr, pin::Pin, time::Duration};

use btls::{
    pkey::PKey,
    ssl::{AlpnError, NameType, Ssl, SslAcceptor, SslMethod, select_next_proto},
    x509::X509,
};
use phantom_profile::{
    AlpsSettings, CertificateCompression, CipherSuite, NamedGroup, SignatureScheme, TlsSettings,
    TlsVersion,
};
use phantom_testkit::tls::{CaptureLimits, capture_client_hello};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use tokio::{net::TcpListener, task::JoinHandle, time::Instant};
use tokio_btls::SslStream as BoringStream;

use super::{TlsConnector, TlsErrorKind, encode_trust_anchor_ids, require_supported};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const TEST_SERVER_NAME: &str = "server.phantom.test";
const H2_ALPN_WIRE: &[u8] = b"\x02h2";

type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

mod chrome;

#[test]
fn trust_anchor_ids_are_length_prefixed_for_boringssl() {
    let ids = [Box::from(&b"a"[..]), Box::from(&b"bc"[..])];

    assert_eq!(encode_trust_anchor_ids(&ids).as_ref(), b"\x01a\x02bc");
}

fn chromium_152_macos_reference() -> TlsSettings {
    TlsSettings {
        min_version: TlsVersion::Tls12,
        max_version: TlsVersion::Tls13,
        cipher_suites: vec![
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::Chacha20Poly1305Sha256,
            CipherSuite::EcdheEcdsaAes128GcmSha256,
            CipherSuite::EcdheRsaAes128GcmSha256,
            CipherSuite::EcdheEcdsaAes256GcmSha384,
            CipherSuite::EcdheRsaAes256GcmSha384,
            CipherSuite::EcdheEcdsaChacha20Poly1305Sha256,
            CipherSuite::EcdheRsaChacha20Poly1305Sha256,
            CipherSuite::EcdheRsaAes128CbcSha,
            CipherSuite::EcdheRsaAes256CbcSha,
            CipherSuite::RsaAes128GcmSha256,
            CipherSuite::RsaAes256GcmSha384,
            CipherSuite::RsaAes128CbcSha,
            CipherSuite::RsaAes256CbcSha,
        ],
        groups: vec![
            NamedGroup::X25519MlKem768,
            NamedGroup::X25519,
            NamedGroup::Secp256r1,
            NamedGroup::Secp384r1,
        ],
        key_shares: vec![NamedGroup::X25519MlKem768, NamedGroup::X25519],
        signature_schemes: vec![
            SignatureScheme::MlDsa44,
            SignatureScheme::MlDsa65,
            SignatureScheme::MlDsa87,
            SignatureScheme::EcdsaSecp256r1Sha256,
            SignatureScheme::RsaPssRsaeSha256,
            SignatureScheme::RsaPkcs1Sha256,
            SignatureScheme::EcdsaSecp384r1Sha384,
            SignatureScheme::RsaPssRsaeSha384,
            SignatureScheme::RsaPkcs1Sha384,
            SignatureScheme::RsaPssRsaeSha512,
            SignatureScheme::RsaPkcs1Sha512,
        ],
        alpn_protocols: vec![Box::from(&b"h2"[..]), Box::from(&b"http/1.1"[..])],
        alps: Some(AlpsSettings {
            protocol: Box::from(&b"h2"[..]),
            use_new_codepoint: true,
        }),
        certificate_compression: vec![CertificateCompression::Brotli],
        requested_trust_anchor_ids: Some(Vec::new()),
        grease: true,
        grease_signature_algorithms: true,
        permute_extensions: true,
        ech_grease: true,
        request_ocsp_staple: true,
        request_signed_certificate_timestamps: true,
        aes_hardware: true,
    }
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

    let mut settings = chromium_152_macos_reference();
    settings.max_version = TlsVersion::Tls12;
    settings.alps = None;
    settings.key_shares.clear();
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

#[test]
fn invalid_settings_fail_before_stream_io() -> TestResult<()> {
    let mut settings = chromium_152_macos_reference();
    settings.alpn_protocols = vec![Box::default()];

    let error = match TlsConnector::new(&settings) {
        Ok(_) => return Err("empty ALPN unexpectedly built a connector".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), TlsErrorKind::InvalidConfiguration);
    assert!(error.to_string().contains("alpn_protocols"));
    Ok(())
}

#[tokio::test]
async fn trusted_chain_succeeds_and_reports_alpn_and_sni() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, server_task) = start_server(&identity, true).await?;
    let connector = TlsConnector::new_with_roots(
        &chromium_152_macos_reference(),
        [identity.root_der.as_slice()],
    )?;

    let stream = connect_local(&connector, address, TEST_SERVER_NAME).await??;
    assert_eq!(stream.negotiated_alpn(), Some(&b"h2"[..]));

    let observed_sni = tokio::time::timeout(TEST_TIMEOUT, server_task).await???;
    assert_eq!(observed_sni.as_deref(), Some(TEST_SERVER_NAME));
    Ok(())
}

#[tokio::test]
async fn successful_handshake_without_alpn_reports_none() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, server_task) = start_server(&identity, false).await?;
    let connector = TlsConnector::new_with_roots(
        &chromium_152_macos_reference(),
        [identity.root_der.as_slice()],
    )?;

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
    let connector = TlsConnector::new_with_roots(
        &chromium_152_macos_reference(),
        [identity.root_der.as_slice()],
    )?;

    let result = connect_local(&connector, address, "wrong.phantom.test").await?;
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(TlsErrorKind::Handshake)
    );

    let server_result = tokio::time::timeout(TEST_TIMEOUT, server_task).await??;
    assert!(server_result.is_err());
    Ok(())
}

#[tokio::test]
async fn untrusted_root_fails() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, server_task) = start_server(&identity, true).await?;
    let connector =
        TlsConnector::new_with_roots(&chromium_152_macos_reference(), std::iter::empty())?;

    let result = connect_local(&connector, address, TEST_SERVER_NAME).await?;
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(TlsErrorKind::Handshake)
    );

    let server_result = tokio::time::timeout(TEST_TIMEOUT, server_task).await??;
    assert!(server_result.is_err());
    Ok(())
}

struct TestIdentity {
    root_der: Vec<u8>,
    leaf_der: Vec<u8>,
    private_key_der: Vec<u8>,
}

impl TestIdentity {
    fn generate() -> TestResult<Self> {
        let mut root_params = CertificateParams::new(Vec::<String>::new())?;
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let root = CertifiedIssuer::self_signed(root_params, KeyPair::generate()?)?;

        let mut leaf_params = CertificateParams::new(vec![TEST_SERVER_NAME.to_owned()])?;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf_params.use_authority_key_identifier_extension = true;
        let leaf_key = KeyPair::generate()?;
        let leaf = leaf_params.signed_by(&leaf_key, &root)?;

        Ok(Self {
            root_der: root.der().to_vec(),
            leaf_der: leaf.der().to_vec(),
            private_key_der: leaf_key.serialize_der(),
        })
    }
}

async fn start_server(
    identity: &TestIdentity,
    select_h2: bool,
) -> TestResult<(SocketAddr, JoinHandle<TestResult<Option<String>>>)> {
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    let leaf = X509::from_der(&identity.leaf_der)?;
    let root = X509::from_der(&identity.root_der)?;
    let private_key = PKey::private_key_from_pkcs8(&identity.private_key_der)?;
    acceptor.set_certificate(&leaf)?;
    acceptor.set_private_key(&private_key)?;
    acceptor.add_extra_chain_cert(root)?;
    acceptor.check_private_key()?;
    if select_h2 {
        acceptor.set_alpn_select_callback(|_, offered| {
            select_next_proto(H2_ALPN_WIRE, offered).ok_or(AlpnError::NOACK)
        });
    }
    let acceptor = acceptor.build();

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let ssl = Ssl::new(acceptor.context())?;
        let mut stream = BoringStream::new(ssl, tcp)?;
        Pin::new(&mut stream).accept().await?;
        Ok(stream
            .ssl()
            .servername(NameType::HOST_NAME)
            .map(str::to_owned))
    });
    Ok((address, task))
}

async fn connect_local(
    connector: &TlsConnector,
    address: SocketAddr,
    server_name: &str,
) -> TestResult<Result<super::TlsStream<tokio::net::TcpStream>, super::TlsError>> {
    let tcp = tokio::time::timeout(TEST_TIMEOUT, tokio::net::TcpStream::connect(address))
        .await
        .map_err(Box::<dyn Error + Send + Sync>::from)??;
    Ok(tokio::time::timeout(TEST_TIMEOUT, connector.connect(server_name, tcp)).await?)
}
