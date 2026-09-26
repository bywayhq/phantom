//! A client certificate answers a server's request for client authentication.

use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use btls::{
    pkey::PKey,
    rsa::Rsa,
    ssl::{SslAcceptor, SslVerifyMode},
    x509::X509,
};
use bytes::Bytes;
use http::{Response, StatusCode};
use phantom::{
    BuildErrorKind, Client, ClientCertificate, ClientCertificateErrorKind, HttpProtocol,
    RequestError, RequestErrorKind,
    profile::{CipherSuite, ClientProfile, NamedGroup, SignatureScheme, TlsSettings, TlsVersion},
};
use phantom_testkit::tls::{CaptureLimits, ClientHelloSummary, capture_client_hello};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384,
};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
};
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::oneshot, time::timeout};

use crate::support::{h3 as h3_support, tls as tls_support};
use tls_support::{H1_ALPN, TestIdentity, TestResult, accept_tls, read_head, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// A client certificate issued by a private authority, in the forms a
/// caller and a test server need.
struct ClientIdentity {
    authority_der: Vec<u8>,
    leaf_der: Vec<u8>,
    chain_pem: String,
    key_pem: String,
}

impl ClientIdentity {
    fn issue(key: KeyPair) -> TestResult<Self> {
        let mut authority_params = CertificateParams::new(Vec::<String>::new())?;
        authority_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        authority_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let authority = CertifiedIssuer::self_signed(
            authority_params,
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?,
        )?;

        let mut leaf_params = CertificateParams::new(Vec::<String>::new())?;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        leaf_params.use_authority_key_identifier_extension = true;
        let leaf = leaf_params.signed_by(&key, &authority)?;

        Ok(Self {
            authority_der: authority.der().to_vec(),
            leaf_der: leaf.der().to_vec(),
            chain_pem: format!("{}{}", leaf.pem(), authority.pem()),
            key_pem: key.serialize_pem(),
        })
    }

    fn p256() -> TestResult<Self> {
        Self::issue(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?)
    }

    fn rsa() -> TestResult<Self> {
        let key = PKey::from_rsa(Rsa::generate(2048)?)?;
        let pem = String::from_utf8(key.private_key_to_pem_pkcs8()?)?;
        Self::issue(KeyPair::from_pem(&pem)?)
    }

    fn certificate(&self) -> TestResult<ClientCertificate> {
        Ok(ClientCertificate::from_pem(
            self.chain_pem.as_bytes(),
            self.key_pem.as_bytes(),
        )?)
    }
}

/// TLS settings for HTTP/1.1 at `version` that can sign with RSA and P-256.
fn tls(version: TlsVersion) -> TlsSettings {
    let mut tls = tls_settings();
    tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    tls.signature_schemes = vec![
        SignatureScheme::EcdsaSecp256r1Sha256,
        SignatureScheme::RsaPssRsaeSha256,
        SignatureScheme::RsaPkcs1Sha256,
    ];
    tls.min_version = version;
    tls.max_version = version;
    if version == TlsVersion::Tls13 {
        tls.cipher_suites = vec![CipherSuite::Aes128GcmSha256];
        tls.key_shares = vec![NamedGroup::X25519];
    }
    tls
}

fn client(
    server: &TestIdentity,
    tls: TlsSettings,
    certificate: Option<ClientCertificate>,
) -> TestResult<Client> {
    let builder =
        Client::builder(ClientProfile::new(tls)).add_root_certificate_der(server.root_der.clone());
    Ok(match certificate {
        Some(certificate) => builder.client_certificate(certificate),
        None => builder,
    }
    .build()?)
}

/// A TLS acceptor that requires a certificate issued by `client_authority`,
/// or requests none without one.
fn acceptor(server: &TestIdentity, client_authority: Option<&[u8]>) -> TestResult<SslAcceptor> {
    let mut builder = server.acceptor_builder(H1_ALPN)?;
    if let Some(authority) = client_authority {
        builder
            .cert_store_mut()
            .add_cert(X509::from_der(authority)?)?;
        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    }
    Ok(builder.build())
}

/// Serves one HTTP/1.1 request over TLS and returns the client certificate
/// the handshake received, if any.
async fn serve_one(listener: TcpListener, acceptor: SslAcceptor) -> TestResult<Option<Vec<u8>>> {
    let mut stream = accept_tls(listener, acceptor).await?;
    let presented = stream
        .ssl()
        .peer_certificate()
        .map(|certificate| certificate.to_der())
        .transpose()?;
    read_head(&mut stream).await?;
    stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await?;
    Ok(presented)
}

async fn get(client: &Client, url: String) -> Result<StatusCode, RequestError> {
    Ok(client
        .get(HttpProtocol::Http1, &url)?
        .send()
        .await?
        .status())
}

#[tokio::test]
async fn requested_certificate_is_presented_over_tls_1_2_and_1_3() -> TestResult<()> {
    let server = TestIdentity::generate()?;
    for (version, identity) in [
        (TlsVersion::Tls12, ClientIdentity::p256()?),
        (TlsVersion::Tls12, ClientIdentity::rsa()?),
        (TlsVersion::Tls13, ClientIdentity::p256()?),
        (TlsVersion::Tls13, ClientIdentity::rsa()?),
    ] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = acceptor(&server, Some(&identity.authority_der))?;
        let client = client(&server, tls(version), Some(identity.certificate()?))?;

        let (presented, status) = timeout(TEST_TIMEOUT, async {
            tokio::join!(
                serve_one(listener, acceptor),
                get(&client, format!("https://{address}/"))
            )
        })
        .await?;

        assert_eq!(status?, StatusCode::NO_CONTENT, "{version:?}");
        assert_eq!(presented?, Some(identity.leaf_der), "{version:?}");
    }
    Ok(())
}

#[tokio::test]
async fn certificate_is_not_sent_unless_the_server_requests_it() -> TestResult<()> {
    let server = TestIdentity::generate()?;
    let identity = ClientIdentity::p256()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let client = client(
        &server,
        tls(TlsVersion::Tls13),
        Some(identity.certificate()?),
    )?;

    let acceptor = acceptor(&server, None)?;

    let (presented, status) = timeout(TEST_TIMEOUT, async {
        tokio::join!(
            serve_one(listener, acceptor),
            get(&client, format!("https://{address}/"))
        )
    })
    .await?;

    assert_eq!(status?, StatusCode::NO_CONTENT);
    assert_eq!(presented?, None);
    Ok(())
}

#[tokio::test]
async fn server_that_requires_a_certificate_rejects_a_client_without_one() -> TestResult<()> {
    let server = TestIdentity::generate()?;
    let identity = ClientIdentity::p256()?;
    // A TLS 1.2 client learns of the rejection during its handshake. A TLS
    // 1.3 client finishes its handshake first, so the server's alert can
    // arrive only when the client reads the response.
    for (version, expected) in [
        (TlsVersion::Tls12, [RequestErrorKind::Tls; 2]),
        (
            TlsVersion::Tls13,
            [RequestErrorKind::Tls, RequestErrorKind::Http1],
        ),
    ] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = acceptor(&server, Some(&identity.authority_der))?;
        let client = client(&server, tls(version), None)?;

        let (served, status) = timeout(TEST_TIMEOUT, async {
            tokio::join!(
                serve_one(listener, acceptor),
                get(&client, format!("https://{address}/"))
            )
        })
        .await?;

        assert!(served.is_err(), "{version:?}");
        let error = status
            .err()
            .ok_or("the server accepted a client without a certificate")?;
        assert!(expected.contains(&error.kind()), "{version:?}: {error}");
    }
    Ok(())
}

#[tokio::test]
async fn certificate_leaves_the_client_hello_unchanged() -> TestResult<()> {
    let server = TestIdentity::generate()?;
    let identity = ClientIdentity::p256()?;
    let mut summaries = Vec::new();
    for certificate in [None, Some(identity.certificate()?)] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let client = client(&server, tls(TlsVersion::Tls13), certificate)?;
        let capture = async {
            let (mut stream, _) = listener.accept().await?;
            let capture = capture_client_hello(
                &mut stream,
                tokio::time::Instant::now() + TEST_TIMEOUT,
                CaptureLimits::new(64 * 1024, 64 * 1024, 8),
            )
            .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                ClientHelloSummary::from_handshake_bytes(capture.handshake_bytes())?,
            )
        };

        let (summary, _) = timeout(TEST_TIMEOUT, async {
            tokio::join!(capture, get(&client, format!("https://{address}/")))
        })
        .await?;
        summaries.push(summary?);
    }

    assert_eq!(summaries[0], summaries[1]);
    Ok(())
}

#[test]
fn key_of_another_certificate_is_a_key_mismatch() -> TestResult<()> {
    let identity = ClientIdentity::p256()?;
    let other = ClientIdentity::p256()?;

    let error =
        ClientCertificate::from_pem(identity.chain_pem.as_bytes(), other.key_pem.as_bytes())
            .err()
            .ok_or("a foreign key was accepted")?;

    assert_eq!(error.kind(), ClientCertificateErrorKind::KeyMismatch);
    Ok(())
}

#[test]
fn der_and_pem_forms_are_parsed_alike() -> TestResult<()> {
    let identity = ClientIdentity::p256()?;
    let key = PKey::private_key_from_pem(identity.key_pem.as_bytes())?;
    let key_der = key.private_key_to_der()?;
    let other_key_der = PKey::private_key_from_pem(ClientIdentity::p256()?.key_pem.as_bytes())?
        .private_key_to_der()?;

    ClientCertificate::from_der([identity.leaf_der.as_slice()], &key_der)?;
    let error = ClientCertificate::from_der([identity.leaf_der.as_slice()], &other_key_der)
        .err()
        .ok_or("a foreign DER key was accepted")?;

    assert_eq!(error.kind(), ClientCertificateErrorKind::KeyMismatch);
    Ok(())
}

#[test]
fn malformed_input_names_the_part_that_failed() -> TestResult<()> {
    let identity = ClientIdentity::p256()?;
    let cases = [
        (
            ClientCertificate::from_pem(b"", identity.key_pem.as_bytes()),
            ClientCertificateErrorKind::Certificate,
        ),
        (
            ClientCertificate::from_pem(b"not pem", identity.key_pem.as_bytes()),
            ClientCertificateErrorKind::Certificate,
        ),
        (
            ClientCertificate::from_pem(identity.chain_pem.as_bytes(), b"not a key"),
            ClientCertificateErrorKind::PrivateKey,
        ),
        (
            ClientCertificate::from_der([], b""),
            ClientCertificateErrorKind::PrivateKey,
        ),
        (
            ClientCertificate::from_der([&b"not der"[..]], b""),
            ClientCertificateErrorKind::Certificate,
        ),
    ];
    for (result, kind) in cases {
        assert_eq!(result.err().map(|error| error.kind()), Some(kind));
    }
    Ok(())
}

#[test]
fn profile_that_cannot_sign_with_the_key_is_an_invalid_policy() -> TestResult<()> {
    let server = TestIdentity::generate()?;
    let mut rsa_only = tls(TlsVersion::Tls13);
    rsa_only.signature_schemes = vec![SignatureScheme::RsaPssRsaeSha256];
    for (tls, identity) in [
        (rsa_only, ClientIdentity::p256()?),
        (
            tls(TlsVersion::Tls13),
            ClientIdentity::issue(KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)?)?,
        ),
    ] {
        let error = client(&server, tls, Some(identity.certificate()?))
            .err()
            .ok_or("a profile without a usable signature scheme was accepted")?;
        let error = error
            .downcast_ref::<phantom::BuildError>()
            .ok_or("the client failed with another error")?;
        assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);
    }
    Ok(())
}

/// A QUIC endpoint that requires a certificate issued by `client_authority`.
fn quic_endpoint_requiring(
    server: &TestIdentity,
    client_authority: &[u8],
) -> TestResult<(std::net::SocketAddr, quinn::Endpoint)> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(client_authority.to_vec()))?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
    let mut tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from(server.leaf_der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server.private_key_der().to_vec())),
        )?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?;
    Ok((endpoint.local_addr()?, endpoint))
}

/// Answers one HTTP/3 request and returns the client certificate the
/// connection received.
async fn serve_one_http3(
    endpoint: &quinn::Endpoint,
    done: oneshot::Receiver<()>,
) -> TestResult<Option<Vec<u8>>> {
    let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
    let connection = incoming.await?;
    let presented = connection
        .peer_identity()
        .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
        .and_then(|chain| chain.first().map(|certificate| certificate.to_vec()));
    let mut connection =
        h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection)).await?;
    let resolver = connection
        .accept()
        .await?
        .ok_or("client closed before sending a request")?;
    let (_, mut stream) = resolver.resolve_request().await?;
    stream
        .send_response(
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(())?,
        )
        .await?;
    stream.finish().await?;
    let _ = done.await;
    Ok(presented)
}

fn http3_client(
    server: &TestIdentity,
    certificate: Option<ClientCertificate>,
) -> TestResult<Client> {
    let builder = Client::builder(
        ClientProfile::new(tls_settings()).with_http3(h3_support::client_settings()),
    )
    .add_root_certificate_der(server.root_der.clone());
    Ok(match certificate {
        Some(certificate) => builder.client_certificate(certificate),
        None => builder,
    }
    .build()?)
}

#[tokio::test]
async fn requested_certificate_is_presented_over_quic() -> TestResult<()> {
    let server = TestIdentity::generate()?;
    let identity = ClientIdentity::p256()?;
    let (address, endpoint) = quic_endpoint_requiring(&server, &identity.authority_der)?;
    let client = http3_client(&server, Some(identity.certificate()?))?;

    let (done, done_received) = oneshot::channel();

    let (presented, status) = timeout(TEST_TIMEOUT, async {
        tokio::join!(serve_one_http3(&endpoint, done_received), async {
            let status = client
                .get(HttpProtocol::Http3, &format!("https://{address}/"))?
                .send()
                .await?
                .status();
            let _ = done.send(());
            Ok::<_, RequestError>(status)
        })
    })
    .await?;

    assert_eq!(status?, StatusCode::NO_CONTENT);
    assert_eq!(presented?, Some(identity.leaf_der));
    Ok(())
}

#[tokio::test]
async fn quic_server_that_requires_a_certificate_rejects_a_client_without_one() -> TestResult<()> {
    let server = TestIdentity::generate()?;
    let identity = ClientIdentity::p256()?;
    let (address, endpoint) = quic_endpoint_requiring(&server, &identity.authority_der)?;
    let client = http3_client(&server, None)?;

    let (_done, done_received) = oneshot::channel();

    let (_, result) = timeout(TEST_TIMEOUT, async {
        tokio::join!(serve_one_http3(&endpoint, done_received), async {
            client
                .get(HttpProtocol::Http3, &format!("https://{address}/"))?
                .send()
                .await
        })
    })
    .await?;

    let error = result
        .err()
        .ok_or("the QUIC server accepted a client without a certificate")?;
    assert!(
        matches!(
            error.kind(),
            RequestErrorKind::Tls | RequestErrorKind::Http3
        ),
        "{error}"
    );
    Ok(())
}
