//! A client certificate answers a server's request for client authentication.

use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use btls::{
    pkey::{Id, PKey},
    ssl::{SslAcceptor, SslVerifyMode},
    x509::X509,
};
use bytes::Bytes;
use http::{Response, StatusCode};
use phantom::{
    BuildErrorKind, Client, ClientCertificate, ClientCertificateErrorKind, HttpProtocol, HttpProxy,
    RequestError, RequestErrorKind, Route,
    profile::{
        CipherSuite, ClientProfile, Http3ClientSettings, NamedGroup, SignatureScheme, TlsSettings,
        TlsVersion, chromium,
    },
};
use phantom_quic_btls::{QuicServerConfig, ServerHandshakeData};
use phantom_testkit::tls::{CaptureLimits, ClientHelloSummary, capture_client_hello, is_grease};
use rcgen::{KeyPair, PKCS_ECDSA_P384_SHA384, PKCS_ED25519};
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::oneshot, time::timeout};

use crate::support::{
    client_certificate::{ClientIdentity, presented_leaf, quic_endpoint_requiring},
    h3 as h3_support, tls as tls_support,
    tunnel_proxy::https1_connect_recording_client_certificate,
};
use tls_support::{H1_ALPN, TestIdentity, TestResult, accept_tls, read_head, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
/// The `quic_transport_parameters` extension type (RFC 9001).
const QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039;
/// The `encrypted_client_hello` extension type (RFC 9849).
const ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

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
async fn https_proxy_that_requests_a_certificate_never_receives_it() -> TestResult<()> {
    let origin = TestIdentity::generate()?;
    let proxy = TestIdentity::generate()?;
    let identity = ClientIdentity::p256()?;
    let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let origin_address = origin_listener.local_addr()?;
    let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy_address = proxy_listener.local_addr()?;
    // The proxy sends a CertificateRequest and accepts whatever comes back.
    let mut proxy_acceptor = proxy.acceptor_builder(H1_ALPN)?;
    proxy_acceptor.set_verify_callback(SslVerifyMode::PEER, |_, _| true);
    let proxy_task = tokio::spawn(https1_connect_recording_client_certificate(
        proxy_listener,
        proxy_acceptor.build(),
        origin_address,
    ));
    let origin_acceptor = acceptor(&origin, Some(&identity.authority_der))?;
    let client = Client::builder(ClientProfile::new(tls(TlsVersion::Tls13)))
        .add_root_certificate_der(origin.root_der.clone())
        .add_proxy_root_certificate_der(proxy.root_der.clone())
        .route(Route::http_connect(HttpProxy::new(&format!(
            "https://{proxy_address}"
        ))?))
        .client_certificate(identity.certificate()?)
        .build()?;

    let (presented_to_origin, status) = timeout(TEST_TIMEOUT, async {
        tokio::join!(
            serve_one(origin_listener, origin_acceptor),
            get(&client, format!("https://{origin_address}/"))
        )
    })
    .await?;

    assert_eq!(status?, StatusCode::NO_CONTENT);
    assert_eq!(presented_to_origin?, Some(identity.leaf_der));
    assert_eq!(timeout(TEST_TIMEOUT, proxy_task).await???, None);
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

/// The ClientHello fields that stay fixed across connections of one
/// profile: GREASE values are dropped and extensions sorted by type, because
/// the Chromium recipes draw GREASE and permute extensions per connection.
/// Every extension keeps its payload length except those `HelloShape::of`
/// is told vary per connection. The QUIC transport parameters are decoded
/// and sorted by identifier, because the Chromium recipe permutes them per
/// connection, less GREASE parameters, GREASE versions, and the random
/// `initial_source_connection_id`.
#[derive(Debug, Eq, PartialEq)]
struct HelloShape {
    legacy_version: u16,
    cipher_suites: Vec<u16>,
    extension_layout: Vec<(u16, usize)>,
    groups: Vec<u16>,
    ec_point_formats: Vec<u8>,
    signature_algorithms: Vec<u16>,
    versions: Vec<u16>,
    key_share_groups: Vec<u16>,
    alpn: Vec<Vec<u8>>,
    server_name: Option<Vec<u8>>,
    requested_trust_anchor_ids: Option<Vec<Vec<u8>>>,
    transport_parameters: Option<Vec<(u64, Vec<u8>)>>,
}

impl HelloShape {
    /// Summarizes `handshake`, recording a zero length for each extension
    /// type in `varying_lengths`.
    fn of(handshake: &[u8], varying_lengths: &[u16]) -> TestResult<Self> {
        let hello = ClientHelloSummary::from_handshake_bytes(handshake)?;
        let kept = |values: &[u16]| {
            values
                .iter()
                .copied()
                .filter(|value| !is_grease(*value))
                .collect::<Vec<_>>()
        };
        let mut extension_layout = hello
            .extension_layout()
            .filter(|(extension, _)| !is_grease(*extension))
            .map(|(extension, length)| {
                if varying_lengths.contains(&extension) {
                    (extension, 0)
                } else {
                    (extension, length)
                }
            })
            .collect::<Vec<_>>();
        extension_layout.sort_unstable();
        Ok(Self {
            legacy_version: hello.legacy_version(),
            cipher_suites: kept(hello.cipher_suites()),
            extension_layout,
            groups: kept(hello.supported_groups()),
            ec_point_formats: hello.ec_point_formats().to_vec(),
            signature_algorithms: kept(hello.signature_algorithms()),
            versions: kept(hello.supported_versions()),
            key_share_groups: kept(hello.key_share_groups()),
            alpn: hello.alpn_protocols().to_vec(),
            server_name: hello.server_name().map(<[u8]>::to_vec),
            requested_trust_anchor_ids: hello.requested_trust_anchor_ids().map(<[_]>::to_vec),
            transport_parameters: extension_payload(handshake, QUIC_TRANSPORT_PARAMETERS)
                .map(fixed_transport_parameters)
                .transpose()?,
        })
    }
}

/// Returns the payload of the first `extension` in a ClientHello handshake
/// message.
fn extension_payload(handshake: &[u8], extension: u16) -> Option<&[u8]> {
    let u16_at = |offset: usize| -> Option<usize> {
        Some(usize::from(u16::from_be_bytes([
            *handshake.get(offset)?,
            *handshake.get(offset + 1)?,
        ])))
    };
    // Message type and length, legacy_version, and random.
    let mut offset = 4 + 2 + 32;
    offset += 1 + usize::from(*handshake.get(offset)?);
    offset += 2 + u16_at(offset)?;
    offset += 1 + usize::from(*handshake.get(offset)?);
    let end = offset + 2 + u16_at(offset)?;
    offset += 2;
    while offset < end {
        let kind = u16::try_from(u16_at(offset)?).ok()?;
        let length = u16_at(offset + 2)?;
        let payload = handshake.get(offset + 4..offset + 4 + length)?;
        if kind == extension {
            return Some(payload);
        }
        offset += 4 + length;
    }
    None
}

/// Decodes QUIC transport parameters (RFC 9000, section 18) and sorts them
/// by identifier, dropping reserved (GREASE) identifiers,
/// `initial_source_connection_id`, and the reserved versions in
/// `version_information` (RFC 9368), all of which are random per connection.
fn fixed_transport_parameters(mut encoded: &[u8]) -> TestResult<Vec<(u64, Vec<u8>)>> {
    const INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;
    const VERSION_INFORMATION: u64 = 0x11;
    let mut parameters = Vec::new();
    while !encoded.is_empty() {
        let (id, id_length) = decode_varint(encoded).ok_or("truncated parameter id")?;
        encoded = &encoded[id_length..];
        let (length, length_length) = decode_varint(encoded).ok_or("truncated parameter length")?;
        encoded = &encoded[length_length..];
        let length = usize::try_from(length)?;
        let value = encoded.get(..length).ok_or("truncated parameter value")?;
        let reserved = id >= 27 && (id - 27).is_multiple_of(31);
        if id == VERSION_INFORMATION {
            let versions = value
                .as_chunks::<4>()
                .0
                .iter()
                .filter(|version| u32::from_be_bytes(**version) & 0x0f0f_0f0f != 0x0a0a_0a0a)
                .flatten()
                .copied()
                .collect();
            parameters.push((id, versions));
        } else if !reserved && id != INITIAL_SOURCE_CONNECTION_ID {
            parameters.push((id, value.to_vec()));
        }
        encoded = &encoded[length..];
    }
    parameters.sort_unstable();
    Ok(parameters)
}

fn decode_varint(encoded: &[u8]) -> Option<(u64, usize)> {
    let first = *encoded.first()?;
    let length = 1_usize << (first >> 6);
    let rest = encoded.get(1..length)?;
    let value = rest.iter().fold(u64::from(first & 0x3f), |value, byte| {
        (value << 8) | u64::from(*byte)
    });
    Some((value, length))
}

#[tokio::test]
async fn certificate_leaves_the_chromium_client_hello_unchanged() -> TestResult<()> {
    let server = TestIdentity::generate()?;
    let identity = ClientIdentity::p256()?;
    let mut shapes = Vec::new();
    for certificate in [None, Some(identity.certificate()?)] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let client = client(&server, chromium::v154_tls(), certificate)?;
        let capture = async {
            let (mut stream, _) = listener.accept().await?;
            let capture = capture_client_hello(
                &mut stream,
                tokio::time::Instant::now() + TEST_TIMEOUT,
                CaptureLimits::new(64 * 1024, 64 * 1024, 8),
            )
            .await?;
            // BoringSSL draws the GREASE ECH payload length per connection.
            HelloShape::of(capture.handshake_bytes(), &[ENCRYPTED_CLIENT_HELLO])
        };

        let (shape, _) = timeout(TEST_TIMEOUT, async {
            tokio::join!(capture, get(&client, format!("https://{address}/")))
        })
        .await?;
        shapes.push(shape?);
    }

    assert_eq!(shapes[0], shapes[1]);
    Ok(())
}

#[tokio::test]
async fn certificate_leaves_the_chromium_quic_client_hello_unchanged() -> TestResult<()> {
    let server = TestIdentity::generate()?;
    let identity = ClientIdentity::p256()?;
    let context = server.acceptor(b"\x02h3")?.context().to_owned();
    let mut shapes = Vec::new();
    for certificate in [None, Some(identity.certificate()?)] {
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::new(context.clone()))),
            (Ipv4Addr::LOCALHOST, 0).into(),
        )?;
        let address = endpoint.local_addr()?;
        let builder = Client::builder(ClientProfile::new(chromium::v154_tls()).with_http3(
            Http3ClientSettings::new(
                chromium::v154_http3_tls(),
                chromium::v154_quic(),
                chromium::v154_http3(),
                chromium::v154_http3_request(),
            ),
        ))
        .add_root_certificate_der(server.root_der.clone());
        let client = match certificate {
            Some(certificate) => builder.client_certificate(certificate),
            None => builder,
        }
        .build()?;
        let capture = async {
            let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
            let mut connecting = incoming.accept()?;
            let data = connecting
                .handshake_data()
                .await?
                .downcast::<ServerHandshakeData>()
                .map_err(|_| "unexpected server handshake data")?;
            // BoringSSL draws the GREASE ECH payload length per connection,
            // and Chromium's QUIC transport parameters carry a GREASE
            // parameter of random length, so the extension's length varies;
            // its decoded parameters are compared instead.
            HelloShape::of(
                data.client_hello(),
                &[QUIC_TRANSPORT_PARAMETERS, ENCRYPTED_CLIENT_HELLO],
            )
        };
        let request = async {
            let _ = client
                .get(HttpProtocol::Http3, &format!("https://{address}/"))?
                .send()
                .await;
            Ok::<_, RequestError>(())
        };

        let (shape, _) = timeout(TEST_TIMEOUT, async {
            tokio::select! {
                shape = capture => (shape, Ok(())),
                sent = request => (Err("the request ended before the capture".into()), sent),
            }
        })
        .await?;
        shapes.push(shape?);
    }

    assert_eq!(shapes[0], shapes[1]);
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
fn der_chain_parses_and_a_foreign_der_key_is_a_key_mismatch() -> TestResult<()> {
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

#[test]
fn ed25519_key_parses_but_build_rejects_it_as_an_invalid_policy() -> TestResult<()> {
    let server = TestIdentity::generate()?;
    // This pins the PKCS #8 v1 path, the form BoringSSL writes. A v2 key,
    // the form rcgen generates, fails earlier, with kind PrivateKey.
    let key = PKey::generate(Id::ED25519)?;
    let key_der = key.private_key_to_der_pkcs8()?;
    let identity = ClientIdentity::issue(KeyPair::from_pem(&String::from_utf8(
        key.private_key_to_pem_pkcs8()?,
    )?)?)?;

    ClientCertificate::from_der([identity.leaf_der.as_slice()], &key_der)?;
    let error = client(
        &server,
        tls(TlsVersion::Tls13),
        Some(identity.certificate()?),
    )
    .err()
    .ok_or("a profile without an Ed25519 signature scheme was accepted")?;
    let error = error
        .downcast_ref::<phantom::BuildError>()
        .ok_or("the client failed with another error")?;

    assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);
    Ok(())
}

#[test]
fn pkcs8_v2_ed25519_key_is_a_private_key_error() -> TestResult<()> {
    // rcgen, like ring and aws-lc-rs, writes a PKCS #8 v2 Ed25519 key, with
    // its public key; BoringSSL reads only version 0 of PrivateKeyInfo.
    let key = KeyPair::generate_for(&PKCS_ED25519)?;
    let key_der = key.serialize_der();
    let key_pem = key.serialize_pem();
    let identity = ClientIdentity::issue(key)?;

    for result in [
        ClientCertificate::from_pem(identity.chain_pem.as_bytes(), key_pem.as_bytes()),
        ClientCertificate::from_der([identity.leaf_der.as_slice()], &key_der),
    ] {
        let error = result.err().ok_or("a PKCS #8 v2 Ed25519 key parsed")?;
        assert_eq!(error.kind(), ClientCertificateErrorKind::PrivateKey);
    }
    Ok(())
}

/// Answers one HTTP/3 request and returns the client certificate the
/// connection received.
async fn serve_one_http3(
    endpoint: &quinn::Endpoint,
    done: oneshot::Receiver<()>,
) -> TestResult<Option<Vec<u8>>> {
    let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
    let connection = incoming.await?;
    let presented = presented_leaf(&connection);
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
