use std::{net::SocketAddr, sync::Arc};

use bytes::Bytes;
use http::Request;
use phantom::profile::{
    CipherSuite, ClientHelloExtensionOrder, Http3ClientSettings, NamedGroup, SignatureScheme,
    TlsSettings, TlsVersion, chromium,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::tls_support::{TestIdentity, TestResult};

pub(crate) fn client_settings() -> Http3ClientSettings {
    Http3ClientSettings::new(
        tls_settings(),
        chromium::v154_quic(),
        chromium::v154_http3(),
        chromium::v154_http3_request(),
    )
}

fn tls_settings() -> TlsSettings {
    TlsSettings {
        min_version: TlsVersion::Tls13,
        max_version: TlsVersion::Tls13,
        cipher_suites: vec![CipherSuite::Aes128GcmSha256],
        groups: vec![NamedGroup::X25519],
        key_shares: vec![NamedGroup::X25519],
        signature_schemes: vec![SignatureScheme::EcdsaSecp256r1Sha256],
        delegated_credential_schemes: Vec::new(),
        alpn_protocols: vec![Box::from(&b"h3"[..])],
        alps: None,
        certificate_compression: Vec::new(),
        session_tickets: false,
        record_size_limit: None,
        requested_trust_anchor_ids: None,
        grease: false,
        grease_signature_algorithms: false,
        extension_order: ClientHelloExtensionOrder::BackendDefault,
        ech_grease: false,
        ech_grease_payload_length: None,
        ech_grease_aeads: Vec::new(),
        request_ocsp_staple: false,
        request_signed_certificate_timestamps: false,
        aes_hardware: true,
    }
}

pub(crate) fn server_endpoint(
    identity: &TestIdentity,
) -> TestResult<(SocketAddr, quinn::Endpoint)> {
    let certificate = CertificateDer::from(identity.leaf_der().to_vec());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        identity.private_key_der().to_vec(),
    ));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        "127.0.0.1:0".parse()?,
    )?;
    Ok((endpoint.local_addr()?, endpoint))
}

pub(crate) async fn accept_request(
    endpoint: &quinn::Endpoint,
) -> TestResult<(
    Request<()>,
    h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    h3::server::Connection<h3_quinn::Connection, Bytes>,
)> {
    let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
    let connection = incoming.await?;
    let mut connection = h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?;
    let resolver = connection
        .accept()
        .await?
        .ok_or("client closed before sending a request")?;
    let (request, stream) = resolver.resolve_request().await?;
    Ok((request, stream, connection))
}
