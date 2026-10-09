use std::{net::SocketAddr, sync::Arc};

use bytes::Bytes;
use http::Request;
use phantom::profile::{
    CipherSuite, ClientHelloExtensionOrder, Http3AltUsed, Http3ClientSettings, NamedGroup,
    SessionTicketOrder, SignatureScheme, TlsSettings, TlsVersion, browser::chrome,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::support::tls::{TestIdentity, TestResult};

pub(crate) fn client_settings() -> Http3ClientSettings {
    Http3ClientSettings::new(
        client_tls_settings(),
        chrome::v154_quic(),
        chrome::v154_http3(),
        chrome::v154_http3_request(),
    )
}

/// Returns `settings` with a request profile that appends `Alt-Used` to a
/// request sent to an alternative service, as the Firefox 157 recipe does
/// and the Chromium recipe of [`client_settings`] does not.
pub(crate) fn appending_alt_used(settings: Http3ClientSettings) -> Http3ClientSettings {
    let mut request = settings.request().clone();
    request.alt_used = Http3AltUsed::Append;
    Http3ClientSettings::new(
        settings.tls().clone(),
        settings.quic_transport().clone(),
        settings.http3().clone(),
        request,
    )
}

/// The TLS settings of [`client_settings`].
pub(crate) fn client_tls_settings() -> TlsSettings {
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
        session_tickets_per_origin: 2,
        session_ticket_order: SessionTicketOrder::NewestFirst,
        session_ticket_extension_when_resuming: true,
        tcp_early_data: false,
        record_size_limit: None,
        tls12_extensions_in_tls13_client_hello: false,
        requested_trust_anchor_ids: None,
        grease: false,
        grease_signature_algorithms: false,
        extension_order: ClientHelloExtensionOrder::BackendDefault,
        ech_grease: false,
        ech_grease_payload_length: phantom::profile::EchGreasePayloadLength::BackendDefault,
        ech_grease_aeads: Vec::new(),
        ech_from_https_records: false,
        request_ocsp_staple: false,
        request_signed_certificate_timestamps: false,
        aes_hardware: true,
        close_notify: true,
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
    let endpoint = quic_server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        "127.0.0.1:0".parse()?,
    )?;
    Ok((endpoint.local_addr()?, endpoint))
}

/// A QUIC endpoint that serves `config` on `local`, as
/// `quinn::Endpoint::server` does, with a bind to port 0 that survives a
/// Windows reserved port block.
pub(crate) fn quic_server(
    config: quinn::ServerConfig,
    local: SocketAddr,
) -> std::io::Result<quinn::Endpoint> {
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(config),
        phantom_testkit::udp::bind(local)?,
        Arc::new(quinn::TokioRuntime),
    )
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
