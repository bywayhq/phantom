//! Client certificates from a private authority, and QUIC servers that ask
//! for them.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use btls::{pkey::PKey, rsa::Rsa};
use phantom::ClientCertificate;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
};

use super::h3::quic_server;
use super::tls::{TestIdentity, TestResult};

/// A client certificate issued by a private authority, in the forms a
/// caller and a test server need.
pub(crate) struct ClientIdentity {
    pub(crate) authority_der: Vec<u8>,
    pub(crate) leaf_der: Vec<u8>,
    pub(crate) chain_pem: String,
    pub(crate) key_pem: String,
}

impl ClientIdentity {
    pub(crate) fn issue(key: KeyPair) -> TestResult<Self> {
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

    pub(crate) fn p256() -> TestResult<Self> {
        Self::issue(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?)
    }

    pub(crate) fn rsa() -> TestResult<Self> {
        let key = PKey::from_rsa(Rsa::generate(2048)?)?;
        let pem = String::from_utf8(key.private_key_to_pem_pkcs8()?)?;
        Self::issue(KeyPair::from_pem(&pem)?)
    }

    pub(crate) fn certificate(&self) -> TestResult<ClientCertificate> {
        Ok(ClientCertificate::from_pem(
            self.chain_pem.as_bytes(),
            self.key_pem.as_bytes(),
        )?)
    }
}

/// A rustls server configuration for `server` that asks for a client
/// certificate issued by `client_authority`: required, or optional.
pub(crate) fn rustls_config_requesting(
    server: &TestIdentity,
    client_authority: &[u8],
    required: bool,
) -> TestResult<rustls::ServerConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(client_authority.to_vec()))?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots));
    let verifier = if required {
        verifier.build()?
    } else {
        verifier.allow_unauthenticated().build()?
    };
    let mut tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from(server.leaf_der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server.private_key_der().to_vec())),
        )?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    Ok(tls)
}

/// A loopback QUIC endpoint that requires a certificate issued by
/// `client_authority`.
pub(crate) fn quic_endpoint_requiring(
    server: &TestIdentity,
    client_authority: &[u8],
) -> TestResult<(SocketAddr, quinn::Endpoint)> {
    let tls = rustls_config_requesting(server, client_authority, true)?;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let endpoint = quic_server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?;
    Ok((endpoint.local_addr()?, endpoint))
}

/// Returns the first certificate the client presented on `connection`.
pub(crate) fn presented_leaf(connection: &quinn::Connection) -> Option<Vec<u8>> {
    connection
        .peer_identity()
        .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
        .and_then(|chain| chain.first().map(|certificate| certificate.to_vec()))
}
