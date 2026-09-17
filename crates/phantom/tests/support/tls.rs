use std::{error::Error, net::Ipv4Addr, pin::Pin};

use btls::{
    pkey::PKey,
    ssl::{AlpnError, Ssl, SslAcceptor, SslAcceptorBuilder, SslMethod, select_next_proto},
    x509::X509,
};
use phantom::{
    Client, ClientBuilder,
    profile::{
        CipherSuite, ClientHelloExtensionOrder, ClientProfile, NamedGroup, SignatureScheme,
        TlsSettings, TlsVersion, chromium,
    },
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::{TcpListener, TcpStream},
};
use tokio_btls::SslStream;

pub(crate) const H1_ALPN: &[u8] = b"\x08http/1.1";
pub(crate) const H2_ALPN: &[u8] = b"\x02h2";

pub(crate) type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

pub(crate) fn client_builder(identity: &TestIdentity, http2: bool) -> ClientBuilder {
    let mut tls = tls_settings();
    if !http2 {
        tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    }
    let mut profile = ClientProfile::new(tls);
    if http2 {
        profile = profile.with_http2(chromium::v152_macos_http2());
    }
    Client::builder(profile).add_root_certificate_der(identity.root_der.clone())
}

pub(crate) fn test_client(identity: &TestIdentity, http2: bool) -> TestResult<Client> {
    Ok(client_builder(identity, http2).build()?)
}

pub(crate) fn tls_settings() -> TlsSettings {
    TlsSettings {
        min_version: TlsVersion::Tls12,
        max_version: TlsVersion::Tls12,
        cipher_suites: vec![CipherSuite::EcdheEcdsaAes128GcmSha256],
        groups: vec![NamedGroup::X25519, NamedGroup::Secp256r1],
        key_shares: Vec::new(),
        signature_schemes: vec![SignatureScheme::EcdsaSecp256r1Sha256],
        delegated_credential_schemes: Vec::new(),
        alpn_protocols: vec![Box::from(&b"h2"[..]), Box::from(&b"http/1.1"[..])],
        alps: None,
        certificate_compression: Vec::new(),
        session_tickets: true,
        record_size_limit: None,
        requested_trust_anchor_ids: None,
        grease: false,
        grease_signature_algorithms: false,
        extension_order: ClientHelloExtensionOrder::BackendDefault,
        ech_grease: false,
        ech_grease_payload_length: None,
        request_ocsp_staple: false,
        request_signed_certificate_timestamps: false,
        aes_hardware: true,
    }
}

pub(crate) async fn read_head(stream: &mut (impl AsyncRead + Unpin)) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() == 32 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request head exceeded test bound",
            ));
        }
        stream.read_exact(&mut byte).await?;
        bytes.push(byte[0]);
    }
    Ok(bytes)
}

pub(crate) async fn accept_tls(
    listener: TcpListener,
    acceptor: SslAcceptor,
) -> TestResult<SslStream<TcpStream>> {
    let (tcp, _) = listener.accept().await?;
    let ssl = Ssl::new(acceptor.context())?;
    let mut stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
}

pub(crate) struct TestIdentity {
    pub(crate) root_der: Vec<u8>,
    leaf_der: Vec<u8>,
    private_key_der: Vec<u8>,
}

impl TestIdentity {
    pub(crate) fn generate() -> TestResult<Self> {
        Self::generate_with_san(SanType::IpAddress(std::net::IpAddr::V4(
            Ipv4Addr::LOCALHOST,
        )))
    }

    pub(crate) fn generate_for_dns(name: &str) -> TestResult<Self> {
        Self::generate_with_san(SanType::DnsName(name.try_into()?))
    }

    fn generate_with_san(subject_alt_name: SanType) -> TestResult<Self> {
        let mut root_params = CertificateParams::new(Vec::<String>::new())?;
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let root = CertifiedIssuer::self_signed(root_params, KeyPair::generate()?)?;

        let mut leaf_params = CertificateParams::new(Vec::<String>::new())?;
        leaf_params.subject_alt_names.push(subject_alt_name);
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

    pub(crate) fn acceptor(&self, alpn: &'static [u8]) -> TestResult<SslAcceptor> {
        Ok(self.acceptor_builder(alpn)?.build())
    }

    pub(crate) fn acceptor_builder(&self, alpn: &'static [u8]) -> TestResult<SslAcceptorBuilder> {
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        let certificate = X509::from_der(self.leaf_der())?;
        let private_key = PKey::private_key_from_pkcs8(self.private_key_der())?;
        acceptor.set_certificate(&certificate)?;
        acceptor.set_private_key(&private_key)?;
        acceptor.add_extra_chain_cert(X509::from_der(&self.root_der)?)?;
        acceptor.check_private_key()?;
        acceptor.set_alpn_select_callback(move |_, offered| {
            select_next_proto(alpn, offered).ok_or(AlpnError::NOACK)
        });
        Ok(acceptor)
    }

    pub(crate) fn leaf_der(&self) -> &[u8] {
        &self.leaf_der
    }

    pub(crate) fn private_key_der(&self) -> &[u8] {
        &self.private_key_der
    }
}
