use std::{error::Error, net::SocketAddr, pin::Pin, time::Duration};

use btls::{
    pkey::PKey,
    ssl::{
        AlpnError, NameType, Ssl, SslAcceptor, SslAcceptorBuilder, SslMethod, select_next_proto,
    },
    x509::X509,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_btls::SslStream as BoringStream;

use super::{TlsConnector, TlsError, TlsStream};

pub(crate) const TEST_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const TEST_SERVER_NAME: &str = "server.phantom.test";
pub(crate) const H2_ALPN_WIRE: &[u8] = b"\x02h2";

const HTTP1_ALPN_WIRE: &[u8] = b"\x08http/1.1";

pub(crate) type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

pub(crate) struct TestIdentity {
    root_der: Vec<u8>,
    leaf_der: Vec<u8>,
    private_key_der: Vec<u8>,
}

impl TestIdentity {
    pub(crate) fn generate() -> TestResult<Self> {
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

    pub(crate) fn root_der(&self) -> &[u8] {
        &self.root_der
    }

    pub(crate) fn acceptor_builder(&self) -> TestResult<SslAcceptorBuilder> {
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        let leaf = X509::from_der(&self.leaf_der)?;
        let private_key = PKey::private_key_from_pkcs8(&self.private_key_der)?;
        acceptor.set_certificate(&leaf)?;
        acceptor.set_private_key(&private_key)?;
        acceptor.add_extra_chain_cert(X509::from_der(&self.root_der)?)?;
        acceptor.check_private_key()?;
        Ok(acceptor)
    }

    pub(crate) fn acceptor(&self, alpn: TestServerAlpn) -> TestResult<SslAcceptor> {
        let mut acceptor = self.acceptor_builder()?;
        match alpn {
            TestServerAlpn::None => {}
            TestServerAlpn::Http1 => acceptor.set_alpn_select_callback(|_, offered| {
                select_next_proto(HTTP1_ALPN_WIRE, offered).ok_or(AlpnError::NOACK)
            }),
            TestServerAlpn::H2 => acceptor.set_alpn_select_callback(|_, offered| {
                select_next_proto(H2_ALPN_WIRE, offered).ok_or(AlpnError::NOACK)
            }),
        }
        Ok(acceptor.build())
    }
}

#[derive(Clone, Copy)]
pub(crate) enum TestServerAlpn {
    None,
    Http1,
    H2,
}

pub(crate) async fn loopback_listener() -> TestResult<(SocketAddr, TcpListener)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    Ok((listener.local_addr()?, listener))
}

pub(crate) async fn accept_tls(
    listener: TcpListener,
    acceptor: SslAcceptor,
) -> TestResult<(BoringStream<TcpStream>, Option<String>)> {
    let (tcp, _) = listener.accept().await?;
    let ssl = Ssl::new(acceptor.context())?;
    let mut stream = BoringStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    let sni = stream
        .ssl()
        .servername(NameType::HOST_NAME)
        .map(str::to_owned);
    Ok((stream, sni))
}

pub(crate) async fn connect_local(
    connector: &TlsConnector,
    address: SocketAddr,
    server_name: &str,
) -> TestResult<Result<TlsStream<TcpStream>, TlsError>> {
    let tcp = tokio::time::timeout(TEST_TIMEOUT, TcpStream::connect(address)).await??;
    Ok(tokio::time::timeout(TEST_TIMEOUT, connector.connect(server_name, tcp)).await?)
}
