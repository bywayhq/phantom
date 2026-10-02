use std::{
    error::Error,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

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
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    net::{TcpListener, TcpStream},
};
use tokio_btls::SslStream as BoringStream;

use super::{TlsConnector, TlsError, TlsStream};

pub(crate) mod nss_ech_grease;

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
        Self::generate_for_names(&[TEST_SERVER_NAME])
    }

    pub(crate) fn generate_for_names(names: &[&str]) -> TestResult<Self> {
        let mut root_params = CertificateParams::new(Vec::<String>::new())?;
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let root = CertifiedIssuer::self_signed(root_params, KeyPair::generate()?)?;

        let mut leaf_params = CertificateParams::new(
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )?;
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

    pub(crate) fn leaf_der(&self) -> &[u8] {
        &self.leaf_der
    }

    pub(crate) fn private_key_der(&self) -> &[u8] {
        &self.private_key_der
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

/// One accepted server TLS connection that records the application bytes it
/// read before its handshake completed, which were early data.
pub(crate) struct EarlyDataServerStream {
    inner: BoringStream<TcpStream>,
    early: Arc<Mutex<Vec<u8>>>,
}

impl EarlyDataServerStream {
    /// Returns a handle to the bytes read as early data so far.
    pub(crate) fn early_bytes(&self) -> Arc<Mutex<Vec<u8>>> {
        Arc::clone(&self.early)
    }

    pub(crate) fn early_data_accepted(&self) -> bool {
        self.inner.ssl().early_data_accepted()
    }

    pub(crate) fn session_reused(&self) -> bool {
        self.inner.ssl().session_reused()
    }
}

impl AsyncRead for EarlyDataServerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        // Application data read while the handshake is still in progress can
        // only be early data: 1-RTT data follows the client's Finished.
        if !self.inner.ssl().is_init_finished() {
            self.early
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(&buffer.filled()[before..]);
        }
        result
    }
}

impl AsyncWrite for EarlyDataServerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

/// Accepts one TLS connection that issues tickets permitting early data and
/// accepts early data when `early_data` is set.
///
/// The handshake starts `delay` after the TCP accept, so a client's early
/// data is already on the wire when the server answers its ClientHello.
pub(crate) async fn accept_tls_with_early_data(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
    early_data: bool,
    delay: Duration,
) -> TestResult<EarlyDataServerStream> {
    let (tcp, _) = listener.accept().await?;
    tokio::time::sleep(delay).await;
    let mut ssl = Ssl::new(acceptor.context())?;
    ssl.set_early_data_enabled(early_data);
    let mut stream = BoringStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(EarlyDataServerStream {
        inner: stream,
        early: Arc::default(),
    })
}

pub(crate) async fn connect_local(
    connector: &TlsConnector,
    address: SocketAddr,
    server_name: &str,
) -> TestResult<Result<TlsStream<TcpStream>, TlsError>> {
    let tcp = tokio::time::timeout(TEST_TIMEOUT, TcpStream::connect(address)).await??;
    Ok(tokio::time::timeout(TEST_TIMEOUT, connector.connect(server_name, tcp)).await?)
}

pub(crate) struct TouchCountingStream {
    inner: DuplexStream,
    touches: Arc<AtomicUsize>,
}

impl TouchCountingStream {
    pub(crate) fn new(inner: DuplexStream, touches: Arc<AtomicUsize>) -> Self {
        Self { inner, touches }
    }

    fn touched(&self) {
        self.touches.fetch_add(1, Ordering::SeqCst);
    }
}

impl AsyncRead for TouchCountingStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.touched();
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for TouchCountingStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.touched();
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.touched();
        Pin::new(&mut self.inner).poll_write_vectored(context, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.touched();
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.touched();
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}
