use std::{
    error::Error,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use btls::{
    pkey::PKey,
    ssl::{AlpnError, NameType, Ssl, SslAcceptor, SslMethod, select_next_proto},
    x509::X509,
};
use http_body_util::BodyExt;
use phantom_profile::{CipherSuite, NamedGroup, SignatureScheme, TlsSettings, TlsVersion};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream as BoringStream;

use super::{Http1TlsConnector, Http1TlsError};
use crate::http1::{OriginForm, RequestHeader};

type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const TEST_SERVER_NAME: &str = "server.phantom.test";
const HTTP1_ALPN_WIRE: &[u8] = b"\x08http/1.1";
const H2_ALPN_WIRE: &[u8] = b"\x02h2";

async fn bounded_tls_test<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    match timeout(TEST_TIMEOUT, future).await {
        Ok(result) => result,
        Err(_) => Err("HTTP/1-over-TLS test exceeded its absolute deadline".into()),
    }
}

#[tokio::test]
async fn streams_ordered_http1_over_trusted_tls() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = server_acceptor(&identity, ServerAlpn::Http1)?;
        let (release_later, wait_for_release) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            let (mut stream, sni) = accept_tls(listener, acceptor).await?;
            let request = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nfirst")
                .await?;
            stream.flush().await?;
            wait_for_release.await.map_err(io::Error::other)?;
            stream.write_all(b"later").await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((sni, request))
        });

        let connector = test_connector(&identity)?;
        let tcp = TcpStream::connect(address).await?;
        let response = connector
            .send_get(
                tcp,
                TEST_SERVER_NAME,
                OriginForm::parse("/resource?item=1")?,
                vec![
                    RequestHeader::new("Host", TEST_SERVER_NAME),
                    RequestHeader::new("X-First", "one"),
                    RequestHeader::new("x-repeat", "alpha"),
                    RequestHeader::new("X-Repeat", "beta"),
                ],
            )
            .await?;
        assert_eq!(response.status(), 200);

        let mut body = response.into_body();
        let visible = loop {
            let data = body
                .frame()
                .await
                .ok_or("body ended before any data was observable")??
                .into_data()
                .map_err(|_| "expected a data frame")?;
            if !data.is_empty() {
                break data;
            }
        };

        release_later
            .send(())
            .map_err(|_| "server stopped before later body release")?;
        let remaining = body.collect().await?.to_bytes();
        let mut complete = visible.to_vec();
        complete.extend_from_slice(&remaining);
        assert_eq!(complete, b"firstlater");

        let (sni, request) = server_task.await??;
        assert_eq!(sni.as_deref(), Some(TEST_SERVER_NAME));
        assert_eq!(
            request,
            b"GET /resource?item=1 HTTP/1.1\r\nHost: server.phantom.test\r\nX-First: one\r\nx-repeat: alpha\r\nX-Repeat: beta\r\n\r\n"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn rejects_h2_before_writing_http1_bytes() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = server_acceptor(&identity, ServerAlpn::H2)?;
        let server_task = tokio::spawn(async move {
            let (mut stream, sni) = accept_tls(listener, acceptor).await?;
            let mut plaintext = Vec::new();
            if let Err(error) = stream.read_to_end(&mut plaintext).await {
                if !plaintext.is_empty() {
                    return Err(error.into());
                }
            }
            Ok::<_, Box<dyn Error + Send + Sync>>((sni, plaintext))
        });

        let connector = test_connector(&identity)?;
        let tcp = TcpStream::connect(address).await?;
        let result = connector
            .send_get(
                tcp,
                TEST_SERVER_NAME,
                OriginForm::parse("/")?,
                vec![RequestHeader::new("Host", TEST_SERVER_NAME)],
            )
            .await;
        let error = match result {
            Ok(_) => return Err("h2 selection unexpectedly entered HTTP/1".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            Http1TlsError::UnsupportedAlpn { ref selected } if selected.as_ref() == b"h2"
        ));

        let (sni, plaintext) = server_task.await??;
        assert_eq!(sni.as_deref(), Some(TEST_SERVER_NAME));
        assert!(plaintext.is_empty(), "HTTP/1 bytes followed h2 selection");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn no_negotiated_alpn_proceeds_as_http1() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = server_acceptor(&identity, ServerAlpn::None)?;
        let server_task = tokio::spawn(async move {
            let (mut stream, sni) = accept_tls(listener, acceptor).await?;
            let request = read_head(&mut stream).await?;
            stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((sni, request))
        });

        let connector = test_connector(&identity)?;
        let tcp = TcpStream::connect(address).await?;
        let response = connector
            .send_get(
                tcp,
                TEST_SERVER_NAME,
                OriginForm::parse("/health")?,
                vec![RequestHeader::new("Host", TEST_SERVER_NAME)],
            )
            .await?;
        assert_eq!(response.status(), 204);
        assert!(response.into_body().collect().await?.to_bytes().is_empty());

        let (sni, request) = server_task.await??;
        assert_eq!(sni.as_deref(), Some(TEST_SERVER_NAME));
        assert_eq!(
            request,
            b"GET /health HTTP/1.1\r\nHost: server.phantom.test\r\n\r\n"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn invalid_request_never_touches_tls_stream() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let connector = test_connector(&identity)?;
        let touches = Arc::new(AtomicUsize::new(0));
        let (client, _server) = duplex(128);
        let stream = TouchCountingStream {
            inner: client,
            touches: Arc::clone(&touches),
        };

        let result = connector
            .send_get(
                stream,
                TEST_SERVER_NAME,
                OriginForm::parse("/")?,
                Vec::new(),
            )
            .await;
        assert!(matches!(result, Err(Http1TlsError::Http1(_))));
        assert_eq!(touches.load(Ordering::SeqCst), 0);
        Ok(())
    })
    .await
}

#[test]
fn rejects_h2_h3_only_settings_before_stream_io() -> TestResult<()> {
    let mut settings = tls_settings();
    settings.alpn_protocols = vec![Box::from(&b"h2"[..]), Box::from(&b"h3"[..])];

    let bundled_roots_error = match Http1TlsConnector::new(&settings) {
        Ok(_) => return Err("h2/h3-only settings built with bundled roots".into()),
        Err(error) => error,
    };
    assert!(matches!(
        bundled_roots_error,
        Http1TlsError::MissingHttp1Alpn
    ));

    let explicit_roots_error =
        match Http1TlsConnector::new_with_roots(&settings, std::iter::empty::<&[u8]>()) {
            Ok(_) => return Err("h2/h3-only settings built with explicit roots".into()),
            Err(error) => error,
        };
    assert!(matches!(
        explicit_roots_error,
        Http1TlsError::MissingHttp1Alpn
    ));
    Ok(())
}

fn tls_settings() -> TlsSettings {
    TlsSettings {
        min_version: TlsVersion::Tls12,
        max_version: TlsVersion::Tls12,
        cipher_suites: vec![CipherSuite::EcdheEcdsaAes128GcmSha256],
        groups: vec![NamedGroup::X25519, NamedGroup::Secp256r1],
        key_shares: Vec::new(),
        signature_schemes: vec![SignatureScheme::EcdsaSecp256r1Sha256],
        alpn_protocols: vec![Box::from(&b"h2"[..]), Box::from(&b"http/1.1"[..])],
        alps: None,
        certificate_compression: Vec::new(),
        requested_trust_anchor_ids: None,
        grease: false,
        grease_signature_algorithms: false,
        permute_extensions: false,
        ech_grease: false,
        request_ocsp_staple: false,
        request_signed_certificate_timestamps: false,
        aes_hardware: true,
    }
}

fn test_connector(identity: &TestIdentity) -> TestResult<Http1TlsConnector> {
    Ok(Http1TlsConnector::new_with_roots(
        &tls_settings(),
        [identity.root_der.as_slice()],
    )?)
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

#[derive(Clone, Copy)]
enum ServerAlpn {
    None,
    Http1,
    H2,
}

fn server_acceptor(identity: &TestIdentity, alpn: ServerAlpn) -> TestResult<SslAcceptor> {
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    let leaf = X509::from_der(&identity.leaf_der)?;
    let root = X509::from_der(&identity.root_der)?;
    let private_key = PKey::private_key_from_pkcs8(&identity.private_key_der)?;
    acceptor.set_certificate(&leaf)?;
    acceptor.set_private_key(&private_key)?;
    acceptor.add_extra_chain_cert(root)?;
    acceptor.check_private_key()?;
    match alpn {
        ServerAlpn::None => {}
        ServerAlpn::Http1 => acceptor.set_alpn_select_callback(|_, offered| {
            select_next_proto(HTTP1_ALPN_WIRE, offered).ok_or(AlpnError::NOACK)
        }),
        ServerAlpn::H2 => acceptor.set_alpn_select_callback(|_, offered| {
            select_next_proto(H2_ALPN_WIRE, offered).ok_or(AlpnError::NOACK)
        }),
    }
    Ok(acceptor.build())
}

async fn loopback_listener() -> TestResult<(SocketAddr, TcpListener)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    Ok((listener.local_addr()?, listener))
}

async fn accept_tls(
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

async fn read_head(stream: &mut BoringStream<TcpStream>) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await?;
        bytes.push(byte[0]);
    }
    Ok(bytes)
}

struct TouchCountingStream {
    inner: DuplexStream,
    touches: Arc<AtomicUsize>,
}

impl TouchCountingStream {
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
