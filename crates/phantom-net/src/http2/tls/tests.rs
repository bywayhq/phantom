use std::{
    error::Error,
    future::{Future, poll_fn},
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
use bytes::Bytes;
use http::{HeaderMap, Response};
use http_body_util::BodyExt;
use phantom_profile::{
    CipherSuite, NamedGroup, SignatureScheme, TlsSettings, TlsVersion, chromium::v152_macos_http2,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, DuplexStream, ReadBuf, duplex},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_btls::SslStream as BoringStream;

use super::{Http2TlsConnector, Http2TlsError};
use crate::http2::{Http2Error, OriginForm, RequestHeader};

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
        Err(_) => Err("HTTP/2-over-TLS test exceeded its absolute deadline".into()),
    }
}

#[tokio::test]
async fn streams_http2_over_certificate_verified_tls() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = server_acceptor(&identity, ServerAlpn::H2)?;
        let server = tokio::spawn(async move {
            let (stream, sni) = accept_tls(listener, acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before request")??;
            let response = Response::builder().status(207).body(())?;
            let mut send = respond.send_response(response, false)?;
            send.send_data(Bytes::from_static(b"secure"), false)?;
            let mut trailers = HeaderMap::new();
            trailers.insert("x-secure", "yes".parse()?);
            send.send_trailers(trailers)?;
            let uri = request.uri().clone();
            drop(request);
            drop(send);
            drop(respond);
            poll_fn(|cx| connection.poll_closed(cx)).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((sni, uri))
        });

        let connector = test_connector(&identity)?;
        let tcp = TcpStream::connect(address).await?;
        let response = connector
            .send_get(
                tcp,
                TEST_SERVER_NAME,
                OriginForm::parse("/secure?item=1")?,
                vec![RequestHeader::new("accept", "*/*")],
            )
            .await?;
        assert_eq!(response.status(), 207);
        let mut body = response.into_body();
        let mut data = Vec::new();
        let mut trailer = None;
        while let Some(frame) = body.frame().await {
            let frame = frame?;
            match frame.into_data() {
                Ok(bytes) => data.extend_from_slice(&bytes),
                Err(frame) => {
                    if let Ok(fields) = frame.into_trailers() {
                        trailer = fields.get("x-secure").cloned();
                    }
                }
            }
        }
        assert_eq!(data, b"secure");
        assert_eq!(
            trailer.as_ref().and_then(|value| value.to_str().ok()),
            Some("yes")
        );

        let (sni, uri) = server.await??;
        assert_eq!(sni.as_deref(), Some(TEST_SERVER_NAME));
        assert_eq!(uri, "https://server.phantom.test/secure?item=1");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn rejects_missing_and_http1_alpn_without_http2_bytes() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        for selected in [ServerAlpn::None, ServerAlpn::Http1] {
            let (address, listener) = loopback_listener().await?;
            let acceptor = server_acceptor(&identity, selected)?;
            let server = tokio::spawn(async move {
                let (mut stream, _) = accept_tls(listener, acceptor).await?;
                let mut plaintext = Vec::new();
                if let Err(error) = stream.read_to_end(&mut plaintext).await {
                    if !plaintext.is_empty() {
                        return Err(error.into());
                    }
                }
                Ok::<_, Box<dyn Error + Send + Sync>>(plaintext)
            });

            let connector = test_connector(&identity)?;
            let tcp = TcpStream::connect(address).await?;
            let result = connector
                .send_get(tcp, TEST_SERVER_NAME, OriginForm::parse("/")?, vec![])
                .await;
            match selected {
                ServerAlpn::None => {
                    assert!(matches!(result, Err(Http2TlsError::MissingNegotiatedAlpn)));
                }
                ServerAlpn::Http1 => assert!(matches!(
                    result,
                    Err(Http2TlsError::UnsupportedAlpn { ref selected })
                        if selected.as_ref() == b"http/1.1"
                )),
                ServerAlpn::H2 => unreachable!("test cases exclude h2"),
            }
            assert!(
                server.await??.is_empty(),
                "HTTP/2 bytes followed rejected ALPN"
            );
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn invalid_request_does_not_touch_tls_stream() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = test_connector(&identity)?;
    let touches = Arc::new(AtomicUsize::new(0));
    let (client, _server) = duplex(128);
    let result = connector
        .send_get(
            TouchCountingStream {
                inner: client,
                touches: Arc::clone(&touches),
            },
            TEST_SERVER_NAME,
            OriginForm::parse("/")?,
            vec![RequestHeader::new("host", TEST_SERVER_NAME)],
        )
        .await;
    assert!(matches!(result, Err(Http2TlsError::Http2(_))));
    assert_eq!(touches.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn constructor_requires_h2_and_validates_http2_settings() -> TestResult<()> {
    let mut tls = tls_settings();
    tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    assert!(matches!(
        Http2TlsConnector::new(&tls, &v152_macos_http2()),
        Err(Http2TlsError::MissingHttp2Alpn)
    ));

    let mut http2 = v152_macos_http2();
    http2.initial_connection_window_size = 65_534;
    assert!(matches!(
        Http2TlsConnector::new(&tls_settings(), &http2),
        Err(Http2TlsError::Http2(Http2Error::InvalidSettings(_)))
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

fn test_connector(identity: &TestIdentity) -> TestResult<Http2TlsConnector> {
    Ok(Http2TlsConnector::new_with_roots(
        &tls_settings(),
        &v152_macos_http2(),
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

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.touched();
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.touched();
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}
