//! Public-facade integration tests.

mod support;

use std::{
    error::Error,
    future::{Future, poll_fn},
    io,
    net::{IpAddr, Ipv4Addr, TcpListener as StdTcpListener},
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    task::{Context, Waker},
    time::Duration,
};

use btls::{
    pkey::PKey,
    ssl::{AlpnError, Ssl, SslAcceptor, SslMethod, select_next_proto},
    x509::X509,
};
use bytes::Bytes;
use http::{HeaderMap, Response};
use http_body_util::BodyExt;
use phantom::{
    BuildErrorKind, Client, HttpProtocol, RequestErrorKind, RequestHeader,
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
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream;
use tracing::instrument::WithSubscriber;

use support::OutcomeSubscriber;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const H1_ALPN: &[u8] = b"\x08http/1.1";
const H2_ALPN: &[u8] = b"\x02h2";

type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[test]
fn runtime_without_io_panics_and_records_panicked_outcomes() -> TestResult<()> {
    let profile = ClientProfile::new(chromium::v152_macos_tls());
    let client = Client::builder(profile).build()?;
    let request = client.get(HttpProtocol::Http1, "https://127.0.0.1:9/")?;
    let subscriber = OutcomeSubscriber::default();
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;

    let result = catch_unwind(AssertUnwindSafe(|| {
        runtime.block_on(request.send().with_subscriber(subscriber.dispatch()))
    }));

    assert!(result.is_err(), "runtime without network I/O did not panic");
    assert_eq!(subscriber.outcomes_for("client.request"), ["panicked"]);
    assert_eq!(
        subscriber.outcomes_for("http1.tls.response_head"),
        ["panicked"]
    );
    Ok(())
}

#[tokio::test]
async fn public_client_streams_http1_over_verified_tls() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let (release, released) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut stream = accept_tls(listener, acceptor).await?;
            let request = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nfirst")
                .await?;
            stream.flush().await?;
            released.await.map_err(io::Error::other)?;
            stream.write_all(b"later").await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(request)
        });

        let client = test_client(&identity, false)?;
        let response = client
            .get(
                HttpProtocol::Http1,
                &format!("https://{address}/resource?item=1"),
            )?
            .headers(vec![
                RequestHeader::new("X-First", "one"),
                RequestHeader::new("x-repeat", "alpha"),
                RequestHeader::new("X-Repeat", "beta"),
            ])
            .send()
            .await?;
        assert_eq!(response.status(), 200);

        let mut body = response.into_body();
        let first = next_data(&mut body).await?;
        assert_eq!(first, "first");
        release
            .send(())
            .map_err(|_| "server stopped before later body release")?;
        assert_eq!(body.collect().await?.to_bytes(), "later");

        let request = server.await??;
        let expected = format!(
            "GET /resource?item=1 HTTP/1.1\r\nHost: {address}\r\nX-First: one\r\nx-repeat: alpha\r\nX-Repeat: beta\r\n\r\n"
        );
        assert_eq!(request, expected.as_bytes());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn public_client_streams_http2_data_and_trailers() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (release, released) = oneshot::channel();
        let server = tokio::spawn(async move {
            let stream = accept_tls(listener, acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before request")??;
            let response = Response::builder().status(206).body(())?;
            let mut send = respond.send_response(response, false)?;
            send.send_data(Bytes::from_static(b"first"), false)?;

            tokio::pin!(released);
            tokio::select! {
                result = &mut released => result.map_err(io::Error::other)?,
                incoming = connection.accept() => {
                    if incoming.is_none() {
                        return Err("connection closed before later data release".into());
                    }
                    return Err("one-shot client sent a second request".into());
                }
            }

            send.send_data(Bytes::from_static(b"later"), false)?;
            let mut trailers = HeaderMap::new();
            trailers.insert("x-finished", "yes".parse()?);
            send.send_trailers(trailers)?;
            let uri = request.uri().clone();
            drop(request);
            drop(send);
            drop(respond);
            poll_fn(|context| connection.poll_closed(context)).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(uri)
        });

        let client = test_client(&identity, true)?;
        let response = client
            .get(
                HttpProtocol::Http2,
                &format!("https://{address}/resource?item=1"),
            )?
            .header(RequestHeader::new("x-repeat", "alpha"))
            .header(RequestHeader::new("x-repeat", "beta"))
            .send()
            .await?;
        assert_eq!(response.status(), 206);

        let mut body = response.into_body();
        assert_eq!(next_data(&mut body).await?, "first");
        release
            .send(())
            .map_err(|_| "server stopped before later body release")?;

        let mut later = None;
        let mut trailer = None;
        while let Some(frame) = body.frame().await {
            let frame = frame?;
            match frame.into_data() {
                Ok(data) if !data.is_empty() => later = Some(data),
                Ok(_) => {}
                Err(frame) => {
                    if let Ok(fields) = frame.into_trailers() {
                        trailer = fields.get("x-finished").cloned();
                    }
                }
            }
        }
        assert_eq!(later.as_deref(), Some(&b"later"[..]));
        assert_eq!(
            trailer.as_ref().and_then(|value| value.to_str().ok()),
            Some("yes")
        );

        let uri = server.await??;
        let expected_authority = address.to_string();
        assert_eq!(
            uri.authority().map(|value| value.as_str()),
            Some(expected_authority.as_str())
        );
        assert_eq!(
            uri.path_and_query().map(|value| value.as_str()),
            Some("/resource?item=1")
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn unavailable_protocol_fails_before_network_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity, false)?;
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;

    let error = match client.get(HttpProtocol::Http2, &format!("https://{address}/")) {
        Ok(_) => return Err("HTTP/2 unexpectedly available".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::ProtocolUnavailable);
    assert_eq!(error.protocol(), Some(HttpProtocol::Http2));
    assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    Ok(())
}

#[tokio::test]
async fn invalid_http2_field_fails_before_network_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity, true)?;
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;

    let result = client
        .get(HttpProtocol::Http2, &format!("https://{address}/"))?
        .header(RequestHeader::new("X-Uppercase", "rejected"))
        .send()
        .await;
    let error = match result {
        Ok(_) => return Err("invalid HTTP/2 field unexpectedly sent".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::Http2);
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    Ok(())
}

#[tokio::test]
async fn empty_host_fails_before_network_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity, false)?;
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();

    let error = match client.get(HttpProtocol::Http1, &format!("https://:{port}/")) {
        Ok(_) => return Err("empty request host was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::InvalidAuthority);
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    Ok(())
}

#[tokio::test]
async fn bracketed_ipv4_host_fails_before_network_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity, false)?;
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();

    let error = match client.get(HttpProtocol::Http1, &format!("https://[127.0.0.1]:{port}/")) {
        Ok(_) => return Err("bracketed IPv4 request host was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::InvalidAuthority);
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    Ok(())
}

#[tokio::test]
async fn malformed_explicit_ports_fail_before_network_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity, false)?;
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;

    for (port, description) in [
        ("", "empty"),
        ("not-a-port", "nonnumeric"),
        ("65536", "overflow"),
    ] {
        let uri = format!("https://127.0.0.1:{port}/");
        let error = match client.get(HttpProtocol::Http1, &uri) {
            Ok(_) => return Err(format!("{description} request port was accepted").into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::InvalidAuthority);
        assert!(matches!(
            listener.accept(),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
    }
    Ok(())
}

#[test]
fn polling_direct_request_without_tokio_returns_error() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity, false)?;
    let request = client.get(HttpProtocol::Http1, "https://127.0.0.1:9/")?;
    let mut future = std::pin::pin!(request.send());
    let mut context = Context::from_waker(Waker::noop());

    let result = match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => return Err("request waited without a Tokio runtime".into()),
    };
    let error = match result {
        Ok(_) => return Err("request completed outside a Tokio runtime".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::RuntimeUnavailable);
    Ok(())
}

#[test]
fn invalid_http2_profile_has_stable_build_category() -> TestResult<()> {
    let mut tls = tls_settings();
    tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    let error =
        match Client::builder(ClientProfile::new(tls).with_http2(chromium::v152_macos_http2()))
            .build()
        {
            Ok(_) => return Err("HTTP/2 profile without h2 ALPN was accepted".into()),
            Err(error) => error,
        };
    assert_eq!(error.kind(), BuildErrorKind::InvalidProfile);

    let mut http2 = chromium::v152_macos_http2();
    http2.initial_connection_window_size = 65_534;
    let error = match Client::builder(ClientProfile::new(tls_settings()).with_http2(http2)).build()
    {
        Ok(_) => return Err("invalid HTTP/2 settings were accepted".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), BuildErrorKind::InvalidProfile);
    Ok(())
}

#[test]
fn invalid_additional_root_has_stable_build_category() -> TestResult<()> {
    let mut tls = tls_settings();
    tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    let error = match Client::builder(ClientProfile::new(tls))
        .add_root_certificate_der([0_u8])
        .build()
    {
        Ok(_) => return Err("invalid additional trust root was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), BuildErrorKind::TrustStore);
    Ok(())
}

fn test_client(identity: &TestIdentity, http2: bool) -> TestResult<Client> {
    let mut tls = tls_settings();
    if !http2 {
        tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    }
    let mut profile = ClientProfile::new(tls);
    if http2 {
        profile = profile.with_http2(chromium::v152_macos_http2());
    }
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}

fn tls_settings() -> TlsSettings {
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

async fn next_data(body: &mut phantom::ResponseBody) -> TestResult<Bytes> {
    loop {
        let frame = body.frame().await.ok_or("response body ended")??;
        if let Ok(data) = frame.into_data() {
            if !data.is_empty() {
                return Ok(data);
            }
        }
    }
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "client test exceeded its deadline")?
}

async fn read_head(stream: &mut SslStream<TcpStream>) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() == 32 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request head exceeded test bound",
            ));
        }
        stream.read_exact(&mut byte).await?;
        bytes.push(byte[0]);
    }
    Ok(bytes)
}

async fn accept_tls(
    listener: TcpListener,
    acceptor: SslAcceptor,
) -> TestResult<SslStream<TcpStream>> {
    let (tcp, _) = listener.accept().await?;
    let ssl = Ssl::new(acceptor.context())?;
    let mut stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
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

        let mut leaf_params = CertificateParams::new(Vec::<String>::new())?;
        leaf_params
            .subject_alt_names
            .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
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

    fn acceptor(&self, alpn: &'static [u8]) -> TestResult<SslAcceptor> {
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        let certificate = X509::from_der(&self.leaf_der)?;
        let private_key = PKey::private_key_from_pkcs8(&self.private_key_der)?;
        acceptor.set_certificate(&certificate)?;
        acceptor.set_private_key(&private_key)?;
        acceptor.add_extra_chain_cert(X509::from_der(&self.root_der)?)?;
        acceptor.check_private_key()?;
        acceptor.set_alpn_select_callback(move |_, offered| {
            select_next_proto(alpn, offered).ok_or(AlpnError::NOACK)
        });
        Ok(acceptor.build())
    }
}
