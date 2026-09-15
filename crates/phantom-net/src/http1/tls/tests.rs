use std::{
    error::Error,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use http_body_util::BodyExt;
use phantom_profile::{CipherSuite, NamedGroup, SignatureScheme, TlsSettings, TlsVersion};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex},
    net::TcpStream,
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream as BoringStream;

use super::{Http1TlsConnector, Http1TlsError};
use crate::http1::{OriginForm, RequestHeader};
use crate::tls::test_support::{
    TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, TestServerAlpn, accept_tls,
    loopback_listener,
};
use crate::tracing_test::{OutcomeSubscriber, poll_once_then_drop};

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
async fn dropping_tls_response_head_future_records_cancelled_once() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = test_connector(&identity)?;
    let subscriber = OutcomeSubscriber::default();
    let (client, _server) = duplex(64 * 1024);
    let pending = poll_once_then_drop(
        connector.send_get(
            client,
            TEST_SERVER_NAME,
            OriginForm::parse("/")?,
            vec![RequestHeader::new("Host", TEST_SERVER_NAME)],
        ),
        subscriber.clone(),
    )
    .await;
    if !pending {
        return Err("HTTP/1-over-TLS response-head future completed before cancellation".into());
    }

    assert_eq!(
        subscriber.outcomes_for("http1.tls.response_head"),
        ["cancelled"]
    );
    assert_eq!(subscriber.outcomes_for("tls.handshake"), ["cancelled"]);
    Ok(())
}

#[tokio::test]
async fn streams_ordered_http1_over_trusted_tls() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::Http1)?;
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
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
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
        let acceptor = identity.acceptor(TestServerAlpn::None)?;
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
        [identity.root_der()],
    )?)
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
