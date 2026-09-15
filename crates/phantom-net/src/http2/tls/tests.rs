use std::{
    error::Error,
    future::{Future, poll_fn},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use bytes::Bytes;
use http::{HeaderMap, Response};
use http_body_util::BodyExt;
use phantom_profile::{
    CipherSuite, NamedGroup, SignatureScheme, TlsSettings, TlsVersion, chromium::v152_macos_http2,
};
use tokio::{
    io::{AsyncReadExt, duplex},
    net::TcpStream,
    time::timeout,
};

use super::{Http2TlsConnector, Http2TlsError};
use crate::http2::{Http2Error, OriginForm, RequestHeader};
use crate::tls::test_support::{
    TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, TestServerAlpn, TouchCountingStream,
    accept_tls, loopback_listener,
};

const TEST_AUTHORITY: &str = "server.phantom.test:8443";

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
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
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
                TEST_AUTHORITY,
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
        assert_eq!(uri, "https://server.phantom.test:8443/secure?item=1");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn rejects_missing_and_http1_alpn_without_http2_bytes() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        for selected in [TestServerAlpn::None, TestServerAlpn::Http1] {
            let (address, listener) = loopback_listener().await?;
            let acceptor = identity.acceptor(selected)?;
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
                .send_get(
                    tcp,
                    TEST_SERVER_NAME,
                    TEST_AUTHORITY,
                    OriginForm::parse("/")?,
                    vec![],
                )
                .await;
            match selected {
                TestServerAlpn::None => {
                    assert!(matches!(result, Err(Http2TlsError::MissingNegotiatedAlpn)));
                }
                TestServerAlpn::Http1 => assert!(matches!(
                    result,
                    Err(Http2TlsError::UnsupportedAlpn { ref selected })
                        if selected.as_ref() == b"http/1.1"
                )),
                TestServerAlpn::H2 => unreachable!("test cases exclude h2"),
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
            TouchCountingStream::new(client, Arc::clone(&touches)),
            TEST_SERVER_NAME,
            TEST_AUTHORITY,
            OriginForm::parse("/")?,
            vec![RequestHeader::new("host", TEST_SERVER_NAME)],
        )
        .await;
    assert!(matches!(result, Err(Http2TlsError::Http2(_))));
    assert_eq!(touches.load(Ordering::SeqCst), 0);

    let touches = Arc::new(AtomicUsize::new(0));
    let (client, _server) = duplex(128);
    let result = connector
        .send_get(
            TouchCountingStream::new(client, Arc::clone(&touches)),
            TEST_SERVER_NAME,
            "user@example.test",
            OriginForm::parse("/")?,
            vec![],
        )
        .await;
    assert!(matches!(
        result,
        Err(Http2TlsError::Http2(Http2Error::AuthorityContainsUserinfo))
    ));
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
        [identity.root_der()],
    )?)
}
