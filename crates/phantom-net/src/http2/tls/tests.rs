use std::{
    error::Error,
    future::{Future, poll_fn},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use btls::ssl::{AlpnError, Ssl, SslAcceptor, SslVersion, select_next_proto};
use bytes::Bytes;
use http::{HeaderMap, Response};
use http_body_util::BodyExt;
use phantom_profile::{
    AlpsSettings, CipherSuite, ClientHelloExtensionOrder, NamedGroup, SignatureScheme, TlsSettings,
    TlsVersion, chromium::v154_http2,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, duplex},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_btls::SslStream as BoringStream;
use tracing::{Dispatch, instrument::WithSubscriber};

use super::{Http2TlsConnector, Http2TlsError};
use crate::http2::{Http2Error, OriginForm, RequestHeader};
use crate::proxy::HttpConnectHeader;
use crate::tls::test_support::{
    H2_ALPN_WIRE, TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, TestServerAlpn,
    TouchCountingStream, accept_tls, loopback_listener,
};
use crate::tracing_test::OutcomeSubscriber;

mod alps_concurrency_gate;
mod alps_hpack_last_wins;
mod key_update;
mod record_shape;

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
async fn reusable_connect_applies_alpn_and_alps_to_multiple_requests() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = alps_acceptor(&identity)?;
        let application_settings =
            accept_ch_alps("https://server.phantom.test:8443", "Sec-CH-UA-Arch");
        let server = tokio::spawn(async move {
            let mut stream = accept_alps(listener, acceptor, &application_settings).await?;
            let mut preface = [0_u8; 24];
            stream.read_exact(&mut preface).await?;
            assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

            let mut stream_ids = Vec::new();
            while stream_ids.len() < 2 {
                let frame = read_raw_frame(&mut stream).await?;
                if frame.kind == 1 {
                    stream_ids.push(frame.stream_id);
                    write_raw_frame(&mut stream, 1, 0x5, frame.stream_id, &[0x89]).await?;
                }
            }
            Ok::<_, Box<dyn Error + Send + Sync>>(stream_ids)
        });

        let connector = alps_test_connector(&identity)?;
        let tcp = TcpStream::connect(address).await?;
        let connection = connector.connect(tcp, TEST_SERVER_NAME).await?;
        assert_eq!(
            connection.accept_ch_for_origin("https://server.phantom.test:8443"),
            Some(&b"Sec-CH-UA-Arch"[..])
        );
        request_and_collect(&connection, "/first", vec![]).await?;
        request_and_collect(&connection, "/second", vec![]).await?;
        assert_eq!(server.await??, [1, 3]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn reusable_connect_direct_serves_multiple_requests() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let server = tokio::spawn(async move {
            let (stream, sni) = accept_tls(listener, acceptor).await?;
            let paths = serve_two_requests(stream).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((sni, paths))
        });

        let connector = test_connector(&identity)?;
        let connection = connector
            .connect_direct("127.0.0.1", address.port(), TEST_SERVER_NAME)
            .await?;
        request_and_collect(&connection, "/direct-one", vec![]).await?;
        request_and_collect(&connection, "/direct-two", vec![]).await?;
        drop(connection);

        let (sni, paths) = server.await??;
        assert_eq!(sni.as_deref(), Some(TEST_SERVER_NAME));
        assert_eq!(paths, ["/direct-one", "/direct-two"]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn reusable_connect_http_connect_keeps_origin_data_out_of_proxy_head() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let server = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await?;
            let proxy_head = read_http_head(&mut tcp).await?;
            tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;

            let ssl = Ssl::new(acceptor.context())?;
            let mut stream = BoringStream::new(ssl, tcp)?;
            Pin::new(&mut stream).accept().await?;
            let paths = serve_two_requests(stream).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((proxy_head, paths))
        });

        let connector = test_connector(&identity)?;
        let connect_headers = [
            HttpConnectHeader::authority("Host"),
            HttpConnectHeader::field(RequestHeader::new("Proxy-Authorization", "Basic cHJveHk=")),
        ];
        let connection = connector
            .connect_http_connect(
                "127.0.0.1",
                address.port(),
                TEST_AUTHORITY,
                &connect_headers,
                TEST_SERVER_NAME,
            )
            .await?;
        let origin_headers = vec![RequestHeader::new("x-origin-secret", "not-for-proxy")];
        request_and_collect(&connection, "/tunneled-one", origin_headers).await?;
        request_and_collect(&connection, "/tunneled-two", vec![]).await?;
        drop(connection);

        let (proxy_head, paths) = server.await??;
        assert_eq!(
            proxy_head,
            b"CONNECT server.phantom.test:8443 HTTP/1.1\r\n\
Host: server.phantom.test:8443\r\n\
Proxy-Authorization: Basic cHJveHk=\r\n\r\n"
        );
        assert!(
            !proxy_head
                .windows(b"/tunneled-one".len())
                .any(|part| part == b"/tunneled-one")
        );
        assert!(
            !proxy_head
                .windows(b"x-origin-secret".len())
                .any(|part| part == b"x-origin-secret")
        );
        assert_eq!(paths, ["/tunneled-one", "/tunneled-two"]);
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
                if let Err(error) = stream.read_to_end(&mut plaintext).await
                    && !plaintext.is_empty()
                {
                    return Err(error.into());
                }
                Ok::<_, Box<dyn Error + Send + Sync>>(plaintext)
            });

            let connector = test_connector(&identity)?;
            let tcp = TcpStream::connect(address).await?;
            let subscriber = OutcomeSubscriber::default();
            let result = connector
                .send_get(
                    tcp,
                    TEST_SERVER_NAME,
                    TEST_AUTHORITY,
                    OriginForm::parse("/")?,
                    vec![],
                )
                .with_subscriber(Dispatch::new(subscriber.clone()))
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
            assert_eq!(
                subscriber.outcomes_for("http2.tls.response_head"),
                ["unsupported_alpn"]
            );
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
async fn alps_settings_frame_allows_response_before_wire_settings() -> TestResult<()> {
    bounded_tls_test(async {
        const EMPTY_SETTINGS_FRAME: &[u8] = &[0, 0, 0, 4, 0, 0, 0, 0, 0];

        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = alps_acceptor(&identity)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_alps(listener, acceptor, EMPTY_SETTINGS_FRAME).await?;
            let mut preface = [0_u8; 24];
            stream.read_exact(&mut preface).await?;
            assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

            let mut settings_acks = 0;
            let request = loop {
                let frame = read_raw_frame(&mut stream).await?;
                if frame.kind == 4 && frame.flags & 1 != 0 {
                    settings_acks += 1;
                }
                if frame.kind == 1 {
                    break frame;
                }
            };
            assert_eq!(settings_acks, 0, "negotiated ALPS was acknowledged");
            write_raw_frame(&mut stream, 1, 0x5, 1, &[0x89]).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(request.stream_id)
        });

        let connector = alps_test_connector(&identity)?;
        let tcp = TcpStream::connect(address).await?;
        let response = connector
            .send_get(
                tcp,
                TEST_SERVER_NAME,
                TEST_AUTHORITY,
                OriginForm::parse("/alps")?,
                vec![],
            )
            .await?;
        assert_eq!(response.status(), 204);
        assert!(response.into_body().collect().await?.to_bytes().is_empty());
        assert_eq!(server.await??, 1);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn alps_without_a_settings_frame_still_requires_wire_settings() -> TestResult<()> {
    bounded_tls_test(async {
        const NEGOTIATED_EMPTY: &[u8] = &[];
        const UNKNOWN_EXTENSION_FRAME: &[u8] = &[0, 0, 0, 0x10, 0, 0, 0, 0, 0];

        for application_settings in [NEGOTIATED_EMPTY, UNKNOWN_EXTENSION_FRAME] {
            let identity = TestIdentity::generate()?;
            let (address, listener) = loopback_listener().await?;
            let acceptor = alps_acceptor(&identity)?;
            let server = tokio::spawn(async move {
                let mut stream = accept_alps(listener, acceptor, application_settings).await?;
                let mut preface = [0_u8; 24];
                stream.read_exact(&mut preface).await?;
                assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

                loop {
                    let request = read_raw_frame(&mut stream).await?;
                    if request.kind == 1 {
                        assert_eq!(request.stream_id, 1);
                        break;
                    }
                }
                write_raw_frame(&mut stream, 1, 0x5, 1, &[0x89]).await?;
                Ok::<_, Box<dyn Error + Send + Sync>>(())
            });

            let connector = alps_test_connector(&identity)?;
            let tcp = TcpStream::connect(address).await?;
            let subscriber = OutcomeSubscriber::default();
            let result = connector
                .send_get(
                    tcp,
                    TEST_SERVER_NAME,
                    TEST_AUTHORITY,
                    OriginForm::parse("/alps")?,
                    vec![],
                )
                .with_subscriber(Dispatch::new(subscriber.clone()))
                .await;
            assert!(matches!(
                result,
                Err(Http2TlsError::Http2(Http2Error::Protocol(ref error)))
                    if error.reason_code() == Some(1)
            ));
            assert_eq!(
                subscriber.outcomes_for("http2.tls.response_head"),
                ["http_protocol_error"]
            );
            server.await??;
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn malformed_peer_alps_fails_before_http2_plaintext() -> TestResult<()> {
    bounded_tls_test(async {
        const MALFORMED_ALPS: &[u8] = &[0];

        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = alps_acceptor(&identity)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_alps(listener, acceptor, MALFORMED_ALPS).await?;
            let mut plaintext = Vec::new();
            if let Err(error) = stream.read_to_end(&mut plaintext).await
                && !plaintext.is_empty()
            {
                return Err(error.into());
            }
            Ok::<_, Box<dyn Error + Send + Sync>>(plaintext)
        });

        let connector = alps_test_connector(&identity)?;
        let tcp = TcpStream::connect(address).await?;
        let subscriber = OutcomeSubscriber::default();
        let result = connector
            .send_get(
                tcp,
                TEST_SERVER_NAME,
                TEST_AUTHORITY,
                OriginForm::parse("/")?,
                vec![],
            )
            .with_subscriber(Dispatch::new(subscriber.clone()))
            .await;
        let error = match result {
            Ok(_) => return Err("malformed peer ALPS was accepted".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            Http2TlsError::InvalidPeerApplicationSettings {
                frame_index: 0,
                offset: 0,
                ..
            }
        ));
        assert_eq!(
            subscriber.outcomes_for("http2.tls.response_head"),
            ["invalid_peer_alps"]
        );
        assert!(
            server.await??.is_empty(),
            "HTTP/2 plaintext followed malformed ALPS"
        );
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
    let subscriber = OutcomeSubscriber::default();
    let result = connector
        .send_get(
            TouchCountingStream::new(client, Arc::clone(&touches)),
            TEST_SERVER_NAME,
            TEST_AUTHORITY,
            OriginForm::parse("/")?,
            vec![RequestHeader::new("host", TEST_SERVER_NAME)],
        )
        .with_subscriber(Dispatch::new(subscriber.clone()))
        .await;
    assert!(matches!(result, Err(Http2TlsError::Http2(_))));
    assert_eq!(touches.load(Ordering::SeqCst), 0);
    assert_eq!(
        subscriber.outcomes_for("http2.tls.response_head"),
        ["http_preparation_error"]
    );

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

#[tokio::test]
async fn handshake_failure_has_tls_wrapper_outcome() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = test_connector(&identity)?;
    let (client, server) = duplex(4096);
    drop(server);
    let subscriber = OutcomeSubscriber::default();

    let result = connector
        .send_get(
            client,
            TEST_SERVER_NAME,
            TEST_AUTHORITY,
            OriginForm::parse("/")?,
            Vec::new(),
        )
        .with_subscriber(Dispatch::new(subscriber.clone()))
        .await;
    assert!(matches!(result, Err(Http2TlsError::Tls(_))));
    assert_eq!(
        subscriber.outcomes_for("http2.tls.response_head"),
        ["tls_error"]
    );
    Ok(())
}

#[test]
fn constructor_requires_h2_and_validates_http2_settings() -> TestResult<()> {
    let mut tls = tls_settings();
    tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    assert!(matches!(
        Http2TlsConnector::new(&tls, &v154_http2()),
        Err(Http2TlsError::MissingHttp2Alpn)
    ));

    let mut http2 = v154_http2();
    http2.initial_connection_window_size = 65_534;
    assert!(matches!(
        Http2TlsConnector::new(&tls_settings(), &http2),
        Err(Http2TlsError::Http2(Http2Error::InvalidSettings(_)))
    ));
    Ok(())
}

async fn request_and_collect(
    connection: &crate::http2::Http2Connection,
    path: &str,
    headers: Vec<RequestHeader>,
) -> TestResult<()> {
    let response = connection
        .send_get(TEST_AUTHORITY, OriginForm::parse(path)?, headers)
        .await?;
    assert_eq!(response.status(), 204);
    assert!(response.into_body().collect().await?.to_bytes().is_empty());
    Ok(())
}

async fn serve_two_requests<S>(stream: S) -> TestResult<Vec<String>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut connection = ::http2::server::handshake(stream).await?;
    let mut paths = Vec::new();
    for _ in 0..2 {
        let (request, mut respond) = connection
            .accept()
            .await
            .ok_or("connection closed before reusable request")??;
        paths.push(request.uri().path().to_owned());
        respond.send_response(Response::builder().status(204).body(())?, true)?;
    }
    if connection.accept().await.is_some() {
        return Err("client opened an unexpected third reusable request".into());
    }
    Ok(paths)
}

async fn read_http_head<S>(stream: &mut S) -> TestResult<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    const MAX_HEAD_BYTES: usize = 4096;

    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() == MAX_HEAD_BYTES {
            return Err("HTTP proxy request head exceeded test bound".into());
        }
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await?;
        head.push(byte[0]);
    }
    Ok(head)
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
        ech_grease_aeads: Vec::new(),
        ech_from_https_records: false,
        request_ocsp_staple: false,
        request_signed_certificate_timestamps: false,
        aes_hardware: true,
    }
}

fn test_connector(identity: &TestIdentity) -> TestResult<Http2TlsConnector> {
    Ok(Http2TlsConnector::new_with_roots(
        &tls_settings(),
        &v154_http2(),
        [identity.root_der()],
    )?)
}

fn alps_test_connector(identity: &TestIdentity) -> TestResult<Http2TlsConnector> {
    let mut tls = tls_settings();
    tls.min_version = TlsVersion::Tls13;
    tls.max_version = TlsVersion::Tls13;
    tls.key_shares = vec![NamedGroup::X25519];
    tls.alps = Some(AlpsSettings {
        protocol: Box::from(&b"h2"[..]),
        settings: Box::default(),
        use_new_codepoint: true,
    });
    Ok(Http2TlsConnector::new_with_roots(
        &tls,
        &v154_http2(),
        [identity.root_der()],
    )?)
}

fn alps_acceptor(identity: &TestIdentity) -> TestResult<SslAcceptor> {
    let mut acceptor = identity.acceptor_builder()?;
    acceptor.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    acceptor.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    acceptor.set_alpn_select_callback(|_, offered| {
        select_next_proto(H2_ALPN_WIRE, offered).ok_or(AlpnError::NOACK)
    });
    Ok(acceptor.build())
}

async fn accept_alps(
    listener: TcpListener,
    acceptor: SslAcceptor,
    application_settings: &[u8],
) -> TestResult<BoringStream<TcpStream>> {
    let (tcp, _) = listener.accept().await?;
    let mut ssl = Ssl::new(acceptor.context())?;
    ssl.add_application_settings_with_payload(b"h2", application_settings)?;
    ssl.set_alps_use_new_codepoint(true);
    let mut stream = BoringStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
}

fn accept_ch_alps(origin: &str, value: &str) -> Vec<u8> {
    let Ok(origin_len) = u16::try_from(origin.len()) else {
        panic!("test origin exceeds the HTTP/2 field width");
    };
    let Ok(value_len) = u16::try_from(value.len()) else {
        panic!("test value exceeds the HTTP/2 field width");
    };
    let payload_len = 4 + origin.len() + value.len();
    let mut encoded = vec![0, 0, 0, 4, 0, 0, 0, 0, 0];
    encoded.extend([
        ((payload_len >> 16) & 0xff) as u8,
        ((payload_len >> 8) & 0xff) as u8,
        (payload_len & 0xff) as u8,
        0x89,
        0,
        0,
        0,
        0,
        0,
    ]);
    encoded.extend(origin_len.to_be_bytes());
    encoded.extend(origin.as_bytes());
    encoded.extend(value_len.to_be_bytes());
    encoded.extend(value.as_bytes());
    encoded
}

struct RawFrame {
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

async fn read_raw_frame<S>(stream: &mut S) -> TestResult<RawFrame>
where
    S: AsyncRead + Unpin,
{
    let mut head = [0_u8; 9];
    stream.read_exact(&mut head).await?;
    let length = (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).await?;
    Ok(RawFrame {
        kind: head[3],
        flags: head[4],
        stream_id: u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff,
        payload,
    })
}

async fn write_raw_frame<S>(
    stream: &mut S,
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload: &[u8],
) -> TestResult<()>
where
    S: AsyncWrite + Unpin,
{
    let length = payload.len();
    let mut head = [0_u8; 9];
    head[0] = ((length >> 16) & 0xff) as u8;
    head[1] = ((length >> 8) & 0xff) as u8;
    head[2] = (length & 0xff) as u8;
    head[3] = kind;
    head[4] = flags;
    head[5..].copy_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    stream.write_all(&head).await?;
    stream.write_all(payload).await?;
    Ok(())
}
