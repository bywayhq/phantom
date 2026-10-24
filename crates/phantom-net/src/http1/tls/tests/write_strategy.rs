use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
};

use bytes::Bytes;
use http::Method;
use http_body_util::BodyExt;
use phantom_profile::{NamedGroup, TlsVersion, TlsVersionRange};
use rustls::{
    ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};

use super::{
    TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, bounded_tls_test, tls_settings,
};
use crate::{
    http1::{Http1TlsConnector, Http1WriteStrategy},
    request::{OriginForm, RequestHeader},
    route::{ConnectedStream, DirectTlsSetup, Http1Route, OriginRoute, TcpRoute},
};

const BODY: [u8; 512] = [b'x'; 512];
const MAX_CAPTURE: usize = 64 * 1024;

#[tokio::test]
async fn write_strategies_preserve_tls_uploads_and_expose_actual_record_grouping() -> TestResult<()>
{
    for strategy in [Http1WriteStrategy::Automatic, Http1WriteStrategy::Queued] {
        bounded_tls_test(async {
            let identity = TestIdentity::generate()?;
            let mut config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(identity.leaf_der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    identity.private_key_der().to_vec(),
                )),
            )?;
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let address = listener.local_addr()?;
            let tcp = tokio::net::TcpStream::connect(address).await?;
            let server =
                tokio::task::spawn_blocking(move || serve_upload(listener, Arc::new(config)));
            let mut settings = tls_settings();
            settings.versions = TlsVersionRange::only(TlsVersion::Tls13);
            settings.key_shares = vec![NamedGroup::X25519];
            let connector = Http1TlsConnector::new_with_roots(&settings, [identity.root_der()])?
                .with_write_strategy(strategy);
            let (connection, slower) = connector
                .connect(Http1Route::Origin(OriginRoute::Tls {
                    tcp: TcpRoute::Connected(ConnectedStream::new(tcp)),
                    server_name: TEST_SERVER_NAME,
                    setup: DirectTlsSetup::Default,
                }))
                .await?;
            assert!(slower.is_none());
            connection
                .send_get(
                    OriginForm::parse("/ready")?,
                    vec![RequestHeader::new("Host", TEST_SERVER_NAME)],
                )
                .await?
                .into_body()
                .collect()
                .await?;
            let response = connection
                .send_request(
                    Method::POST,
                    OriginForm::parse("/upload")?,
                    vec![RequestHeader::new("Host", TEST_SERVER_NAME)],
                    Some(Bytes::from_static(&BODY)),
                )
                .await?;
            assert_eq!(response.status(), 204);
            assert!(response.into_body().collect().await?.to_bytes().is_empty());
            let response = connection
                .send_get(
                    OriginForm::parse("/reuse")?,
                    vec![RequestHeader::new("Host", TEST_SERVER_NAME)],
                )
                .await?;
            assert_eq!(response.status(), 204);
            response.into_body().collect().await?;
            drop(connection);

            let records = server.await??;
            assert!(!records.is_empty());
            // Record grouping is an observation, not a portable count guarantee.
            eprintln!("{strategy:?} TLS 1.3 request application record lengths: {records:?}");
            Ok(())
        })
        .await?;
    }
    Ok(())
}

fn serve_upload(listener: TcpListener, config: Arc<ServerConfig>) -> TestResult<Vec<usize>> {
    let (tcp, _) = listener.accept()?;
    tcp.set_read_timeout(Some(TEST_TIMEOUT))?;
    tcp.set_write_timeout(Some(TEST_TIMEOUT))?;
    let mut stream = StreamOwned::new(
        ServerConnection::new(config)?,
        RecordingTcp {
            tcp,
            received: Vec::new(),
        },
    );
    assert_eq!(
        read_head(&mut stream)?,
        format!("GET /ready HTTP/1.1\r\nHost: {TEST_SERVER_NAME}\r\n\r\n").as_bytes()
    );
    // The client waits for this response, so subsequent reads contain only
    // the upload and reused request, after the handshake has completed.
    stream.sock.received.clear();
    stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n")?;
    stream.flush()?;
    assert_eq!(
        read_head(&mut stream)?,
        format!("POST /upload HTTP/1.1\r\nHost: {TEST_SERVER_NAME}\r\nContent-Length: 512\r\n\r\n")
            .as_bytes()
    );
    let mut body = [0; BODY.len()];
    stream.read_exact(&mut body)?;
    assert_eq!(body, BODY);
    stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n")?;
    stream.flush()?;
    assert_eq!(
        read_head(&mut stream)?,
        format!("GET /reuse HTTP/1.1\r\nHost: {TEST_SERVER_NAME}\r\n\r\n").as_bytes()
    );
    stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n")?;
    stream.flush()?;
    application_record_lengths(&stream.sock.received)
}

fn read_head(stream: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() == 32 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request head exceeds test bound",
            ));
        }
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        head.push(byte[0]);
    }
    Ok(head)
}

fn application_record_lengths(mut bytes: &[u8]) -> TestResult<Vec<usize>> {
    let mut lengths = Vec::new();
    while !bytes.is_empty() {
        let header = bytes.get(..5).ok_or("truncated TLS record header")?;
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let rest = bytes
            .get(5..)
            .and_then(|payload| payload.get(length..))
            .ok_or("truncated TLS record payload")?;
        if header[0] == 23 {
            lengths.push(length);
        }
        bytes = rest;
    }
    Ok(lengths)
}

struct RecordingTcp {
    tcp: TcpStream,
    received: Vec<u8>,
}

impl Read for RecordingTcp {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.tcp.read(buffer)?;
        if count > MAX_CAPTURE.saturating_sub(self.received.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS capture exceeds test bound",
            ));
        }
        self.received.extend_from_slice(&buffer[..count]);
        Ok(count)
    }
}

impl Write for RecordingTcp {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.tcp.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}
