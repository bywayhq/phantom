use std::{
    io::{Read, Write},
    net::{TcpListener as StdTcpListener, TcpStream as StdTcpStream},
    sync::Arc,
};

use bytes::Bytes;
use http_body_util::BodyExt;
use phantom_profile::{NamedGroup, TlsVersion, chromium::v152_macos_http2};
use rustls::{
    ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};

use super::{
    Http2TlsConnector, TEST_AUTHORITY, TEST_SERVER_NAME, TestIdentity, TestResult,
    bounded_tls_test, tls_settings,
};
use crate::http2::OriginForm;

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const TLS_FRAGMENT_SIZE: usize = 1024;
const TLS13_RECORD_PAYLOAD_BOUND: usize = TLS_FRAGMENT_SIZE - 5 + 17;
const RESPONSE_BODY_LEN: usize = 8 * 1024;
const FOLLOWUP_BODY: &[u8] = b"record-shape complete";
const MAX_CAPTURE_BYTES: usize = 256 * 1024;
const MAX_FRAME_LENGTH: usize = 64 * 1024;
const MAX_PROBE_FRAMES: usize = 128;

#[tokio::test]
async fn fragmented_tls13_records_preserve_body_and_connection_reuse() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let server_config = record_shape_server_config(&identity)?;
        let listener = StdTcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let tcp = tokio::net::TcpStream::connect(address).await?;
        let server = tokio::task::spawn_blocking(move || {
            let (tcp, _) = listener.accept()?;
            tcp.set_read_timeout(Some(super::TEST_TIMEOUT))?;
            tcp.set_write_timeout(Some(super::TEST_TIMEOUT))?;
            serve_record_shape_probe(tcp, server_config)
        });

        let connector = tls13_connector(&identity)?;
        let connection = connector.connect(tcp, TEST_SERVER_NAME).await?;
        let response = connection
            .send_get(TEST_AUTHORITY, OriginForm::parse("/")?, Vec::new())
            .await?;
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.into_body().collect().await?.to_bytes(),
            Bytes::from(record_shape_body())
        );

        let followup = connection
            .send_get(
                TEST_AUTHORITY,
                OriginForm::parse("/.well-known/reaper/record-shape")?,
                Vec::new(),
            )
            .await?;
        assert_eq!(followup.status(), 200);
        assert_eq!(
            followup.into_body().collect().await?.to_bytes(),
            Bytes::from_static(FOLLOWUP_BODY)
        );
        drop(connection);

        let observation = server.await??;
        assert!(!observation.capture_overflowed);
        assert!(observation.application_records > 1);
        assert_eq!(
            observation.max_application_payload,
            TLS13_RECORD_PAYLOAD_BOUND
        );
        Ok(())
    })
    .await
}

fn record_shape_server_config(identity: &TestIdentity) -> TestResult<Arc<ServerConfig>> {
    let provider = rustls::crypto::ring::default_provider();
    let builder = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let certificate = CertificateDer::from(identity.leaf_der().to_vec());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        identity.private_key_der().to_vec(),
    ));
    let mut config = builder
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.max_fragment_size = Some(TLS_FRAGMENT_SIZE);
    Ok(Arc::new(config))
}

fn tls13_connector(identity: &TestIdentity) -> TestResult<Http2TlsConnector> {
    let mut tls = tls_settings();
    tls.min_version = TlsVersion::Tls13;
    tls.max_version = TlsVersion::Tls13;
    tls.key_shares = vec![NamedGroup::X25519];
    Ok(Http2TlsConnector::new_with_roots(
        &tls,
        &v152_macos_http2(),
        [identity.root_der()],
    )?)
}

fn serve_record_shape_probe(
    tcp: StdTcpStream,
    config: Arc<ServerConfig>,
) -> TestResult<RecordShapeObservation> {
    let connection = ServerConnection::new(config)?;
    let mut stream = StreamOwned::new(connection, RecordingTcp::new(tcp));
    let mut preface = [0_u8; CLIENT_PREFACE.len()];
    stream.read_exact(&mut preface)?;
    if preface != CLIENT_PREFACE {
        return Err("client sent an invalid HTTP/2 preface".into());
    }

    write_frame(&mut stream, 4, 0, 0, &[])?;
    stream.flush()?;
    wait_for_request(&mut stream, 1)?;
    stream.flush()?;

    let baseline = stream.sock.outbound.len();
    validate_record_boundaries(&stream.sock.outbound[..baseline])?;
    write_frame(&mut stream, 1, 4, 1, &[0x88])?;
    write_frame(&mut stream, 0, 1, 1, &record_shape_body())?;
    stream.flush()?;

    let response_end = stream.sock.outbound.len();
    let records = tls_records(&stream.sock.outbound[baseline..response_end])?;
    let application: Vec<_> = records
        .into_iter()
        .filter_map(|record| (record.content_type == 23).then_some(record.payload_len))
        .collect();
    if application.is_empty() {
        return Err("record-shape response produced no TLS application records".into());
    }
    if application
        .iter()
        .any(|length| *length > TLS13_RECORD_PAYLOAD_BOUND)
    {
        return Err("record-shape response exceeded the configured TLS fragment bound".into());
    }

    wait_for_request(&mut stream, 3)?;
    write_frame(&mut stream, 1, 4, 3, &[0x88])?;
    write_frame(&mut stream, 0, 1, 3, FOLLOWUP_BODY)?;
    stream.flush()?;

    Ok(RecordShapeObservation {
        application_records: application.len(),
        max_application_payload: application.iter().copied().max().unwrap_or_default(),
        capture_overflowed: stream.sock.capture_overflowed,
    })
}

fn record_shape_body() -> Vec<u8> {
    let mut body = Vec::from(
        "<!doctype html><meta charset=utf-8><pre id=result>waiting…</pre><script>fetch('/.well-known/reaper/record-shape',{cache:'no-store'}).then(r=>r.text()).then(t=>result.textContent=t).catch(e=>result.textContent='probe failed: '+e)</script><!--"
            .as_bytes(),
    );
    body.resize(RESPONSE_BODY_LEN, b'R');
    body.extend_from_slice(b"-->");
    body
}

fn wait_for_request(
    stream: &mut StreamOwned<ServerConnection, RecordingTcp>,
    expected_stream_id: u32,
) -> TestResult<()> {
    for _ in 0..MAX_PROBE_FRAMES {
        let frame = read_frame(stream)?;
        match frame.kind {
            4 if frame.flags & 1 == 0 => {
                if frame.stream_id != 0 || frame.payload_len % 6 != 0 {
                    return Err("client sent an invalid SETTINGS frame".into());
                }
                write_frame(stream, 4, 1, 0, &[])?;
            }
            1 if frame.stream_id == expected_stream_id => {
                consume_continuations(stream, &frame)?;
                return Ok(());
            }
            _ => {}
        }
    }
    Err(format!("client did not send request stream {expected_stream_id}").into())
}

fn consume_continuations(
    stream: &mut StreamOwned<ServerConnection, RecordingTcp>,
    first: &RawFrame,
) -> TestResult<()> {
    if first.flags & 4 != 0 {
        return Ok(());
    }
    loop {
        let frame = read_frame(stream)?;
        if frame.kind != 9 || frame.stream_id != first.stream_id {
            return Err("client interrupted an HTTP/2 header block".into());
        }
        if frame.flags & 4 != 0 {
            return Ok(());
        }
    }
}

fn read_frame(stream: &mut StreamOwned<ServerConnection, RecordingTcp>) -> TestResult<RawFrame> {
    let mut header = [0_u8; 9];
    stream.read_exact(&mut header)?;
    let payload_len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    if payload_len > MAX_FRAME_LENGTH {
        return Err("client frame exceeds the test peer bound".into());
    }
    let mut payload = vec![0_u8; payload_len];
    stream.read_exact(&mut payload)?;
    Ok(RawFrame {
        kind: header[3],
        flags: header[4],
        stream_id: u32::from_be_bytes(header[5..9].try_into()?) & 0x7fff_ffff,
        payload_len,
    })
}

fn write_frame(
    stream: &mut StreamOwned<ServerConnection, RecordingTcp>,
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload: &[u8],
) -> TestResult<()> {
    let length = u32::try_from(payload.len())?;
    if length > 0x00ff_ffff {
        return Err("test frame exceeds the HTTP/2 length field".into());
    }
    let mut header = [0_u8; 9];
    header[..3].copy_from_slice(&length.to_be_bytes()[1..]);
    header[3] = kind;
    header[4] = flags;
    header[5..].copy_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    stream.write_all(&header)?;
    stream.write_all(payload)?;
    Ok(())
}

fn validate_record_boundaries(bytes: &[u8]) -> TestResult<()> {
    tls_records(bytes).map(drop)
}

fn tls_records(bytes: &[u8]) -> TestResult<Vec<TlsRecord>> {
    let mut records = Vec::new();
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let header = bytes
            .get(offset..offset + 5)
            .ok_or("captured TLS record has a truncated header")?;
        let payload_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let end = offset
            .checked_add(5)
            .and_then(|value| value.checked_add(payload_len))
            .ok_or("captured TLS record length overflowed")?;
        if end > bytes.len() {
            return Err("captured TLS record has a truncated payload".into());
        }
        records.push(TlsRecord {
            content_type: header[0],
            payload_len,
        });
        offset = end;
    }
    Ok(records)
}

struct RecordingTcp {
    inner: StdTcpStream,
    outbound: Vec<u8>,
    capture_overflowed: bool,
}

impl RecordingTcp {
    fn new(inner: StdTcpStream) -> Self {
        Self {
            inner,
            outbound: Vec::new(),
            capture_overflowed: false,
        }
    }

    fn record(&mut self, bytes: &[u8]) {
        let remaining = MAX_CAPTURE_BYTES.saturating_sub(self.outbound.len());
        let retained = bytes.len().min(remaining);
        self.outbound.extend_from_slice(&bytes[..retained]);
        self.capture_overflowed |= retained != bytes.len();
    }
}

impl Read for RecordingTcp {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buffer)
    }
}

impl Write for RecordingTcp {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.record(&buffer[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct RawFrame {
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload_len: usize,
}

struct TlsRecord {
    content_type: u8,
    payload_len: usize,
}

struct RecordShapeObservation {
    application_records: usize,
    max_application_payload: usize,
    capture_overflowed: bool,
}
