use std::{
    io::{Read, Write},
    net::{TcpListener as StdTcpListener, TcpStream as StdTcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use btls::ssl::{
    AlpnError, Ssl, SslKeyUpdateRequest, SslMessageContentType, SslMessageDirection, SslVersion,
    select_next_proto,
};
use bytes::Bytes;
use http_body_util::BodyExt;
use phantom_profile::{NamedGroup, TlsVersion, chromium::v152_http2};

use super::{
    H2_ALPN_WIRE, Http2TlsConnector, TEST_AUTHORITY, TEST_SERVER_NAME, TestIdentity, TestResult,
    bounded_tls_test, tls_settings,
};
use crate::http2::{Http2Connection, OriginForm};

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const PING_PAYLOAD: &[u8] = b"PHANTOMK";
const REQUESTED_KEY_UPDATE: &[u8] = &[24, 0, 0, 1, 1];
const NOT_REQUESTED_KEY_UPDATE: &[u8] = &[24, 0, 0, 1, 0];
const MAX_FRAME_LENGTH: usize = 64 * 1024;
const MAX_PROBE_FRAMES: usize = 128;

#[tokio::test]
async fn requested_key_update_preserves_http2_connection() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let key_updates = Arc::new(ObservedKeyUpdates::default());
        let mut acceptor = identity.acceptor_builder()?;
        acceptor.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        acceptor.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        acceptor.set_alpn_select_callback(|_, offered| {
            select_next_proto(H2_ALPN_WIRE, offered).ok_or(AlpnError::NOACK)
        });
        let observed = Arc::clone(&key_updates);
        acceptor.set_msg_callback(move |_, message| {
            if message.content_type != SslMessageContentType::HANDSHAKE {
                return;
            }
            if message.data.first() == Some(&24) {
                match message.direction {
                    SslMessageDirection::Write => {
                        observed.written_total.fetch_add(1, Ordering::Relaxed);
                    }
                    SslMessageDirection::Read => {
                        observed.read_total.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            if message.direction == SslMessageDirection::Write
                && message.data == REQUESTED_KEY_UPDATE
            {
                observed.requested.fetch_add(1, Ordering::Relaxed);
            } else if message.direction == SslMessageDirection::Read
                && message.data == NOT_REQUESTED_KEY_UPDATE
            {
                observed.answered.fetch_add(1, Ordering::Relaxed);
            }
        });
        let acceptor = acceptor.build();
        let listener = StdTcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let tcp = tokio::net::TcpStream::connect(address).await?;
        let server = tokio::task::spawn_blocking(move || {
            let (tcp, _) = listener.accept()?;
            tcp.set_read_timeout(Some(super::TEST_TIMEOUT))?;
            tcp.set_write_timeout(Some(super::TEST_TIMEOUT))?;
            let ssl = Ssl::new(acceptor.context())?;
            let stream = ssl.accept(tcp)?;
            serve_key_update_probe(stream)
        });

        let connector = tls13_connector(&identity)?;
        let connection = connector.connect(tcp, TEST_SERVER_NAME).await?;
        assert_response(&connection, "/during-update", b"before-after").await?;
        assert_response(&connection, "/after-update", b"reused").await?;
        drop(connection);
        server.await??;

        assert_eq!(key_updates.written_total.load(Ordering::Relaxed), 1);
        assert_eq!(key_updates.read_total.load(Ordering::Relaxed), 1);
        assert_eq!(key_updates.requested.load(Ordering::Relaxed), 1);
        assert_eq!(key_updates.answered.load(Ordering::Relaxed), 1);
        Ok(())
    })
    .await
}

fn tls13_connector(identity: &TestIdentity) -> TestResult<Http2TlsConnector> {
    let mut tls = tls_settings();
    tls.min_version = TlsVersion::Tls13;
    tls.max_version = TlsVersion::Tls13;
    tls.key_shares = vec![NamedGroup::X25519];
    Ok(Http2TlsConnector::new_with_roots(
        &tls,
        &v152_http2(),
        [identity.root_der()],
    )?)
}

async fn assert_response(
    connection: &Http2Connection,
    path: &str,
    expected: &'static [u8],
) -> TestResult<()> {
    let response = connection
        .send_get(TEST_AUTHORITY, OriginForm::parse(path)?, Vec::new())
        .await?;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.into_body().collect().await?.to_bytes(),
        Bytes::from_static(expected)
    );
    Ok(())
}

fn serve_key_update_probe(mut stream: btls::ssl::SslStream<StdTcpStream>) -> TestResult<()> {
    let mut preface = [0_u8; CLIENT_PREFACE.len()];
    stream.read_exact(&mut preface)?;
    if preface != CLIENT_PREFACE {
        return Err("client sent an invalid HTTP/2 preface".into());
    }

    write_frame(&mut stream, 4, 0, 0, &[])?;
    let mut saw_client_settings = false;
    let mut saw_first_request = false;
    for _ in 0..MAX_PROBE_FRAMES {
        let frame = read_frame(&mut stream)?;
        if frame.kind == 4 && frame.flags & 1 == 0 {
            validate_settings(&frame)?;
            write_frame(&mut stream, 4, 1, 0, &[])?;
            saw_client_settings = true;
        } else if frame.kind == 1 && frame.stream_id == 1 {
            consume_continuations(&mut stream, &frame)?;
            saw_first_request = true;
        }
        if saw_client_settings && saw_first_request {
            break;
        }
    }
    if !saw_client_settings || !saw_first_request {
        return Err("client did not send initial SETTINGS and stream 1".into());
    }
    write_frame(&mut stream, 1, 4, 1, &[0x88])?;
    write_frame(&mut stream, 0, 0, 1, b"before-")?;
    stream.flush()?;

    stream
        .ssl_mut()
        .key_update(SslKeyUpdateRequest::Requested)?;
    write_frame(&mut stream, 6, 0, 0, PING_PAYLOAD)?;
    stream.flush()?;

    let mut saw_ping_ack = false;
    for _ in 0..MAX_PROBE_FRAMES {
        let frame = read_frame(&mut stream)?;
        match frame.kind {
            4 if frame.flags & 1 == 0 => {
                validate_settings(&frame)?;
                write_frame(&mut stream, 4, 1, 0, &[])?;
            }
            6 if frame.flags & 1 != 0 => {
                if frame.stream_id != 0 || frame.payload != PING_PAYLOAD {
                    return Err("client changed the PING acknowledgement payload".into());
                }
                saw_ping_ack = true;
            }
            _ => {}
        }
        if saw_ping_ack {
            break;
        }
    }
    if !saw_ping_ack {
        return Err("client did not acknowledge the KeyUpdate flush PING".into());
    }
    write_frame(&mut stream, 0, 1, 1, b"after")?;
    stream.flush()?;

    let mut saw_second_request = false;
    for _ in 0..MAX_PROBE_FRAMES {
        let frame = read_frame(&mut stream)?;
        if frame.kind == 1 && frame.stream_id == 3 {
            consume_continuations(&mut stream, &frame)?;
            saw_second_request = true;
            break;
        }
        if frame.kind == 4 && frame.flags & 1 == 0 {
            validate_settings(&frame)?;
            write_frame(&mut stream, 4, 1, 0, &[])?;
        }
    }
    if !saw_second_request {
        return Err("client did not reuse the connection on stream 3".into());
    }
    write_response(&mut stream, 3, b"reused")?;
    Ok(())
}

fn consume_continuations(
    stream: &mut btls::ssl::SslStream<StdTcpStream>,
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

fn validate_settings(frame: &RawFrame) -> TestResult<()> {
    if frame.stream_id != 0 || frame.payload.len() % 6 != 0 {
        return Err("client sent an invalid SETTINGS frame".into());
    }
    Ok(())
}

fn write_response(
    stream: &mut btls::ssl::SslStream<StdTcpStream>,
    stream_id: u32,
    body: &[u8],
) -> TestResult<()> {
    write_frame(stream, 1, 4, stream_id, &[0x88])?;
    write_frame(stream, 0, 1, stream_id, body)?;
    stream.flush()?;
    Ok(())
}

fn write_frame(
    stream: &mut btls::ssl::SslStream<StdTcpStream>,
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

fn read_frame(stream: &mut btls::ssl::SslStream<StdTcpStream>) -> TestResult<RawFrame> {
    let mut header = [0_u8; 9];
    stream.read_exact(&mut header)?;
    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    if length > MAX_FRAME_LENGTH {
        return Err("client frame exceeds the test peer bound".into());
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    Ok(RawFrame {
        kind: header[3],
        flags: header[4],
        stream_id: u32::from_be_bytes(header[5..9].try_into()?) & 0x7fff_ffff,
        payload,
    })
}

struct RawFrame {
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

#[derive(Default)]
struct ObservedKeyUpdates {
    written_total: AtomicUsize,
    read_total: AtomicUsize,
    requested: AtomicUsize,
    answered: AtomicUsize,
}
