use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use btls::ssl::{AlpnError, Ssl, SslVersion, select_next_proto};
use phantom_profile::{TlsVersion, chromium::v152_macos_tls};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_btls::SslStream;

use super::TlsConnector;
use crate::tls::test_support::{
    H2_ALPN_WIRE, TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, loopback_listener,
};

const MAX_CAPTURE_BYTES: usize = 128 * 1024;
const MAX_CLIENT_HELLOS: usize = 2;

#[tokio::test]
async fn authenticated_hello_retry_has_only_permitted_client_hello_delta() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut acceptor = identity.acceptor_builder()?;
    acceptor.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    acceptor.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    acceptor.set_curves_list("P-384")?;
    acceptor.set_alpn_select_callback(|_, offered| {
        select_next_proto(H2_ALPN_WIRE, offered).ok_or(AlpnError::NOACK)
    });
    let acceptor = acceptor.build();
    let (address, listener) = loopback_listener().await?;
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let capture = Arc::new(Mutex::new(Vec::new()));
        let recording = RecordingIo::new(tcp, capture.clone());
        let ssl = Ssl::new(acceptor.context())?;
        let mut stream = SslStream::new(ssl, recording)?;
        tokio::time::timeout(TEST_TIMEOUT, Pin::new(&mut stream).accept()).await??;
        let used_hrr = stream.ssl().used_hello_retry_request();
        drop(stream);
        let bytes = capture
            .lock()
            .map_err(|_| "ClientHello capture lock was poisoned")?
            .clone();
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((used_hrr, bytes))
    });

    let mut settings = v152_macos_tls();
    settings.min_version = TlsVersion::Tls13;
    settings.max_version = TlsVersion::Tls13;
    let connector = TlsConnector::new_with_roots(&settings, [identity.root_der()])?;
    let tcp = tokio::time::timeout(TEST_TIMEOUT, TcpStream::connect(address)).await??;
    let stream =
        tokio::time::timeout(TEST_TIMEOUT, connector.connect(TEST_SERVER_NAME, tcp)).await??;
    assert_eq!(stream.negotiated_tls_version(), Some(TlsVersion::Tls13));
    drop(stream);

    let (used_hrr, wire) = tokio::time::timeout(TEST_TIMEOUT, server).await???;
    assert!(used_hrr, "server did not authenticate a HelloRetryRequest");
    let hellos = extract_client_hellos(&wire);
    assert_eq!(hellos.len(), 2, "capture did not contain two ClientHellos");
    let first = parse_client_hello(&hellos[0]).ok_or("invalid first ClientHello")?;
    let second = parse_client_hello(&hellos[1]).ok_or("invalid second ClientHello")?;

    assert_eq!(first.session_id, second.session_id);
    assert_eq!(first.cipher_suites, second.cipher_suites);
    assert_eq!(
        stable_extensions(&first.extension_ids),
        stable_extensions(&second.extension_ids)
    );
    assert_eq!(non_grease_groups(&first.key_share_groups), [0x11ec, 29]);
    assert_eq!(second.key_share_groups, [24]);
    Ok(())
}

struct RecordingIo<S> {
    inner: S,
    capture: Arc<Mutex<Vec<u8>>>,
}

impl<S> RecordingIo<S> {
    fn new(inner: S, capture: Arc<Mutex<Vec<u8>>>) -> Self {
        Self { inner, capture }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RecordingIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if result.is_ready() && buffer.filled().len() > before {
            let mut capture = match self.capture.lock() {
                Ok(capture) => capture,
                Err(_) => {
                    return Poll::Ready(Err(std::io::Error::other(
                        "ClientHello capture lock was poisoned",
                    )));
                }
            };
            let remaining = MAX_CAPTURE_BYTES.saturating_sub(capture.len());
            capture.extend_from_slice(
                &buffer.filled()[before..][..remaining.min(buffer.filled().len() - before)],
            );
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RecordingIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

struct ClientHelloShape {
    session_id: Vec<u8>,
    cipher_suites: Vec<u8>,
    extension_ids: Vec<u16>,
    key_share_groups: Vec<u16>,
}

fn extract_client_hellos(tls: &[u8]) -> Vec<Vec<u8>> {
    let mut handshake = Vec::new();
    let mut offset = 0usize;
    while offset + 5 <= tls.len() && handshake.len() < MAX_CAPTURE_BYTES {
        let length = usize::from(u16::from_be_bytes([tls[offset + 3], tls[offset + 4]]));
        let Some(end) = offset
            .checked_add(5)
            .and_then(|value| value.checked_add(length))
        else {
            break;
        };
        if end > tls.len() {
            break;
        }
        if tls[offset] == 22 {
            let remaining = MAX_CAPTURE_BYTES.saturating_sub(handshake.len());
            handshake.extend_from_slice(&tls[offset + 5..end][..length.min(remaining)]);
        }
        offset = end;
    }

    let mut hellos = Vec::new();
    let mut cursor = 0usize;
    while cursor + 4 <= handshake.len() && hellos.len() < MAX_CLIENT_HELLOS {
        let length = (usize::from(handshake[cursor + 1]) << 16)
            | (usize::from(handshake[cursor + 2]) << 8)
            | usize::from(handshake[cursor + 3]);
        let Some(end) = cursor
            .checked_add(4)
            .and_then(|value| value.checked_add(length))
        else {
            break;
        };
        if end > handshake.len() {
            break;
        }
        if handshake[cursor] == 1 {
            hellos.push(handshake[cursor + 4..end].to_vec());
        }
        cursor = end;
    }
    hellos
}

fn parse_client_hello(body: &[u8]) -> Option<ClientHelloShape> {
    let mut cursor = 34usize;
    let session_length = usize::from(*body.get(cursor)?);
    cursor += 1;
    let session_id = body
        .get(cursor..cursor.checked_add(session_length)?)?
        .to_vec();
    cursor += session_length;
    let cipher_length = usize::from(read_u16(body, &mut cursor)?);
    let cipher_suites = body
        .get(cursor..cursor.checked_add(cipher_length)?)?
        .to_vec();
    cursor += cipher_length;
    let compression_length = usize::from(*body.get(cursor)?);
    cursor = cursor.checked_add(1 + compression_length)?;
    let extensions_length = usize::from(read_u16(body, &mut cursor)?);
    let end = cursor.checked_add(extensions_length)?;
    if end > body.len() {
        return None;
    }
    let mut extension_ids = Vec::new();
    let mut key_share_groups = Vec::new();
    while cursor + 4 <= end {
        let identifier = read_u16(body, &mut cursor)?;
        let length = usize::from(read_u16(body, &mut cursor)?);
        let extension_end = cursor.checked_add(length)?;
        let data = body.get(cursor..extension_end)?;
        extension_ids.push(identifier);
        if identifier == 51 {
            parse_key_shares(data, &mut key_share_groups)?;
        }
        cursor = extension_end;
    }
    (cursor == end).then_some(ClientHelloShape {
        session_id,
        cipher_suites,
        extension_ids,
        key_share_groups,
    })
}

fn parse_key_shares(data: &[u8], groups: &mut Vec<u16>) -> Option<()> {
    let mut cursor = 0usize;
    let list_length = usize::from(read_u16(data, &mut cursor)?);
    let end = cursor.checked_add(list_length)?;
    if end != data.len() {
        return None;
    }
    while cursor + 4 <= end {
        groups.push(read_u16(data, &mut cursor)?);
        let length = usize::from(read_u16(data, &mut cursor)?);
        cursor = cursor.checked_add(length)?;
        if cursor > end {
            return None;
        }
    }
    (cursor == end).then_some(())
}

fn stable_extensions(identifiers: &[u16]) -> Vec<u16> {
    identifiers
        .iter()
        .copied()
        .filter(|identifier| !matches!(identifier, 21 | 41 | 42 | 44 | 51))
        .collect()
}

fn non_grease_groups(groups: &[u16]) -> Vec<u16> {
    groups
        .iter()
        .copied()
        .filter(|group| group & 0x0f0f != 0x0a0a)
        .collect()
}

fn read_u16(input: &[u8], cursor: &mut usize) -> Option<u16> {
    let bytes = input.get(*cursor..cursor.checked_add(2)?)?;
    *cursor += 2;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}
