//! Minimal RFC 9298 CONNECT-UDP test proxy and HTTP/3 origin helpers.
//!
//! The proxy is Hyperium's `h3` server with extended CONNECT and HTTP/3
//! Datagrams enabled. It relays Context ID zero datagrams between the
//! accepted request stream and one connected local UDP socket per request.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard},
};

use bytes::{Buf, Bytes, BytesMut};
use http::{Response, StatusCode};
use phantom::profile::{Http3ClientSettings, Http3PseudoHeader, Http3RequestSettings, chromium};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{net::UdpSocket, sync::watch, task::JoinHandle};

use crate::h3_support::client_settings;
use crate::tls_support::{TestIdentity, TestResult};

/// Largest datagram the relay reads from the origin socket.
const MAX_UDP_PAYLOAD: usize = 65_527;
/// Unknown capsule type sent before relaying; clients must skip it.
const UNKNOWN_CAPSULE: &[u8] = &[0x2a, 0x03, b'x', b'y', b'z'];
/// Unknown Context ID datagram sent before relaying; clients must drop it.
const UNKNOWN_CONTEXT_PAYLOAD: &[u8] = b"\x02unknown-context";

/// How the test proxy answers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProxyMode {
    /// Accept CONNECT-UDP and relay datagrams.
    Relay,
    /// Answer every CONNECT-UDP request with this final status.
    Reject(u16),
    /// Omit `SETTINGS_ENABLE_CONNECT_PROTOCOL`.
    WithoutExtendedConnect,
    /// Omit `SETTINGS_H3_DATAGRAM`.
    WithoutH3Datagram,
}

/// One CONNECT-UDP request as the proxy observed it.
#[derive(Clone, Debug)]
pub(crate) struct ObservedConnectUdp {
    pub(crate) method: String,
    pub(crate) protocol: Option<String>,
    pub(crate) scheme: Option<String>,
    pub(crate) authority: Option<String>,
    pub(crate) path: String,
    pub(crate) fields: Vec<(String, Vec<u8>)>,
}

#[derive(Default)]
struct ProxyLog {
    connections: usize,
    requests: Vec<ObservedConnectUdp>,
}

/// A running CONNECT-UDP proxy; aborted on drop.
pub(crate) struct MasqueProxy {
    pub(crate) address: SocketAddr,
    log: Arc<Mutex<ProxyLog>>,
    close: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl MasqueProxy {
    pub(crate) fn spawn(identity: &TestIdentity, mode: ProxyMode) -> TestResult<Self> {
        let (address, endpoint) = relay_endpoint(identity)?;
        let log = Arc::new(Mutex::new(ProxyLog::default()));
        let (close, close_rx) = watch::channel(false);
        let task_log = Arc::clone(&log);
        let task = tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                lock(&task_log).connections += 1;
                let log = Arc::clone(&task_log);
                let close_rx = close_rx.clone();
                tokio::spawn(async move {
                    let _ = serve_connection(incoming, mode, log, close_rx).await;
                });
            }
        });
        Ok(Self {
            address,
            log,
            close,
            task,
        })
    }

    /// Template for this proxy using the RFC 9298 default path shape.
    pub(crate) fn template(&self) -> String {
        format!(
            "https://127.0.0.1:{}/.well-known/masque/udp/{{target_host}}/{{target_port}}/",
            self.address.port()
        )
    }

    pub(crate) fn connections(&self) -> usize {
        lock(&self.log).connections
    }

    pub(crate) fn requests(&self) -> Vec<ObservedConnectUdp> {
        lock(&self.log).requests.clone()
    }

    /// Closes every open outer QUIC connection.
    pub(crate) fn close_connections(&self) {
        let _ = self.close.send(true);
    }

    /// Accepts outer connections normally again after a close.
    pub(crate) fn reopen(&self) {
        let _ = self.close.send(false);
    }
}

impl Drop for MasqueProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_connection(
    incoming: quinn::Incoming,
    mode: ProxyMode,
    log: Arc<Mutex<ProxyLog>>,
    mut close: watch::Receiver<bool>,
) -> TestResult<()> {
    let quinn = incoming.await?;
    let mut builder = h3::server::builder();
    builder
        .enable_extended_connect(mode != ProxyMode::WithoutExtendedConnect)
        .enable_datagram(mode != ProxyMode::WithoutH3Datagram);
    let mut connection = builder
        .build(h3_quinn::Connection::new(quinn.clone()))
        .await?;
    let Some(resolver) = connection.accept().await? else {
        return Ok(());
    };
    let (request, mut stream) = resolver.resolve_request().await?;
    let observed = ObservedConnectUdp {
        method: request.method().to_string(),
        protocol: request
            .extensions()
            .get::<h3::ext::Protocol>()
            .map(|protocol| protocol.as_str().to_owned()),
        scheme: request.uri().scheme_str().map(str::to_owned),
        authority: request.uri().authority().map(|value| value.to_string()),
        path: request
            .uri()
            .path_and_query()
            .map_or_else(String::new, |value| value.as_str().to_owned()),
        fields: request
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect(),
    };
    lock(&log).requests.push(observed.clone());
    if let ProxyMode::Reject(status) = mode {
        stream
            .send_response(Response::builder().status(status).body(())?)
            .await?;
        stream.finish().await?;
        // Hold the connection until the client closes it.
        let _ = connection.accept().await;
        return Ok(());
    }

    let target = parse_target(&observed.path).ok_or("CONNECT-UDP path has no target")?;
    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    udp.connect(target).await?;
    stream
        .send_response(
            Response::builder()
                .status(StatusCode::OK)
                .header("capsule-protocol", "?1")
                .body(())?,
        )
        .await?;
    stream
        .send_data(Bytes::from_static(UNKNOWN_CAPSULE))
        .await?;
    let quarter_stream_id = stream.id().into_inner() / 4;
    let mut prefix = Vec::new();
    encode_varint(quarter_stream_id, &mut prefix);
    let _ = quinn.send_datagram(datagram(&prefix, UNKNOWN_CONTEXT_PAYLOAD));
    prefix.push(0);

    let mut buffer = vec![0; MAX_UDP_PAYLOAD];
    loop {
        tokio::select! {
            received = quinn.read_datagram() => {
                let Ok(mut payload) = received else { break };
                let Some(stream_id) = decode_varint(&mut payload) else { continue };
                let Some(context) = decode_varint(&mut payload) else { continue };
                if stream_id == quarter_stream_id && context == 0 {
                    let _ = udp.send(&payload).await;
                }
            }
            received = udp.recv(&mut buffer) => match received {
                Ok(count) => {
                    let _ = quinn.send_datagram(datagram(&prefix, &buffer[..count]));
                }
                // Windows reports an earlier ICMP port-unreachable here.
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                Err(_) => break,
            },
            changed = close.changed() => {
                let closed = changed.is_err() || *close.borrow_and_update();
                if closed {
                    quinn.close(0_u32.into(), b"test proxy closed the connection");
                    break;
                }
            }
        }
    }
    drop(stream);
    drop(connection);
    Ok(())
}

fn datagram(prefix: &[u8], payload: &[u8]) -> Bytes {
    let mut datagram = BytesMut::with_capacity(prefix.len() + payload.len());
    datagram.extend_from_slice(prefix);
    datagram.extend_from_slice(payload);
    datagram.freeze()
}

/// Extracts `{target_host}/{target_port}` from the default template path.
fn parse_target(path: &str) -> Option<SocketAddr> {
    let rest = path.strip_prefix("/.well-known/masque/udp/")?;
    let mut parts = rest.trim_end_matches('/').split('/');
    let host = parts.next()?.replace("%3A", ":");
    let port = parts.next()?.parse::<u16>().ok()?;
    let ip = host.parse().ok()?;
    Some(SocketAddr::new(ip, port))
}

fn decode_varint(buffer: &mut Bytes) -> Option<u64> {
    let first = *buffer.first()?;
    let width = 1_usize << (first >> 6);
    if buffer.len() < width {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &buffer[1..width] {
        value = (value << 8) | u64::from(*byte);
    }
    buffer.advance(width);
    Some(value)
}

fn encode_varint(value: u64, output: &mut Vec<u8>) {
    match value {
        0..=63 => output.push(value as u8),
        64..=16_383 => output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        _ => output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes()),
    }
}

/// A QUIC server endpoint whose path MTU carries a full relayed Initial.
fn relay_endpoint(identity: &TestIdentity) -> TestResult<(SocketAddr, quinn::Endpoint)> {
    let certificate = CertificateDer::from(identity.leaf_der().to_vec());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        identity.private_key_der().to_vec(),
    ));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut transport = quinn::TransportConfig::default();
    transport.initial_mtu(1_400).min_mtu(1_400);
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(transport));
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse()?)?;
    Ok((endpoint.local_addr()?, endpoint))
}

/// The H3 test profile with an explicit extended CONNECT pseudo-header order.
pub(crate) fn masque_client_settings() -> Http3ClientSettings {
    let base = client_settings();
    Http3ClientSettings::new(
        base.tls().clone(),
        base.quic_transport().clone(),
        base.http3().clone(),
        extended_request_settings(),
    )
}

pub(crate) fn extended_request_settings() -> Http3RequestSettings {
    let mut settings = chromium::v152_http3_request();
    settings.extended_connect_pseudo_header_order = Some(vec![
        Http3PseudoHeader::Method,
        Http3PseudoHeader::Protocol,
        Http3PseudoHeader::Scheme,
        Http3PseudoHeader::Authority,
        Http3PseudoHeader::Path,
    ]);
    settings
}

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
