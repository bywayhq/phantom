//! Minimal RFC 9298 CONNECT-UDP test proxies and HTTP/3 origin helpers.
//!
//! [`MasqueProxy`] is Hyperium's `h3` server with extended CONNECT and HTTP/3
//! Datagrams enabled. [`MasqueStreamProxy`] is a TLS proxy that accepts
//! HTTP/1.1 Upgrade or HTTP/2 extended CONNECT and carries DATAGRAM capsules
//! on the request stream. Both relay Context ID zero payloads to one
//! connected local UDP socket per request.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard},
};

use std::future::poll_fn;

use bytes::{Buf, Bytes, BytesMut};
use http::{Response, StatusCode};
use phantom::profile::{Http3ClientSettings, Http3PseudoHeader, Http3RequestSettings, chromium};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::{mpsc, watch},
    task::JoinHandle,
};

use crate::h3_support::client_settings;
use crate::tls_support::{
    H1_ALPN, H2_ALPN, TestIdentity, TestResult, accept_tls_stream, is_peer_gone, read_head,
};

/// Largest datagram the relay reads from the origin socket.
const MAX_UDP_PAYLOAD: usize = 65_527;
/// Unknown capsule type sent before relaying; clients must skip it.
const UNKNOWN_CAPSULE: &[u8] = &[0x2a, 0x03, b'x', b'y', b'z'];
/// Unknown Context ID datagram sent before relaying; clients must drop it.
const UNKNOWN_CONTEXT_PAYLOAD: &[u8] = b"\x02unknown-context";
/// Basic challenge realm sent by the authentication modes.
const CHALLENGE: &str = "Basic realm=\"masque\"";

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
    /// Answer 407 with a Basic challenge unless the request carries
    /// `proxy-authorization`, then relay.
    Challenge,
    /// Answer every request with 407 and a Basic challenge.
    AlwaysChallenge,
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
    /// Names of fields the peer encoded as never-indexed literals.
    pub(crate) sensitive: Vec<String>,
}

impl ObservedConnectUdp {
    fn authorized(&self) -> bool {
        self.fields
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("proxy-authorization"))
    }
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
        Self::spawn_with_session_storage(identity, mode, None)
    }

    /// A proxy whose TLS server keeps its resumable sessions in `storage`.
    pub(crate) fn spawn_with_session_storage(
        identity: &TestIdentity,
        mode: ProxyMode,
        storage: Option<Arc<dyn rustls::server::StoresServerSessions>>,
    ) -> TestResult<Self> {
        let (address, endpoint) = relay_endpoint(identity, storage)?;
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
        sensitive: request
            .headers()
            .iter()
            .filter(|(_, value)| value.is_sensitive())
            .map(|(name, _)| name.as_str().to_owned())
            .collect(),
    };
    lock(&log).requests.push(observed.clone());
    let answer = match mode {
        ProxyMode::Reject(status) => Some((status, false)),
        ProxyMode::AlwaysChallenge => Some((407, true)),
        ProxyMode::Challenge if !observed.authorized() => Some((407, true)),
        _ => None,
    };
    if let Some((status, challenge)) = answer {
        let mut response = Response::builder().status(status);
        if challenge {
            response = response.header("proxy-authenticate", CHALLENGE);
        }
        stream.send_response(response.body(())?).await?;
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
fn relay_endpoint(
    identity: &TestIdentity,
    storage: Option<Arc<dyn rustls::server::StoresServerSessions>>,
) -> TestResult<(SocketAddr, quinn::Endpoint)> {
    let certificate = CertificateDer::from(identity.leaf_der().to_vec());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        identity.private_key_der().to_vec(),
    ));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    if let Some(storage) = storage {
        tls.session_storage = storage;
    }
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
    let mut settings = chromium::v154_http3_request();
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

/// Protocol spoken by [`MasqueStreamProxy`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StreamLeg {
    /// RFC 9298 section 3.2 HTTP/1.1 Upgrade.
    Http1,
    /// RFC 9298 section 3.4 HTTP/2 extended CONNECT.
    Http2,
}

/// How [`MasqueStreamProxy`] answers each request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StreamMode {
    /// Accept CONNECT-UDP and relay DATAGRAM capsules.
    Relay,
    /// Answer every request with this final status.
    Reject(u16),
    /// Answer 407 with a Basic challenge unless the request carries
    /// `Proxy-Authorization`, then relay.
    Challenge,
    /// Answer every request with 407 and a Basic challenge.
    AlwaysChallenge,
    /// HTTP/2: omit `SETTINGS_ENABLE_CONNECT_PROTOCOL`.
    WithoutExtendedConnect,
    /// HTTP/1.1: answer 200 instead of 101.
    OkInsteadOfUpgrade,
}

/// One request and the client's capsule framing as the stream proxy saw it.
#[derive(Clone, Debug, Default)]
pub(crate) struct ObservedStreamRequest {
    pub(crate) method: String,
    pub(crate) protocol: Option<String>,
    pub(crate) scheme: Option<String>,
    pub(crate) authority: Option<String>,
    pub(crate) path: String,
    pub(crate) fields: Vec<(String, Vec<u8>)>,
    /// The exact HTTP/1.1 request head.
    pub(crate) head: Option<Vec<u8>>,
}

#[derive(Default)]
struct StreamLog {
    connections: usize,
    requests: Vec<ObservedStreamRequest>,
    /// Type, Context ID, and value length of each client capsule.
    client_capsules: Vec<(u64, Option<u64>, usize)>,
}

/// A running HTTP/1.1 or HTTP/2 CONNECT-UDP proxy; aborted on drop.
pub(crate) struct MasqueStreamProxy {
    pub(crate) address: SocketAddr,
    log: Arc<Mutex<StreamLog>>,
    task: JoinHandle<()>,
}

impl MasqueStreamProxy {
    pub(crate) async fn spawn(
        identity: &TestIdentity,
        leg: StreamLeg,
        mode: StreamMode,
    ) -> TestResult<Self> {
        let alpn = match leg {
            StreamLeg::Http1 => H1_ALPN,
            StreamLeg::Http2 => H2_ALPN,
        };
        Self::spawn_with_alpn(identity, leg, mode, alpn).await
    }

    /// Spawns a proxy whose TLS server selects only from `alpn`.
    pub(crate) async fn spawn_with_alpn(
        identity: &TestIdentity,
        leg: StreamLeg,
        mode: StreamMode,
        alpn: &'static [u8],
    ) -> TestResult<Self> {
        let acceptor = identity.acceptor(alpn)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let log = Arc::new(Mutex::new(StreamLog::default()));
        let task_log = Arc::clone(&log);
        let task = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                lock(&task_log).connections += 1;
                let log = Arc::clone(&task_log);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(stream) = accept_tls_stream(tcp, acceptor).await else {
                        return;
                    };
                    let _ = match leg {
                        StreamLeg::Http1 => serve_http1(stream, mode, log).await,
                        StreamLeg::Http2 => serve_http2(stream, mode, log).await,
                    };
                });
            }
        });
        Ok(Self { address, log, task })
    }

    pub(crate) fn template(&self) -> String {
        format!(
            "https://127.0.0.1:{}/.well-known/masque/udp/{{target_host}}/{{target_port}}/",
            self.address.port()
        )
    }

    pub(crate) fn connections(&self) -> usize {
        lock(&self.log).connections
    }

    pub(crate) fn requests(&self) -> Vec<ObservedStreamRequest> {
        lock(&self.log).requests.clone()
    }

    pub(crate) fn client_capsules(&self) -> Vec<(u64, Option<u64>, usize)> {
        lock(&self.log).client_capsules.clone()
    }
}

impl Drop for MasqueStreamProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

enum Answer {
    Status(u16, bool),
    Ok200,
    Relay,
}

fn answer(mode: StreamMode, authorized: bool) -> Answer {
    match mode {
        StreamMode::Reject(status) => Answer::Status(status, false),
        StreamMode::AlwaysChallenge => Answer::Status(407, true),
        StreamMode::Challenge if !authorized => Answer::Status(407, true),
        StreamMode::OkInsteadOfUpgrade => Answer::Ok200,
        _ => Answer::Relay,
    }
}

async fn serve_http1<S>(
    mut stream: S,
    mode: StreamMode,
    log: Arc<Mutex<StreamLog>>,
) -> TestResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let head = read_head(&mut stream).await?;
    let text = String::from_utf8(head.clone())?;
    let mut lines = text.split("\r\n");
    let mut request_line = lines.next().ok_or("empty request head")?.split(' ');
    let method = request_line.next().unwrap_or_default().to_owned();
    let path = request_line.next().unwrap_or_default().to_owned();
    let fields = lines
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(": "))
        .map(|(name, value)| (name.to_owned(), value.as_bytes().to_vec()))
        .collect::<Vec<_>>();
    let observed = ObservedStreamRequest {
        method,
        authority: fields
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("host"))
            .map(|(_, value)| String::from_utf8_lossy(value).into_owned()),
        path,
        fields,
        head: Some(head),
        ..ObservedStreamRequest::default()
    };
    let authorized = observed
        .fields
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("proxy-authorization"));
    let target = parse_target(&observed.path);
    lock(&log).requests.push(observed);
    match answer(mode, authorized) {
        Answer::Status(status, challenge) => {
            let challenge = if challenge {
                format!("Proxy-Authenticate: {CHALLENGE}\r\n")
            } else {
                String::new()
            };
            stream
                .write_all(
                    format!("HTTP/1.1 {status} Refused\r\n{challenge}Content-Length: 0\r\n\r\n")
                        .as_bytes(),
                )
                .await?;
            stream.flush().await?;
            hold_until_closed(stream).await;
            Ok(())
        }
        Answer::Ok200 => {
            stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
            stream.flush().await?;
            hold_until_closed(stream).await;
            Ok(())
        }
        Answer::Relay => {
            let target = target.ok_or("CONNECT-UDP path has no target")?;
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\
                      Upgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n",
                )
                .await?;
            let (inbound_tx, inbound) = mpsc::channel(64);
            let (outbound, mut outbound_rx) = mpsc::channel::<Bytes>(64);
            let (mut reader, mut writer) = tokio::io::split(stream);
            tokio::spawn(async move {
                let mut buffer = vec![0; 16 * 1024];
                while let Ok(count) = reader.read(&mut buffer).await {
                    if count == 0
                        || inbound_tx
                            .send(Bytes::copy_from_slice(&buffer[..count]))
                            .await
                            .is_err()
                    {
                        break;
                    }
                }
            });
            tokio::spawn(async move {
                while let Some(bytes) = outbound_rx.recv().await {
                    match writer.write_all(&bytes).await {
                        Ok(()) => {}
                        Err(error) if is_peer_gone(&error) => return,
                        Err(_) => return,
                    }
                    if writer.flush().await.is_err() {
                        return;
                    }
                }
            });
            relay_capsules(inbound, outbound, target, log).await
        }
    }
}

async fn serve_http2<S>(stream: S, mode: StreamMode, log: Arc<Mutex<StreamLog>>) -> TestResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = ::http2::server::Builder::new();
    if mode != StreamMode::WithoutExtendedConnect {
        builder.enable_connect_protocol();
    }
    let mut connection = builder.handshake::<_, Bytes>(stream).await?;
    let Some(accepted) = connection.accept().await else {
        return Ok(());
    };
    let (request, mut respond) = accepted?;
    let observed = ObservedStreamRequest {
        method: request.method().to_string(),
        protocol: request
            .extensions()
            .get::<::http2::ext::Protocol>()
            .map(|protocol| protocol.as_str().to_owned()),
        scheme: request.uri().scheme_str().map(str::to_owned),
        authority: request.uri().authority().map(ToString::to_string),
        path: request
            .uri()
            .path_and_query()
            .map_or_else(String::new, |value| value.as_str().to_owned()),
        fields: request
            .extensions()
            .get::<::http2::ext::OrderedHeaders>()
            .map(|headers| {
                headers
                    .as_slice()
                    .iter()
                    .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
                    .collect()
            })
            .unwrap_or_default(),
        head: None,
    };
    let authorized = observed
        .fields
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("proxy-authorization"));
    let target = parse_target(&observed.path);
    lock(&log).requests.push(observed);
    match answer(mode, authorized) {
        Answer::Status(status, challenge) => {
            let mut response = Response::builder().status(status);
            if challenge {
                response = response.header("proxy-authenticate", CHALLENGE);
            }
            respond.send_response(response.body(())?, true)?;
            while let Some(Ok(_)) = connection.accept().await {}
            Ok(())
        }
        Answer::Ok200 | Answer::Relay => {
            let target = target.ok_or("CONNECT-UDP path has no target")?;
            let mut send = respond.send_response(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("capsule-protocol", "?1")
                    .body(())?,
                false,
            )?;
            let mut body = request.into_body();
            tokio::spawn(async move { while let Some(Ok(_)) = connection.accept().await {} });
            let (inbound_tx, inbound) = mpsc::channel(64);
            let (outbound, mut outbound_rx) = mpsc::channel::<Bytes>(64);
            tokio::spawn(async move {
                while let Some(Ok(chunk)) = body.data().await {
                    let _ = body.flow_control().release_capacity(chunk.len());
                    if inbound_tx.send(chunk).await.is_err() {
                        break;
                    }
                }
            });
            tokio::spawn(async move {
                while let Some(mut chunk) = outbound_rx.recv().await {
                    while !chunk.is_empty() {
                        send.reserve_capacity(chunk.len());
                        let capacity = match poll_fn(|context| send.poll_capacity(context)).await {
                            Some(Ok(capacity)) => capacity,
                            _ => return,
                        };
                        let part = chunk.split_to(capacity.min(chunk.len()));
                        if send.send_data(part, false).is_err() {
                            return;
                        }
                    }
                }
            });
            relay_capsules(inbound, outbound, target, log).await
        }
    }
}

/// Reads until the client closes, so no response bytes are lost to a reset.
async fn hold_until_closed<S: AsyncRead + Unpin>(mut stream: S) {
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read_to_end(&mut rest),
    )
    .await;
}

/// Relays DATAGRAM capsules between the client stream and one UDP target.
///
/// An unknown capsule and an unknown-Context-ID DATAGRAM capsule are sent
/// first; clients must skip and drop them (RFC 9297 section 3.2; RFC 9298
/// section 4).
async fn relay_capsules(
    mut inbound: mpsc::Receiver<Bytes>,
    outbound: mpsc::Sender<Bytes>,
    target: SocketAddr,
    log: Arc<Mutex<StreamLog>>,
) -> TestResult<()> {
    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    udp.connect(target).await?;
    let mut preamble = UNKNOWN_CAPSULE.to_vec();
    preamble.extend(encode_capsule(0, UNKNOWN_CONTEXT_PAYLOAD));
    outbound.send(Bytes::from(preamble)).await?;
    let mut pending = Vec::new();
    let mut buffer = vec![0; MAX_UDP_PAYLOAD];
    loop {
        tokio::select! {
            received = inbound.recv() => {
                let Some(bytes) = received else { break };
                pending.extend_from_slice(&bytes);
                while let Some((capsule_type, value, used)) = decode_capsule(&pending) {
                    pending.drain(..used);
                    let value_len = value.len();
                    let mut payload = Bytes::from(value);
                    let context = if capsule_type == 0 { decode_varint(&mut payload) } else { None };
                    lock(&log).client_capsules.push((capsule_type, context, value_len));
                    if capsule_type == 0 && context == Some(0) {
                        let _ = udp.send(&payload).await;
                    }
                }
            }
            received = udp.recv(&mut buffer) => match received {
                Ok(count) => {
                    let mut value = vec![0];
                    value.extend_from_slice(&buffer[..count]);
                    if outbound.send(Bytes::from(encode_capsule(0, &value))).await.is_err() {
                        break;
                    }
                }
                // Windows reports an earlier ICMP port-unreachable here.
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                Err(_) => break,
            },
        }
    }
    Ok(())
}

fn encode_capsule(capsule_type: u64, value: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(value.len() + 8);
    encode_varint(capsule_type, &mut output);
    encode_varint(value.len() as u64, &mut output);
    output.extend_from_slice(value);
    output
}

/// Returns one complete capsule's type, value, and encoded length.
fn decode_capsule(input: &[u8]) -> Option<(u64, Vec<u8>, usize)> {
    let mut cursor = Bytes::copy_from_slice(&input[..input.len().min(16)]);
    let before = cursor.len();
    let capsule_type = decode_varint(&mut cursor)?;
    let length = usize::try_from(decode_varint(&mut cursor)?).ok()?;
    let header = before - cursor.len();
    let end = header.checked_add(length)?;
    (input.len() >= end).then(|| (capsule_type, input[header..end].to_vec(), end))
}
