//! Minimal RFC 9298 CONNECT-UDP test proxies and HTTP/3 origin helpers.
//!
//! [`MasqueProxy`] is Hyperium's `h3` server with extended CONNECT and HTTP/3
//! Datagrams enabled. [`MasqueStreamProxy`] is a TLS proxy that accepts
//! HTTP/1.1 Upgrade or HTTP/2 extended CONNECT and carries DATAGRAM capsules
//! on the request stream. Both relay Context ID zero payloads to one
//! connected local UDP socket per request.

use std::{
    future::poll_fn,
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use bytes::{Buf, Bytes, BytesMut};
use http::{Response, StatusCode};
use phantom::profile::{
    Http3ClientSettings, Http3PseudoHeader, Http3RequestSettings, browser::chrome,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::{mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

use crate::support::client_certificate::{presented_leaf, rustls_config_requesting};
use crate::support::h3::{client_settings, quic_server};
use crate::support::tls::{
    H1_ALPN, H2_ALPN, TestIdentity, TestResult, accept_tls_stream, is_peer_gone, read_head,
};
use crate::support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup};

#[path = "masque/python_peer.rs"]
pub(crate) mod python_peer;
#[path = "masque/sharing.rs"]
mod sharing;
#[path = "masque/stream_outcomes.rs"]
mod stream_outcomes;

/// Largest datagram the relay reads from the origin socket.
const MAX_UDP_PAYLOAD: usize = 65_527;
// One maximum UDP payload plus the largest encoded Context ID.
const MAX_CAPSULE_PAYLOAD: usize = MAX_UDP_PAYLOAD + 8;
const CAPSULE_CHUNK: usize = 16 * 1024;
const MAX_PENDING_CAPSULE: usize = MAX_CAPSULE_PAYLOAD + 16 + CAPSULE_CHUNK;
const MAX_REJECTED_BODY: usize = 64 * 1024;
const MAX_STREAM_CONNECTIONS: usize = 64;
const MAX_STREAM_REQUESTS: usize = 128;
const MAX_CLIENT_CAPSULES: usize = 4096;
const STREAM_SHUTDOWN: Duration = Duration::from_secs(5);
/// Unknown capsule type sent before relaying; clients must skip it.
const UNKNOWN_CAPSULE: &[u8] = &[0x2a, 0x03, b'x', b'y', b'z'];
/// Unknown Context ID datagram sent before relaying; clients must drop it.
const UNKNOWN_CONTEXT_PAYLOAD: &[u8] = b"\x02unknown-context";
/// Basic challenge realm sent by the authentication modes.
const CHALLENGE: &str = "Basic realm=\"masque\"";

/// How the test proxy answers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProxyMode {
    /// Accept many independently owned streams per outer connection.
    Sharing,
    /// Reset the first stream while retaining the outer connection.
    SharingResetFirst,
    /// Validate Basic credentials and relay many authenticated streams.
    SharingChallenge,
    /// Reset only the first valid authenticated retry, then require a new challenge.
    SharingChallengeResetOnce,
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

pub(crate) struct HeldSetupControl {
    pub(crate) observed: oneshot::Receiver<(usize, u64)>,
    pub(crate) release: oneshot::Sender<()>,
}

struct HeldSetup {
    observed: oneshot::Sender<(usize, u64)>,
    release: oneshot::Receiver<()>,
}

#[derive(Default)]
struct ProxyLog {
    connections: usize,
    requests: Vec<ObservedConnectUdp>,
    origin_datagrams: usize,
    /// Outer connections on which the client presented a certificate.
    client_certificates: usize,
    stream_ids: Vec<(usize, u64)>,
    failures: Vec<Box<dyn std::error::Error + Send + Sync>>,
    held_setup: Option<HeldSetup>,
    authenticated_reset_sent: bool,
}

#[derive(Clone, Copy, Default)]
struct CloseState {
    generation: u64,
    closed: bool,
    shutdown: bool,
}

/// Closing the endpoint is distinct from dropping its last user handle:
/// active connections otherwise keep Quinn's endpoint driver and socket alive.
struct ProxyEndpoint(quinn::Endpoint);

impl Drop for ProxyEndpoint {
    fn drop(&mut self) {
        self.0.close(0_u32.into(), b"test proxy owner dropped");
    }
}

struct ProxyConnection<'a>(&'a quinn::Connection);

impl Drop for ProxyConnection<'_> {
    fn drop(&mut self) {
        self.0
            .close(0_u32.into(), b"test proxy closed the connection");
    }
}

/// A running CONNECT-UDP proxy; aborted on drop.
pub(crate) struct MasqueProxy {
    pub(crate) address: SocketAddr,
    endpoint: quinn::Endpoint,
    log: Arc<Mutex<ProxyLog>>,
    close: watch::Sender<CloseState>,
    task: JoinHandle<()>,
    finished: bool,
}

impl MasqueProxy {
    /// Parks the next sharing CONNECT after parsing, before accepting it.
    pub(crate) fn hold_next_setup(&self) -> TestResult<HeldSetupControl> {
        let mut log = lock(&self.log);
        if log.held_setup.is_some() {
            return Err("MASQUE held setup already installed".into());
        }
        let (observed, received) = oneshot::channel();
        let (release, released) = oneshot::channel();
        log.held_setup = Some(HeldSetup {
            observed,
            release: released,
        });
        Ok(HeldSetupControl {
            observed: received,
            release,
        })
    }

    pub(crate) fn stream_ids(&self) -> Vec<(usize, u64)> {
        lock(&self.log).stream_ids.clone()
    }
    pub(crate) fn spawn(identity: &TestIdentity, mode: ProxyMode) -> TestResult<Self> {
        Self::spawn_with_session_storage(identity, mode, None)
    }

    /// Advertise one actual QUIC bidirectional request stream at a time.
    pub(crate) fn spawn_with_single_bidi_stream(identity: &TestIdentity) -> TestResult<Self> {
        Self::spawn_on(
            relay_endpoint_with_stream_limit(identity, None, Some(1_u8.into()))?,
            ProxyMode::Sharing,
        )
    }

    /// A proxy whose TLS server asks for an optional client certificate
    /// issued by `client_authority` on every outer connection.
    pub(crate) fn spawn_requesting_client_certificates(
        identity: &TestIdentity,
        mode: ProxyMode,
        client_authority: &[u8],
    ) -> TestResult<Self> {
        let tls = rustls_config_requesting(identity, client_authority, false)?;
        Self::spawn_on(relay_endpoint_with(tls)?, mode)
    }

    /// A proxy whose TLS server keeps its resumable sessions in `storage`.
    pub(crate) fn spawn_with_session_storage(
        identity: &TestIdentity,
        mode: ProxyMode,
        storage: Option<Arc<dyn rustls::server::StoresServerSessions>>,
    ) -> TestResult<Self> {
        Self::spawn_on(relay_endpoint(identity, storage)?, mode)
    }

    fn spawn_on(
        (address, endpoint): (SocketAddr, quinn::Endpoint),
        mode: ProxyMode,
    ) -> TestResult<Self> {
        let log = Arc::new(Mutex::new(ProxyLog::default()));
        let (close, mut close_rx) = watch::channel(CloseState::default());
        let task_log = Arc::clone(&log);
        let retained_endpoint = endpoint.clone();
        let task = tokio::spawn(async move {
            let endpoint = ProxyEndpoint(endpoint);
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    changed = close_rx.changed() => {
                        if changed.is_err() || close_rx.borrow().shutdown {
                            break;
                        }
                    }
                    completed = connections.join_next(), if !connections.is_empty() => {
                        match completed {
                            Some(Ok(Ok(()))) | None => {}
                            Some(Ok(Err(error))) => lock(&task_log).failures.push(error),
                            Some(Err(error)) => lock(&task_log).failures.push(error.into()),
                        }
                    }
                    incoming = endpoint.0.accept() => {
                        let Some(incoming) = incoming else { break };
                        lock(&task_log).connections += 1;
                        let log = Arc::clone(&task_log);
                        let close_rx = close_rx.clone();
                        // Snapshot in the accepting owner, before the child can be scheduled.
                        let state = *close_rx.borrow();
                        connections.spawn(serve_connection(incoming, mode, log, close_rx, state));
                    }
                }
            }
            endpoint.0.close(0_u32.into(), b"test proxy finishing");
            while let Some(completed) = connections.join_next().await {
                match completed {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => lock(&task_log).failures.push(error),
                    Err(error) => lock(&task_log).failures.push(error.into()),
                }
            }
        });
        Ok(Self {
            address,
            endpoint: retained_endpoint,
            log,
            close,
            task,
            finished: false,
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

    /// Returns how many outer connections presented a client certificate.
    pub(crate) fn client_certificates(&self) -> usize {
        lock(&self.log).client_certificates
    }

    /// Takes completed background failures without turning them into a quiet result.
    pub(crate) fn take_failures(&self) -> Vec<Box<dyn std::error::Error + Send + Sync>> {
        std::mem::take(&mut lock(&self.log).failures)
    }

    /// Stops accepting, joins every connection child and retains typed failures.
    pub(crate) async fn finish(&mut self) -> TestResult<()> {
        let mut result = Ok(());
        if !self.finished {
            self.close.send_modify(|state| state.shutdown = true);
            match timeout(STREAM_SHUTDOWN, &mut self.task).await {
                Ok(joined) => {
                    self.finished = true;
                    result = joined.map_err(Into::into);
                }
                Err(error) => result = Err(error.into()),
            }
        }
        for error in self.take_failures() {
            result = finish_with_cleanup(result, Err(error));
        }
        result
    }

    /// Closes existing connections and waits for their QUIC drainage.
    /// Reopen explicitly before starting a replacement connection.
    pub(crate) async fn close_connections_and_wait(&self) -> TestResult<()> {
        self.close_connections();
        timeout(STREAM_SHUTDOWN, self.endpoint.wait_idle()).await?;
        Ok(())
    }

    /// Closes every open outer QUIC connection.
    pub(crate) fn close_connections(&self) {
        self.close.send_modify(|state| {
            state.generation = state.generation.wrapping_add(1);
            state.closed = true;
        });
    }

    /// Accepts outer connections normally again after a close.
    pub(crate) fn reopen(&self) {
        self.close.send_modify(|state| state.closed = false);
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
    mut close: watch::Receiver<CloseState>,
    initial: CloseState,
) -> TestResult<()> {
    let quinn = tokio::select! {
        biased;
        () = connection_closed(&mut close, initial) => return Ok(()),
        connected = incoming => connected?,
    };
    if presented_leaf(&quinn).is_some() {
        lock(&log).client_certificates += 1;
    }

    if matches!(
        mode,
        ProxyMode::Sharing
            | ProxyMode::SharingChallenge
            | ProxyMode::SharingChallengeResetOnce
            | ProxyMode::SharingResetFirst
    ) {
        let _connection = ProxyConnection(&quinn);
        return sharing::serve_h3(&quinn, mode, log, close, initial).await;
    }

    let serving = serve_connected(&quinn, mode, log);
    tokio::pin!(serving);
    // This guard drops before the pinned serving future: H3's own Drop sends
    // H3_NO_ERROR, which must not replace the proxy's explicit QUIC close.
    let _connection = ProxyConnection(&quinn);

    // Keep serving pinned through this branch so explicit close precedes H3
    // teardown, including cancellation during its nested setup/relay awaits.
    tokio::select! {
        biased;
        () = connection_closed(&mut close, initial) => {
            quinn.close(0_u32.into(), b"test proxy closed the connection");
            Ok(())
        }
        result = &mut serving => result,
    }
}

async fn connection_closed(close: &mut watch::Receiver<CloseState>, initial: CloseState) {
    loop {
        let state = *close.borrow_and_update();
        if initial.closed
            || state.closed
            || state.shutdown
            || state.generation != initial.generation
        {
            return;
        }
        if close.changed().await.is_err() {
            return;
        }
    }
}

async fn serve_connected(
    quinn: &quinn::Connection,
    mode: ProxyMode,
    log: Arc<Mutex<ProxyLog>>,
) -> TestResult<()> {
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
        match connection.accept().await {
            Ok(None) => {}
            // The rejection test peer deliberately closes QUIC with code zero.
            Err(h3::error::ConnectionError::Remote(
                h3::quic::ConnectionErrorIncoming::ApplicationClose { error_code: 0 },
                ..,
            )) => {}
            Err(error) => return Err(error.into()),
            Ok(Some(_)) => return Err("unexpected second CONNECT-UDP request".into()),
        }
        return Ok(());
    }

    let target = parse_target(&observed.path).ok_or("CONNECT-UDP path has no loopback target")?;
    let udp = phantom_testkit::udp::bind_tokio("127.0.0.1:0".parse()?)?;
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
    quinn.send_datagram(datagram(&prefix, UNKNOWN_CONTEXT_PAYLOAD))?;
    prefix.push(0);

    let mut buffer = vec![0; MAX_UDP_PAYLOAD];
    loop {
        tokio::select! {
            received = quinn.read_datagram() => {
                let mut payload = received?;
                let Some(stream_id) = decode_varint(&mut payload) else { continue };
                let Some(context) = decode_varint(&mut payload) else { continue };
                if stream_id == quarter_stream_id && context == 0 {
                    udp.send(&payload).await?;
                }
            }
            received = udp.recv(&mut buffer) => match received {
                Ok(count) => {
                    lock(&log).origin_datagrams += 1;
                    match quinn.send_datagram(datagram(&prefix, &buffer[..count])) {
                        Ok(()) => {}
                        // RFC 9298 section 6.1: a payload that cannot fit the
                        // outer QUIC datagram is dropped without ending the tunnel.
                        Err(quinn::SendDatagramError::TooLarge) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                // Windows reports an earlier ICMP port-unreachable here.
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                Err(error) => return Err(error.into()),
            },
        }
    }
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
    let ip: IpAddr = host.parse().ok()?;
    ip.is_loopback().then_some(SocketAddr::new(ip, port))
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
        16_384..=1_073_741_823 => {
            output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes())
        }
        _ => output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

/// A QUIC server endpoint whose path MTU carries a full relayed Initial.
fn relay_endpoint(
    identity: &TestIdentity,
    storage: Option<Arc<dyn rustls::server::StoresServerSessions>>,
) -> TestResult<(SocketAddr, quinn::Endpoint)> {
    relay_endpoint_with_stream_limit(identity, storage, None)
}

fn relay_endpoint_with_stream_limit(
    identity: &TestIdentity,
    storage: Option<Arc<dyn rustls::server::StoresServerSessions>>,
    bidi_stream_limit: Option<quinn::VarInt>,
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
    relay_endpoint_with_settings(tls, bidi_stream_limit)
}

/// A QUIC server endpoint for `tls` whose path MTU carries a full relayed
/// Initial.
fn relay_endpoint_with(tls: rustls::ServerConfig) -> TestResult<(SocketAddr, quinn::Endpoint)> {
    relay_endpoint_with_settings(tls, None)
}

fn relay_endpoint_with_settings(
    tls: rustls::ServerConfig,
    bidi_stream_limit: Option<quinn::VarInt>,
) -> TestResult<(SocketAddr, quinn::Endpoint)> {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut transport = quinn::TransportConfig::default();
    transport.initial_mtu(1_400).min_mtu(1_400);
    if let Some(limit) = bidi_stream_limit {
        transport.max_concurrent_bidi_streams(limit);
    }
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(transport));
    let endpoint = quic_server(config, "127.0.0.1:0".parse()?)?;
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
    let mut settings = chrome::v154_http3_request();
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
    /// Accept many independently owned H2 streams per outer connection.
    Sharing,
    /// Reset the first stream while retaining the outer connection.
    SharingResetFirst,
    /// Validate Basic credentials and relay many authenticated H2 streams.
    SharingChallenge,
    /// Reset only the first valid authenticated retry, then require a new challenge.
    SharingChallengeResetOnce,
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
    completed_connections: usize,
    sharing_connections: usize,
    stream_ids: Vec<(usize, u64)>,
    requests: Vec<ObservedStreamRequest>,
    /// Type, Context ID, and value length of each client capsule.
    client_capsules: Vec<(u64, Option<u64>, usize)>,
    authenticated_reset_sent: bool,
}

/// A running HTTP/1.1 or HTTP/2 CONNECT-UDP proxy; aborted on drop.
pub(crate) struct MasqueStreamProxy {
    pub(crate) address: SocketAddr,
    log: Arc<Mutex<StreamLog>>,
    stopping: watch::Sender<bool>,
    task: Option<ConnectionPeer<TestResult<()>>>,
}

impl MasqueStreamProxy {
    pub(crate) fn stream_ids(&self) -> Vec<(usize, u64)> {
        lock(&self.log).stream_ids.clone()
    }
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
        let (stopping, mut stopped) = watch::channel(false);
        let stop_children = stopping.clone();
        let task = ConnectionPeer::spawn(async move {
            let mut connections = JoinSet::new();
            let mut outcome = Ok(());
            let accepting: TestResult<()> = async {
                loop {
                    tokio::select! {
                        biased;
                        completed = connections.join_next(), if !connections.is_empty() => {
                            let completed = completed.ok_or("MASQUE connection task disappeared")?;
                            lock(&task_log).completed_connections += 1;
                            let completed = match completed {
                                Ok(result) => result,
                                Err(error) => Err(error.into()),
                            };
                            let previous = std::mem::replace(&mut outcome, Ok(()));
                            outcome = finish_with_cleanup(previous, completed);
                        }
                        stopped = stream_outcomes::stopped(&mut stopped) => return stopped,
                        accepted = listener.accept() => {
                            let (tcp, _) = accepted?;
                            if connections.len() == MAX_STREAM_CONNECTIONS {
                                return Err("MASQUE accepted connection limit exceeded".into());
                            }

                            {
                                let mut log = lock(&task_log);
                                if log.connections == MAX_STREAM_REQUESTS {
                                    return Err("MASQUE connection record limit exceeded".into());
                                }
                                log.connections += 1;
                            }

                            let log = Arc::clone(&task_log);
                            let acceptor = acceptor.clone();
                            let mut stopped = stopped.clone();
                            connections.spawn(async move {
                                let stream = tokio::select! {
                                    biased;
                                    stream = accept_tls_stream(tcp, acceptor) => stream?,
                                    stopped = stream_outcomes::stopped(&mut stopped) => return stopped,
                                };

                                match leg {
                                    StreamLeg::Http1 => serve_http1_until(stream, mode, log, stopped).await,
                                    StreamLeg::Http2 => serve_http2_until(stream, mode, log, stopped).await,
                                }
                            });
                        }
                    }
                }
            }
            .await;

            stop_children.send_replace(true);
            outcome = finish_with_cleanup(outcome, accepting);
            while let Some(completed) = connections.join_next().await {
                lock(&task_log).completed_connections += 1;
                let completed = match completed {
                    Ok(result) => result,
                    Err(error) => Err(error.into()),
                };
                outcome = finish_with_cleanup(outcome, completed);
            }
            outcome
        });
        Ok(Self {
            address,
            log,
            stopping,
            task: Some(task),
        })
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

    /// Stops accepting, collects owned connections and keeps an interrupted join retryable.
    pub(crate) async fn shutdown(&mut self) -> TestResult<()> {
        self.stopping.send_replace(true);
        let Some(task) = self.task.as_mut() else {
            return Ok(());
        };

        let joined = timeout(STREAM_SHUTDOWN, task.join()).await?;
        drop(self.task.take());
        joined?
    }
}

impl Drop for MasqueStreamProxy {
    fn drop(&mut self) {
        self.stopping.send_replace(true);
        if let Some(task) = &self.task {
            task.abort();
        }
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

#[cfg(test)]
async fn serve_http1<S>(stream: S, mode: StreamMode, log: Arc<Mutex<StreamLog>>) -> TestResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (_stopping, stopped) = watch::channel(false);
    serve_http1_until(stream, mode, log, stopped).await
}

async fn serve_http1_until<S>(
    mut stream: S,
    mode: StreamMode,
    log: Arc<Mutex<StreamLog>>,
    mut stopped: watch::Receiver<bool>,
) -> TestResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let head = tokio::select! {
        biased;
        head = async {
            let mut first = [0];
            match stream.read(&mut first).await {
                Ok(0) => return Ok(None),
                Ok(_) => {}
                Err(error) if stream_outcomes::peer_gone(&error) => return Ok(None),
                Err(error) => return Err(error),
            }

            let mut input = AsyncReadExt::chain(first.as_slice(), &mut stream);
            read_head(&mut input).await.map(Some)
        } => head?,
        stopped = stream_outcomes::stopped(&mut stopped) => return stopped,
    };
    let Some(head) = head else {
        return Ok(());
    };

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
    record_stream_request(&log, observed)?;

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
            tokio::select! {
                biased;
                result = hold_until_closed(stream) => result,
                stopped = stream_outcomes::stopped(&mut stopped) => stopped,
            }
        }
        Answer::Ok200 => {
            stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
            stream.flush().await?;
            tokio::select! {
                biased;
                result = hold_until_closed(stream) => result,
                stopped = stream_outcomes::stopped(&mut stopped) => stopped,
            }
        }
        Answer::Relay => {
            let target = target.ok_or("CONNECT-UDP path has no loopback target")?;
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\
                      Upgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n",
                )
                .await?;
            let (inbound_tx, inbound) = mpsc::channel(64);
            let (outbound, mut outbound_rx) = mpsc::channel::<Bytes>(64);
            let (mut reader, mut writer) = tokio::io::split(stream);
            // The relay future owns both halves, including on cancellation
            // while a partial capsule keeps the reader waiting for bytes.
            let mut pumps = JoinSet::new();
            pumps.spawn(async move {
                let mut buffer = vec![0; 16 * 1024];
                loop {
                    let count = match reader.read(&mut buffer).await {
                        Ok(0) => return Ok(stream_outcomes::PumpEnd::InputEnded),
                        Ok(count) => count,
                        Err(error) if stream_outcomes::peer_gone(&error) => {
                            return Ok(stream_outcomes::PumpEnd::InputEnded);
                        }
                        Err(error) => return Err(error.into()),
                    };
                    inbound_tx
                        .send(Bytes::copy_from_slice(&buffer[..count]))
                        .await?;
                }
            });
            pumps.spawn(async move {
                while let Some(bytes) = outbound_rx.recv().await {
                    match writer.write_all(&bytes).await {
                        Ok(()) => {}
                        Err(error) if stream_outcomes::peer_gone(&error) => {
                            return Ok(stream_outcomes::PumpEnd::PeerClosed);
                        }
                        Err(error) => return Err(error.into()),
                    }
                    if let Err(error) = writer.flush().await {
                        if stream_outcomes::peer_gone(&error) {
                            return Ok(stream_outcomes::PumpEnd::PeerClosed);
                        }
                        return Err(error.into());
                    }
                }
                Ok(stream_outcomes::PumpEnd::OutputEnded)
            });
            stream_outcomes::relay(
                pumps,
                relay_capsules(inbound, outbound, target, log),
                stopped,
            )
            .await
        }
    }
}

#[cfg(test)]
async fn serve_http2<S>(stream: S, mode: StreamMode, log: Arc<Mutex<StreamLog>>) -> TestResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (_stopping, stopped) = watch::channel(false);
    serve_http2_until(stream, mode, log, stopped).await
}

async fn serve_http2_until<S>(
    stream: S,
    mode: StreamMode,
    log: Arc<Mutex<StreamLog>>,
    mut stopped: watch::Receiver<bool>,
) -> TestResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut stream = BufReader::new(stream);
    let first_read = tokio::select! {
        biased;
        result = stream.fill_buf() => result,
        stopped = stream_outcomes::stopped(&mut stopped) => return stopped,
    };
    match first_read {
        Ok([]) => return Ok(()),
        Ok(_) => {}
        Err(error) if stream_outcomes::peer_gone(&error) => return Ok(()),
        Err(error) => return Err(error.into()),
    }

    if matches!(
        mode,
        StreamMode::Sharing
            | StreamMode::SharingChallenge
            | StreamMode::SharingChallengeResetOnce
            | StreamMode::SharingResetFirst
    ) {
        return sharing::serve_h2(stream, mode, log, stopped).await;
    }
    // A peer may retire after ALPN selection, before any H2 preface. Once
    // its first byte arrives, the H2 parser owns all truncation failures.
    let mut builder = ::http2::server::Builder::new();
    if mode != StreamMode::WithoutExtendedConnect {
        builder.enable_connect_protocol();
    }
    let mut connection = tokio::select! {
        biased;
        result = builder.handshake::<_, Bytes>(stream) => match result {
            Ok(connection) => connection,
            Err(error) if stream_outcomes::h2_peer_closed(&error) => return Ok(()),
            Err(error) => return Err(error.into()),
        },
        stopped = stream_outcomes::stopped(&mut stopped) => return stopped,
    };
    let accepted = tokio::select! {
        biased;
        accepted = connection.accept() => accepted,
        stopped = stream_outcomes::stopped(&mut stopped) => return stopped,
    };
    let Some(accepted) = accepted else {
        return Ok(());
    };
    let (request, mut respond) = match accepted {
        Ok(request) => request,
        Err(error) if stream_outcomes::h2_peer_closed(&error) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
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
    record_stream_request(&log, observed)?;

    match answer(mode, authorized) {
        Answer::Status(status, challenge) => {
            let mut response = Response::builder().status(status);
            if challenge {
                response = response.header("proxy-authenticate", CHALLENGE);
            }
            respond.send_response(response.body(())?, true)?;
            tokio::select! {
                biased;
                accepted = connection.accept() => match accepted {
                    None => Ok(()),
                    Some(Err(error)) if stream_outcomes::h2_peer_closed(&error) => Ok(()),
                    Some(Err(error)) => Err(error.into()),
                    Some(Ok(_)) => Err("unexpected second CONNECT-UDP request".into()),
                },
                stopped = stream_outcomes::stopped(&mut stopped) => stopped,
            }
        }
        Answer::Ok200 | Answer::Relay => {
            let target = target.ok_or("CONNECT-UDP path has no loopback target")?;
            let mut send = respond.send_response(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("capsule-protocol", "?1")
                    .body(())?,
                false,
            )?;
            let mut body = request.into_body();
            // All transport and body pumps share the relay's lifetime.
            let mut pumps = JoinSet::new();
            pumps.spawn(async move {
                match connection.accept().await {
                    None => Ok(stream_outcomes::PumpEnd::PeerClosed),
                    Some(Err(error)) if stream_outcomes::h2_peer_closed(&error) => {
                        Ok(stream_outcomes::PumpEnd::PeerClosed)
                    }
                    Some(Err(error)) => Err(error.into()),
                    Some(Ok(_)) => Err("unexpected second CONNECT-UDP request".into()),
                }
            });
            let (inbound_tx, inbound) = mpsc::channel(64);
            let (outbound, mut outbound_rx) = mpsc::channel::<Bytes>(64);
            pumps.spawn(async move {
                loop {
                    let chunk = match body.data().await {
                        Some(Ok(chunk)) => chunk,
                        None => return Ok(stream_outcomes::PumpEnd::InputEnded),
                        Some(Err(error)) if stream_outcomes::h2_peer_closed(&error) => {
                            return Ok(stream_outcomes::PumpEnd::PeerClosed);
                        }
                        Some(Err(error)) => return Err(error.into()),
                    };
                    body.flow_control().release_capacity(chunk.len())?;
                    inbound_tx.send(chunk).await?;
                }
            });
            pumps.spawn(async move {
                while let Some(mut chunk) = outbound_rx.recv().await {
                    while !chunk.is_empty() {
                        send.reserve_capacity(chunk.len());
                        let capacity = match poll_fn(|context| send.poll_capacity(context)).await {
                            Some(Ok(capacity)) => capacity,
                            Some(Err(error)) if stream_outcomes::h2_peer_closed(&error) => {
                                return Ok(stream_outcomes::PumpEnd::PeerClosed);
                            }
                            Some(Err(error)) => return Err(error.into()),
                            None => {
                                return match poll_fn(|context| send.poll_reset(context)).await {
                                    Ok(::http2::Reason::CANCEL) => {
                                        Ok(stream_outcomes::PumpEnd::PeerClosed)
                                    }
                                    Ok(reason) => {
                                        Err(stream_outcomes::UnexpectedReset(reason).into())
                                    }
                                    Err(error) if stream_outcomes::h2_peer_closed(&error) => {
                                        Ok(stream_outcomes::PumpEnd::PeerClosed)
                                    }
                                    Err(error) => Err(error.into()),
                                };
                            }
                        };
                        let part = chunk.split_to(capacity.min(chunk.len()));
                        if let Err(error) = send.send_data(part, false) {
                            if stream_outcomes::h2_peer_closed(&error) {
                                return Ok(stream_outcomes::PumpEnd::PeerClosed);
                            }
                            return Err(error.into());
                        }
                    }
                }
                Ok(stream_outcomes::PumpEnd::OutputEnded)
            });
            stream_outcomes::relay(
                pumps,
                relay_capsules(inbound, outbound, target, log),
                stopped,
            )
            .await
        }
    }
}

fn record_stream_request(log: &Mutex<StreamLog>, request: ObservedStreamRequest) -> TestResult<()> {
    let mut log = lock(log);
    if log.requests.len() == MAX_STREAM_REQUESTS {
        return Err("MASQUE request record limit exceeded".into());
    }

    log.requests.push(request);
    Ok(())
}

/// Reads until the client closes, so no response bytes are lost to a reset.
async fn hold_until_closed<S: AsyncRead + Unpin>(mut stream: S) -> TestResult<()> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut buffer = [0; 4096];
        let mut received = 0;
        loop {
            let count = match stream.read(&mut buffer).await {
                Ok(0) => return Ok(()),
                Ok(count) => count,
                Err(error) if is_peer_gone(&error) => return Ok(()),
                Err(error) => return Err(error.into()),
            };
            received += count;
            if received > MAX_REJECTED_BODY {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "rejected CONNECT-UDP body exceeds fixture limit",
                )
                .into());
            }
        }
    })
    .await?
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
    let udp = phantom_testkit::udp::bind_tokio("127.0.0.1:0".parse()?)?;
    udp.connect(target).await?;
    let mut preamble = UNKNOWN_CAPSULE.to_vec();
    preamble.extend(encode_capsule(0, UNKNOWN_CONTEXT_PAYLOAD));
    outbound.send(Bytes::from(preamble)).await?;
    let mut pending = Vec::new();
    let mut buffer = vec![0; MAX_UDP_PAYLOAD];
    loop {
        tokio::select! {
            received = inbound.recv() => {
                let Some(bytes) = received else {
                    if !pending.is_empty() {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "CONNECT-UDP stream ended inside a capsule",
                        ).into());
                    }
                    break;
                };
                for chunk in bytes.chunks(CAPSULE_CHUNK) {
                    if pending.len() + chunk.len() > MAX_PENDING_CAPSULE {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "CONNECT-UDP capsule buffer exceeds fixture limit",
                        ).into());
                    }
                    pending.extend_from_slice(chunk);
                    while let Some((capsule_type, value, used)) = decode_capsule(&pending)? {
                        pending.drain(..used);
                        let value_len = value.len();
                        let mut payload = Bytes::from(value);
                        let context = if capsule_type == 0 { decode_varint(&mut payload) } else { None };
                        {
                            let mut log = lock(&log);
                            if log.client_capsules.len() == MAX_CLIENT_CAPSULES {
                                return Err("MASQUE capsule record limit exceeded".into());
                            }
                            log.client_capsules.push((capsule_type, context, value_len));
                        }
                        if capsule_type == 0 && context == Some(0) {
                            udp.send(&payload).await?;
                        }
                    }
                }
            }
            received = udp.recv(&mut buffer) => match received {
                Ok(count) => {
                    let mut value = vec![0];
                    value.extend_from_slice(&buffer[..count]);
                    outbound.send(Bytes::from(encode_capsule(0, &value))).await?;
                }
                // Windows reports an earlier ICMP port-unreachable here.
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                Err(error) => return Err(error.into()),
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
type DecodedCapsule = (u64, Vec<u8>, usize);

fn decode_capsule(input: &[u8]) -> TestResult<Option<DecodedCapsule>> {
    let mut cursor = Bytes::copy_from_slice(&input[..input.len().min(16)]);
    let before = cursor.len();
    let Some(capsule_type) = decode_varint(&mut cursor) else {
        return Ok(None);
    };
    let Some(length) = decode_varint(&mut cursor) else {
        return Ok(None);
    };
    if length > MAX_CAPSULE_PAYLOAD as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CONNECT-UDP capsule payload exceeds fixture limit",
        )
        .into());
    }

    let length = usize::try_from(length)?;
    let header = before - cursor.len();
    let end = header + length;
    Ok((input.len() >= end).then(|| (capsule_type, input[header..end].to_vec(), end)))
}

#[cfg(test)]
#[path = "masque/h3_ownership_controls.rs"]
mod h3_ownership_controls;

#[cfg(test)]
#[path = "masque/input_controls.rs"]
mod input_controls;

#[cfg(test)]
#[path = "masque/stream_ownership_controls.rs"]
mod stream_ownership_controls;

#[cfg(test)]
mod tests {
    use std::{
        future::pending,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use bytes::Bytes;
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
        task::JoinSet,
        time::timeout,
    };

    use super::{
        MasqueStreamProxy, StreamLeg, StreamLog, StreamMode, TestIdentity, TestResult,
        encode_capsule, serve_http1, serve_http2,
    };
    use crate::support::tls::{is_peer_gone, read_head};

    const DEADLINE: Duration = Duration::from_secs(5);

    async fn accepted_proxy() -> TestResult<(MasqueStreamProxy, TcpStream)> {
        let identity = TestIdentity::generate()?;
        let proxy =
            MasqueStreamProxy::spawn(&identity, StreamLeg::Http1, StreamMode::Relay).await?;
        let peer = TcpStream::connect(proxy.address).await?;
        timeout(DEADLINE, async {
            while proxy.connections() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok((proxy, peer))
    }

    async fn assert_peer_closed(peer: &mut (impl AsyncRead + Unpin)) -> TestResult<()> {
        let mut byte = [0];
        match timeout(DEADLINE, peer.read(&mut byte)).await? {
            Ok(0) => Ok(()),
            Err(error) if is_peer_gone(&error) => Ok(()),
            Ok(_) => Err("peer sent unexpected bytes instead of closing".into()),
            Err(error) => Err(error.into()),
        }
    }

    #[tokio::test]
    async fn dropping_proxy_closes_an_accepted_stalled_tls_peer() -> TestResult<()> {
        let (proxy, mut peer) = accepted_proxy().await?;
        drop(proxy);
        assert_peer_closed(&mut peer).await
    }

    #[tokio::test]
    async fn cancelling_proxy_owner_closes_an_accepted_stalled_tls_peer() -> TestResult<()> {
        let (proxy, mut peer) = accepted_proxy().await?;
        let mut owners = JoinSet::new();
        owners.spawn(async move {
            let _proxy = proxy;
            pending::<()>().await;
        });

        owners.abort_all();
        assert!(
            owners
                .join_next()
                .await
                .ok_or("missing owner task")?
                .err()
                .ok_or("owner was not cancelled")?
                .is_cancelled()
        );

        assert_peer_closed(&mut peer).await
    }

    #[tokio::test]
    async fn cancelling_h1_relay_closes_peer_after_a_partial_capsule() -> TestResult<()> {
        let target = phantom_testkit::udp::bind_tokio("127.0.0.1:0".parse()?)?;
        let (mut peer, stream) = tokio::io::duplex(4096);
        let mut owners = JoinSet::new();
        owners.spawn(serve_http1(
            stream,
            StreamMode::Relay,
            Arc::new(Mutex::new(StreamLog::default())),
        ));

        let path = format!(
            "/.well-known/masque/udp/127.0.0.1/{}/",
            target.local_addr()?.port()
        );
        peer.write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n\r\n").as_bytes()).await?;
        let response = timeout(DEADLINE, read_head(&mut peer)).await??;
        assert!(response.starts_with(b"HTTP/1.1 101 "));
        let mut preamble = vec![
            0;
            super::UNKNOWN_CAPSULE.len()
                + encode_capsule(0, super::UNKNOWN_CONTEXT_PAYLOAD).len()
        ];
        timeout(DEADLINE, peer.read_exact(&mut preamble)).await??;

        peer.write_all(&encode_capsule(0, b"\0ready")).await?;
        let mut datagram = [0; 64];
        let (count, relay_address) = timeout(DEADLINE, target.recv_from(&mut datagram)).await??;
        assert_eq!(&datagram[..count], b"ready");
        target.send_to(b"reply", relay_address).await?;
        let mut echo = [0; 8];
        timeout(DEADLINE, peer.read_exact(&mut echo)).await??;
        assert_eq!(&echo, &[0, 6, 0, b'r', b'e', b'p', b'l', b'y']);

        // A complete exchange proves relay readiness. Leave an incomplete
        // capsule length queued while cancelling its owner, with the peer live.
        peer.write_all(&[0, 0x40]).await?;
        owners.abort_all();
        assert!(
            owners
                .join_next()
                .await
                .ok_or("missing relay task")?
                .err()
                .ok_or("relay was not cancelled")?
                .is_cancelled()
        );

        assert_peer_closed(&mut peer).await
    }

    #[tokio::test]
    async fn cancelling_h2_relay_closes_connection_after_a_partial_capsule() -> TestResult<()> {
        let target = phantom_testkit::udp::bind_tokio("127.0.0.1:0".parse()?)?;
        let (peer, stream) = tokio::io::duplex(4096);
        let mut owners = JoinSet::new();
        owners.spawn(serve_http2(
            stream,
            StreamMode::Relay,
            Arc::new(Mutex::new(StreamLog::default())),
        ));

        let (client, connection) = timeout(DEADLINE, ::http2::client::handshake(peer)).await??;
        let mut drivers = JoinSet::new();
        drivers.spawn(connection);
        let mut client = timeout(DEADLINE, client.ready()).await??;
        timeout(DEADLINE, async {
            while !client.is_extended_connect_protocol_enabled() {
                tokio::task::yield_now().await;
            }
        })
        .await?;

        let uri = format!(
            "https://localhost/.well-known/masque/udp/127.0.0.1/{}/",
            target.local_addr()?.port()
        );
        let mut request = http::Request::builder()
            .method("CONNECT")
            .version(http::Version::HTTP_2)
            .uri(uri)
            .body(())?;
        request
            .extensions_mut()
            .insert(::http2::ext::Protocol::from_static("connect-udp"));
        let (response, mut send) = client.send_request(request, false)?;
        let mut body = timeout(DEADLINE, response).await??.into_body();
        let preamble = timeout(DEADLINE, body.data())
            .await?
            .ok_or("missing relay preamble")??;
        body.flow_control().release_capacity(preamble.len())?;

        send.send_data(Bytes::from(encode_capsule(0, b"\0ready")), false)?;
        let mut datagram = [0; 64];
        let (count, relay_address) = timeout(DEADLINE, target.recv_from(&mut datagram)).await??;
        assert_eq!(&datagram[..count], b"ready");
        target.send_to(b"reply", relay_address).await?;
        let echo = timeout(DEADLINE, body.data())
            .await?
            .ok_or("missing relayed reply")??;
        assert_eq!(echo.as_ref(), &[0, 6, 0, b'r', b'e', b'p', b'l', b'y']);
        body.flow_control().release_capacity(echo.len())?;

        send.send_data(Bytes::from_static(&[0, 0x40]), false)?;
        owners.abort_all();
        assert!(
            owners
                .join_next()
                .await
                .ok_or("missing relay task")?
                .err()
                .ok_or("relay was not cancelled")?
                .is_cancelled()
        );

        // Keep both stream halves and the request handle live. Only release of
        // the server transport can finish the independently driven client.
        let closed = timeout(DEADLINE, drivers.join_next())
            .await?
            .ok_or("missing client driver")?;
        // A transport error or EOF is expected; a driver panic is not.
        let _transport_result = closed?;
        Ok(())
    }
}
