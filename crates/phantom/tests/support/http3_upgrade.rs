//! Deterministic loopback origin and alternative services for Alt-Svc tests.

#![allow(dead_code)]

use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
};

use btls::ssl::{ErrorCode, NameType, Ssl};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Response, StatusCode};
use quinn::{Endpoint, VarInt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
    task::{JoinHandle, JoinSet},
};
use tokio_btls::SslStream;

use crate::support::{
    shared_port,
    tls::{H2_ALPN, TestIdentity, TestResult, is_peer_gone},
};

const H3_ALPN: &[u8] = b"h3";

/// A response served by either the origin or the HTTP/3 alternative.
#[derive(Clone, Debug)]
pub(crate) struct PlannedResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    advertise_alternative: bool,
    altsvc_frames: Vec<PlannedAltSvcFrame>,
}

/// An HTTP/2 ALTSVC frame carrying the fixture's generated advertisement.
///
/// Any response with planned frames switches the origin to a raw HTTP/2
/// server, because the vendored server cannot emit ALTSVC.
#[derive(Clone, Debug)]
pub(crate) enum PlannedAltSvcFrame {
    /// Stream 0 with the origin's canonical serialization.
    CanonicalOrigin,
    /// Stream 0 with a literal origin.
    Origin(String),
    /// The response's stream, with an empty origin.
    RequestStream,
}

impl PlannedResponse {
    pub(crate) fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: Bytes::new(),
            advertise_alternative: false,
            altsvc_frames: Vec::new(),
        }
    }

    /// Send an ALTSVC frame with the generated advertisement before this response.
    pub(crate) fn altsvc_frame(mut self, frame: PlannedAltSvcFrame) -> Self {
        self.altsvc_frames.push(frame);
        self
    }

    pub(crate) fn header(
        mut self,
        name: impl http::header::IntoHeaderName,
        value: HeaderValue,
    ) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub(crate) fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    /// Add the fixture's generated Alt-Svc value to this origin response.
    pub(crate) fn advertise_alternative(mut self) -> Self {
        self.advertise_alternative = true;
        self
    }
}

/// How the origin advertises the alternative endpoint.
#[derive(Clone, Debug)]
pub(crate) struct AltSvcAdvertisement {
    protocol: String,
    authority: AlternativeAuthority,
    max_age: Option<u64>,
    persist: bool,
}

impl Default for AltSvcAdvertisement {
    fn default() -> Self {
        Self {
            protocol: "h3".to_owned(),
            authority: AlternativeAuthority::OriginHost,
            max_age: None,
            persist: false,
        }
    }
}

impl AltSvcAdvertisement {
    pub(crate) fn max_age(mut self, seconds: u64) -> Self {
        self.max_age = Some(seconds);
        self
    }

    pub(crate) fn persist(mut self) -> Self {
        self.persist = true;
        self
    }

    /// Override the advertised ALPN token, for example to exercise an unknown token.
    pub(crate) fn protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = protocol.into();
        self
    }

    /// Override the advertised authority instead of preserving the origin host.
    pub(crate) fn authority(mut self, authority: impl Into<String>) -> Self {
        self.authority = AlternativeAuthority::Explicit(authority.into());
        self
    }

    /// Advertise a different host while using the generated alternative port.
    pub(crate) fn host(mut self, host: impl Into<String>) -> Self {
        self.authority = AlternativeAuthority::ExplicitHost(host.into());
        self
    }

    fn value(&self, alternative: SocketAddr) -> TestResult<HeaderValue> {
        let authority = match &self.authority {
            AlternativeAuthority::OriginHost => format!(":{}", alternative.port()),
            AlternativeAuthority::Explicit(authority) => authority.clone(),
            AlternativeAuthority::ExplicitHost(host) => {
                format!("{host}:{}", alternative.port())
            }
        };
        let mut value = format!("{}=\"{authority}\"", self.protocol);
        if let Some(max_age) = self.max_age {
            value.push_str(&format!("; ma={max_age}"));
        }
        if self.persist {
            value.push_str("; persist=1");
        }
        Ok(HeaderValue::from_str(&value)?)
    }
}

#[derive(Clone, Debug)]
enum AlternativeAuthority {
    OriginHost,
    Explicit(String),
    ExplicitHost(String),
}

/// The alternative can respond normally or fail after an authenticated QUIC handshake.
#[derive(Clone, Debug)]
pub(crate) enum AlternativeBehavior {
    Responses(Vec<PlannedResponse>),
    CloseAfterHandshake { code: u32, reason: Vec<u8> },
}

impl AlternativeBehavior {
    pub(crate) fn responses(responses: impl IntoIterator<Item = PlannedResponse>) -> Self {
        Self::Responses(responses.into_iter().collect())
    }

    pub(crate) fn close_after_handshake(code: u32, reason: impl Into<Vec<u8>>) -> Self {
        Self::CloseAfterHandshake {
            code,
            reason: reason.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct UpgradeScript {
    origin_responses: Vec<PlannedResponse>,
    alternative_behavior: AlternativeBehavior,
    advertisement: AltSvcAdvertisement,
    alternative_ip: IpAddr,
    origin_http3_responses: Option<Vec<PlannedResponse>>,
}

impl UpgradeScript {
    /// Also serve exact HTTP/3 on UDP at the origin's IPv4 loopback TCP port.
    pub(crate) fn origin_http3(
        mut self,
        responses: impl IntoIterator<Item = PlannedResponse>,
    ) -> Self {
        self.origin_http3_responses = Some(responses.into_iter().collect());
        self
    }

    pub(crate) fn new(
        origin_responses: impl IntoIterator<Item = PlannedResponse>,
        alternative_behavior: AlternativeBehavior,
    ) -> Self {
        Self {
            origin_responses: origin_responses.into_iter().collect(),
            alternative_behavior,
            advertisement: AltSvcAdvertisement::default(),
            alternative_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            origin_http3_responses: None,
        }
    }

    pub(crate) fn advertisement(mut self, advertisement: AltSvcAdvertisement) -> Self {
        self.advertisement = advertisement;
        self
    }

    pub(crate) fn alternative_ip(mut self, alternative_ip: IpAddr) -> Self {
        self.alternative_ip = alternative_ip;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedField {
    pub(crate) name: String,
    pub(crate) value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedRequest {
    pub(crate) method: Method,
    pub(crate) authority: Option<String>,
    pub(crate) path_and_query: Option<String>,
    pub(crate) server_name: Option<String>,
    pub(crate) fields: Vec<ObservedField>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct UpgradeObservations {
    pub(crate) origin_connections: usize,
    pub(crate) alternative_connections: usize,
    /// Every origin request; the raw ALTSVC origin records no request fields.
    pub(crate) origin_request_count: usize,
    pub(crate) origin_requests: Vec<ObservedRequest>,
    pub(crate) alternative_requests: Vec<ObservedRequest>,
    /// Exact-H3 service on the origin's own port, when scripted.
    pub(crate) origin_http3_connections: usize,
    pub(crate) origin_http3_requests: Vec<ObservedRequest>,
}

#[derive(Default)]
struct SharedObservations {
    origin_connections: AtomicUsize,
    origin_request_count: AtomicUsize,
    alternative_connections: AtomicUsize,
    origin_requests: Mutex<Vec<ObservedRequest>>,
    alternative_requests: Mutex<Vec<ObservedRequest>>,
}

/// Owns both listeners. Call [`Self::finish`] after dropping the client under test.
pub(crate) struct Http3UpgradeFixture {
    origin_name: String,
    origin_address: SocketAddr,
    alternative_address: SocketAddr,
    alternative_endpoint: Endpoint,
    observations: Arc<SharedObservations>,
    shutdown: watch::Sender<bool>,
    origin_task: JoinHandle<TestResult<()>>,
    alternative_task: JoinHandle<TestResult<()>>,
    origin_http3: Option<OriginHttp3Service>,
}

/// Exact HTTP/3 served at the origin's transport location.
///
/// A client that resolves `localhost` may try `::1` first, so the service
/// also listens on the IPv6 loopback at the same port when the host has one.
/// Each listener serves its own copy of the planned responses.
struct OriginHttp3Service {
    endpoints: Vec<Endpoint>,
    observations: Arc<SharedObservations>,
    tasks: Vec<JoinHandle<TestResult<()>>>,
}

impl Http3UpgradeFixture {
    pub(crate) async fn spawn(
        identity: &TestIdentity,
        origin_name: impl Into<String>,
        script: UpgradeScript,
    ) -> TestResult<Self> {
        let origin_name = origin_name.into();
        let (listener, origin_endpoints) = if script.origin_http3_responses.is_some() {
            let (listener, endpoints) = bind_shared_origin_port(identity).await?;
            (listener, Some(endpoints))
        } else {
            (TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?, None)
        };
        let origin_address = listener.local_addr()?;
        let alternative_endpoint =
            h3_endpoint(identity, SocketAddr::new(script.alternative_ip, 0))?;
        let alternative_address = alternative_endpoint.local_addr()?;
        let alt_svc = script.advertisement.value(alternative_address)?;
        let raw_canonical_origin = script
            .origin_responses
            .iter()
            .any(|response| !response.altsvc_frames.is_empty())
            .then(|| format!("https://{origin_name}:{}", origin_address.port()));
        let observations = Arc::new(SharedObservations::default());
        let origin_responses = Arc::new(Mutex::new(VecDeque::from(script.origin_responses)));
        let (shutdown, shutdown_rx) = watch::channel(false);

        let origin_task = tokio::spawn(run_origin(
            listener,
            identity.acceptor(H2_ALPN)?,
            origin_responses,
            OriginPlan {
                alt_svc,
                raw_canonical_origin,
            },
            Arc::clone(&observations),
            shutdown_rx.clone(),
        ));
        let origin_http3 = match (script.origin_http3_responses, origin_endpoints) {
            (Some(responses), Some(endpoints)) => {
                let observations = Arc::new(SharedObservations::default());
                let tasks = endpoints
                    .iter()
                    .map(|endpoint| {
                        tokio::spawn(run_alternative(
                            endpoint.clone(),
                            AlternativeBehavior::Responses(responses.clone()),
                            Arc::clone(&observations),
                            shutdown_rx.clone(),
                        ))
                    })
                    .collect();
                Some(OriginHttp3Service {
                    endpoints,
                    observations,
                    tasks,
                })
            }
            _ => None,
        };
        let alternative_task = tokio::spawn(run_alternative(
            alternative_endpoint.clone(),
            script.alternative_behavior,
            Arc::clone(&observations),
            shutdown_rx,
        ));

        Ok(Self {
            origin_name,
            origin_address,
            alternative_address,
            alternative_endpoint,
            observations,
            shutdown,
            origin_task,
            alternative_task,
            origin_http3,
        })
    }

    pub(crate) fn origin_address(&self) -> SocketAddr {
        self.origin_address
    }

    pub(crate) fn alternative_address(&self) -> SocketAddr {
        self.alternative_address
    }

    pub(crate) fn origin_url(&self, path_and_query: &str) -> String {
        assert!(path_and_query.starts_with('/'));
        format!(
            "https://{}:{}{path_and_query}",
            self.origin_name,
            self.origin_address.port()
        )
    }

    pub(crate) fn snapshot(&self) -> TestResult<UpgradeObservations> {
        snapshot(
            &self.observations,
            self.origin_http3
                .as_ref()
                .map(|service| &*service.observations),
        )
    }

    pub(crate) async fn finish(self) -> TestResult<UpgradeObservations> {
        let _ = self.shutdown.send(true);
        self.alternative_endpoint
            .close(VarInt::from_u32(0), b"test complete");
        self.origin_task.await??;
        self.alternative_task.await??;
        let origin_http3 = match self.origin_http3 {
            Some(service) => {
                for endpoint in &service.endpoints {
                    endpoint.close(VarInt::from_u32(0), b"test complete");
                }
                for task in service.tasks {
                    task.await??;
                }
                Some(service.observations)
            }
            None => None,
        };
        snapshot(&self.observations, origin_http3.as_deref())
    }
}

async fn run_origin(
    listener: TcpListener,
    acceptor: btls::ssl::SslAcceptor,
    responses: Arc<Mutex<VecDeque<PlannedResponse>>>,
    plan: OriginPlan,
    observations: Arc<SharedObservations>,
    mut shutdown: watch::Receiver<bool>,
) -> TestResult<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                break;
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                connections.spawn(serve_origin_connection(
                    stream,
                    acceptor.clone(),
                    Arc::clone(&responses),
                    plan.clone(),
                    Arc::clone(&observations),
                    shutdown.clone(),
                ));
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(completed) = completed {
                    completed??;
                }
            }
        }
    }
    connections.abort_all();
    while let Some(completed) = connections.join_next().await {
        match completed {
            Ok(result) => result?,
            Err(error) if error.is_cancelled() => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

async fn serve_origin_connection(
    stream: TcpStream,
    acceptor: btls::ssl::SslAcceptor,
    responses: Arc<Mutex<VecDeque<PlannedResponse>>>,
    plan: OriginPlan,
    observations: Arc<SharedObservations>,
    mut shutdown: watch::Receiver<bool>,
) -> TestResult<()> {
    let ssl = Ssl::new(acceptor.context())?;
    let mut stream = SslStream::new(ssl, stream)?;
    if let Err(error) = Pin::new(&mut stream).accept().await {
        // A racing client drops the losing origin setup mid-handshake; that
        // connection never counts as an origin connection.
        if error.code() == ErrorCode::SYSCALL && error.io_error().is_none_or(is_peer_gone) {
            return Ok(());
        }
        return Err(error.into());
    }
    observations
        .origin_connections
        .fetch_add(1, Ordering::SeqCst);
    let alt_svc = plan.alt_svc;
    if let Some(canonical_origin) = plan.raw_canonical_origin {
        return raw_http2::serve(
            stream,
            &responses,
            &alt_svc,
            &canonical_origin,
            &observations,
            shutdown,
        )
        .await;
    }
    let server_name = stream
        .ssl()
        .servername(NameType::HOST_NAME)
        .map(str::to_owned);
    let mut connection = http2::server::handshake(stream).await?;

    loop {
        let accepted = tokio::select! {
            _ = shutdown.changed() => {
                return Ok(());
            }
            accepted = connection.accept() => accepted,
        };
        let Some(result) = accepted else {
            return Ok(());
        };
        let (request, mut respond) = result?;
        observations
            .origin_request_count
            .fetch_add(1, Ordering::SeqCst);
        lock(&observations.origin_requests)?.push(observe_request(&request, &server_name));
        let response = pop_response(&responses, "origin")?;
        let end_stream = response.body.is_empty();
        let response_head = response_head(
            &response,
            response.advertise_alternative.then_some(&alt_svc),
        )?;
        let mut send = respond.send_response(response_head, end_stream)?;
        if !end_stream {
            send.send_data(response.body, true)?;
        }
    }
}

async fn run_alternative(
    endpoint: Endpoint,
    behavior: AlternativeBehavior,
    observations: Arc<SharedObservations>,
    mut shutdown: watch::Receiver<bool>,
) -> TestResult<()> {
    let responses = match &behavior {
        AlternativeBehavior::Responses(responses) => {
            Some(Arc::new(Mutex::new(VecDeque::from(responses.clone()))))
        }
        AlternativeBehavior::CloseAfterHandshake { .. } => None,
    };
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                break;
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                connections.spawn(serve_alternative_connection(
                    incoming,
                    behavior.clone(),
                    responses.clone(),
                    Arc::clone(&observations),
                    shutdown.clone(),
                ));
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(completed) = completed {
                    completed??;
                }
            }
        }
    }
    connections.abort_all();
    while let Some(completed) = connections.join_next().await {
        match completed {
            Ok(result) => result?,
            Err(error) if error.is_cancelled() => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

async fn serve_alternative_connection(
    incoming: quinn::Incoming,
    behavior: AlternativeBehavior,
    responses: Option<Arc<Mutex<VecDeque<PlannedResponse>>>>,
    observations: Arc<SharedObservations>,
    mut shutdown: watch::Receiver<bool>,
) -> TestResult<()> {
    let connection = incoming.await?;
    observations
        .alternative_connections
        .fetch_add(1, Ordering::SeqCst);
    let server_name = connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.server_name.clone());

    if let AlternativeBehavior::CloseAfterHandshake { code, reason } = behavior {
        connection.close(VarInt::from_u32(code), &reason);
        return Ok(());
    }

    let responses = responses.ok_or_else(|| io::Error::other("missing HTTP/3 response script"))?;
    let mut h3 = h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?;
    loop {
        let accepted = tokio::select! {
            _ = shutdown.changed() => {
                return Ok(());
            }
            accepted = h3.accept() => accepted?,
        };
        let Some(resolver) = accepted else {
            return Ok(());
        };
        let (request, mut stream) = resolver.resolve_request().await?;
        lock(&observations.alternative_requests)?.push(observe_request(&request, &server_name));
        let response = pop_response(&responses, "alternative")?;
        stream
            .send_response(response_head(&response, None)?)
            .await?;
        if !response.body.is_empty() {
            stream.send_data(response.body).await?;
        }
        stream.finish().await?;
    }
}

fn response_head(
    response: &PlannedResponse,
    alt_svc: Option<&HeaderValue>,
) -> TestResult<Response<()>> {
    let mut head = Response::builder().status(response.status).body(())?;
    *head.headers_mut() = response.headers.clone();
    if let Some(value) = alt_svc {
        head.headers_mut()
            .insert(http::header::ALT_SVC, value.clone());
    }
    Ok(head)
}

fn pop_response(
    responses: &Mutex<VecDeque<PlannedResponse>>,
    service: &str,
) -> TestResult<PlannedResponse> {
    lock(responses)?.pop_front().ok_or_else(|| {
        io::Error::other(format!(
            "unexpected request exhausted {service} response script"
        ))
        .into()
    })
}

fn observe_request<B>(request: &http::Request<B>, server_name: &Option<String>) -> ObservedRequest {
    ObservedRequest {
        method: request.method().clone(),
        authority: request.uri().authority().map(ToString::to_string),
        path_and_query: request.uri().path_and_query().map(ToString::to_string),
        server_name: server_name.clone(),
        fields: ordered_fields(request),
    }
}

fn ordered_fields<B>(request: &http::Request<B>) -> Vec<ObservedField> {
    if let Some(ordered) = request.extensions().get::<h3::ext::OrderedHeaders>() {
        return observed_fields(ordered.as_slice());
    }
    if let Some(ordered) = request.extensions().get::<http2::ext::OrderedHeaders>() {
        return observed_fields(ordered.as_slice());
    }
    request
        .headers()
        .iter()
        .map(|(name, value)| ObservedField {
            name: name.as_str().to_owned(),
            value: value.as_bytes().to_vec(),
        })
        .collect()
}

fn observed_fields(fields: &[(http::HeaderName, HeaderValue)]) -> Vec<ObservedField> {
    fields
        .iter()
        .map(|(name, value)| ObservedField {
            name: name.as_str().to_owned(),
            value: value.as_bytes().to_vec(),
        })
        .collect()
}

fn snapshot(
    observations: &SharedObservations,
    origin_http3: Option<&SharedObservations>,
) -> TestResult<UpgradeObservations> {
    Ok(UpgradeObservations {
        origin_connections: observations.origin_connections.load(Ordering::SeqCst),
        origin_request_count: observations.origin_request_count.load(Ordering::SeqCst),
        alternative_connections: observations.alternative_connections.load(Ordering::SeqCst),
        origin_requests: lock(&observations.origin_requests)?.clone(),
        alternative_requests: lock(&observations.alternative_requests)?.clone(),
        origin_http3_connections: origin_http3.map_or(0, |observations| {
            observations.alternative_connections.load(Ordering::SeqCst)
        }),
        origin_http3_requests: match origin_http3 {
            Some(observations) => lock(&observations.alternative_requests)?.clone(),
            None => Vec::new(),
        },
    })
}

fn lock<T>(mutex: &Mutex<T>) -> TestResult<MutexGuard<'_, T>> {
    mutex
        .lock()
        .map_err(|_| io::Error::other("HTTP/3 upgrade fixture mutex poisoned").into())
}

fn h3_endpoint(identity: &TestIdentity, bind: SocketAddr) -> TestResult<Endpoint> {
    let provider = rustls::crypto::ring::default_provider();
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(identity.leaf_der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                identity.private_key_der().to_vec(),
            )),
        )?;
    crypto.alpn_protocols = vec![H3_ALPN.to_vec()];
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?,
    ));
    Ok(Endpoint::server(server_config, bind)?)
}

#[derive(Clone)]
struct OriginPlan {
    alt_svc: HeaderValue,
    /// Set when the script plans ALTSVC frames and the origin must be raw.
    raw_canonical_origin: Option<String>,
}

/// A minimal HTTP/2 origin that can write ALTSVC frames (RFC 7838 section 4).
///
/// It answers each request HEADERS frame on its stream without decoding the
/// request block and encodes response fields as HPACK literals without
/// indexing, so it keeps no HPACK state.
mod raw_http2 {
    use std::io;

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    use super::*;

    const DATA: u8 = 0;
    const HEADERS: u8 = 1;
    const SETTINGS: u8 = 4;
    const GOAWAY: u8 = 7;
    const ALTSVC: u8 = 10;
    const END_STREAM: u8 = 0x1;
    const ACK: u8 = 0x1;
    const END_HEADERS: u8 = 0x4;

    pub(super) async fn serve<S>(
        mut stream: S,
        responses: &Mutex<VecDeque<PlannedResponse>>,
        alt_svc: &HeaderValue,
        canonical_origin: &str,
        observations: &SharedObservations,
        mut shutdown: watch::Receiver<bool>,
    ) -> TestResult<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut preface = [0_u8; 24];
        stream.read_exact(&mut preface).await?;
        if &preface != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
            return Err(io::Error::other("client sent an invalid HTTP/2 preface").into());
        }
        write_frame(&mut stream, SETTINGS, 0, 0, &[]).await?;
        loop {
            let frame = tokio::select! {
                _ = shutdown.changed() => return Ok(()),
                frame = read_frame(&mut stream) => frame?,
            };
            let Some((kind, flags, stream_id)) = frame else {
                return Ok(());
            };
            match kind {
                SETTINGS if flags & ACK == 0 => {
                    write_frame(&mut stream, SETTINGS, ACK, 0, &[]).await?;
                }
                HEADERS => {
                    if flags & END_HEADERS == 0 || flags & END_STREAM == 0 {
                        return Err(io::Error::other(
                            "raw origin supports only single-frame bodiless requests",
                        )
                        .into());
                    }
                    observations
                        .origin_request_count
                        .fetch_add(1, Ordering::SeqCst);
                    let response = pop_response(responses, "origin")?;
                    respond(&mut stream, stream_id, &response, alt_svc, canonical_origin).await?;
                }
                GOAWAY => return Ok(()),
                _ => {}
            }
        }
    }

    async fn respond<S>(
        stream: &mut S,
        stream_id: u32,
        response: &PlannedResponse,
        alt_svc: &HeaderValue,
        canonical_origin: &str,
    ) -> TestResult<()>
    where
        S: AsyncWrite + Unpin,
    {
        for frame in &response.altsvc_frames {
            let (frame_stream, origin) = match frame {
                PlannedAltSvcFrame::CanonicalOrigin => (0, canonical_origin),
                PlannedAltSvcFrame::Origin(origin) => (0, origin.as_str()),
                PlannedAltSvcFrame::RequestStream => (stream_id, ""),
            };
            let origin_len = u16::try_from(origin.len())?;
            let mut payload = origin_len.to_be_bytes().to_vec();
            payload.extend_from_slice(origin.as_bytes());
            payload.extend_from_slice(alt_svc.as_bytes());
            write_frame(stream, ALTSVC, 0, frame_stream, &payload).await?;
        }

        // `:status` as a literal without indexing, name index 8.
        let mut block = vec![0x08];
        push_string(&mut block, response.status.as_str().as_bytes());
        let mut fields: Vec<(&[u8], &[u8])> = response
            .headers
            .iter()
            .map(|(name, value)| (name.as_str().as_bytes(), value.as_bytes()))
            .collect();
        if response.advertise_alternative {
            fields.push((b"alt-svc", alt_svc.as_bytes()));
        }
        for (name, value) in fields {
            block.push(0x00);
            push_string(&mut block, name);
            push_string(&mut block, value);
        }
        let end_stream = response.body.is_empty();
        let flags = END_HEADERS | if end_stream { END_STREAM } else { 0 };
        write_frame(stream, HEADERS, flags, stream_id, &block).await?;
        if !end_stream {
            write_frame(stream, DATA, END_STREAM, stream_id, &response.body).await?;
        }
        Ok(())
    }

    /// Appends an HPACK string literal without Huffman coding (RFC 7541 5.2).
    fn push_string(block: &mut Vec<u8>, value: &[u8]) {
        let mut length = value.len();
        if length < 0x7f {
            block.push(length as u8);
        } else {
            block.push(0x7f);
            length -= 0x7f;
            while length >= 0x80 {
                block.push((length % 0x80) as u8 | 0x80);
                length /= 0x80;
            }
            block.push(length as u8);
        }
        block.extend_from_slice(value);
    }

    async fn read_frame<S>(stream: &mut S) -> TestResult<Option<(u8, u8, u32)>>
    where
        S: AsyncRead + Unpin,
    {
        let mut head = [0_u8; 9];
        match stream.read_exact(&mut head).await {
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        }
        let length =
            (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
        let mut payload = vec![0_u8; length];
        stream.read_exact(&mut payload).await?;
        let stream_id = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
        Ok(Some((head[3], head[4], stream_id)))
    }

    async fn write_frame<S>(
        stream: &mut S,
        kind: u8,
        flags: u8,
        stream_id: u32,
        payload: &[u8],
    ) -> TestResult<()>
    where
        S: AsyncWrite + Unpin,
    {
        let length = u32::try_from(payload.len())?.to_be_bytes();
        let mut frame = vec![length[1], length[2], length[3], kind, flags];
        frame.extend_from_slice(&stream_id.to_be_bytes());
        frame.extend_from_slice(payload);
        stream.write_all(&frame).await?;
        stream.flush().await?;
        Ok(())
    }
}

/// Binds the H3 service's UDP endpoints first, then the origin's TCP listener
/// on the same port number, so both share one transport location.
///
/// The H3 service listens on the IPv4 loopback and, when the host has one, on
/// the IPv6 loopback at the same port.
async fn bind_shared_origin_port(
    identity: &TestIdentity,
) -> TestResult<(TcpListener, Vec<Endpoint>)> {
    let mut last_error = None;
    for port in shared_port::candidates() {
        let bind = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
        let endpoint = match h3_endpoint(identity, bind) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                last_error = Some(error.to_string());
                continue;
            }
        };
        let mut endpoints = vec![endpoint];
        match h3_endpoint(identity, SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port)) {
            Ok(endpoint) => endpoints.push(endpoint),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::AddrNotAvailable) => {}
            Err(error) => {
                last_error = Some(error.to_string());
                continue;
            }
        }
        match TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
            Ok(listener) => return Ok((listener, endpoints)),
            Err(error) if shared_port::is_unavailable(&error) => {
                last_error = Some(error.to_string());
                continue;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(format!(
        "no loopback port was free for both TCP and UDP; last error: {}",
        last_error.as_deref().unwrap_or("none")
    )
    .into())
}
