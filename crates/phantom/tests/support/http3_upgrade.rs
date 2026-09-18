//! Deterministic loopback origin and alternative services for Alt-Svc tests.

#![allow(dead_code)]

use std::{
    collections::VecDeque,
    io,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
};

use btls::ssl::{NameType, Ssl};
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

use crate::tls_support::{H2_ALPN, TestIdentity, TestResult};

const H3_ALPN: &[u8] = b"h3";

/// A response served by either the origin or the HTTP/3 alternative.
#[derive(Clone, Debug)]
pub(crate) struct PlannedResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    advertise_alternative: bool,
}

impl PlannedResponse {
    pub(crate) fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: Bytes::new(),
            advertise_alternative: false,
        }
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
}

impl UpgradeScript {
    pub(crate) fn new(
        origin_responses: impl IntoIterator<Item = PlannedResponse>,
        alternative_behavior: AlternativeBehavior,
    ) -> Self {
        Self {
            origin_responses: origin_responses.into_iter().collect(),
            alternative_behavior,
            advertisement: AltSvcAdvertisement::default(),
        }
    }

    pub(crate) fn advertisement(mut self, advertisement: AltSvcAdvertisement) -> Self {
        self.advertisement = advertisement;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedRequest {
    pub(crate) method: Method,
    pub(crate) authority: Option<String>,
    pub(crate) path_and_query: Option<String>,
    pub(crate) server_name: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct UpgradeObservations {
    pub(crate) origin_connections: usize,
    pub(crate) alternative_connections: usize,
    pub(crate) origin_requests: Vec<ObservedRequest>,
    pub(crate) alternative_requests: Vec<ObservedRequest>,
}

#[derive(Default)]
struct SharedObservations {
    origin_connections: AtomicUsize,
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
}

impl Http3UpgradeFixture {
    pub(crate) async fn spawn(
        identity: &TestIdentity,
        origin_name: impl Into<String>,
        script: UpgradeScript,
    ) -> TestResult<Self> {
        let origin_name = origin_name.into();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = listener.local_addr()?;
        let alternative_endpoint = h3_endpoint(identity)?;
        let alternative_address = alternative_endpoint.local_addr()?;
        let alt_svc = script.advertisement.value(alternative_address)?;
        let observations = Arc::new(SharedObservations::default());
        let origin_responses = Arc::new(Mutex::new(VecDeque::from(script.origin_responses)));
        let (shutdown, shutdown_rx) = watch::channel(false);

        let origin_task = tokio::spawn(run_origin(
            listener,
            identity.acceptor(H2_ALPN)?,
            origin_responses,
            alt_svc,
            Arc::clone(&observations),
            shutdown_rx.clone(),
        ));
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
        snapshot(&self.observations)
    }

    pub(crate) async fn finish(self) -> TestResult<UpgradeObservations> {
        let _ = self.shutdown.send(true);
        self.alternative_endpoint
            .close(VarInt::from_u32(0), b"test complete");
        self.origin_task.await??;
        self.alternative_task.await??;
        snapshot(&self.observations)
    }
}

async fn run_origin(
    listener: TcpListener,
    acceptor: btls::ssl::SslAcceptor,
    responses: Arc<Mutex<VecDeque<PlannedResponse>>>,
    alt_svc: HeaderValue,
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
                    alt_svc.clone(),
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
    alt_svc: HeaderValue,
    observations: Arc<SharedObservations>,
    mut shutdown: watch::Receiver<bool>,
) -> TestResult<()> {
    let ssl = Ssl::new(acceptor.context())?;
    let mut stream = SslStream::new(ssl, stream)?;
    Pin::new(&mut stream).accept().await?;
    observations
        .origin_connections
        .fetch_add(1, Ordering::SeqCst);
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
    }
}

fn snapshot(observations: &SharedObservations) -> TestResult<UpgradeObservations> {
    Ok(UpgradeObservations {
        origin_connections: observations.origin_connections.load(Ordering::SeqCst),
        alternative_connections: observations.alternative_connections.load(Ordering::SeqCst),
        origin_requests: lock(&observations.origin_requests)?.clone(),
        alternative_requests: lock(&observations.alternative_requests)?.clone(),
    })
}

fn lock<T>(mutex: &Mutex<T>) -> TestResult<MutexGuard<'_, T>> {
    mutex
        .lock()
        .map_err(|_| io::Error::other("HTTP/3 upgrade fixture mutex poisoned").into())
}

fn h3_endpoint(identity: &TestIdentity) -> TestResult<Endpoint> {
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
    Ok(Endpoint::server(
        server_config,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )?)
}
