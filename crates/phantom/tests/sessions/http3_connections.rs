//! Opt-in HTTP/3 connections per origin.
//!
//! By default a pool key keeps one HTTP/3 connection per transport location,
//! as browsers do. With `max_http3_connections_per_origin`, requests that
//! find every connection at the server's `initial_max_streams_bidi` open
//! another, up to the configured count.

use std::{
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use phantom::{
    Client, ClientBuilder, HttpProtocol, ResponseInfo,
    profile::{ClientProfile, Http3ClientSettings},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ServerSessionMemoryCache, StoresServerSessions};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::{mpsc, watch},
    task::JoinSet,
    time::{sleep, timeout},
};
use tracing::instrument::WithSubscriber;

use crate::support::{
    deadline::FixtureDeadline,
    h3 as h3_support, tls as tls_support,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

use goaway_observation::GoawayObservation;
use h3_support::client_settings;
use request_workers::Requests;
use tls_support::{H1_ALPN, TestIdentity, accept_tls_stream, read_head, tls_settings};

mod goaway_observation;
mod request_workers;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the origin must stay quiet for a request to count as queued.
const QUIET_WINDOW: Duration = Duration::from_millis(300);
/// The origin's `initial_max_streams_bidi`, which Quinn keeps as the number
/// of request streams open at once.
const PEER_STREAMS: u32 = 2;
/// Requests sent at once in each connection-count test.
const REQUESTS: usize = 5;

#[derive(Debug)]
enum Event {
    Accepted(usize),
    Request { connection: usize },
    Failed,
}

/// A TLS session store that counts the tickets a client presented and the
/// server accepted.
#[derive(Debug)]
struct CountingStore {
    inner: Arc<ServerSessionMemoryCache>,
    accepted: AtomicUsize,
}

impl StoresServerSessions for CountingStore {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.inner.put(key, value)
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.get(key)
    }

    // rustls looks up every TLS 1.3 ticket a client presents with `take`.
    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        let value = self.inner.take(key);
        if value.is_some() {
            self.accepted.fetch_add(1, Ordering::SeqCst);
        }
        value
    }

    fn can_cache(&self) -> bool {
        self.inner.can_cache()
    }
}

/// A loopback HTTP/3 origin that allows [`PEER_STREAMS`] request streams per
/// connection and holds every response except `/warm` until
/// [`Origin::release`].
struct Origin {
    address: SocketAddr,
    events: mpsc::UnboundedReceiver<Event>,
    release: watch::Sender<bool>,
    goaway: watch::Sender<Option<usize>>,
    goaway_release: watch::Sender<bool>,
    handshakes: watch::Sender<bool>,
    tickets: Arc<CountingStore>,
    stopping: watch::Sender<bool>,
    failures: Arc<Mutex<Vec<Box<dyn std::error::Error + Send + Sync>>>>,
    task: ConnectionPeer<TestResult>,
}

impl Origin {
    fn start(identity: &TestIdentity) -> TestResult<Self> {
        Self::with(identity, None)
    }

    /// Like [`Origin::start`], and answers the `stalled` connection's
    /// handshake only after [`Origin::release_handshake`].
    fn with(identity: &TestIdentity, stalled: Option<usize>) -> TestResult<Self> {
        let tickets = Arc::new(CountingStore {
            inner: ServerSessionMemoryCache::new(64),
            accepted: AtomicUsize::new(0),
        });
        let endpoint = crate::support::h3::quic_server(
            server_config(identity, Arc::clone(&tickets))?,
            (Ipv4Addr::LOCALHOST, 0).into(),
        )?;
        let address = endpoint.local_addr()?;
        let (sender, events) = mpsc::unbounded_channel();
        let (release, released) = watch::channel(false);
        let (goaway, goaway_requested) = watch::channel(None);
        let (goaway_release, goaway_released) = watch::channel(true);
        let (handshakes, handshakes_released) = watch::channel(false);
        let (stopping, mut stopped) = watch::channel(false);
        let shutdown = stopping.clone();
        let failures = Arc::new(Mutex::new(Vec::new()));
        let errors = Arc::clone(&failures);
        let endpoint = EndpointOwner(endpoint);
        let task = ConnectionPeer::spawn(async move {
            let mut peers = JoinSet::new();
            let mut accepted = 0;
            let primary: TestResult = async {
                loop {
                    tokio::select! {
                        biased;
                        joined = peers.join_next(), if !peers.is_empty() => {
                            joined.ok_or("origin connection disappeared")???;
                        }
                        changed = async { stopped.wait_for(|stopped| *stopped).await.map(drop) } => {
                            changed?;
                            break;
                        }
                        incoming = endpoint.0.accept() => {
                            let incoming = incoming.ok_or("origin acceptor stopped")?;
                            let index = accepted;
                            accepted += 1;
                            sender.send(Event::Accepted(index))?;
                            let (sender, released, goaway, goaway_release, mut handshakes, mut stopping) = (
                                sender.clone(),
                                released.clone(),
                                goaway_requested.clone(),
                                goaway_released.clone(),
                                handshakes_released.clone(),
                                stopped.clone(),
                            );
                            peers.spawn(async move {
                                if stalled == Some(index) {
                                    tokio::select! {
                                        released = async { handshakes.wait_for(|released| *released).await.map(drop) } => {
                                            released?;
                                        }
                                        changed = async { stopping.wait_for(|stopped| *stopped).await.map(drop) } => {
                                            changed?;
                                            return Ok(());
                                        }
                                    }
                                }
                                serve(incoming, index, sender, released, goaway, goaway_release, stopping).await
                            });
                        }
                    }
                }
                Ok(())
            }
            .await;
            if let Err(error) = primary {
                errors
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(error);
                let _ = sender.send(Event::Failed);
            }
            shutdown.send_replace(true);
            eprintln!(
                "HTTP/3 fixture: phase=cleanup-peers-start remaining={}",
                peers.len()
            );
            while let Some(joined) = peers.join_next().await {
                eprintln!(
                    "HTTP/3 fixture: phase=cleanup-peer-joined remaining={}",
                    peers.len()
                );
                let result = joined.map_err(Into::into).and_then(|result| result);
                if let Err(error) = result {
                    errors
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(error);
                    let _ = sender.send(Event::Failed);
                }
            }
            eprintln!(
                "HTTP/3 fixture: phase=endpoint-close connections={}",
                endpoint.0.open_connections()
            );
            endpoint.0.close(0u32.into(), b"fixture finished");
            eprintln!(
                "HTTP/3 fixture: phase=endpoint-wait-idle connections={}",
                endpoint.0.open_connections()
            );
            endpoint.0.wait_idle().await;
            eprintln!("HTTP/3 fixture: phase=endpoint-idle");
            Ok(())
        });
        Ok(Self {
            address,
            events,
            release,
            goaway,
            goaway_release,
            handshakes,
            tickets,
            stopping,
            failures,
            task,
        })
    }

    /// Lets the stalled connection's handshake proceed.
    fn release_handshake(&self) {
        self.handshakes.send_replace(true);
    }

    async fn next_accepted(&mut self) -> TestResult<usize> {
        loop {
            match timeout(TEST_TIMEOUT, self.events.recv())
                .await
                .map_err(|elapsed| {
                    FixtureDeadline::new(
                        "HTTP/3 origin acceptance wait exceeded its deadline",
                        elapsed,
                    )
                })?
                .ok_or_else(|| self.failure())?
            {
                Event::Accepted(index) => return Ok(index),
                Event::Request { .. } => {}
                Event::Failed => return Err(self.failure()),
            }
        }
    }

    /// Sends GOAWAY on the numbered connection; its open streams finish.
    fn goaway(&self, connection: usize) {
        eprintln!("HTTP/3 fixture: connection={connection} phase=goaway-requested");
        self.goaway.send_replace(Some(connection));
    }

    /// Waits for client processing, rather than treating elapsed time as readiness.
    async fn observe_goaway(
        &self,
        connection: usize,
        observed: &mut GoawayObservation,
        delayed: bool,
    ) -> TestResult {
        if delayed {
            self.goaway_release.send_replace(false);
        }
        self.goaway(connection);
        let mut waiting = std::pin::pin!(observed.wait());
        if delayed {
            // The original tests proceeded after this interval. Keep the
            // server gated throughout it to exercise that scheduling gap.
            tokio::select! {
                result = waiting.as_mut() => {
                    result?;
                    return Err("client observed GOAWAY before its server gate opened".into());
                }
                () = sleep(QUIET_WINDOW) => {}
            }
            self.goaway_release.send_replace(true);
        }
        waiting.await
    }

    fn uri(&self, path: &str) -> String {
        format!("https://{}/{path}", self.address)
    }

    fn release(&self) {
        self.release.send_replace(true);
    }

    /// Waits for `requests` requests, then for a quiet window, and returns
    /// how many connections the origin accepted and requests it saw.
    async fn settle(&mut self, requests: usize) -> TestResult<(usize, usize)> {
        let (mut connections, mut seen) = (0, 0);
        while seen < requests {
            match timeout(TEST_TIMEOUT, self.events.recv())
                .await
                .map_err(|elapsed| {
                    FixtureDeadline::new(
                        "HTTP/3 origin request-count wait exceeded its deadline",
                        elapsed,
                    )
                })?
                .ok_or_else(|| self.failure())?
            {
                Event::Accepted(_) => connections += 1,
                Event::Request { .. } => seen += 1,
                Event::Failed => return Err(self.failure()),
            }
        }
        loop {
            match timeout(QUIET_WINDOW, self.events.recv()).await {
                Err(_) => break,
                Ok(None) => return Err(self.failure()),
                Ok(Some(Event::Failed)) => return Err(self.failure()),
                Ok(Some(Event::Accepted(_))) => connections += 1,
                Ok(Some(Event::Request { .. })) => seen += 1,
            }
        }
        Ok((connections, seen))
    }

    /// Returns the connection that carried the next request.
    async fn next_request(&mut self) -> TestResult<usize> {
        loop {
            match timeout(TEST_TIMEOUT, self.events.recv())
                .await
                .map_err(|elapsed| {
                    FixtureDeadline::new(
                        "HTTP/3 origin request wait exceeded its deadline",
                        elapsed,
                    )
                })?
                .ok_or_else(|| self.failure())?
            {
                Event::Request { connection } => return Ok(connection),
                Event::Accepted(_) => {}
                Event::Failed => return Err(self.failure()),
            }
        }
    }

    fn failure(&self) -> Box<dyn std::error::Error + Send + Sync> {
        self.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
            .unwrap_or_else(|| "origin stopped".into())
    }

    async fn finish<T>(&mut self, primary: TestResult<T>) -> TestResult<T> {
        self.stopping.send_replace(true);
        let cleanup = async {
            timeout(Duration::from_secs(5), self.task.join())
                .await
                .map_err(|elapsed| {
                    FixtureDeadline::new("HTTP/3 origin cleanup exceeded its deadline", elapsed)
                })???;
            Ok(())
        }
        .await;
        let mut result = finish_with_cleanup(primary, cleanup);
        let errors =
            std::mem::take(&mut *self.failures.lock().unwrap_or_else(PoisonError::into_inner));
        for error in errors {
            result = finish_with_cleanup(result, Err(error));
        }
        result
    }
}

struct EndpointOwner(quinn::Endpoint);

impl Drop for EndpointOwner {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"fixture dropped");
    }
}

fn server_config(
    identity: &TestIdentity,
    tickets: Arc<CountingStore>,
) -> TestResult<quinn::ServerConfig> {
    let certificate = CertificateDer::from(identity.leaf_der().to_vec());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        identity.private_key_der().to_vec(),
    ));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.session_storage = tickets;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(PEER_STREAMS.into());
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

async fn serve(
    incoming: quinn::Incoming,
    connection: usize,
    events: mpsc::UnboundedSender<Event>,
    released: watch::Receiver<bool>,
    mut goaway: watch::Receiver<Option<usize>>,
    mut goaway_released: watch::Receiver<bool>,
    mut stopping: watch::Receiver<bool>,
) -> TestResult {
    let quic = tokio::select! {
        quic = incoming => quic?,
        stopped = async { stopping.wait_for(|stopped| *stopped).await.map(drop) } => {
            stopped?;
            return Ok(());
        }
    };
    let mut server: h3::server::Connection<h3_quinn::Connection, Bytes> = tokio::select! {
        server = h3::server::Connection::new(h3_quinn::Connection::new(quic)) => server?,
        stopped = async { stopping.wait_for(|stopped| *stopped).await.map(drop) } => {
            stopped?;
            return Ok(());
        }
    };
    let mut streams = JoinSet::new();
    let mut shutting_down = false;
    let mut accepting = true;
    let primary: TestResult = async {
        loop {
            let accepted = tokio::select! {
                biased;
                joined = streams.join_next(), if !streams.is_empty() => {
                    joined.ok_or("response task disappeared")???;
                    continue;
                }
                stopped = async { stopping.wait_for(|stopped| *stopped).await.map(drop) } => {
                    stopped?;
                    break;
                }
                accepted = server.accept(), if accepting => match accepted {
                    Ok(accepted) => accepted,
                    Err(error) if error.is_h3_no_error() => {
                        accepting = false;
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                },
                changed = async {
                    goaway.wait_for(|target| *target == Some(connection)).await.map(drop)
                }, if !shutting_down => {
                    changed?;
                    tokio::select! {
                        released = async { goaway_released.wait_for(|released| *released).await.map(drop) } => {
                            released?;
                        }
                        stopped = async { stopping.wait_for(|stopped| *stopped).await.map(drop) } => {
                            stopped?;
                            break;
                        }
                    }
                    server.shutdown(0).await?;
                    eprintln!("HTTP/3 fixture: connection={connection} phase=goaway-write-completed");
                    shutting_down = true;
                    continue;
                }
            };
            let Some(resolver) = accepted else {
                // Keep the connection open for its owned response streams.
                accepting = false;
                continue;
            };
            let (request, mut stream) = tokio::select! {
                request = resolver.resolve_request() => request?,
                stopped = async { stopping.wait_for(|stopped| *stopped).await.map(drop) } => {
                    stopped?;
                    break;
                }
            };
            events.send(Event::Request { connection })?;
            let path = request.uri().path().to_owned();
            let mut released = released.clone();
            streams.spawn(async move {
                if path != "/warm" {
                    released.wait_for(|released| *released).await?;
                }
                stream
                    .send_response(Response::builder().status(StatusCode::OK).body(())?)
                    .await?;
                stream.send_data(Bytes::from_static(b"done")).await?;
                stream.finish().await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            });
        }
        Ok(())
    }
    .await;
    streams.abort_all();
    let mut result = primary;
    while let Some(joined) = streams.join_next().await {
        let cleanup = match joined {
            Ok(result) => result,
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error.into()),
        };
        result = finish_with_cleanup(result, cleanup);
    }
    result
}

fn bound(value: usize) -> TestResult<NonZeroUsize> {
    Ok(NonZeroUsize::new(value).ok_or("zero bound")?)
}

/// An HTTP/3 client whose QUIC TLS profile enables session tickets.
fn client_builder(identity: &TestIdentity) -> ClientBuilder {
    let base = client_settings();
    let mut quic_tls = base.tls().clone();
    quic_tls.session_tickets = phantom_profile::browser::chrome::v154_quic_tls().session_tickets;
    let http3 = Http3ClientSettings::new(
        quic_tls,
        base.quic_transport().clone(),
        base.http3().clone(),
        base.request().clone(),
    );
    let mut tcp_tls = tls_settings();
    tcp_tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    Client::builder(ClientProfile::new(tcp_tls).with_http3(http3))
        .add_root_certificate_der(identity.root_der.clone())
}

async fn send(client: &Client, uri: &str) -> TestResult<Response<phantom::ResponseBody>> {
    let request = client.get(HttpProtocol::Http3, uri)?;
    Ok(timeout(TEST_TIMEOUT, request.send())
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new("HTTP/3 request send exceeded its deadline", elapsed)
        })??)
}

async fn finish(response: Response<phantom::ResponseBody>) -> TestResult {
    let protocol = response
        .extensions()
        .get::<ResponseInfo>()
        .map(ResponseInfo::protocol);
    assert_eq!(protocol, Some(HttpProtocol::Http3));
    let body = timeout(TEST_TIMEOUT, response.into_body().collect())
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new("HTTP/3 response body exceeded its deadline", elapsed)
        })??
        .to_bytes();
    assert_eq!(body, "done");
    Ok(())
}

/// Sends one held request per path at once and returns their tasks.
fn spawn_held(
    requests: &mut Requests,
    client: &Client,
    origin: &Origin,
    paths: &[&str],
) -> std::ops::Range<usize> {
    let start = requests.len();
    for path in paths {
        let (client, uri) = (client.clone(), origin.uri(path));
        requests.spawn(
            async move { finish(send(&client, &uri).await?).await }.with_current_subscriber(),
        );
    }
    start..requests.len()
}

/// Sends `/warm` so the client knows the server's stream limit, then
/// [`REQUESTS`] held requests at once, and returns the connections the
/// origin accepted and the requests it saw before the release.
async fn connections_for(
    builder: ClientBuilder,
    identity: &TestIdentity,
    expected: usize,
    origins: &mut Vec<Origin>,
    requests: &mut Requests,
) -> TestResult<(usize, usize)> {
    origins.push(Origin::start(identity)?);
    let origin = origins.last_mut().ok_or("origin owner missing")?;
    let client = builder.build()?;
    finish(send(&client, &origin.uri("warm")).await?).await?;
    let held = spawn_held(requests, &client, origin, &["held"; REQUESTS]);
    // The warm request's connection and request count too.
    let observed = origin.settle(expected + 1).await?;
    origin.release();
    requests.join(held).await?;
    Ok((observed.0, observed.1 - 1))
}

async fn bounded<F>(future: F) -> TestResult
where
    F: std::future::Future<Output = TestResult>,
{
    timeout(Duration::from_secs(30), future)
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new("HTTP/3 connection test exceeded its deadline", elapsed)
        })?
}

#[tokio::test]
async fn requests_queue_on_one_connection_by_default() -> TestResult {
    let mut origins = Vec::new();
    let mut requests = Requests::default();
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        let (connections, requests) = connections_for(
            client_builder(&identity),
            &identity,
            2,
            &mut origins,
            &mut requests,
        )
        .await?;
        assert_eq!(connections, 1);
        // The server allows two streams; the rest wait on the one connection
        // for stream credit until those end.
        assert_eq!(requests, PEER_STREAMS as usize);
        Ok(())
    })
    .await;
    let mut result = primary;
    for origin in &mut origins {
        result = origin.finish(result).await;
    }
    requests.finish(result).await
}

/// Five requests at a server limit of two streams need three connections,
/// and a limit of two connections caps them at two.
#[tokio::test]
async fn saturated_connections_open_more_up_to_the_configured_limit() -> TestResult {
    let mut origins = Vec::new();
    let mut requests = Requests::default();
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        let builder = client_builder(&identity).max_http3_connections_per_origin(bound(4)?);
        let (connections, observed_requests) =
            connections_for(builder, &identity, REQUESTS, &mut origins, &mut requests).await?;
        // ceil(5 / 2) = 3 connections, below the limit of 4.
        assert_eq!(connections, 3);
        assert_eq!(observed_requests, REQUESTS);

        let identity = TestIdentity::generate()?;
        let builder = client_builder(&identity).max_http3_connections_per_origin(bound(2)?);
        let (connections, observed_requests) =
            connections_for(builder, &identity, 4, &mut origins, &mut requests).await?;
        // The limit caps it at two; the fifth stream waits for credit.
        assert_eq!(connections, 2);
        assert_eq!(observed_requests, 4);
        Ok(())
    })
    .await;
    let mut result = primary;
    for origin in &mut origins {
        result = origin.finish(result).await;
    }
    requests.finish(result).await
}

/// Concurrent requests to an origin with no connection share each setup
/// instead of opening one each.
#[tokio::test]
async fn concurrent_requests_to_a_cold_origin_do_not_stampede() -> TestResult {
    let mut origins = Vec::new();
    let mut requests = Requests::default();
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        origins.push(Origin::start(&identity)?);
        let origin = origins.last_mut().ok_or("origin owner missing")?;
        let client = client_builder(&identity).build()?;
        let tasks = spawn_held(&mut requests, &client, origin, &["warm"; REQUESTS]);
        // All five share the one connection, two streams at a time.
        assert_eq!(origin.settle(REQUESTS).await?, (1, REQUESTS));
        requests.join(tasks).await?;

        let identity = TestIdentity::generate()?;
        origins.push(Origin::start(&identity)?);
        let origin = origins.last_mut().ok_or("origin owner missing")?;
        let client = client_builder(&identity)
            .max_http3_connections_per_origin(bound(8)?)
            .build()?;
        let tasks = spawn_held(&mut requests, &client, origin, &["held"; 6]);
        // One setup at a time: each new connection takes two requests before
        // the next opens, so six requests need three connections, not six.
        assert_eq!(origin.settle(6).await?, (3, 6));
        origin.release();
        requests.join(tasks).await
    })
    .await;
    let mut result = primary;
    for origin in &mut origins {
        result = origin.finish(result).await;
    }
    requests.finish(result).await
}

#[tokio::test]
async fn a_draining_connection_takes_no_new_requests() -> TestResult {
    draining_configured_limit(false).await
}

async fn draining_configured_limit(delayed_goaway: bool) -> TestResult {
    let mut origins = Vec::new();
    let mut requests = Requests::default();
    let mut observed = GoawayObservation::new();
    let dispatch = observed.dispatch();
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        origins.push(Origin::start(&identity)?);
        let origin = origins.last_mut().ok_or("origin owner missing")?;
        let client = client_builder(&identity)
            .max_http3_connections_per_origin(bound(2)?)
            .build()?;
        finish(send(&client, &origin.uri("warm")).await?).await?;

        // Both connections fill up, so the location is at its limit.
        let held = spawn_held(
            &mut requests,
            &client,
            origin,
            &["held-1", "held-2", "held-3", "held-4"],
        );
        assert_eq!(origin.settle(5).await?, (2, 5));

        // After GOAWAY on connection 0, it no longer counts: the next request
        // opens connection 2 instead of queueing on a full one.
        origin
            .observe_goaway(0, &mut observed, delayed_goaway)
            .await?;
        let next = spawn_held(&mut requests, &client, origin, &["held-5"]);
        assert_eq!(origin.next_accepted().await?, 2);
        assert_eq!(origin.next_request().await?, 2);
        origin.release();
        requests.join(held).await?;
        requests.join(next).await
    })
    .with_subscriber(dispatch)
    .await;
    let mut result = primary;
    for origin in &mut origins {
        result = origin.finish(result).await;
    }
    requests.finish(result).await
}

#[tokio::test]
async fn a_draining_connection_is_replaced_at_the_default_limit() -> TestResult {
    draining_default_limit(false).await
}

async fn draining_default_limit(delayed_goaway: bool) -> TestResult {
    let mut origins = Vec::new();
    let mut requests = Requests::default();
    let mut observed = GoawayObservation::new();
    let dispatch = observed.dispatch();
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        origins.push(Origin::start(&identity)?);
        let origin = origins.last_mut().ok_or("origin owner missing")?;
        let client = client_builder(&identity).build()?;
        finish(send(&client, &origin.uri("warm")).await?).await?;
        let held = spawn_held(&mut requests, &client, origin, &["held-1"]);
        assert_eq!(origin.settle(2).await?, (1, 2));

        // The one connection drains, so the next request reconnects.
        origin
            .observe_goaway(0, &mut observed, delayed_goaway)
            .await?;
        let next = spawn_held(&mut requests, &client, origin, &["held-2"]);
        assert_eq!(origin.next_accepted().await?, 1);
        assert_eq!(origin.next_request().await?, 1);
        origin.release();
        requests.join(held).await?;
        requests.join(next).await
    })
    .with_subscriber(dispatch)
    .await;
    let mut result = primary;
    for origin in &mut origins {
        result = origin.finish(result).await;
    }
    requests.finish(result).await
}

#[tokio::test]
async fn a_new_connection_resumes_the_session_an_earlier_one_learned() -> TestResult {
    let mut origins = Vec::new();
    let mut requests = Requests::default();
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        origins.push(Origin::start(&identity)?);
        let origin = origins.last_mut().ok_or("origin owner missing")?;
        let client = client_builder(&identity)
            .max_http3_connections_per_origin(bound(2)?)
            .build()?;
        // Connection 0 makes a full handshake and receives tickets.
        finish(send(&client, &origin.uri("warm")).await?).await?;
        assert_eq!(origin.tickets.accepted.load(Ordering::SeqCst), 0);

        // Filling connection 0 opens connection 1, which presents a ticket.
        let held = spawn_held(
            &mut requests,
            &client,
            origin,
            &["held-1", "held-2", "held-3"],
        );
        assert_eq!(origin.settle(4).await?, (2, 4));
        assert_eq!(origin.tickets.accepted.load(Ordering::SeqCst), 1);
        origin.release();
        requests.join(held).await
    })
    .await;
    let mut result = primary;
    for origin in &mut origins {
        result = origin.finish(result).await;
    }
    requests.finish(result).await
}

#[test]
fn a_limit_above_the_ceiling_is_rejected_at_build() -> TestResult {
    let identity = TestIdentity::generate()?;
    client_builder(&identity)
        .max_http3_connections_per_origin(bound(8)?)
        .build()?;
    let error = client_builder(&identity)
        .max_http3_connections_per_origin(bound(9)?)
        .build()
        .err()
        .ok_or("nine HTTP/3 connections per origin must be rejected")?;
    assert_eq!(error.kind(), phantom::BuildErrorKind::InvalidPolicy);
    Ok(())
}

#[tokio::test]
async fn a_request_waiting_for_a_setup_takes_room_a_finished_stream_frees() -> TestResult {
    let mut origins = Vec::new();
    let mut requests = Requests::default();
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        // Connection 1's handshake waits until the test releases it.
        origins.push(Origin::with(&identity, Some(1))?);
        let origin = origins.last_mut().ok_or("origin owner missing")?;
        let client = client_builder(&identity)
            .max_http3_connections_per_origin(bound(2)?)
            .build()?;
        finish(send(&client, &origin.uri("warm")).await?).await?;

        // Two streams fill connection 0 and a third starts connection 1.
        let held = spawn_held(
            &mut requests,
            &client,
            origin,
            &["held-1", "held-2", "held-3"],
        );
        assert_eq!(origin.settle(3).await?, (2, 3));
        // This request waits: connection 0 is full and a setup is in flight.
        let waiting = spawn_held(&mut requests, &client, origin, &["held-4"]);
        sleep(QUIET_WINDOW).await;
        assert!(!requests.any_finished(waiting.clone())?);

        // Connection 0's streams end, which wakes the waiting request while
        // connection 1's setup is still held.
        origin.release();
        assert_eq!(origin.next_request().await?, 0);
        requests.join(waiting).await?;

        origin.release_handshake();
        requests.join(held).await
    })
    .await;
    let mut result = primary;
    for origin in &mut origins {
        result = origin.finish(result).await;
    }
    requests.finish(result).await
}

/// Owns the advertising listener and each TLS response child.
struct AdvertisingOrigin {
    stopping: watch::Sender<bool>,
    task: ConnectionPeer<TestResult>,
}

impl AdvertisingOrigin {
    async fn finish(&mut self, primary: TestResult) -> TestResult {
        self.stopping.send_replace(true);
        let cleanup = async {
            timeout(Duration::from_secs(5), self.task.join())
                .await
                .map_err(|elapsed| {
                    FixtureDeadline::new(
                        "Alt-Svc advertiser cleanup exceeded its deadline",
                        elapsed,
                    )
                })???;
            Ok(())
        }
        .await;
        finish_with_cleanup(primary, cleanup)
    }
}

/// An H1 origin that advertises the H3 alternative at `alternative`'s port.
async fn advertising_origin(
    identity: &TestIdentity,
    alternative: u16,
) -> TestResult<(SocketAddr, AdvertisingOrigin)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let (stopping, mut stopped) = watch::channel(false);
    let task = ConnectionPeer::spawn(async move {
        let mut peers = JoinSet::new();
        let primary: TestResult = async {
            loop {
                tokio::select! {
                    biased;
                    joined = peers.join_next(), if !peers.is_empty() => {
                        joined.ok_or("advertising response disappeared")???;
                    }
                    changed = async { stopped.wait_for(|stopped| *stopped).await.map(drop) } => {
                        changed?;
                        break;
                    }
                    accepted = listener.accept() => {
                        let (tcp, _) = accepted?;
                        let acceptor = acceptor.clone();
                        peers.spawn(async move {
                            let mut stream = accept_tls_stream(tcp, acceptor).await?;
                            read_head(&mut stream).await?;
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nalt-svc: h3=\":{alternative}\"\r\n\
                                 content-length: 4\r\nconnection: close\r\n\r\ndone"
                            );
                            stream.write_all(response.as_bytes()).await?;
                            stream.shutdown().await?;
                            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                        });
                    }
                }
            }
            Ok(())
        }
        .await;
        peers.abort_all();
        let mut result = primary;
        while let Some(joined) = peers.join_next().await {
            let cleanup = match joined {
                Ok(result) => result,
                Err(error) if error.is_cancelled() => Ok(()),
                Err(error) => Err(error.into()),
            };
            result = finish_with_cleanup(result, cleanup);
        }
        result
    });
    Ok((address, AdvertisingOrigin { stopping, task }))
}

#[tokio::test]
async fn an_alt_svc_alternative_opens_more_connections_up_to_the_limit() -> TestResult {
    let mut origins = Vec::new();
    let mut requests = Requests::default();
    let mut advertiser = None;
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        origins.push(Origin::start(&identity)?);
        let alternative = origins.last_mut().ok_or("origin owner missing")?;
        let (address, origin) = advertising_origin(&identity, alternative.address.port()).await?;
        advertiser = Some(origin);
        let base = client_settings();
        let http3 = Http3ClientSettings::new(
            base.tls().clone(),
            base.quic_transport().clone(),
            base.http3().clone(),
            base.request().clone(),
        );
        let profile = ClientProfile::new(tls_settings())
            .with_http2(phantom::profile::browser::chrome::v154_http2())
            .with_http3(http3);
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .alt_svc(bound(8)?)
            .max_http3_connections_per_origin(bound(2)?)
            .build()?;

        // The first request learns the alternative over HTTP/1.1.
        let learned = timeout(
            TEST_TIMEOUT,
            client
                .get_negotiated(&format!("https://{address}/warm"))?
                .send(),
        )
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new("Alt-Svc discovery request exceeded its deadline", elapsed)
        })??;
        assert_eq!(
            learned
                .extensions()
                .get::<ResponseInfo>()
                .map(ResponseInfo::protocol),
            Some(HttpProtocol::Http1)
        );
        timeout(TEST_TIMEOUT, learned.into_body().collect())
            .await
            .map_err(|elapsed| {
                FixtureDeadline::new("Alt-Svc discovery body exceeded its deadline", elapsed)
            })??;

        // Three held requests at two streams per connection use both
        // connections the limit allows to the alternative.
        let start = requests.len();
        for path in ["held-1", "held-2", "held-3"] {
            let (client, uri) = (client.clone(), format!("https://{address}/{path}"));
            requests.spawn(async move {
                let request = client.get_negotiated(&uri)?;
                let response =
                    timeout(TEST_TIMEOUT, request.send())
                        .await
                        .map_err(|elapsed| {
                            FixtureDeadline::new(
                                "Alt-Svc held request exceeded its deadline",
                                elapsed,
                            )
                        })??;
                finish(response).await
            });
        }
        let held = start..requests.len();
        assert_eq!(alternative.settle(3).await?, (2, 3));
        alternative.release();
        requests.join(held).await?;
        Ok(())
    })
    .await;
    let mut result = primary;
    for origin in &mut origins {
        result = origin.finish(result).await;
    }
    if let Some(origin) = &mut advertiser {
        result = origin.finish(result).await;
    }
    requests.finish(result).await
}

mod peer_controls;
