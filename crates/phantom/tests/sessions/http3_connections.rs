//! Opt-in HTTP/3 connections per origin.
//!
//! By default a pool key keeps one HTTP/3 connection per transport location,
//! as browsers do. With `max_http3_connections_per_origin`, requests that
//! find every connection at the server's `initial_max_streams_bidi` open
//! another, up to the configured count.

use crate::support::h3 as h3_support;
use crate::support::tls as tls_support;

use std::{
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::{
        Arc,
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
    sync::{mpsc, watch},
    task::JoinHandle,
    time::{sleep, timeout},
};

use h3_support::client_settings;
use tls_support::{TestIdentity, tls_settings};

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
    tickets: Arc<CountingStore>,
    task: JoinHandle<()>,
}

impl Origin {
    fn start(identity: &TestIdentity) -> TestResult<Self> {
        Self::with(identity, None)
    }

    /// Like [`Origin::start`], and answers the `stalled` connection's
    /// handshake only after 3 seconds.
    fn with(identity: &TestIdentity, stalled: Option<usize>) -> TestResult<Self> {
        let tickets = Arc::new(CountingStore {
            inner: ServerSessionMemoryCache::new(64),
            accepted: AtomicUsize::new(0),
        });
        let endpoint = quinn::Endpoint::server(
            server_config(identity, Arc::clone(&tickets))?,
            (Ipv4Addr::LOCALHOST, 0).into(),
        )?;
        let address = endpoint.local_addr()?;
        let (sender, events) = mpsc::unbounded_channel();
        let (release, released) = watch::channel(false);
        let (goaway, goaway_requested) = watch::channel(None);
        let task = tokio::spawn(async move {
            let mut accepted = 0;
            while let Some(incoming) = endpoint.accept().await {
                let index = accepted;
                accepted += 1;
                if sender.send(Event::Accepted(index)).is_err() {
                    return;
                }
                let (sender, released, goaway) =
                    (sender.clone(), released.clone(), goaway_requested.clone());
                tokio::spawn(async move {
                    if stalled == Some(index) {
                        sleep(Duration::from_secs(3)).await;
                    }
                    let _ = serve(incoming, index, sender, released, goaway).await;
                });
            }
        });
        Ok(Self {
            address,
            events,
            release,
            goaway,
            tickets,
            task,
        })
    }

    /// Sends GOAWAY on the numbered connection; its open streams finish.
    fn goaway(&self, connection: usize) {
        self.goaway.send_replace(Some(connection));
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
                .await?
                .ok_or("origin stopped")?
            {
                Event::Accepted(_) => connections += 1,
                Event::Request { .. } => seen += 1,
            }
        }
        while let Ok(Some(event)) = timeout(QUIET_WINDOW, self.events.recv()).await {
            match event {
                Event::Accepted(_) => connections += 1,
                Event::Request { .. } => seen += 1,
            }
        }
        Ok((connections, seen))
    }

    /// Returns the connection that carried the next request.
    async fn next_request(&mut self) -> TestResult<usize> {
        loop {
            match timeout(TEST_TIMEOUT, self.events.recv())
                .await?
                .ok_or("origin stopped")?
            {
                Event::Request { connection } => return Ok(connection),
                Event::Accepted(_) => {}
            }
        }
    }

    /// Returns the sorted connections of the next `count` requests, and
    /// fails if the origin accepts a connection meanwhile.
    async fn requests_without_new_connections(&mut self, count: usize) -> TestResult<Vec<usize>> {
        let mut connections = Vec::new();
        while connections.len() < count {
            match timeout(TEST_TIMEOUT, self.events.recv())
                .await?
                .ok_or("origin stopped")?
            {
                Event::Request { connection } => connections.push(connection),
                Event::Accepted(index) => return Err(format!("connection {index} opened").into()),
            }
        }
        connections.sort_unstable();
        Ok(connections)
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
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
) -> TestResult {
    let quic = incoming.await?;
    let mut server: h3::server::Connection<h3_quinn::Connection, Bytes> =
        h3::server::Connection::new(h3_quinn::Connection::new(quic)).await?;
    let mut shutting_down = false;
    loop {
        let accepted = tokio::select! {
            accepted = server.accept() => accepted?,
            changed = async {
                goaway
                    .wait_for(|target| *target == Some(connection))
                    .await
                    .map(drop)
            },
                if !shutting_down =>
            {
                changed?;
                // Streams already open still finish.
                server.shutdown(0).await?;
                shutting_down = true;
                continue;
            }
        };
        let Some(resolver) = accepted else {
            // Keep the connection open for the streams still being served.
            std::future::pending::<()>().await;
            return Ok(());
        };
        let (request, mut stream) = resolver.resolve_request().await?;
        events.send(Event::Request { connection })?;
        let path = request.uri().path().to_owned();
        let mut released = released.clone();
        tokio::spawn(async move {
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
}

fn bound(value: usize) -> TestResult<NonZeroUsize> {
    Ok(NonZeroUsize::new(value).ok_or("zero bound")?)
}

/// An HTTP/3 client whose QUIC TLS profile enables session tickets.
fn client_builder(identity: &TestIdentity) -> ClientBuilder {
    let base = client_settings();
    let mut quic_tls = base.tls().clone();
    quic_tls.session_tickets = true;
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
    Ok(timeout(TEST_TIMEOUT, request.send()).await??)
}

async fn finish(response: Response<phantom::ResponseBody>) -> TestResult {
    let protocol = response
        .extensions()
        .get::<ResponseInfo>()
        .map(ResponseInfo::protocol);
    assert_eq!(protocol, Some(HttpProtocol::Http3));
    let body = timeout(TEST_TIMEOUT, response.into_body().collect())
        .await??
        .to_bytes();
    assert_eq!(body, "done");
    Ok(())
}

/// Sends one held request per path at once and returns their tasks.
fn spawn_held(client: &Client, origin: &Origin, paths: &[&str]) -> Vec<JoinHandle<TestResult>> {
    paths
        .iter()
        .map(|path| {
            let (client, uri) = (client.clone(), origin.uri(path));
            tokio::spawn(async move { finish(send(&client, &uri).await?).await })
        })
        .collect()
}

async fn join(tasks: Vec<JoinHandle<TestResult>>) -> TestResult {
    for task in tasks {
        timeout(TEST_TIMEOUT, task).await???;
    }
    Ok(())
}

/// Sends `/warm` so the client knows the server's stream limit, then
/// [`REQUESTS`] held requests at once, and returns the connections the
/// origin accepted and the requests it saw before the release.
async fn connections_for(
    builder: ClientBuilder,
    identity: &TestIdentity,
    expected: usize,
) -> TestResult<(usize, usize)> {
    let mut origin = Origin::start(identity)?;
    let client = builder.build()?;
    finish(send(&client, &origin.uri("warm")).await?).await?;

    let held = spawn_held(&client, &origin, &["held"; REQUESTS]);
    // The warm request's connection and request count too.
    let observed = origin.settle(expected + 1).await?;
    origin.release();
    join(held).await?;
    Ok((observed.0, observed.1 - 1))
}

async fn bounded<F>(future: F) -> TestResult
where
    F: std::future::Future<Output = TestResult>,
{
    timeout(Duration::from_secs(30), future)
        .await
        .map_err(|_| "HTTP/3 connection test exceeded its deadline")?
}

#[tokio::test]
async fn requests_queue_on_one_connection_by_default() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (connections, requests) =
            connections_for(client_builder(&identity), &identity, 2).await?;
        assert_eq!(connections, 1);
        // The server allows two streams; the rest wait on the one connection
        // for stream credit until those end.
        assert_eq!(requests, PEER_STREAMS as usize);
        Ok(())
    })
    .await
}

/// Five requests at a server limit of two streams need three connections,
/// and a limit of two connections caps them at two.
#[tokio::test]
async fn saturated_connections_open_more_up_to_the_configured_limit() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let builder = client_builder(&identity).max_http3_connections_per_origin(bound(4)?);
        let (connections, requests) = connections_for(builder, &identity, REQUESTS).await?;
        // ceil(5 / 2) = 3 connections, below the limit of 4.
        assert_eq!(connections, 3);
        assert_eq!(requests, REQUESTS);

        let identity = TestIdentity::generate()?;
        let builder = client_builder(&identity).max_http3_connections_per_origin(bound(2)?);
        let (connections, requests) = connections_for(builder, &identity, 4).await?;
        // The limit caps it at two; the fifth stream waits for credit.
        assert_eq!(connections, 2);
        assert_eq!(requests, 4);
        Ok(())
    })
    .await
}

/// Concurrent requests to an origin with no connection share each setup
/// instead of opening one each.
#[tokio::test]
async fn concurrent_requests_to_a_cold_origin_do_not_stampede() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let mut origin = Origin::start(&identity)?;
        let client = client_builder(&identity).build()?;
        let tasks = spawn_held(&client, &origin, &["warm"; REQUESTS]);
        // All five share the one connection, two streams at a time.
        assert_eq!(origin.settle(REQUESTS).await?, (1, REQUESTS));
        join(tasks).await?;

        let identity = TestIdentity::generate()?;
        let mut origin = Origin::start(&identity)?;
        let client = client_builder(&identity)
            .max_http3_connections_per_origin(bound(8)?)
            .build()?;
        let tasks = spawn_held(&client, &origin, &["held"; 6]);
        // One setup at a time: each new connection takes two requests before
        // the next opens, so six requests need three connections, not six.
        assert_eq!(origin.settle(6).await?, (3, 6));
        origin.release();
        join(tasks).await
    })
    .await
}

#[tokio::test]
async fn a_draining_connection_takes_no_new_requests() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let mut origin = Origin::start(&identity)?;
        let client = client_builder(&identity)
            .max_http3_connections_per_origin(bound(3)?)
            .build()?;
        finish(send(&client, &origin.uri("warm")).await?).await?;

        // Connection 0 fills up, so a third stream opens connection 1.
        let held = spawn_held(&client, &origin, &["held-1", "held-2", "held-3"]);
        assert_eq!(origin.settle(4).await?, (2, 4));

        // After GOAWAY on connection 0, the next request goes to connection
        // 1, which has room, and opens no connection.
        origin.goaway(0);
        sleep(QUIET_WINDOW).await;
        let next = spawn_held(&client, &origin, &["held-4"]);
        assert_eq!(origin.requests_without_new_connections(1).await?, [1]);
        origin.release();
        join(held).await?;
        join(next).await
    })
    .await
}

#[tokio::test]
async fn a_new_connection_resumes_the_session_an_earlier_one_learned() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let mut origin = Origin::start(&identity)?;
        let client = client_builder(&identity)
            .max_http3_connections_per_origin(bound(2)?)
            .build()?;
        // Connection 0 makes a full handshake and receives tickets.
        finish(send(&client, &origin.uri("warm")).await?).await?;
        assert_eq!(origin.tickets.accepted.load(Ordering::SeqCst), 0);

        // Filling connection 0 opens connection 1, which presents a ticket.
        let held = spawn_held(&client, &origin, &["held-1", "held-2", "held-3"]);
        assert_eq!(origin.settle(4).await?, (2, 4));
        assert_eq!(origin.tickets.accepted.load(Ordering::SeqCst), 1);
        origin.release();
        join(held).await
    })
    .await
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
    bounded(async {
        let identity = TestIdentity::generate()?;
        // Connection 1's handshake stalls for 3 seconds.
        let mut origin = Origin::with(&identity, Some(1))?;
        let client = client_builder(&identity)
            .max_http3_connections_per_origin(bound(2)?)
            .build()?;
        finish(send(&client, &origin.uri("warm")).await?).await?;

        // Two streams fill connection 0 and a third starts connection 1.
        let held = spawn_held(&client, &origin, &["held-1", "held-2", "held-3"]);
        assert_eq!(origin.settle(3).await?, (2, 3));
        // This request waits: connection 0 is full and a setup is in flight.
        let waiting = spawn_held(&client, &origin, &["held-4"]);
        sleep(QUIET_WINDOW).await;
        assert!(!waiting.iter().any(JoinHandle::is_finished));

        // Connection 0's streams end, which wakes the waiting request before
        // the stalled setup finishes.
        let started = std::time::Instant::now();
        origin.release();
        assert_eq!(origin.next_request().await?, 0);
        join(waiting).await?;
        assert!(started.elapsed() < Duration::from_secs(2));
        for task in held {
            task.abort();
        }
        Ok(())
    })
    .await
}
