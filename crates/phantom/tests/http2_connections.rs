//! Opt-in HTTP/2 connections per origin, and the negotiated setup wait limit.
//!
//! By default a pool key keeps one HTTP/2 connection, as browsers do. With
//! `max_http2_connections_per_origin`, requests that find every connection
//! at the peer's stream limit open another, up to the configured count.

#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    time::Duration,
};

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use phantom::{Client, ClientBuilder, HttpProtocol, ResponseInfo};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, watch},
    task::JoinHandle,
    time::{sleep, timeout},
};

use btls::ssl::SslAcceptor;
use tls_support::{H2_ALPN, TestIdentity, accept_tls_stream, client_builder};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the origin must stay quiet for a request to count as queued.
const QUIET_WINDOW: Duration = Duration::from_millis(300);
/// The origin's `SETTINGS_MAX_CONCURRENT_STREAMS`.
const PEER_STREAMS: u32 = 2;
/// Requests sent at once in each connection-count test.
const REQUESTS: usize = 5;

#[derive(Debug)]
enum Event {
    Accepted(usize),
    Request { connection: usize },
}

/// A loopback HTTP/2 origin that allows two streams per connection and holds
/// every response except `/warm` until [`Origin::release`]. A `/head-*`
/// response sends its head at once and holds only its body.
struct Origin {
    address: SocketAddr,
    events: mpsc::UnboundedReceiver<Event>,
    release: watch::Sender<bool>,
    goaway: watch::Sender<Option<usize>>,
    task: JoinHandle<()>,
}

impl Origin {
    /// `stalled` names a connection whose TLS handshake waits 3 seconds.
    async fn start(identity: &TestIdentity, stalled: Option<usize>) -> TestResult<Self> {
        Self::with(identity, stalled, None).await
    }

    /// Like [`Origin::start`], and closes the `dropped` connection before
    /// its TLS handshake.
    async fn with(
        identity: &TestIdentity,
        stalled: Option<usize>,
        dropped: Option<usize>,
    ) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (sender, events) = mpsc::unbounded_channel();
        let (release, released) = watch::channel(false);
        let (goaway, goaway_requested) = watch::channel(None);
        let task = tokio::spawn(async move {
            let mut accepted = 0;
            while let Ok((tcp, _)) = listener.accept().await {
                let index = accepted;
                accepted += 1;
                if sender.send(Event::Accepted(index)).is_err() {
                    return;
                }
                let (acceptor, sender, released, goaway) = (
                    acceptor.clone(),
                    sender.clone(),
                    released.clone(),
                    goaway_requested.clone(),
                );
                if dropped == Some(index) {
                    drop(tcp);
                    continue;
                }
                tokio::spawn(async move {
                    if stalled == Some(index) {
                        sleep(Duration::from_secs(3)).await;
                    }
                    let _ = serve(tcp, acceptor, index, sender, released, goaway).await;
                });
            }
        });
        Ok(Self {
            address,
            events,
            release,
            goaway,
            task,
        })
    }

    /// Holds responses again after a release.
    fn hold(&self) {
        self.release.send_replace(false);
    }

    /// Sends a graceful GOAWAY on the numbered connection.
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

    async fn next_accepted(&mut self) -> TestResult<usize> {
        loop {
            match timeout(TEST_TIMEOUT, self.events.recv())
                .await?
                .ok_or("origin stopped")?
            {
                Event::Accepted(index) => return Ok(index),
                Event::Request { .. } => {}
            }
        }
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(
    tcp: TcpStream,
    acceptor: SslAcceptor,
    connection: usize,
    events: mpsc::UnboundedSender<Event>,
    released: watch::Receiver<bool>,
    mut goaway: watch::Receiver<Option<usize>>,
) -> TestResult {
    let stream = accept_tls_stream(tcp, acceptor).await?;
    let mut builder = ::http2::server::Builder::new();
    builder.max_concurrent_streams(PEER_STREAMS);
    let mut server = builder.handshake::<_, Bytes>(stream).await?;
    let mut shutting_down = false;
    loop {
        let accepted = tokio::select! {
            accepted = server.accept() => accepted,
            changed = goaway.wait_for(|target| *target == Some(connection)),
                if !shutting_down =>
            {
                changed?;
                // Streams already open still finish.
                server.graceful_shutdown();
                shutting_down = true;
                continue;
            }
        };
        let Some(accepted) = accepted else {
            return Ok(());
        };
        let (request, mut respond) = accepted?;
        events.send(Event::Request { connection })?;
        let path = request.uri().path().to_owned();
        let mut released = released.clone();
        tokio::spawn(async move {
            let mut body = None;
            if path.starts_with("/head") {
                body =
                    Some(respond.send_response(
                        Response::builder().status(StatusCode::OK).body(())?,
                        false,
                    )?);
            }
            if path != "/warm" {
                released.wait_for(|released| *released).await?;
            }
            let mut body = match body {
                Some(body) => body,
                None => respond
                    .send_response(Response::builder().status(StatusCode::OK).body(())?, false)?,
            };
            body.send_data(Bytes::from_static(b"done"), true)?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
    }
}

fn bound(value: usize) -> TestResult<NonZeroUsize> {
    Ok(NonZeroUsize::new(value).ok_or("zero bound")?)
}

#[derive(Clone, Copy)]
enum Mode {
    Exact,
    Negotiated,
}

async fn send(
    client: &Client,
    mode: Mode,
    uri: &str,
) -> TestResult<Response<phantom::ResponseBody>> {
    let request = match mode {
        Mode::Exact => client.get(HttpProtocol::Http2, uri)?,
        Mode::Negotiated => client.get_negotiated(uri)?,
    };
    Ok(timeout(TEST_TIMEOUT, request.send()).await??)
}

async fn finish(response: Response<phantom::ResponseBody>) -> TestResult {
    let protocol = response
        .extensions()
        .get::<ResponseInfo>()
        .map(ResponseInfo::protocol);
    assert_eq!(protocol, Some(HttpProtocol::Http2));
    let body = timeout(TEST_TIMEOUT, response.into_body().collect())
        .await??
        .to_bytes();
    assert_eq!(body, "done");
    Ok(())
}

/// Sends `/warm` so the client knows the peer's stream limit, then
/// [`REQUESTS`] held requests at once, and returns the connections the
/// origin accepted and the requests it saw before the release.
async fn connections_for_identity(
    builder: ClientBuilder,
    identity: &TestIdentity,
    mode: Mode,
    expected: usize,
) -> TestResult<(usize, usize)> {
    let mut origin = Origin::start(identity, None).await?;
    let client = builder.build()?;
    finish(send(&client, mode, &origin.uri("warm")).await?).await?;

    let mut tasks = Vec::new();
    for index in 0..REQUESTS {
        let (client, uri) = (client.clone(), origin.uri(&format!("held-{index}")));
        tasks.push(tokio::spawn(async move {
            finish(send(&client, mode, &uri).await?).await
        }));
    }
    // The warm request's connection and request count too.
    let observed = origin.settle(expected + 1).await?;
    origin.release();
    for task in tasks {
        timeout(TEST_TIMEOUT, task).await???;
    }
    Ok((observed.0, observed.1 - 1))
}

async fn bounded<F>(future: F) -> TestResult
where
    F: std::future::Future<Output = TestResult>,
{
    timeout(Duration::from_secs(30), future)
        .await
        .map_err(|_| "HTTP/2 connection test exceeded its deadline")?
}

/// Five requests at a peer limit of two streams need three connections.
#[tokio::test]
async fn full_connections_open_more_up_to_the_configured_limit() -> TestResult {
    bounded(async {
        for mode in [Mode::Exact, Mode::Negotiated] {
            let identity = TestIdentity::generate()?;
            let builder =
                client_builder(&identity, true).max_http2_connections_per_origin(bound(4)?);
            let (connections, requests) =
                connections_for_identity(builder, &identity, mode, 5).await?;
            // ceil(5 / 2) = 3 connections, below the limit of 4.
            assert_eq!(connections, 3);
            assert_eq!(requests, REQUESTS);

            let identity = TestIdentity::generate()?;
            let builder =
                client_builder(&identity, true).max_http2_connections_per_origin(bound(2)?);
            let (connections, requests) =
                connections_for_identity(builder, &identity, mode, 4).await?;
            // The limit caps it at two; the fifth stream waits for the peer.
            assert_eq!(connections, 2);
            assert_eq!(requests, 4);
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn one_connection_per_origin_is_the_default() -> TestResult {
    bounded(async {
        for mode in [Mode::Exact, Mode::Negotiated] {
            let identity = TestIdentity::generate()?;
            let builder = client_builder(&identity, true);
            let (connections, requests) =
                connections_for_identity(builder, &identity, mode, 2).await?;
            assert_eq!(connections, 1);
            // The peer allows two streams; the rest queue on the one
            // connection until those end.
            assert_eq!(requests, PEER_STREAMS as usize);
        }
        Ok(())
    })
    .await
}

/// Evicts the origin's pool entry, so the next request to it knows the
/// origin selected HTTP/2 but has no connection, then starts a request whose
/// TLS handshake the origin stalls for 3 seconds.
async fn stall_a_setup(
    client: &Client,
    origin: &mut Origin,
    other: &Origin,
) -> TestResult<JoinHandle<TestResult>> {
    finish(send(client, Mode::Negotiated, &origin.uri("warm")).await?).await?;
    // The client retains one negotiated pool entry.
    finish(send(client, Mode::Negotiated, &other.uri("warm")).await?).await?;
    let stalled = {
        let (client, uri) = (client.clone(), origin.uri("warm"));
        tokio::spawn(async move { finish(send(&client, Mode::Negotiated, &uri).await?).await })
    };
    assert_eq!(origin.next_request().await?, 0);
    assert_eq!(origin.next_accepted().await?, 1);
    Ok(stalled)
}

fn negotiated_builder(identity: &TestIdentity) -> TestResult<ClientBuilder> {
    Ok(client_builder(identity, true)
        .max_retained_http1_connections(NonZeroUsize::MIN)
        // Room for a second setup while the first holds a connection slot.
        .max_concurrent_http1_requests_per_origin(bound(6)?))
}

#[tokio::test]
async fn setup_wait_limit_opens_a_connection_past_a_stalled_handshake() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let mut origin = Origin::start(&identity, Some(1)).await?;
        let other = Origin::start(&identity, None).await?;
        let client = negotiated_builder(&identity)?
            .negotiated_setup_wait_limit(Duration::from_millis(100))
            .build()?;
        let stalled = stall_a_setup(&client, &mut origin, &other).await?;

        // After 100 ms the request opens connection 2 instead of waiting
        // for the stalled handshake of connection 1.
        let started = std::time::Instant::now();
        let response = send(&client, Mode::Negotiated, &origin.uri("warm")).await?;
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(origin.next_accepted().await?, 2);
        assert_eq!(origin.next_request().await?, 2);
        finish(response).await?;
        stalled.abort();
        Ok(())
    })
    .await
}

#[tokio::test]
async fn without_a_setup_wait_limit_a_request_waits_for_the_handshake() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let mut origin = Origin::start(&identity, Some(1)).await?;
        let other = Origin::start(&identity, None).await?;
        let client = negotiated_builder(&identity)?.build()?;
        let stalled = stall_a_setup(&client, &mut origin, &other).await?;

        let (client_clone, uri) = (client.clone(), origin.uri("warm"));
        let waiting = tokio::spawn(async move {
            finish(send(&client_clone, Mode::Negotiated, &uri).await?).await
        });
        // As Firefox does, the request waits and opens no connection.
        let opened = timeout(QUIET_WINDOW * 2, origin.next_accepted()).await;
        assert!(opened.is_err(), "a second setup opened: {opened:?}");
        assert!(!waiting.is_finished());
        waiting.abort();
        stalled.abort();
        Ok(())
    })
    .await
}

#[test]
fn an_unrepresentable_setup_wait_limit_is_rejected_at_build() -> TestResult {
    let identity = TestIdentity::generate()?;
    let error = client_builder(&identity, true)
        .negotiated_setup_wait_limit(Duration::MAX)
        .build()
        .err()
        .ok_or("a wait limit beyond the runtime clock must be rejected")?;
    assert_eq!(error.kind(), phantom::BuildErrorKind::InvalidPolicy);
    Ok(())
}

/// Sends one held exact request per path at once and returns their tasks.
fn spawn_held(client: &Client, origin: &Origin, paths: &[&str]) -> Vec<JoinHandle<TestResult>> {
    paths
        .iter()
        .map(|path| {
            let (client, uri) = (client.clone(), origin.uri(path));
            tokio::spawn(async move { finish(send(&client, Mode::Exact, &uri).await?).await })
        })
        .collect()
}

async fn join(tasks: Vec<JoinHandle<TestResult>>) -> TestResult {
    for task in tasks {
        timeout(TEST_TIMEOUT, task).await???;
    }
    Ok(())
}

/// Returns the sorted connections of the next `count` requests, and fails
/// if the origin accepts a connection meanwhile.
async fn requests_without_new_connections(
    origin: &mut Origin,
    count: usize,
) -> TestResult<Vec<usize>> {
    let mut connections = Vec::new();
    while connections.len() < count {
        match timeout(TEST_TIMEOUT, origin.events.recv())
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

#[tokio::test]
async fn stream_counts_fall_when_bodies_end_or_are_dropped() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let mut origin = Origin::start(&identity, None).await?;
        let client = client_builder(&identity, true)
            .max_http2_connections_per_origin(bound(2)?)
            .build()?;
        finish(send(&client, Mode::Exact, &origin.uri("warm")).await?).await?;
        assert_eq!(origin.next_request().await?, 0);

        // Two response heads arrive while their bodies are held; dropping
        // the bodies unread ends both streams.
        let first = send(&client, Mode::Exact, &origin.uri("head-1")).await?;
        let second = send(&client, Mode::Exact, &origin.uri("head-2")).await?;
        assert_eq!(
            requests_without_new_connections(&mut origin, 2).await?,
            [0, 0]
        );
        drop((first, second));

        // Connection 0 has room again, so two more streams need no new
        // connection.
        let tasks = spawn_held(&client, &origin, &["held-1", "held-2"]);
        assert_eq!(
            requests_without_new_connections(&mut origin, 2).await?,
            [0, 0]
        );
        origin.release();
        join(tasks).await?;

        // Those streams ended with their bodies, so connection 0 takes the
        // next two as well.
        origin.hold();
        let tasks = spawn_held(&client, &origin, &["held-3", "held-4"]);
        assert_eq!(
            requests_without_new_connections(&mut origin, 2).await?,
            [0, 0]
        );
        origin.release();
        join(tasks).await
    })
    .await
}

#[tokio::test]
async fn a_connection_that_received_goaway_takes_no_new_streams() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let mut origin = Origin::start(&identity, None).await?;
        let client = client_builder(&identity, true)
            .max_http2_connections_per_origin(bound(3)?)
            .build()?;
        finish(send(&client, Mode::Exact, &origin.uri("warm")).await?).await?;

        // Connection 0 fills up, so a third stream opens connection 1.
        let held = spawn_held(&client, &origin, &["held-1", "held-2", "held-3"]);
        assert_eq!(origin.settle(4).await?, (2, 4));

        // After GOAWAY on connection 0, the next stream goes to connection
        // 1, which has room.
        origin.goaway(0);
        sleep(QUIET_WINDOW).await;
        let next = spawn_held(&client, &origin, &["held-4"]);
        assert_eq!(requests_without_new_connections(&mut origin, 1).await?, [1]);
        origin.release();
        join(held).await?;
        join(next).await
    })
    .await
}

#[tokio::test]
async fn a_connection_with_room_serves_while_another_is_being_set_up() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        // Connection 1's TLS handshake stalls for 3 seconds.
        let mut origin = Origin::start(&identity, Some(1)).await?;
        let client = client_builder(&identity, true)
            .max_http2_connections_per_origin(bound(2)?)
            .build()?;
        finish(send(&client, Mode::Exact, &origin.uri("warm")).await?).await?;

        // Two streams fill connection 0; the third starts connection 1.
        let mut held = spawn_held(&client, &origin, &["held-1", "held-2", "held-3"]);
        // The warm request and two held ones reach connection 0; connection
        // 1 is accepted but its handshake stalls.
        assert_eq!(origin.settle(3).await?, (2, 3));
        let stalled = held.pop().ok_or("no third request")?;
        origin.release();
        join(held).await?;

        // Connection 0 has room again. The request does not wait behind the
        // stalled setup of connection 1.
        let started = std::time::Instant::now();
        finish(send(&client, Mode::Exact, &origin.uri("warm")).await?).await?;
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(origin.next_request().await?, 0);

        // Cancelling the stalled request frees its setup: once connection 0
        // is full again, the next request opens a connection of its own.
        stalled.abort();
        origin.hold();
        let held = spawn_held(&client, &origin, &["held-4", "held-5", "held-6"]);
        assert_eq!(origin.next_accepted().await?, 2);
        origin.release();
        join(held).await
    })
    .await
}

#[tokio::test]
async fn concurrent_requests_to_a_cold_origin_open_one_connection_by_default() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let mut origin = Origin::start(&identity, None).await?;
        let client = client_builder(&identity, true).build()?;
        let tasks = spawn_held(&client, &origin, &["warm"; REQUESTS]);
        // All five share the one connection, two streams at a time.
        assert_eq!(origin.settle(REQUESTS).await?, (1, REQUESTS));
        join(tasks).await
    })
    .await
}

#[tokio::test]
async fn a_failed_setup_lets_a_waiting_request_make_its_own_attempt() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        // Connection 0 closes before its TLS handshake.
        let mut origin = Origin::with(&identity, None, Some(0)).await?;
        let client = client_builder(&identity, true).build()?;
        let first = {
            let (client, uri) = (client.clone(), origin.uri("warm"));
            tokio::spawn(async move { send(&client, Mode::Exact, &uri).await.map(drop) })
        };
        let second = {
            let (client, uri) = (client.clone(), origin.uri("warm"));
            tokio::spawn(async move { send(&client, Mode::Exact, &uri).await.map(drop) })
        };
        let results = [
            timeout(TEST_TIMEOUT, first).await??,
            timeout(TEST_TIMEOUT, second).await??,
        ];
        // One request owned the failed setup; the other woke and connected.
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(origin.next_accepted().await?, 0);
        assert_eq!(origin.next_accepted().await?, 1);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_request_waiting_for_a_setup_takes_room_a_finished_stream_frees() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        // Connection 1's TLS handshake stalls for 3 seconds.
        let mut origin = Origin::start(&identity, Some(1)).await?;
        let client = client_builder(&identity, true)
            .max_http2_connections_per_origin(bound(2)?)
            .build()?;
        finish(send(&client, Mode::Exact, &origin.uri("warm")).await?).await?;

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
