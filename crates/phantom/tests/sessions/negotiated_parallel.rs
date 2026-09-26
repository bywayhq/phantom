//! Parallel connections for negotiated HTTP/1.1-or-HTTP/2 requests.
//!
//! When ALPN selects HTTP/1.1, concurrent requests to one origin and route
//! open connections up to the profile's HTTP/1.1 bound, each with its own TLS
//! handshake. When it selects HTTP/2, the requests share one connection.

use crate::support::reserved_port;
use crate::support::tls as tls_support;
use crate::support::tracing as tracing_support;

use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, HttpProxy, RequestErrorKind, RequestTimeouts, ResponseBody, ResponseInfo,
    RetryPolicy, Route,
    profile::{ClientProfile, chromium, firefox},
};
use tokio::{
    io::{AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
    time::{sleep, timeout},
};

use btls::ssl::SslAcceptor;
use tracing::instrument::WithSubscriber;

use reserved_port::ReservedPort;
use tracing_support::OutcomeSubscriber;

use tls_support::{
    H1_ALPN, H2_ALPN, TestIdentity, accept_tls_stream, client_builder, read_head, tls_settings,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a request must stay queued, or a listener stay quiet, to count as
/// waiting rather than merely slow.
const QUIET_WINDOW: Duration = Duration::from_millis(200);

/// What a loopback origin observed, in order.
#[derive(Debug, Eq, PartialEq)]
enum Event {
    /// The listener accepted its nth TCP connection, counting from zero.
    Accepted(usize),
    /// A request arrived on the numbered connection.
    Request { connection: usize, path: String },
    /// The numbered connection ended, whichever side closed it.
    Closed(usize),
}

#[derive(Clone, Copy)]
enum Alpn {
    Http1,
    Http2,
}

/// How a loopback origin treats its connections.
#[derive(Clone, Copy)]
struct Config {
    alpn: Alpn,
    /// Complete no TLS handshake until this many TCP connections arrived, so
    /// a client that waited for one handshake before the next would stall.
    gate: usize,
    /// Wait this long before each TLS handshake.
    handshake_delay: Duration,
    /// Answer no request until [`Origin::release`].
    hold_responses: bool,
    /// Close the connection, unanswered, the first time `/stale` arrives.
    drop_first_stale: bool,
}

impl Config {
    const fn new(alpn: Alpn) -> Self {
        Self {
            alpn,
            gate: 0,
            handshake_delay: Duration::ZERO,
            hold_responses: false,
            drop_first_stale: false,
        }
    }

    const fn gate(mut self, gate: usize) -> Self {
        self.gate = gate;
        self
    }
}

/// A loopback TLS origin that selects one protocol and answers every request
/// with a 4-byte body.
struct Origin {
    address: SocketAddr,
    events: mpsc::UnboundedReceiver<Event>,
    release: watch::Sender<bool>,
    task: JoinHandle<()>,
}

/// What each served connection shares with the origin.
#[derive(Clone)]
struct Shared {
    events: mpsc::UnboundedSender<Event>,
    release: watch::Receiver<bool>,
    stale_dropped: Arc<AtomicBool>,
    config: Config,
}

impl Origin {
    async fn start(identity: &TestIdentity, alpn: Alpn, gate: usize) -> TestResult<Self> {
        Self::with(identity, Config::new(alpn).gate(gate)).await
    }

    async fn with(identity: &TestIdentity, config: Config) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        Self::serve(identity, config, listener)
    }

    /// Serves on a listener the test already bound.
    fn serve(identity: &TestIdentity, config: Config, listener: TcpListener) -> TestResult<Self> {
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(match config.alpn {
            Alpn::Http1 => H1_ALPN,
            Alpn::Http2 => H2_ALPN,
        })?;
        let (sender, events) = mpsc::unbounded_channel();
        let (release, released) = watch::channel(!config.hold_responses);
        let shared = Shared {
            events: sender,
            release: released,
            stale_dropped: Arc::new(AtomicBool::new(false)),
            config,
        };
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            let mut accepted = 0;
            while let Ok((tcp, _)) = listener.accept().await {
                if shared.events.send(Event::Accepted(accepted)).is_err() {
                    return;
                }
                held.push((accepted, tcp));
                accepted += 1;
                if accepted < config.gate {
                    continue;
                }
                for (index, tcp) in held.drain(..) {
                    let (acceptor, shared) = (acceptor.clone(), shared.clone());
                    tokio::spawn(async move {
                        sleep(shared.config.handshake_delay).await;
                        let events = shared.events.clone();
                        let _ = match shared.config.alpn {
                            Alpn::Http1 => serve_http1(tcp, acceptor, index, shared).await,
                            Alpn::Http2 => serve_http2(tcp, acceptor, index, shared).await,
                        };
                        let _ = events.send(Event::Closed(index));
                    });
                }
            }
        });
        Ok(Self {
            address,
            events,
            release,
            task,
        })
    }

    fn uri(&self, path: &str) -> String {
        format!("https://{}/{path}", self.address)
    }

    /// Lets a held origin answer every request, waiting or future.
    fn release(&self) {
        self.release.send_replace(true);
    }

    async fn next(&mut self) -> TestResult<Event> {
        Ok(timeout(TEST_TIMEOUT, self.events.recv())
            .await?
            .ok_or("origin stopped")?)
    }

    /// Returns the next request, skipping connection accepts and closes.
    async fn next_request(&mut self) -> TestResult<(usize, String)> {
        loop {
            if let Event::Request { connection, path } = self.next().await? {
                return Ok((connection, path));
            }
        }
    }

    /// Collects events until the origin stays quiet for the quiet window.
    async fn drain(&mut self) -> Vec<Event> {
        let mut events = Vec::new();
        while let Ok(Some(event)) = timeout(QUIET_WINDOW, self.events.recv()).await {
            events.push(event);
        }
        events
    }

    /// Fails if the origin observes anything within the quiet window.
    async fn assert_quiet(&mut self) -> TestResult {
        match timeout(QUIET_WINDOW, self.events.recv()).await {
            Err(_) => Ok(()),
            Ok(event) => Err(format!("unexpected origin event {event:?}").into()),
        }
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Shared {
    async fn released(&mut self) -> TestResult {
        self.release.wait_for(|released| *released).await?;
        Ok(())
    }

    /// Whether this request is the first `/stale` one, which goes unanswered.
    fn drops(&self, path: &str) -> bool {
        self.config.drop_first_stale
            && path == "stale"
            && !self.stale_dropped.swap(true, Ordering::AcqRel)
    }
}

async fn serve_http1(
    tcp: TcpStream,
    acceptor: SslAcceptor,
    connection: usize,
    mut shared: Shared,
) -> TestResult {
    let mut stream = accept_tls_stream(tcp, acceptor).await?;
    while let Ok(head) = read_head(&mut stream).await {
        let path = request_path(&head);
        let drops = shared.drops(&path);
        shared.events.send(Event::Request { connection, path })?;
        if drops {
            return Ok(());
        }
        shared.released().await?;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone")
            .await?;
    }
    Ok(())
}

async fn serve_http2(
    tcp: TcpStream,
    acceptor: SslAcceptor,
    connection: usize,
    shared: Shared,
) -> TestResult {
    let stream = accept_tls_stream(tcp, acceptor).await?;
    let mut server = ::http2::server::handshake(stream).await?;
    while let Some(accepted) = server.accept().await {
        let (request, mut respond) = accepted?;
        let path = request.uri().path().trim_start_matches('/').to_owned();
        shared.events.send(Event::Request { connection, path })?;
        let mut shared = shared.clone();
        tokio::spawn(async move {
            shared.released().await?;
            let mut body = respond
                .send_response(Response::builder().status(StatusCode::OK).body(())?, false)?;
            body.send_data(Bytes::from_static(b"done"), true)?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
    }
    Ok(())
}

fn request_path(head: &[u8]) -> String {
    let line = String::from_utf8_lossy(head);
    let target = line.split(' ').nth(1).unwrap_or_default();
    target.trim_start_matches('/').to_owned()
}

fn bound(value: usize) -> TestResult<NonZeroUsize> {
    Ok(NonZeroUsize::new(value).ok_or("zero bound")?)
}

/// A negotiated client whose profile has no HTTP/1.1 policy, with `bound`
/// HTTP/1.1 connections per origin and route.
fn client(identity: &TestIdentity, bound: NonZeroUsize) -> TestResult<Client> {
    Ok(client_builder(identity, true)
        .max_concurrent_http1_requests_per_origin(bound)
        .build()?)
}

fn protocol<B>(response: &Response<B>) -> TestResult<HttpProtocol> {
    response
        .extensions()
        .get::<ResponseInfo>()
        .map(ResponseInfo::protocol)
        .ok_or_else(|| "response omitted protocol metadata".into())
}

/// Sends a negotiated GET and returns its response with the body unread, so
/// an H1 connection stays busy until [`finish`].
async fn hold(client: &Client, uri: &str) -> TestResult<Response<ResponseBody>> {
    Ok(timeout(TEST_TIMEOUT, client.get_negotiated(uri)?.send()).await??)
}

async fn finish(response: Response<ResponseBody>) -> TestResult {
    let body = timeout(TEST_TIMEOUT, response.into_body().collect())
        .await??
        .to_bytes();
    assert_eq!(body, "done");
    Ok(())
}

/// Sends one negotiated GET per URI at once and returns each protocol.
async fn concurrently(client: &Client, uris: &[String]) -> TestResult<Vec<HttpProtocol>> {
    let mut tasks = Vec::new();
    for uri in uris {
        let request = client.get_negotiated(uri)?;
        tasks.push(tokio::spawn(async move {
            let response = request.send().await?;
            let selected = protocol(&response)?;
            finish(response).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(selected)
        }));
    }
    let mut protocols = Vec::new();
    for task in tasks {
        protocols.push(timeout(TEST_TIMEOUT, task).await???);
    }
    Ok(protocols)
}

fn accepted(events: &[Event]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event, Event::Accepted(_)))
        .count()
}

/// The connections that ended, in index order.
fn closed(events: &[Event]) -> Vec<usize> {
    let mut closed = events
        .iter()
        .filter_map(|event| match event {
            Event::Closed(connection) => Some(*connection),
            _ => None,
        })
        .collect::<Vec<_>>();
    closed.sort_unstable();
    closed
}

fn request_connections(events: &[Event]) -> Vec<usize> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Request { connection, .. } => Some(*connection),
            Event::Accepted(_) | Event::Closed(_) => None,
        })
        .collect()
}

async fn bounded<F>(future: F) -> TestResult
where
    F: Future<Output = TestResult>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "negotiated parallel test exceeded its deadline")?
}

#[tokio::test]
async fn first_contact_with_an_http1_origin_opens_parallel_handshakes_up_to_the_bound() -> TestResult
{
    bounded(async {
        let identity = TestIdentity::generate()?;
        // No handshake completes before three TCP connections arrive, so the
        // requests succeed only if their handshakes run in parallel.
        let mut origin = Origin::start(&identity, Alpn::Http1, 3).await?;
        let client = client(&identity, bound(3)?)?;

        let uris = (0..5)
            .map(|index| origin.uri(&format!("request-{index}")))
            .collect::<Vec<_>>();
        let protocols = concurrently(&client, &uris).await?;
        assert_eq!(protocols, [HttpProtocol::Http1; 5]);

        let events = origin.drain().await;
        assert_eq!(accepted(&events), 3);
        assert_eq!(request_connections(&events).len(), 5);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn fewer_requests_than_the_bound_open_one_connection_each() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let mut origin = Origin::start(&identity, Alpn::Http1, 2).await?;
        let client = client(&identity, bound(6)?)?;

        let uris = [origin.uri("first"), origin.uri("second")];
        let protocols = concurrently(&client, &uris).await?;
        assert_eq!(protocols, [HttpProtocol::Http1; 2]);

        let events = origin.drain().await;
        assert_eq!(accepted(&events), 2);
        let mut connections = request_connections(&events);
        connections.sort_unstable();
        assert_eq!(connections, [0, 1]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn named_recipe_opens_six_negotiated_http1_connections() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        for recipe in [chromium::v154_http1(), firefox::v156_http1()] {
            let mut origin = Origin::start(&identity, Alpn::Http1, 0).await?;
            let profile = ClientProfile::new(tls_settings())
                .with_http2(chromium::v154_http2())
                .with_http1(recipe);
            let client = Client::builder(profile)
                .add_root_certificate_der(identity.root_der.clone())
                .build()?;

            let mut held = Vec::new();
            for index in 0..6 {
                let response = hold(&client, &origin.uri(&format!("held-{index}"))).await?;
                assert_eq!(protocol(&response)?, HttpProtocol::Http1);
                held.push(response);
            }
            let mut seventh = tokio::spawn(client.get_negotiated(&origin.uri("seventh"))?.send());
            assert!(
                timeout(QUIET_WINDOW, &mut seventh).await.is_err(),
                "a seventh request ran while six connections were busy"
            );
            assert_eq!(accepted(&origin.drain().await), 6);

            for response in held {
                finish(response).await?;
            }
            finish(timeout(TEST_TIMEOUT, seventh).await???).await?;
            // The seventh request reused a connection.
            assert_eq!(accepted(&origin.drain().await), 0);
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn idle_negotiated_http1_connection_is_reused_before_another_opens() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let mut origin = Origin::start(&identity, Alpn::Http1, 0).await?;
        let client = client(&identity, bound(6)?)?;

        let first = hold(&client, &origin.uri("first")).await?;
        let second = hold(&client, &origin.uri("second")).await?;
        assert_eq!(origin.next().await?, Event::Accepted(0));
        assert_eq!(origin.next_request().await?, (0, "first".to_owned()));
        assert_eq!(origin.next().await?, Event::Accepted(1));
        assert_eq!(origin.next_request().await?, (1, "second".to_owned()));

        finish(second).await?;
        let third = hold(&client, &origin.uri("third")).await?;
        assert_eq!(
            origin.next().await?,
            Event::Request {
                connection: 1,
                path: "third".to_owned(),
            }
        );
        finish(third).await?;
        finish(first).await?;
        origin.assert_quiet().await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn negotiated_http1_request_beyond_the_bound_waits_for_a_free_connection() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let mut origin = Origin::start(&identity, Alpn::Http1, 0).await?;
        let client = client(&identity, bound(2)?)?;

        let first = hold(&client, &origin.uri("first")).await?;
        let second = hold(&client, &origin.uri("second")).await?;
        assert_eq!(accepted(&origin.drain().await), 2);

        let mut third = tokio::spawn(client.get_negotiated(&origin.uri("third"))?.send());
        origin.assert_quiet().await?;
        assert!(
            timeout(QUIET_WINDOW, &mut third).await.is_err(),
            "a third request ran while two connections were busy"
        );

        finish(first).await?;
        let third = timeout(TEST_TIMEOUT, third).await???;
        assert_eq!(
            origin.next().await?,
            Event::Request {
                connection: 0,
                path: "third".to_owned(),
            }
        );
        finish(second).await?;
        finish(third).await?;
        origin.assert_quiet().await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn first_contact_with_an_h2_origin_converges_on_one_connection() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        // Before any ALPN result the key is unknown, so three handshakes start
        // at once, as they do in Chromium and Firefox.
        let mut origin = Origin::start(&identity, Alpn::Http2, 3).await?;
        let client = client(&identity, bound(3)?)?;

        let uris = (0..3)
            .map(|index| origin.uri(&format!("request-{index}")))
            .collect::<Vec<_>>();
        let protocols = concurrently(&client, &uris).await?;
        assert_eq!(protocols, [HttpProtocol::Http2; 3]);

        let events = origin.drain().await;
        assert_eq!(accepted(&events), 3);
        let connections = request_connections(&events);
        assert_eq!(connections.len(), 3);
        assert!(
            connections.iter().all(|index| *index == connections[0]),
            "H2 requests were spread over connections {connections:?}"
        );
        // The client closed the two connections that lost the race.
        let redundant = (0..3)
            .filter(|index| *index != connections[0])
            .collect::<Vec<_>>();
        assert_eq!(closed(&events), redundant);

        // Later requests stay on the one H2 connection.
        let later = hold(&client, &origin.uri("later")).await?;
        assert_eq!(protocol(&later)?, HttpProtocol::Http2);
        finish(later).await?;
        assert_eq!(origin.next_request().await?.0, connections[0]);
        origin.assert_quiet().await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn concurrent_requests_to_a_known_h2_origin_wait_for_the_handshake_in_flight() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (closed_tx, closed_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            // The first connection teaches the client that the origin
            // selects H2, then closes after one request.
            let (tcp, _) = listener.accept().await?;
            let stream = accept_tls_stream(tcp, acceptor.clone()).await?;
            let mut first = ::http2::server::handshake(stream).await?;
            let (_, mut respond) = first.accept().await.ok_or("no first request")??;
            let mut body = respond
                .send_response(Response::builder().status(StatusCode::OK).body(())?, false)?;
            body.send_data(Bytes::from_static(b"done"), true)?;
            first.graceful_shutdown();
            // The client may drop the connection first; Windows reports that
            // as `ConnectionAborted`.
            while let Some(Ok(_)) = first.accept().await {}
            drop(first);
            closed_tx.send(()).map_err(|_| "client stopped")?;

            // The replacement's handshake is held for the quiet window; no
            // other connection may open while it is in flight.
            let (tcp, _) = listener.accept().await?;
            let extra_during_setup = timeout(QUIET_WINDOW, listener.accept()).await.is_ok();
            let stream = accept_tls_stream(tcp, acceptor).await?;
            let mut second = ::http2::server::handshake(stream).await?;
            let mut served = 0;
            while served < 3 {
                let (_, mut respond) = second.accept().await.ok_or("replacement closed")??;
                let mut body = respond
                    .send_response(Response::builder().status(StatusCode::OK).body(())?, false)?;
                body.send_data(Bytes::from_static(b"done"), true)?;
                served += 1;
            }
            let extra_after = tokio::select! {
                _ = async { while let Some(Ok(_)) = second.accept().await {} } => false,
                accepted = timeout(QUIET_WINDOW, listener.accept()) => accepted.is_ok(),
            };
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((extra_during_setup, extra_after))
        });

        let client = client(&identity, bound(3)?)?;
        let first = hold(&client, &format!("https://{address}/first")).await?;
        assert_eq!(protocol(&first)?, HttpProtocol::Http2);
        finish(first).await?;
        if timeout(TEST_TIMEOUT, closed_rx).await?.is_err() {
            return Err(format!("origin failed: {:?}", server.await?).into());
        }
        // Let the client observe the closed connection before reusing the key.
        sleep(QUIET_WINDOW).await;

        let uris = (0..3)
            .map(|index| format!("https://{address}/after-{index}"))
            .collect::<Vec<_>>();
        let protocols = concurrently(&client, &uris).await?;
        assert_eq!(protocols, [HttpProtocol::Http2; 3]);

        let (extra_during_setup, extra_after) = timeout(TEST_TIMEOUT, server).await???;
        assert!(
            !extra_during_setup,
            "a request opened a connection while the known-H2 handshake was in flight"
        );
        assert!(!extra_after, "a request opened a third connection");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn negotiated_http1_through_an_http_proxy_opens_one_tunnel_per_connection() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let mut origin = Origin::start(&identity, Alpn::Http1, 2).await?;
        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy.local_addr()?;
        let (connects_tx, mut connects) = mpsc::unbounded_channel();
        let origin_address = origin.address;
        let proxy_task = tokio::spawn(async move {
            while let Ok((mut downstream, _)) = proxy.accept().await {
                let connects_tx = connects_tx.clone();
                tokio::spawn(async move {
                    let head = read_head(&mut downstream).await?;
                    connects_tx.send(head)?;
                    let mut upstream = TcpStream::connect(origin_address).await?;
                    downstream
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await?;
                    let _ = copy_bidirectional(&mut downstream, &mut upstream).await;
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                });
            }
        });
        let client = client_builder(&identity, true)
            .max_concurrent_http1_requests_per_origin(bound(2)?)
            .route(Route::http_proxy(HttpProxy::new(&format!(
                "http://{proxy_address}"
            ))?))
            .build()?;

        let uris = [origin.uri("first"), origin.uri("second")];
        let protocols = concurrently(&client, &uris).await?;
        assert_eq!(protocols, [HttpProtocol::Http1; 2]);
        // An idle tunnel carries the next request.
        let third = hold(&client, &origin.uri("third")).await?;
        finish(third).await?;

        let events = origin.drain().await;
        assert_eq!(accepted(&events), 2);
        assert_eq!(request_connections(&events).len(), 3);
        let expected =
            format!("CONNECT {origin_address} HTTP/1.1\r\nHost: {origin_address}\r\n\r\n");
        for _ in 0..2 {
            let head = timeout(TEST_TIMEOUT, connects.recv())
                .await?
                .ok_or("proxy stopped")?;
            assert_eq!(String::from_utf8(head)?, expected);
        }
        assert!(
            timeout(QUIET_WINDOW, connects.recv()).await.is_err(),
            "the proxy saw a third CONNECT"
        );
        proxy_task.abort();
        Ok(())
    })
    .await
}

/// What one concurrent request ended with: its protocol, or its error kind
/// and protocol.
type Outcome = Result<HttpProtocol, (RequestErrorKind, Option<HttpProtocol>)>;

/// Starts one negotiated GET per URI; each task reads its whole body.
fn spawn_all(client: &Client, uris: &[String]) -> TestResult<Vec<JoinHandle<TestResult<Outcome>>>> {
    let mut tasks = Vec::new();
    for uri in uris {
        let request = client.get_negotiated(uri)?;
        tasks.push(tokio::spawn(async move {
            let response = match request.send().await {
                Ok(response) => response,
                Err(error) => return Ok(Err((error.kind(), error.protocol()))),
            };
            let selected = protocol(&response)?;
            finish(response).await?;
            Ok(Ok(selected))
        }));
    }
    Ok(tasks)
}

#[tokio::test]
async fn burst_past_the_http1_limits_to_a_new_h2_origin_succeeds_on_one_connection() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        // The slow handshake keeps every request waiting before ALPN answers.
        let config = Config {
            handshake_delay: QUIET_WINDOW,
            ..Config::new(Alpn::Http2)
        };
        let mut origin = Origin::with(&identity, config).await?;
        // Two H1 slots and one H1 waiter; the H2 limits are 100 each.
        let client = client_builder(&identity, true)
            .max_concurrent_http1_requests_per_origin(bound(2)?)
            .max_pending_http1_requests_per_origin(NonZeroUsize::MIN)
            .build()?;

        let uris = (0..20)
            .map(|index| origin.uri(&format!("burst-{index}")))
            .collect::<Vec<_>>();
        let protocols = concurrently(&client, &uris).await?;
        assert_eq!(protocols, [HttpProtocol::Http2; 20]);

        let events = origin.drain().await;
        assert_eq!(accepted(&events), 2);
        let connections = request_connections(&events);
        assert_eq!(connections.len(), 20);
        assert!(
            connections.iter().all(|index| *index == connections[0]),
            "H2 requests were spread over connections {connections:?}"
        );
        assert_eq!(closed(&events), [1 - connections[0]]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn burst_to_a_new_http1_origin_meets_the_http1_limits() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let config = Config {
            handshake_delay: QUIET_WINDOW,
            hold_responses: true,
            ..Config::new(Alpn::Http1)
        };
        let mut origin = Origin::with(&identity, config).await?;
        let client = client_builder(&identity, true)
            .max_concurrent_http1_requests_per_origin(bound(2)?)
            .max_pending_http1_requests_per_origin(bound(3)?)
            .build()?;

        let uris = (0..12)
            .map(|index| origin.uri(&format!("burst-{index}")))
            .collect::<Vec<_>>();
        let mut tasks = spawn_all(&client, &uris)?;
        // Once a handshake selects H1, two requests run, three wait, and the
        // other seven fail at the H1 waiting bound.
        let mut rejected = Vec::new();
        while rejected.len() < 7 {
            sleep(Duration::from_millis(10)).await;
            let mut running = Vec::new();
            for task in tasks {
                if task.is_finished() {
                    rejected.push(task.await??);
                } else {
                    running.push(task);
                }
            }
            tasks = running;
        }
        assert_eq!(
            rejected,
            vec![Err((RequestErrorKind::Capacity, Some(HttpProtocol::Http1))); 7]
        );
        sleep(QUIET_WINDOW).await;
        assert!(tasks.iter().all(|task| !task.is_finished()));

        origin.release();
        for task in tasks {
            assert_eq!(
                timeout(TEST_TIMEOUT, task).await???,
                Ok(HttpProtocol::Http1)
            );
        }
        assert_eq!(accepted(&origin.drain().await), 2);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn short_pool_admission_timeout_spares_requests_waiting_for_a_handshake() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let config = Config {
            handshake_delay: QUIET_WINDOW,
            ..Config::new(Alpn::Http2)
        };
        let origin = Origin::with(&identity, config).await?;
        // Waiting for another request's handshake counts as connecting, so a
        // pool-admission limit shorter than the handshake fails nothing.
        let client = client_builder(&identity, true)
            .request_timeouts(RequestTimeouts::new().pool_admission(Duration::from_millis(20)))
            .build()?;

        let uris = (0..5)
            .map(|index| origin.uri(&format!("waiting-{index}")))
            .collect::<Vec<_>>();
        let protocols = concurrently(&client, &uris).await?;
        assert_eq!(protocols, [HttpProtocol::Http2; 5]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn setup_retry_delay_releases_the_connection_slot() -> TestResult {
    timeout(Duration::from_secs(20), async {
        let identity = TestIdentity::generate()?;
        let reserved = ReservedPort::bind()?;
        let address = reserved.address();
        let client = client_builder(&identity, true)
            .max_concurrent_http1_requests_per_origin(NonZeroUsize::MIN)
            .build()?;
        let uri = |path: &str| format!("https://{address}/{path}");

        let subscriber = OutcomeSubscriber::default();
        let delayed = client
            .get_negotiated(&uri("delayed"))?
            .retry_policy(RetryPolicy::connection_failures(
                NonZeroUsize::MIN,
                Duration::from_secs(2),
            ))
            .send()
            .with_subscriber(subscriber.dispatch());
        let delayed = tokio::spawn(delayed);
        // The refused connect puts the request in its retry delay.
        timeout(TEST_TIMEOUT, async {
            while subscriber.retry_reasons_for("client.request") != ["connection_setup"] {
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await?;

        let mut origin = Origin::serve(&identity, Config::new(Alpn::Http1), reserved.listen()?)?;
        // The only slot is free during the delay, so this request connects.
        let during = hold(&client, &uri("during")).await?;
        assert!(!delayed.is_finished(), "the delay ended before the check");
        finish(during).await?;

        let delayed = timeout(TEST_TIMEOUT, delayed).await???;
        finish(delayed).await?;
        let events = origin.drain().await;
        assert_eq!(accepted(&events), 1);
        assert_eq!(request_connections(&events), [0, 0]);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await
    .map_err(|_| "retry delay test exceeded its deadline")?
}

#[tokio::test]
async fn reused_connection_replay_opens_a_fresh_connection_past_idle_ones() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let config = Config {
            drop_first_stale: true,
            ..Config::new(Alpn::Http1)
        };
        let mut origin = Origin::with(&identity, config).await?;
        let client = client_builder(&identity, true)
            .max_concurrent_http1_requests_per_origin(bound(3)?)
            .retry_policy(RetryPolicy::none().with_reused_connection_replay(true))
            .build()?;

        let first = hold(&client, &origin.uri("first")).await?;
        let second = hold(&client, &origin.uri("second")).await?;
        finish(first).await?;
        finish(second).await?;
        assert_eq!(accepted(&origin.drain().await), 2);

        // The most recently used idle connection closes on the request; the
        // replay must not take the other idle one, which served a request.
        let stale = hold(&client, &origin.uri("stale")).await?;
        finish(stale).await?;
        assert_eq!(origin.next_request().await?, (1, "stale".to_owned()));
        let events = origin.drain().await;
        assert!(events.contains(&Event::Accepted(2)), "{events:?}");
        assert_eq!(request_connections(&events), [2]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn requests_cancelled_during_handshakes_release_their_slots() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        // No handshake completes before a third connection arrives.
        let mut origin = Origin::start(&identity, Alpn::Http1, 3).await?;
        let client = client(&identity, bound(2)?)?;

        let setups = spawn_all(
            &client,
            &[origin.uri("cancelled-0"), origin.uri("cancelled-1")],
        )?;
        assert_eq!(origin.next().await?, Event::Accepted(0));
        assert_eq!(origin.next().await?, Event::Accepted(1));
        for setup in setups {
            setup.abort();
            assert!(setup.await.is_err_and(|error| error.is_cancelled()));
        }

        // Both slots came back, so two new requests open two connections.
        let uris = [origin.uri("first"), origin.uri("second")];
        let protocols = concurrently(&client, &uris).await?;
        assert_eq!(protocols, [HttpProtocol::Http1; 2]);
        let events = origin.drain().await;
        assert_eq!(accepted(&events), 2);
        let mut connections = request_connections(&events);
        connections.sort_unstable();
        assert_eq!(connections, [2, 3]);
        Ok(())
    })
    .await
}
