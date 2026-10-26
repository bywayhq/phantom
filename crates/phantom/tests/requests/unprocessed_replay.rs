//! Opt-in replay of HTTP/2 and HTTP/3 requests the peer reported as not
//! processed.

use crate::support::h2 as h2_support;
use crate::support::h3 as h3_support;
use crate::support::tls as tls_support;
use crate::support::tracing as tracing_support;

use std::{
    error::Error,
    future::{Future, poll_fn},
    net::Ipv4Addr,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use btls::ssl::{Ssl, SslAcceptor};
use bytes::{Buf, Bytes};
use http::{Method, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use phantom::{
    Client, HttpProtocol, RedirectPolicy, RequestError, RequestErrorKind, ResponseInfo,
    RetryPolicy,
    profile::{ClientProfile, browser::chrome},
};
use phantom_net::http2::{Http2Error, Http2ProtocolError, Http2ProtocolErrorKind};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream;
use tracing::instrument::WithSubscriber;

use h2_support::{accept_client_preface, read_frame, read_request_headers, write_frame};
use h3_support::{accept_request, client_settings, server_endpoint};
use tls_support::{H2_ALPN, TestIdentity, client_builder, is_peer_gone, tls_settings};
use tracing_support::OutcomeSubscriber;

use super::ping_failure_replay::{
    drain_tls,
    replay_connections::{ReplayConnections, ReplaySpawner},
};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const HEADERS: u8 = 0x1;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const END_STREAM_AND_HEADERS: u8 = 0x5;
const NO_ERROR: u32 = 0x0;
const INTERNAL_ERROR: u32 = 0x2;
const ENHANCE_YOUR_CALM: u32 = 0xb;
// The longest script has three connections, their drivers, one body handler
// and its coordinator. Eight lifetime task slots cover that actual script.
const MAX_REPLAY_TASKS: usize = 8;
// The longest recorded body in these scripts is the seven-byte "payload".
const MAX_REQUEST_BODY_BYTES: usize = b"payload".len();
const MAX_GOAWAY_FRAMES: usize = 8;

#[tokio::test]
async fn shared_attempt_budget_stops_hidden_graceful_goaway_replays() -> TestResult {
    for negotiated in [false, true] {
        let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
        let result = bounded(async {
            let identity = TestIdentity::generate()?;
            let server = ScriptedHttp2Server::start(
                &identity,
                vec![Script::GoAway {
                    last_stream_id: 0,
                    code: NO_ERROR,
                }],
                connections.spawner(),
            )
            .await?;
            let client = http2_client(&identity)?;
            let budget = phantom::HttpAttemptBudget::new(1);
            let url = server.url("/limited");
            let request = if negotiated {
                client.get(&url)?
            } else {
                client.get_with_protocol(HttpProtocol::Http2, &url)?
            };
            let error = request
                .attempt_budget(budget.clone())
                .send()
                .await
                .err()
                .ok_or("GOAWAY replay exceeded allowance")?;
            assert_eq!(error.kind(), RequestErrorKind::AttemptBudgetExhausted);
            assert_eq!(budget.remaining(), 0);
            drop(client);
            assert!(server.finish().await?.is_empty());
            Ok(())
        })
        .await;
        connections.finish(result).await?;
    }
    Ok(())
}

fn replay_policy(maximum: usize) -> TestResult<RetryPolicy> {
    let maximum = NonZeroUsize::new(maximum).ok_or("replay budget must be non-zero")?;
    Ok(RetryPolicy::none().with_unprocessed_replay(Some(maximum)))
}

/// One scripted answer to an accepted HTTP/2 request.
#[derive(Clone, Copy)]
enum Reply {
    /// `RST_STREAM(REFUSED_STREAM)` before reading the request body.
    Refuse,
    /// A complete response after reading the request body.
    Status(u16),
    /// A `302 Found` to `location` after reading the request body.
    Redirect(&'static str),
}

/// A request the scripted server observed, tagged with its connection.
#[derive(Debug, Eq, PartialEq)]
struct Observed {
    connection: usize,
    method: Method,
    path: String,
    body: Vec<u8>,
}

impl Observed {
    fn new(connection: usize, method: Method, path: &str, body: &[u8]) -> Self {
        Self {
            connection,
            method,
            path: path.to_owned(),
            body: body.to_vec(),
        }
    }
}

/// How the scripted server treats one accepted TLS connection.
enum Script {
    /// Reads the preface and request HEADERS on stream 1, then sends a raw
    /// `GOAWAY(last_stream_id, code)` and closes the connection.
    GoAway { last_stream_id: u32, code: u32 },
    /// Serves requests with an HTTP/2 server in order, one reply each.
    Serve(Vec<Reply>),
    /// Answers stream 1 with an empty `200`, then reads stream 3's HEADERS
    /// and the PING after them without answering either, and requires the
    /// client's `GOAWAY(0, PROTOCOL_ERROR, "Failed ping.")`.
    IgnorePing,
}

/// Requests observed across every scripted connection.
type ObservedLog = Arc<Mutex<Vec<Observed>>>;

/// Accepts one connection per script entry, in order, then reports whether
/// the client finished without opening another connection.
struct ScriptedHttp2Server {
    address: std::net::SocketAddr,
    client_done: oneshot::Sender<()>,
    observed: oneshot::Receiver<(Vec<Observed>, bool)>,
}

impl ScriptedHttp2Server {
    async fn start(
        identity: &TestIdentity,
        scripts: Vec<Script>,
        connections: ReplaySpawner,
    ) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (client_done, done_received) = oneshot::channel();
        let (observed_send, observed_received) = oneshot::channel();
        let children = connections.clone();
        connections.spawn(async move {
            let observed = ObservedLog::default();
            for (connection, script) in scripts.into_iter().enumerate() {
                let stream = accept_tls(&listener, &acceptor).await?;
                match script {
                    Script::GoAway {
                        last_stream_id,
                        code,
                    } => send_goaway(stream, last_stream_id, code, &children).await?,
                    Script::Serve(replies) => {
                        serve(stream, connection, replies, &observed, &children).await?;
                    }
                    Script::IgnorePing => ignore_ping(stream, &children).await?,
                }
            }
            let finished = tokio::select! {
                biased;
                accepted = listener.accept() => {
                    accepted?;
                    false
                }
                completed = done_received => {
                    completed?;
                    true
                }
            };
            let observed = std::mem::take(&mut *lock(&observed));
            observed_send
                .send((observed, finished))
                .map_err(|_| "client stopped before receiving replay observations")?;
            Ok(())
        })?;
        Ok(Self {
            address,
            client_done,
            observed: observed_received,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("https://{}{path}", self.address)
    }

    /// Returns the observed requests after asserting no extra connection.
    async fn finish(self) -> TestResult<Vec<Observed>> {
        self.client_done
            .send(())
            .map_err(|_| "server stopped before client completion")?;
        let (observed, finished) = self.observed.await?;
        assert!(finished, "the client opened an unscripted connection");
        Ok(observed)
    }
}

fn lock(observed: &ObservedLog) -> MutexGuard<'_, Vec<Observed>> {
    match observed.lock() {
        Ok(observed) => observed,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Answers the preface and stream 1 with `GOAWAY(last_stream_id, code)`,
/// then closes. The socket is drained until the client closes it, so unread
/// request bytes never turn the close into a reset that races the frame.
async fn send_goaway(
    mut stream: SslStream<TcpStream>,
    last_stream_id: u32,
    code: u32,
    connections: &ReplaySpawner,
) -> TestResult<()> {
    accept_client_preface(&mut stream).await?;
    read_request_headers(&mut stream, 1).await?;
    let mut payload = [0_u8; 8];
    payload[..4].copy_from_slice(&last_stream_id.to_be_bytes());
    payload[4..].copy_from_slice(&code.to_be_bytes());
    write_frame(&mut stream, GOAWAY, 0, 0, &payload).await?;
    stream.flush().await?;
    match stream.shutdown().await {
        Err(error) if !is_peer_gone(&error) => return Err(error.into()),
        _ => {}
    }
    connections.spawn(drain_tls(stream))?;
    Ok(())
}

/// Plays [`Script::IgnorePing`], then drains the socket until the client
/// closes it.
async fn ignore_ping(
    mut stream: SslStream<TcpStream>,
    connections: &ReplaySpawner,
) -> TestResult<()> {
    accept_client_preface(&mut stream).await?;
    read_request_headers(&mut stream, 1).await?;
    // `:status: 200` is static table entry 8.
    write_frame(&mut stream, HEADERS, END_STREAM_AND_HEADERS, 1, &[0x88]).await?;
    stream.flush().await?;
    read_request_headers(&mut stream, 3).await?;
    let ping = read_frame(&mut stream).await?;
    if (ping.kind, ping.flags) != (PING, 0) {
        return Err("the request HEADERS were not followed by a PING".into());
    }
    let mut go_away = None;
    for _ in 0..MAX_GOAWAY_FRAMES {
        let frame = read_frame(&mut stream).await?;
        if frame.kind == GOAWAY {
            go_away = Some(frame);
            break;
        }
    }
    let go_away = go_away.ok_or("failed PING script exceeded its frame limit before GOAWAY")?;
    let mut expected = vec![0, 0, 0, 0, 0, 0, 0, 1];
    expected.extend_from_slice(b"Failed ping.");
    if go_away.payload != expected {
        return Err("the client's GOAWAY was not GOAWAY(0, PROTOCOL_ERROR, Failed ping.)".into());
    }
    connections.spawn(drain_tls(stream))?;
    Ok(())
}

/// Serves one reply per accepted request. The connection keeps being driven
/// while request handlers read bodies, and afterwards until the client
/// releases it, so queued resets and responses are flushed.
async fn serve(
    stream: SslStream<TcpStream>,
    connection_index: usize,
    replies: Vec<Reply>,
    observed: &ObservedLog,
    connections: &ReplaySpawner,
) -> TestResult<()> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let expected = replies.len();
    let answered = Arc::new(AtomicUsize::new(0));
    for reply in replies {
        let (request, mut respond) = connection
            .accept()
            .await
            .ok_or("connection closed before a scripted request")??;
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let response = match reply {
            Reply::Refuse => {
                respond.send_reset(::http2::Reason::REFUSED_STREAM);
                lock(observed).push(Observed::new(connection_index, method, &path, b""));
                answered.fetch_add(1, Ordering::Release);
                continue;
            }
            Reply::Status(status) => Response::builder().status(status).body(())?,
            Reply::Redirect(location) => Response::builder()
                .status(StatusCode::FOUND)
                .header("location", location)
                .body(())?,
        };
        let observed = Arc::clone(observed);
        let answered = Arc::clone(&answered);
        connections.spawn(async move {
            let mut body = request.into_body();
            let mut bytes = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk?;
                if chunk.len() > MAX_REQUEST_BODY_BYTES - bytes.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "unprocessed replay request body exceeded its script limit",
                    )
                    .into());
                }
                body.flow_control().release_capacity(chunk.len())?;
                bytes.extend_from_slice(&chunk);
            }
            lock(&observed).push(Observed::new(connection_index, method, &path, &bytes));
            respond.send_response(response, true)?;
            answered.fetch_add(1, Ordering::Release);
            Ok(())
        })?;
    }
    // Accept peer hangup only after every scripted response or reset was
    // queued successfully. Earlier I/O errors retain their original cause.
    connections.spawn(async move {
        match poll_fn(|context| connection.poll_closed(context)).await {
            Ok(()) => Ok(()),
            Err(error)
                if answered.load(Ordering::Acquire) == expected
                    && error.get_io().is_some_and(is_peer_gone) =>
            {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    })?;
    Ok(())
}

async fn accept_tls(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
) -> TestResult<SslStream<TcpStream>> {
    let (tcp, _) = listener.accept().await?;
    let ssl = Ssl::new(acceptor.context())?;
    let mut stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
}

/// A Chromium-recipe client whose preface PING follows 1 second without a
/// read and closes the connection when unanswered for 2 seconds. It sends
/// no request again after the PING fails, so only the retry policy could.
fn short_ping_timeout_client(identity: &TestIdentity) -> TestResult<Client> {
    let mut http2 = chrome::v154_http2();
    http2.preface_ping_after = Some(Duration::from_secs(1));
    http2.ping_timeout = Some(Duration::from_secs(2));
    http2.ping_failure_retries = 0;
    Ok(
        Client::builder(ClientProfile::new(tls_settings()).with_http2(http2))
            .add_root_certificate_der(identity.root_der.clone())
            .build()?,
    )
}

fn http2_client(identity: &TestIdentity) -> TestResult<Client> {
    Ok(client_builder(identity, true).build()?)
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future).await.map_err(|elapsed| {
        crate::support::deadline::FixtureDeadline::new(
            "unprocessed replay test exceeded its deadline",
            elapsed,
        )
    })?
}

fn expect_error<T>(
    result: Result<T, RequestError>,
    message: &'static str,
) -> TestResult<RequestError> {
    match result {
        Ok(_) => Err(message.into()),
        Err(error) => Ok(error),
    }
}

fn http2_protocol_error(error: &RequestError) -> Option<&Http2ProtocolError> {
    let mut current: Option<&(dyn Error + 'static)> = Some(error);
    while let Some(error) = current {
        if let Some(protocol) = error.downcast_ref::<Http2ProtocolError>() {
            return Some(protocol);
        }
        current = error.source();
    }
    None
}

#[tokio::test]
async fn refused_stream_replays_owned_body_post_when_policy_allows() -> TestResult {
    let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let server = ScriptedHttp2Server::start(
            &identity,
            vec![
                Script::Serve(vec![Reply::Refuse]),
                Script::Serve(vec![Reply::Status(201)]),
            ],
            connections.spawner(),
        )
        .await?;

        let client = http2_client(&identity)?;
        let response = client
            .request_with_protocol(HttpProtocol::Http2, Method::POST, &server.url("/orders"))?
            .body(Bytes::from_static(b"payload"))
            .retry_policy(replay_policy(1)?)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response
                .extensions()
                .get::<ResponseInfo>()
                .map(ResponseInfo::protocol),
            Some(HttpProtocol::Http2)
        );
        response.into_body().collect().await?;
        drop(client);

        assert_eq!(
            server.finish().await?,
            [
                Observed::new(0, Method::POST, "/orders", b""),
                Observed::new(1, Method::POST, "/orders", b"payload"),
            ]
        );
        Ok(())
    })
    .await;
    connections.finish(result).await
}

#[tokio::test]
async fn goaway_above_last_stream_id_with_error_code_replays_when_policy_allows() -> TestResult {
    let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let server = ScriptedHttp2Server::start(
            &identity,
            vec![
                Script::GoAway {
                    last_stream_id: 0,
                    code: ENHANCE_YOUR_CALM,
                },
                Script::Serve(vec![Reply::Status(204)]),
            ],
            connections.spawner(),
        )
        .await?;

        let client = http2_client(&identity)?;
        let response = client
            .request_with_protocol(HttpProtocol::Http2, Method::DELETE, &server.url("/item"))?
            .body(Bytes::from_static(b"reason"))
            .retry_policy(replay_policy(1)?)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        drop(client);

        assert_eq!(
            server.finish().await?,
            [Observed::new(1, Method::DELETE, "/item", b"reason")]
        );
        Ok(())
    })
    .await;
    connections.finish(result).await
}

#[tokio::test]
async fn processed_stream_closed_after_goaway_is_not_replayed() -> TestResult {
    let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        // Stream 1 is at the last-stream-id, so the peer may have processed
        // it; the connection then closes before any response.
        let server = ScriptedHttp2Server::start(
            &identity,
            vec![Script::GoAway {
                last_stream_id: 1,
                code: INTERNAL_ERROR,
            }],
            connections.spawner(),
        )
        .await?;

        let client = http2_client(&identity)?;
        let result = client
            .request_with_protocol(HttpProtocol::Http2, Method::POST, &server.url("/orders"))?
            .body(Bytes::from_static(b"payload"))
            .retry_policy(replay_policy(3)?)
            .send()
            .await;
        let error = expect_error(result, "a possibly processed stream was replayed")?;
        assert_eq!(error.kind(), RequestErrorKind::Http2);
        let protocol = http2_protocol_error(&error).ok_or("missing HTTP/2 protocol error")?;
        assert_eq!(protocol.kind(), Http2ProtocolErrorKind::Transport);
        assert!(!protocol.is_remote());
        drop(client);

        assert!(server.finish().await?.is_empty());
        Ok(())
    })
    .await;
    connections.finish(result).await
}

/// A request whose connection closes after an unanswered PING fails with
/// [`Http2Error::PingTimeout`] and is not replayed, even with unprocessed
/// replay enabled: the client closed the connection, so nothing says the
/// peer did not process the request. The pool drops the connection, and the
/// next request opens a new one.
#[tokio::test]
async fn ping_timeout_fails_the_request_without_replay_and_retires_the_connection() -> TestResult {
    let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let server = ScriptedHttp2Server::start(
            &identity,
            vec![Script::IgnorePing, Script::Serve(vec![Reply::Status(204)])],
            connections.spawner(),
        )
        .await?;
        let client = short_ping_timeout_client(&identity)?;
        let first = client
            .request_with_protocol(HttpProtocol::Http2, Method::GET, &server.url("/first"))?
            .send()
            .await?;
        assert_eq!(first.status(), StatusCode::OK);
        first.into_body().collect().await?;

        tokio::time::sleep(Duration::from_millis(1_500)).await;
        let error = expect_error(
            client
                .request_with_protocol(
                    HttpProtocol::Http2,
                    Method::GET,
                    &server.url("/unanswered"),
                )?
                .retry_policy(replay_policy(1)?)
                .send()
                .await,
            "a request on a connection closed by a PING timeout succeeded",
        )?;
        assert_eq!(error.kind(), RequestErrorKind::Http2);
        assert!(
            source_chain_has_ping_timeout(&error),
            "missing Http2Error::PingTimeout: {error:?}"
        );

        let next = client
            .request_with_protocol(HttpProtocol::Http2, Method::GET, &server.url("/next"))?
            .send()
            .await?;
        assert_eq!(next.status(), StatusCode::NO_CONTENT);
        next.into_body().collect().await?;
        drop(client);

        assert_eq!(
            server.finish().await?,
            [Observed::new(1, Method::GET, "/next", b"")]
        );
        Ok(())
    })
    .await;
    connections.finish(result).await
}

fn source_chain_has_ping_timeout(error: &RequestError) -> bool {
    let mut current: Option<&(dyn Error + 'static)> = Some(error);
    while let Some(error) = current {
        if matches!(
            error.downcast_ref::<Http2Error>(),
            Some(Http2Error::PingTimeout)
        ) {
            return true;
        }
        current = error.source();
    }
    false
}

#[tokio::test]
async fn unprocessed_replay_refuses_one_shot_streaming_body() -> TestResult {
    let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let server = ScriptedHttp2Server::start(
            &identity,
            vec![Script::Serve(vec![Reply::Refuse])],
            connections.spawner(),
        )
        .await?;

        let client = http2_client(&identity)?;
        let result = client
            .request_with_protocol(HttpProtocol::Http2, Method::POST, &server.url("/stream"))?
            .streaming_body(Full::new(Bytes::from_static(b"one-shot")))
            .retry_policy(replay_policy(2)?)
            .send()
            .await;
        let error = expect_error(result, "a one-shot streaming body was replayed")?;
        assert_eq!(error.kind(), RequestErrorKind::Http2);
        let protocol = http2_protocol_error(&error).ok_or("missing HTTP/2 protocol error")?;
        assert_eq!(protocol.kind(), Http2ProtocolErrorKind::StreamReset);
        assert_eq!(protocol.reason_code(), Some(0x7));
        drop(client);

        assert_eq!(
            server.finish().await?,
            [Observed::new(0, Method::POST, "/stream", b"")]
        );
        Ok(())
    })
    .await;
    connections.finish(result).await
}

#[tokio::test]
async fn refused_stream_replays_a_buffered_streaming_body() -> TestResult {
    let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let server = ScriptedHttp2Server::start(
            &identity,
            vec![
                Script::Serve(vec![Reply::Refuse]),
                Script::Serve(vec![Reply::Status(201)]),
            ],
            connections.spawner(),
        )
        .await?;

        let client = http2_client(&identity)?;
        let response = client
            .request_with_protocol(HttpProtocol::Http2, Method::POST, &server.url("/orders"))?
            .buffered_streaming_body(Full::new(Bytes::from_static(b"payload")), 64)
            .retry_policy(replay_policy(1)?)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED);
        response.into_body().collect().await?;
        drop(client);

        assert_eq!(
            server.finish().await?,
            [
                Observed::new(0, Method::POST, "/orders", b""),
                Observed::new(1, Method::POST, "/orders", b"payload"),
            ]
        );
        Ok(())
    })
    .await;
    connections.finish(result).await
}

#[tokio::test]
async fn unprocessed_replay_budget_is_bounded_across_redirects() -> TestResult {
    let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let server = ScriptedHttp2Server::start(
            &identity,
            vec![
                Script::Serve(vec![Reply::Refuse]),
                Script::Serve(vec![Reply::Redirect("/next"), Reply::Refuse]),
                Script::Serve(vec![Reply::Refuse]),
            ],
            connections.spawner(),
        )
        .await?;

        let client = client_builder(&identity, true)
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .build()?;
        let result = client
            .get_with_protocol(HttpProtocol::Http2, &server.url("/first"))?
            .retry_policy(replay_policy(2)?)
            .send()
            .await;
        let error = expect_error(result, "the replay budget was not request-scoped")?;
        assert_eq!(error.kind(), RequestErrorKind::Http2);
        drop(client);

        assert_eq!(
            server.finish().await?,
            [
                Observed::new(0, Method::GET, "/first", b""),
                Observed::new(1, Method::GET, "/first", b""),
                Observed::new(1, Method::GET, "/next", b""),
                Observed::new(2, Method::GET, "/next", b""),
            ]
        );
        Ok(())
    })
    .await;
    connections.finish(result).await
}

#[tokio::test]
async fn unprocessed_replay_is_disabled_by_default() -> TestResult {
    let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
    let result = bounded(async {
        assert_eq!(RetryPolicy::default().unprocessed_replay(), None);
        let identity = TestIdentity::generate()?;
        let server = ScriptedHttp2Server::start(
            &identity,
            vec![Script::Serve(vec![Reply::Refuse])],
            connections.spawner(),
        )
        .await?;

        let client = http2_client(&identity)?;
        let result = client
            .get_with_protocol(HttpProtocol::Http2, &server.url("/refused"))?
            .send()
            .await;
        let error = expect_error(result, "a refused stream was replayed without policy")?;
        assert_eq!(error.kind(), RequestErrorKind::Http2);
        drop(client);

        assert_eq!(
            server.finish().await?,
            [Observed::new(0, Method::GET, "/refused", b"")]
        );
        Ok(())
    })
    .await;
    connections.finish(result).await
}

#[tokio::test]
async fn default_graceful_goaway_retry_is_unchanged_without_policy() -> TestResult {
    let subscriber = OutcomeSubscriber::default();
    async {
        let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
        let result = bounded(async {
            let identity = TestIdentity::generate()?;
            let server = ScriptedHttp2Server::start(
                &identity,
                vec![
                    Script::GoAway {
                        last_stream_id: 0,
                        code: NO_ERROR,
                    },
                    Script::Serve(vec![Reply::Status(204)]),
                ],
                connections.spawner(),
            )
            .await?;

            let client = http2_client(&identity)?;
            let response = client
                .get_with_protocol(HttpProtocol::Http2, &server.url("/graceful"))?
                .retry_policy(phantom::RetryPolicy::none().with_max_retries(Some(0)))
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            response.into_body().collect().await?;
            drop(client);

            assert_eq!(
                server.finish().await?,
                [Observed::new(1, Method::GET, "/graceful", b"")]
            );
            Ok(())
        })
        .await;
        connections.finish(result).await
    }
    .with_subscriber(subscriber.dispatch())
    .await?;
    assert!(
        subscriber
            .unprocessed_replays_for("client.request")
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn replay_is_recorded_in_span() -> TestResult {
    let subscriber = OutcomeSubscriber::default();
    async {
        let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
        let result = bounded(async {
            let identity = TestIdentity::generate()?;
            let server = ScriptedHttp2Server::start(
                &identity,
                vec![
                    Script::Serve(vec![Reply::Refuse]),
                    Script::Serve(vec![Reply::Status(200)]),
                ],
                connections.spawner(),
            )
            .await?;

            let client = http2_client(&identity)?;
            let response = client
                .request_with_protocol(HttpProtocol::Http2, Method::PATCH, &server.url("/span"))?
                .body(Bytes::from_static(b"patch"))
                .retry_policy(replay_policy(2)?)
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            response.into_body().collect().await?;
            drop(client);

            assert_eq!(server.finish().await?.len(), 2);
            Ok(())
        })
        .await;
        connections.finish(result).await
    }
    .with_subscriber(subscriber.dispatch())
    .await?;
    assert_eq!(subscriber.unprocessed_replays_for("client.request"), [1]);
    assert!(
        subscriber
            .retries_performed_for("client.request")
            .is_empty()
    );
    assert!(subscriber.status_retries_for("client.request").is_empty());
    Ok(())
}

fn http3_client(identity: &TestIdentity) -> TestResult<Client> {
    let mut tcp_tls = tls_settings();
    tcp_tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    let profile = ClientProfile::new(tcp_tls).with_http3(client_settings());
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}

type H3ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// Reads the request body, answers `status`, and returns the method, path,
/// and body.
async fn answer_http3(
    request: &http::Request<()>,
    stream: &mut H3ServerStream,
    status: StatusCode,
) -> TestResult<(Method, String, Vec<u8>)> {
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        let remaining = chunk.remaining();
        if remaining > MAX_REQUEST_BODY_BYTES - body.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP/3 replay request body exceeded its script limit",
            )
            .into());
        }
        body.extend_from_slice(&chunk.copy_to_bytes(remaining));
    }
    stream
        .send_response(Response::builder().status(status).body(())?)
        .await?;
    stream.finish().await?;
    Ok((
        request.method().clone(),
        request.uri().path().to_owned(),
        body,
    ))
}

#[tokio::test]
async fn h3_request_rejected_replays_on_same_route_and_location() -> TestResult {
    let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (client_done, done_received) = oneshot::channel();
        let (observed_send, observed_received) = oneshot::channel();
        connections.spawner().spawn(async move {
            let (_, mut rejected, first_connection) = accept_request(&endpoint).await?;
            rejected.stop_sending(h3::error::Code::H3_REQUEST_REJECTED);
            rejected.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);

            // The replay arrives on a new QUIC connection to this endpoint.
            let (request, mut stream, second_connection) = accept_request(&endpoint).await?;
            let observed = answer_http3(&request, &mut stream, StatusCode::CREATED).await?;
            done_received.await?;
            drop((first_connection, second_connection));
            observed_send
                .send(observed)
                .map_err(|_| "HTTP/3 replay observer stopped")?;
            Ok(())
        })?;

        let client = http3_client(&identity)?;
        let response = client
            .request_with_protocol(
                HttpProtocol::Http3,
                Method::POST,
                &format!("https://{address}/orders"),
            )?
            .body(Bytes::from_static(b"payload"))
            .retry_policy(replay_policy(1)?)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response
                .extensions()
                .get::<ResponseInfo>()
                .map(ResponseInfo::protocol),
            Some(HttpProtocol::Http3)
        );
        response.into_body().collect().await?;

        client_done
            .send(())
            .map_err(|_| "HTTP/3 server stopped before client completion")?;
        let (method, path, body) = observed_received.await?;
        assert_eq!(method, Method::POST);
        assert_eq!(path, "/orders");
        assert_eq!(body, b"payload");
        Ok(())
    })
    .await;
    connections.finish(result).await
}

/// Once the first connection sends `GOAWAY(0)` after serving stream 0, a
/// later request never runs there, whatever the client has observed: the
/// pool may already refuse to reuse the connection, the request may be
/// refused before its stream opens and replayed, or stream 4 may reach the
/// server, which rejects it with `H3_REQUEST_REJECTED` and so replays it.
/// The deterministic proof that an observed `GOAWAY` tags a refused request
/// is the phantom-net connection test that waits for the closing state.
#[tokio::test]
async fn h3_request_after_goaway_is_served_once_on_a_new_connection() -> TestResult {
    let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (goaway_sent, goaway_received) = oneshot::channel();
        let (client_done, done_received) = oneshot::channel();
        let (observed_send, observed_received) = oneshot::channel();
        connections.spawner().spawn(async move {
            let (request, mut stream, mut first_connection) = accept_request(&endpoint).await?;
            let first = answer_http3(&request, &mut stream, StatusCode::OK).await?;
            // Stream 0 was the last accepted, so this sends GOAWAY(0), and
            // the connection rejects every later request stream.
            first_connection.shutdown(0).await?;
            goaway_sent
                .send(())
                .map_err(|_| "client stopped before GOAWAY")?;

            // Keep driving the first connection, so a late stream 4 is
            // rejected, while the replacement connection serves the request.
            let mut served_on_first = false;
            let mut first_open = true;
            let replacement = accept_request(&endpoint);
            tokio::pin!(replacement);
            let second = loop {
                tokio::select! {
                    accepted = first_connection.accept(), if first_open => {
                        match accepted {
                            Ok(Some(_)) => served_on_first = true,
                            Ok(None) => {},
                            Err(error) if error.is_h3_no_error() => {},
                            Err(error) => return Err(error.into()),
                        }
                        first_open = false;
                    }
                    accepted = &mut replacement => {
                        let (request, mut stream, second_connection) = accepted?;
                        let second =
                            answer_http3(&request, &mut stream, StatusCode::CREATED).await?;
                        break (second, second_connection);
                    }
                }
            };
            done_received.await?;
            drop((first_connection, second.1));
            observed_send
                .send((first, second.0, served_on_first))
                .map_err(|_| "HTTP/3 GOAWAY replay observer stopped")?;
            Ok(())
        })?;

        let client = http3_client(&identity)?;
        let exchange = async {
            let first = client
                .get_with_protocol(HttpProtocol::Http3, &format!("https://{address}/first"))?
                .send()
                .await?;
            assert_eq!(first.status(), StatusCode::OK);
            first.into_body().collect().await?;
            goaway_received.await?;

            let response = client
                .request_with_protocol(
                    HttpProtocol::Http3,
                    Method::PUT,
                    &format!("https://{address}/resource"),
                )?
                .body(Bytes::from_static(b"state"))
                .retry_policy(replay_policy(1)?)
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::CREATED);
            response.into_body().collect().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        exchange.await?;

        client_done
            .send(())
            .map_err(|_| "HTTP/3 server stopped before client completion")?;
        let (first, second, served_on_first) = observed_received.await?;
        assert_eq!(first, (Method::GET, "/first".to_owned(), Vec::new()));
        assert_eq!(
            second,
            (Method::PUT, "/resource".to_owned(), b"state".to_vec())
        );
        assert!(
            !served_on_first,
            "a request ran on the connection that sent GOAWAY"
        );
        Ok(())
    })
    .await;
    connections.finish(result).await
}

#[tokio::test]
async fn zero_shared_cap_returns_refused_stream_without_a_replay() -> TestResult {
    let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let server = ScriptedHttp2Server::start(
            &identity,
            vec![Script::Serve(vec![Reply::Refuse])],
            connections.spawner(),
        )
        .await?;
        let client = http2_client(&identity)?;
        let error = client
            .request_with_protocol(HttpProtocol::Http2, Method::POST, &server.url("/capped"))?
            .body(Bytes::from_static(b"payload"))
            .retry_policy(replay_policy(1)?.with_max_retries(Some(0)))
            .send()
            .await
            .err()
            .ok_or("a refused stream returned a response")?;
        assert_eq!(error.protocol(), Some(HttpProtocol::Http2));
        drop(client);
        assert_eq!(
            server.finish().await?,
            [Observed::new(0, Method::POST, "/capped", b"")]
        );
        Ok(())
    })
    .await;
    connections.finish(result).await
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, io, task::Poll};

    use crate::support::tunnel_proxy::connection_peer::FixtureFailures;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn actual_pending_replay_caller_retains_its_contextual_elapsed() -> TestResult {
        let entered = Cell::new(false);
        let pending = bounded(poll_fn(|_| {
            entered.set(true);
            Poll::<TestResult>::Pending
        }));
        tokio::pin!(pending);
        assert!(futures_util::poll!(&mut pending).is_pending());
        tokio::time::advance(TEST_TIMEOUT).await;
        let error = pending
            .await
            .err()
            .ok_or("pending replay caller did not time out")?;
        assert!(entered.get());
        assert_eq!(
            error.to_string(),
            "unprocessed replay test exceeded its deadline"
        );
        assert!(
            error
                .source()
                .is_some_and(|cause| cause.is::<tokio::time::error::Elapsed>())
        );
        Ok(())
    }

    #[tokio::test]
    async fn actual_scripted_http2_body_limit_survives_coordinator_shutdown() -> TestResult {
        let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
        let result = bounded(async {
            let identity = TestIdentity::generate()?;
            let server = ScriptedHttp2Server::start(
                &identity,
                vec![Script::Serve(vec![Reply::Status(204)])],
                connections.spawner(),
            )
            .await?;
            let client = http2_client(&identity)?;
            let request = client
                .request_with_protocol(
                    HttpProtocol::Http2,
                    Method::POST,
                    &server.url("/oversized"),
                )?
                .body("payload!")
                .send()
                .await;
            let error = expect_error(request, "oversized scripted body received a response")?;
            drop(client);
            let error = connections
                .finish(Err(error.into()))
                .await
                .err()
                .ok_or("scripted body failure disappeared")?;
            assert!(contains_body_limit(
                &*error,
                "unprocessed replay request body exceeded its script limit"
            ));
            Ok(())
        })
        .await;
        connections.finish(result).await
    }

    #[tokio::test]
    async fn actual_http3_body_limit_remains_a_typed_original_server_failure() -> TestResult {
        let mut connections = ReplayConnections::new(MAX_REPLAY_TASKS);
        let result = bounded(async {
            let identity = TestIdentity::generate()?;
            let (address, endpoint) = server_endpoint(&identity)?;
            connections.spawner().spawn(async move {
                let (request, mut stream, _connection) = accept_request(&endpoint).await?;
                answer_http3(&request, &mut stream, StatusCode::CREATED).await?;
                Ok(())
            })?;
            let client = http3_client(&identity)?;
            let request = client
                .request_with_protocol(
                    HttpProtocol::Http3,
                    Method::POST,
                    &format!("https://{address}/oversized"),
                )?
                .body("payload!")
                .send()
                .await;
            let error = expect_error(request, "oversized HTTP/3 body received a response")?;
            drop(client);
            let error = connections
                .finish(Err(error.into()))
                .await
                .err()
                .ok_or("HTTP/3 body failure disappeared")?;
            assert!(contains_body_limit(
                &*error,
                "HTTP/3 replay request body exceeded its script limit"
            ));
            Ok(())
        })
        .await;
        connections.finish(result).await
    }

    fn contains_body_limit(error: &(dyn Error + 'static), message: &str) -> bool {
        if error.downcast_ref::<io::Error>().is_some_and(|error| {
            error.kind() == io::ErrorKind::InvalidData && error.to_string() == message
        }) {
            return true;
        }
        if let Some(failures) = error.downcast_ref::<FixtureFailures>() {
            return contains_body_limit(&*failures.primary, message)
                || contains_body_limit(&*failures.cleanup, message);
        }
        error
            .source()
            .is_some_and(|cause| contains_body_limit(cause, message))
    }
}
