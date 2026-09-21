//! Opt-in replay of HTTP/2 and HTTP/3 requests the peer reported as not
//! processed.

#[allow(dead_code)]
#[path = "support/h2.rs"]
mod h2_support;
#[allow(dead_code)]
#[path = "support/h3.rs"]
mod h3_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;
#[path = "support/tracing.rs"]
mod tracing_support;

use std::{
    error::Error,
    future::{Future, poll_fn},
    net::Ipv4Addr,
    num::NonZeroUsize,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use btls::ssl::{Ssl, SslAcceptor};
use bytes::{Buf, Bytes};
use http::{Method, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use phantom::{
    Client, HttpProtocol, RedirectPolicy, RequestError, RequestErrorKind, ResponseInfo,
    RetryPolicy, profile::ClientProfile,
};
use phantom_net::http2::{Http2ProtocolError, Http2ProtocolErrorKind};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};
use tokio_btls::SslStream;
use tracing::instrument::WithSubscriber;

use h2_support::{accept_client_preface, read_request_headers, write_frame};
use h3_support::{accept_request, client_settings, server_endpoint};
use tls_support::{H2_ALPN, TestIdentity, client_builder, is_peer_gone, tls_settings};
use tracing_support::OutcomeSubscriber;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const GOAWAY: u8 = 0x7;
const NO_ERROR: u32 = 0x0;
const INTERNAL_ERROR: u32 = 0x2;
const ENHANCE_YOUR_CALM: u32 = 0xb;

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
}

/// Requests observed across every scripted connection.
type ObservedLog = Arc<Mutex<Vec<Observed>>>;

/// Accepts one connection per script entry, in order, then reports whether
/// the client finished without opening another connection.
struct ScriptedHttp2Server {
    address: std::net::SocketAddr,
    client_done: oneshot::Sender<()>,
    task: JoinHandle<TestResult<(Vec<Observed>, bool)>>,
}

impl ScriptedHttp2Server {
    async fn start(identity: &TestIdentity, scripts: Vec<Script>) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (client_done, done_received) = oneshot::channel();
        let task = tokio::spawn(async move {
            let observed = ObservedLog::default();
            let mut handlers = Vec::new();
            for (connection, script) in scripts.into_iter().enumerate() {
                let stream = accept_tls(&listener, &acceptor).await?;
                match script {
                    Script::GoAway {
                        last_stream_id,
                        code,
                    } => send_goaway(stream, last_stream_id, code).await?,
                    Script::Serve(replies) => {
                        serve(stream, connection, replies, &observed, &mut handlers).await?;
                    }
                }
            }
            let finished = tokio::select! {
                biased;
                accepted = listener.accept() => {
                    accepted?;
                    false
                }
                completed = done_received => {
                    completed.map_err(|_| "client stopped before reporting completion")?;
                    true
                }
            };
            for handler in handlers {
                handler.await??;
            }
            let observed = std::mem::take(&mut *lock(&observed));
            Ok((observed, finished))
        });
        Ok(Self {
            address,
            client_done,
            task,
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
        let (observed, finished) = self.task.await??;
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
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut stream, &mut tokio::io::sink()).await;
    });
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
    handlers: &mut Vec<JoinHandle<TestResult>>,
) -> TestResult<()> {
    let mut connection = ::http2::server::handshake(stream).await?;
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
                continue;
            }
            Reply::Status(status) => Response::builder().status(status).body(())?,
            Reply::Redirect(location) => Response::builder()
                .status(StatusCode::FOUND)
                .header("location", location)
                .body(())?,
        };
        let observed = Arc::clone(observed);
        handlers.push(tokio::spawn(async move {
            let mut body = request.into_body();
            let mut bytes = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk?;
                body.flow_control().release_capacity(chunk.len())?;
                bytes.extend_from_slice(&chunk);
            }
            lock(&observed).push(Observed::new(connection_index, method, &path, &bytes));
            respond.send_response(response, true)?;
            Ok(())
        }));
    }
    tokio::spawn(async move {
        let _ = poll_fn(|context| connection.poll_closed(context)).await;
    });
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

fn http2_client(identity: &TestIdentity) -> TestResult<Client> {
    Ok(client_builder(identity, true).build()?)
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "unprocessed replay test exceeded its deadline")?
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
    bounded(async {
        let identity = TestIdentity::generate()?;
        let server = ScriptedHttp2Server::start(
            &identity,
            vec![
                Script::Serve(vec![Reply::Refuse]),
                Script::Serve(vec![Reply::Status(201)]),
            ],
        )
        .await?;

        let client = http2_client(&identity)?;
        let response = client
            .request(HttpProtocol::Http2, Method::POST, &server.url("/orders"))?
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
    .await
}

#[tokio::test]
async fn goaway_above_last_stream_id_with_error_code_replays_when_policy_allows() -> TestResult {
    bounded(async {
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
        )
        .await?;

        let client = http2_client(&identity)?;
        let response = client
            .request(HttpProtocol::Http2, Method::DELETE, &server.url("/item"))?
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
    .await
}

#[tokio::test]
async fn processed_stream_closed_after_goaway_is_not_replayed() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        // Stream 1 is at the last-stream-id, so the peer may have processed
        // it; the connection then closes before any response.
        let server = ScriptedHttp2Server::start(
            &identity,
            vec![Script::GoAway {
                last_stream_id: 1,
                code: INTERNAL_ERROR,
            }],
        )
        .await?;

        let client = http2_client(&identity)?;
        let result = client
            .request(HttpProtocol::Http2, Method::POST, &server.url("/orders"))?
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
    .await
}

#[tokio::test]
async fn unprocessed_replay_refuses_one_shot_streaming_body() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let server =
            ScriptedHttp2Server::start(&identity, vec![Script::Serve(vec![Reply::Refuse])]).await?;

        let client = http2_client(&identity)?;
        let result = client
            .request(HttpProtocol::Http2, Method::POST, &server.url("/stream"))?
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
    .await
}

#[tokio::test]
async fn unprocessed_replay_budget_is_bounded_across_redirects() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let server = ScriptedHttp2Server::start(
            &identity,
            vec![
                Script::Serve(vec![Reply::Refuse]),
                Script::Serve(vec![Reply::Redirect("/next"), Reply::Refuse]),
                Script::Serve(vec![Reply::Refuse]),
            ],
        )
        .await?;

        let client = client_builder(&identity, true)
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .build()?;
        let result = client
            .get(HttpProtocol::Http2, &server.url("/first"))?
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
    .await
}

#[tokio::test]
async fn unprocessed_replay_is_disabled_by_default() -> TestResult {
    bounded(async {
        assert_eq!(RetryPolicy::default().unprocessed_replay(), None);
        let identity = TestIdentity::generate()?;
        let server =
            ScriptedHttp2Server::start(&identity, vec![Script::Serve(vec![Reply::Refuse])]).await?;

        let client = http2_client(&identity)?;
        let result = client
            .get(HttpProtocol::Http2, &server.url("/refused"))?
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
    .await
}

#[tokio::test]
async fn default_graceful_goaway_retry_is_unchanged_without_policy() -> TestResult {
    let subscriber = OutcomeSubscriber::default();
    async {
        bounded(async {
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
            )
            .await?;

            let client = http2_client(&identity)?;
            let response = client
                .get(HttpProtocol::Http2, &server.url("/graceful"))?
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
        .await
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
        bounded(async {
            let identity = TestIdentity::generate()?;
            let server = ScriptedHttp2Server::start(
                &identity,
                vec![
                    Script::Serve(vec![Reply::Refuse]),
                    Script::Serve(vec![Reply::Status(200)]),
                ],
            )
            .await?;

            let client = http2_client(&identity)?;
            let response = client
                .request(HttpProtocol::Http2, Method::PATCH, &server.url("/span"))?
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
        .await
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
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (client_done, done_received) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (_, mut rejected, first_connection) = accept_request(&endpoint).await?;
            rejected.stop_sending(h3::error::Code::H3_REQUEST_REJECTED);
            rejected.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);

            // The replay arrives on a new QUIC connection to this endpoint.
            let (request, mut stream, second_connection) = accept_request(&endpoint).await?;
            let observed = answer_http3(&request, &mut stream, StatusCode::CREATED).await?;
            done_received
                .await
                .map_err(|_| "client stopped before reporting completion")?;
            drop((first_connection, second_connection));
            Ok::<_, Box<dyn Error + Send + Sync>>(observed)
        });

        let client = http3_client(&identity)?;
        let response = client
            .request(
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
        let (method, path, body) = server.await??;
        assert_eq!(method, Method::POST);
        assert_eq!(path, "/orders");
        assert_eq!(body, b"payload");
        Ok(())
    })
    .await
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
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (goaway_sent, goaway_received) = oneshot::channel();
        let (client_done, done_received) = oneshot::channel();
        let server = tokio::spawn(async move {
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
                        served_on_first |= matches!(accepted, Ok(Some(_)));
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
            done_received
                .await
                .map_err(|_| "client stopped before reporting completion")?;
            drop((first_connection, second.1));
            Ok::<_, Box<dyn Error + Send + Sync>>((first, second.0, served_on_first))
        });

        let client = http3_client(&identity)?;
        let exchange = async {
            let first = client
                .get(HttpProtocol::Http3, &format!("https://{address}/first"))?
                .send()
                .await?;
            assert_eq!(first.status(), StatusCode::OK);
            first.into_body().collect().await?;
            goaway_received
                .await
                .map_err(|_| "HTTP/3 server stopped before GOAWAY")?;

            let response = client
                .request(
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
        if let Err(error) = exchange.await {
            // A server failure closes its connections, so report it first.
            server.abort();
            return match server.await {
                Ok(Err(server_error)) => {
                    Err(format!("server: {server_error}; client: {error}").into())
                }
                _ => Err(error),
            };
        }

        client_done
            .send(())
            .map_err(|_| "HTTP/3 server stopped before client completion")?;
        let (first, second, served_on_first) = server.await??;
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
    .await
}
