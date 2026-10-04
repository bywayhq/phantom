//! A request whose HTTP/2 connection closed itself after an unanswered PING
//! is sent again on a new connection, as the Chromium recipes do; see
//! `Http2Settings::ping_failure_retries`.

use crate::support::h2 as h2_support;
use crate::support::tls as tls_support;

use std::{
    error::Error,
    future::{Future, poll_fn},
    net::Ipv4Addr,
    pin::Pin,
    time::Duration,
};

use btls::ssl::{Ssl, SslAcceptor};
use bytes::Bytes;
use http::{Method, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use phantom::{
    Client, HttpProtocol, HttpProxy, RequestError, RequestErrorKind, Route,
    profile::{ClientProfile, chromium},
};
use phantom_net::http2::Http2Error;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};
use tokio_btls::SslStream;

use h2_support::{accept_client_preface, read_frame, read_request_headers, write_frame};
use tls_support::{H2_ALPN, TestIdentity, tls_settings};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const TEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Longer than the client's 1-second preface PING threshold.
const IDLE: Duration = Duration::from_millis(1_500);
const HEADERS: u8 = 0x1;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const END_STREAM_AND_HEADERS: u8 = 0x5;

/// The request a server connection answered.
#[derive(Debug, Eq, PartialEq)]
struct Observed {
    method: Method,
    path: String,
    body: Vec<u8>,
}

/// Serves `/first` on a connection that then ignores the PING after the next
/// request, and, when `replacement` is set, serves the request that comes on
/// a second connection. Reports whether the client opened another
/// connection before it finished.
struct Server {
    address: std::net::SocketAddr,
    client_done: oneshot::Sender<()>,
    task: JoinHandle<TestResult<(Option<Observed>, bool)>>,
}

impl Server {
    async fn start(identity: &TestIdentity, replacement: bool) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (client_done, done_received) = oneshot::channel();
        let task = tokio::spawn(async move {
            ignore_ping(accept_tls(&listener, &acceptor).await?).await?;
            let observed = if replacement {
                Some(serve_one(accept_tls(&listener, &acceptor).await?).await?)
            } else {
                None
            };
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

    /// Returns what the second connection observed, after asserting that
    /// the client opened no other connection.
    async fn finish(self) -> TestResult<Option<Observed>> {
        self.client_done
            .send(())
            .map_err(|_| "server stopped before client completion")?;
        let (observed, finished) = self.task.await??;
        assert!(finished, "the client opened an unscripted connection");
        Ok(observed)
    }
}

/// Answers stream 1 with an empty `200`, then reads stream 3's HEADERS and
/// the PING after them without answering either, and requires the client's
/// `GOAWAY(0, PROTOCOL_ERROR, "Failed ping.")`. Any DATA of stream 3 is
/// read and dropped.
async fn ignore_ping(mut stream: SslStream<TcpStream>) -> TestResult<()> {
    accept_client_preface(&mut stream).await?;
    read_request_headers(&mut stream, 1).await?;
    // `:status: 200` is static table entry 8.
    write_frame(&mut stream, HEADERS, END_STREAM_AND_HEADERS, 1, &[0x88]).await?;
    stream.flush().await?;
    read_request_headers(&mut stream, 3).await?;
    require_failed_ping(stream).await
}

/// Reads the PING that follows request HEADERS without answering it, and
/// requires the client's `GOAWAY(0, PROTOCOL_ERROR, "Failed ping.")`. Any
/// frame after them is read and dropped.
async fn require_failed_ping(mut stream: SslStream<TcpStream>) -> TestResult<()> {
    let ping = read_frame(&mut stream).await?;
    if (ping.kind, ping.flags) != (PING, 0) {
        return Err("the request HEADERS were not followed by a PING".into());
    }
    let go_away = loop {
        let frame = read_frame(&mut stream).await?;
        if frame.kind == GOAWAY {
            break frame;
        }
    };
    let mut expected = vec![0, 0, 0, 0, 0, 0, 0, 1];
    expected.extend_from_slice(b"Failed ping.");
    if go_away.payload != expected {
        return Err("the client's GOAWAY was not GOAWAY(0, PROTOCOL_ERROR, Failed ping.)".into());
    }
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut stream, &mut tokio::io::sink()).await;
    });
    Ok(())
}

/// Answers one request with `204` after reading its body, and keeps driving
/// the connection until the client releases it.
async fn serve_one(stream: SslStream<TcpStream>) -> TestResult<Observed> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before the replayed request")??;
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let mut body = request.into_body();
    let mut bytes = Vec::new();
    let handler = tokio::spawn(async move {
        while let Some(chunk) = body.data().await {
            let chunk = chunk?;
            body.flow_control().release_capacity(chunk.len())?;
            bytes.extend_from_slice(&chunk);
        }
        respond.send_response(
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(())?,
            true,
        )?;
        Ok::<_, Box<dyn Error + Send + Sync>>(bytes)
    });
    tokio::pin!(handler);
    let body = tokio::select! {
        body = &mut handler => body??,
        accepted = connection.accept() => match accepted {
            Some(Ok(_)) => return Err("the replacement connection got a second request".into()),
            _ => handler.await??,
        },
    };
    tokio::spawn(async move {
        let _ = poll_fn(|context| connection.poll_closed(context)).await;
    });
    Ok(Observed { method, path, body })
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
/// read and closes the connection when unanswered for 2 seconds; it keeps
/// the recipe's two PING-failure retries.
fn short_ping_timeout_client(identity: &TestIdentity) -> TestResult<Client> {
    let mut http2 = chromium::v154_http2();
    http2.preface_ping_after = Some(Duration::from_secs(1));
    http2.ping_timeout = Some(Duration::from_secs(2));
    assert_eq!(http2.ping_failure_retries, 2);
    Ok(
        Client::builder(ClientProfile::new(tls_settings()).with_http2(http2))
            .add_root_certificate_der(identity.root_der.clone())
            .build()?,
    )
}

/// Sends `/first`, waits past the PING threshold, and sends `request`.
async fn after_an_idle_connection<F, T>(
    client: &Client,
    server: &Server,
    request: F,
) -> TestResult<Result<T, RequestError>>
where
    F: Future<Output = Result<T, RequestError>>,
{
    let first = client
        .request(HttpProtocol::Http2, Method::GET, &server.url("/first"))?
        .send()
        .await?;
    assert_eq!(first.status(), StatusCode::OK);
    first.into_body().collect().await?;
    tokio::time::sleep(IDLE).await;
    Ok(request.await)
}

/// The resends one request gets before it fails: the recipe's
/// `ping_failure_retries`.
const PING_FAILURE_RETRIES: u8 = 2;

/// A Chromium-recipe client that follows every request's HEADERS with a
/// PING, since its connections are always read-idle for longer than zero,
/// and closes the connection when the PING goes unanswered for 500 ms.
fn every_request_pings_client(identity: &TestIdentity) -> TestResult<Client> {
    let mut http2 = chromium::v154_http2();
    http2.preface_ping_after = Some(Duration::ZERO);
    http2.ping_timeout = Some(Duration::from_millis(500));
    assert_eq!(http2.ping_failure_retries, PING_FAILURE_RETRIES);
    Ok(
        Client::builder(ClientProfile::new(tls_settings()).with_http2(http2))
            .add_root_certificate_der(identity.root_der.clone())
            .build()?,
    )
}

#[tokio::test]
async fn a_request_is_sent_again_at_most_twice_after_ping_failures() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (client_done, done_received) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            // The first attempt and each resend fail their PING.
            for _ in 0..=PING_FAILURE_RETRIES {
                let mut stream = accept_tls(&listener, &acceptor).await?;
                accept_client_preface(&mut stream).await?;
                read_request_headers(&mut stream, 1).await?;
                require_failed_ping(stream).await?;
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
            Ok::<_, Box<dyn Error + Send + Sync>>(finished)
        });

        let client = every_request_pings_client(&identity)?;
        let error = match client
            .request(
                HttpProtocol::Http2,
                Method::GET,
                &format!("https://{address}/limited"),
            )?
            .send()
            .await
        {
            Ok(_) => return Err("a request whose every PING failed got a response".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::Http2);
        assert!(
            source_chain_has_ping_timeout(&error),
            "missing Http2Error::PingTimeout: {error:?}"
        );
        client_done
            .send(())
            .map_err(|_| "server stopped before client completion")?;
        assert!(server.await??, "the client sent the request a fourth time");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_ping_failure_sends_the_request_again_on_a_new_connection() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let server = Server::start(&identity, true).await?;
        let client = short_ping_timeout_client(&identity)?;
        let request = client
            .request(HttpProtocol::Http2, Method::GET, &server.url("/b"))?
            .send();
        let response = after_an_idle_connection(&client, &server, request).await??;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        drop(client);

        assert_eq!(
            server.finish().await?,
            Some(Observed {
                method: Method::GET,
                path: "/b".to_owned(),
                body: Vec::new(),
            })
        );
        Ok(())
    })
    .await
}

/// Chromium resends after a PING failure whatever the method, with the same
/// body.
#[tokio::test]
async fn a_ping_failure_sends_a_post_with_its_owned_body_again() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let server = Server::start(&identity, true).await?;
        let client = short_ping_timeout_client(&identity)?;
        let request = client
            .request(HttpProtocol::Http2, Method::POST, &server.url("/b"))?
            .body("payload")
            .send();
        let response = after_an_idle_connection(&client, &server, request).await??;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        drop(client);

        assert_eq!(
            server.finish().await?,
            Some(Observed {
                method: Method::POST,
                path: "/b".to_owned(),
                body: b"payload".to_vec(),
            })
        );
        Ok(())
    })
    .await
}

/// A buffered streaming body within its limit is sent again like an owned
/// one.
#[tokio::test]
async fn a_ping_failure_sends_a_buffered_streaming_body_again() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let server = Server::start(&identity, true).await?;
        let client = short_ping_timeout_client(&identity)?;
        let request = client
            .request(HttpProtocol::Http2, Method::POST, &server.url("/b"))?
            .buffered_streaming_body(Full::new(Bytes::from_static(b"payload")), 64)
            .send();
        let response = after_an_idle_connection(&client, &server, request).await??;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        drop(client);

        assert_eq!(
            server.finish().await?,
            Some(Observed {
                method: Method::POST,
                path: "/b".to_owned(),
                body: b"payload".to_vec(),
            })
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_negotiated_request_is_sent_again_after_a_ping_failure() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let server = Server::start(&identity, true).await?;
        let client = short_ping_timeout_client(&identity)?;
        let first = client.get_negotiated(&server.url("/first"))?.send().await?;
        assert_eq!(first.status(), StatusCode::OK);
        first.into_body().collect().await?;
        tokio::time::sleep(IDLE).await;
        let response = client.get_negotiated(&server.url("/b"))?.send().await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        drop(client);

        assert_eq!(
            server.finish().await?,
            Some(Observed {
                method: Method::GET,
                path: "/b".to_owned(),
                body: Vec::new(),
            })
        );
        Ok(())
    })
    .await
}

/// Relays every CONNECT it accepts to `origin`, as a plaintext HTTP proxy.
async fn tunnel_every_connect(listener: TcpListener, origin: std::net::SocketAddr) {
    while let Ok((mut downstream, _)) = listener.accept().await {
        tokio::spawn(async move {
            if tls_support::read_head(&mut downstream).await.is_err() {
                return;
            }
            let Ok(mut upstream) = TcpStream::connect(origin).await else {
                return;
            };
            if downstream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .is_ok()
            {
                let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
            }
        });
    }
}

/// Through a CONNECT tunnel the resend opens a new tunnel to the origin.
#[tokio::test]
async fn a_request_through_a_tunnel_is_sent_again_after_a_ping_failure() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let server = Server::start(&identity, true).await?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(tunnel_every_connect(proxy_listener, server.address));
        let mut http2 = chromium::v154_http2();
        http2.preface_ping_after = Some(Duration::from_secs(1));
        http2.ping_timeout = Some(Duration::from_secs(2));
        let client = Client::builder(ClientProfile::new(tls_settings()).with_http2(http2))
            .add_root_certificate_der(identity.root_der.clone())
            .route(Route::http_proxy(HttpProxy::new(&format!(
                "http://{proxy_address}"
            ))?))
            .build()?;
        let request = client
            .request(HttpProtocol::Http2, Method::GET, &server.url("/b"))?
            .send();
        let response = after_an_idle_connection(&client, &server, request).await??;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        drop(client);

        assert_eq!(
            server.finish().await?,
            Some(Observed {
                method: Method::GET,
                path: "/b".to_owned(),
                body: Vec::new(),
            })
        );
        proxy.abort();
        Ok(())
    })
    .await
}

/// A one-shot streaming body went into the failed attempt, so the request
/// fails with the PING timeout and opens no other connection.
#[tokio::test]
async fn a_ping_failure_does_not_send_a_streaming_body_again() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let server = Server::start(&identity, false).await?;
        let client = short_ping_timeout_client(&identity)?;
        let request = client
            .request(HttpProtocol::Http2, Method::POST, &server.url("/b"))?
            .streaming_body(Full::new(Bytes::from_static(b"one-shot")))
            .send();
        let error = match after_an_idle_connection(&client, &server, request).await? {
            Ok(_) => return Err("a one-shot streaming body was sent again".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::Http2);
        assert!(
            source_chain_has_ping_timeout(&error),
            "missing Http2Error::PingTimeout: {error:?}"
        );
        drop(client);

        assert_eq!(server.finish().await?, None);
        Ok(())
    })
    .await
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

async fn bounded<F>(future: F) -> TestResult
where
    F: Future<Output = TestResult>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "test exceeded its timeout")?
}
