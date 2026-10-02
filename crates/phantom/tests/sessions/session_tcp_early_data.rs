//! TLS early data over TCP through the public client with the Firefox recipe.

use crate::support::tls as tls_support;

use std::{
    error::Error,
    future::{Future, poll_fn},
    net::Ipv4Addr,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    task::{Context, Poll},
    time::Duration,
};

use btls::ssl::{AlpnError, ExtensionType, SelectCertError, Ssl, SslAcceptor, select_next_proto};
use http::{Method, Response, StatusCode};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, RequestErrorKind, RequestTimeouts,
    profile::{ClientProfile, firefox},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream;

use tls_support::{H1_ALPN, H2_ALPN, TestIdentity};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Long enough that the client's early data is on the wire before the server
/// answers its ClientHello.
const SERVER_DELAY: Duration = Duration::from_millis(200);
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const H2_HEADERS: u8 = 0x1;

type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

/// What one ClientHello offered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Offer {
    early_data: bool,
    pre_shared_key: bool,
}

const FRESH: Offer = Offer {
    early_data: false,
    pre_shared_key: false,
};
const EARLY: Offer = Offer {
    early_data: true,
    pre_shared_key: true,
};

#[tokio::test]
async fn a_resumed_negotiated_get_travels_as_early_data() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let offers = Offers::default();
        let acceptor = acceptor(&identity, &offers, [H2_ALPN, H2_ALPN])?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (first_closed, wait_for_first_close) = oneshot::channel();
        let server = tokio::spawn(async move {
            let first = accept(&listener, &acceptor, Duration::ZERO).await?;
            serve_http2(first, "/").await?;
            first_closed
                .send(())
                .map_err(|_| "client stopped before the first connection closed")?;

            let second = accept(&listener, &acceptor, SERVER_DELAY).await?;
            let early = second.early_bytes();
            assert!(second.stream.ssl().session_reused());
            assert!(second.stream.ssl().early_data_accepted());
            serve_http2(second, "/early").await?;
            let early = early.lock().unwrap_or_else(PoisonError::into_inner).clone();
            Ok::<_, Box<dyn Error + Send + Sync>>(early)
        });

        let session = client(&identity)?;
        send_negotiated(&session, Method::GET, &format!("https://{address}/")).await?;
        if wait_for_first_close.await.is_err() {
            server.await??;
            return Err("server stopped before closing the first connection".into());
        }
        send_negotiated(&session, Method::GET, &format!("https://{address}/early")).await?;

        let early = server.await??;
        // The preface, SETTINGS, and the request HEADERS went out before the
        // server answered.
        assert!(h2_frame_types(&early)?.contains(&H2_HEADERS));
        assert_eq!(offers.take(), [FRESH, EARLY]);
        Ok(())
    })
    .await
}

/// The second connection resumes a ticket issued under `h2`, but the server
/// rejects its early data and selects `http/1.1`. The connection fails, and
/// the GET goes out again on a third connection that offers neither early
/// data nor a ticket, as Firefox restarts it after removing the peer's
/// resumption tokens.
#[tokio::test]
async fn an_alpn_change_restarts_a_get_on_a_full_handshake() -> TestResult<()> {
    let restarted = alpn_change_restart(Method::GET).await?;
    assert!(restarted.starts_with(b"GET /restarted HTTP/1.1\r\n"));
    Ok(())
}

/// A POST waits for the server's answer, so after the ALPN change its body
/// reaches only the restarted connection.
#[tokio::test]
async fn an_alpn_change_restarts_a_post_without_sending_its_body_early() -> TestResult<()> {
    let restarted = alpn_change_restart(Method::POST).await?;
    assert!(restarted.starts_with(b"POST /restarted HTTP/1.1\r\n"));
    assert!(restarted.ends_with(b"\r\n\r\npayload"));
    Ok(())
}

/// An exact HTTP/2 request whose resumed connection's early data is rejected
/// under `http/1.1` fails as a fresh connection that selects `http/1.1` does.
#[tokio::test]
async fn exact_http2_reports_an_alpn_change_after_early_data() -> TestResult<()> {
    let error =
        failure_after_early_data(Some(HttpProtocol::Http2), [H2_ALPN, H1_ALPN], false).await?;
    assert_eq!(error.kind(), RequestErrorKind::Http2);
    let chain = source_chain(&error);
    assert!(
        chain.contains("TLS selected http/1.1 ALPN, which is unsupported by the HTTP/2 transport"),
        "{chain}"
    );
    Ok(())
}

/// An exact HTTP/1.1 request whose resumed connection's early data is
/// rejected under `h2` fails as a fresh connection that selects `h2` does.
#[tokio::test]
async fn exact_http1_reports_an_alpn_change_after_early_data() -> TestResult<()> {
    let error =
        failure_after_early_data(Some(HttpProtocol::Http1), [H1_ALPN, H2_ALPN], false).await?;
    assert_eq!(error.kind(), RequestErrorKind::Http1);
    let chain = source_chain(&error);
    assert!(
        chain.contains("TLS selected h2 ALPN, which is unsupported by the HTTP/1 transport"),
        "{chain}"
    );
    Ok(())
}

/// The second server cannot resume the ticket and presents an untrusted
/// certificate: the handshake that completes after the rejected early data
/// fails as a fresh connection's would.
#[tokio::test]
async fn exact_http2_reports_a_handshake_failure_after_early_data() -> TestResult<()> {
    let error =
        failure_after_early_data(Some(HttpProtocol::Http2), [H2_ALPN, H2_ALPN], true).await?;
    assert_eq!(error.kind(), RequestErrorKind::Tls);
    assert!(
        source_chain(&error).contains("TLS handshake failed after early data"),
        "{error}"
    );
    Ok(())
}

#[tokio::test]
async fn exact_http1_reports_a_handshake_failure_after_early_data() -> TestResult<()> {
    let error =
        failure_after_early_data(Some(HttpProtocol::Http1), [H1_ALPN, H1_ALPN], true).await?;
    assert_eq!(error.kind(), RequestErrorKind::Tls);
    assert!(
        source_chain(&error).contains("TLS handshake failed after early data"),
        "{error}"
    );
    Ok(())
}

/// A negotiated request on a connection whose handshake fails after a
/// rejected ticket fails with the TLS error, not a connection error, and is
/// not restarted.
#[tokio::test]
async fn negotiated_request_reports_a_handshake_failure_after_early_data() -> TestResult<()> {
    let error = failure_after_early_data(None, [H2_ALPN, H2_ALPN], true).await?;
    assert_eq!(error.kind(), RequestErrorKind::Tls);
    assert!(
        source_chain(&error).contains("TLS handshake failed after early data"),
        "{error}"
    );
    Ok(())
}

/// The POST waits in pool admission longer than its connect limit, behind a
/// slow request on the origin's only HTTP/1.1 connection. Its own connection
/// then offers early data, and its wait for the server's delayed answer
/// counts against the connect phase of that connection attempt only.
#[tokio::test]
async fn a_post_waits_for_early_data_within_its_own_connect_attempt() -> TestResult<()> {
    // The POST's admission wait exceeds its connect limit by half the limit;
    // the early-data wait that follows takes SERVER_DELAY, a fifth of it.
    const ADMISSION_WAIT: Duration = Duration::from_millis(1500);
    const CONNECT_LIMIT: Duration = Duration::from_millis(1000);
    bounded(async {
        let identity = TestIdentity::generate()?;
        let offers = Offers::default();
        let acceptor = acceptor(&identity, &offers, [H1_ALPN, H1_ALPN])?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (slow_head_read, wait_for_slow_head) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut slow = accept(&listener, &acceptor, Duration::ZERO).await?;
            tls_support::read_head(&mut slow).await?;
            slow_head_read
                .send(())
                .map_err(|_| "client stopped before the slow request was read")?;
            // The POST, sent once the head is read, waits in pool admission
            // for all of this, which is longer than its connect limit.
            tokio::time::sleep(ADMISSION_WAIT).await;
            slow.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await?;
            slow.shutdown().await?;

            let mut resumed = accept(&listener, &acceptor, SERVER_DELAY).await?;
            assert!(resumed.stream.ssl().early_data_accepted());
            let early = resumed.early_bytes();
            let mut request = tls_support::read_head(&mut resumed).await?;
            let mut body = [0_u8; 7];
            resumed.read_exact(&mut body).await?;
            request.extend_from_slice(&body);
            resumed
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await?;
            resumed.shutdown().await?;
            let early = early.lock().unwrap_or_else(PoisonError::into_inner).clone();
            Ok::<_, Box<dyn Error + Send + Sync>>((request, early))
        });

        let mut http1 = firefox::v156_http1();
        http1.max_connections_per_origin = std::num::NonZeroUsize::MIN;
        let profile = ClientProfile::new(firefox::v156_tls())
            .with_http2(firefox::v156_http2())
            .with_http1(http1);
        let session = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
        let slow_uri = format!("https://{address}/slow");
        let slow = send_negotiated(&session, Method::GET, &slow_uri);
        let post = async {
            // The slow request holds the origin's only connection from here on.
            wait_for_slow_head
                .await
                .map_err(|_| "server stopped before reading the slow request")?;
            let response = session
                .request_negotiated(Method::POST, &format!("https://{address}/post"))?
                .body("payload")
                .timeouts(RequestTimeouts::new().connect(CONNECT_LIMIT))
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            response.into_body().collect().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        let (slow, post) = tokio::join!(slow, post);
        slow?;
        post?;

        let (request, early) = server.await??;
        assert!(request.starts_with(b"POST /post HTTP/1.1\r\n"));
        assert!(request.ends_with(b"\r\n\r\npayload"));
        assert!(early.is_empty());
        assert_eq!(offers.take(), [FRESH, EARLY]);
        Ok(())
    })
    .await
}

/// Learns an `h2` ticket, then sends `method` to `/restarted` while the
/// server rejects the resumed connection's early data and selects
/// `http/1.1`. Returns what the third connection received.
async fn alpn_change_restart(method: Method) -> TestResult<Vec<u8>> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let offers = Offers::default();
        let acceptor = acceptor(&identity, &offers, [H2_ALPN, H1_ALPN])?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (first_closed, wait_for_first_close) = oneshot::channel();
        let server = tokio::spawn(async move {
            let first = accept(&listener, &acceptor, Duration::ZERO).await?;
            serve_http2(first, "/").await?;
            first_closed
                .send(())
                .map_err(|_| "client stopped before the first connection closed")?;

            // The client drops this connection without sending a request.
            let mut rejected = accept(&listener, &acceptor, SERVER_DELAY).await?;
            assert!(!rejected.stream.ssl().early_data_accepted());
            let mut unprocessed = Vec::new();
            let _ = rejected.read_to_end(&mut unprocessed).await;
            assert!(unprocessed.is_empty(), "{unprocessed:?}");

            let mut restarted = accept(&listener, &acceptor, Duration::ZERO).await?;
            assert!(!restarted.stream.ssl().session_reused());
            let mut request = tls_support::read_head(&mut restarted).await?;
            if request.starts_with(b"POST ") {
                let mut body = [0_u8; 7];
                restarted.read_exact(&mut body).await?;
                request.extend_from_slice(&body);
            }
            restarted
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await?;
            restarted.shutdown().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(request)
        });

        let session = client(&identity)?;
        send_negotiated(&session, Method::GET, &format!("https://{address}/")).await?;
        if wait_for_first_close.await.is_err() {
            server.await??;
            return Err("server stopped before closing the first connection".into());
        }
        send_negotiated(&session, method, &format!("https://{address}/restarted")).await?;

        let restarted = server.await??;
        assert_eq!(offers.take(), [FRESH, EARLY, FRESH]);
        Ok(restarted)
    })
    .await
}

/// Learns a ticket over `protocol`, or a negotiated `h2` with `None`, then
/// sends a GET while the second connection selects `alpn[1]` or, with
/// `untrusted`, presents an untrusted certificate. Returns the request's
/// error.
async fn failure_after_early_data(
    protocol: Option<HttpProtocol>,
    alpn: [&'static [u8]; 2],
    untrusted: bool,
) -> TestResult<phantom::RequestError> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let offers = Offers::default();
        let acceptor = acceptor(&identity, &offers, alpn)?;
        let second = if untrusted {
            acceptor_for(&TestIdentity::generate()?, &offers, alpn[1])?
        } else {
            acceptor.clone()
        };
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (first_closed, wait_for_first_close) = oneshot::channel();
        let server = tokio::spawn(async move {
            let first = accept(&listener, &acceptor, Duration::ZERO).await?;
            if protocol == Some(HttpProtocol::Http1) {
                serve_http1(first).await?;
            } else {
                serve_http2(first, "/").await?;
            }
            first_closed
                .send(())
                .map_err(|_| "client stopped before the first connection closed")?;
            // The handshake fails on the client, or the client drops the
            // connection after the ALPN change; either way it sends nothing
            // the server processes.
            if let Ok(mut rejected) = accept(&listener, &second, SERVER_DELAY).await {
                assert!(!rejected.stream.ssl().early_data_accepted());
                let mut unprocessed = Vec::new();
                let _ = rejected.read_to_end(&mut unprocessed).await;
                assert!(unprocessed.is_empty(), "{unprocessed:?}");
            }
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let session = client(&identity)?;
        let first = format!("https://{address}/");
        match protocol {
            Some(protocol) => send(&session, protocol, Method::GET, &first).await?,
            None => send_negotiated(&session, Method::GET, &first).await?,
        }
        if wait_for_first_close.await.is_err() {
            server.await??;
            return Err("server stopped before closing the first connection".into());
        }
        let uri = format!("https://{address}/failed");
        let failed = match protocol {
            Some(protocol) => session.get(protocol, &uri)?,
            None => session.get_negotiated(&uri)?,
        };
        let error = match failed.send().await {
            Ok(_) => return Err("the request succeeded after the handshake failed".into()),
            Err(error) => error,
        };
        server.await??;
        assert_eq!(offers.take()[1], EARLY);
        Ok(error)
    })
    .await
}

fn client(identity: &TestIdentity) -> TestResult<Client> {
    let profile = ClientProfile::new(firefox::v156_tls()).with_http2(firefox::v156_http2());
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}

/// The ClientHello offers the server saw, in order.
#[derive(Clone, Default)]
struct Offers(Arc<Mutex<Vec<Offer>>>);

impl Offers {
    fn record(&self, offer: Offer) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(offer);
    }

    fn take(&self) -> Vec<Offer> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// Builds an acceptor that records each ClientHello's offer and selects the
/// ALPN protocol at the handshake's index in `alpn`, and the last one after.
fn acceptor(
    identity: &TestIdentity,
    offers: &Offers,
    alpn: [&'static [u8]; 2],
) -> TestResult<SslAcceptor> {
    let handshakes = std::sync::atomic::AtomicUsize::new(0);
    build_acceptor(identity, offers, move || {
        let handshake = handshakes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        alpn[handshake.min(1)]
    })
}

fn acceptor_for(
    identity: &TestIdentity,
    offers: &Offers,
    alpn: &'static [u8],
) -> TestResult<SslAcceptor> {
    build_acceptor(identity, offers, move || alpn)
}

fn build_acceptor(
    identity: &TestIdentity,
    offers: &Offers,
    alpn: impl Fn() -> &'static [u8] + Send + Sync + 'static,
) -> TestResult<SslAcceptor> {
    let mut acceptor = identity.acceptor_builder(H2_ALPN)?;
    let offers = offers.clone();
    acceptor.set_select_certificate_callback(move |hello| {
        offers.record(Offer {
            early_data: hello.get_extension(ExtensionType::EARLY_DATA).is_some(),
            pre_shared_key: hello.get_extension(ExtensionType::PRE_SHARED_KEY).is_some(),
        });
        Ok::<_, SelectCertError>(())
    });
    acceptor.set_alpn_select_callback(move |_, offered| {
        select_next_proto(alpn(), offered).ok_or(AlpnError::NOACK)
    });
    Ok(acceptor.build())
}

/// A server TLS stream that records the application bytes it read before its
/// handshake completed, which were early data.
struct Server {
    stream: SslStream<TcpStream>,
    early: Arc<Mutex<Vec<u8>>>,
}

impl Server {
    fn early_bytes(&self) -> Arc<Mutex<Vec<u8>>> {
        Arc::clone(&self.early)
    }
}

impl AsyncRead for Server {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(context, buffer);
        if !self.stream.ssl().is_init_finished() {
            self.early
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(&buffer.filled()[before..]);
        }
        result
    }
}

impl AsyncWrite for Server {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

/// Accepts one connection that issues tickets permitting early data and
/// accepts early data, starting the handshake `delay` after the TCP accept.
async fn accept(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
    delay: Duration,
) -> TestResult<Server> {
    let (tcp, _) = listener.accept().await?;
    tokio::time::sleep(delay).await;
    let mut ssl = Ssl::new(acceptor.context())?;
    ssl.set_early_data_enabled(true);
    let mut stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(Server {
        stream,
        early: Arc::default(),
    })
}

async fn serve_http2(stream: Server, expected_path: &str) -> TestResult<()> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before request")??;
    assert_eq!(request.uri().path(), expected_path);
    respond.send_response(Response::builder().status(StatusCode::OK).body(())?, true)?;
    connection.graceful_shutdown();
    match poll_fn(|context| connection.poll_closed(context)).await {
        Ok(()) => Ok(()),
        Err(error) if error.get_io().is_some_and(tls_support::is_peer_gone) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

async fn serve_http1(mut stream: Server) -> TestResult<()> {
    tls_support::read_head(&mut stream).await?;
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await?;
    stream.shutdown().await?;
    Ok(())
}

async fn send_negotiated(session: &phantom::Client, method: Method, uri: &str) -> TestResult<()> {
    let mut request = session.request_negotiated(method.clone(), uri)?;
    if method == Method::POST {
        request = request.body("payload");
    }
    let response = request.send().await?;
    assert_eq!(response.status(), StatusCode::OK);
    response.into_body().collect().await?;
    Ok(())
}

async fn send(
    session: &phantom::Client,
    protocol: HttpProtocol,
    method: Method,
    uri: &str,
) -> TestResult<()> {
    let response = session.request(protocol, method, uri)?.send().await?;
    assert_eq!(response.status(), StatusCode::OK);
    response.into_body().collect().await?;
    Ok(())
}

/// Returns the type of every frame after the client preface.
fn h2_frame_types(bytes: &[u8]) -> TestResult<Vec<u8>> {
    let mut frames = bytes
        .strip_prefix(H2_PREFACE)
        .ok_or("the early data does not start with the HTTP/2 preface")?;
    let mut types = Vec::new();
    while let Some(header) = frames.first_chunk::<9>() {
        let length =
            usize::from(header[0]) << 16 | usize::from(header[1]) << 8 | usize::from(header[2]);
        types.push(header[3]);
        frames = frames.get(9 + length..).unwrap_or_default();
    }
    Ok(types)
}

/// Joins the messages of `error` and its sources.
fn source_chain(error: &(dyn Error + 'static)) -> String {
    let mut messages = vec![error.to_string()];
    let mut source = error.source();
    while let Some(error) = source {
        messages.push(error.to_string());
        source = error.source();
    }
    messages.join(": ")
}

async fn bounded<T, F>(future: F) -> TestResult<T>
where
    F: Future<Output = TestResult<T>>,
{
    timeout(TEST_TIMEOUT, future).await?
}
