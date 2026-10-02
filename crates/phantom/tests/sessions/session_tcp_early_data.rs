//! TLS early data over TCP through the public client with the Firefox recipe.

use crate::support::tls as tls_support;

use std::{
    error::Error,
    future::{Future, poll_fn},
    net::Ipv4Addr,
    pin::Pin,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use btls::ssl::{AlpnError, ExtensionType, SelectCertError, Ssl, SslAcceptor, select_next_proto};
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use phantom::{
    Client,
    profile::{ClientProfile, firefox},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream;

use tls_support::TestIdentity;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Long enough that the client's early data is on the wire before the server
/// answers its ClientHello.
const SERVER_DELAY: Duration = Duration::from_millis(200);
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::test]
async fn a_resumed_negotiated_get_travels_as_early_data() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let offers = Arc::new(Mutex::new(Vec::new()));
        let acceptor = acceptor(&identity, Arc::clone(&offers), |_| tls_support::H2_ALPN)?;
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

        let session = client(&identity)?.session();
        get(&session, &format!("https://{address}/")).await?;
        if wait_for_first_close.await.is_err() {
            server.await??;
            return Err("server stopped before closing the first connection".into());
        }
        get(&session, &format!("https://{address}/early")).await?;

        let early = server.await??;
        // The preface, SETTINGS, and the request HEADERS went out before the
        // server answered.
        assert!(early.starts_with(H2_PREFACE));
        assert!(early.len() > H2_PREFACE.len() + 50);
        assert_eq!(
            *offers.lock().unwrap_or_else(PoisonError::into_inner),
            [false, true]
        );
        Ok(())
    })
    .await
}

/// The second connection resumes a ticket issued under `h2`, but the server
/// rejects its early data and selects `http/1.1`. The connection fails, and
/// the request goes out again on a third connection that offers no early
/// data, as Firefox restarts it.
#[tokio::test]
async fn an_alpn_change_after_rejected_early_data_restarts_without_early_data() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let offers = Arc::new(Mutex::new(Vec::new()));
        let handshakes = AtomicUsize::new(0);
        let acceptor = acceptor(&identity, Arc::clone(&offers), move |_| {
            if handshakes.fetch_add(1, Ordering::SeqCst) == 0 {
                tls_support::H2_ALPN
            } else {
                tls_support::H1_ALPN
            }
        })?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (first_closed, wait_for_first_close) = oneshot::channel();
        let server = tokio::spawn(async move {
            let first = accept(&listener, &acceptor, Duration::ZERO).await?;
            serve_http2(first, "/").await?;
            first_closed
                .send(())
                .map_err(|_| "client stopped before the first connection closed")?;

            // The client drops this connection without a request.
            let mut rejected = accept(&listener, &acceptor, SERVER_DELAY).await?;
            assert!(!rejected.stream.ssl().early_data_accepted());
            let mut unprocessed = Vec::new();
            let _ = rejected.read_to_end(&mut unprocessed).await;

            let mut restarted = accept(&listener, &acceptor, Duration::ZERO).await?;
            let head = tls_support::read_head(&mut restarted).await?;
            assert!(head.starts_with(b"GET /restarted HTTP/1.1\r\n"));
            restarted
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await?;
            restarted.shutdown().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(unprocessed)
        });

        let session = client(&identity)?.session();
        get(&session, &format!("https://{address}/")).await?;
        if wait_for_first_close.await.is_err() {
            server.await??;
            return Err("server stopped before closing the first connection".into());
        }
        get(&session, &format!("https://{address}/restarted")).await?;

        let unprocessed = server.await??;
        assert!(unprocessed.is_empty());
        assert_eq!(
            *offers.lock().unwrap_or_else(PoisonError::into_inner),
            [false, true, false]
        );
        Ok(())
    })
    .await
}

fn client(identity: &TestIdentity) -> TestResult<Client> {
    let profile = ClientProfile::new(firefox::v156_tls()).with_http2(firefox::v156_http2());
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}

/// Builds an acceptor that records whether each ClientHello offered early
/// data and selects the ALPN protocol `alpn` returns for it.
fn acceptor(
    identity: &TestIdentity,
    offers: Arc<Mutex<Vec<bool>>>,
    alpn: impl Fn(&[u8]) -> &'static [u8] + Send + Sync + 'static,
) -> TestResult<SslAcceptor> {
    let mut acceptor = identity.acceptor_builder(tls_support::H2_ALPN)?;
    acceptor.set_select_certificate_callback(move |hello| {
        offers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(hello.get_extension(ExtensionType::EARLY_DATA).is_some());
        Ok::<_, SelectCertError>(())
    });
    acceptor.set_alpn_select_callback(move |_, offered| {
        select_next_proto(alpn(offered), offered).ok_or(AlpnError::NOACK)
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

async fn get(session: &phantom::Session, uri: &str) -> TestResult<()> {
    let response = session.get_negotiated(uri)?.send().await?;
    assert_eq!(response.status(), StatusCode::OK);
    response.into_body().collect().await?;
    Ok(())
}

async fn bounded<T, F>(future: F) -> TestResult<T>
where
    F: Future<Output = TestResult<T>>,
{
    timeout(TEST_TIMEOUT, future).await?
}
