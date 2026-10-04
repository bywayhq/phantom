//! TLS ticket resumption on `Client` WebSocket openings: an opening shares
//! the TLS session tickets of the request pool key of its origin and route,
//! in both directions.

use crate::support::{tls as tls_support, websocket as websocket_support};

use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use btls::ssl::{AlpnError, ExtensionType, SelectCertError, SslAcceptor, select_next_proto};
use bytes::Bytes;
use http::{Method, Response, StatusCode};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, HttpProxy, Route,
    profile::{ClientProfile, chromium, firefox},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
};

use super::early_data_server::{
    SERVER_DELAY, Server, TestResult, accept, bounded, h2_frame_types, serve_http1, serve_http2,
};
use tls_support::TestIdentity;

const H2_SETTINGS: u8 = 0x4;
const H2_WINDOW_UPDATE: u8 = 0x8;
/// The server's ALPN preference: `h2` when the client offers it.
const H2_THEN_HTTP1: &[u8] = b"\x02h2\x08http/1.1";
const HTTP1_ONLY: &[u8] = b"\x08http/1.1";

/// What one ClientHello offered.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Hello {
    pre_shared_key: bool,
    early_data: bool,
    alpn: Vec<String>,
}

/// The ClientHellos the server saw, in order.
#[derive(Clone, Default)]
struct Hellos(Arc<Mutex<Vec<Hello>>>);

impl Hellos {
    fn take(&self) -> Vec<Hello> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

fn hello(pre_shared_key: bool, early_data: bool, alpn: &[&str]) -> Hello {
    Hello {
        pre_shared_key,
        early_data,
        alpn: alpn.iter().map(|protocol| (*protocol).to_owned()).collect(),
    }
}

/// An acceptor that records each ClientHello and selects ALPN from
/// `preference`, a wire-format list in the server's order.
fn acceptor(
    identity: &TestIdentity,
    hellos: &Hellos,
    preference: &'static [u8],
) -> TestResult<SslAcceptor> {
    let mut acceptor = identity.acceptor_builder(preference)?;
    let hellos = hellos.clone();
    acceptor.set_select_certificate_callback(move |client_hello| {
        let alpn = client_hello
            .get_extension(ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
            .map(decode_alpn_extension)
            .unwrap_or_default();
        hellos
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Hello {
                pre_shared_key: client_hello
                    .get_extension(ExtensionType::PRE_SHARED_KEY)
                    .is_some(),
                early_data: client_hello
                    .get_extension(ExtensionType::EARLY_DATA)
                    .is_some(),
                alpn,
            });
        Ok::<_, SelectCertError>(())
    });
    acceptor.set_alpn_select_callback(move |_, offered| {
        select_next_proto(preference, offered).ok_or(AlpnError::NOACK)
    });
    Ok(acceptor.build())
}

/// Decodes an ALPN extension body: a two-byte length, then the protocols.
fn decode_alpn_extension(body: &[u8]) -> Vec<String> {
    let mut protocols = Vec::new();
    let mut rest = body.get(2..).unwrap_or_default();
    while let Some((&length, tail)) = rest.split_first() {
        let Some((protocol, tail)) = tail.split_at_checked(usize::from(length)) else {
            break;
        };
        protocols.push(String::from_utf8_lossy(protocol).into_owned());
        rest = tail;
    }
    protocols
}

fn firefox_client(identity: &TestIdentity) -> TestResult<Client> {
    let profile = ClientProfile::new(firefox::v157_tls())
        .with_http1(firefox::v157_http1())
        .with_http2(firefox::v157_http2())
        .with_websocket(firefox::v157_websocket());
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}

fn chromium_client(identity: &TestIdentity) -> TestResult<Client> {
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http1(chromium::v154_http1())
        .with_http2(chromium::v154_http2())
        .with_websocket(chromium::v154_websocket());
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}

/// Answers one WebSocket Upgrade to `path` and waits for the client to close
/// the connection.
async fn serve_upgrade(mut stream: Server, path: &str) -> TestResult<()> {
    let head = tls_support::read_head(&mut stream).await?;
    if !head.starts_with(format!("GET {path} HTTP/1.1\r\n").as_bytes()) {
        return Err(format!("unexpected opening: {}", String::from_utf8_lossy(&head)).into());
    }
    let key = websocket_support::header_value(&head, "sec-websocket-key")
        .ok_or("the opening has no Sec-WebSocket-Key")?;
    let accept = websocket_support::websocket_accept(key);
    stream
        .write_all(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                 Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
    stream.flush().await?;
    let mut rest = Vec::new();
    // The client closes or resets the connection when it drops the socket.
    let _ = stream.read_to_end(&mut rest).await;
    Ok(())
}

/// Accepts one extended CONNECT on an HTTP/2 connection that enables it,
/// answers 200, and waits for the client to close the connection.
async fn serve_extended_connect(stream: Server) -> TestResult<()> {
    let mut builder = ::http2::server::Builder::new();
    builder.enable_connect_protocol();
    let mut connection = builder.handshake::<_, Bytes>(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before the extended CONNECT")??;
    assert_eq!(request.method(), Method::CONNECT);
    let send = respond.send_response(Response::new(()), false)?;
    while let Some(Ok(_)) = connection.accept().await {}
    drop(send);
    Ok(())
}

async fn get(client: &Client, protocol: Option<HttpProtocol>, uri: &str) -> TestResult<()> {
    let request = match protocol {
        Some(protocol) => client.get(protocol, uri)?,
        None => client.get_negotiated(uri)?,
    };
    let response = request.send().await?;
    assert_eq!(response.status(), StatusCode::OK);
    response.into_body().collect().await?;
    Ok(())
}

/// Mirrors Firefox 157's `websocket` resumption capture: the page's
/// connection closes, and the WebSocket's new HTTP/2 connection resumes its
/// ticket and sends the preface, SETTINGS, and WINDOW_UPDATE as early data.
/// The extended CONNECT waits for the server's SETTINGS, so it is not early
/// data.
#[tokio::test]
async fn a_firefox_websocket_after_a_negotiated_request_sends_its_preface_early() -> TestResult<()>
{
    bounded(async {
        let identity = TestIdentity::generate()?;
        let hellos = Hellos::default();
        let acceptor = acceptor(&identity, &hellos, H2_THEN_HTTP1)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (page_closed, wait_for_page_close) = oneshot::channel();
        let server = tokio::spawn(async move {
            let page = accept(&listener, &acceptor, Duration::ZERO).await?;
            serve_http2(page, "/").await?;
            page_closed
                .send(())
                .map_err(|_| "client stopped before the page's connection closed")?;

            let socket = accept(&listener, &acceptor, SERVER_DELAY).await?;
            let early = socket.early_bytes();
            assert!(socket.stream.ssl().session_reused());
            assert!(socket.stream.ssl().early_data_accepted());
            serve_extended_connect(socket).await?;
            let early = early.lock().unwrap_or_else(PoisonError::into_inner).clone();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(early)
        });

        let client = firefox_client(&identity)?;
        get(&client, None, &format!("https://{address}/")).await?;
        if wait_for_page_close.await.is_err() {
            server.await??;
            return Err("server stopped before closing the page's connection".into());
        }
        let socket = client
            .websocket_with_profile_policy(&format!("wss://{address}/socket"))?
            .connect()
            .await?;
        drop(socket);
        drop(client);

        let early = server.await??;
        // Firefox 157's capture records SETTINGS and then WINDOW_UPDATE.
        assert_eq!(h2_frame_types(&early)?, [H2_SETTINGS, H2_WINDOW_UPDATE]);
        assert_eq!(
            hellos.take(),
            [
                hello(false, false, &["h2", "http/1.1"]),
                hello(true, true, &["h2", "http/1.1"]),
            ]
        );
        Ok(())
    })
    .await
}

/// Mirrors Firefox 157's `websocket-http1` resumption capture: after an
/// HTTP/1.1 request, the WebSocket connection resumes the request's ticket
/// and sends its Upgrade as early data.
#[tokio::test]
async fn a_firefox_upgrade_after_an_http1_request_travels_as_early_data() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let hellos = Hellos::default();
        let acceptor = acceptor(&identity, &hellos, HTTP1_ONLY)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            serve_http1(accept(&listener, &acceptor, Duration::ZERO).await?).await?;

            let socket = accept(&listener, &acceptor, SERVER_DELAY).await?;
            let early = socket.early_bytes();
            assert!(socket.stream.ssl().session_reused());
            assert!(socket.stream.ssl().early_data_accepted());
            serve_upgrade(socket, "/socket").await?;
            let early = early.lock().unwrap_or_else(PoisonError::into_inner).clone();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(early)
        });

        let client = firefox_client(&identity)?;
        get(
            &client,
            Some(HttpProtocol::Http1),
            &format!("https://{address}/"),
        )
        .await?;
        let socket = client
            .websocket(&format!("wss://{address}/socket"))?
            .connect()
            .await?;
        drop(socket);
        drop(client);

        let early = server.await??;
        assert!(early.starts_with(b"GET /socket HTTP/1.1\r\n"));
        assert_eq!(
            hellos.take(),
            [
                hello(false, false, &["h2", "http/1.1"]),
                hello(true, true, &["h2", "http/1.1"]),
            ]
        );
        Ok(())
    })
    .await
}

/// Follows the order of Firefox 157's `websocket-http1` capture: the
/// request after the WebSocket resumed a ticket of the page's connection,
/// not of the WebSocket's. The page's and the request's connections reach
/// acceptor A and the WebSocket's reaches acceptor B, whose ticket keys
/// differ, so the request resumes only with one of the page's tickets.
#[tokio::test]
async fn a_firefox_request_after_an_upgrade_resumes_the_page_ticket() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let hellos = Hellos::default();
        let page_acceptor = acceptor(&identity, &hellos, HTTP1_ONLY)?;
        let socket_acceptor = acceptor(&identity, &hellos, HTTP1_ONLY)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            serve_http1(accept(&listener, &page_acceptor, Duration::ZERO).await?).await?;

            let socket = accept(&listener, &socket_acceptor, Duration::ZERO).await?;
            assert!(!socket.stream.ssl().session_reused());
            serve_upgrade(socket, "/socket").await?;

            let done = accept(&listener, &page_acceptor, SERVER_DELAY).await?;
            let early = done.early_bytes();
            assert!(done.stream.ssl().session_reused());
            assert!(done.stream.ssl().early_data_accepted());
            serve_http1(done).await?;
            let early = early.lock().unwrap_or_else(PoisonError::into_inner).clone();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(early)
        });

        let client = firefox_client(&identity)?;
        exchange_around_an_upgrade(&client, address).await?;

        let early = server.await??;
        assert!(early.starts_with(b"GET /done HTTP/1.1\r\n"));
        assert_eq!(
            hellos.take(),
            [
                hello(false, false, &["h2", "http/1.1"]),
                hello(true, true, &["h2", "http/1.1"]),
                hello(true, true, &["h2", "http/1.1"]),
            ]
        );
        Ok(())
    })
    .await
}

/// The Chromium twin of the test above: Chrome presents its newest ticket,
/// one the WebSocket's connection was issued, and keeps two, so the
/// request offers B's ticket to A and makes a full handshake.
#[tokio::test]
async fn a_chromium_request_after_an_upgrade_presents_the_upgrade_ticket() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let hellos = Hellos::default();
        let page_acceptor = acceptor(&identity, &hellos, HTTP1_ONLY)?;
        let socket_acceptor = acceptor(&identity, &hellos, HTTP1_ONLY)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            serve_http1(accept(&listener, &page_acceptor, Duration::ZERO).await?).await?;

            let socket = accept(&listener, &socket_acceptor, Duration::ZERO).await?;
            assert!(!socket.stream.ssl().session_reused());
            serve_upgrade(socket, "/socket").await?;

            let done = accept(&listener, &page_acceptor, Duration::ZERO).await?;
            assert!(!done.stream.ssl().session_reused());
            serve_http1(done).await
        });

        let client = chromium_client(&identity)?;
        exchange_around_an_upgrade(&client, address).await?;

        server.await??;
        assert_eq!(
            hellos.take(),
            [
                hello(false, false, &["h2", "http/1.1"]),
                hello(true, false, &["h2", "http/1.1"]),
                hello(true, false, &["h2", "http/1.1"]),
            ]
        );
        Ok(())
    })
    .await
}

/// Sends an exact HTTP/1.1 request, opens and drops a WebSocket, and sends
/// another exact HTTP/1.1 request to `/done`, as the `websocket-http1`
/// capture's page does.
async fn exchange_around_an_upgrade(
    client: &Client,
    address: std::net::SocketAddr,
) -> TestResult<()> {
    get(
        client,
        Some(HttpProtocol::Http1),
        &format!("https://{address}/"),
    )
    .await?;
    let socket = client
        .websocket(&format!("wss://{address}/socket"))?
        .connect()
        .await?;
    drop(socket);
    get(
        client,
        Some(HttpProtocol::Http1),
        &format!("https://{address}/done"),
    )
    .await
}

/// Chrome's WebSocket connection offers only `http/1.1` but resumes the
/// ticket of the origin's `h2` connection: its session cache is keyed by
/// host, port, and partition, not by ALPN.
#[tokio::test]
async fn a_chromium_upgrade_resumes_the_ticket_of_a_negotiated_request() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let hellos = Hellos::default();
        let acceptor = acceptor(&identity, &hellos, H2_THEN_HTTP1)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (page_closed, wait_for_page_close) = oneshot::channel();
        let server = tokio::spawn(async move {
            serve_http2(accept(&listener, &acceptor, Duration::ZERO).await?, "/").await?;
            page_closed
                .send(())
                .map_err(|_| "client stopped before the page's connection closed")?;

            let socket = accept(&listener, &acceptor, Duration::ZERO).await?;
            assert!(socket.stream.ssl().session_reused());
            assert_eq!(
                socket.stream.ssl().selected_alpn_protocol(),
                Some(&b"http/1.1"[..])
            );
            serve_upgrade(socket, "/socket").await
        });

        let client = chromium_client(&identity)?;
        get(&client, None, &format!("https://{address}/")).await?;
        if wait_for_page_close.await.is_err() {
            server.await??;
            return Err("server stopped before closing the page's connection".into());
        }
        let socket = client
            .websocket_with_profile_policy(&format!("wss://{address}/socket"))?
            .connect()
            .await?;
        drop(socket);
        drop(client);

        server.await??;
        assert_eq!(
            hellos.take(),
            [
                hello(false, false, &["h2", "http/1.1"]),
                hello(true, false, &["http/1.1"]),
            ]
        );
        Ok(())
    })
    .await
}

/// A WebSocket that is the first contact with an origin leaves its ticket
/// for the origin's later requests.
#[tokio::test]
async fn a_negotiated_request_resumes_the_ticket_of_a_chromium_upgrade() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let hellos = Hellos::default();
        let acceptor = acceptor(&identity, &hellos, H2_THEN_HTTP1)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            serve_upgrade(
                accept(&listener, &acceptor, Duration::ZERO).await?,
                "/socket",
            )
            .await?;

            let page = accept(&listener, &acceptor, Duration::ZERO).await?;
            assert!(page.stream.ssl().session_reused());
            serve_http2(page, "/").await
        });

        let client = chromium_client(&identity)?;
        let socket = client
            .websocket_with_profile_policy(&format!("wss://{address}/socket"))?
            .connect()
            .await?;
        drop(socket);
        get(&client, None, &format!("https://{address}/")).await?;
        drop(client);

        server.await??;
        assert_eq!(
            hellos.take(),
            [
                hello(false, false, &["http/1.1"]),
                hello(true, false, &["h2", "http/1.1"]),
            ]
        );
        Ok(())
    })
    .await
}

/// An exact HTTP/2 opening shares the exact HTTP/2 pool's tickets.
#[tokio::test]
async fn an_exact_http2_websocket_resumes_the_ticket_of_an_exact_http2_request() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let hellos = Hellos::default();
        let acceptor = acceptor(&identity, &hellos, H2_THEN_HTTP1)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (page_closed, wait_for_page_close) = oneshot::channel();
        let server = tokio::spawn(async move {
            serve_http2(accept(&listener, &acceptor, Duration::ZERO).await?, "/").await?;
            page_closed
                .send(())
                .map_err(|_| "client stopped before the page's connection closed")?;

            let socket = accept(&listener, &acceptor, Duration::ZERO).await?;
            assert!(socket.stream.ssl().session_reused());
            serve_extended_connect(socket).await
        });

        let client = chromium_client(&identity)?;
        get(
            &client,
            Some(HttpProtocol::Http2),
            &format!("https://{address}/"),
        )
        .await?;
        if wait_for_page_close.await.is_err() {
            server.await??;
            return Err("server stopped before closing the page's connection".into());
        }
        let socket = client
            .websocket_with_protocol(HttpProtocol::Http2, &format!("wss://{address}/socket"))?
            .connect()
            .await?;
        drop(socket);
        drop(client);

        server.await??;
        assert_eq!(
            hellos.take(),
            [
                hello(false, false, &["h2", "http/1.1"]),
                hello(true, false, &["h2", "http/1.1"]),
            ]
        );
        Ok(())
    })
    .await
}

/// An HTTP/2 connection the page keeps open, whose server never enables
/// extended CONNECT, so a profile-policy opening beside it takes the
/// policy's choice for an incapable session.
struct OpenPage {
    shutdown: oneshot::Sender<()>,
    driver: tokio::task::JoinHandle<TestResult<()>>,
}

impl OpenPage {
    /// Answers the page's GET to `/` and keeps serving the connection until
    /// [`Self::close`].
    async fn serve(stream: Server) -> TestResult<Self> {
        let mut connection = ::http2::server::handshake(stream).await?;
        let (request, mut respond) = connection
            .accept()
            .await
            .ok_or("connection closed before the page's request")??;
        assert_eq!(request.uri().path(), "/");
        respond.send_response(Response::builder().status(StatusCode::OK).body(())?, true)?;
        let (shutdown, closed) = oneshot::channel::<()>();
        let driver = tokio::spawn(async move {
            tokio::select! {
                () = async { while let Some(Ok(_)) = connection.accept().await {} } => {}
                _ = closed => {}
            }
            connection.graceful_shutdown();
            match std::future::poll_fn(|context| connection.poll_closed(context)).await {
                Ok(()) => Ok(()),
                Err(error) if error.get_io().is_some_and(tls_support::is_peer_gone) => Ok(()),
                Err(error) => Err(error.into()),
            }
        });
        Ok(Self { shutdown, driver })
    }

    /// Sends GOAWAY and waits until the client has closed the connection.
    async fn close(self) -> TestResult<()> {
        // The driver ends on its own once the client closes the connection.
        let _ = self.shutdown.send(());
        self.driver.await?
    }
}

/// Beside an HTTP/2 session that cannot carry a WebSocket, Firefox's policy
/// opens an Upgrade connection that offers only `http/1.1`. It resumes the
/// ticket the `h2` page connection was issued but offers no early data,
/// because the ticket's ALPN protocol is not in its offer.
#[tokio::test]
async fn a_firefox_upgrade_beside_an_incapable_session_resumes_without_early_data() -> TestResult<()>
{
    bounded(async {
        let identity = TestIdentity::generate()?;
        let hellos = Hellos::default();
        let acceptor = acceptor(&identity, &hellos, H2_THEN_HTTP1)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let page = OpenPage::serve(accept(&listener, &acceptor, Duration::ZERO).await?).await?;
            let socket = accept(&listener, &acceptor, Duration::ZERO).await?;
            assert!(socket.stream.ssl().session_reused());
            serve_upgrade(socket, "/socket").await?;
            page.close().await
        });

        let client = firefox_client(&identity)?;
        get(&client, None, &format!("https://{address}/")).await?;
        let socket = client
            .websocket_with_profile_policy(&format!("wss://{address}/socket"))?
            .connect()
            .await?;
        drop(socket);
        drop(client);

        server.await??;
        assert_eq!(
            hellos.take(),
            [
                hello(false, false, &["h2", "http/1.1"]),
                hello(true, false, &["http/1.1"]),
            ]
        );
        Ok(())
    })
    .await
}

/// Two such Upgrades use the `h2` page connection's two tickets, so the
/// tickets of the earliest connection left are those the first Upgrade's
/// `http/1.1` connection was issued. A later negotiated request resumes one
/// and sends its GET as early data under `http/1.1`; a server that selects
/// `h2` rejects the early data, and the request starts again on a full
/// handshake, as after any such ALPN change.
#[tokio::test]
async fn a_negotiated_request_after_a_firefox_upgrade_restarts_on_an_alpn_change() -> TestResult<()>
{
    bounded(async {
        let identity = TestIdentity::generate()?;
        let hellos = Hellos::default();
        let acceptor = acceptor(&identity, &hellos, H2_THEN_HTTP1)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (page_closed, wait_for_page_close) = oneshot::channel();
        let server = tokio::spawn(async move {
            let page = OpenPage::serve(accept(&listener, &acceptor, Duration::ZERO).await?).await?;
            for _ in 0..2 {
                let socket = accept(&listener, &acceptor, Duration::ZERO).await?;
                assert!(socket.stream.ssl().session_reused());
                serve_upgrade(socket, "/socket").await?;
            }
            page.close().await?;
            page_closed
                .send(())
                .map_err(|_| "client stopped before the page's connection closed")?;

            let rejected = accept(&listener, &acceptor, SERVER_DELAY).await?;
            assert!(rejected.stream.ssl().session_reused());
            assert!(!rejected.stream.ssl().early_data_accepted());
            assert_eq!(
                rejected.stream.ssl().selected_alpn_protocol(),
                Some(&b"h2"[..])
            );
            drop(rejected);
            serve_http2(
                accept(&listener, &acceptor, Duration::ZERO).await?,
                "/later",
            )
            .await
        });

        let client = firefox_client(&identity)?;
        get(&client, None, &format!("https://{address}/")).await?;
        for _ in 0..2 {
            let socket = client
                .websocket_with_profile_policy(&format!("wss://{address}/socket"))?
                .connect()
                .await?;
            drop(socket);
        }
        if wait_for_page_close.await.is_err() {
            server.await??;
            return Err("server stopped before closing the page's connection".into());
        }
        get(&client, None, &format!("https://{address}/later")).await?;
        drop(client);

        server.await??;
        assert_eq!(
            hellos.take(),
            [
                hello(false, false, &["h2", "http/1.1"]),
                hello(true, false, &["http/1.1"]),
                hello(true, false, &["http/1.1"]),
                hello(true, true, &["h2", "http/1.1"]),
                hello(false, false, &["h2", "http/1.1"]),
            ]
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
            let Ok(mut upstream) = tokio::net::TcpStream::connect(origin).await else {
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

/// Through an HTTP proxy, the tunnelled origin connection of an opening
/// shares the tickets of the origin's pool key for that route.
#[tokio::test]
async fn a_chromium_upgrade_through_a_proxy_resumes_the_ticket_of_a_proxied_request()
-> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let hellos = Hellos::default();
        let acceptor = acceptor(&identity, &hellos, H2_THEN_HTTP1)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(tunnel_every_connect(proxy_listener, address));
        let (page_closed, wait_for_page_close) = oneshot::channel();
        let server = tokio::spawn(async move {
            serve_http2(accept(&listener, &acceptor, Duration::ZERO).await?, "/").await?;
            page_closed
                .send(())
                .map_err(|_| "client stopped before the page's connection closed")?;

            let socket = accept(&listener, &acceptor, Duration::ZERO).await?;
            assert!(socket.stream.ssl().session_reused());
            serve_upgrade(socket, "/socket").await
        });

        let profile = ClientProfile::new(chromium::v154_tls())
            .with_http1(chromium::v154_http1())
            .with_http2(chromium::v154_http2())
            .with_websocket(chromium::v154_websocket());
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .route(Route::http_proxy(HttpProxy::new(&format!(
                "http://{proxy_address}"
            ))?))
            .build()?;
        get(&client, None, &format!("https://{address}/")).await?;
        if wait_for_page_close.await.is_err() {
            server.await??;
            return Err("server stopped before closing the page's connection".into());
        }
        let socket = client
            .websocket_with_profile_policy(&format!("wss://{address}/socket"))?
            .connect()
            .await?;
        drop(socket);
        drop(client);

        server.await??;
        proxy.abort();
        assert_eq!(
            hellos.take(),
            [
                hello(false, false, &["h2", "http/1.1"]),
                hello(true, false, &["http/1.1"]),
            ]
        );
        Ok(())
    })
    .await
}
