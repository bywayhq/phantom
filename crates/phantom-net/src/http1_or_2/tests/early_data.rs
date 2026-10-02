//! Early data on direct negotiated connections with the Firefox recipe: which
//! requests travel as early data, and what the server receives after it
//! accepts or rejects them.

use std::{
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use btls::ssl::{AlpnError, ExtensionType, SelectCertError, Ssl, SslAcceptor, select_next_proto};
use bytes::Bytes;
use http::{Method, Response};
use http_body_util::BodyExt as _;
use phantom_profile::firefox;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

use crate::{
    http1_or_2::{Http1Or2Connection, Http1Or2TlsConnector},
    proxy::HttpConnectHeader,
    request::{OriginForm, RequestHeader},
    tls::test_support::{
        EarlyDataServerStream, TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult,
        TestServerAlpn, accept_tls_with_early_data, loopback_listener,
    },
};

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const H2_HEADERS: u8 = 0x1;

/// Long enough that the client's early data is on the wire before the server
/// answers its ClientHello.
const SERVER_DELAY: Duration = Duration::from_millis(200);

/// How the server treats one connection.
#[derive(Clone, Copy)]
struct Serve {
    accept_early_data: bool,
    delay: Duration,
}

/// The first connection only issues tickets; later ones resume.
const FIRST: Serve = Serve {
    accept_early_data: true,
    delay: Duration::ZERO,
};
const ACCEPT: Serve = Serve {
    accept_early_data: true,
    delay: SERVER_DELAY,
};
const REJECT: Serve = Serve {
    accept_early_data: false,
    delay: SERVER_DELAY,
};

/// What the server saw on one connection.
#[derive(Debug)]
struct Observed {
    /// The request head and body bytes for HTTP/1.1, or the method for H2.
    request: Vec<u8>,
    /// The application bytes read as early data.
    early: Vec<u8>,
    early_data_accepted: bool,
    session_reused: bool,
    /// Bytes the client sent after the request, before closing.
    trailing: Vec<u8>,
}

#[tokio::test]
async fn http1_sends_a_get_as_early_data_and_holds_a_post_until_the_answer() -> TestResult<()> {
    let (connector, port, server) = start(TestServerAlpn::Http1, [FIRST, ACCEPT, ACCEPT]).await?;
    for method in [Method::GET, Method::GET, Method::POST] {
        send_http1(&connector, port, method).await?;
    }
    let [_, get, post] = observed(server).await?;

    assert!(get.request.starts_with(b"GET / HTTP/1.1\r\n"));
    assert_eq!(get.early, get.request);
    assert!(get.early_data_accepted);
    assert!(get.session_reused);
    assert!(get.trailing.is_empty());

    // Firefox offers early data and sends none for a POST.
    assert!(post.request.starts_with(b"POST / HTTP/1.1\r\n"));
    assert!(post.request.ends_with(b"\r\n\r\nx"));
    assert!(post.early.is_empty());
    assert!(post.early_data_accepted);
    assert!(post.session_reused);
    assert!(post.trailing.is_empty());
    Ok(())
}

#[tokio::test]
async fn http1_sends_a_rejected_get_once_more_on_the_same_connection() -> TestResult<()> {
    let (connector, port, server) = start(TestServerAlpn::Http1, [FIRST, REJECT]).await?;
    for method in [Method::GET, Method::GET] {
        send_http1(&connector, port, method).await?;
    }
    let [_, get] = observed(server).await?;

    assert!(get.request.starts_with(b"GET / HTTP/1.1\r\n"));
    assert!(get.early.is_empty());
    assert!(!get.early_data_accepted);
    assert!(get.session_reused);
    // One copy of the request, and nothing after it.
    assert!(get.trailing.is_empty());
    Ok(())
}

#[tokio::test]
async fn http2_sends_the_preface_and_a_get_as_early_data_and_holds_a_post() -> TestResult<()> {
    let (connector, port, server) = start(TestServerAlpn::H2, [FIRST, ACCEPT, ACCEPT]).await?;
    for method in [Method::GET, Method::GET, Method::POST] {
        send_http2(&connector, port, method).await?;
    }
    let [_, get, post] = observed(server).await?;

    assert_eq!(get.request, b"GET");
    assert!(get.early.starts_with(H2_PREFACE));
    assert!(h2_frame_types(&get.early)?.contains(&H2_HEADERS));
    assert!(get.early_data_accepted);

    // The preface and SETTINGS go out as early data, the POST after it.
    assert_eq!(post.request, b"POST");
    assert!(post.early.starts_with(H2_PREFACE));
    assert!(!h2_frame_types(&post.early)?.is_empty());
    assert!(!h2_frame_types(&post.early)?.contains(&H2_HEADERS));
    assert!(post.early_data_accepted);
    Ok(())
}

#[tokio::test]
async fn http2_sends_a_rejected_get_once_more_on_the_same_connection() -> TestResult<()> {
    let (connector, port, server) = start(TestServerAlpn::H2, [FIRST, REJECT]).await?;
    for method in [Method::GET, Method::GET] {
        send_http2(&connector, port, method).await?;
    }
    let [_, get] = observed(server).await?;

    // The server decoded the resent preface, SETTINGS, and HEADERS.
    assert_eq!(get.request, b"GET");
    assert!(get.early.is_empty());
    assert!(!get.early_data_accepted);
    assert!(get.session_reused);
    Ok(())
}

/// Firefox disables early data on every proxy connection
/// (`TlsHandshaker::InitSSLParams`,
/// `netwerk/protocol/http/TlsHandshaker.cpp:134-137` at tag
/// `FIREFOX_157_0_RELEASE`). The ticket learned directly permits early data,
/// and the connection through a CONNECT tunnel resumes it without offering
/// any.
#[tokio::test]
async fn a_connection_through_a_proxy_offers_no_early_data() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = Http1Or2TlsConnector::new_with_additional_roots(
        &firefox::v157_tls(),
        &firefox::v157_http2(),
        [identity.root_der()],
    )?
    .with_isolated_session_cache();
    let offers = Arc::new(Mutex::new(Vec::new()));
    let mut acceptor = identity.acceptor_builder()?;
    let recorded = Arc::clone(&offers);
    acceptor.set_select_certificate_callback(move |hello| {
        recorded
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(hello.get_extension(ExtensionType::EARLY_DATA).is_some());
        Ok::<_, SelectCertError>(())
    });
    acceptor.set_alpn_select_callback(|_, offered| {
        select_next_proto(b"\x08http/1.1", offered).ok_or(AlpnError::NOACK)
    });
    let acceptor = acceptor.build();
    let (address, listener) = loopback_listener().await?;
    let server = tokio::spawn(async move {
        let direct = accept_tls_with_early_data(&listener, &acceptor, true, Duration::ZERO).await?;
        serve_http1(direct).await?;

        // The same listener plays the proxy, then the origin in the tunnel.
        let (mut tcp, _) = listener.accept().await?;
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            tcp.read_exact(&mut byte).await?;
            head.push(byte[0]);
        }
        tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        let mut ssl = Ssl::new(acceptor.context())?;
        ssl.set_early_data_enabled(true);
        let mut tunnelled = tokio_btls::SslStream::new(ssl, tcp)?;
        Pin::new(&mut tunnelled).accept().await?;
        let resumed = tunnelled.ssl().session_reused();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            tunnelled.read_exact(&mut byte).await?;
            request.push(byte[0]);
        }
        tunnelled
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await?;
        tunnelled.flush().await?;
        let _ = tunnelled.read_to_end(&mut Vec::new()).await;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((head, resumed))
    });

    send_http1(&connector, address.port(), Method::GET).await?;
    let authority = format!("{TEST_SERVER_NAME}:{}", address.port());
    let connection = tokio::time::timeout(
        TEST_TIMEOUT,
        connector.connect_http_connect(
            "127.0.0.1",
            address.port(),
            &authority,
            &[HttpConnectHeader::authority("Host")],
            TEST_SERVER_NAME,
        ),
    )
    .await??;
    let Http1Or2Connection::Http1(connection) = connection else {
        return Err("the tunnelled origin did not select HTTP/1.1".into());
    };
    let response = tokio::time::timeout(
        TEST_TIMEOUT,
        connection.send_request(
            Method::GET,
            OriginForm::parse("/")?,
            vec![RequestHeader::new("host", authority.as_str())],
            None,
        ),
    )
    .await??;
    response.into_body().collect().await?;
    drop(connection);

    let (head, resumed) = tokio::time::timeout(TEST_TIMEOUT, server).await???;
    assert!(head.starts_with(b"CONNECT "));
    assert!(resumed);
    assert_eq!(
        *offers.lock().unwrap_or_else(PoisonError::into_inner),
        [false, false]
    );
    Ok(())
}

type Started<const N: usize> = (
    Http1Or2TlsConnector,
    u16,
    JoinHandle<TestResult<[Observed; N]>>,
);

/// Starts a server for `connections`, one after another, and returns a
/// Firefox-recipe connector that trusts it.
async fn start<const N: usize>(
    alpn: TestServerAlpn,
    connections: [Serve; N],
) -> TestResult<Started<N>> {
    let identity = TestIdentity::generate()?;
    let connector = Http1Or2TlsConnector::new_with_additional_roots(
        &firefox::v157_tls(),
        &firefox::v157_http2(),
        [identity.root_der()],
    )?
    .with_isolated_session_cache();
    let acceptor = identity.acceptor(alpn)?;
    let (address, listener) = loopback_listener().await?;
    let server = tokio::spawn(serve(listener, acceptor, alpn, connections));
    Ok((connector, address.port(), server))
}

async fn serve<const N: usize>(
    listener: TcpListener,
    acceptor: SslAcceptor,
    alpn: TestServerAlpn,
    connections: [Serve; N],
) -> TestResult<[Observed; N]> {
    let mut observed = Vec::with_capacity(N);
    for connection in connections {
        let stream = accept_tls_with_early_data(
            &listener,
            &acceptor,
            connection.accept_early_data,
            connection.delay,
        )
        .await?;
        let early_data_accepted = stream.early_data_accepted();
        let session_reused = stream.session_reused();
        let early = stream.early_bytes();
        let (request, trailing) = match alpn {
            TestServerAlpn::H2 => serve_http2(stream).await?,
            _ => serve_http1(stream).await?,
        };
        let early = early.lock().unwrap_or_else(PoisonError::into_inner).clone();
        observed.push(Observed {
            request,
            early,
            early_data_accepted,
            session_reused,
            trailing,
        });
    }
    observed
        .try_into()
        .map_err(|_| "the server observed the wrong number of connections".into())
}

/// Reads one request, answers `200`, and returns the request and whatever
/// the client sent after it before closing.
async fn serve_http1(mut stream: EarlyDataServerStream) -> TestResult<(Vec<u8>, Vec<u8>)> {
    let mut request = Vec::new();
    let mut byte = [0_u8; 1];
    while !request.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await?;
        request.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&request).to_ascii_lowercase();
    let body_length = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .map(|value| value.trim().parse::<usize>())
        .transpose()?
        .unwrap_or(0);
    let mut body = vec![0_u8; body_length];
    stream.read_exact(&mut body).await?;
    request.extend_from_slice(&body);
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        .await?;
    stream.flush().await?;
    let mut trailing = Vec::new();
    let _ = stream.read_to_end(&mut trailing).await;
    Ok((request, trailing))
}

/// Accepts one stream, answers `200`, and returns its method.
async fn serve_http2(stream: EarlyDataServerStream) -> TestResult<(Vec<u8>, Vec<u8>)> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("the connection closed before a request")??;
    let method = request.method().as_str().as_bytes().to_vec();
    let answer = async move {
        let mut body = request.into_body();
        while let Some(chunk) = body.data().await {
            let chunk = chunk?;
            body.flow_control().release_capacity(chunk.len())?;
        }
        respond.send_response(Response::builder().status(200).body(())?, true)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    // The connection must be polled while the body is read; it then runs
    // until the client closes.
    let (answered, next) = tokio::join!(answer, connection.accept());
    answered?;
    if next.is_some() {
        return Err("the client opened a second stream".into());
    }
    Ok((method, Vec::new()))
}

async fn send_http1(connector: &Http1Or2TlsConnector, port: u16, method: Method) -> TestResult<()> {
    let Http1Or2Connection::Http1(connection) = connect(connector, port).await? else {
        return Err("the server did not select HTTP/1.1".into());
    };
    let body = (method == Method::POST).then(|| Bytes::from_static(b"x"));
    let headers = vec![RequestHeader::new(
        "host",
        format!("{TEST_SERVER_NAME}:{port}"),
    )];
    let response = tokio::time::timeout(
        TEST_TIMEOUT,
        connection.send_request(method, OriginForm::parse("/")?, headers, body),
    )
    .await??;
    assert_eq!(response.status(), 200);
    response.into_body().collect().await?;
    Ok(())
}

async fn send_http2(connector: &Http1Or2TlsConnector, port: u16, method: Method) -> TestResult<()> {
    let Http1Or2Connection::Http2(connection) = connect(connector, port).await? else {
        return Err("the server did not select HTTP/2".into());
    };
    let body = (method == Method::POST).then(|| Bytes::from_static(b"x"));
    let authority = format!("{TEST_SERVER_NAME}:{port}");
    let response = tokio::time::timeout(
        TEST_TIMEOUT,
        connection.send_request(
            method,
            &authority,
            OriginForm::parse("/")?,
            Vec::new(),
            body,
        ),
    )
    .await??;
    assert_eq!(response.status(), 200);
    response.into_body().collect().await?;
    Ok(())
}

async fn connect(connector: &Http1Or2TlsConnector, port: u16) -> TestResult<Http1Or2Connection> {
    Ok(tokio::time::timeout(
        TEST_TIMEOUT,
        connector.connect_direct("127.0.0.1", port, TEST_SERVER_NAME),
    )
    .await??)
}

async fn observed<const N: usize>(
    server: JoinHandle<TestResult<[Observed; N]>>,
) -> TestResult<[Observed; N]> {
    tokio::time::timeout(TEST_TIMEOUT, server).await??
}

/// Returns the type of every frame after the client preface, including a
/// last frame whose payload the early data does not hold in full.
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
