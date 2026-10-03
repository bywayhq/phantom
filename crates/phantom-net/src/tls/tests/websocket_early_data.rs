//! Early data on direct WebSocket openings with the Firefox recipe, as the
//! Firefox 157 `resumption-websocket.txt` and
//! `resumption-websocket-http1.txt` captures show: an HTTP/1.1 Upgrade GET
//! travels as early data, and over HTTP/2 only the preface, SETTINGS, and
//! WINDOW_UPDATE do.

use std::{
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use btls::ssl::{AlpnError, ExtensionType, SelectCertError, SslAcceptor, select_next_proto};

use bytes::Bytes;
use http::{Method, Response, StatusCode};
use phantom_profile::firefox;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    http1::{Http1TlsConnector, Http1TlsError, Http1UpgradeOutcome},
    http2::{Http2ExtendedConnectOutcome, Http2TlsConnector, Http2TlsError},
    request::{OriginForm, RequestHeader},
    tls::{
        TlsError, TlsErrorKind,
        test_support::{
            EarlyDataServerStream, TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult,
            TestServerAlpn, accept_tls_with_early_data,
        },
    },
};

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const H2_SETTINGS: u8 = 0x4;
const H2_WINDOW_UPDATE: u8 = 0x8;
/// Long enough that the client's early data is on the wire before the server
/// answers its ClientHello.
const SERVER_DELAY: Duration = Duration::from_millis(200);

/// How the server answers the second opening, which presents the ticket the
/// first was issued.
#[derive(Clone, Copy)]
enum Second {
    /// Resumes and accepts the early data.
    Accept,
    /// Resumes and rejects the early data.
    Reject,
    /// Cannot resume the ticket, so rejects the early data, and selects
    /// another ALPN protocol.
    SelectAlpn(TestServerAlpn),
    /// Cannot resume the ticket and presents an untrusted certificate.
    Untrusted,
}

/// What the server saw on the second connection.
struct Observed {
    /// The Upgrade GET head, or the extended CONNECT's `:protocol`.
    request: Vec<u8>,
    /// The application bytes read as early data.
    early: Vec<u8>,
    early_data_accepted: bool,
    session_reused: bool,
}

#[tokio::test]
async fn a_resumed_http1_websocket_opening_sends_its_upgrade_get_as_early_data() -> TestResult<()> {
    let (result, observed, offers) = http1_openings(Second::Accept).await?;
    assert_eq!(result?, StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(offers, [false, true]);
    let observed = observed.ok_or("the server did not serve the second opening")?;
    assert!(observed.request.starts_with(b"GET /socket HTTP/1.1\r\n"));
    assert_eq!(observed.early, observed.request);
    assert!(observed.early_data_accepted);
    assert!(observed.session_reused);
    Ok(())
}

/// After a rejection the connection finishes the handshake and sends the
/// Upgrade GET once more; the server reads one copy.
#[tokio::test]
async fn a_rejected_http1_websocket_opening_is_sent_once_more_on_the_same_connection()
-> TestResult<()> {
    let (result, observed, offers) = http1_openings(Second::Reject).await?;
    assert_eq!(result?, StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(offers, [false, true]);
    let observed = observed.ok_or("the server did not serve the second opening")?;
    assert!(observed.request.starts_with(b"GET /socket HTTP/1.1\r\n"));
    assert!(observed.early.is_empty());
    assert!(!observed.early_data_accepted);
    assert!(observed.session_reused);
    Ok(())
}

#[tokio::test]
async fn an_http1_websocket_opening_reports_a_handshake_failure_after_early_data() -> TestResult<()>
{
    let (result, _, offers) = http1_openings(Second::Untrusted).await?;
    assert_eq!(offers, [false, true]);
    match result {
        Err(Http1TlsError::Tls(error)) => assert_failed_after_early_data(&error),
        other => Err(format!("expected a TLS error, got {other:?}").into()),
    }
}

/// The server rejects the early data sent under `http/1.1` and selects `h2`,
/// which the opening reports as a fresh connection that selects `h2` does.
#[tokio::test]
async fn an_http1_websocket_opening_reports_an_alpn_change_after_early_data() -> TestResult<()> {
    let (result, _, offers) = http1_openings(Second::SelectAlpn(TestServerAlpn::H2)).await?;
    assert_eq!(offers, [false, true]);
    match result {
        Err(Http1TlsError::UnsupportedAlpn { selected }) => {
            assert_eq!(&*selected, b"h2");
            Ok(())
        }
        other => Err(format!("expected an unsupported ALPN error, got {other:?}").into()),
    }
}

#[tokio::test]
async fn a_resumed_http2_websocket_opening_holds_its_connect_until_the_answer() -> TestResult<()> {
    let (result, observed, offers) = http2_openings(Second::Accept).await?;
    assert_eq!(result?, StatusCode::OK);
    assert_eq!(offers, [false, true]);
    let observed = observed.ok_or("the server did not serve the second opening")?;
    assert_eq!(observed.request, b"websocket");
    assert_eq!(
        h2_frame_types(&observed.early)?,
        [H2_SETTINGS, H2_WINDOW_UPDATE]
    );
    assert!(observed.early_data_accepted);
    assert!(observed.session_reused);
    Ok(())
}

/// After a rejection the connection sends its preface and SETTINGS once
/// more, then the extended CONNECT; the server decodes one copy.
#[tokio::test]
async fn a_rejected_http2_websocket_opening_resends_its_preface_on_the_same_connection()
-> TestResult<()> {
    let (result, observed, offers) = http2_openings(Second::Reject).await?;
    assert_eq!(result?, StatusCode::OK);
    assert_eq!(offers, [false, true]);
    let observed = observed.ok_or("the server did not serve the second opening")?;
    assert_eq!(observed.request, b"websocket");
    assert!(observed.early.is_empty());
    assert!(!observed.early_data_accepted);
    assert!(observed.session_reused);
    Ok(())
}

#[tokio::test]
async fn an_http2_websocket_opening_reports_a_handshake_failure_after_early_data() -> TestResult<()>
{
    let (result, _, offers) = http2_openings(Second::Untrusted).await?;
    assert_eq!(offers, [false, true]);
    match result {
        Err(Http2TlsError::Tls(error)) => assert_failed_after_early_data(&error),
        other => Err(format!("expected a TLS error, got {other:?}").into()),
    }
}

/// The server rejects the early data sent under `h2` and selects
/// `http/1.1`, which the opening reports as a fresh connection that selects
/// `http/1.1` does.
#[tokio::test]
async fn an_http2_websocket_opening_reports_an_alpn_change_after_early_data() -> TestResult<()> {
    let (result, _, offers) = http2_openings(Second::SelectAlpn(TestServerAlpn::Http1)).await?;
    assert_eq!(offers, [false, true]);
    match result {
        Err(Http2TlsError::UnsupportedAlpn { selected }) => {
            assert_eq!(&*selected, b"http/1.1");
            Ok(())
        }
        other => Err(format!("expected an unsupported ALPN error, got {other:?}").into()),
    }
}

/// Returns the response status and drops the stream, which closes it.
fn status(outcome: Http2ExtendedConnectOutcome) -> StatusCode {
    match outcome {
        Http2ExtendedConnectOutcome::Accepted { response, .. } => response.status(),
        Http2ExtendedConnectOutcome::Rejected(response) => response.status(),
    }
}

fn assert_failed_after_early_data(error: &TlsError) -> TestResult<()> {
    assert_eq!(error.kind(), TlsErrorKind::Handshake);
    assert_eq!(error.to_string(), "TLS handshake failed after early data");
    Ok(())
}

/// The second opening's response status or error, and what the server saw
/// when it served the opening.
/// Whether each ClientHello the server saw offered early data, in order.
type Offers = Arc<Mutex<Vec<bool>>>;

type Openings<E> = (Result<StatusCode, E>, Option<Observed>, Vec<bool>);

/// Opens two WebSockets over HTTP/1.1; the second presents the first's
/// ticket to a server that answers as `second` says. Returns the second
/// opening's result and, when the server served it, what it saw.
async fn http1_openings(second: Second) -> TestResult<Openings<Http1TlsError>> {
    let identity = TestIdentity::generate()?;
    let connector =
        Http1TlsConnector::new_with_additional_roots(&firefox::v157_tls(), [identity.root_der()])?
            .with_isolated_session_cache();
    let server = serve_two(identity, TestServerAlpn::Http1, second, serve_upgrade)?;
    let port = server.port;

    let host = format!("{TEST_SERVER_NAME}:{port}");
    let target = OriginForm::parse("/socket")?;
    let open = || {
        connector.upgrade_get_direct(
            "127.0.0.1",
            port,
            TEST_SERVER_NAME,
            target.clone(),
            vec![
                RequestHeader::new("Host", host.as_str()),
                RequestHeader::new("Connection", "Upgrade"),
                RequestHeader::new("Upgrade", "websocket"),
                RequestHeader::new("Sec-WebSocket-Version", "13"),
                RequestHeader::new("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ],
        )
    };
    let first = tokio::time::timeout(TEST_TIMEOUT, open()).await??;
    let Http1UpgradeOutcome::Upgraded(response) = first else {
        return Err("the server did not switch protocols".into());
    };
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    drop(response);
    // The status alone, so the upgraded stream closes before the server is
    // awaited.
    let result = tokio::time::timeout(TEST_TIMEOUT, open())
        .await?
        .map(|outcome| match outcome {
            Http1UpgradeOutcome::Upgraded(response) => response.status(),
            Http1UpgradeOutcome::Rejected(response) => response.status(),
        });
    let (observed, offers) = server.finish().await?;
    Ok((result, observed, offers))
}

/// Opens two WebSockets over HTTP/2 extended CONNECT, as
/// [`http1_openings`] does over HTTP/1.1.
async fn http2_openings(second: Second) -> TestResult<Openings<Http2TlsError>> {
    let identity = TestIdentity::generate()?;
    let connector = Http2TlsConnector::new_with_additional_roots(
        &firefox::v157_tls(),
        &firefox::v157_http2(),
        [identity.root_der()],
    )?
    .with_isolated_session_cache();
    let server = serve_two(identity, TestServerAlpn::H2, second, serve_extended_connect)?;
    let port = server.port;

    let authority = format!("{TEST_SERVER_NAME}:{port}");
    let target = OriginForm::parse("/socket")?;
    let open = || {
        connector.send_extended_connect_direct(
            "127.0.0.1",
            port,
            TEST_SERVER_NAME,
            &authority,
            target.clone(),
            vec![RequestHeader::new("sec-websocket-version", "13")],
        )
    };
    let first = tokio::time::timeout(TEST_TIMEOUT, open()).await??;
    assert_eq!(status(first), StatusCode::OK);
    let result = tokio::time::timeout(TEST_TIMEOUT, open())
        .await?
        .map(status);
    let (observed, offers) = server.finish().await?;
    Ok((result, observed, offers))
}

/// A server for two connections, the second answered as [`Second`] says.
struct TwoConnections {
    port: u16,
    offers: Offers,
    task: tokio::task::JoinHandle<TestResult<Option<Observed>>>,
}

impl TwoConnections {
    async fn finish(self) -> TestResult<(Option<Observed>, Vec<bool>)> {
        let observed = tokio::time::timeout(TEST_TIMEOUT, self.task).await???;
        let offers = self
            .offers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        Ok((observed, offers))
    }
}

/// Builds an acceptor that selects `alpn` and records whether each
/// ClientHello offered early data.
fn recording_acceptor(
    identity: &TestIdentity,
    alpn: TestServerAlpn,
    offers: &Offers,
) -> TestResult<SslAcceptor> {
    let mut acceptor = identity.acceptor_builder()?;
    let wire: &'static [u8] = match alpn {
        TestServerAlpn::None => b"",
        TestServerAlpn::Http1 => b"\x08http/1.1",
        TestServerAlpn::H2 => b"\x02h2",
    };
    acceptor.set_alpn_select_callback(move |_, offered| {
        select_next_proto(wire, offered).ok_or(AlpnError::NOACK)
    });
    let offers = Arc::clone(offers);
    acceptor.set_select_certificate_callback(move |hello| {
        offers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(hello.get_extension(ExtensionType::EARLY_DATA).is_some());
        Ok::<_, SelectCertError>(())
    });
    Ok(acceptor.build())
}

fn serve_two<F, Fut>(
    identity: TestIdentity,
    alpn: TestServerAlpn,
    second: Second,
    serve: F,
) -> TestResult<TwoConnections>
where
    F: Fn(EarlyDataServerStream) -> Fut + Send + 'static,
    Fut: Future<Output = TestResult<Vec<u8>>> + Send,
{
    let offers = Offers::default();
    let acceptor = recording_acceptor(&identity, alpn, &offers)?;
    // A new context holds new ticket keys, so it cannot resume the ticket.
    let (other, accept_early_data) = match second {
        Second::Accept => (acceptor.clone(), true),
        Second::Reject => (acceptor.clone(), false),
        Second::SelectAlpn(alpn) => (recording_acceptor(&identity, alpn, &offers)?, false),
        Second::Untrusted => (
            recording_acceptor(&TestIdentity::generate()?, alpn, &offers)?,
            false,
        ),
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let task = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener)?;
        let first = accept_tls_with_early_data(&listener, &acceptor, true, Duration::ZERO).await?;
        serve(first).await?;
        let stream =
            accept_tls_with_early_data(&listener, &other, accept_early_data, SERVER_DELAY).await;
        if matches!(second, Second::Accept | Second::Reject) {
            return Ok(Some(observe(stream?, serve).await?));
        }
        // The client fails the connection; it sends nothing the server
        // processes.
        if let Ok(mut failed) = stream {
            let mut unprocessed = Vec::new();
            let _ = failed.read_to_end(&mut unprocessed).await;
            if !unprocessed.is_empty() {
                return Err(format!("the server read {} bytes", unprocessed.len()).into());
            }
        }
        Ok(None)
    });
    Ok(TwoConnections { port, offers, task })
}

/// Serves `stream` with `serve` and records what it read as early data.
async fn observe<F, Fut>(stream: EarlyDataServerStream, serve: F) -> TestResult<Observed>
where
    F: FnOnce(EarlyDataServerStream) -> Fut,
    Fut: Future<Output = TestResult<Vec<u8>>>,
{
    let early_data_accepted = stream.early_data_accepted();
    let session_reused = stream.session_reused();
    let early = stream.early_bytes();
    let request = serve(stream).await?;
    let early = early.lock().unwrap_or_else(PoisonError::into_inner).clone();
    Ok(Observed {
        request,
        early,
        early_data_accepted,
        session_reused,
    })
}

/// Reads one Upgrade GET, answers `101`, and reads until the client closes
/// the connection, which must send nothing more. Returns the request head.
async fn serve_upgrade(mut stream: EarlyDataServerStream) -> TestResult<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await?;
        head.push(byte[0]);
    }
    stream
        .write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        )
        .await?;
    stream.flush().await?;
    let mut trailing = Vec::new();
    let _ = stream.read_to_end(&mut trailing).await;
    if !trailing.is_empty() {
        return Err(format!("the client sent {} more bytes", trailing.len()).into());
    }
    Ok(head)
}

/// Accepts one extended CONNECT, answers `200`, and holds the stream open
/// until the client closes the connection. Returns its `:protocol`.
async fn serve_extended_connect(stream: EarlyDataServerStream) -> TestResult<Vec<u8>> {
    let mut builder = ::http2::server::Builder::new();
    builder.enable_connect_protocol();
    let mut connection = builder.handshake::<_, Bytes>(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("the connection closed before the extended CONNECT")??;
    if request.method() != Method::CONNECT {
        return Err("the client sent another method than CONNECT".into());
    }
    let protocol = request
        .extensions()
        .get::<::http2::ext::Protocol>()
        .map(|protocol| protocol.as_str().as_bytes().to_vec())
        .unwrap_or_default();
    let _send =
        respond.send_response(Response::builder().status(StatusCode::OK).body(())?, false)?;
    // The client closes the connection once it drops the stream.
    let _ = std::future::poll_fn(|context| connection.poll_closed(context)).await;
    drop(request);
    Ok(protocol)
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
