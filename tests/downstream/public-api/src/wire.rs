//! Exercise the public harness against real plaintext HTTP/1 requests.

use std::{error::Error, fmt, net::Ipv4Addr, time::Duration};

use phantom::{
    Client, HttpProtocol, StatusCode,
    profile::{
        ClientProfile,
        browser::{chrome, firefox},
    },
};
use phantom_testkit::http1::{
    CaptureError, CaptureLimits, RequestHeadCapture, capture_request_head,
    expectation::{AdjustableHeader, RequestExpectation},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::{Instant, timeout, timeout_at},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const CHROME: &str = include_str!("../fixtures/http1/chrome-154-windows-h1-accept.txt");
const FIREFOX: &str = include_str!("../fixtures/http1/firefox-157-windows-h1-accept.txt");
const TARGET: &str = "/ws.html?run=local-wire-check";
const CHROME_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36";

#[tokio::test]
async fn chrome_navigation_matches_retained_header_bytes() -> TestResult {
    let profile = ClientProfile::new(chrome::v154_tcp_tls())
        .with_tcp(chrome::v154_tcp())
        .with_http1(chrome::v154_http1())
        .with_client_hints(chrome::v154_windows_client_hints())
        .with_request_template(chrome::v154_windows_navigation_template());
    check_navigation(profile, CHROME, "Google Chrome", "154.0.8037.58", Some(6)).await
}

#[tokio::test]
async fn firefox_navigation_matches_retained_header_bytes() -> TestResult {
    let profile = ClientProfile::new(firefox::v157_tcp_tls())
        .with_tcp(firefox::v157_tcp())
        .with_http1(firefox::v157_http1())
        .with_request_template(firefox::v157_windows_navigation_template());
    check_navigation(profile, FIREFOX, "Mozilla Firefox", "157.0", None).await
}

async fn check_navigation(
    profile: ClientProfile,
    fixture: &str,
    browser: &str,
    build: &str,
    user_agent_index: Option<usize>,
) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut peer = None;
    let primary = timeout_at(deadline, async {
        let limits = CaptureLimits::new(32_768, 8_192, 128);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let authority = listener.local_addr()?.to_string();
        let mut expected = RequestExpectation::from_retained(fixture, 0, 0, 65_536, limits)?;
        assert_eq!(expected.metadata().browser(), browser);
        assert_eq!(expected.metadata().build(), build);
        assert_eq!(
            expected.metadata().platform(),
            "Windows 11 Home 10.0.26200 x64"
        );
        assert_eq!(expected.metadata().launch_mode(), "headless");
        assert_eq!(expected.metadata().scenario(), "h1-accept");
        assert_eq!(expected.metadata().request_kind(), "page");
        expected.replace_target(TARGET.as_bytes())?;
        expected.replace_header_value(
            0,
            AdjustableHeader::Host,
            format!(" {authority}").as_bytes(),
        )?;
        // This capture used headless Chrome. The ordinary Windows recipe has
        // a different User-Agent; declare that one value change explicitly.
        if let Some(index) = user_agent_index {
            expected.replace_header_value(
                index,
                AdjustableHeader::UserAgent,
                format!(" {CHROME_USER_AGENT}").as_bytes(),
            )?;
        }
        peer = Some(WirePeer::new(tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            capture_stream(stream, deadline, limits).await
        })));
        let client = Client::builder(profile).build()?;
        let response = client
            .get(HttpProtocol::Http1, &format!("http://{authority}{TARGET}"))?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            response
                .into_body()
                .collect_with_limit(1_024)
                .await?
                .is_empty()
        );
        let actual = peer.as_mut().ok_or("wire peer missing")?.join().await?;
        expected.compare(&actual)?;
        check_negative_controls(&expected, &actual, limits)?;
        Ok(())
    })
    .await;
    let primary = match primary {
        Ok(result) => result,
        Err(elapsed) => Err(elapsed.into()),
    };
    match peer {
        Some(mut peer) => peer.finish(primary).await,
        None => primary,
    }
}

async fn capture_stream(
    stream: impl AsyncRead + AsyncWrite + Unpin,
    deadline: Instant,
    limits: CaptureLimits,
) -> TestResult<RequestHeadCapture> {
    let mut stream = BufReader::new(stream);
    let head = capture_request_head(&mut stream, deadline, limits).await?;
    stream
        .get_mut()
        .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
        .await?;
    Ok(head)
}

/// Retains the plaintext capture task when the consuming caller stops early.
struct WirePeer {
    task: Option<JoinHandle<TestResult<RequestHeadCapture>>>,
}

impl WirePeer {
    fn new(task: JoinHandle<TestResult<RequestHeadCapture>>) -> Self {
        Self { task: Some(task) }
    }

    async fn join(&mut self) -> TestResult<RequestHeadCapture> {
        let result = self
            .task
            .as_mut()
            .ok_or("wire peer already collected")?
            .await;
        self.task = None;
        result?
    }

    async fn stop(&mut self) -> TestResult {
        let Some(task) = self.task.as_mut() else {
            return Ok(());
        };
        let cancelled = !task.is_finished();
        if cancelled {
            task.abort();
        }
        let result = timeout(Duration::from_secs(5), task).await?;
        self.task = None;
        match result {
            Ok(result) => result.map(drop),
            Err(error) if cancelled && error.is_cancelled() => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    async fn finish<T>(&mut self, primary: TestResult<T>) -> TestResult<T> {
        let cleanup = self.stop().await;
        match (primary, cleanup) {
            (Err(primary), Err(cleanup)) => Err(Box::new(WireFailures { primary, cleanup })),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        }
    }
}

impl Drop for WirePeer {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

#[derive(Debug)]
struct WireFailures {
    primary: Box<dyn Error + Send + Sync>,
    cleanup: Box<dyn Error + Send + Sync>,
}

impl fmt::Display for WireFailures {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "wire caller failed: {}; peer cleanup failed: {}",
            self.primary, self.cleanup
        )
    }
}

impl Error for WireFailures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.primary.as_ref())
    }
}

fn check_negative_controls(
    expected: &RequestExpectation,
    actual: &RequestHeadCapture,
    limits: CaptureLimits,
) -> TestResult {
    let original: Vec<Vec<u8>> = actual
        .headers()
        .iter()
        .map(|field| field.bytes().to_vec())
        .collect();
    let mut reordered = original.clone();
    reordered.swap(1, 2);
    assert!(
        expected
            .compare(&mutant(actual, &reordered, limits)?)
            .is_err()
    );
    let mut changed_value = original.clone();
    changed_value[1].push(b'x');
    assert!(
        expected
            .compare(&mutant(actual, &changed_value, limits)?)
            .is_err()
    );
    let mut changed_case = original.clone();
    changed_case[0][0] = b'h';
    assert!(
        expected
            .compare(&mutant(actual, &changed_case, limits)?)
            .is_err()
    );
    assert!(
        expected
            .compare(&mutant(actual, &original[..original.len() - 1], limits)?)
            .is_err()
    );
    assert!(matches!(
        RequestHeadCapture::parse(&[], limits),
        Err(CaptureError::EmptyInput)
    ));
    assert!(matches!(
        RequestHeadCapture::parse(&actual.bytes()[..actual.bytes().len() - 1], limits),
        Err(CaptureError::TruncatedHead)
    ));
    Ok(())
}

fn mutant(
    actual: &RequestHeadCapture,
    headers: &[Vec<u8>],
    limits: CaptureLimits,
) -> TestResult<RequestHeadCapture> {
    let mut bytes = actual.request_line().to_vec();
    bytes.extend_from_slice(b"\r\n");
    for header in headers {
        bytes.extend_from_slice(header);
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"\r\n");
    Ok(RequestHeadCapture::parse(&bytes, limits)?)
}

mod peer_controls {
    use std::{
        io,
        net::SocketAddr,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll},
    };

    use tokio::{
        io::{AsyncReadExt, ReadBuf},
        task::yield_now,
        time::error::Elapsed,
    };

    use super::*;

    struct ObservedCapture {
        stream: TcpStream,
        read: Arc<AtomicBool>,
    }

    impl AsyncRead for ObservedCapture {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let before = buffer.filled().len();
            let result = Pin::new(&mut self.stream).poll_read(cx, buffer);
            if matches!(result, Poll::Ready(Ok(()))) && &buffer.filled()[before..] == b"G" {
                self.read.store(true, Ordering::SeqCst);
            }
            result
        }
    }

    impl AsyncWrite for ObservedCapture {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.stream).poll_write(cx, bytes)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_shutdown(cx)
        }
    }

    async fn blocked_capture() -> TestResult<(WirePeer, TcpStream, SocketAddr)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let read = Arc::new(AtomicBool::new(false));
        let observed = read.clone();
        let deadline = Instant::now() + Duration::from_secs(10);
        let limits = CaptureLimits::new(32_768, 8_192, 128);
        let peer = WirePeer::new(tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let stream = ObservedCapture {
                stream,
                read: observed,
            };
            capture_stream(stream, deadline, limits).await
        }));
        let mut client = TcpStream::connect(address).await?;
        client.write_all(b"G").await?;
        timeout(Duration::from_secs(2), async {
            while !read.load(Ordering::SeqCst) {
                yield_now().await;
            }
        })
        .await?;
        Ok((peer, client, address))
    }

    async fn retired(client: &mut TcpStream, address: SocketAddr) -> TestResult {
        let mut byte = [0];
        let read = timeout(Duration::from_secs(2), client.read(&mut byte)).await??;
        if read != 0 {
            return Err("capture socket did not reach EOF".into());
        }
        let rebound = TcpListener::bind(address).await?;
        assert_eq!(rebound.local_addr()?, address);
        Ok(())
    }

    #[tokio::test]
    async fn failed_caller_collects_the_actual_capture_socket_and_listener() -> TestResult {
        let (mut peer, mut client, address) = blocked_capture().await?;
        let backup = peer
            .task
            .as_ref()
            .ok_or("capture peer missing")?
            .abort_handle();
        let caller = Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "original caller",
        ));
        let original = std::ptr::from_ref(caller.as_ref());

        let result = async {
            let Err(error) = peer.finish::<()>(Err(caller)).await else {
                return Err("failed caller was accepted".into());
            };
            let retained = error
                .downcast_ref::<io::Error>()
                .ok_or("caller cause lost")?;
            assert!(std::ptr::eq(retained, original));
            retired(&mut client, address).await?;
            assert!(peer.task.is_none());
            Ok(())
        }
        .await;
        // Backup runs only after the actual retirement assertions above.
        backup.abort();
        result
    }

    #[tokio::test]
    async fn caller_deadline_keeps_elapsed_and_collects_the_actual_capture() -> TestResult {
        let (mut peer, mut client, address) = blocked_capture().await?;
        let backup = peer
            .task
            .as_ref()
            .ok_or("capture peer missing")?
            .abort_handle();
        let Err(elapsed) = timeout(Duration::ZERO, std::future::pending::<()>()).await else {
            return Err("pending caller completed".into());
        };
        let caller = Box::new(elapsed);
        let original = std::ptr::from_ref(caller.as_ref());

        let result = async {
            let Err(error) = peer.finish::<()>(Err(caller)).await else {
                return Err("expired caller was accepted".into());
            };
            let retained = error
                .downcast_ref::<Elapsed>()
                .ok_or("elapsed cause lost")?;
            assert!(std::ptr::eq(retained, original));
            retired(&mut client, address).await?;
            assert!(peer.task.is_none());
            Ok(())
        }
        .await;
        backup.abort();
        result
    }

    #[tokio::test]
    async fn completed_capture_failure_and_caller_keep_both_original_errors() -> TestResult {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let limits = CaptureLimits::new(32_768, 8_192, 128);
        let cause = Box::new(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "original peer",
        ));
        let original_peer = std::ptr::from_ref(cause.as_ref());
        let mut peer = WirePeer::new(tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            capture_stream(stream, deadline, limits).await?;
            let cause: Box<dyn Error + Send + Sync> = cause;
            Err(cause)
        }));
        let mut client = TcpStream::connect(address).await?;
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: local\r\n\r\n")
            .await?;
        let mut response = Vec::new();
        timeout(Duration::from_secs(2), client.read_to_end(&mut response)).await??;
        assert_eq!(
            response,
            b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
        );
        timeout(Duration::from_secs(2), async {
            while peer.task.as_ref().is_some_and(|task| !task.is_finished()) {
                yield_now().await;
            }
        })
        .await?;
        let caller = Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "original caller",
        ));
        let original_caller = std::ptr::from_ref(caller.as_ref());

        let Err(error) = peer.finish::<()>(Err(caller)).await else {
            return Err("failed caller and peer were accepted".into());
        };
        let failures = error
            .downcast_ref::<WireFailures>()
            .ok_or("peer cause lost")?;
        let caller = failures
            .primary
            .downcast_ref::<io::Error>()
            .ok_or("caller cause lost")?;
        let peer_error = failures
            .cleanup
            .downcast_ref::<io::Error>()
            .ok_or("peer cause changed")?;
        assert!(std::ptr::eq(caller, original_caller));
        assert!(std::ptr::eq(peer_error, original_peer));
        assert!(peer.task.is_none());
        retired(&mut client, address).await
    }
}
