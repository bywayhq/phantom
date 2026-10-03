//! A client used from more than one Tokio runtime.
//!
//! A pooled connection's driver runs on the runtime that opened it, so a
//! request on another runtime must not take it: once that runtime has stopped
//! being driven, or has been dropped, nothing reads the connection. Each test
//! sends one request on a first runtime, keeps or drops that runtime, and
//! sends a second request on a new one. The origins run on a runtime of their
//! own, which serves both requests.

use crate::support::h3 as h3_support;
use crate::support::tls as tls_support;

use std::{
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol,
    profile::{ClientProfile, chromium},
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    runtime::{Builder, Runtime},
    time::timeout,
};

use tls_support::{H2_ALPN, TestIdentity, accept_tls_stream, read_head, tls_settings};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a request must stay unanswered to count as held.
const QUIET_WINDOW: Duration = Duration::from_millis(300);

/// What happens to the first request's runtime before the second request.
#[derive(Clone, Copy, Debug)]
enum FirstRuntime {
    /// Alive, but no longer driven, as after `block_on` returns.
    Kept,
    Dropped,
}

/// An origin on its own runtime that counts the connections it accepted.
struct Origin {
    _runtime: Runtime,
    uri: String,
    connections: Arc<AtomicUsize>,
}

impl Origin {
    fn http1() -> TestResult<Self> {
        let runtime = Runtime::new()?;
        let connections = Arc::new(AtomicUsize::new(0));
        let listener = runtime.block_on(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)))?;
        let uri = format!("http://{}/", listener.local_addr()?);
        let accepted = Arc::clone(&connections);
        runtime.spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    while read_head(&mut stream).await.is_ok() {
                        if stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone")
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });
        Ok(Self {
            _runtime: runtime,
            uri,
            connections,
        })
    }

    fn http2(identity: &TestIdentity) -> TestResult<Self> {
        let runtime = Runtime::new()?;
        let connections = Arc::new(AtomicUsize::new(0));
        let listener = runtime.block_on(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)))?;
        let uri = format!("https://{}/", listener.local_addr()?);
        let acceptor = identity.acceptor(H2_ALPN)?;
        let accepted = Arc::clone(&connections);
        runtime.spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                accepted.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let stream = accept_tls_stream(tcp, acceptor).await?;
                    let mut server = ::http2::server::handshake(stream).await?;
                    while let Some(accepted) = server.accept().await {
                        let (_, mut respond) = accepted?;
                        let mut body = respond.send_response(
                            Response::builder().status(StatusCode::OK).body(())?,
                            false,
                        )?;
                        body.send_data(Bytes::from_static(b"done"), true)?;
                    }
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                });
            }
        });
        Ok(Self {
            _runtime: runtime,
            uri,
            connections,
        })
    }

    fn http3(identity: &TestIdentity) -> TestResult<Self> {
        let runtime = Runtime::new()?;
        let connections = Arc::new(AtomicUsize::new(0));
        let (address, endpoint) = {
            let _entered = runtime.enter();
            h3_support::server_endpoint(identity)?
        };
        let uri = format!("https://{address}/");
        let accepted = Arc::clone(&connections);
        runtime.spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let quic = incoming.await?;
                    let mut server: h3::server::Connection<h3_quinn::Connection, Bytes> =
                        h3::server::Connection::new(h3_quinn::Connection::new(quic)).await?;
                    while let Some(resolver) = server.accept().await? {
                        let (_, mut stream) = resolver.resolve_request().await?;
                        stream
                            .send_response(Response::builder().status(StatusCode::OK).body(())?)
                            .await?;
                        stream.send_data(Bytes::from_static(b"done")).await?;
                        stream.finish().await?;
                    }
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                });
            }
        });
        Ok(Self {
            _runtime: runtime,
            uri,
            connections,
        })
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

/// Sends one request on a new current-thread runtime and returns the runtime.
fn request_on_new_runtime(
    client: &Client,
    protocol: HttpProtocol,
    uri: &str,
) -> TestResult<Runtime> {
    let runtime = Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        let response = timeout(TEST_TIMEOUT, client.get(protocol, uri)?.send())
            .await
            .map_err(|_| "the request on this runtime did not finish")??;
        assert_eq!(response.status(), StatusCode::OK);
        let body = timeout(TEST_TIMEOUT, response.into_body().collect())
            .await??
            .to_bytes();
        assert_eq!(body, "done");
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })?;
    Ok(runtime)
}

/// Sends a request on one runtime, keeps or drops it, sends another on a
/// second runtime, and checks that the second opened its own connection.
fn second_runtime_opens_its_own_connection(
    client: &Client,
    origin: &Origin,
    protocol: HttpProtocol,
    first_runtime: FirstRuntime,
) -> TestResult {
    let first = request_on_new_runtime(client, protocol, &origin.uri)?;
    assert_eq!(origin.connections(), 1);
    let kept = match first_runtime {
        FirstRuntime::Kept => Some(first),
        FirstRuntime::Dropped => {
            drop(first);
            None
        }
    };

    let second = request_on_new_runtime(client, protocol, &origin.uri)?;

    assert_eq!(
        origin.connections(),
        2,
        "{protocol:?} after a {first_runtime:?} runtime"
    );
    drop((second, kept));
    Ok(())
}

#[test]
fn http1_request_on_another_runtime_opens_its_own_connection() -> TestResult {
    for first_runtime in [FirstRuntime::Kept, FirstRuntime::Dropped] {
        let origin = Origin::http1()?;
        let client = Client::builder(ClientProfile::new(tls_settings())).build()?;
        second_runtime_opens_its_own_connection(
            &client,
            &origin,
            HttpProtocol::Http1,
            first_runtime,
        )?;
    }
    Ok(())
}

#[test]
fn http2_request_on_another_runtime_opens_its_own_connection() -> TestResult {
    let identity = TestIdentity::generate()?;
    for first_runtime in [FirstRuntime::Kept, FirstRuntime::Dropped] {
        let origin = Origin::http2(&identity)?;
        let client = tls_support::test_client(&identity, true)?;
        second_runtime_opens_its_own_connection(
            &client,
            &origin,
            HttpProtocol::Http2,
            first_runtime,
        )?;
    }
    Ok(())
}

#[test]
fn http3_request_on_another_runtime_opens_its_own_connection() -> TestResult {
    let identity = TestIdentity::generate()?;
    for first_runtime in [FirstRuntime::Kept, FirstRuntime::Dropped] {
        let origin = Origin::http3(&identity)?;
        let client = Client::builder(
            ClientProfile::new(tls_settings()).with_http3(h3_support::client_settings()),
        )
        .add_root_certificate_der(identity.root_der.clone())
        .build()?;
        second_runtime_opens_its_own_connection(
            &client,
            &origin,
            HttpProtocol::Http3,
            first_runtime,
        )?;
    }
    Ok(())
}

/// Sends two negotiated requests at once on a new current-thread runtime.
fn two_negotiated_requests_on_new_runtime(client: &Client, uri: &str) -> TestResult<Runtime> {
    let runtime = Builder::new_current_thread().enable_all().build()?;
    let send = || async {
        let response = timeout(TEST_TIMEOUT, client.get_negotiated(uri)?.send())
            .await
            .map_err(|_| "the negotiated request on this runtime did not finish")??;
        assert_eq!(response.status(), StatusCode::OK);
        timeout(TEST_TIMEOUT, response.into_body().collect()).await??;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    runtime.block_on(async { tokio::try_join!(send(), send()) })?;
    Ok(runtime)
}

/// The memory that an origin selected HTTP/2 spans runtimes: on a second
/// runtime, a request to that origin waits for the connection already being
/// set up instead of opening another, as on the first.
#[test]
fn second_runtime_waits_for_its_own_setup_to_an_origin_known_for_http2() -> TestResult {
    let identity = TestIdentity::generate()?;
    let origin = Origin::http2(&identity)?;
    // An HTTP/1.1 policy lets a first contact open connections in parallel.
    let client = Client::builder(
        ClientProfile::new(tls_settings())
            .with_http1(chromium::v154_http1())
            .with_http2(chromium::v154_http2()),
    )
    .add_root_certificate_der(identity.root_der.clone())
    .build()?;
    let first = Builder::new_current_thread().enable_all().build()?;
    first.block_on(async {
        let response = timeout(TEST_TIMEOUT, client.get_negotiated(&origin.uri)?.send())
            .await
            .map_err(|_| "the first negotiated request did not finish")??;
        timeout(TEST_TIMEOUT, response.into_body().collect()).await??;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })?;
    drop(first);
    assert_eq!(origin.connections(), 1);

    let second = two_negotiated_requests_on_new_runtime(&client, &origin.uri)?;

    assert_eq!(origin.connections(), 2);
    drop(second);
    Ok(())
}

/// The per-origin request limit spans runtimes. Without an HTTP/1.1 policy
/// an origin takes one request at a time, so a request on a second runtime
/// waits while the first runtime's request is open instead of opening a
/// second connection.
#[test]
fn per_origin_request_limit_spans_runtimes() -> TestResult {
    let server_runtime = Runtime::new()?;
    let listener = server_runtime.block_on(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)))?;
    let uri = format!("http://{}/", listener.local_addr()?);
    let connections = Arc::new(AtomicUsize::new(0));
    let (seen_tx, seen) = std::sync::mpsc::channel();
    let (release, released) = tokio::sync::watch::channel(false);
    let accepted = Arc::clone(&connections);
    server_runtime.spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            accepted.fetch_add(1, Ordering::SeqCst);
            let seen_tx = seen_tx.clone();
            let mut released = released.clone();
            tokio::spawn(async move {
                while read_head(&mut stream).await.is_ok() {
                    let _ = seen_tx.send(());
                    let _ = released.wait_for(|released| *released).await;
                    if stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone")
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    let client = Client::builder(ClientProfile::new(tls_settings())).build()?;

    std::thread::scope(|scope| -> TestResult {
        let first = scope.spawn(|| -> TestResult {
            request_on_new_runtime(&client, HttpProtocol::Http1, &uri)?;
            Ok(())
        });
        seen.recv_timeout(TEST_TIMEOUT)?;
        let second = Builder::new_current_thread().enable_all().build()?;
        let waited = second.block_on(async {
            timeout(QUIET_WINDOW, client.get(HttpProtocol::Http1, &uri)?.send())
                .await
                .is_err()
                .then_some(())
                .ok_or_else(|| "the second runtime's request was not held".into())
        });
        let _ = release.send(true);
        first
            .join()
            .map_err(|_| "the first runtime's request panicked")??;
        waited
    })?;

    assert_eq!(connections.load(Ordering::SeqCst), 1);
    Ok(())
}
