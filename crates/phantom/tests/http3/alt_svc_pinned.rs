//! An exact HTTP/3 request sent to an alternative the caller pins, direct
//! and through a CONNECT-UDP proxy.

use std::{
    error::Error,
    fmt,
    future::Future,
    io,
    net::SocketAddr,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use phantom::{
    AddressResolver, Client, ClientBuilder, ConnectUdpProxy, HttpProtocol, RedirectPolicy,
    RequestErrorKind, RequestHeader, ResponseInfo, RetryPolicy, Route,
    profile::{ClientProfile, Http3ClientSettings, browser::chrome},
};
use tokio::{
    sync::oneshot,
    task::JoinHandle,
    time::{error::Elapsed, timeout},
};

use crate::support::h3 as h3_support;
use crate::support::masque as masque_support;
use crate::support::tls as tls_support;
use crate::support::tunnel_proxy::finish_with_cleanup;
use h3_support::{appending_alt_used, client_settings, server_endpoint};
use masque_support::{MasqueProxy, ProxyMode, masque_client_settings};
use tls_support::{TestIdentity, TestResult, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
/// A name the test never resolves: only the pinned alternative is reached.
const ORIGIN: &str = "origin.test";

mod deadline_contract;
mod peer_contract;
mod route_contract;

#[derive(Debug)]
struct PinnedDeadline {
    context: &'static str,
    cause: Elapsed,
    cleanup: Option<Box<dyn Error + Send + Sync>>,
}

impl fmt::Display for PinnedDeadline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.context, self.cause)?;
        if let Some(cleanup) = &self.cleanup {
            write!(formatter, "; pinned peer cleanup failed: {cleanup}")?;
        }
        Ok(())
    }
}

impl Error for PinnedDeadline {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.cause)
    }
}

/// One request as the alternative received it.
#[derive(Debug)]
struct Received {
    authority: String,
    path: String,
    alt_used: Option<String>,
}

struct AlternativePeer {
    endpoint: quinn::Endpoint,
    task: JoinHandle<TestResult<Vec<Received>>>,
}

impl AlternativePeer {
    fn refuse(endpoint: quinn::Endpoint) -> Self {
        let retained_endpoint = endpoint.clone();
        let task = tokio::spawn(async move {
            endpoint
                .accept()
                .await
                .ok_or("QUIC endpoint closed")?
                .refuse();
            Ok(Vec::new())
        });
        Self {
            endpoint: retained_endpoint,
            task,
        }
    }

    async fn finish(mut self) -> TestResult<Vec<Received>> {
        match timeout(TEST_TIMEOUT, &mut self.task).await {
            Ok(result) => result?,
            Err(cause) => {
                let cleanup = self.abort_and_join().await.err();
                Err(PinnedDeadline {
                    context: "pinned alternative peer did not finish",
                    cause,
                    cleanup,
                }
                .into())
            }
        }
    }

    async fn finish_after<T>(self, operation: TestResult<T>) -> TestResult<(T, Vec<Received>)> {
        match operation {
            Ok(value) => self.finish().await.map(|received| (value, received)),
            Err(primary) => finish_with_cleanup(Err(primary), self.abort_and_join().await),
        }
    }

    async fn abort_and_join(mut self) -> TestResult<()> {
        self.endpoint.close(0_u32.into(), b"test cancelled");
        self.task.abort();
        match timeout(TEST_TIMEOUT, &mut self.task).await {
            Ok(Err(error)) if error.is_cancelled() => Ok(()),
            Ok(result) => result?.map(|_| ()),
            Err(cause) => Err(PinnedDeadline {
                context: "pinned alternative peer did not stop after abort",
                cause,
                cleanup: None,
            }
            .into()),
        }
    }
}

impl Drop for AlternativePeer {
    fn drop(&mut self) {
        self.endpoint.close(0_u32.into(), b"test complete");
        self.task.abort();
    }
}

/// Serves `responses` in order on one connection at `endpoint`, each a status
/// and an optional `Location`, holds the connection until `done` fires, and
/// returns the requests it received.
fn serve_alternative(
    endpoint: quinn::Endpoint,
    responses: Vec<(StatusCode, Option<&'static str>)>,
    done: oneshot::Receiver<()>,
) -> AlternativePeer {
    let retained_endpoint = endpoint.clone();
    let task = tokio::spawn(async move {
        let incoming = endpoint.accept().await.ok_or("QUIC endpoint closed")?;
        let connection = incoming.await?;
        let mut h3 =
            h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection)).await?;
        let mut received = Vec::new();
        for (status, location) in responses {
            let resolver = h3
                .accept()
                .await?
                .ok_or("client closed before sending a request")?;
            let (request, mut stream) = resolver.resolve_request().await?;
            received.push(Received {
                authority: request
                    .uri()
                    .authority()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                path: request.uri().path().to_owned(),
                alt_used: request
                    .headers()
                    .get("alt-used")
                    .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned()),
            });
            // An advertisement the client must not learn from.
            let mut response = Response::builder()
                .status(status)
                .header("alt-svc", "h3=\":443\"; ma=3600");
            if let Some(location) = location {
                response = response.header("location", location);
            }
            stream.send_response(response.body(())?).await?;
            stream.finish().await?;
        }
        // Sender cancellation also releases the connection when its caller fails.
        let _ = done.await;
        Ok(received)
    });
    AlternativePeer {
        endpoint: retained_endpoint,
        task,
    }
}

fn direct_client(identity: &TestIdentity) -> ClientBuilder {
    direct_client_with(identity, client_settings())
}

/// A direct client builder whose HTTP/3 profile is `http3`.
fn direct_client_with(identity: &TestIdentity, http3: Http3ClientSettings) -> ClientBuilder {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(chrome::v154_http2())
        .with_http3(http3);
    Client::builder(profile).add_root_certificate_der(identity.root_der.clone())
}

fn alternative(address: SocketAddr) -> (String, u16) {
    (address.ip().to_string(), address.port())
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|cause| PinnedDeadline {
            context: "pinned alternative test exceeded its deadline",
            cause,
            cleanup: None,
        })?
}

#[tokio::test]
async fn a_pinned_alternative_receives_the_request_for_the_origin() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN)?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (done, wait_for_done) = oneshot::channel();
        let server = serve_alternative(endpoint, vec![(StatusCode::OK, None)], wait_for_done);
        let (host, port) = alternative(address);

        let operation = async {
            let client = direct_client(&identity)
                .alt_svc(NonZeroUsize::MIN)
                .build()?;
            let response = client
                .get(HttpProtocol::Http3, &format!("https://{ORIGIN}/pinned"))?
                .alt_svc_alternative(&host, port)
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            let info = response
                .extensions()
                .get::<ResponseInfo>()
                .ok_or("response omitted ResponseInfo")?;
            assert_eq!(info.protocol(), HttpProtocol::Http3);
            response.into_body().collect().await?;
            TestResult::Ok(client)
        }
        .await;

        let _ = done.send(());

        let (client, received) = server.finish_after(operation).await?;
        assert_eq!(received.len(), 1);
        // The origin's authority, and no `Alt-Used` from the Chromium request
        // recipe, as Chrome 154 sends none.
        assert_eq!(received[0].authority, ORIGIN);
        assert_eq!(received[0].path, "/pinned");
        assert!(
            client
                .export_alt_svc()
                .ok_or("Alt-Svc is enabled")?
                .is_empty()
        );
        assert_eq!(received[0].alt_used, None);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_profile_that_appends_alt_used_names_the_pinned_alternative() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN)?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (done, wait_for_done) = oneshot::channel();
        let server = serve_alternative(endpoint, vec![(StatusCode::OK, None)], wait_for_done);
        let (host, port) = alternative(address);

        let operation = async {
            let client =
                direct_client_with(&identity, appending_alt_used(client_settings())).build()?;
            let response = client
                .get(HttpProtocol::Http3, &format!("https://{ORIGIN}/pinned"))?
                .alt_svc_alternative(&host, port)
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            response.into_body().collect().await?;
            TestResult::Ok(client)
        }
        .await;

        let _ = done.send(());

        let (_client, received) = server.finish_after(operation).await?;
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].authority, ORIGIN);
        assert_eq!(
            received[0].alt_used.as_deref(),
            Some(&*format!("{host}:{port}"))
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_pinned_alternative_is_reached_through_connect_udp() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN)?;
        let proxy_identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (done, wait_for_done) = oneshot::channel();
        let server = serve_alternative(endpoint, vec![(StatusCode::OK, None)], wait_for_done);
        let (host, port) = alternative(address);

        let operation = async {
            let proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::Relay)?;

            let profile = ClientProfile::new(tls_settings())
                .with_http3(appending_alt_used(masque_client_settings()));
            let client = Client::builder(profile)
                .add_root_certificate_der(identity.root_der.clone())
                .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
                .route(Route::connect_udp(ConnectUdpProxy::new(&proxy.template())?))
                .build()?;
            let response = client
                .get(HttpProtocol::Http3, &format!("https://{ORIGIN}/proxied"))?
                .alt_svc_alternative(&host, port)
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            response.into_body().collect().await?;

            let requests = proxy.requests();
            assert_eq!(requests.len(), 1);
            // The proxy is asked for the alternative, never the origin.
            assert!(
                requests[0].path.ends_with(&format!("/{host}/{port}/")),
                "{}",
                requests[0].path
            );
            TestResult::Ok((client, proxy))
        }
        .await;

        let _ = done.send(());
        let (_client_and_proxy, received) = server.finish_after(operation).await?;
        assert_eq!(received[0].authority, ORIGIN);
        assert_eq!(
            received[0].alt_used.as_deref(),
            Some(&*format!("{host}:{port}"))
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_same_origin_redirect_keeps_the_pinned_alternative() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN)?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (done, wait_for_done) = oneshot::channel();
        let server = serve_alternative(
            endpoint,
            vec![
                (StatusCode::TEMPORARY_REDIRECT, Some("/next")),
                (StatusCode::OK, None),
            ],
            wait_for_done,
        );
        let (host, port) = alternative(address);

        let operation = async {
            let client = direct_client_with(&identity, appending_alt_used(client_settings()))
                .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
                .build()?;
            let response = client
                .get(HttpProtocol::Http3, &format!("https://{ORIGIN}/first"))?
                .alt_svc_alternative(&host, port)
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            response.into_body().collect().await?;
            TestResult::Ok(client)
        }
        .await;

        let _ = done.send(());

        let (_client, received) = server.finish_after(operation).await?;
        let paths = received
            .iter()
            .map(|request| request.path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(paths, ["/first", "/next"]);
        assert!(received.iter().all(|request| request.alt_used.is_some()));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_redirect_to_another_origin_leaves_the_pinned_alternative() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN)?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (done, wait_for_done) = oneshot::channel();
        let server = serve_alternative(
            endpoint,
            vec![(
                StatusCode::TEMPORARY_REDIRECT,
                Some("https://other.test/next"),
            )],
            wait_for_done,
        );
        let (host, port) = alternative(address);

        let lookups = Arc::new(Mutex::new(Vec::new()));
        let recorded_lookups = Arc::clone(&lookups);
        let resolver = AddressResolver::from_fn(move |host| {
            let lookups = Arc::clone(&recorded_lookups);
            async move {
                lookups
                    .lock()
                    .map_err(|_| io::Error::other("resolver observation lock poisoned"))?
                    .push(host);
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "test resolver refused the foreign origin",
                ))
            }
        });
        let operation = async {
            let client = direct_client(&identity)
                .dns_resolver(resolver)
                .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
                .build()?;

            let error = client
                .get(HttpProtocol::Http3, &format!("https://{ORIGIN}/first"))?
                .alt_svc_alternative(&host, port)
                .send()
                .await
                .err()
                .ok_or("the foreign origin bypassed the selected resolver")?;
            // The second hop looked up the other origin instead of reusing the
            // alternative.
            assert_eq!(error.kind(), RequestErrorKind::Resolve);
            TestResult::Ok(client)
        }
        .await;

        let _ = done.send(());
        let (_client, received) = server.finish_after(operation).await?;
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].authority, ORIGIN);
        assert_eq!(received[0].path, "/first");
        assert_eq!(received[0].alt_used, None);

        assert_eq!(
            lookups
                .lock()
                .map_err(|_| "resolver observation lock poisoned")?
                .as_slice(),
            ["other.test"]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_failed_pinned_alternative_returns_the_http3_error() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN)?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let refused = AlternativePeer::refuse(endpoint);
        let (host, port) = alternative(address);

        let operation = async {
            let client = direct_client(&identity).build()?;
            let error = client
                .get(HttpProtocol::Http3, &format!("https://{ORIGIN}/refused"))?
                .alt_svc_alternative(&host, port)
                // A pinned alternative never falls back to the origin.
                .retry_policy(RetryPolicy::none().with_http2_fallback(true))
                .send()
                .await
                .err()
                .ok_or("a refused alternative returned a response")?;
            assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
            // Not the origin's resolution failure over HTTP/2.
            assert_ne!(error.kind(), RequestErrorKind::Resolve);
            TestResult::Ok(client)
        }
        .await;

        let (_client, received) = refused.finish_after(operation).await?;
        assert!(received.is_empty());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn an_invalid_pin_fails_before_any_io() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN)?;
        let proxy_identity = TestIdentity::generate()?;
        let proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::Relay)?;
        let profile = ClientProfile::new(tls_settings())
            .with_http2(chrome::v154_http2())
            .with_http3(masque_client_settings());
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .route(Route::connect_udp(ConnectUdpProxy::new(&proxy.template())?))
            .build()?;
        let url = format!("https://{ORIGIN}/");

        for (host, port) in [("127.0.0.1", 0), ("LOCALHOST", 443), ("[::1]", 443)] {
            let error = client
                .get(HttpProtocol::Http3, &url)?
                .alt_svc_alternative(host, port)
                .send()
                .await
                .err()
                .ok_or("an invalid alternative was accepted")?;
            assert_eq!(
                error.kind(),
                RequestErrorKind::InvalidAuthority,
                "{host}:{port}"
            );
        }

        let error = client
            .get_negotiated(&url)?
            .alt_svc_alternative("127.0.0.1", 443)
            .send()
            .await
            .err()
            .ok_or("a negotiated request accepted an alternative")?;
        assert_eq!(error.kind(), RequestErrorKind::ProtocolUnavailable);
        assert_eq!(error.protocol(), Some(HttpProtocol::Http3));

        let error = client
            .get(HttpProtocol::Http3, &url)?
            .header(RequestHeader::new("alt-used", "127.0.0.1:443"))
            .alt_svc_alternative("127.0.0.1", 443)
            .send()
            .await
            .err()
            .ok_or("a caller Alt-Used field was accepted")?;
        assert_eq!(error.kind(), RequestErrorKind::InvalidHeader);

        assert_eq!(proxy.connections(), 0);
        Ok(())
    })
    .await
}
