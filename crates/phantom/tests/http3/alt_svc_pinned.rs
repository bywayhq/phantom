//! An exact HTTP/3 request sent to an alternative the caller pins, direct
//! and through a CONNECT-UDP proxy.

use crate::support::h3 as h3_support;
use crate::support::masque as masque_support;
use crate::support::tls as tls_support;

use std::{future::Future, net::SocketAddr, num::NonZeroUsize, time::Duration};

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use phantom::{
    Client, ClientBuilder, ConnectUdpProxy, HttpProtocol, RedirectPolicy, RequestErrorKind,
    RequestHeader, ResponseInfo, RetryPolicy, Route,
    profile::{ClientProfile, chromium},
};
use tokio::{sync::oneshot, task::JoinHandle, time::timeout};

use h3_support::{client_settings, server_endpoint};
use masque_support::{MasqueProxy, ProxyMode, masque_client_settings};
use tls_support::{TestIdentity, TestResult, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
/// A name the test never resolves: only the pinned alternative is reached.
const ORIGIN: &str = "origin.test";

/// One request as the alternative received it.
#[derive(Debug)]
struct Received {
    authority: String,
    path: String,
    alt_used: Option<String>,
}

/// Serves `responses` in order on one connection at `endpoint`, each a status
/// and an optional `Location`, holds the connection until `done` fires, and
/// returns the requests it received.
fn serve_alternative(
    endpoint: quinn::Endpoint,
    responses: Vec<(StatusCode, Option<&'static str>)>,
    done: oneshot::Receiver<()>,
) -> JoinHandle<TestResult<Vec<Received>>> {
    tokio::spawn(async move {
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
        let _ = done.await;
        Ok(received)
    })
}

fn direct_client(identity: &TestIdentity) -> ClientBuilder {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(chromium::v154_http2())
        .with_http3(client_settings());
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
        .map_err(|_| "pinned alternative test exceeded its deadline")?
}

#[tokio::test]
async fn a_pinned_alternative_receives_the_request_for_the_origin() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN)?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (done, wait_for_done) = oneshot::channel();
        let server = serve_alternative(endpoint, vec![(StatusCode::OK, None)], wait_for_done);
        let (host, port) = alternative(address);

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
        let _ = done.send(());

        let received = server.await??;
        assert_eq!(received.len(), 1);
        // The origin's authority and the alternative's `Alt-Used`.
        assert_eq!(received[0].authority, ORIGIN);
        assert_eq!(received[0].path, "/pinned");
        assert!(
            client
                .export_alt_svc()
                .ok_or("Alt-Svc is enabled")?
                .is_empty()
        );
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
        let proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::Relay)?;
        let (host, port) = alternative(address);

        let profile = ClientProfile::new(tls_settings()).with_http3(masque_client_settings());
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
        let _ = done.send(());

        let requests = proxy.requests();
        assert_eq!(requests.len(), 1);
        // The proxy is asked for the alternative, never the origin.
        assert!(
            requests[0].path.ends_with(&format!("/{host}/{port}/")),
            "{}",
            requests[0].path
        );
        let received = server.await??;
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

        let response = direct_client(&identity)
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .build()?
            .get(HttpProtocol::Http3, &format!("https://{ORIGIN}/first"))?
            .alt_svc_alternative(&host, port)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect().await?;
        let _ = done.send(());

        let received = server.await??;
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

        let error = direct_client(&identity)
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .build()?
            .get(HttpProtocol::Http3, &format!("https://{ORIGIN}/first"))?
            .alt_svc_alternative(&host, port)
            .send()
            .await
            .err()
            .ok_or("the other origin, which never resolves, answered")?;
        // The second hop looked up the other origin instead of reusing the
        // alternative.
        assert_eq!(error.kind(), RequestErrorKind::Resolve);
        let _ = done.send(());
        let received = server.await??;
        assert_eq!(received.len(), 1);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_failed_pinned_alternative_returns_the_http3_error() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN)?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let refused = tokio::spawn(async move {
            endpoint
                .accept()
                .await
                .ok_or("QUIC endpoint closed")?
                .refuse();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let (host, port) = alternative(address);

        let error = direct_client(&identity)
            .build()?
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
        refused.await??;
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
            .with_http2(chromium::v154_http2())
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
