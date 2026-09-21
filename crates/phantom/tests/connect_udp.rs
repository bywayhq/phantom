//! Exact HTTP/3 over RFC 9298 CONNECT-UDP (MASQUE) proxies.

#[allow(dead_code)]
#[path = "support/h3.rs"]
mod h3_support;
#[allow(dead_code)]
#[path = "support/masque.rs"]
mod masque_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;
#[allow(dead_code)]
#[path = "support/tracing.rs"]
mod tracing_support;

use std::{
    error::Error as StdError,
    future::Future,
    net::SocketAddr,
    num::NonZeroUsize,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use phantom::{
    Client, ClientBuilder, ConnectUdpProxy, HttpProtocol, RequestError, RequestErrorKind,
    RequestHeader, RetryPolicy, Route,
    profile::{ClientProfile, Http3ClientSettings, Http3Setting, chromium},
};
use phantom_net::http3::{ConnectUdpError, ConnectUdpErrorKind};
use tokio::{task::JoinHandle, time::timeout};
use tracing::{
    Dispatch, Event, Metadata, Subscriber,
    field::{Field, Visit},
    instrument::WithSubscriber,
    span::{Attributes, Id, Record},
    subscriber::Interest,
};

use h3_support::server_endpoint;
use masque_support::{MasqueProxy, ProxyMode, masque_client_settings};
use tls_support::{TestIdentity, TestResult, tls_settings};
use tracing_support::OutcomeSubscriber;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[tokio::test]
async fn exact_h3_over_connect_udp_completes_request() -> TestResult<()> {
    bounded(async {
        let (origin_identity, proxy_identity) = identities()?;
        let origin = Origin::spawn(&origin_identity)?;
        let proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::Relay)?;
        let client = client(&origin_identity, &proxy_identity, &proxy)?;

        let response = client
            .get(HttpProtocol::Http3, &origin.uri("/hello"))?
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "/hello");
        assert_eq!(proxy.requests().len(), 1);
        assert_eq!(origin.requests(), ["/hello"]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn connect_udp_emits_template_path_protocol_and_capsule_field() -> TestResult<()> {
    bounded(async {
        let (origin_identity, proxy_identity) = identities()?;
        let origin = Origin::spawn(&origin_identity)?;
        let proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::Relay)?;
        let route = Route::connect_udp(
            ConnectUdpProxy::new(&proxy.template())?
                .header(RequestHeader::new("x-masque-client", "phantom")),
        );
        let client = client_builder(&origin_identity, &proxy_identity)
            .route(route)
            .build()?;

        client
            .get(HttpProtocol::Http3, &origin.uri("/fields"))?
            .send()
            .await?;

        let requests = proxy.requests();
        let [request] = requests.as_slice() else {
            return Err("proxy did not observe exactly one CONNECT-UDP request".into());
        };
        assert_eq!(request.method, "CONNECT");
        assert_eq!(request.protocol.as_deref(), Some("connect-udp"));
        assert_eq!(request.scheme.as_deref(), Some("https"));
        assert_eq!(
            request.authority.as_deref(),
            Some(format!("127.0.0.1:{}", proxy.address.port()).as_str())
        );
        assert_eq!(
            request.path,
            format!(
                "/.well-known/masque/udp/127.0.0.1/{}/",
                origin.address.port()
            )
        );
        assert_eq!(
            request.fields,
            [
                ("capsule-protocol".to_owned(), b"?1".to_vec()),
                ("x-masque-client".to_owned(), b"phantom".to_vec()),
            ]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn connect_udp_route_reuses_session_for_compatible_requests() -> TestResult<()> {
    bounded(async {
        let (origin_identity, proxy_identity) = identities()?;
        let origin = Origin::spawn(&origin_identity)?;
        let proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::Relay)?;
        let client = client(&origin_identity, &proxy_identity, &proxy)?;

        for path in ["/first", "/second"] {
            let response = client
                .get(HttpProtocol::Http3, &origin.uri(path))?
                .send()
                .await?;
            assert_eq!(response.into_body().collect().await?.to_bytes(), path);
        }

        assert_eq!(proxy.connections(), 1);
        assert_eq!(proxy.requests().len(), 1);
        assert_eq!(origin.connections(), 1);
        assert_eq!(origin.requests(), ["/first", "/second"]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn proxy_without_extended_connect_fails_without_origin_io() -> TestResult<()> {
    assert_setup_failure(
        ProxyMode::WithoutExtendedConnect,
        ConnectUdpErrorKind::ExtendedConnectUnavailable,
    )
    .await
}

#[tokio::test]
async fn proxy_without_h3_datagram_fails_typed() -> TestResult<()> {
    assert_setup_failure(
        ProxyMode::WithoutH3Datagram,
        ConnectUdpErrorKind::DatagramUnavailable,
    )
    .await
}

async fn assert_setup_failure(mode: ProxyMode, expected: ConnectUdpErrorKind) -> TestResult<()> {
    bounded(async {
        let (origin_identity, proxy_identity) = identities()?;
        let origin = Origin::spawn(&origin_identity)?;
        let proxy = MasqueProxy::spawn(&proxy_identity, mode)?;
        let client = client(&origin_identity, &proxy_identity, &proxy)?;

        let error = client
            .get(HttpProtocol::Http3, &origin.uri("/"))?
            .send()
            .await
            .err()
            .ok_or("CONNECT-UDP setup unexpectedly succeeded")?;

        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
        assert_eq!(connect_udp_kind(&error), Some(expected));
        assert!(proxy.requests().is_empty());
        assert_eq!(origin.connections(), 0);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn proxy_rejection_is_typed_without_direct_fallback() -> TestResult<()> {
    bounded(async {
        let (origin_identity, proxy_identity) = identities()?;
        let origin = Origin::spawn(&origin_identity)?;
        let proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::Reject(403))?;
        let client = client(&origin_identity, &proxy_identity, &proxy)?;

        let error = client
            .get(HttpProtocol::Http3, &origin.uri("/"))?
            .send()
            .await
            .err()
            .ok_or("rejected CONNECT-UDP request succeeded")?;

        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        let rejection = connect_udp_error(&error).ok_or("rejection lost its typed source")?;
        assert_eq!(rejection.kind(), ConnectUdpErrorKind::Rejected);
        assert_eq!(rejection.status(), Some(StatusCode::FORBIDDEN));
        assert!(rejection.to_string().contains("403"));
        assert_eq!(proxy.requests().len(), 1);
        assert_eq!(origin.connections(), 0);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn origin_and_proxy_trust_roots_are_independent() -> TestResult<()> {
    bounded(async {
        let (origin_identity, proxy_identity) = identities()?;
        let origin = Origin::spawn(&origin_identity)?;
        let proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::Relay)?;
        let route = Route::connect_udp(ConnectUdpProxy::new(&proxy.template())?);

        // The origin root authenticates only the origin, never the proxy.
        let origin_only = Client::builder(profile())
            .add_root_certificate_der(origin_identity.root_der.clone())
            .add_root_certificate_der(proxy_identity.root_der.clone())
            .route(route.clone())
            .build()?;
        let error = origin_only
            .get(HttpProtocol::Http3, &origin.uri("/"))?
            .send()
            .await
            .err()
            .ok_or("proxy was authenticated with origin roots")?;
        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        assert_eq!(
            connect_udp_kind(&error),
            Some(ConnectUdpErrorKind::Handshake)
        );
        assert!(proxy.requests().is_empty());
        assert_eq!(origin.connections(), 0);

        // The proxy root authenticates only the proxy, never the origin.
        let proxy_only = Client::builder(profile())
            .add_proxy_root_certificate_der(origin_identity.root_der.clone())
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .route(route)
            .build()?;
        let error = proxy_only
            .get(HttpProtocol::Http3, &origin.uri("/"))?
            .send()
            .await
            .err()
            .ok_or("origin was authenticated with proxy roots")?;
        assert_eq!(error.kind(), RequestErrorKind::Tls);
        assert_eq!(connect_udp_kind(&error), None);
        assert_eq!(proxy.requests().len(), 1);
        assert!(origin.requests().is_empty());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn connect_udp_route_rejects_h1_h2_negotiated_and_websocket_before_io() -> TestResult<()> {
    bounded(async {
        let (origin_identity, proxy_identity) = identities()?;
        let proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::Relay)?;
        let client = client(&origin_identity, &proxy_identity, &proxy)?;
        let uri = "https://127.0.0.1:9/";

        for protocol in [HttpProtocol::Http1, HttpProtocol::Http2] {
            let error = client
                .get(protocol, uri)?
                .send()
                .await
                .err()
                .ok_or("TCP protocol accepted a CONNECT-UDP route")?;
            assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);
            assert_eq!(error.protocol(), Some(protocol));
        }
        let error = client
            .get_negotiated(uri)?
            .send()
            .await
            .err()
            .ok_or("negotiated request accepted a CONNECT-UDP route")?;
        assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);

        #[cfg(feature = "websocket")]
        for uri in ["wss://127.0.0.1:9/", "ws://127.0.0.1:9/"] {
            let error = client
                .websocket(uri)?
                .connect()
                .await
                .err()
                .ok_or("WebSocket accepted a CONNECT-UDP route")?;
            assert_eq!(error.kind(), phantom::WebSocketErrorKind::UnsupportedRoute);
        }

        assert_eq!(proxy.connections(), 0);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn mtu_config_that_cannot_fit_an_initial_fails_before_io() -> TestResult<()> {
    bounded(async {
        let (origin_identity, proxy_identity) = identities()?;
        let proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::Relay)?;
        let base = masque_client_settings();
        let mut small_datagrams = base.quic_transport().clone();
        small_datagrams.max_datagram_frame_size = Some(1_024);
        let mut without_h3_datagram = base.http3().clone();
        without_h3_datagram
            .initial_settings
            .retain(|setting| !matches!(setting, Http3Setting::H3Datagram(_)));

        for settings in [
            Http3ClientSettings::new(
                base.tls().clone(),
                small_datagrams,
                base.http3().clone(),
                base.request().clone(),
            ),
            Http3ClientSettings::new(
                base.tls().clone(),
                base.quic_transport().clone(),
                without_h3_datagram,
                base.request().clone(),
            ),
        ] {
            let client = Client::builder(ClientProfile::new(tls_settings()).with_http3(settings))
                .add_root_certificate_der(origin_identity.root_der.clone())
                .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
                .route(Route::connect_udp(ConnectUdpProxy::new(&proxy.template())?))
                .build()?;
            let error = client
                .get(HttpProtocol::Http3, "https://127.0.0.1:9/")?
                .send()
                .await
                .err()
                .ok_or("outer profile without datagram capacity was accepted")?;
            assert_eq!(error.kind(), RequestErrorKind::Proxy);
            assert_eq!(
                connect_udp_kind(&error),
                Some(ConnectUdpErrorKind::Configuration)
            );
        }
        assert_eq!(proxy.connections(), 0);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn connect_udp_retries_only_outer_connect_failures() -> TestResult<()> {
    bounded(async {
        let (origin_identity, proxy_identity) = identities()?;
        let retries = RetryPolicy::connection_failures(
            NonZeroUsize::new(2).ok_or("invalid retry count")?,
            Duration::ZERO,
        );

        // An unresolvable proxy is an outer setup failure: every retry makes
        // a fresh attempt on the same CONNECT-UDP route.
        let unresolvable = Route::connect_udp(ConnectUdpProxy::new(
            "https://masque-proxy.invalid/.well-known/masque/udp/{target_host}/{target_port}/",
        )?);
        let unresolvable_client = client_builder(&origin_identity, &proxy_identity)
            .route(unresolvable)
            .retry_policy(retries)
            .build()?;
        let subscriber = OutcomeSubscriber::default();
        let error = unresolvable_client
            .get(HttpProtocol::Http3, "https://127.0.0.1:9/")?
            .send()
            .with_subscriber(subscriber.dispatch())
            .await
            .err()
            .ok_or("unresolvable proxy succeeded")?;
        assert_eq!(connect_udp_kind(&error), Some(ConnectUdpErrorKind::Resolve));
        assert_eq!(
            subscriber.retries_performed_for("client.request").last(),
            Some(&2)
        );

        // A proxy rejection and an inner handshake failure are terminal.
        let origin = Origin::spawn(&origin_identity)?;
        let rejecting = MasqueProxy::spawn(&proxy_identity, ProxyMode::Reject(502))?;
        let relaying = MasqueProxy::spawn(&proxy_identity, ProxyMode::Relay)?;
        let untrusted_origin = Client::builder(profile())
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .route(Route::connect_udp(ConnectUdpProxy::new(
                &relaying.template(),
            )?))
            .retry_policy(retries)
            .build()?;
        for (terminal_client, proxy, kind) in [
            (
                client(&origin_identity, &proxy_identity, &rejecting)?,
                &rejecting,
                RequestErrorKind::Proxy,
            ),
            (untrusted_origin, &relaying, RequestErrorKind::Tls),
        ] {
            let subscriber = OutcomeSubscriber::default();
            let error = terminal_client
                .get(HttpProtocol::Http3, &origin.uri("/"))?
                .retry_policy(retries)
                .send()
                .with_subscriber(subscriber.dispatch())
                .await
                .err()
                .ok_or("terminal CONNECT-UDP failure succeeded")?;
            assert_eq!(error.kind(), kind);
            assert_eq!(proxy.requests().len(), 1);
            assert!(
                subscriber
                    .retries_performed_for("client.request")
                    .iter()
                    .all(|retries| *retries == 0)
            );
        }
        assert!(origin.requests().is_empty());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn outer_close_fails_inner_connection_and_invalidates_pool_entry() -> TestResult<()> {
    bounded(async {
        let (origin_identity, proxy_identity) = identities()?;
        let origin = Origin::spawn(&origin_identity)?;
        let proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::Relay)?;
        let client = client(&origin_identity, &proxy_identity, &proxy)?;

        let response = client
            .get(HttpProtocol::Http3, &origin.uri("/stall"))?
            .send()
            .await?;
        let mut body = response.into_body();
        let first = body
            .frame()
            .await
            .ok_or("stalled body ended early")??
            .into_data()
            .map_err(|_| "stalled body sent trailers")?;
        assert_eq!(first, "partial");

        proxy.close_connections();
        let failure = timeout(TEST_TIMEOUT, body.collect())
            .await
            .map_err(|_| "inner body did not fail after the outer connection closed")?;
        let error = failure
            .err()
            .ok_or("inner body completed after the outer connection closed")?;
        assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
        proxy.reopen();

        let response = client
            .get(HttpProtocol::Http3, &origin.uri("/after-close"))?
            .send()
            .await?;
        assert_eq!(
            response.into_body().collect().await?.to_bytes(),
            "/after-close"
        );
        assert_eq!(proxy.connections(), 2);
        assert_eq!(proxy.requests().len(), 2);
        assert_eq!(origin.connections(), 2);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn connect_udp_diagnostics_exclude_payloads() -> TestResult<()> {
    bounded(async {
        let (origin_identity, proxy_identity) = identities()?;
        let origin = Origin::spawn(&origin_identity)?;
        let proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::Relay)?;
        let route = Route::connect_udp(
            ConnectUdpProxy::new(&proxy.template())?
                .header(RequestHeader::new("x-masque-secret", "proxy-credential")),
        );
        let client = client_builder(&origin_identity, &proxy_identity)
            .route(route)
            .build()?;
        let capture = FieldCapture::default();

        let body = async {
            let response = client
                .get(HttpProtocol::Http3, &origin.uri("/payload-secret"))?
                .send()
                .await?;
            Ok::<_, RequestError>(response.into_body().collect().await?.to_bytes())
        }
        .with_subscriber(capture.dispatch())
        .await?;
        assert_eq!(body, "/payload-secret");
        drop(client);

        timeout(TEST_TIMEOUT, async {
            while capture
                .values("proxy.connect_udp", "dropped_unknown_context")
                .is_empty()
            {
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        })
        .await
        .map_err(|_| "tunnel drop counters were not recorded")?;

        assert_eq!(
            capture.values("proxy.connect_udp", "proxy_protocol"),
            ["connect-udp"]
        );
        assert_eq!(capture.values("proxy.connect_udp", "status"), ["200"]);
        assert_eq!(capture.values("proxy.connect_udp", "outcome"), ["accepted"]);
        for field in [
            "dropped_overflow",
            "dropped_early",
            "dropped_malformed",
            "dropped_oversized",
            "dropped_send",
        ] {
            assert_eq!(
                capture.values("proxy.connect_udp", field).len(),
                1,
                "{field}"
            );
        }
        let recorded = capture.all_values();
        for secret in ["proxy-credential", "payload-secret", "unknown-context"] {
            assert!(
                !recorded.iter().any(|value| value.contains(secret)),
                "diagnostics recorded {secret}"
            );
        }
        Ok(())
    })
    .await
}

fn identities() -> TestResult<(TestIdentity, TestIdentity)> {
    Ok((TestIdentity::generate()?, TestIdentity::generate()?))
}

fn profile() -> ClientProfile {
    ClientProfile::new(tls_settings())
        .with_http2(chromium::v152_macos_http2())
        .with_http3(masque_client_settings())
}

fn client_builder(origin: &TestIdentity, proxy: &TestIdentity) -> ClientBuilder {
    Client::builder(profile())
        .add_root_certificate_der(origin.root_der.clone())
        .add_proxy_root_certificate_der(proxy.root_der.clone())
}

fn client(origin: &TestIdentity, proxy: &TestIdentity, masque: &MasqueProxy) -> TestResult<Client> {
    Ok(client_builder(origin, proxy)
        .route(Route::connect_udp(ConnectUdpProxy::new(
            &masque.template(),
        )?))
        .build()?)
}

fn connect_udp_error(error: &RequestError) -> Option<&ConnectUdpError> {
    let mut current = error.source();
    while let Some(source) = current {
        if let Some(error) = source.downcast_ref::<ConnectUdpError>() {
            return Some(error);
        }
        current = source.source();
    }
    None
}

fn connect_udp_kind(error: &RequestError) -> Option<ConnectUdpErrorKind> {
    connect_udp_error(error).map(ConnectUdpError::kind)
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(Duration::from_secs(30), future)
        .await
        .map_err(|_| "CONNECT-UDP integration test exceeded its deadline")?
}

type ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// HTTP/3 origin that answers each request with its path; `/stall` sends a
/// partial body and never finishes.
struct Origin {
    address: SocketAddr,
    connections: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl Origin {
    fn spawn(identity: &TestIdentity) -> TestResult<Self> {
        let (address, endpoint) = server_endpoint(identity)?;
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let task_connections = Arc::clone(&connections);
        let task_requests = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let requests = Arc::clone(&task_requests);
                let connections = Arc::clone(&task_connections);
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    connections.fetch_add(1, Ordering::SeqCst);
                    let Ok(mut connection) = h3::server::Connection::<_, Bytes>::new(
                        h3_quinn::Connection::new(connection),
                    )
                    .await
                    else {
                        return;
                    };
                    while let Ok(Some(resolver)) = connection.accept().await {
                        let Ok((request, stream)) = resolver.resolve_request().await else {
                            return;
                        };
                        let path = request.uri().path().to_owned();
                        requests
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push(path.clone());
                        tokio::spawn(respond(stream, path));
                    }
                });
            }
        });
        Ok(Self {
            address,
            connections,
            requests,
            task,
        })
    }

    fn uri(&self, path: &str) -> String {
        format!("https://{}{path}", self.address)
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn respond(mut stream: ServerStream, path: String) -> TestResult<()> {
    stream
        .send_response(Response::builder().status(StatusCode::OK).body(())?)
        .await?;
    if path == "/stall" {
        stream.send_data(Bytes::from_static(b"partial")).await?;
        std::future::pending::<()>().await;
    }
    stream.send_data(Bytes::from(path)).await?;
    stream.finish().await?;
    Ok(())
}

/// Records every span and event field value as text.
#[derive(Clone, Default)]
struct FieldCapture {
    next_id: Arc<AtomicU64>,
    state: Arc<Mutex<CaptureState>>,
}

#[derive(Default)]
struct CaptureState {
    names: Vec<(u64, &'static str)>,
    values: Vec<(&'static str, String, String)>,
}

impl FieldCapture {
    fn dispatch(&self) -> Dispatch {
        // Installs the shared dynamic-interest fallback once per process.
        let _ = OutcomeSubscriber::default().dispatch();
        let dispatch = Dispatch::new(self.clone());
        tracing::callsite::rebuild_interest_cache();
        dispatch
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CaptureState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn values(&self, span: &str, field: &str) -> Vec<String> {
        self.lock()
            .values
            .iter()
            .filter(|(name, key, _)| *name == span && key == field)
            .map(|(_, _, value)| value.clone())
            .collect()
    }

    fn all_values(&self) -> Vec<String> {
        self.lock()
            .values
            .iter()
            .map(|(_, _, value)| value.clone())
            .collect()
    }

    fn record(&self, name: &'static str, visitor: FieldVisitor) {
        self.lock().values.extend(
            visitor
                .fields
                .into_iter()
                .map(|(key, value)| (name, key, value)),
        );
    }

    fn span_name(&self, id: &Id) -> &'static str {
        self.lock()
            .names
            .iter()
            .find(|(candidate, _)| *candidate == id.into_u64())
            .map_or("", |(_, name)| name)
    }
}

impl Subscriber for FieldCapture {
    fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
        Interest::always()
    }

    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, attributes: &Attributes<'_>) -> Id {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let name = attributes.metadata().name();
        self.lock().names.push((id, name));
        let mut visitor = FieldVisitor::default();
        attributes.record(&mut visitor);
        self.record(name, visitor);
        Id::from_u64(id)
    }

    fn record(&self, span: &Id, values: &Record<'_>) {
        let mut visitor = FieldVisitor::default();
        values.record(&mut visitor);
        let name = self.span_name(span);
        FieldCapture::record(self, name, visitor);
    }

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        FieldCapture::record(self, event.metadata().name(), visitor);
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

#[derive(Default)]
struct FieldVisitor {
    fields: Vec<(String, String)>,
}

impl Visit for FieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields
            .push((field.name().to_owned(), value.to_owned()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields
            .push((field.name().to_owned(), format!("{value:?}")));
    }
}
