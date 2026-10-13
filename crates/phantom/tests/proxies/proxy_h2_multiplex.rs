//! Several CONNECT tunnels, forwarded requests, and WebSocket openings on
//! shared HTTP/2 proxy connections, per browser profile.

use std::{
    error::Error as StdError,
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::Duration,
};

use btls::ssl::SslAcceptor;
use bytes::Bytes;
use http::{Method, Response};
use http_body_util::BodyExt;
use phantom::{
    BuildErrorKind, Client, HttpProtocol, HttpProxy, Route,
    profile::{
        ClientProfile,
        browser::{chrome, firefox},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use crate::support::tls::{
    H1_ALPN, H2_ALPN, TestIdentity, TestResult, accept_tls_stream, read_head, tls_settings,
};
#[cfg(feature = "websocket")]
use crate::support::websocket_origin;

#[cfg(feature = "websocket")]
use crate::proxy_h2::connection_tasks::{finish_peer, stop_optional};
use crate::proxy_h2::{
    connection_tasks::{AcceptedConnections, ConnectionRegistry},
    normal_h2_teardown,
};
pub(super) use crate::proxy_h2::{relay_downstream, relay_upstream};
use crate::support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup};
use peer_contract::{TaskProbe, TaskRole};

mod deadline_contract;
mod listener_contract;
mod origin_contract;
pub(super) mod outcome_contract;
pub(super) mod peer_contract;
mod relay_contract;
#[cfg(feature = "websocket")]
mod websocket_contract;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

struct ProxyFixture {
    address: SocketAddr,
    log: ProxyLog,
    listener: ConnectionPeer<TestResult<()>>,
    handlers: AcceptedConnections,
    relays: AcceptedConnections,
}

impl ProxyFixture {
    fn completed_handlers(&self) -> TestResult<usize> {
        self.handlers.completed()
    }

    async fn finish_operation(self, operation: TestResult<()>) -> TestResult<()> {
        finish_with_cleanup(operation, self.finish().await)
    }

    async fn finish(self) -> TestResult<()> {
        let listener = self.listener.stop().await;
        let handlers = self.handlers.finish().await;
        let connections = finish_with_cleanup(listener, handlers);
        finish_with_cleanup(connections, self.relays.finish().await)
    }
}

struct OriginFixture {
    address: SocketAddr,
    listener: ConnectionPeer<TestResult<()>>,
    handlers: AcceptedConnections,
    requests: Arc<std::sync::atomic::AtomicUsize>,
}

impl OriginFixture {
    fn completed_handlers(&self) -> TestResult<usize> {
        self.handlers.completed()
    }

    async fn finish(self) -> TestResult<()> {
        let listener = self.listener.stop().await;
        let handlers = self.handlers.finish().await;
        finish_with_cleanup(listener, handlers)
    }
}

/// One request the proxy received.
#[derive(Clone, Debug)]
struct Seen {
    /// The proxy connection, numbered in accept order.
    connection: usize,
    stream: u32,
    method: Method,
    authority: String,
}

type ProxyLog = Arc<Mutex<Vec<Seen>>>;

/// Starts an HTTP/2 proxy that answers every CONNECT with `200` and relays
/// it to its authority, and every other request with `200 forwarded`.
async fn spawn_proxy(identity: &TestIdentity) -> TestResult<ProxyFixture> {
    spawn_limited_proxy(identity, None).await
}

/// Starts the proxy of [`spawn_proxy`], announcing `max_streams` as its
/// `SETTINGS_MAX_CONCURRENT_STREAMS`.
async fn spawn_limited_proxy(
    identity: &TestIdentity,
    max_streams: Option<u32>,
) -> TestResult<ProxyFixture> {
    spawn_proxy_fixture(identity, max_streams, None).await
}

async fn spawn_proxy_fixture(
    identity: &TestIdentity,
    max_streams: Option<u32>,
    probe: Option<TaskProbe>,
) -> TestResult<ProxyFixture> {
    spawn_proxy_fixture_with_fault(identity, max_streams, probe, None).await
}

async fn spawn_proxy_fixture_with_fault(
    identity: &TestIdentity,
    max_streams: Option<u32>,
    probe: Option<TaskProbe>,
    read_fault: Option<crate::proxy_h2::relay_contract::Fault>,
) -> TestResult<ProxyFixture> {
    spawn_proxy_fixture_with_faults(identity, max_streams, probe, read_fault, None).await
}

async fn spawn_proxy_fixture_with_faults(
    identity: &TestIdentity,
    max_streams: Option<u32>,
    probe: Option<TaskProbe>,
    read_fault: Option<crate::proxy_h2::relay_contract::Fault>,
    accept_fault: Option<crate::proxy_h2::relay_contract::Fault>,
) -> TestResult<ProxyFixture> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H2_ALPN)?;
    let log = ProxyLog::default();
    let seen = Arc::clone(&log);
    let children = probe.clone();
    let handlers = AcceptedConnections::new();
    let accepted = handlers.registry();
    let relays = AcceptedConnections::new();
    let relay_tasks = relays.registry();
    let task = async move {
        let mut index = 0;
        loop {
            let (tcp, _) = match listener_contract::accept(&listener, accept_fault.as_ref()).await {
                Ok(accepted) => accepted,
                Err(error) => return TestResult::<()>::Err(error.into()),
            };
            let future = serve_proxy_connection(
                tcp,
                acceptor.clone(),
                index,
                max_streams,
                Arc::clone(&seen),
                RelayOwners {
                    probe: children.clone(),
                    registry: Arc::clone(&relay_tasks),
                },
                read_fault.clone(),
            );
            let mut accepted = accepted
                .lock()
                .map_err(|_| io::Error::other("actual accepted handler registry poisoned"))?;
            let handler = if let Some(probe) = &children {
                probe.spawn(TaskRole::ProxyConnection, future)
            } else {
                ConnectionPeer::spawn(future)
            };
            accepted.push(handler);
            index += 1;
        }
    };
    let listener = match probe {
        Some(probe) => probe.spawn(TaskRole::ProxyListener, task),
        None => ConnectionPeer::spawn(task),
    };
    Ok(ProxyFixture {
        address,
        log,
        listener,
        handlers,
        relays,
    })
}

struct RelayOwners {
    probe: Option<TaskProbe>,
    registry: ConnectionRegistry,
}

async fn serve_proxy_connection(
    tcp: TcpStream,
    acceptor: SslAcceptor,
    index: usize,
    max_streams: Option<u32>,
    log: ProxyLog,
    relays: RelayOwners,
    read_fault: Option<crate::proxy_h2::relay_contract::Fault>,
) -> TestResult<()> {
    let stream = accept_tls_stream(tcp, acceptor).await?;
    let mut builder = ::http2::server::Builder::new();
    if let Some(max_streams) = max_streams {
        builder.max_concurrent_streams(max_streams);
    }

    let stream = outcome_contract::ReadFailure {
        inner: stream,
        fault: read_fault,
    };
    let mut connection = builder.handshake(stream).await?;
    loop {
        let accepted = connection.accept().await;
        let Some(accepted) = accepted else {
            return TestResult::<()>::Ok(());
        };
        let (request, mut respond) = match accepted {
            Ok(accepted) => accepted,
            Err(error) if normal_h2_teardown(&error) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let authority = request
            .uri()
            .authority()
            .map(ToString::to_string)
            .unwrap_or_default();
        log.lock()
            .map_err(|_| io::Error::other("proxy observation log poisoned"))?
            .push(Seen {
                connection: index,
                stream: respond.stream_id().as_u32(),
                method: request.method().clone(),
                authority: authority.clone(),
            });

        if request.method() == Method::CONNECT {
            let send = respond.send_response(Response::new(()), false)?;
            let upstream = TcpStream::connect(authority.as_str()).await?;
            spawn_relay(
                &relays.registry,
                request.into_body(),
                send,
                upstream,
                relays.probe.clone(),
            )?;
        } else {
            let mut send = respond.send_response(Response::new(()), false)?;
            send.send_data(Bytes::from_static(b"forwarded"), true)?;
        }
    }
}

fn spawn_relay(
    relays: &ConnectionRegistry,
    downstream: ::http2::RecvStream,
    send: ::http2::SendStream<Bytes>,
    upstream: TcpStream,
    probe: Option<TaskProbe>,
) -> TestResult<()> {
    let mut relays = relays
        .lock()
        .map_err(|_| io::Error::other("actual relay registry poisoned"))?;
    let (read, write) = upstream.into_split();
    let downstream = relay_downstream(downstream, write);
    let upstream = relay_upstream(read, send);
    let (downstream, upstream) = match probe {
        Some(probe) => (
            probe.spawn(TaskRole::RelayDownstream, downstream),
            probe.spawn(TaskRole::RelayUpstream, upstream),
        ),
        None => (
            ConnectionPeer::spawn(downstream),
            ConnectionPeer::spawn(upstream),
        ),
    };
    relays.extend([downstream, upstream]);
    Ok(())
}

/// Starts an HTTPS origin that answers every HTTP/1.1 request with `ok`.
async fn spawn_origin(identity: &TestIdentity) -> TestResult<OriginFixture> {
    spawn_origin_fixture(identity, None).await
}

async fn spawn_origin_fixture(
    identity: &TestIdentity,
    probe: Option<TaskProbe>,
) -> TestResult<OriginFixture> {
    spawn_origin_fixture_with_faults(identity, probe, OriginFaults::default()).await
}

#[derive(Clone, Default)]
struct OriginFaults {
    read: Option<crate::proxy_h2::relay_contract::Fault>,
    write: Option<crate::proxy_h2::relay_contract::Fault>,
    accept: Option<crate::proxy_h2::relay_contract::Fault>,
}

async fn spawn_origin_fixture_with_faults(
    identity: &TestIdentity,
    probe: Option<TaskProbe>,
    faults: OriginFaults,
) -> TestResult<OriginFixture> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let children = probe.clone();
    let handlers = AcceptedConnections::new();
    let accepted = handlers.registry();
    let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = Arc::clone(&requests);
    let task = async move {
        loop {
            let (tcp, _) = match listener_contract::accept(&listener, faults.accept.as_ref()).await
            {
                Ok(accepted) => accepted,
                Err(error) => return TestResult::<()>::Err(error.into()),
            };
            let acceptor = acceptor.clone();
            let faults = faults.clone();
            let requests = Arc::clone(&observed);
            let future = async move {
                let stream = accept_tls_stream(tcp, acceptor).await?;
                let stream = outcome_contract::ReadFailure {
                    inner: stream,
                    fault: faults.read,
                };
                let mut stream = origin_contract::WriteFailure {
                    inner: stream,
                    fault: faults.write,
                };
                loop {
                    let mut first = [0_u8; 1];
                    match stream.read(&mut first).await {
                        Ok(0) => return TestResult::<()>::Ok(()),
                        Ok(_) => {}
                        Err(error) if crate::support::tls::is_peer_gone(&error) => return Ok(()),
                        Err(error) => return Err(error.into()),
                    }

                    read_head(&mut first.as_slice().chain(&mut stream)).await?;
                    requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if let Err(error) = stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await
                    {
                        return if crate::support::tls::is_peer_gone(&error) {
                            Ok(())
                        } else {
                            Err(error.into())
                        };
                    }
                }
            };
            let mut accepted = accepted
                .lock()
                .map_err(|_| io::Error::other("actual origin handler registry poisoned"))?;
            let handler = if let Some(probe) = &children {
                probe.spawn(TaskRole::OriginConnection, future)
            } else {
                ConnectionPeer::spawn(future)
            };
            accepted.push(handler);
        }
    };
    let listener = match probe {
        Some(probe) => probe.spawn(TaskRole::OriginListener, task),
        None => ConnectionPeer::spawn(task),
    };
    Ok(OriginFixture {
        address,
        listener,
        handlers,
        requests,
    })
}

fn client(
    profile: ClientProfile,
    origin_identity: &TestIdentity,
    proxy_identity: &TestIdentity,
    proxy: SocketAddr,
) -> TestResult<Client> {
    Ok(Client::builder(profile)
        .add_root_certificate_der(origin_identity.root_der.clone())
        .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
        .route(Route::http_proxy(
            HttpProxy::new(&format!("https://{proxy}"))?.with_http2_transport()?,
        ))
        .build()?)
}

fn chromium_profile() -> ClientProfile {
    ClientProfile::new(tls_settings())
        .with_http2(chrome::v154_http2())
        .with_proxy_connect(chrome::v154_proxy_connect())
}

fn firefox_profile() -> ClientProfile {
    ClientProfile::new(tls_settings())
        .with_http2(firefox::v157_http2())
        .with_proxy_connect(firefox::v157_proxy_connect())
}

async fn get_https(client: &Client, origin: SocketAddr) -> TestResult<()> {
    let response = client
        .get(HttpProtocol::Http1, &format!("https://{origin}/"))?
        .send()
        .await?;
    assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
    Ok(())
}

async fn get_forwarded(client: &Client, origin: &str) -> TestResult<()> {
    let response = client
        .get(HttpProtocol::Http2, &format!("http://{origin}/"))?
        .send()
        .await?;
    assert_eq!(
        response.into_body().collect().await?.to_bytes(),
        "forwarded"
    );
    Ok(())
}

#[cfg(feature = "websocket")]
fn finish_websocket_exchange(
    operation: TestResult<()>,
    peer: impl Into<ConnectionPeer<TestResult<(Vec<u8>, websocket_origin::ClientFrame)>>>,
) -> impl Future<Output = TestResult<(Vec<u8>, websocket_origin::ClientFrame)>> {
    finish_peer(operation, peer)
}

fn observe_log(log: &ProxyLog) -> TestResult<Vec<Seen>> {
    Ok(log
        .lock()
        .map_err(|_| io::Error::other("proxy observation log poisoned"))?
        .clone())
}

/// Tunnels to three origins through a client become streams 1, 3, and 5 of
/// one proxy connection.
#[tokio::test]
async fn tunnels_to_different_origins_share_one_proxy_connection() -> TestResult<()> {
    bounded(async {
        let mut proxy_owner = None;
        let mut client_owner = None;
        let mut origin_owners = Vec::new();
        let operation = async {
            let origin_identity = TestIdentity::generate()?;
            let proxy_identity = TestIdentity::generate()?;
            proxy_owner = Some(spawn_proxy(&proxy_identity).await?);
            let fixture = proxy_owner.as_ref().ok_or("missing proxy fixture")?;
            let proxy = fixture.address;
            let log = &fixture.log;
            let origins = [
                {
                    origin_owners.push(spawn_origin(&origin_identity).await?);
                    origin_owners
                        .last()
                        .ok_or("missing origin fixture")?
                        .address
                },
                {
                    origin_owners.push(spawn_origin(&origin_identity).await?);
                    origin_owners
                        .last()
                        .ok_or("missing origin fixture")?
                        .address
                },
                {
                    origin_owners.push(spawn_origin(&origin_identity).await?);
                    origin_owners
                        .last()
                        .ok_or("missing origin fixture")?
                        .address
                },
            ];
            client_owner = Some(client(
                chromium_profile(),
                &origin_identity,
                &proxy_identity,
                proxy,
            )?);
            let client = client_owner.as_ref().ok_or("missing client owner")?;
            for origin in origins {
                get_https(client, origin).await?;
            }
            let seen = observe_log(log)?;
            let placement: Vec<(usize, u32, String)> = seen
                .iter()
                .map(|seen| (seen.connection, seen.stream, seen.authority.clone()))
                .collect();
            assert_eq!(
                placement,
                origins
                    .iter()
                    .zip([1, 3, 5])
                    .map(|(origin, stream)| (0, stream, origin.to_string()))
                    .collect::<Vec<_>>()
            );
            assert!(seen.iter().all(|seen| seen.method == Method::CONNECT));
            Ok(())
        }
        .await;

        let mut cleanup = Ok(());
        if let Some(proxy) = proxy_owner {
            cleanup = finish_with_cleanup(cleanup, proxy.finish().await);
        }
        for origin in origin_owners {
            cleanup = finish_with_cleanup(cleanup, origin.finish().await);
        }
        finish_with_cleanup(operation, cleanup)
    })
    .await
}

/// With the Chromium recipe, a forwarded `http://` request and CONNECT
/// tunnels are streams of one proxy connection, as Chrome 154 sends a page's
/// navigation, `fetch()`, and CONNECTs in the `https-proxy-*` captures.
/// With the Firefox recipe, forwarded requests and tunnels use separate
/// connections, each numbered from stream 3, as Firefox 157 does in the same
/// captures.
#[tokio::test]
async fn forwarded_requests_join_the_tunnel_connection_as_the_profile_says() -> TestResult<()> {
    bounded(async {
        for (profile, shared) in [(chromium_profile(), true), (firefox_profile(), false)] {
            let mut proxy_owner = None;
            let mut client_owner = None;
            let mut origin_owner = None;
            let operation = async {
                let origin_identity = TestIdentity::generate()?;
                let proxy_identity = TestIdentity::generate()?;
                proxy_owner = Some(spawn_proxy(&proxy_identity).await?);
                let fixture = proxy_owner.as_ref().ok_or("missing proxy fixture")?;
                let proxy = fixture.address;
                let log = &fixture.log;
                let origin = {
                    origin_owner = Some(spawn_origin(&origin_identity).await?);
                    origin_owner
                        .as_ref()
                        .ok_or("missing origin fixture")?
                        .address
                };
                client_owner = Some(client(profile, &origin_identity, &proxy_identity, proxy)?);
                let client = client_owner.as_ref().ok_or("missing client owner")?;
                get_forwarded(client, "first.test:8080").await?;
                get_https(client, origin).await?;
                get_forwarded(client, "second.test:8080").await?;

                let placement: Vec<(usize, u32)> = observe_log(log)?
                    .iter()
                    .map(|seen| (seen.connection, seen.stream))
                    .collect();
                if shared {
                    assert_eq!(placement, [(0, 1), (0, 3), (0, 5)]);
                } else {
                    // Forwarded requests to both origins share one connection;
                    // the tunnel has its own.
                    assert_eq!(placement, [(0, 3), (1, 3), (0, 5)]);
                }
                Ok(())
            }
            .await;

            let mut cleanup = Ok(());
            if let Some(proxy) = proxy_owner {
                cleanup = finish_with_cleanup(cleanup, proxy.finish().await);
            }
            if let Some(origin) = origin_owner {
                cleanup = finish_with_cleanup(cleanup, origin.finish().await);
            }
            finish_with_cleanup(operation, cleanup)?;
        }
        Ok(())
    })
    .await
}

/// With `max_http2_proxy_connections_per_route`, a tunnel that would wait
/// behind the proxy's stream limit opens another proxy connection instead.
#[tokio::test]
async fn opted_in_routes_open_another_connection_at_the_proxy_stream_limit() -> TestResult<()> {
    bounded(async {
        let mut proxy_owner = None;
        let mut client_owner = None;
        let mut origin_owners = Vec::new();
        let operation = async {
            let origin_identity = TestIdentity::generate()?;
            let proxy_identity = TestIdentity::generate()?;
            proxy_owner = Some(spawn_limited_proxy(&proxy_identity, Some(1)).await?);
            let fixture = proxy_owner.as_ref().ok_or("missing proxy fixture")?;
            let proxy = fixture.address;
            let log = &fixture.log;
            let origins = [
                {
                    origin_owners.push(spawn_origin(&origin_identity).await?);
                    origin_owners
                        .last()
                        .ok_or("missing origin fixture")?
                        .address
                },
                {
                    origin_owners.push(spawn_origin(&origin_identity).await?);
                    origin_owners
                        .last()
                        .ok_or("missing origin fixture")?
                        .address
                },
            ];
            client_owner = Some(
                Client::builder(chromium_profile())
                    .add_root_certificate_der(origin_identity.root_der.clone())
                    .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
                    .route(Route::http_proxy(
                        HttpProxy::new(&format!("https://{proxy}"))?.with_http2_transport()?,
                    ))
                    .max_http2_proxy_connections_per_route(NonZeroUsize::new(2).ok_or("0")?)
                    .build()?,
            );
            let client = client_owner.as_ref().ok_or("missing client owner")?;
            // Each origin connection keeps its tunnel open.
            for origin in origins {
                get_https(client, origin).await?;
            }
            let placement: Vec<(usize, u32)> = observe_log(log)?
                .iter()
                .map(|seen| (seen.connection, seen.stream))
                .collect();
            assert_eq!(placement, [(0, 1), (1, 1)]);
            Ok(())
        }
        .await;

        let mut cleanup = Ok(());
        if let Some(proxy) = proxy_owner {
            cleanup = finish_with_cleanup(cleanup, proxy.finish().await);
        }
        for origin in origin_owners {
            cleanup = finish_with_cleanup(cleanup, origin.finish().await);
        }
        finish_with_cleanup(operation, cleanup)
    })
    .await
}

/// A value above the pool's ceiling fails the build instead of being
/// lowered.
#[test]
fn a_proxy_connection_maximum_above_the_ceiling_fails_the_build() -> TestResult<()> {
    let ceiling = phantom_net::proxy::HTTP2_PROXY_CONNECTIONS_PER_ROUTE_CEILING;
    Client::builder(chromium_profile())
        .max_http2_proxy_connections_per_route(NonZeroUsize::new(ceiling).ok_or("0")?)
        .build()?;
    let error = match Client::builder(chromium_profile())
        .max_http2_proxy_connections_per_route(NonZeroUsize::new(ceiling + 1).ok_or("0")?)
        .build()
    {
        Ok(_) => return Err("a maximum above the ceiling was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);
    Ok(())
}

/// A client keeps its own proxy connections, as it keeps its own pools.
#[tokio::test]
async fn separately_built_clients_never_share_a_proxy_connection() -> TestResult<()> {
    bounded(async {
        let mut proxy_owner = None;
        let mut first_owner = None;
        let mut second_owner = None;
        let mut origin_owner = None;
        let operation = async {
            let origin_identity = TestIdentity::generate()?;
            let proxy_identity = TestIdentity::generate()?;
            proxy_owner = Some(spawn_proxy(&proxy_identity).await?);
            let fixture = proxy_owner.as_ref().ok_or("missing proxy fixture")?;
            let proxy = fixture.address;
            let log = &fixture.log;
            let origin = {
                origin_owner = Some(spawn_origin(&origin_identity).await?);
                origin_owner
                    .as_ref()
                    .ok_or("missing origin fixture")?
                    .address
            };
            first_owner = Some(client(
                chromium_profile(),
                &origin_identity,
                &proxy_identity,
                proxy,
            )?);
            second_owner = Some(client(
                chromium_profile(),
                &origin_identity,
                &proxy_identity,
                proxy,
            )?);
            get_https(first_owner.as_ref().ok_or("missing first client")?, origin).await?;
            get_https(
                second_owner.as_ref().ok_or("missing second client")?,
                origin,
            )
            .await?;
            let connections: Vec<usize> = observe_log(log)?
                .iter()
                .map(|seen| seen.connection)
                .collect();
            assert_eq!(connections, [0, 1]);
            Ok(())
        }
        .await;

        let mut cleanup = Ok(());
        if let Some(proxy) = proxy_owner {
            cleanup = finish_with_cleanup(cleanup, proxy.finish().await);
        }
        if let Some(origin) = origin_owner {
            cleanup = finish_with_cleanup(cleanup, origin.finish().await);
        }
        finish_with_cleanup(operation, cleanup)
    })
    .await
}

/// A `ws://` opening joins the tunnel connection with the Chromium recipe
/// and opens its own with the Firefox recipe, as Chrome 154 and Firefox 157
/// do in the `https-proxy-hostname` captures, where each Firefox connection
/// starts at stream 3.
#[cfg(feature = "websocket")]
#[tokio::test]
async fn websocket_tunnels_use_the_connection_the_profile_gives_them() -> TestResult<()> {
    bounded(async {
        for (profile, shared) in [(chromium_profile(), true), (firefox_profile(), false)] {
            let mut proxy_owner = None;
            let mut client_owner = None;
            let mut origin_owner = None;
            let mut websocket_owner = None;
            let operation = async {
                let origin_identity = TestIdentity::generate()?;
                let proxy_identity = TestIdentity::generate()?;
                proxy_owner = Some(spawn_proxy(&proxy_identity).await?);
                let fixture = proxy_owner.as_ref().ok_or("missing proxy fixture")?;
                let proxy = fixture.address;
                let log = &fixture.log;
                let origin = {
                    origin_owner = Some(spawn_origin(&origin_identity).await?);
                    origin_owner
                        .as_ref()
                        .ok_or("missing origin fixture")?
                        .address
                };
                let websocket_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
                let websocket_origin = websocket_listener.local_addr()?;
                websocket_owner = Some(ConnectionPeer::spawn(
                    websocket_origin::serve_plaintext_h1_echo(websocket_listener),
                ));
                client_owner = Some(client(profile, &origin_identity, &proxy_identity, proxy)?);
                let client = client_owner.as_ref().ok_or("missing client owner")?;
                get_https(client, origin).await?;
                let mut socket = client
                    .websocket(&format!("ws://{websocket_origin}/socket"))?
                    .connect()
                    .await?;
                socket
                    .send(phantom::WebSocketMessage::Text("hello".into()))
                    .await?;
                assert_eq!(
                    socket.receive().await?,
                    phantom::WebSocketMessage::Text("echo:hello".into())
                );
                let close = phantom::WebSocketCloseFrame::new(1000, "done")?;
                socket.close(Some(close)).await?;
                socket.receive().await?;
                // The origin reads until the tunnel ends.
                drop(socket);
                finish_websocket_exchange(
                    Ok(()),
                    websocket_owner.take().ok_or("missing WebSocket owner")?,
                )
                .await?;
                get_https(client, origin).await?;

                let placement: Vec<(usize, u32, String)> = observe_log(log)?
                    .iter()
                    .map(|seen| (seen.connection, seen.stream, seen.authority.clone()))
                    .collect();
                let (first, websocket_placement) = if shared { (1, (0, 3)) } else { (3, (1, 3)) };
                assert_eq!(
                    placement,
                    [
                        (0, first, origin.to_string()),
                        (
                            websocket_placement.0,
                            websocket_placement.1,
                            websocket_origin.to_string()
                        ),
                    ],
                    "the second https request reuses its pooled origin connection"
                );
                Ok(())
            }
            .await;

            let mut cleanup = Ok(());
            cleanup = finish_with_cleanup(cleanup, stop_optional(websocket_owner).await);
            if let Some(proxy) = proxy_owner {
                cleanup = finish_with_cleanup(cleanup, proxy.finish().await);
            }
            if let Some(origin) = origin_owner {
                cleanup = finish_with_cleanup(cleanup, origin.finish().await);
            }
            finish_with_cleanup(operation, cleanup)?;
        }
        Ok(())
    })
    .await
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|elapsed| MultiplexDeadline { elapsed })?
}

#[derive(Debug)]
struct MultiplexDeadline {
    elapsed: tokio::time::error::Elapsed,
}

impl std::fmt::Display for MultiplexDeadline {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HTTP/2 proxy multiplexing test exceeded its deadline")
    }
}

impl StdError for MultiplexDeadline {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.elapsed)
    }
}
