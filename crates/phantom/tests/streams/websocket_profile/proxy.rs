//! Profile-policy WebSockets on proxy routes.
//!
//! Under `WebSocketProxiedSession::Reuse`, which both recipes set, a WebSocket
//! joins the HTTP/2 session that an ordinary request opened through the same
//! proxy route, so the proxy sees no second tunnel. Under `Ignore` it opens a
//! tunnel of its own. No retained capture opens a `wss://` WebSocket through
//! a proxy, so the extended CONNECT is compared with the direct `accept`
//! capture: the session's encoding does not depend on the tunnel beneath it.

use std::{
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::Arc,
    time::Duration,
};

use http::Version;
use phantom::{
    Client, ClientBuilder, HttpProxy, Route, Socks5Proxy,
    profile::{
        ClientProfile, WebSocketProxiedSession,
        browser::{chrome, firefox},
    },
};
use tokio::{net::TcpListener, task::JoinHandle};

use super::{
    Behavior, CHROME_ACCEPT, Capture, FIREFOX_ACCEPT, PooledSession, Reply, TestResult, TestServer,
    assert_websocket_joins_the_session, bounded, close_gracefully, exchange, methods,
    pooled_get_at,
};
use crate::support::tls::{H1_ALPN, H2_ALPN, TestIdentity, tls_settings};
use crate::support::tunnel_proxy::{self, Http2ConnectRecord, Socks5Target};
use crate::support::websocket_origin::header_value;

/// A name, so a SOCKS5 proxy with remote resolution receives a domain.
const ORIGIN_NAME: &str = "localhost";
const ALICE: &str = "Basic YWxpY2U6c2VjcmV0";
const BOB: &str = "Basic Ym9iOnNlY3JldA==";

#[tokio::test]
async fn chromium_websocket_joins_a_session_tunnelled_through_an_http_proxy() -> TestResult<()> {
    assert_joins_through(Recipe::Chromium, Tunnel::Http1, true).await
}

#[tokio::test]
async fn chromium_websocket_joins_a_session_tunnelled_through_an_https_proxy() -> TestResult<()> {
    assert_joins_through(Recipe::Chromium, Tunnel::Https1, true).await
}

#[tokio::test]
async fn chromium_websocket_joins_a_session_tunnelled_through_an_http2_proxy() -> TestResult<()> {
    assert_joins_through(Recipe::Chromium, Tunnel::Http2, true).await
}

#[tokio::test]
async fn chromium_websocket_joins_a_session_through_socks5_with_local_dns() -> TestResult<()> {
    assert_joins_through(Recipe::Chromium, Tunnel::Socks5LocalDns, true).await
}

#[tokio::test]
async fn chromium_websocket_joins_a_session_through_socks5_with_remote_dns() -> TestResult<()> {
    assert_joins_through(Recipe::Chromium, Tunnel::Socks5RemoteDns, true).await
}

#[tokio::test]
async fn chromium_websocket_joins_an_exact_http2_session_through_a_proxy() -> TestResult<()> {
    assert_joins_through(Recipe::Chromium, Tunnel::Http1, false).await
}

#[tokio::test]
async fn firefox_websocket_joins_a_session_tunnelled_through_an_http_proxy() -> TestResult<()> {
    assert_joins_through(Recipe::Firefox, Tunnel::Http1, true).await
}

#[tokio::test]
async fn firefox_websocket_joins_a_session_tunnelled_through_an_https_proxy() -> TestResult<()> {
    assert_joins_through(Recipe::Firefox, Tunnel::Https1, true).await
}

#[tokio::test]
async fn firefox_websocket_joins_a_session_tunnelled_through_an_http2_proxy() -> TestResult<()> {
    assert_joins_through(Recipe::Firefox, Tunnel::Http2, true).await
}

#[tokio::test]
async fn firefox_websocket_joins_a_session_through_socks5_with_local_dns() -> TestResult<()> {
    assert_joins_through(Recipe::Firefox, Tunnel::Socks5LocalDns, true).await
}

#[tokio::test]
async fn firefox_websocket_joins_a_session_through_socks5_with_remote_dns() -> TestResult<()> {
    assert_joins_through(Recipe::Firefox, Tunnel::Socks5RemoteDns, true).await
}

#[tokio::test]
async fn firefox_websocket_joins_an_exact_http2_session_through_a_proxy() -> TestResult<()> {
    assert_joins_through(Recipe::Firefox, Tunnel::Http1, false).await
}

#[tokio::test]
async fn websocket_on_a_challenged_http1_tunnel_sends_no_connect_or_credentials() -> TestResult<()>
{
    bounded(async {
        let (identity, server) = start_origin(Behavior::ACCEPT).await?;
        let listener = bind().await?;
        let address = listener.local_addr()?;
        let origin = server.address;
        let task = tokio::spawn(async move {
            let heads = tunnel_proxy::http1_challenge_then_connect_on(&listener, origin).await?;
            TestResult::<_>::Ok((heads, listener))
        });
        let route = Route::http_proxy(
            HttpProxy::new(&format!("http://{address}"))?.with_basic_auth("alice", "secret")?,
        );
        let client = client_on(Recipe::Chromium.profile(), &identity, route, None).build()?;

        Recipe::Chromium
            .assert_joins(&client, &server, &origin.to_string(), true)
            .await?;

        let ((anonymous, authorized, _), listener) = task.await??;
        assert_eq!(header_value(&anonymous, "proxy-authorization"), None);
        assert_eq!(
            header_value(&authorized, "proxy-authorization"),
            Some(ALICE)
        );
        assert!(
            tunnel_proxy::no_connection_arrives(&listener).await,
            "the WebSocket opened another proxy connection"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn websocket_on_a_challenged_http2_tunnel_sends_no_connect_or_credentials() -> TestResult<()>
{
    bounded(async {
        let (identity, server) = start_origin(Behavior::ACCEPT).await?;
        let proxy_identity = TestIdentity::generate()?;
        let acceptor = proxy_identity.acceptor(H2_ALPN)?;
        let listener = bind().await?;
        let address = listener.local_addr()?;
        let origin = server.address;
        let task = tokio::spawn(async move {
            let (records, late) =
                tunnel_proxy::http2_challenge_then_connect_on(&listener, acceptor, origin).await?;
            TestResult::<_>::Ok((records, late, listener))
        });
        let route = Route::http_proxy(
            HttpProxy::new(&format!("https://{address}"))?
                .with_basic_auth("alice", "secret")?
                .with_http2_transport()?,
        );
        let client = client_on(
            Recipe::Chromium.profile(),
            &identity,
            route,
            Some(proxy_identity.root_der.clone()),
        )
        .build()?;

        Recipe::Chromium
            .assert_joins(&client, &server, &origin.to_string(), true)
            .await?;

        let (records, late, listener) = task.await??;
        let sent: Vec<_> = records
            .iter()
            .map(|record| (record.stream_id, proxy_authorization(record)))
            .collect();
        assert_eq!(sent, [(1, None), (3, Some(ALICE.as_bytes().to_vec()))]);
        let late: Vec<_> = late
            .lock()
            .map_err(|_| "late CONNECT log poisoned")?
            .iter()
            .map(|record| record.stream_id)
            .collect();
        assert!(
            late.is_empty(),
            "the WebSocket sent proxy CONNECT streams {late:?}"
        );
        assert!(
            tunnel_proxy::no_connection_arrives(&listener).await,
            "the WebSocket opened another proxy connection"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn websocket_with_other_proxy_credentials_opens_its_own_tunnel() -> TestResult<()> {
    bounded(async {
        let (identity, server) = start_origin(Behavior::ACCEPT).await?;
        let listener = bind().await?;
        let address = listener.local_addr()?;
        let origin = server.address;
        let task = tokio::spawn(async move {
            let (_, alice, _) =
                tunnel_proxy::http1_challenge_then_connect_on(&listener, origin).await?;
            let (_, bob, _) =
                tunnel_proxy::http1_challenge_then_connect_on(&listener, origin).await?;
            TestResult::<_>::Ok(([alice, bob], listener))
        });
        let proxy = HttpProxy::new(&format!("http://{address}"))?;
        let alice = Route::http_proxy(proxy.clone().with_basic_auth("alice", "secret")?);
        let bob = Route::http_proxy(proxy.with_basic_auth("bob", "secret")?);
        let client = client_on(Recipe::Chromium.profile(), &identity, alice, None).build()?;

        pooled_get_at(&client, origin, true).await?;
        let socket = client
            .websocket_with_profile_policy(&format!("wss://{origin}/echo"))?
            .route(bob)
            .connect()
            .await?;
        // Without a session on its own route, the recipe upgrades a new
        // connection.
        assert_eq!(socket.handshake_response().version(), Version::HTTP_11);
        exchange(socket).await?;

        let (heads, listener) = task.await??;
        for head in &heads {
            assert!(head.starts_with(format!("CONNECT {origin} HTTP/1.1\r\n").as_bytes()));
        }
        let [alice, bob] = heads;
        assert_eq!(header_value(&alice, "proxy-authorization"), Some(ALICE));
        assert_eq!(header_value(&bob, "proxy-authorization"), Some(BOB));
        assert!(tunnel_proxy::no_connection_arrives(&listener).await);
        let connections = server.connections()?;
        assert_eq!(connections.len(), 2);
        assert_eq!(methods(&connections[0]), ["GET"]);
        assert_eq!(connections[1].h1.len(), 1);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn chromium_websocket_beside_an_incapable_proxied_session_upgrades_through_a_new_tunnel()
-> TestResult<()> {
    for negotiated in [true, false] {
        bounded(async {
            let behavior = Behavior {
                connect_protocol: false,
                ..Behavior::ACCEPT
            };
            let (identity, server) = start_origin(behavior).await?;
            let listener = bind().await?;
            let address = listener.local_addr()?;
            let origin = server.address;
            let task = tokio::spawn(async move {
                let first = tunnel_proxy::http1_connect_on(&listener, origin).await?;
                let second = tunnel_proxy::http1_connect_on(&listener, origin).await?;
                TestResult::<_>::Ok(([first, second], listener))
            });
            let route = Route::http_proxy(HttpProxy::new(&format!("http://{address}"))?);
            let client = client_on(Recipe::Chromium.profile(), &identity, route, None).build()?;

            pooled_get_at(&client, origin, negotiated).await?;
            let socket = client
                .websocket_with_profile_policy(&format!("wss://{origin}/echo"))?
                .connect()
                .await?;
            // The session's peer did not enable extended CONNECT, so the
            // recipe upgrades a new connection through a tunnel of its own.
            assert_eq!(socket.handshake_response().version(), Version::HTTP_11);
            exchange(socket).await?;

            let (heads, listener) = task.await??;
            for head in heads {
                assert!(head.starts_with(format!("CONNECT {origin} HTTP/1.1\r\n").as_bytes()));
            }
            assert!(tunnel_proxy::no_connection_arrives(&listener).await);
            let connections = server.connections()?;
            assert_eq!(connections.len(), 2, "negotiated: {negotiated}");
            assert_eq!(connections[0].protocol.as_deref(), Some("h2"));
            assert_eq!(
                methods(&connections[0]),
                ["GET"],
                "CONNECT reached an incapable session"
            );
            assert_eq!(connections[1].protocol.as_deref(), Some("http/1.1"));
            assert_eq!(connections[1].h1.len(), 1);
            Ok(())
        })
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn ignore_policy_opens_its_own_tunnel_beside_a_proxied_session() -> TestResult<()> {
    for negotiated in [true, false] {
        bounded(async {
            let (identity, server) = start_origin(Behavior::ACCEPT).await?;
            let listener = bind().await?;
            let address = listener.local_addr()?;
            let origin = server.address;
            let task = tokio::spawn(async move {
                let first = tunnel_proxy::http1_connect_on(&listener, origin).await?;
                let second = tunnel_proxy::http1_connect_on(&listener, origin).await?;
                TestResult::<_>::Ok(([first, second], listener))
            });
            let route = Route::http_proxy(HttpProxy::new(&format!("http://{address}"))?);
            let mut websocket = firefox::v157_websocket();
            websocket.connection.proxied_http2_session = WebSocketProxiedSession::Ignore;
            let profile = Recipe::Firefox.profile().with_websocket(websocket);
            let client = client_on(profile, &identity, route, None).build()?;

            pooled_get_at(&client, origin, negotiated).await?;
            let socket = client
                .websocket_with_profile_policy(&format!("wss://{origin}/echo"))?
                .connect()
                .await?;
            // With no session to use, Firefox's recipe opens a new HTTP/2
            // connection.
            assert_eq!(socket.handshake_response().version(), Version::HTTP_2);
            exchange(socket).await?;

            let (heads, listener) = task.await??;
            for head in heads {
                assert!(head.starts_with(format!("CONNECT {origin} HTTP/1.1\r\n").as_bytes()));
            }
            assert!(tunnel_proxy::no_connection_arrives(&listener).await);
            let connections = server.connections()?;
            assert_eq!(connections.len(), 2, "negotiated: {negotiated}");
            assert_eq!(methods(&connections[0]), ["GET"]);
            assert_eq!(methods(&connections[1]), ["CONNECT"]);
            Ok(())
        })
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn refused_connect_stream_reopens_once_on_the_proxied_session() -> TestResult<()> {
    bounded(async {
        let behavior = Behavior {
            connect: Reply::RefuseFirstStream,
            ..Behavior::ACCEPT
        };
        let (identity, server) = start_origin(behavior).await?;
        let origin = server.address;
        let proxy = Tunnel::Http1.start(origin).await?;
        let client = client_on(
            Recipe::Chromium.profile(),
            &identity,
            proxy.route.clone(),
            None,
        )
        .build()?;

        pooled_get_at(&client, origin, true).await?;
        let socket = client
            .websocket_with_profile_policy(&format!("wss://{origin}/echo"))?
            .connect()
            .await?;
        assert_eq!(socket.handshake_response().status(), 200);

        proxy.assert_one_tunnel(origin).await?;
        let connections = server.connections()?;
        assert_eq!(connections.len(), 1, "the reopening left the session");
        assert_eq!(methods(&connections[0]), ["GET", "CONNECT", "CONNECT"]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn proxied_websocket_counts_against_origin_admission() -> TestResult<()> {
    bounded(async {
        let (identity, server) = start_origin(Behavior::ACCEPT).await?;
        let origin = server.address;
        let proxy = Tunnel::Http1.start(origin).await?;
        let client = client_on(
            Recipe::Chromium.profile(),
            &identity,
            proxy.route.clone(),
            None,
        )
        .max_concurrent_http2_requests_per_origin(NonZeroUsize::MIN)
        .max_pending_http2_requests_per_origin(NonZeroUsize::MIN)
        .build()?;

        pooled_get_at(&client, origin, true).await?;
        let mut socket = client
            .websocket_with_profile_policy(&format!("wss://{origin}/echo"))?
            .connect()
            .await?;
        // With one active slot per origin, the open WebSocket holds it.
        let waiting = tokio::spawn({
            let client = client.clone();
            async move {
                pooled_get_at(&client, origin, true)
                    .await
                    .map_err(|error| error.to_string())
            }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !waiting.is_finished(),
            "request bypassed the WebSocket's admission"
        );

        close_gracefully(&mut socket).await?;
        waiting.await??;
        proxy.assert_one_tunnel(origin).await?;
        assert_eq!(
            methods(&server.connections()?[0]),
            ["GET", "CONNECT", "GET"]
        );
        Ok(())
    })
    .await
}

/// A proxy that tunnels to the origin.
#[derive(Clone, Copy, Debug)]
enum Tunnel {
    Http1,
    Https1,
    Http2,
    Socks5LocalDns,
    Socks5RemoteDns,
}

/// What a proxy saw for its one tunnel.
#[derive(Debug)]
enum Served {
    Http1(Vec<u8>),
    Http2(Http2ConnectRecord),
    Socks5(Socks5Target, u16),
}

/// A running proxy that serves one tunnel and then keeps its listener, so a
/// test can check that nothing else connected.
struct Proxy {
    tunnel: Tunnel,
    route: Route,
    root: Option<Vec<u8>>,
    task: JoinHandle<TestResult<(Served, TcpListener)>>,
}

impl Tunnel {
    async fn start(self, origin: SocketAddr) -> TestResult<Proxy> {
        let listener = bind().await?;
        let address = listener.local_addr()?;
        let identity = TestIdentity::generate()?;
        let (route, root, task) = match self {
            Self::Http1 => (
                Route::http_proxy(HttpProxy::new(&format!("http://{address}"))?),
                None,
                tokio::spawn(async move {
                    let head = tunnel_proxy::http1_connect_on(&listener, origin).await?;
                    Ok((Served::Http1(head), listener))
                }),
            ),
            Self::Https1 => {
                let acceptor = identity.acceptor(H1_ALPN)?;
                (
                    Route::http_proxy(HttpProxy::new(&format!("https://{address}"))?),
                    Some(identity.root_der.clone()),
                    tokio::spawn(async move {
                        let head =
                            tunnel_proxy::https1_connect_on(&listener, acceptor, origin).await?;
                        Ok((Served::Http1(head), listener))
                    }),
                )
            }
            Self::Http2 => {
                let acceptor = identity.acceptor(H2_ALPN)?;
                (
                    Route::http_proxy(
                        HttpProxy::new(&format!("https://{address}"))?.with_http2_transport()?,
                    ),
                    Some(identity.root_der.clone()),
                    tokio::spawn(async move {
                        let record =
                            tunnel_proxy::http2_connect_on(&listener, acceptor, origin).await?;
                        Ok((Served::Http2(record), listener))
                    }),
                )
            }
            Self::Socks5LocalDns | Self::Socks5RemoteDns => {
                let scheme = if matches!(self, Self::Socks5LocalDns) {
                    "socks5"
                } else {
                    "socks5h"
                };
                (
                    Route::socks5(Socks5Proxy::new(&format!("{scheme}://{address}"))?),
                    None,
                    tokio::spawn(async move {
                        let (target, port) =
                            tunnel_proxy::socks5_connect_on(&listener, origin).await?;
                        Ok((Served::Socks5(target, port), listener))
                    }),
                )
            }
        };
        Ok(Proxy {
            tunnel: self,
            route,
            root,
            task,
        })
    }

    /// The `host:port` the client asks for: a name for SOCKS5, so remote
    /// resolution sends it, and the origin's address otherwise.
    fn authority(self, origin: SocketAddr) -> String {
        match self {
            Self::Socks5LocalDns | Self::Socks5RemoteDns => {
                format!("{ORIGIN_NAME}:{}", origin.port())
            }
            Self::Http1 | Self::Https1 | Self::Http2 => origin.to_string(),
        }
    }
}

impl Proxy {
    /// Checks the tunnel's one CONNECT and that no other connection arrived.
    ///
    /// A second CONNECT stream on an HTTP/2 proxy connection is reset by the
    /// proxy, so it would already have failed the WebSocket.
    async fn assert_one_tunnel(self, origin: SocketAddr) -> TestResult<()> {
        let authority = self.tunnel.authority(origin);
        let (served, listener) = self.task.await??;
        match (self.tunnel, served) {
            (Tunnel::Http1 | Tunnel::Https1, Served::Http1(head)) => {
                assert!(head.starts_with(format!("CONNECT {authority} HTTP/1.1\r\n").as_bytes()));
            }
            (Tunnel::Http2, Served::Http2(record)) => {
                assert_eq!(record.authority.as_deref(), Some(authority.as_str()));
            }
            (Tunnel::Socks5LocalDns, Served::Socks5(Socks5Target::Ip(address), port)) => {
                assert!(address.is_loopback());
                assert_eq!(port, origin.port());
            }
            (Tunnel::Socks5RemoteDns, Served::Socks5(Socks5Target::Domain(name), port)) => {
                assert_eq!(name, ORIGIN_NAME);
                assert_eq!(port, origin.port());
            }
            (tunnel, served) => {
                return Err(format!("{tunnel:?} proxy served {served:?}").into());
            }
        }
        assert!(
            tunnel_proxy::no_connection_arrives(&listener).await,
            "the WebSocket opened another {:?} proxy connection",
            self.tunnel
        );
        Ok(())
    }
}

/// Sends a GET through the negotiated or the exact HTTP/2 pool and then a
/// profile-policy WebSocket through `tunnel`, and checks that the WebSocket
/// joined the GET's session without a second tunnel.
async fn assert_joins_through(recipe: Recipe, tunnel: Tunnel, negotiated: bool) -> TestResult<()> {
    bounded(async {
        let (identity, server) = start_origin(Behavior::ACCEPT).await?;
        let proxy = tunnel.start(server.address).await?;
        let client = client_on(
            recipe.profile(),
            &identity,
            proxy.route.clone(),
            proxy.root.clone(),
        )
        .build()?;
        let authority = tunnel.authority(server.address);
        recipe
            .assert_joins(&client, &server, &authority, negotiated)
            .await?;
        proxy.assert_one_tunnel(server.address).await
    })
    .await
}

/// A named recipe family whose WebSocket recipe sets `Reuse`.
#[derive(Clone, Copy, Debug)]
enum Recipe {
    Chromium,
    Firefox,
}

impl Recipe {
    /// The family's recipes, with its proxy CONNECT recipe, which shapes the
    /// CONNECT fields without changing a route's pool identity.
    fn profile(self) -> ClientProfile {
        let profile = ClientProfile::new(tls_settings());
        match self {
            Self::Chromium => profile
                .with_http2(chrome::v154_http2())
                .with_websocket(chrome::v154_websocket())
                .with_proxy_connect(chrome::v154_proxy_connect()),
            Self::Firefox => profile
                .with_http2(firefox::v157_http2())
                .with_websocket(firefox::v157_websocket())
                .with_proxy_connect(firefox::v157_proxy_connect()),
        }
    }

    async fn assert_joins(
        self,
        client: &Client,
        server: &TestServer,
        authority: &str,
        negotiated: bool,
    ) -> TestResult<()> {
        let (capture, http2, websocket) = match self {
            Self::Chromium => (
                CHROME_ACCEPT,
                chrome::v154_http2(),
                chrome::v154_websocket(),
            ),
            Self::Firefox => (
                FIREFOX_ACCEPT,
                firefox::v157_http2(),
                firefox::v157_websocket(),
            ),
        };
        let session = PooledSession {
            authority,
            negotiated,
        };
        assert_websocket_joins_the_session(
            client,
            server,
            session,
            &Capture::parse(capture)?,
            &http2,
            &websocket,
        )
        .await
    }
}

/// Starts an origin whose certificate names both `127.0.0.1` and
/// [`ORIGIN_NAME`].
async fn start_origin(behavior: Behavior) -> TestResult<(Arc<TestIdentity>, TestServer)> {
    let identity = Arc::new(TestIdentity::generate_for_ip_and_dns(
        Ipv4Addr::LOCALHOST.into(),
        ORIGIN_NAME,
    )?);
    let server = TestServer::start(Arc::clone(&identity), behavior).await?;
    Ok((identity, server))
}

async fn bind() -> TestResult<TcpListener> {
    Ok(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?)
}

fn client_on(
    profile: ClientProfile,
    identity: &TestIdentity,
    route: Route,
    proxy_root: Option<Vec<u8>>,
) -> ClientBuilder {
    let builder = Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .route(route);
    match proxy_root {
        Some(root) => builder.add_proxy_root_certificate_der(root),
        None => builder,
    }
}

fn proxy_authorization(record: &Http2ConnectRecord) -> Option<Vec<u8>> {
    record
        .fields
        .iter()
        .find(|(name, _)| name == "proxy-authorization")
        .map(|(_, value)| value.clone())
}
