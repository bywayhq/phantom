//! CONNECT tunnels that share pooled HTTP/2 proxy connections, against a
//! frame-level proxy.

use std::{
    future::Future,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Poll,
    time::Duration,
};

use btls::ssl::SslAcceptor;
use phantom_profile::{chromium::v154_http2, firefox::v156_http2};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

use super::{
    http2_connect::bounded,
    http2_raw_proxy::{DATA, HEADERS, RST_STREAM, RawConnection, frame, goaway, response},
    https_connect::tls_settings,
};
use crate::{
    proxy::{
        HTTP2_PROXY_CONNECTIONS_PER_ROUTE_CEILING, Http2ProxyPool, HttpBasicCredentials,
        HttpConnectError, HttpConnectErrorKind, HttpConnectHeader, HttpsProxyConnector,
        HttpsProxyProtocol, MAX_HTTP2_PROXY_POOL_ROUTES, https_connect::HttpsProxyTunnel,
    },
    tls::test_support::{TEST_SERVER_NAME, TestIdentity, TestResult, TestServerAlpn},
};

/// SETTINGS_MAX_CONCURRENT_STREAMS.
const MAX_CONCURRENT_STREAMS: u16 = 0x3;
/// RST_STREAM error code CANCEL.
const CANCEL: [u8; 4] = [0, 0, 0, 8];
/// How long the proxy waits for a connection that must not come.
const NO_CONNECTION_WAIT: Duration = Duration::from_millis(300);

type ProxyResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Proxy {
    port: u16,
    listener: TcpListener,
    acceptor: SslAcceptor,
    identity: TestIdentity,
}

impl Proxy {
    fn bind() -> TestResult<Self> {
        let identity = TestIdentity::generate()?;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            port: listener.local_addr()?.port(),
            listener: TcpListener::from_std(listener)?,
            acceptor: identity.acceptor(TestServerAlpn::H2)?,
            identity,
        })
    }

    fn connector(&self) -> TestResult<HttpsProxyConnector> {
        Ok(HttpsProxyConnector::new_with_additional_roots(
            &tls_settings(),
            [self.identity.root_der()],
        )?
        .with_http2_settings(&v154_http2())
        .with_protocol(HttpsProxyProtocol::Http2))
    }
}

/// Accepts the next proxy connection, announcing `settings`.
async fn accept(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
    settings: &[(u16, u32)],
) -> ProxyResult<RawConnection> {
    RawConnection::accept(listener, acceptor, settings)
        .await
        .map_err(|error| error.to_string().into())
}

/// Answers the CONNECT on `stream` with `200` and echoes its first DATA.
async fn serve_tunnel(connection: &mut RawConnection, stream: u32) -> ProxyResult<()> {
    let result = async {
        connection
            .read_until(|frame| frame.kind == HEADERS && frame.stream == stream)
            .await?;
        connection.write(&[response(stream, 200, false)]).await?;
        connection.echo(stream).await
    }
    .await;
    result.map_err(|error| error.to_string().into())
}

/// Answers every CONNECT with `200` and echoes every DATA payload, until
/// `echoes` payloads are echoed or the client closes the connection.
async fn serve_all(mut connection: RawConnection, echoes: usize) -> ProxyResult<RawConnection> {
    let mut echoed = 0;
    while echoed < echoes {
        let Some(received) = connection
            .read_frame()
            .await
            .map_err(|error| error.to_string())?
        else {
            break;
        };
        let reply = match received.kind {
            HEADERS => response(received.stream, 200, false),
            DATA if !received.payload.is_empty() => {
                echoed += 1;
                frame(DATA, 0, received.stream, &received.payload)
            }
            _ => continue,
        };
        connection
            .write(&[reply])
            .await
            .map_err(|error| error.to_string())?;
    }
    Ok(connection)
}

/// Polls `future` once, so it starts; fails if it already finished.
async fn start<F: Future>(future: &mut Pin<Box<F>>) -> TestResult<()> {
    let finished =
        std::future::poll_fn(|context| Poll::Ready(future.as_mut().poll(context).is_ready())).await;
    if finished {
        return Err("the tunnel finished before the proxy answered".into());
    }
    Ok(())
}

/// Reports whether the client reset `ended` before it sent the HEADERS that
/// open `opened`.
fn ends_before_opens(connection: &RawConnection, ended: u32, opened: u32) -> bool {
    let position = |kind: u8, stream: u32| {
        connection
            .frames
            .iter()
            .position(|frame| frame.kind == kind && frame.stream == stream)
    };
    matches!(
        (position(RST_STREAM, ended), position(HEADERS, opened)),
        (Some(reset), Some(headers)) if reset < headers
    )
}

/// Fails unless no further connection arrives.
async fn expect_no_connection(listener: &TcpListener) -> ProxyResult<()> {
    match timeout(NO_CONNECTION_WAIT, listener.accept()).await {
        Err(_) => Ok(()),
        Ok(_) => Err("the client opened another proxy connection".into()),
    }
}

async fn open(
    connector: &HttpsProxyConnector,
    port: u16,
    origin: &str,
) -> TestResult<HttpsProxyTunnel> {
    Ok(connector
        .connect_tunnel(
            "127.0.0.1",
            port,
            TEST_SERVER_NAME,
            origin,
            &[HttpConnectHeader::authority("Host")],
        )
        .await?)
}

async fn open_with_credentials(
    connector: &HttpsProxyConnector,
    port: u16,
    origin: &str,
    credentials: &HttpBasicCredentials,
) -> TestResult<HttpsProxyTunnel> {
    Ok(connector
        .connect_tunnel_with_basic_auth(
            "127.0.0.1",
            port,
            TEST_SERVER_NAME,
            origin,
            &[
                HttpConnectHeader::authority("Host"),
                HttpConnectHeader::proxy_authorization("Proxy-Authorization"),
            ],
            credentials,
        )
        .await?)
}

async fn ping(tunnel: &mut HttpsProxyTunnel) -> TestResult<()> {
    tunnel.write_all(b"ping").await?;
    let mut echoed = [0_u8; 4];
    tunnel.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"ping");
    Ok(())
}

/// Tunnels to three origins become streams 1, 3, and 5 of one proxy
/// connection, as Chrome 154 numbers a page's CONNECTs in the
/// `https-proxy-secure-hostname` captures; Firefox 156 shares its
/// connection the same way but starts at stream 3.
#[tokio::test]
async fn tunnels_to_different_origins_share_one_connection() -> TestResult<()> {
    bounded(async {
        let proxy = Proxy::bind()?;
        let connector = proxy
            .connector()?
            .with_http2_proxy_pool(Http2ProxyPool::new());
        let port = proxy.port;
        let server = tokio::spawn(async move {
            let mut connection = accept(&proxy.listener, &proxy.acceptor, &[]).await?;
            for stream in [1, 3, 5] {
                serve_tunnel(&mut connection, stream).await?;
            }
            expect_no_connection(&proxy.listener).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(connection)
        });

        let mut tunnels = Vec::new();
        for origin in ["a.example:443", "b.example:443", "c.example:8443"] {
            let mut tunnel = open(&connector, port, origin).await?;
            ping(&mut tunnel).await?;
            tunnels.push(tunnel);
        }
        let connection = server.await??;
        let streams: Vec<u32> = connection
            .frames
            .iter()
            .filter(|frame| frame.kind == HEADERS)
            .map(|frame| frame.stream)
            .collect();
        assert_eq!(streams, [1, 3, 5]);
        Ok(())
    })
    .await
}

/// With the default pool, tunnels past the proxy's
/// `SETTINGS_MAX_CONCURRENT_STREAMS` wait on the route's one connection, as
/// browsers queue streams on their proxy session: the third CONNECT's
/// HEADERS reaches the proxy on the same connection only after a tunnel
/// there ends.
#[tokio::test]
async fn the_proxy_stream_limit_queues_later_tunnels_on_the_same_connection() -> TestResult<()> {
    bounded(async {
        let proxy = Proxy::bind()?;
        let connector = proxy
            .connector()?
            .with_http2_proxy_pool(Http2ProxyPool::new());
        let port = proxy.port;
        let server = tokio::spawn(async move {
            let settings = [(MAX_CONCURRENT_STREAMS, 2)];
            let mut connection = accept(&proxy.listener, &proxy.acceptor, &settings).await?;
            serve_tunnel(&mut connection, 1).await?;
            serve_tunnel(&mut connection, 3).await?;
            serve_tunnel(&mut connection, 5).await?;
            expect_no_connection(&proxy.listener).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(connection)
        });

        let mut first = open(&connector, port, "a.example:443").await?;
        ping(&mut first).await?;
        let mut second = open(&connector, port, "b.example:443").await?;
        ping(&mut second).await?;
        let mut third = Box::pin(open(&connector, port, "c.example:443"));
        start(&mut third).await?;
        drop(first);
        let mut third = third.await?;
        ping(&mut third).await?;
        let connection = server.await??;
        assert!(
            ends_before_opens(&connection, 1, 5),
            "stream 5 opened before stream 1 ended"
        );
        drop(second);
        Ok(())
    })
    .await
}

/// With more connections allowed per route, a connection takes no more
/// tunnels than the proxy's `SETTINGS_MAX_CONCURRENT_STREAMS` and the next
/// tunnel opens another. At the ceiling, a tunnel waits on the least loaded
/// connection, and one that ends makes room there.
#[tokio::test]
async fn an_opted_in_route_opens_connections_up_to_its_ceiling() -> TestResult<()> {
    bounded(async {
        let proxy = Proxy::bind()?;
        let pool = Http2ProxyPool::with_max_connections_per_route(NonZeroUsize::new(2).ok_or("0")?);
        assert_eq!(pool.max_connections_per_route().get(), 2);
        let connector = proxy.connector()?.with_http2_proxy_pool(pool);
        let port = proxy.port;
        let server = tokio::spawn(async move {
            let settings = [(MAX_CONCURRENT_STREAMS, 2)];
            let mut first = accept(&proxy.listener, &proxy.acceptor, &settings).await?;
            serve_tunnel(&mut first, 1).await?;
            serve_tunnel(&mut first, 3).await?;
            let mut second = accept(&proxy.listener, &proxy.acceptor, &settings).await?;
            serve_tunnel(&mut second, 1).await?;
            serve_tunnel(&mut second, 3).await?;
            serve_tunnel(&mut first, 5).await?;
            expect_no_connection(&proxy.listener).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(first)
        });

        let mut tunnels = Vec::new();
        for origin in [
            "a.example:443",
            "b.example:443",
            "c.example:443",
            "d.example:443",
        ] {
            let mut tunnel = open(&connector, port, origin).await?;
            ping(&mut tunnel).await?;
            tunnels.push(tunnel);
        }
        let mut fifth = Box::pin(open(&connector, port, "e.example:443"));
        start(&mut fifth).await?;
        drop(tunnels.remove(0));
        let mut fifth = fifth.await?;
        ping(&mut fifth).await?;
        let first = server.await??;
        assert!(
            ends_before_opens(&first, 1, 5),
            "stream 5 opened before stream 1 ended"
        );
        // A request above the ceiling is lowered to it.
        let large = Http2ProxyPool::with_max_connections_per_route(NonZeroUsize::MAX);
        assert_eq!(
            large.max_connections_per_route().get(),
            HTTP2_PROXY_CONNECTIONS_PER_ROUTE_CEILING
        );
        Ok(())
    })
    .await
}

/// A rejected CONNECT gives its count back, so the connection takes the
/// next tunnel instead of an opted-in route opening another.
#[tokio::test]
async fn a_rejected_connect_gives_its_place_back() -> TestResult<()> {
    bounded(async {
        let proxy = Proxy::bind()?;
        let pool = Http2ProxyPool::with_max_connections_per_route(NonZeroUsize::new(2).ok_or("0")?);
        let connector = proxy.connector()?.with_http2_proxy_pool(pool);
        let port = proxy.port;
        let server = tokio::spawn(async move {
            let settings = [(MAX_CONCURRENT_STREAMS, 1)];
            let mut connection = accept(&proxy.listener, &proxy.acceptor, &settings).await?;
            connection
                .read_until(|frame| frame.kind == HEADERS && frame.stream == 1)
                .await
                .map_err(|error| error.to_string())?;
            connection
                .write(&[response(1, 403, true)])
                .await
                .map_err(|error| error.to_string())?;
            serve_tunnel(&mut connection, 3).await?;
            expect_no_connection(&proxy.listener).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let error = open(&connector, port, "a.example:443")
            .await
            .err()
            .ok_or("the proxy's 403 opened a tunnel")?;
        assert!(error.to_string().contains("403"), "{error}");
        let mut tunnel = open(&connector, port, "b.example:443").await?;
        ping(&mut tunnel).await?;
        server.await??;
        Ok(())
    })
    .await
}

/// Tunnels opened at once wait for the route's one connection setup and
/// share its connection.
#[tokio::test]
async fn concurrent_tunnels_wait_for_one_connection_setup() -> TestResult<()> {
    bounded(async {
        let proxy = Proxy::bind()?;
        let connector = proxy
            .connector()?
            .with_http2_proxy_pool(Http2ProxyPool::new());
        let port = proxy.port;
        let server = tokio::spawn(async move {
            let connection = accept(&proxy.listener, &proxy.acceptor, &[]).await?;
            let connection = serve_all(connection, 3).await?;
            expect_no_connection(&proxy.listener).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(connection)
        });

        let (first, second, third) = tokio::join!(
            open(&connector, port, "a.example:443"),
            open(&connector, port, "b.example:443"),
            open(&connector, port, "c.example:443"),
        );
        for mut tunnel in [first?, second?, third?] {
            ping(&mut tunnel).await?;
        }
        let connection = server.await??;
        let mut streams: Vec<u32> = connection
            .frames
            .iter()
            .filter(|frame| frame.kind == HEADERS)
            .map(|frame| frame.stream)
            .collect();
        streams.sort_unstable();
        assert_eq!(streams, [1, 3, 5]);
        Ok(())
    })
    .await
}

/// When the route's connection setup fails, the tunnels that waited for it
/// fail with the same kind of error instead of each connecting in turn.
#[tokio::test]
async fn a_failed_setup_fails_every_tunnel_that_waited_for_it() -> TestResult<()> {
    bounded(async {
        let proxy = Proxy::bind()?;
        let connector = proxy
            .connector()?
            .with_http2_proxy_pool(Http2ProxyPool::new());
        let port = proxy.port;
        let server = tokio::spawn(async move {
            // The proxy refuses TLS by closing the connection.
            let (tcp, _) = proxy.listener.accept().await?;
            drop(tcp);
            expect_no_connection(&proxy.listener).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let headers = [HttpConnectHeader::authority("Host")];
        let connect = |origin: &'static str| {
            connector.connect_tunnel("127.0.0.1", port, TEST_SERVER_NAME, origin, &headers)
        };
        let (first, second, third) = tokio::join!(
            connect("a.example:443"),
            connect("b.example:443"),
            connect("c.example:443"),
        );
        let errors = [first.err(), second.err(), third.err()];
        let errors: Vec<HttpConnectError> = errors.into_iter().flatten().collect();
        assert_eq!(errors.len(), 3, "a tunnel opened through a refusing proxy");
        let kinds: Vec<HttpConnectErrorKind> = errors.iter().map(HttpConnectError::kind).collect();
        assert!(kinds.iter().all(|kind| *kind == kinds[0]), "{kinds:?}");
        let waiters = errors
            .iter()
            .filter(|error| matches!(error, HttpConnectError::PooledSetupFailed { .. }))
            .count();
        assert_eq!(waiters, 2);
        server.await??;
        Ok(())
    })
    .await
}

/// A route the pool forgets, least recently used first, keeps its open
/// tunnel working; the next tunnel on that route opens a new connection.
#[tokio::test]
async fn forgetting_a_route_leaves_its_open_tunnel_working() -> TestResult<()> {
    bounded(async {
        let proxy = Proxy::bind()?;
        let connector = proxy
            .connector()?
            .with_http2_proxy_pool(Http2ProxyPool::new());
        let port = proxy.port;
        let accepted = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&accepted);
        let server = tokio::spawn(async move {
            loop {
                let connection = accept(&proxy.listener, &proxy.acceptor, &[]).await?;
                counted.fetch_add(1, Ordering::AcqRel);
                tokio::spawn(serve_all(connection, usize::MAX));
            }
            #[allow(unreachable_code)]
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        // Each set of credentials is its own route.
        let credentials =
            |index: usize| HttpBasicCredentials::new(format!("user{index}"), "secret");
        let mut first =
            open_with_credentials(&connector, port, "a.example:443", &credentials(0)?).await?;
        ping(&mut first).await?;
        for index in 1..=MAX_HTTP2_PROXY_POOL_ROUTES {
            let mut tunnel =
                open_with_credentials(&connector, port, "a.example:443", &credentials(index)?)
                    .await?;
            ping(&mut tunnel).await?;
        }
        assert_eq!(
            accepted.load(Ordering::Acquire),
            MAX_HTTP2_PROXY_POOL_ROUTES + 1
        );
        ping(&mut first).await?;
        let mut again =
            open_with_credentials(&connector, port, "b.example:443", &credentials(0)?).await?;
        ping(&mut again).await?;
        assert_eq!(
            accepted.load(Ordering::Acquire),
            MAX_HTTP2_PROXY_POOL_ROUTES + 2
        );
        server.abort();
        Ok(())
    })
    .await
}

/// Closing one tunnel and a proxy reset of another leave the rest of the
/// connection's tunnels working, and the connection takes new tunnels.
#[tokio::test]
async fn closing_or_resetting_one_tunnel_keeps_the_others() -> TestResult<()> {
    bounded(async {
        let proxy = Proxy::bind()?;
        let connector = proxy
            .connector()?
            .with_http2_proxy_pool(Http2ProxyPool::new());
        let port = proxy.port;
        let server = tokio::spawn(async move {
            let mut connection = accept(&proxy.listener, &proxy.acceptor, &[]).await?;
            for stream in [1, 3, 5] {
                serve_tunnel(&mut connection, stream).await?;
            }
            connection
                .write(&[frame(RST_STREAM, 0, 3, &CANCEL)])
                .await
                .map_err(|error| error.to_string())?;
            connection
                .read_until(|frame| frame.kind == RST_STREAM && frame.stream == 1)
                .await
                .map_err(|error| error.to_string())?;
            connection
                .echo(5)
                .await
                .map_err(|error| error.to_string())?;
            serve_tunnel(&mut connection, 7).await?;
            expect_no_connection(&proxy.listener).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let mut one = open(&connector, port, "a.example:443").await?;
        ping(&mut one).await?;
        let mut two = open(&connector, port, "b.example:443").await?;
        ping(&mut two).await?;
        let mut three = open(&connector, port, "c.example:443").await?;
        ping(&mut three).await?;
        // The proxy reset stream 3, so its tunnel fails.
        let mut byte = [0_u8; 1];
        assert!(two.read(&mut byte).await.is_err());
        drop(one);
        ping(&mut three).await?;
        let mut four = open(&connector, port, "d.example:443").await?;
        ping(&mut four).await?;
        server.await??;
        Ok(())
    })
    .await
}

/// After the proxy's `GOAWAY`, the tunnel it covers keeps working and a new
/// tunnel opens a new connection.
#[tokio::test]
async fn goaway_moves_new_tunnels_to_a_new_connection() -> TestResult<()> {
    bounded(async {
        let proxy = Proxy::bind()?;
        let connector = proxy
            .connector()?
            .with_http2_proxy_pool(Http2ProxyPool::new());
        let port = proxy.port;
        let server = tokio::spawn(async move {
            let mut first = accept(&proxy.listener, &proxy.acceptor, &[]).await?;
            serve_tunnel(&mut first, 1).await?;
            first
                .write(&[goaway(1)])
                .await
                .map_err(|error| error.to_string())?;
            first.echo(1).await.map_err(|error| error.to_string())?;
            let mut second = accept(&proxy.listener, &proxy.acceptor, &[]).await?;
            serve_tunnel(&mut second, 1).await?;
            first.echo(1).await.map_err(|error| error.to_string())?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let mut one = open(&connector, port, "a.example:443").await?;
        ping(&mut one).await?;
        // This echo arrives after the GOAWAY, so the client has read it.
        ping(&mut one).await?;
        let mut two = open(&connector, port, "b.example:443").await?;
        ping(&mut two).await?;
        ping(&mut one).await?;
        server.await??;
        Ok(())
    })
    .await
}

/// A CONNECT that a `GOAWAY` leaves unprocessed on a reused connection goes
/// once more on a new connection.
#[tokio::test]
async fn a_connect_cut_off_by_goaway_moves_to_a_new_connection() -> TestResult<()> {
    bounded(async {
        let proxy = Proxy::bind()?;
        let connector = proxy
            .connector()?
            .with_http2_proxy_pool(Http2ProxyPool::new());
        let port = proxy.port;
        let server = tokio::spawn(async move {
            let mut first = accept(&proxy.listener, &proxy.acceptor, &[]).await?;
            serve_tunnel(&mut first, 1).await?;
            first
                .read_until(|frame| frame.kind == HEADERS && frame.stream == 3)
                .await
                .map_err(|error| error.to_string())?;
            first
                .write(&[goaway(1)])
                .await
                .map_err(|error| error.to_string())?;
            let mut second = accept(&proxy.listener, &proxy.acceptor, &[]).await?;
            serve_tunnel(&mut second, 1).await?;
            first.echo(1).await.map_err(|error| error.to_string())?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let mut one = open(&connector, port, "a.example:443").await?;
        ping(&mut one).await?;
        let mut two = open(&connector, port, "b.example:443").await?;
        ping(&mut two).await?;
        ping(&mut one).await?;
        server.await??;
        Ok(())
    })
    .await
}

/// Routes with other credentials, and connectors with other HTTP/2
/// settings, never share a connection, even from one pool.
#[tokio::test]
async fn other_credentials_or_settings_never_share_a_connection() -> TestResult<()> {
    bounded(async {
        let proxy = Proxy::bind()?;
        let pool = Http2ProxyPool::new();
        let connector = proxy.connector()?.with_http2_proxy_pool(pool.clone());
        let firefox = proxy
            .connector()?
            .with_http2_settings(&v156_http2())
            .with_http2_proxy_pool(pool.clone());
        let port = proxy.port;
        let server = tokio::spawn(async move {
            let mut connections = Vec::new();
            for _ in 0..4 {
                let mut connection = accept(&proxy.listener, &proxy.acceptor, &[]).await?;
                serve_tunnel(&mut connection, 1).await?;
                connections.push(connection);
            }
            expect_no_connection(&proxy.listener).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(connections)
        });

        let mut anonymous = open(&connector, port, "a.example:443").await?;
        ping(&mut anonymous).await?;
        let alice = HttpBasicCredentials::new("alice", "secret")?;
        let mut alice = open_with_credentials(&connector, port, "a.example:443", &alice).await?;
        ping(&mut alice).await?;
        let bob = HttpBasicCredentials::new("bob", "secret")?;
        let mut bob = open_with_credentials(&connector, port, "a.example:443", &bob).await?;
        ping(&mut bob).await?;
        let mut other_settings = open(&firefox, port, "a.example:443").await?;
        ping(&mut other_settings).await?;
        let connections = server.await??;
        // The Firefox recipe announces other SETTINGS.
        let window = |connection: &RawConnection| {
            connection
                .frames
                .iter()
                .find(|frame| frame.kind == 0x4 && frame.flags == 0)
                .map(|frame| frame.payload.clone())
        };
        assert_ne!(window(&connections[0]), window(&connections[3]));
        Ok(())
    })
    .await
}

/// A challenged CONNECT on a pooled connection that already carries a
/// tunnel of the same route is replayed as the next stream of that
/// connection.
#[tokio::test]
async fn a_challenge_on_a_shared_connection_replays_on_it() -> TestResult<()> {
    bounded(async {
        let proxy = Proxy::bind()?;
        let connector = proxy
            .connector()?
            .with_http2_proxy_pool(Http2ProxyPool::new());
        let port = proxy.port;
        let server = tokio::spawn(async move {
            let mut connection = accept(&proxy.listener, &proxy.acceptor, &[]).await?;
            serve_tunnel(&mut connection, 1).await?;
            connection
                .read_until(|frame| frame.kind == HEADERS && frame.stream == 3)
                .await
                .map_err(|error| error.to_string())?;
            connection
                .write(&[response(3, 407, true)])
                .await
                .map_err(|error| error.to_string())?;
            serve_tunnel(&mut connection, 5).await?;
            connection
                .echo(1)
                .await
                .map_err(|error| error.to_string())?;
            expect_no_connection(&proxy.listener).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let credentials = HttpBasicCredentials::new("alice", "secret")?;
        let mut first =
            open_with_credentials(&connector, port, "a.example:443", &credentials).await?;
        ping(&mut first).await?;
        let mut challenged =
            open_with_credentials(&connector, port, "b.example:443", &credentials).await?;
        ping(&mut challenged).await?;
        ping(&mut first).await?;
        server.await??;
        Ok(())
    })
    .await
}
