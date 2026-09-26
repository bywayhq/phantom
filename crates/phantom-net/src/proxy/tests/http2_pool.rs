//! CONNECT tunnels that share pooled HTTP/2 proxy connections, against a
//! frame-level proxy.

use std::time::Duration;

use btls::ssl::SslAcceptor;
use phantom_profile::{chromium::v154_http2, firefox::v156_http2};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

use super::{
    http2_connect::bounded,
    http2_raw_proxy::{HEADERS, RST_STREAM, RawConnection, frame, goaway, response},
    https_connect::tls_settings,
};
use crate::{
    proxy::{
        Http2ProxyPool, HttpBasicCredentials, HttpConnectHeader, HttpsProxyConnector,
        HttpsProxyProtocol, https_connect::HttpsProxyTunnel,
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
/// connection, as Chrome 154 and Firefox 156 open a page's CONNECTs in the
/// `https-proxy-secure-hostname` captures.
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

/// A connection takes no more tunnels than the proxy's
/// `SETTINGS_MAX_CONCURRENT_STREAMS`; the next tunnel opens a second
/// connection, and once both are full, a tunnel that ends makes room on the
/// first again.
#[tokio::test]
async fn the_proxy_stream_limit_sends_later_tunnels_to_a_new_connection() -> TestResult<()> {
    bounded(async {
        let proxy = Proxy::bind()?;
        let connector = proxy
            .connector()?
            .with_http2_proxy_pool(Http2ProxyPool::new());
        let port = proxy.port;
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let settings = [(MAX_CONCURRENT_STREAMS, 2)];
            let mut first = accept(&proxy.listener, &proxy.acceptor, &settings).await?;
            serve_tunnel(&mut first, 1).await?;
            serve_tunnel(&mut first, 3).await?;
            let mut second = accept(&proxy.listener, &proxy.acceptor, &settings).await?;
            serve_tunnel(&mut second, 1).await?;
            serve_tunnel(&mut second, 3).await?;
            // The client resets stream 1 when it drops that tunnel.
            first
                .read_until(|frame| frame.kind == RST_STREAM && frame.stream == 1)
                .await
                .map_err(|error| error.to_string())?;
            let _ = closed_tx.send(());
            serve_tunnel(&mut first, 5).await?;
            expect_no_connection(&proxy.listener).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
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
        drop(tunnels.remove(0));
        closed_rx.await?;
        let mut fifth = open(&connector, port, "e.example:443").await?;
        ping(&mut fifth).await?;
        server.await??;
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
