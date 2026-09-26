//! Several CONNECT tunnels, forwarded requests, and WebSocket openings on
//! shared HTTP/2 proxy connections, per browser profile.

use crate::support::tls;
#[cfg(feature = "websocket")]
use crate::support::websocket_origin;

use std::{
    error::Error as StdError,
    future::{Future, poll_fn},
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
    profile::{ClientProfile, chromium, firefox},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use tls::{H1_ALPN, H2_ALPN, TestIdentity, TestResult, accept_tls_stream, read_head, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

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
async fn spawn_proxy(identity: &TestIdentity) -> TestResult<(SocketAddr, ProxyLog)> {
    spawn_limited_proxy(identity, None).await
}

/// Starts the proxy of [`spawn_proxy`], announcing `max_streams` as its
/// `SETTINGS_MAX_CONCURRENT_STREAMS`.
async fn spawn_limited_proxy(
    identity: &TestIdentity,
    max_streams: Option<u32>,
) -> TestResult<(SocketAddr, ProxyLog)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H2_ALPN)?;
    let log = ProxyLog::default();
    let seen = Arc::clone(&log);
    tokio::spawn(async move {
        let mut index = 0;
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(serve_proxy_connection(
                tcp,
                acceptor.clone(),
                index,
                max_streams,
                Arc::clone(&seen),
            ));
            index += 1;
        }
    });
    Ok((address, log))
}

async fn serve_proxy_connection(
    tcp: TcpStream,
    acceptor: SslAcceptor,
    index: usize,
    max_streams: Option<u32>,
    log: ProxyLog,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let stream = accept_tls_stream(tcp, acceptor)
        .await
        .map_err(|error| error.to_string())?;
    let mut builder = ::http2::server::Builder::new();
    if let Some(max_streams) = max_streams {
        builder.max_concurrent_streams(max_streams);
    }
    let mut connection = builder.handshake(stream).await?;
    while let Some(accepted) = connection.accept().await {
        let (request, mut respond) = accepted?;
        let authority = request
            .uri()
            .authority()
            .map(ToString::to_string)
            .unwrap_or_default();
        if let Ok(mut seen) = log.lock() {
            seen.push(Seen {
                connection: index,
                stream: respond.stream_id().as_u32(),
                method: request.method().clone(),
                authority: authority.clone(),
            });
        }
        if request.method() == Method::CONNECT {
            let send = respond.send_response(Response::new(()), false)?;
            let upstream = TcpStream::connect(authority.as_str()).await?;
            spawn_relay(request.into_body(), send, upstream);
        } else {
            let mut send = respond.send_response(Response::new(()), false)?;
            send.send_data(Bytes::from_static(b"forwarded"), true)?;
        }
    }
    Ok(())
}

fn spawn_relay(
    mut downstream: ::http2::RecvStream,
    mut send: ::http2::SendStream<Bytes>,
    upstream: TcpStream,
) {
    let (mut read, mut write) = upstream.into_split();
    tokio::spawn(async move {
        while let Some(Ok(chunk)) = downstream.data().await {
            let _ = downstream.flow_control().release_capacity(chunk.len());
            if write.write_all(&chunk).await.is_err() {
                return;
            }
        }
        let _ = write.shutdown().await;
    });
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            let count = match read.read(&mut buffer).await {
                Ok(0) | Err(_) => {
                    let _ = send.send_data(Bytes::new(), true);
                    return;
                }
                Ok(count) => count,
            };
            let mut chunk = Bytes::copy_from_slice(&buffer[..count]);
            while !chunk.is_empty() {
                send.reserve_capacity(chunk.len());
                let capacity = match poll_fn(|context| send.poll_capacity(context)).await {
                    Some(Ok(capacity)) => capacity,
                    _ => return,
                };
                let part = chunk.split_to(capacity.min(chunk.len()));
                if send.send_data(part, false).is_err() {
                    return;
                }
            }
        }
    });
}

/// Starts an HTTPS origin that answers every HTTP/1.1 request with `ok`.
async fn spawn_origin(identity: &TestIdentity) -> TestResult<SocketAddr> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = accept_tls_stream(tcp, acceptor).await else {
                    return;
                };
                while read_head(&mut stream).await.is_ok() {
                    if stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    Ok(address)
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
        .with_http2(chromium::v154_http2())
        .with_proxy_connect(chromium::v154_proxy_connect())
}

fn firefox_profile() -> ClientProfile {
    ClientProfile::new(tls_settings())
        .with_http2(firefox::v156_http2())
        .with_proxy_connect(firefox::v156_proxy_connect())
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

fn seen(log: &ProxyLog) -> Vec<Seen> {
    log.lock().map(|seen| seen.clone()).unwrap_or_default()
}

/// Tunnels to three origins through a client become streams 1, 3, and 5 of
/// one proxy connection.
#[tokio::test]
async fn tunnels_to_different_origins_share_one_proxy_connection() -> TestResult<()> {
    bounded(async {
        let origin_identity = TestIdentity::generate()?;
        let proxy_identity = TestIdentity::generate()?;
        let (proxy, log) = spawn_proxy(&proxy_identity).await?;
        let origins = [
            spawn_origin(&origin_identity).await?,
            spawn_origin(&origin_identity).await?,
            spawn_origin(&origin_identity).await?,
        ];
        let client = client(chromium_profile(), &origin_identity, &proxy_identity, proxy)?;
        for origin in origins {
            get_https(&client, origin).await?;
        }
        let seen = seen(&log);
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
    })
    .await
}

/// With the Chromium recipe, a forwarded `http://` request and CONNECT
/// tunnels are streams of one proxy connection, as Chrome 154 sends a page's
/// navigation, `fetch()`, and CONNECTs in the `https-proxy-*` captures.
/// With the Firefox recipe, forwarded requests and tunnels use separate
/// connections, as Firefox 156 does in the same captures.
#[tokio::test]
async fn forwarded_requests_join_the_tunnel_connection_as_the_profile_says() -> TestResult<()> {
    bounded(async {
        for (profile, shared) in [(chromium_profile(), true), (firefox_profile(), false)] {
            let origin_identity = TestIdentity::generate()?;
            let proxy_identity = TestIdentity::generate()?;
            let (proxy, log) = spawn_proxy(&proxy_identity).await?;
            let origin = spawn_origin(&origin_identity).await?;
            let client = client(profile, &origin_identity, &proxy_identity, proxy)?;
            get_forwarded(&client, "first.test:8080").await?;
            get_https(&client, origin).await?;
            get_forwarded(&client, "second.test:8080").await?;

            let placement: Vec<(usize, u32)> = seen(&log)
                .iter()
                .map(|seen| (seen.connection, seen.stream))
                .collect();
            if shared {
                assert_eq!(placement, [(0, 1), (0, 3), (0, 5)]);
            } else {
                // Forwarded requests to both origins share one connection;
                // the tunnel has its own.
                assert_eq!(placement, [(0, 1), (1, 1), (0, 3)]);
            }
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
        let origin_identity = TestIdentity::generate()?;
        let proxy_identity = TestIdentity::generate()?;
        let (proxy, log) = spawn_limited_proxy(&proxy_identity, Some(1)).await?;
        let origins = [
            spawn_origin(&origin_identity).await?,
            spawn_origin(&origin_identity).await?,
        ];
        let client = Client::builder(chromium_profile())
            .add_root_certificate_der(origin_identity.root_der.clone())
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .route(Route::http_proxy(
                HttpProxy::new(&format!("https://{proxy}"))?.with_http2_transport()?,
            ))
            .max_http2_proxy_connections_per_route(NonZeroUsize::new(2).ok_or("0")?)
            .build()?;
        // Each origin connection keeps its tunnel open.
        for origin in origins {
            get_https(&client, origin).await?;
        }
        let placement: Vec<(usize, u32)> = seen(&log)
            .iter()
            .map(|seen| (seen.connection, seen.stream))
            .collect();
        assert_eq!(placement, [(0, 1), (1, 1)]);
        Ok(())
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

/// A session keeps its own proxy connections, as it keeps its own pools.
#[tokio::test]
async fn sessions_never_share_a_proxy_connection() -> TestResult<()> {
    bounded(async {
        let origin_identity = TestIdentity::generate()?;
        let proxy_identity = TestIdentity::generate()?;
        let (proxy, log) = spawn_proxy(&proxy_identity).await?;
        let origin = spawn_origin(&origin_identity).await?;
        let client = client(chromium_profile(), &origin_identity, &proxy_identity, proxy)?;
        let session = client.session();
        get_https(&client, origin).await?;
        get_https(&session, origin).await?;
        let connections: Vec<usize> = seen(&log).iter().map(|seen| seen.connection).collect();
        assert_eq!(connections, [0, 1]);
        Ok(())
    })
    .await
}

/// A `ws://` opening joins the tunnel connection with the Chromium recipe
/// and opens its own with the Firefox recipe, as Chrome 154 and Firefox 156
/// do in the `https-proxy-hostname` captures.
#[cfg(feature = "websocket")]
#[tokio::test]
async fn websocket_tunnels_use_the_connection_the_profile_gives_them() -> TestResult<()> {
    bounded(async {
        for (profile, shared) in [(chromium_profile(), true), (firefox_profile(), false)] {
            let origin_identity = TestIdentity::generate()?;
            let proxy_identity = TestIdentity::generate()?;
            let (proxy, log) = spawn_proxy(&proxy_identity).await?;
            let origin = spawn_origin(&origin_identity).await?;
            let websocket_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let websocket_origin = websocket_listener.local_addr()?;
            let websocket = tokio::spawn(websocket_origin::serve_plaintext_h1_echo(
                websocket_listener,
            ));
            let client = client(profile, &origin_identity, &proxy_identity, proxy)?;
            get_https(&client, origin).await?;
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
            websocket.await??;
            get_https(&client, origin).await?;

            let placement: Vec<(usize, u32, String)> = seen(&log)
                .iter()
                .map(|seen| (seen.connection, seen.stream, seen.authority.clone()))
                .collect();
            let websocket_placement = if shared { (0, 3) } else { (1, 1) };
            assert_eq!(
                placement,
                [
                    (0, 1, origin.to_string()),
                    (
                        websocket_placement.0,
                        websocket_placement.1,
                        websocket_origin.to_string()
                    ),
                ],
                "the second https request reuses its pooled origin connection"
            );
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
        .map_err(|_| "HTTP/2 proxy multiplexing test exceeded its deadline")?
}
