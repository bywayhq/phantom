//! A Basic `407` to an HTTP/2 CONNECT and the replay on the challenged
//! connection.

use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use btls::ssl::{Ssl, SslAcceptor};
use http::{Method, Response};
use phantom_testkit::http2::CLIENT_CONNECTION_PREFACE;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpListener,
    time::timeout,
};
use tokio_btls::SslStream;

use super::http2_connect::{bounded, http2_connector, read_integer, skip_string};
use crate::{
    proxy::{
        HttpBasicCredentials, HttpConnectError, HttpConnectErrorKind, HttpConnectHeader,
        HttpsProxyConnector, ProxyCredentialCache, ProxyScheme,
    },
    tls::test_support::{
        TEST_SERVER_NAME, TestIdentity, TestResult, TestServerAlpn, loopback_listener,
    },
};

const ORIGIN: &str = "origin.example:443";
const AUTHORIZATION: &[u8] = b"Basic YWxpY2U6c2VjcmV0";

/// A challenged CONNECT and its replay share one proxy connection, as in the
/// `https-proxy-auth-secure-hostname` captures of Chrome 154, Edge 154, and
/// Firefox 156. The client ends the challenged stream with an empty
/// END_STREAM DATA frame, as Chrome and Edge do, then opens the replay as
/// the next stream. The credential is a never-indexed literal on static name
/// 49, and the tunnel carries bytes on the replay stream.
#[tokio::test]
async fn challenged_connect_replays_on_the_next_stream_of_its_connection() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let cache = ProxyCredentialCache::new();
        let connector = http2_connector(&identity)?.with_proxy_credential_cache(cache.clone());
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let proxy_task = tokio::spawn(async move {
            let served =
                serve_connects(&listener, &acceptor, &[Reply::Challenge, Reply::Echo]).await?;
            let second = timeout(Duration::from_millis(100), listener.accept()).await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((served, second.is_err()))
        });

        echo_through(&connector, address.port()).await?;

        let (served, one_connection) = proxy_task.await??;
        assert!(one_connection, "the replay opened a new proxy connection");
        let sent: Vec<_> = served
            .connects
            .iter()
            .map(|connect| (connect.stream_id, connect.authorization.clone()))
            .collect();
        assert_eq!(sent, [(1, None), (3, Some(AUTHORIZATION.to_vec()))]);
        assert!(cache.contains(
            ProxyScheme::Https,
            "127.0.0.1",
            address.port(),
            &credentials()?
        ));

        let frames = client_frames(&served.wire()?)?;
        let challenged_end = frames
            .iter()
            .position(|frame| frame.kind == DATA && frame.stream == 1)
            .ok_or("the challenged stream was not ended")?;
        assert_eq!(frames[challenged_end].flags & END_STREAM, END_STREAM);
        assert!(frames[challenged_end].payload.is_empty());
        let replay = frames
            .iter()
            .position(|frame| frame.kind == HEADERS && frame.stream == 3)
            .ok_or("no replay HEADERS")?;
        assert!(challenged_end < replay);
        assert!(
            !frames
                .iter()
                .any(|frame| frame.kind == RST_STREAM && frame.stream == 1),
            "the client reset the challenged stream"
        );
        let challenged = frames
            .iter()
            .find(|frame| frame.kind == HEADERS && frame.stream == 1)
            .ok_or("no challenged HEADERS")?;
        assert!(
            field_representations(header_block(challenged))?
                .iter()
                .all(|&(_, index)| index != PROXY_AUTHORIZATION)
        );
        let representations = field_representations(header_block(&frames[replay]))?;
        assert!(representations.contains(&(NEVER_INDEXED, PROXY_AUTHORIZATION)));
        assert!(
            representations
                .iter()
                .all(|&(kind, index)| index != PROXY_AUTHORIZATION || kind == NEVER_INDEXED)
        );
        Ok(())
    })
    .await
}

/// Remembered credentials go on stream 1 of a new connection. A `407` to
/// them forgets the pair and permits one replay, on stream 3 of the same
/// connection, and the accepted replay records the pair again.
#[tokio::test]
async fn remembered_credentials_and_their_challenge_use_one_connection_each() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let cache = ProxyCredentialCache::new();
        let connector = http2_connector(&identity)?.with_proxy_credential_cache(cache.clone());
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let proxy_task = tokio::spawn(async move {
            let mut connections = Vec::new();
            for replies in [
                &[Reply::Challenge, Reply::Echo][..],
                &[Reply::Echo],
                &[Reply::Challenge, Reply::Echo],
            ] {
                connections.push(serve_connects(&listener, &acceptor, replies).await?);
            }
            let fourth = timeout(Duration::from_millis(100), listener.accept()).await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((connections, fourth.is_err()))
        });

        for _ in 0..3 {
            echo_through(&connector, address.port()).await?;
            assert!(cache.contains(
                ProxyScheme::Https,
                "127.0.0.1",
                address.port(),
                &credentials()?
            ));
        }

        let (connections, three_connections) = proxy_task.await??;
        assert!(three_connections, "a tunnel opened a second connection");
        let sent: Vec<Vec<(u32, bool)>> = connections
            .iter()
            .map(|served| {
                served
                    .connects
                    .iter()
                    .map(|connect| (connect.stream_id, connect.authorization.is_some()))
                    .collect()
            })
            .collect();
        assert_eq!(
            sent,
            [
                vec![(1, false), (3, true)],
                vec![(1, true)],
                vec![(1, true), (3, true)],
            ]
        );
        Ok(())
    })
    .await
}

/// A second `407`, on the replay stream of the same connection, fails with
/// the authentication error and opens no other connection.
#[tokio::test]
async fn second_challenge_on_the_replay_stream_is_an_authentication_failure() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let connector = http2_connector(&identity)?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let proxy_task = tokio::spawn(async move {
            let served =
                serve_connects(&listener, &acceptor, &[Reply::Challenge, Reply::Challenge]).await?;
            let second = timeout(Duration::from_millis(100), listener.accept()).await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((served, second.is_err()))
        });

        let error = connector
            .connect_tunnel_with_basic_auth(
                "127.0.0.1",
                address.port(),
                TEST_SERVER_NAME,
                ORIGIN,
                &auth_headers(),
                &credentials()?,
            )
            .await
            .err()
            .ok_or("a twice-challenged CONNECT succeeded")?;
        assert!(matches!(error, HttpConnectError::AuthenticationRejected));
        assert_eq!(error.kind(), HttpConnectErrorKind::Authentication);

        let (served, one_connection) = proxy_task.await??;
        assert!(one_connection);
        let streams: Vec<_> = served.connects.iter().map(|c| c.stream_id).collect();
        assert_eq!(streams, [1, 3]);
        Ok(())
    })
    .await
}

/// A proxy that refuses the replay stream with `REFUSED_STREAM`, which says
/// it did not process the request, gets the replay on a new connection,
/// once.
#[tokio::test]
async fn refused_replay_moves_to_a_new_connection() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let connector = http2_connector(&identity)?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let proxy_task = tokio::spawn(async move {
            let challenged =
                serve_connects(&listener, &acceptor, &[Reply::Challenge, Reply::Refuse]).await?;
            let replay = serve_connects(&listener, &acceptor, &[Reply::Echo]).await?;
            let third = timeout(Duration::from_millis(100), listener.accept()).await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((challenged, replay, third.is_err()))
        });

        echo_through(&connector, address.port()).await?;

        let (challenged, replay, two_connections) = proxy_task.await??;
        assert!(two_connections);
        let sent = |served: &ServedConnection| -> Vec<(u32, bool)> {
            served
                .connects
                .iter()
                .map(|connect| (connect.stream_id, connect.authorization.is_some()))
                .collect()
        };
        assert_eq!(sent(&challenged), [(1, false), (3, true)]);
        assert_eq!(sent(&replay), [(1, true)]);
        Ok(())
    })
    .await
}

fn credentials() -> TestResult<HttpBasicCredentials> {
    Ok(HttpBasicCredentials::new("alice", "secret")?)
}

fn auth_headers() -> [HttpConnectHeader; 2] {
    [
        HttpConnectHeader::authority("Host"),
        HttpConnectHeader::proxy_authorization("Proxy-Authorization"),
    ]
}

/// Opens one authenticated tunnel and checks that it carries bytes both
/// ways.
async fn echo_through(connector: &HttpsProxyConnector, port: u16) -> TestResult<()> {
    let mut tunnel = connector
        .connect_tunnel_with_basic_auth(
            "127.0.0.1",
            port,
            TEST_SERVER_NAME,
            ORIGIN,
            &auth_headers(),
            &credentials()?,
        )
        .await?;
    tunnel.write_all(b"ping").await?;
    let mut echoed = [0_u8; 4];
    tunnel.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"ping");
    Ok(())
}

/// How the test proxy answers one CONNECT stream.
enum Reply {
    /// `407` with a Basic challenge, ending the stream.
    Challenge,
    /// `RST_STREAM` with `REFUSED_STREAM`.
    Refuse,
    /// `200`, then every DATA byte echoed back.
    Echo,
}

struct ProxyConnect {
    stream_id: u32,
    authorization: Option<Vec<u8>>,
}

struct ServedConnection {
    connects: Vec<ProxyConnect>,
    wire: Arc<Mutex<Vec<u8>>>,
}

impl ServedConnection {
    fn wire(&self) -> TestResult<Vec<u8>> {
        Ok(self
            .wire
            .lock()
            .map_err(|_| "client wire lock was poisoned")?
            .clone())
    }
}

/// Accepts one TLS proxy connection and answers one CONNECT stream per
/// reply, keeping every byte the client sent.
async fn serve_connects(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
    replies: &[Reply],
) -> TestResult<ServedConnection> {
    let (tcp, _) = listener.accept().await?;
    let mut tls = SslStream::new(Ssl::new(acceptor.context())?, tcp)?;
    Pin::new(&mut tls).accept().await?;
    let wire = Arc::new(Mutex::new(Vec::new()));
    let recording = Recording {
        inner: tls,
        wire: Arc::clone(&wire),
    };
    let mut connection = ::http2::server::handshake(recording).await?;
    let mut connects = Vec::with_capacity(replies.len());
    // A challenged request body stays open, as the capture proxy's does, so
    // the client ends the stream itself instead of receiving a reset.
    let mut challenged = Vec::new();
    for reply in replies {
        let (request, mut respond) = connection
            .accept()
            .await
            .ok_or("proxy connection closed before CONNECT")??;
        if request.method() != Method::CONNECT {
            return Err("proxy received a non-CONNECT request".into());
        }
        connects.push(ProxyConnect {
            stream_id: respond.stream_id().as_u32(),
            authorization: request
                .headers()
                .get("proxy-authorization")
                .map(|value| value.as_bytes().to_vec()),
        });
        match reply {
            Reply::Challenge => {
                let response = Response::builder()
                    .status(407)
                    .header("proxy-authenticate", "Basic realm=\"proxy\"")
                    .body(())?;
                respond.send_response(response, true)?;
                challenged.push(request);
            }
            Reply::Refuse => {
                respond.send_reset(::http2::Reason::REFUSED_STREAM);
            }
            Reply::Echo => {
                let mut send = respond.send_response(Response::new(()), false)?;
                let mut body = request.into_body();
                tokio::spawn(async move {
                    while let Some(Ok(chunk)) = body.data().await {
                        let _ = body.flow_control().release_capacity(chunk.len());
                        if send.send_data(chunk, false).is_err() {
                            return;
                        }
                    }
                });
            }
        }
    }
    tokio::spawn(async move {
        let _challenged = challenged;
        while let Some(Ok(_)) = connection.accept().await {}
    });
    Ok(ServedConnection { connects, wire })
}

/// A byte stream that keeps a copy of everything read from it.
struct Recording<S> {
    inner: S,
    wire: Arc<Mutex<Vec<u8>>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Recording<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if let Ok(mut wire) = self.wire.lock() {
            wire.extend_from_slice(&buffer.filled()[before..]);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Recording<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const END_STREAM: u8 = 0x1;
/// First-byte pattern of an HPACK literal never indexed (RFC 7541 section
/// 6.2.3).
const NEVER_INDEXED: u8 = 0x10;
/// HPACK static table index of `proxy-authorization`.
const PROXY_AUTHORIZATION: usize = 49;

struct ClientFrame {
    kind: u8,
    flags: u8,
    stream: u32,
    payload: Vec<u8>,
}

/// Splits the client side of a connection, after its preface, into frames.
fn client_frames(wire: &[u8]) -> TestResult<Vec<ClientFrame>> {
    let mut rest = wire
        .strip_prefix(CLIENT_CONNECTION_PREFACE)
        .ok_or("client omitted the HTTP/2 preface")?;
    let mut frames = Vec::new();
    while rest.len() >= 9 {
        let length =
            (usize::from(rest[0]) << 16) | (usize::from(rest[1]) << 8) | usize::from(rest[2]);
        let payload = rest.get(9..9 + length).ok_or("truncated HTTP/2 frame")?;
        frames.push(ClientFrame {
            kind: rest[3],
            flags: rest[4],
            stream: u32::from_be_bytes([rest[5], rest[6], rest[7], rest[8]]) & 0x7fff_ffff,
            payload: payload.to_vec(),
        });
        rest = &rest[9 + length..];
    }
    Ok(frames)
}

/// Returns an unpadded HEADERS frame's field block, after any priority
/// fields.
fn header_block(frame: &ClientFrame) -> &[u8] {
    if frame.flags & 0x20 != 0 {
        &frame.payload[5..]
    } else {
        &frame.payload
    }
}

/// Returns each field representation's first-byte pattern and name index:
/// 0x80 indexed, 0x40 incrementally indexed, 0x10 never indexed, and 0x00
/// without indexing. A table size update is skipped.
fn field_representations(block: &[u8]) -> TestResult<Vec<(u8, usize)>> {
    let mut position = 0;
    let mut fields = Vec::new();
    while let Some(&first) = block.get(position) {
        let (kind, prefix) = if first & 0x80 != 0 {
            (0x80, 7)
        } else if first & 0xc0 == 0x40 {
            (0x40, 6)
        } else if first & 0xe0 == 0x20 {
            read_integer(block, &mut position, 5)?;
            continue;
        } else if first & 0xf0 == NEVER_INDEXED {
            (NEVER_INDEXED, 4)
        } else {
            (0x00, 4)
        };
        let index = read_integer(block, &mut position, prefix)?;
        if kind != 0x80 {
            if index == 0 {
                skip_string(block, &mut position)?;
            }
            skip_string(block, &mut position)?;
        }
        fields.push((kind, index));
    }
    Ok(fields)
}
