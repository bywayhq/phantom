//! Loopback tunnel proxies that record one CONNECT and relay in the background.
//!
//! Each function returns as soon as the tunnel is established. The relay runs
//! in a detached task and ignores teardown errors, so assertions never depend
//! on how a platform reports the client hanging up.

use std::{
    future::poll_fn,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use btls::ssl::SslAcceptor;
use bytes::Bytes;
use http::{Method, Response};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
};

use super::tls::{TestResult, accept_tls_stream, read_head};

const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const BASIC_CHALLENGE: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
    Proxy-Authenticate: Basic realm=\"websocket\"\r\nContent-Length: 0\r\n\r\n";

/// Accepts one plaintext HTTP/1.1 CONNECT and tunnels it to `origin`.
pub(crate) async fn http1_connect(
    listener: TcpListener,
    origin: SocketAddr,
) -> TestResult<Vec<u8>> {
    let (mut downstream, _) = listener.accept().await?;
    let request = read_head(&mut downstream).await?;
    establish_relay(downstream, origin).await?;
    Ok(request)
}

/// Challenges the first plaintext HTTP/1.1 CONNECT with Basic, then tunnels
/// the second connection's CONNECT to `origin`.
///
/// Returns the anonymous head, the authorized head, and whether the
/// challenged connection carried a second request.
pub(crate) async fn http1_challenge_then_connect(
    listener: TcpListener,
    origin: SocketAddr,
) -> TestResult<(Vec<u8>, Vec<u8>, bool)> {
    let (mut first, _) = listener.accept().await?;
    let anonymous = read_head(&mut first).await?;
    first.write_all(BASIC_CHALLENGE).await?;
    first.flush().await?;
    let challenged = tokio::spawn(async move {
        let mut rest = Vec::new();
        // A reset after the challenge is a hang-up, not a second request.
        let _ = first.read_to_end(&mut rest).await;
        !rest.is_empty()
    });

    let (mut second, _) = listener.accept().await?;
    let authorized = read_head(&mut second).await?;
    establish_relay(second, origin).await?;
    Ok((anonymous, authorized, challenged.await?))
}

/// Accepts one TLS HTTP/1.1 CONNECT and tunnels it to `origin`.
pub(crate) async fn https1_connect(
    listener: TcpListener,
    acceptor: SslAcceptor,
    origin: SocketAddr,
) -> TestResult<Vec<u8>> {
    let (tcp, _) = listener.accept().await?;
    let mut downstream = accept_tls_stream(tcp, acceptor).await?;
    let request = read_head(&mut downstream).await?;
    establish_relay(downstream, origin).await?;
    Ok(request)
}

/// Accepts one plaintext HTTP/1.1 CONNECT and answers it with `status`.
pub(crate) async fn http1_connect_status(
    listener: TcpListener,
    status: u16,
) -> TestResult<Vec<u8>> {
    let (mut downstream, _) = listener.accept().await?;
    let request = read_head(&mut downstream).await?;
    downstream
        .write_all(format!("HTTP/1.1 {status} Refused\r\nContent-Length: 0\r\n\r\n").as_bytes())
        .await?;
    downstream.flush().await?;
    Ok(request)
}

/// Challenges the first TLS HTTP/1.1 CONNECT with Basic, then tunnels the
/// second connection's CONNECT to `origin`.
///
/// Returns the anonymous head, the authorized head, and whether the
/// challenged connection carried a second request.
pub(crate) async fn https1_challenge_then_connect(
    listener: TcpListener,
    acceptor: SslAcceptor,
    origin: SocketAddr,
) -> TestResult<(Vec<u8>, Vec<u8>, bool)> {
    let (first, _) = listener.accept().await?;
    let mut first = accept_tls_stream(first, acceptor.clone()).await?;
    let anonymous = read_head(&mut first).await?;
    first.write_all(BASIC_CHALLENGE).await?;
    first.flush().await?;
    let challenged = tokio::spawn(async move {
        let mut rest = Vec::new();
        // A reset after the challenge is a hang-up, not a second request.
        let _ = first.read_to_end(&mut rest).await;
        !rest.is_empty()
    });

    let (second, _) = listener.accept().await?;
    let mut second = accept_tls_stream(second, acceptor).await?;
    let authorized = read_head(&mut second).await?;
    establish_relay(second, origin).await?;
    Ok((anonymous, authorized, challenged.await?))
}

/// The CONNECT request observed by an HTTP/2 proxy.
#[derive(Debug)]
pub(crate) struct Http2ConnectRecord {
    pub(crate) authority: Option<String>,
    pub(crate) fields: Vec<(String, Vec<u8>)>,
}

/// Accepts one h2-only TLS proxy connection, answers one RFC 9113 CONNECT
/// with 200, and relays its DATA to `origin`.
///
/// The HTTP/2 server rejects `:scheme` or `:path` in a classic CONNECT, so a
/// recorded request proves the proxy leg spoke HTTP/2 CONNECT.
pub(crate) async fn http2_connect(
    listener: TcpListener,
    acceptor: SslAcceptor,
    origin: SocketAddr,
) -> TestResult<Http2ConnectRecord> {
    let (tcp, _) = listener.accept().await?;
    let stream = accept_tls_stream(tcp, acceptor).await?;
    if stream.ssl().selected_alpn_protocol() != Some(b"h2") {
        return Err("proxy connection did not select h2".into());
    }
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("proxy connection closed before CONNECT")??;
    if request.method() != Method::CONNECT {
        return Err("proxy received a non-CONNECT request".into());
    }
    let record = Http2ConnectRecord {
        authority: request.uri().authority().map(ToString::to_string),
        fields: request
            .extensions()
            .get::<::http2::ext::OrderedHeaders>()
            .ok_or("missing ordered CONNECT fields")?
            .as_slice()
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect(),
    };
    let send = respond.send_response(Response::new(()), false)?;
    let upstream = TcpStream::connect(origin).await?;
    spawn_http2_relay(request.into_body(), send, upstream);
    tokio::spawn(async move { while let Some(Ok(_)) = connection.accept().await {} });
    Ok(record)
}

/// The SOCKS5 CONNECT target observed by the proxy.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Socks5Target {
    Ip(IpAddr),
    Domain(String),
}

/// Accepts one no-authentication SOCKS5 CONNECT and tunnels it to `origin`.
pub(crate) async fn socks5_connect(
    listener: TcpListener,
    origin: SocketAddr,
) -> TestResult<(Socks5Target, u16)> {
    let (mut downstream, _) = listener.accept().await?;
    let target = socks5_request(&mut downstream).await?;
    let upstream = TcpStream::connect(origin).await?;
    downstream
        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
        .await?;
    downstream.flush().await?;
    spawn_relay(downstream, upstream);
    Ok(target)
}

/// Accepts one no-authentication SOCKS5 CONNECT and refuses it.
pub(crate) async fn socks5_refuse(listener: TcpListener) -> TestResult<(Socks5Target, u16)> {
    let (mut downstream, _) = listener.accept().await?;
    let target = socks5_request(&mut downstream).await?;
    // Reply 5: connection refused.
    downstream
        .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
        .await?;
    downstream.flush().await?;
    Ok(target)
}

async fn socks5_request(stream: &mut TcpStream) -> TestResult<(Socks5Target, u16)> {
    let mut greeting = [0_u8; 3];
    stream.read_exact(&mut greeting).await?;
    if greeting != [5, 1, 0] {
        return Err("unexpected SOCKS5 greeting".into());
    }
    stream.write_all(&[5, 0]).await?;
    stream.flush().await?;
    let mut head = [0_u8; 4];
    stream.read_exact(&mut head).await?;
    if head[..3] != [5, 1, 0] {
        return Err("unexpected SOCKS5 CONNECT prefix".into());
    }
    let target = match head[3] {
        1 => {
            let mut address = [0_u8; 4];
            stream.read_exact(&mut address).await?;
            Socks5Target::Ip(IpAddr::V4(Ipv4Addr::from(address)))
        }
        3 => {
            let length = stream.read_u8().await?;
            let mut name = vec![0_u8; usize::from(length)];
            stream.read_exact(&mut name).await?;
            Socks5Target::Domain(String::from_utf8(name)?)
        }
        4 => {
            let mut address = [0_u8; 16];
            stream.read_exact(&mut address).await?;
            Socks5Target::Ip(IpAddr::from(address))
        }
        _ => return Err("unsupported SOCKS5 address type".into()),
    };
    let port = stream.read_u16().await?;
    Ok((target, port))
}

async fn establish_relay<S>(mut downstream: S, origin: SocketAddr) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let upstream = TcpStream::connect(origin).await?;
    downstream.write_all(ESTABLISHED).await?;
    downstream.flush().await?;
    spawn_relay(downstream, upstream);
    Ok(())
}

fn spawn_relay<S>(mut downstream: S, mut upstream: TcpStream)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let _ = copy_bidirectional(&mut downstream, &mut upstream).await;
    });
}

fn spawn_http2_relay(
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
