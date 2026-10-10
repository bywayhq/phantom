//! Loopback tunnel proxies that return observed CONNECT fields with their relay owner.
//!
//! Each tunnel function returns as soon as it is established. Keep the returned
//! owner alive while using it, then cancel and join its tasks. An `_on` variant borrows
//! the listener, so a test can keep it and check with
//! [`no_connection_arrives`] that nothing else connected later.

use std::{
    future::poll_fn,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};

use btls::ssl::SslAcceptor;
use bytes::Bytes;
use http::{Method, Response};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use super::tls::{TestResult, accept_tls_stream, read_head};

#[path = "tunnel_proxy/connection_peer.rs"]
mod connection_peer;
pub(crate) use connection_peer::{ConnectionPeer, finish_with_cleanup};

#[path = "tunnel_proxy/relay_controls.rs"]
mod relay_controls;

const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const BASIC_CHALLENGE: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
    Proxy-Authenticate: Basic realm=\"websocket\"\r\nContent-Length: 0\r\n\r\n";

#[derive(Debug)]
pub(crate) struct EstablishedTunnel<T> {
    pub(crate) observed: T,
    peers: Vec<ConnectionPeer<TestResult<()>>>,
}

impl<T> EstablishedTunnel<T> {
    fn new(observed: T, peer: ConnectionPeer<TestResult<()>>) -> Self {
        Self {
            observed,
            peers: vec![peer],
        }
    }

    pub(crate) fn map<U>(self, map: impl FnOnce(T) -> U) -> EstablishedTunnel<U> {
        EstablishedTunnel {
            observed: map(self.observed),
            peers: self.peers,
        }
    }

    pub(crate) fn combine<U>(mut self, other: EstablishedTunnel<U>) -> EstablishedTunnel<(T, U)> {
        self.peers.extend(other.peers);
        EstablishedTunnel {
            observed: (self.observed, other.observed),
            peers: self.peers,
        }
    }

    pub(crate) async fn cancel(self) -> TestResult<T> {
        for peer in &self.peers {
            peer.abort();
        }

        let mut cleanup = Ok(());
        for peer in self.peers {
            cleanup = finish_with_cleanup(cleanup, peer.stop().await);
        }
        cleanup?;
        Ok(self.observed)
    }
}

/// Accepts one plaintext HTTP/1.1 CONNECT and tunnels it to `origin`.
pub(crate) async fn http1_connect(
    listener: TcpListener,
    origin: SocketAddr,
) -> TestResult<EstablishedTunnel<Vec<u8>>> {
    http1_connect_on(&listener, origin).await
}

/// [`http1_connect`] on a borrowed listener.
pub(crate) async fn http1_connect_on(
    listener: &TcpListener,
    origin: SocketAddr,
) -> TestResult<EstablishedTunnel<Vec<u8>>> {
    let (mut downstream, _) = listener.accept().await?;
    let request = read_head(&mut downstream).await?;
    let relay = establish_relay(downstream, origin).await?;
    Ok(EstablishedTunnel::new(request, relay))
}

/// Challenges the first plaintext HTTP/1.1 CONNECT with a keep-alive Basic
/// `407`, then tunnels the replay to `origin`, on the challenged connection
/// or on a new one.
///
/// Returns the anonymous head, the authorized head, and whether the replay
/// used the challenged connection.
pub(crate) async fn http1_challenge_then_connect(
    listener: TcpListener,
    origin: SocketAddr,
) -> TestResult<EstablishedTunnel<(Vec<u8>, Vec<u8>, bool)>> {
    http1_challenge_then_connect_on(&listener, origin).await
}

/// [`http1_challenge_then_connect`] on a borrowed listener.
pub(crate) async fn http1_challenge_then_connect_on(
    listener: &TcpListener,
    origin: SocketAddr,
) -> TestResult<EstablishedTunnel<(Vec<u8>, Vec<u8>, bool)>> {
    let (mut first, _) = listener.accept().await?;
    let anonymous = read_head(&mut first).await?;
    first.write_all(BASIC_CHALLENGE).await?;
    first.flush().await?;
    let replay = tokio::select! {
        head = read_head(&mut first) => match head {
            Ok(head) => Some(head),
            Err(error) if super::tls::is_peer_gone(&error) => None,
            Err(error) => return Err(error.into()),
        },
        accepted = listener.accept() => {
            let (mut second, _) = accepted?;
            let authorized = read_head(&mut second).await?;
            let relay = establish_relay(second, origin).await?;
            return Ok(EstablishedTunnel::new((anonymous, authorized, false), relay));
        }
    };
    if let Some(authorized) = replay {
        let relay = establish_relay(first, origin).await?;
        return Ok(EstablishedTunnel::new((anonymous, authorized, true), relay));
    }
    let (mut second, _) = listener.accept().await?;
    let authorized = read_head(&mut second).await?;
    let relay = establish_relay(second, origin).await?;
    Ok(EstablishedTunnel::new(
        (anonymous, authorized, false),
        relay,
    ))
}

/// Accepts one TLS HTTP/1.1 CONNECT and tunnels it to `origin`.
pub(crate) async fn https1_connect(
    listener: TcpListener,
    acceptor: SslAcceptor,
    origin: SocketAddr,
) -> TestResult<EstablishedTunnel<Vec<u8>>> {
    https1_connect_on(&listener, acceptor, origin).await
}

/// [`https1_connect`] on a borrowed listener.
pub(crate) async fn https1_connect_on(
    listener: &TcpListener,
    acceptor: SslAcceptor,
    origin: SocketAddr,
) -> TestResult<EstablishedTunnel<Vec<u8>>> {
    let (tcp, _) = listener.accept().await?;
    let mut downstream = accept_tls_stream(tcp, acceptor).await?;
    let request = read_head(&mut downstream).await?;
    let relay = establish_relay(downstream, origin).await?;
    Ok(EstablishedTunnel::new(request, relay))
}

/// Accepts one TLS HTTP/1.1 CONNECT and tunnels it to `origin`, returning
/// the client certificate the proxy's handshake received, if any.
pub(crate) async fn https1_connect_recording_client_certificate(
    listener: TcpListener,
    acceptor: SslAcceptor,
    origin: SocketAddr,
) -> TestResult<EstablishedTunnel<Option<Vec<u8>>>> {
    let (tcp, _) = listener.accept().await?;
    let mut downstream = accept_tls_stream(tcp, acceptor).await?;
    let presented = downstream
        .ssl()
        .peer_certificate()
        .map(|certificate| certificate.to_der())
        .transpose()?;
    read_head(&mut downstream).await?;
    let relay = establish_relay(downstream, origin).await?;
    Ok(EstablishedTunnel::new(presented, relay))
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

/// Challenges the first TLS HTTP/1.1 CONNECT with a keep-alive Basic `407`,
/// then tunnels the replay to `origin`, on the challenged connection or on a
/// new one.
///
/// Returns the anonymous head, the authorized head, and whether the replay
/// used the challenged connection.
pub(crate) async fn https1_challenge_then_connect(
    listener: TcpListener,
    acceptor: SslAcceptor,
    origin: SocketAddr,
) -> TestResult<EstablishedTunnel<(Vec<u8>, Vec<u8>, bool)>> {
    let (first, _) = listener.accept().await?;
    let mut first = accept_tls_stream(first, acceptor.clone()).await?;
    let anonymous = read_head(&mut first).await?;
    first.write_all(BASIC_CHALLENGE).await?;
    first.flush().await?;
    let replay = tokio::select! {
        head = read_head(&mut first) => match head {
            Ok(head) => Some(head),
            Err(error) if super::tls::is_peer_gone(&error) => None,
            Err(error) => return Err(error.into()),
        },
        accepted = listener.accept() => {
            let (second, _) = accepted?;
            let mut second = accept_tls_stream(second, acceptor).await?;
            let authorized = read_head(&mut second).await?;
            let relay = establish_relay(second, origin).await?;
            return Ok(EstablishedTunnel::new((anonymous, authorized, false), relay));
        }
    };
    if let Some(authorized) = replay {
        let relay = establish_relay(first, origin).await?;
        return Ok(EstablishedTunnel::new((anonymous, authorized, true), relay));
    }
    let (second, _) = listener.accept().await?;
    let mut second = accept_tls_stream(second, acceptor).await?;
    let authorized = read_head(&mut second).await?;
    let relay = establish_relay(second, origin).await?;
    Ok(EstablishedTunnel::new(
        (anonymous, authorized, false),
        relay,
    ))
}

/// The CONNECT request observed by an HTTP/2 proxy.
#[derive(Debug)]
pub(crate) struct Http2ConnectRecord {
    pub(crate) stream_id: u32,
    pub(crate) authority: Option<String>,
    pub(crate) fields: Vec<(String, Vec<u8>)>,
}

/// The CONNECT streams an HTTP/2 proxy connection received after its tunnel
/// opened. The proxy resets each one.
pub(crate) type LateConnects = Arc<Mutex<Vec<Http2ConnectRecord>>>;

/// Accepts one h2-only TLS proxy connection, answers one RFC 9113 CONNECT
/// with 200, and relays its DATA to `origin`.
///
/// The HTTP/2 server rejects `:scheme` or `:path` in a classic CONNECT, so a
/// recorded request proves the proxy leg spoke HTTP/2 CONNECT.
pub(crate) async fn http2_connect(
    listener: TcpListener,
    acceptor: SslAcceptor,
    origin: SocketAddr,
) -> TestResult<EstablishedTunnel<Http2ConnectRecord>> {
    http2_connect_on(&listener, acceptor, origin).await
}

/// [`http2_connect`] on a borrowed listener.
pub(crate) async fn http2_connect_on(
    listener: &TcpListener,
    acceptor: SslAcceptor,
    origin: SocketAddr,
) -> TestResult<EstablishedTunnel<Http2ConnectRecord>> {
    let tunnel = http2_connects(listener, acceptor, origin, false).await?;
    let EstablishedTunnel {
        observed: (mut records, _),
        peers,
    } = tunnel;
    let observed = records.pop().ok_or("no CONNECT was served")?;
    Ok(EstablishedTunnel { observed, peers })
}

/// Accepts one h2-only TLS proxy connection, answers its first CONNECT with a
/// Basic `407` and the next with 200, and relays that stream to `origin`.
///
/// Returns both requests and whether no other proxy connection arrived
/// within 100 ms after the tunnel opened.
pub(crate) async fn http2_challenge_then_connect(
    listener: TcpListener,
    acceptor: SslAcceptor,
    origin: SocketAddr,
) -> TestResult<EstablishedTunnel<(Vec<Http2ConnectRecord>, bool)>> {
    let tunnel = http2_challenge_then_connect_on(&listener, acceptor, origin).await?;
    let quiet = no_connection_arrives(&listener).await;
    Ok(tunnel.map(|(records, _)| (records, quiet)))
}

/// Serves [`http2_challenge_then_connect`]'s two CONNECTs on a borrowed
/// listener and returns both requests and the log of any later CONNECT on
/// the same proxy connection.
pub(crate) async fn http2_challenge_then_connect_on(
    listener: &TcpListener,
    acceptor: SslAcceptor,
    origin: SocketAddr,
) -> TestResult<EstablishedTunnel<(Vec<Http2ConnectRecord>, LateConnects)>> {
    http2_connects(listener, acceptor, origin, true).await
}

/// Returns whether no other connection arrives at `listener` within 100 ms.
pub(crate) async fn no_connection_arrives(listener: &TcpListener) -> bool {
    timeout(Duration::from_millis(100), listener.accept())
        .await
        .is_err()
}

async fn http2_connects(
    listener: &TcpListener,
    acceptor: SslAcceptor,
    origin: SocketAddr,
    challenge_first: bool,
) -> TestResult<EstablishedTunnel<(Vec<Http2ConnectRecord>, LateConnects)>> {
    let (tcp, _) = listener.accept().await?;
    let stream = accept_tls_stream(tcp, acceptor).await?;
    if stream.ssl().selected_alpn_protocol() != Some(b"h2") {
        return Err("proxy connection did not select h2".into());
    }
    let mut connection = ::http2::server::handshake(stream).await?;
    let mut records = Vec::new();
    let mut peers = Vec::new();
    let mut challenge = challenge_first;
    loop {
        let (request, mut respond) = connection
            .accept()
            .await
            .ok_or("proxy connection closed before CONNECT")??;
        if request.method() != Method::CONNECT {
            return Err("proxy received a non-CONNECT request".into());
        }
        records.push(connect_record(&request, respond.stream_id().as_u32())?);
        if challenge {
            let response = Response::builder()
                .status(407)
                .header("proxy-authenticate", "Basic realm=\"websocket\"")
                .body(())?;
            respond.send_response(response, true)?;
            challenge = false;
            continue;
        }
        let send = respond.send_response(Response::new(()), false)?;
        let upstream = TcpStream::connect(origin).await?;
        spawn_http2_relay(request.into_body(), send, upstream, &mut peers);
        break;
    }
    let late = LateConnects::default();
    let log = Arc::clone(&late);
    peers.push(ConnectionPeer::spawn(async move {
        // Dropping each responder resets its stream.
        while let Some(accepted) = connection.accept().await {
            let (request, respond) = match accepted {
                Ok(accepted) => accepted,
                Err(error) => return relay_result(Err(error.into())),
            };
            let record = connect_record(&request, respond.stream_id().as_u32())?;
            log.lock()
                .map_err(|_| "late CONNECT log was poisoned")?
                .push(record);
        }
        TestResult::Ok(())
    }));
    Ok(EstablishedTunnel {
        observed: (records, late),
        peers,
    })
}

fn connect_record<B>(request: &http::Request<B>, stream_id: u32) -> TestResult<Http2ConnectRecord> {
    Ok(Http2ConnectRecord {
        stream_id,
        authority: request.uri().authority().map(ToString::to_string),
        fields: request
            .extensions()
            .get::<::http2::ext::OrderedHeaders>()
            .ok_or("missing ordered CONNECT fields")?
            .as_slice()
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect(),
    })
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
) -> TestResult<EstablishedTunnel<(Socks5Target, u16)>> {
    socks5_connect_on(&listener, origin).await
}

/// [`socks5_connect`] on a borrowed listener.
pub(crate) async fn socks5_connect_on(
    listener: &TcpListener,
    origin: SocketAddr,
) -> TestResult<EstablishedTunnel<(Socks5Target, u16)>> {
    let (mut downstream, _) = listener.accept().await?;
    let target = socks5_request(&mut downstream).await?;
    let upstream = TcpStream::connect(origin).await?;
    downstream
        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
        .await?;
    downstream.flush().await?;
    Ok(EstablishedTunnel::new(
        target,
        spawn_relay(downstream, upstream),
    ))
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

async fn establish_relay<S>(
    mut downstream: S,
    origin: SocketAddr,
) -> io::Result<ConnectionPeer<TestResult<()>>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let upstream = TcpStream::connect(origin).await?;
    downstream.write_all(ESTABLISHED).await?;
    downstream.flush().await?;
    Ok(spawn_relay(downstream, upstream))
}

fn spawn_relay<S>(mut downstream: S, mut upstream: TcpStream) -> ConnectionPeer<TestResult<()>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    ConnectionPeer::spawn(async move {
        match copy_bidirectional(&mut downstream, &mut upstream).await {
            Ok(_) => Ok(()),
            Err(error) if super::tls::is_peer_gone(&error) => Ok(()),
            Err(error) => Err(error.into()),
        }
    })
}

fn spawn_http2_relay(
    mut downstream: ::http2::RecvStream,
    mut send: ::http2::SendStream<Bytes>,
    upstream: TcpStream,
    peers: &mut Vec<ConnectionPeer<TestResult<()>>>,
) {
    let (mut read, mut write) = upstream.into_split();
    peers.push(ConnectionPeer::spawn(async move {
        let result: TestResult<()> = async {
            while let Some(chunk) = downstream.data().await {
                let chunk = chunk?;
                downstream.flow_control().release_capacity(chunk.len())?;
                write.write_all(&chunk).await?;
            }
            write.shutdown().await?;
            TestResult::Ok(())
        }
        .await;
        relay_result(result)
    }));
    peers.push(ConnectionPeer::spawn(async move {
        let result: TestResult<()> = async {
            let mut buffer = vec![0_u8; 16 * 1024];
            loop {
                let count = tokio::select! {
                    biased;
                    reset = poll_fn(|context| send.poll_reset(context)) => {
                        return http2_reset_result(reset);
                    }
                    count = read.read(&mut buffer) => count?,
                };
                if count == 0 {
                    send_http2_data(&mut send, Bytes::new(), true)?;
                    return TestResult::Ok(());
                }
                let mut chunk = Bytes::copy_from_slice(&buffer[..count]);
                while !chunk.is_empty() {
                    send.reserve_capacity(chunk.len());
                    let Some(capacity) = poll_fn(|context| {
                        match send.poll_reset(context) {
                            Poll::Ready(reset) => {
                                return Poll::Ready(http2_reset_result(reset).map(|()| None));
                            }
                            Poll::Pending => {}
                        }
                        match send.poll_capacity(context) {
                            Poll::Ready(Some(result)) => {
                                Poll::Ready(result.map(Some).map_err(Into::into))
                            }
                            Poll::Ready(None) => Poll::Ready(Err(
                                "proxy CONNECT response stream closed during relay".into(),
                            )),
                            Poll::Pending => Poll::Pending,
                        }
                    })
                    .await?
                    else {
                        return TestResult::Ok(());
                    };
                    let part = chunk.split_to(capacity.min(chunk.len()));
                    send_http2_data(&mut send, part, false)?;
                }
            }
        }
        .await;
        relay_result(result)
    }));
}

fn send_http2_data(
    send: &mut ::http2::SendStream<Bytes>,
    data: Bytes,
    end_stream: bool,
) -> TestResult<()> {
    match send.send_data(data, end_stream) {
        Ok(()) => Ok(()),
        Err(error) => {
            // A reset can arrive between reading the origin and sending DATA.
            // Probe once: awaiting a reset would hang after a local END_STREAM.
            let mut context = Context::from_waker(Waker::noop());
            match send.poll_reset(&mut context) {
                Poll::Ready(Ok(::http2::Reason::CANCEL)) => Ok(()),
                _ => Err(error.into()),
            }
        }
    }
}

fn http2_reset_result(reset: Result<::http2::Reason, ::http2::Error>) -> TestResult<()> {
    match reset {
        Ok(::http2::Reason::CANCEL) => Ok(()),
        Ok(reason) => Err(::http2::Error::from(reason).into()),
        Err(error) => Err(error.into()),
    }
}

/// A deliberate peer teardown can reset the stream or close its transport.
/// Decoder errors, local misuse, and other protocol reasons remain failures.
pub(crate) fn relay_result(result: TestResult<()>) -> TestResult<()> {
    match result {
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(super::tls::is_peer_gone) =>
        {
            Ok(())
        }
        Err(error)
            if error.downcast_ref::<::http2::Error>().is_some_and(|error| {
                error.get_io().is_some_and(|error| {
                    matches!(
                        error.kind(),
                        io::ErrorKind::BrokenPipe
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                    )
                }) || (error.is_remote()
                    && ((error.is_reset() && error.reason() == Some(::http2::Reason::CANCEL))
                        || (error.is_go_away()
                            && error.reason() == Some(::http2::Reason::NO_ERROR))))
            }) =>
        {
            Ok(())
        }
        result => result,
    }
}
