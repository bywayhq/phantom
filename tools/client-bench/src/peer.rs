use crate::{Config, Ready, Result, read_control, signal, write_json};
use bytes::{Buf, Bytes};
use flate2::{Compression, write::GzEncoder};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use serde::Serialize;
use std::{
    io::Write,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    task::JoinSet,
};
use tokio_rustls::TlsAcceptor;

mod delay;
mod upload;

#[derive(Default, Serialize)]
struct Stats {
    connections: AtomicUsize,
    requests: AtomicUsize,
    proxy_connections: AtomicUsize,
    failures: AtomicUsize,
    uploaded_bytes: AtomicU64,
    completed_h1_boundary_closes: AtomicUsize,
    completed_h2_boundary_closes: AtomicUsize,
    completed_h3_no_error_closes: AtomicUsize,
    completed_h3_transport_no_error_closes: AtomicUsize,
    completed_h3_application_zero_closes: AtomicUsize,
    completed_h3_idle_timeouts: AtomicUsize,
    #[serde(skip)]
    phase_complete: AtomicBool,
    #[serde(skip)]
    expected_requests: usize,
}

fn quic_transport_no_error(error: &h3::error::ConnectionError) -> bool {
    // RFC 9000 section 20.1: transport NO_ERROR is distinct from H3_NO_ERROR.
    let h3::error::ConnectionError::Remote(h3::quic::ConnectionErrorIncoming::Undefined(reason)) =
        error
    else {
        return false;
    };
    matches!(
        reason.downcast_ref::<quinn::ConnectionError>(),
        Some(quinn::ConnectionError::ConnectionClosed(close))
            if close.error_code == quinn::TransportErrorCode::NO_ERROR
    )
}

fn quic_application_zero(error: &h3::error::ConnectionError) -> bool {
    matches!(
        error,
        h3::error::ConnectionError::Remote(h3::quic::ConnectionErrorIncoming::ApplicationClose {
            error_code: 0
        })
    )
}

fn completed_http2_close(error: &http2::Error, received: usize, completed: usize) -> bool {
    received > 0
        && received == completed
        && error.get_io().is_some_and(|error| {
            matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
            )
        })
}

impl Stats {
    fn completed_idle_timeout(
        &self,
        error: &h3::error::ConnectionError,
        reason: Option<&quinn::ConnectionError>,
    ) -> bool {
        self.phase_complete.load(Ordering::Acquire)
            && self.requests.load(Ordering::Relaxed) == self.expected_requests
            && matches!(error, h3::error::ConnectionError::Timeout)
            && matches!(reason, Some(quinn::ConnectionError::TimedOut))
    }
}

#[derive(Debug)]
struct BoundaryClose(std::io::Error);

impl std::fmt::Display for BoundaryClose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for BoundaryClose {}

struct Body {
    bytes: Bytes,
    chunk_bytes: usize,
    delay: Duration,
    chunk_delay: Duration,
    gzip: bool,
    upload: upload::Upload,
}

impl Body {
    fn new(config: &Config) -> Result<Self> {
        let mut bytes = vec![b'Z'; config.bytes];
        if config.gzip {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
            encoder.write_all(&bytes)?;
            bytes = encoder.finish()?;
        }
        Ok(Self {
            bytes: bytes.into(),
            chunk_bytes: config.chunk_bytes,
            delay: Duration::from_millis(config.server_delay_ms),
            chunk_delay: Duration::from_millis(config.chunk_delay_ms),
            gzip: config.gzip,
            upload: upload::Upload::new(config),
        })
    }

    async fn before_head(&self) {
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
    }
    async fn before_chunk(&self) {
        if !self.chunk_delay.is_zero() {
            tokio::time::sleep(self.chunk_delay).await;
        }
    }
    fn head(&self) -> Result<http::Response<()>> {
        let mut response = http::Response::builder()
            .status(200)
            .header("content-length", self.bytes.len());
        if self.gzip {
            response = response.header("content-encoding", "gzip");
        }
        Ok(response.body(())?)
    }
}

async fn read_head<S: AsyncRead + Unpin>(reader: &mut BufReader<S>) -> Result<Option<String>> {
    let mut head = String::new();
    loop {
        let mut line = String::new();
        let read = match reader.read_line(&mut line).await {
            Ok(read) => read,
            Err(error)
                if head.is_empty()
                    && line.is_empty()
                    && error.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                return Err(Box::new(BoundaryClose(error)));
            }
            Err(error) => return Err(error.into()),
        };
        if read == 0 {
            return if head.is_empty() {
                Ok(None)
            } else {
                Err("truncated request".into())
            };
        }
        head.push_str(&line);
        if head.len() > 65536 {
            return Err("request head too large".into());
        }
        if line == "\r\n" {
            return Ok(Some(head));
        }
    }
}

async fn http1<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    body: Arc<Body>,
    stats: Arc<Stats>,
) -> Result<()> {
    let mut stream = BufReader::new(stream);
    let mut completed = 0;
    loop {
        let head = match read_head(&mut stream).await {
            Ok(Some(head)) => head,
            Ok(None) => break,
            Err(error) if completed > 0 && error.is::<BoundaryClose>() => {
                stats
                    .completed_h1_boundary_closes
                    .fetch_add(1, Ordering::Relaxed);
                eprintln!("completed H1 connection closed at next-head boundary: {error}");
                break;
            }
            Err(error) => return Err(error),
        };
        body.upload.http1(&head, &mut stream).await?;
        stats
            .uploaded_bytes
            .fetch_add(body.upload.length() as u64, Ordering::Relaxed);
        body.before_head().await;
        let encoding = if body.gzip {
            "content-encoding: gzip\r\n"
        } else {
            ""
        };
        let head = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n{encoding}\r\n",
            body.bytes.len()
        );
        stream.get_mut().write_all(head.as_bytes()).await?;
        for chunk in body.bytes.chunks(body.chunk_bytes) {
            body.before_chunk().await;
            stream.get_mut().write_all(chunk).await?;
        }
        stream.get_mut().flush().await?;
        stats.requests.fetch_add(1, Ordering::Relaxed);
        completed += 1;
    }
    Ok(())
}

async fn http2<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    body: Arc<Body>,
    stats: Arc<Stats>,
) -> Result<()> {
    let mut connection = http2::server::handshake(stream).await?;
    let mut responses = JoinSet::new();
    let (mut received, mut completed) = (0, 0);
    let mut close_error = None;
    while let Some(request) = connection.accept().await {
        let (request, mut respond) = match request {
            Ok(request) => request,
            Err(error) => {
                close_error = Some(error);
                break;
            }
        };
        body.upload
            .head(request.method(), request.headers(), false)?;
        let mut incoming = request.into_body();
        received += 1;
        let (body, stats) = (body.clone(), stats.clone());
        responses.spawn(async move {
            let mut observed = 0;
            while let Some(data) = incoming.data().await {
                let data = data?;
                body.upload.chunk(&mut observed, &data)?;
                incoming.flow_control().release_capacity(data.len())?;
            }
            if incoming.trailers().await?.is_some() {
                return Err("benchmark upload must have no trailers".into());
            }
            body.upload.finish(observed)?;
            stats
                .uploaded_bytes
                .fetch_add(observed as u64, Ordering::Relaxed);
            body.before_head().await;
            let mut send = respond.send_response(body.head()?, body.bytes.is_empty())?;
            let mut offset = 0;
            while offset < body.bytes.len() {
                body.before_chunk().await;
                let chunk_end = (offset + body.chunk_bytes).min(body.bytes.len());
                while offset < chunk_end {
                    let wanted = chunk_end - offset;
                    send.reserve_capacity(wanted);
                    let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx))
                        .await
                        .ok_or("H2 stream closed")??;
                    let length = wanted.min(capacity);
                    if length == 0 {
                        continue;
                    }
                    send.send_data(
                        body.bytes.slice(offset..offset + length),
                        offset + length == body.bytes.len(),
                    )?;
                    offset += length;
                }
            }
            stats.requests.fetch_add(1, Ordering::Relaxed);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        while let Some(result) = responses.try_join_next() {
            result??;
            completed += 1;
        }
    }
    while let Some(result) = responses.join_next().await {
        result??;
        completed += 1;
    }
    if let Some(error) = close_error {
        if !completed_http2_close(&error, received, completed) {
            return Err(error.into());
        }
        stats
            .completed_h2_boundary_closes
            .fetch_add(1, Ordering::Relaxed);
        eprintln!("completed H2 connection closed after all responses: {error}");
    }
    Ok(())
}

fn record(result: Result<()>, stats: &Stats) {
    if let Err(error) = result {
        stats.failures.fetch_add(1, Ordering::Relaxed);
        eprintln!("peer connection: {error}");
    }
}

async fn tcp_listener(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    protocol: String,
    body: Arc<Body>,
    stats: Arc<Stats>,
) -> Result<()> {
    let mut connections = JoinSet::new();
    loop {
        let (socket, _) = listener.accept().await?;
        socket.set_nodelay(true)?;
        stats.connections.fetch_add(1, Ordering::Relaxed);
        let (acceptor, protocol, body, stats) = (
            acceptor.clone(),
            protocol.clone(),
            body.clone(),
            stats.clone(),
        );
        connections.spawn(async move {
            let result = async {
                let tls = acceptor.accept(socket).await?;
                if protocol == "h1" {
                    http1(tls, body, stats.clone()).await
                } else {
                    http2(tls, body, stats.clone()).await
                }
            }
            .await;
            record(result, &stats);
        });
        while let Some(result) = connections.try_join_next() {
            result?;
        }
    }
}

async fn quic_listener(
    endpoint: quinn::Endpoint,
    body: Arc<Body>,
    stats: Arc<Stats>,
) -> Result<()> {
    let mut connections = JoinSet::new();
    while let Some(incoming) = endpoint.accept().await {
        stats.connections.fetch_add(1, Ordering::Relaxed);
        let (body, stats) = (body.clone(), stats.clone());
        connections.spawn(async move {
            let result = async {
                let quic = incoming.await?;
                let mut connection =
                    h3::server::Connection::new(h3_quinn::Connection::new(quic.clone())).await?;
                let mut responses = JoinSet::new();
                let completed = Arc::new(AtomicUsize::new(0));
                loop {
                    let resolver = match connection.accept().await {
                        Ok(Some(resolver)) => resolver,
                        Ok(None) => break,
                        Err(error)
                            if stats
                                .completed_idle_timeout(&error, quic.close_reason().as_ref()) =>
                        {
                            while let Some(result) = responses.join_next().await {
                                result??;
                            }
                            stats
                                .completed_h3_idle_timeouts
                                .fetch_add(1, Ordering::Relaxed);
                            eprintln!("completed H3 connection reached idle timeout: {error}");
                            break;
                        }
                        Err(error) if error.is_h3_no_error() => {
                            while let Some(result) = responses.join_next().await {
                                result??;
                            }
                            if completed.load(Ordering::Relaxed) == 0 {
                                return Err(error.into());
                            }
                            stats
                                .completed_h3_no_error_closes
                                .fetch_add(1, Ordering::Relaxed);
                            eprintln!("completed H3 connection closed: {error}");
                            break;
                        }
                        Err(error) if quic_transport_no_error(&error) => {
                            while let Some(result) = responses.join_next().await {
                                result??;
                            }
                            if completed.load(Ordering::Relaxed) == 0 {
                                return Err(error.into());
                            }
                            stats
                                .completed_h3_transport_no_error_closes
                                .fetch_add(1, Ordering::Relaxed);
                            eprintln!(
                                "completed H3 connection closed with QUIC transport NO_ERROR: {error}"
                            );
                            break;
                        }
                        Err(error) if quic_application_zero(&error) => {
                            while let Some(result) = responses.join_next().await {
                                result??;
                            }
                            if completed.load(Ordering::Relaxed) == 0 {
                                return Err(error.into());
                            }
                            stats
                                .completed_h3_application_zero_closes
                                .fetch_add(1, Ordering::Relaxed);
                            eprintln!(
                                "completed H3 connection closed with application code zero: {error}"
                            );
                            break;
                        }
                        Err(error) => return Err(error.into()),
                    };
                    let (body, stats) = (body.clone(), stats.clone());
                    let completed = completed.clone();
                    responses.spawn(async move {
                        let (request, mut stream) = resolver.resolve_request().await?;
                        body.upload.head(request.method(), request.headers(), false)?;
                        // Reach request FIN before dropping its receive half.
                        // Quinn otherwise sends STOP_SENDING from that drop.
                        let mut observed = 0;
                        while let Some(mut data) = stream.recv_data().await? {
                            while data.has_remaining() {
                                let chunk = data.chunk();
                                body.upload.chunk(&mut observed, chunk)?;
                                let length = chunk.len();
                                data.advance(length);
                            }
                        }
                        if stream.recv_trailers().await?.is_some() {
                            return Err("benchmark upload must have no trailers".into());
                        }
                        body.upload.finish(observed)?;
                        stats.uploaded_bytes.fetch_add(observed as u64, Ordering::Relaxed);
                        body.before_head().await;
                        stream.send_response(body.head()?).await?;
                        for offset in (0..body.bytes.len()).step_by(body.chunk_bytes) {
                            body.before_chunk().await;
                            stream
                                .send_data(body.bytes.slice(
                                    offset..(offset + body.chunk_bytes).min(body.bytes.len()),
                                ))
                                .await?;
                        }
                        stream.finish().await?;
                        stats.requests.fetch_add(1, Ordering::Relaxed);
                        completed.fetch_add(1, Ordering::Relaxed);
                        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                    });
                    while let Some(result) = responses.try_join_next() {
                        result??;
                    }
                }
                while let Some(result) = responses.join_next().await {
                    result??;
                }
                Ok(())
            }
            .await;
            record(result, &stats);
        });
        while let Some(result) = connections.try_join_next() {
            result?;
        }
    }
    Ok(())
}

async fn proxy(
    socket: TcpStream,
    targets: Arc<Vec<SocketAddr>>,
    socks: bool,
    delay_ms: u64,
) -> Result<()> {
    if delay_ms == 0 {
        return proxy_stream(socket, targets, socks).await;
    }
    let (stream, relay) = tokio::io::duplex(64 * 1024);
    tokio::try_join!(proxy_stream(stream, targets, socks), async {
        delay::relay(socket, relay, Duration::from_millis(delay_ms)).await?;
        Result::Ok(())
    },)?;
    Ok(())
}

async fn proxy_stream<S: AsyncRead + AsyncWrite + Unpin>(
    socket: S,
    targets: Arc<Vec<SocketAddr>>,
    socks: bool,
) -> Result<()> {
    let mut stream = BufReader::new(socket);
    let target: SocketAddr = if socks {
        let mut greeting = [0; 2];
        stream.read_exact(&mut greeting).await?;
        if greeting != [5, 1] || stream.read_u8().await? != 0 {
            return Err("expected unauthenticated SOCKS5".into());
        }
        stream.get_mut().write_all(&[5, 0]).await?;
        let mut request = [0; 4];
        stream.read_exact(&mut request).await?;
        if request != [5, 1, 0, 1] {
            return Err("expected IPv4 SOCKS5 CONNECT".into());
        }
        let mut ip = [0; 4];
        stream.read_exact(&mut ip).await?;
        SocketAddr::from((ip, stream.read_u16().await?))
    } else {
        let head = read_head(&mut stream).await?.ok_or("missing CONNECT")?;
        let mut words = head.split_whitespace();
        if words.next() != Some("CONNECT") {
            return Err("expected CONNECT".into());
        }
        words.next().ok_or("missing target")?.parse()?
    };
    if !targets.contains(&target) {
        return Err("proxy target is not a benchmark origin".into());
    }
    let mut origin = TcpStream::connect(target).await?;
    origin.set_nodelay(true)?;
    if socks {
        stream
            .get_mut()
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .await?;
    } else {
        stream
            .get_mut()
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    }
    tokio::io::copy_bidirectional(&mut stream, &mut origin).await?;
    Ok(())
}

pub(crate) async fn serve(config: Config, ready_path: &Path, output: &Path) -> Result<()> {
    let identity =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])?;
    let cert = identity.cert.der().to_vec();
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.clone())],
            PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der()).into(),
        )?;
    tls.alpn_protocols = vec![config.protocol.as_bytes().to_vec()];
    if config.protocol == "h1" {
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    }
    let stats = Arc::new(Stats {
        expected_requests: config.requests + config.warmup,
        ..Stats::default()
    });
    let body = Arc::new(Body::new(&config)?);
    let mut listeners = JoinSet::new();
    let mut urls = Vec::new();
    let mut addresses = Vec::new();
    for _ in 0..config.origins {
        let address;
        if config.protocol == "h3" {
            let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls.clone())?;
            let endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(quinn::ServerConfig::with_crypto(Arc::new(crypto))),
                phantom_testkit::udp::bind((Ipv4Addr::LOCALHOST, 0).into())?,
                Arc::new(quinn::TokioRuntime),
            )?;
            address = endpoint.local_addr()?;
            listeners.spawn(quic_listener(endpoint, body.clone(), stats.clone()));
        } else {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            address = listener.local_addr()?;
            listeners.spawn(tcp_listener(
                listener,
                TlsAcceptor::from(Arc::new(tls.clone())),
                config.protocol.clone(),
                body.clone(),
                stats.clone(),
            ));
        }
        urls.push(format!("https://{address}/"));
        addresses.push(address);
    }
    let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy_address = proxy_listener.local_addr()?;
    let proxy_stats = stats.clone();
    listeners.spawn(async move {
        let targets = Arc::new(addresses);
        let mut connections = JoinSet::new();
        loop {
            let (socket, _) = proxy_listener.accept().await?;
            socket.set_nodelay(true)?;
            proxy_stats
                .proxy_connections
                .fetch_add(1, Ordering::Relaxed);
            let (targets, stats) = (targets.clone(), proxy_stats.clone());
            let socks = config.route == "socks5";
            let delay_ms = config.proxy_delay_ms;
            connections.spawn(async move {
                record(proxy(socket, targets, socks, delay_ms).await, &stats);
            });
            while let Some(result) = connections.try_join_next() {
                result?;
            }
        }
        #[allow(unreachable_code)]
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    write_json(
        ready_path,
        &Ready {
            urls,
            root_der: cert,
            proxy: proxy_address.to_string(),
        },
    )?;
    signal("ready")?;
    loop {
        match read_control()?.as_str() {
            "snapshot" => {
                write_json(&output.with_file_name("peer-phase.json"), &*stats)?;
                stats.phase_complete.store(true, Ordering::Release);
                signal("snapshotted")?;
            }
            "recovery-snapshot" => {
                write_json(&output.with_file_name("peer-recovery.json"), &*stats)?;
                signal("recovery-snapshotted")?;
            }
            "stop" => break,
            _ => return Err("controller disconnected or sent an invalid command".into()),
        }
    }
    // Report listener task failures even if no client could reach them.
    while let Some(result) = listeners.try_join_next() {
        result??;
    }
    write_json(output, &*stats)?;
    listeners.abort_all();
    signal("stopped")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    #[tokio::test]
    async fn completed_disconnects_keep_transport_and_application_errors_distinct() -> Result<()> {
        for kind in [
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::ConnectionAborted,
            std::io::ErrorKind::BrokenPipe,
            std::io::ErrorKind::UnexpectedEof,
        ] {
            let error = http2::server::handshake(AbruptPeer(b"", kind))
                .await
                .err()
                .ok_or("failed transport completed the handshake")?;
            assert!(completed_http2_close(&error, 1, 1));
            assert!(!completed_http2_close(&error, 0, 0));
            assert!(!completed_http2_close(&error, 2, 1));
        }
        assert!(!completed_http2_close(
            &http2::Reason::PROTOCOL_ERROR.into(),
            1,
            1
        ));
        let timeout = http2::server::handshake(AbruptPeer(b"", std::io::ErrorKind::TimedOut))
            .await
            .err()
            .ok_or("failed transport completed the handshake")?;
        assert!(!completed_http2_close(&timeout, 1, 1));
        let zero = h3::error::ConnectionError::Remote(
            h3::quic::ConnectionErrorIncoming::ApplicationClose { error_code: 0 },
        );
        assert!(quic_application_zero(&zero));
        assert!(!quic_transport_no_error(&zero));
        assert!(!quic_application_zero(&h3::error::ConnectionError::Remote(
            h3::quic::ConnectionErrorIncoming::ApplicationClose { error_code: 0x102 },
        )));
        assert!(!quic_application_zero(&h3::error::ConnectionError::Local {
            error: h3::error::internal_error::InternalConnectionError::new(
                h3::error::Code::H3_NO_ERROR,
                "local close".into(),
            )
            .into(),
        }));
        Ok(())
    }
    use tokio::io::ReadBuf;

    #[test]
    fn transport_no_error_requires_the_remote_transport_close_code() {
        use h3::{error::ConnectionError, quic::ConnectionErrorIncoming};

        let reason = |error_code| {
            quinn::ConnectionError::ConnectionClosed(quinn::ConnectionClose {
                error_code,
                frame_type: None,
                reason: Bytes::new(),
            })
        };
        let remote =
            |reason| ConnectionError::Remote(ConnectionErrorIncoming::Undefined(Arc::new(reason)));
        assert!(quic_transport_no_error(&remote(reason(
            quinn::TransportErrorCode::NO_ERROR
        ))));
        assert!(!quic_application_zero(&remote(reason(
            quinn::TransportErrorCode::NO_ERROR
        ))));
        assert!(!quic_transport_no_error(&remote(reason(
            quinn::TransportErrorCode::INTERNAL_ERROR
        ))));
        assert!(!quic_transport_no_error(&remote(
            quinn::ConnectionError::Reset
        )));
        assert!(!quic_transport_no_error(&remote(
            quinn::ConnectionError::TimedOut
        )));
        assert!(!quic_transport_no_error(&ConnectionError::Timeout));
        assert!(!quic_transport_no_error(&ConnectionError::Local {
            error: h3::error::internal_error::InternalConnectionError::new(
                h3::error::Code::H3_SETTINGS_ERROR,
                "invalid settings".into(),
            )
            .into(),
        }));
        assert!(!quic_transport_no_error(&ConnectionError::Remote(
            ConnectionErrorIncoming::ApplicationClose { error_code: 0 },
        )));
    }

    #[test]
    fn only_a_typed_idle_timeout_after_all_requests_is_completed_retirement() {
        let stats = Stats {
            expected_requests: 2,
            ..Stats::default()
        };
        let timeout = h3::error::ConnectionError::Timeout;
        let reason = quinn::ConnectionError::TimedOut;
        stats.requests.store(2, Ordering::Relaxed);
        assert!(!stats.completed_idle_timeout(&timeout, Some(&reason)));
        stats.phase_complete.store(true, Ordering::Release);
        assert!(stats.completed_idle_timeout(&timeout, Some(&reason)));
        stats.requests.store(1, Ordering::Relaxed);
        assert!(!stats.completed_idle_timeout(&timeout, Some(&reason)));
        stats.requests.store(3, Ordering::Relaxed);
        assert!(!stats.completed_idle_timeout(&timeout, Some(&reason)));
        stats.requests.store(2, Ordering::Relaxed);
        assert!(!stats.completed_idle_timeout(&timeout, None));
        assert!(!stats.completed_idle_timeout(&timeout, Some(&quinn::ConnectionError::Reset)));
    }
    struct AbruptPeer(&'static [u8], std::io::ErrorKind);

    struct ResetAtEof(tokio::io::DuplexStream);

    impl AsyncRead for ResetAtEof {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let before = buf.filled().len();
            match Pin::new(&mut self.0).poll_read(cx, buf) {
                Poll::Ready(Ok(())) if buf.filled().len() == before => {
                    Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()))
                }
                result => result,
            }
        }
    }

    impl AsyncWrite for ResetAtEof {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn h2_disconnect_only_records_fully_completed_responses() -> Result<()> {
        for consume in [true, false] {
            let (client, server) = tokio::io::duplex(65536);
            let config = Config {
                bytes: 65536,
                chunk_bytes: 1024,
                chunk_delay_ms: 1,
                ..Config::default()
            };
            let stats = Arc::new(Stats::default());
            let peer = tokio::spawn(http2(
                ResetAtEof(server),
                Arc::new(Body::new(&config)?),
                stats.clone(),
            ));
            let (mut sender, connection) = http2::client::handshake(client).await?;
            let driver = tokio::spawn(connection);
            let request = http::Request::builder()
                .uri("https://localhost/")
                .body(())?;
            let (response, _) = sender.send_request(request, true)?;
            let mut response = response.await?.into_body();
            if consume {
                let mut bytes = 0;
                while let Some(data) = response.data().await {
                    let data = data?;
                    assert!(data.iter().all(|byte| *byte == b'Z'));
                    bytes += data.len();
                    response.flow_control().release_capacity(data.len())?;
                }
                assert_eq!(bytes, config.bytes);
            }
            driver.abort();
            assert!(driver.await.is_err_and(|error| error.is_cancelled()));
            let outcome = tokio::time::timeout(Duration::from_secs(5), peer).await??;
            assert_eq!(outcome.is_ok(), consume);
            assert_eq!(
                stats.completed_h2_boundary_closes.load(Ordering::Relaxed),
                usize::from(consume)
            );
            assert_eq!(stats.requests.load(Ordering::Relaxed), usize::from(consume));
        }
        Ok(())
    }

    impl AsyncRead for AbruptPeer {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.0.is_empty() {
                return Poll::Ready(Err(self.1.into()));
            }
            let length = self.0.len().min(buf.remaining());
            buf.put_slice(&self.0[..length]);
            self.0 = &self.0[length..];
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for AbruptPeer {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn abrupt_close_before_any_response_fails() -> Result<()> {
        let stats = Arc::new(Stats::default());
        let result = http1(
            AbruptPeer(b"", std::io::ErrorKind::UnexpectedEof),
            Arc::new(Body::new(&Config::default())?),
            stats.clone(),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(
            stats.completed_h1_boundary_closes.load(Ordering::Relaxed),
            0
        );
        Ok(())
    }

    #[tokio::test]
    async fn abrupt_close_after_complete_response_is_recorded() -> Result<()> {
        let stats = Arc::new(Stats::default());
        http1(
            AbruptPeer(b"GET / HTTP/1.1\r\n\r\n", std::io::ErrorKind::UnexpectedEof),
            Arc::new(Body::new(&Config::default())?),
            stats.clone(),
        )
        .await?;
        assert_eq!(stats.requests.load(Ordering::Relaxed), 1);
        assert_eq!(
            stats.completed_h1_boundary_closes.load(Ordering::Relaxed),
            1
        );
        Ok(())
    }

    #[tokio::test]
    async fn partial_next_head_still_fails_after_a_complete_response() -> Result<()> {
        let stats = Arc::new(Stats::default());
        let result = http1(
            AbruptPeer(
                b"GET / HTTP/1.1\r\n\r\nGET /part",
                std::io::ErrorKind::UnexpectedEof,
            ),
            Arc::new(Body::new(&Config::default())?),
            stats.clone(),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(
            stats.completed_h1_boundary_closes.load(Ordering::Relaxed),
            0
        );
        Ok(())
    }
}
