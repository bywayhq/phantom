use crate::{Config, Ready, Result, read_control, signal, write_json};
use bytes::Bytes;
use flate2::{Compression, write::GzEncoder};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use serde::Serialize;
use std::{
    io::Write,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    task::JoinSet,
};
use tokio_rustls::TlsAcceptor;

#[derive(Default, Serialize)]
struct Stats {
    connections: AtomicUsize,
    requests: AtomicUsize,
    proxy_connections: AtomicUsize,
    failures: AtomicUsize,
    completed_h1_boundary_closes: AtomicUsize,
    completed_h3_no_error_closes: AtomicUsize,
    completed_h3_idle_timeouts: AtomicUsize,
    #[serde(skip)]
    phase_complete: AtomicBool,
    #[serde(skip)]
    expected_requests: usize,
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
        if !head.starts_with("GET ") {
            return Err("benchmark peer accepts only GET".into());
        }
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
    while let Some(request) = connection.accept().await {
        let (request, mut respond) = request?;
        if request.method() != http::Method::GET {
            return Err("benchmark peer accepts only GET".into());
        }
        let (body, stats) = (body.clone(), stats.clone());
        responses.spawn(async move {
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
        }
    }
    while let Some(result) = responses.join_next().await {
        result??;
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
                        Err(error) => return Err(error.into()),
                    };
                    let (body, stats) = (body.clone(), stats.clone());
                    let completed = completed.clone();
                    responses.spawn(async move {
                        let (request, mut stream) = resolver.resolve_request().await?;
                        if request.method() != http::Method::GET {
                            return Err("benchmark peer accepts only GET".into());
                        }
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

async fn proxy(socket: TcpStream, targets: Arc<Vec<SocketAddr>>, socks: bool) -> Result<()> {
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
            connections.spawn(async move {
                record(proxy(socket, targets, socks).await, &stats);
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
    use tokio::io::ReadBuf;

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
    struct AbruptPeer(&'static [u8]);

    impl AsyncRead for AbruptPeer {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.0.is_empty() {
                return Poll::Ready(Err(std::io::ErrorKind::UnexpectedEof.into()));
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
            AbruptPeer(b""),
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
            AbruptPeer(b"GET / HTTP/1.1\r\n\r\n"),
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
            AbruptPeer(b"GET / HTTP/1.1\r\n\r\nGET /part"),
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
