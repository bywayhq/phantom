use crate::{Config, Ready, Result, read_control, signal, write_json};
use bytes::{Buf, Bytes};
use flate2::{Compression, write::GzEncoder};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use serde::Serialize;
use std::{
    io::Write,
    net::Ipv4Addr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpListener,
    task::JoinSet,
};
use tokio_rustls::TlsAcceptor;

mod delay;
mod proxy;
mod upload;

#[derive(Default, Serialize)]
struct Stats {
    connections: AtomicUsize,
    requests: AtomicUsize,
    cancelled_streams: AtomicUsize,
    cancelled_while_multiplexed: AtomicUsize,
    #[serde(skip)]
    settlement: tokio::sync::Notify,
    proxy_connections: AtomicUsize,
    proxy_tunnels: AtomicUsize,
    proxy_authenticated_connections: AtomicUsize,
    proxy_auth_challenges: AtomicUsize,
    failures: AtomicUsize,
    uploaded_bytes: AtomicU64,
    redirect_responses: AtomicUsize,
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

#[derive(Clone)]
struct Body {
    bytes: Bytes,
    chunk_bytes: usize,
    delay: Duration,
    chunk_delay: Duration,
    gzip: bool,
    upload: upload::Upload,
    redirects: usize,
    redirect_location: Option<String>,
    cancellation_enabled: bool,
    cancel: bool,
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
            redirects: config.redirects,
            redirect_location: None,
            cancellation_enabled: config.cancel_after_bytes != 0,
            cancel: false,
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
            .status(if self.redirect_location.is_some() {
                302
            } else {
                200
            })
            .header("content-length", self.bytes.len());
        if self.gzip {
            response = response.header("content-encoding", "gzip");
        }
        if let Some(location) = &self.redirect_location {
            response = response.header("location", location);
        }
        Ok(response.body(())?)
    }

    fn for_target(&self, target: &str) -> Result<Self> {
        if self.cancellation_enabled {
            let mut body = self.clone();
            let uri: http::Uri = target.parse()?;
            body.cancel = match uri.path_and_query().map(|value| value.as_str()) {
                Some("/") => false,
                Some("/?cancel=1") => true,
                _ => return Err("unexpected cancellation request target".into()),
            };
            return Ok(body);
        }
        let target: http::Uri = target.parse()?;
        let mut response = self.clone();
        if self.redirects != 0 {
            let remaining: usize = target
                .query()
                .and_then(|query| query.strip_prefix("redirects="))
                .ok_or("missing redirect target")?
                .parse()?;
            if remaining > self.redirects {
                return Err("invalid redirect target".into());
            }
            if remaining != 0 {
                response.bytes = Bytes::new();
                response.gzip = false;
                response.redirect_location = Some(format!("/?redirects={}", remaining - 1));
            }
        }
        Ok(response)
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
        let target = body.upload.http1(&head, &mut stream).await?;
        stats
            .uploaded_bytes
            .fetch_add(body.upload.length() as u64, Ordering::Relaxed);
        let body = body.for_target(&target)?;
        body.before_head().await;
        let encoding = if body.gzip {
            "content-encoding: gzip\r\n"
        } else {
            ""
        };
        let head = format!(
            "HTTP/1.1 {}\r\ncontent-length: {}\r\n{encoding}{}\r\n",
            if body.redirect_location.is_some() {
                "302 Found"
            } else {
                "200 OK"
            },
            body.bytes.len(),
            body.redirect_location
                .as_ref()
                .map(|location| format!("location: {location}\r\n"))
                .unwrap_or_default()
        );
        stream.get_mut().write_all(head.as_bytes()).await?;
        for chunk in body.bytes.chunks(body.chunk_bytes) {
            body.before_chunk().await;
            stream.get_mut().write_all(chunk).await?;
        }
        stream.get_mut().flush().await?;
        stats.requests.fetch_add(1, Ordering::Relaxed);
        if body.redirect_location.is_some() {
            stats.redirect_responses.fetch_add(1, Ordering::Relaxed);
        }
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
    let active_full = Arc::new(AtomicUsize::new(0));
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
        let response_body = body.for_target(&request.uri().to_string())?;
        let mut incoming = request.into_body();
        received += 1;
        let (body, stats) = (response_body, stats.clone());
        let active_full = active_full.clone();
        if !body.cancel {
            active_full.fetch_add(1, Ordering::Relaxed);
        }
        responses.spawn(async move {
            let result: Result<()> = async {
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
                        let capacity = match std::future::poll_fn(|cx| send.poll_capacity(cx)).await
                        {
                            Some(capacity) => capacity?,
                            None => {
                                // Capacity closes on a reset. Retain its typed reason.
                                let reason = std::future::poll_fn(|cx| send.poll_reset(cx)).await?;
                                return Err(http2::Error::from(reason).into());
                            }
                        };
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
                if body.redirect_location.is_some() {
                    stats.redirect_responses.fetch_add(1, Ordering::Relaxed);
                }
                Ok(())
            }
            .await;
            let result = if body.cancel
                && result.as_ref().err().is_some_and(|error| {
                    error
                        .downcast_ref::<http2::Error>()
                        .is_some_and(|error| error.reason() == Some(http2::Reason::CANCEL))
                }) {
                stats.cancelled_streams.fetch_add(1, Ordering::Relaxed);
                if active_full.load(Ordering::Relaxed) > 0 {
                    stats
                        .cancelled_while_multiplexed
                        .fetch_add(1, Ordering::Relaxed);
                }
                Ok(())
            } else {
                result
            };
            if !body.cancel {
                active_full.fetch_sub(1, Ordering::Relaxed);
            }
            stats.settlement.notify_one();
            result
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
                        let body = body.for_target(&request.uri().to_string())?;
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
                        if body.redirect_location.is_some() {
                            stats.redirect_responses.fetch_add(1, Ordering::Relaxed);
                        }
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
        expected_requests: (config.requests + config.warmup) * (config.redirects + 1),
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
        urls.push(if config.redirects == 0 {
            format!("https://{address}/")
        } else {
            format!("https://{address}/?redirects={}", config.redirects)
        });
        addresses.push(address);
    }
    let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy_address = proxy_listener.local_addr()?;
    let proxy_stats = stats.clone();
    let proxy_password = if config.proxy_auth {
        proxy::password()?
    } else {
        String::new()
    };
    let proxy_credential = config
        .proxy_auth
        .then(|| proxy::credential(&proxy_password));
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
            let credential = proxy_credential.clone();
            connections.spawn(async move {
                record(
                    proxy::serve(
                        socket,
                        targets,
                        socks,
                        delay_ms,
                        credential.as_deref(),
                        &stats,
                    )
                    .await,
                    &stats,
                );
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
            proxy_password,
        },
    )?;
    signal("ready")?;
    loop {
        match read_control()?.as_str() {
            "snapshot" => {
                if config.cancel_after_bytes != 0 {
                    // Await actual response/reset outcomes, not an arbitrary grace sleep.
                    let settled = tokio::time::timeout(Duration::from_secs(5), async {
                        loop {
                            let notified = stats.settlement.notified();
                            if stats.requests.load(Ordering::Relaxed)
                                + stats.cancelled_streams.load(Ordering::Relaxed)
                                == stats.expected_requests
                            {
                                break;
                            }
                            notified.await;
                        }
                    })
                    .await;
                    if settled.is_err() {
                        stats.failures.fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "cancellation outcomes did not settle before the snapshot deadline"
                        );
                    }
                }
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
mod tests;
