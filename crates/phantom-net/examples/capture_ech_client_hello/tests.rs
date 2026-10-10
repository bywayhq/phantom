use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use btls::{
    ssl::{ErrorCode, SslConnector, SslMethod, SslVerifyMode},
    x509::X509,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_btls::SslStream;

use super::{
    CaptureResult, DnsAnswers, DohCapture, HOSTNAME, Identity, finish_capture, serve_doh,
    serve_doh_connection,
};

const IO_TIMEOUT: Duration = Duration::from_secs(3);
const DEADLINE_TEST_TIMEOUT: Duration = Duration::from_secs(12);
type Client = BufReader<SslStream<TcpStream>>;
type TestResult = CaptureResult<()>;

enum ServerMode {
    Capture,
    Connection,
}

struct Server {
    address: SocketAddr,
    trust_root: Vec<u8>,
    queries: Arc<Mutex<Vec<String>>>,
    task: Option<JoinHandle<CaptureResult<()>>>,
    shutdown: Option<oneshot::Sender<()>>,
}

impl Server {
    async fn start(mode: ServerMode) -> CaptureResult<Self> {
        let (identity, trust_root) = test_identity()?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(None)?;
        let queries = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&queries);
        let answers = DnsAnswers {
            address: address.ip(),
            port: address.port(),
            ech_config_list: Vec::new(),
            quic: false,
        };

        let (shutdown, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            match mode {
                ServerMode::Connection => {
                    let (tcp, _) = listener.accept().await?;
                    // The test sends hundreds of small exchanges, not packet timings.
                    tcp.set_nodelay(true)?;
                    serve_doh_connection(tcp, &acceptor, &recorded, &answers).await
                }
                ServerMode::Capture => {
                    serve_doh(listener, acceptor, recorded, answers, stopped).await
                }
            }
        });

        Ok(Self {
            address,
            trust_root,
            queries,
            task: Some(task),
            shutdown: Some(shutdown),
        })
    }

    async fn client(&self) -> CaptureResult<Client> {
        self.client_with_root(&self.trust_root).await
    }

    async fn client_with_root(&self, trust_root: &[u8]) -> CaptureResult<Client> {
        timeout(IO_TIMEOUT, async {
            let tcp = TcpStream::connect(self.address).await?;
            tcp.set_nodelay(true)?;
            let mut builder = SslConnector::bare_builder(SslMethod::tls())?;
            builder.set_verify(SslVerifyMode::PEER);
            builder
                .cert_store_mut()
                .add_cert(X509::from_der(trust_root)?)?;
            let ssl = builder.build().configure()?.into_ssl(HOSTNAME)?;
            let mut tls = SslStream::new(ssl, tcp)?;
            Pin::new(&mut tls).connect().await?;
            Ok(BufReader::new(tls))
        })
        .await?
    }

    async fn finish(&mut self, deadline: Duration) -> CaptureResult<()> {
        let task = self.task.as_mut().ok_or("DNS listener already joined")?;
        let result = timeout(deadline, task).await?;
        self.task.take();
        result?
    }

    async fn stop(&mut self) -> CaptureResult<()> {
        if let Some(shutdown) = self.shutdown.take() {
            shutdown
                .send(())
                .map_err(|()| "DNS listener already stopped")?;
        }
        self.finish(IO_TIMEOUT).await
    }

    fn take_capture(&mut self) -> CaptureResult<DohCapture> {
        Ok(DohCapture {
            shutdown: self.shutdown.take(),
            task: Some(self.task.take().ok_or("DNS listener already joined")?),
        })
    }

    fn descriptions(&self) -> Vec<String> {
        self.queries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        // A failed assertion must not leave the listener running.
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn test_identity() -> CaptureResult<(Identity, Vec<u8>)> {
    let mut root_params = CertificateParams::new(Vec::<String>::new())?;
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let root = CertifiedIssuer::self_signed(root_params, KeyPair::generate()?)?;

    let mut leaf_params = CertificateParams::new(vec![HOSTNAME.to_owned()])?;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params.use_authority_key_identifier_extension = true;
    let leaf_key = KeyPair::generate()?;
    let leaf = leaf_params.signed_by(&leaf_key, &root)?;

    Ok((
        Identity {
            certificate: leaf.der().to_vec(),
            private_key: leaf_key.serialize_der(),
        },
        root.der().to_vec(),
    ))
}

fn query(name: &str, record_type: u16) -> CaptureResult<Vec<u8>> {
    let mut wire = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        assert!(!label.is_empty() && label.len() <= 63);
        wire.push(u8::try_from(label.len())?);
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
    wire.extend_from_slice(&record_type.to_be_bytes());
    wire.extend_from_slice(&1_u16.to_be_bytes());
    Ok(wire)
}

async fn exchange(client: &mut Client, name: &str, record_type: u16) -> CaptureResult<Vec<u8>> {
    timeout(IO_TIMEOUT, async {
        let message = query(name, record_type)?;
        let mut request = format!(
            "POST /dns-query HTTP/1.1\r\nhost: {HOSTNAME}\r\ncontent-length: {}\r\n\r\n",
            message.len()
        )
        .into_bytes();
        request.extend_from_slice(&message);
        client.write_all(&request).await?;
        client.flush().await?;

        let mut status = String::new();
        client.read_line(&mut status).await?;
        if status != "HTTP/1.1 200 OK\r\n" {
            return Err(format!("expected DNS response, received {status:?}").into());
        }

        let mut length = None;
        loop {
            let mut line = String::new();
            let read = client.read_line(&mut line).await?;
            if read == 0 {
                return Err("DNS response ended before its header delimiter".into());
            }
            if line == "\r\n" {
                break;
            }
            let (name, value) = line.split_once(':').ok_or("invalid response header")?;
            if name.eq_ignore_ascii_case("content-length") {
                length = Some(value.trim().parse::<usize>()?);
            }
        }

        let length = length.ok_or("DNS response omitted content length")?;
        assert!(length <= 65_535);
        let mut response = vec![0; length];
        client.read_exact(&mut response).await?;
        assert_eq!(response.get(..2), Some(&[0x12, 0x34][..]));
        Ok(response)
    })
    .await?
}

async fn assert_closed(client: &mut Client) -> TestResult {
    let mut byte = [0; 1];
    let read = timeout(IO_TIMEOUT, client.read(&mut byte)).await?;
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "closed DNS child still produced response data"
    );
    Ok(())
}

async fn record_large_descriptions(client: &mut Client) -> TestResult {
    let name = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");
    assert_eq!(name.len(), 253);
    for _ in 0..253 {
        exchange(client, &name, 65).await?;
    }
    Ok(())
}

#[tokio::test]
async fn ninth_live_doh_connection_fails_capture_without_detaching_children() -> TestResult {
    let mut server = Server::start(ServerMode::Capture).await?;
    let mut peers = Vec::new();
    for _ in 0..8 {
        let mut peer = server.client().await?;
        exchange(&mut peer, HOSTNAME, 1).await?;
        peers.push(peer);
    }
    assert_eq!(server.descriptions().len(), 8);

    let ninth = server.client().await;
    assert!(ninth.is_err(), "ninth live DNS child was admitted");
    let failure = server
        .finish(IO_TIMEOUT)
        .await
        .err()
        .ok_or("ninth live DNS child did not fail the capture")?;
    assert!(failure.to_string().contains("connection limit"));
    for peer in &mut peers {
        assert_closed(peer).await?;
    }
    Ok(())
}

#[tokio::test]
async fn doh_query_count_accepts_256_then_fails_without_retaining_the_next() -> TestResult {
    let mut server = Server::start(ServerMode::Connection).await?;
    let mut client = server.client().await?;
    for _ in 0..256 {
        exchange(&mut client, HOSTNAME, 1).await?;
    }
    assert_eq!(server.descriptions().len(), 256);

    let overflow = exchange(&mut client, HOSTNAME, 1).await;
    assert!(
        overflow.is_err(),
        "257th query produced a successful response"
    );
    let failure = server
        .finish(IO_TIMEOUT)
        .await
        .err()
        .ok_or("query count overflow did not fail the handler")?;
    assert!(failure.to_string().contains("query count"));
    assert_eq!(server.descriptions().len(), 256);
    Ok(())
}

#[tokio::test]
async fn doh_query_bytes_accept_64_kib_then_reject_three_excess_bytes() -> TestResult {
    let mut server = Server::start(ServerMode::Connection).await?;
    let mut client = server.client().await?;
    record_large_descriptions(&mut client).await?;
    exchange(&mut client, "abc.def", 1).await?;
    let descriptions = server.descriptions();
    assert_eq!(descriptions.len(), 254);
    assert_eq!(descriptions.iter().map(String::len).sum::<usize>(), 65_536);

    let overflow = exchange(&mut client, "x", 1).await;
    assert!(
        overflow.is_err(),
        "query metadata exceeded 64 KiB successfully"
    );
    let failure = server
        .finish(IO_TIMEOUT)
        .await
        .err()
        .ok_or("query metadata overflow did not fail the handler")?;
    assert!(failure.to_string().contains("query metadata"));
    assert_eq!(server.descriptions(), descriptions);
    Ok(())
}

#[tokio::test]
async fn doh_query_metadata_accepts_65536_bytes_and_rejects_65537() -> TestResult {
    let mut accepted = Server::start(ServerMode::Connection).await?;
    let mut client = accepted.client().await?;
    record_large_descriptions(&mut client).await?;
    exchange(&mut client, "ab.c", 1).await?;
    let before = accepted.descriptions();
    assert_eq!(before.len(), 254);
    assert_eq!(before.iter().map(String::len).sum::<usize>(), 65_533);

    exchange(&mut client, "x", 1).await?;
    let inclusive = accepted.descriptions();
    assert_eq!(inclusive.len(), 255);
    assert_eq!(inclusive.iter().map(String::len).sum::<usize>(), 65_536);
    client.shutdown().await?;
    drop(client);
    accepted.finish(IO_TIMEOUT).await?;

    let mut rejected = Server::start(ServerMode::Connection).await?;
    let mut client = rejected.client().await?;
    record_large_descriptions(&mut client).await?;
    exchange(&mut client, "abc.d", 1).await?;
    let before = rejected.descriptions();
    assert_eq!(before.len(), 254);
    assert!(before.len() + 1 < 256);
    assert_eq!(before.iter().map(String::len).sum::<usize>(), 65_534);
    assert_eq!(65_534 + "A x".len(), 65_537);

    let overflow = exchange(&mut client, "x", 1).await;
    assert!(overflow.is_err(), "65,537 metadata bytes were accepted");
    let failure = rejected
        .finish(IO_TIMEOUT)
        .await
        .err()
        .ok_or("one-byte metadata overflow did not fail the handler")?;
    assert!(failure.to_string().contains("query metadata"));
    assert_eq!(rejected.descriptions(), before);
    Ok(())
}

#[tokio::test]
async fn stalled_doh_tls_handshake_has_a_server_deadline() -> TestResult {
    let mut server = Server::start(ServerMode::Connection).await?;
    let tcp = TcpStream::connect(server.address).await?;

    let failure = server
        .finish(DEADLINE_TEST_TIMEOUT)
        .await
        .err()
        .ok_or("stalled TLS handshake completed without a deadline failure")?;
    assert!(
        failure.to_string().contains("TLS handshake") && failure.to_string().contains("timed out"),
        "TLS deadline did not surface its operation: {failure}"
    );
    drop(tcp);
    Ok(())
}

#[tokio::test]
async fn incomplete_doh_request_head_has_a_whole_exchange_deadline() -> TestResult {
    let mut server = Server::start(ServerMode::Connection).await?;
    let mut client = server.client().await?;
    client.write_all(b"POST /dns-query HTTP/1.1\r\n").await?;
    client.flush().await?;

    let failure = server
        .finish(DEADLINE_TEST_TIMEOUT)
        .await
        .err()
        .ok_or("incomplete request head completed without a deadline failure")?;
    assert!(
        failure.to_string().contains("request") && failure.to_string().contains("timed out"),
        "request-head deadline did not surface its operation: {failure}"
    );
    assert!(server.descriptions().is_empty());
    Ok(())
}

#[tokio::test]
async fn incomplete_doh_request_body_has_a_whole_exchange_deadline() -> TestResult {
    let mut server = Server::start(ServerMode::Connection).await?;
    let mut client = server.client().await?;
    client
        .write_all(b"POST /dns-query HTTP/1.1\r\ncontent-length: 32\r\n\r\nx")
        .await?;
    client.flush().await?;

    let failure = server
        .finish(DEADLINE_TEST_TIMEOUT)
        .await
        .err()
        .ok_or("incomplete request body completed without a deadline failure")?;
    assert!(
        failure.to_string().contains("request") && failure.to_string().contains("timed out"),
        "request-body deadline did not surface its operation: {failure}"
    );
    assert!(server.descriptions().is_empty());
    Ok(())
}

#[tokio::test]
async fn aborting_doh_listener_closes_every_acknowledged_child() -> TestResult {
    let mut server = Server::start(ServerMode::Capture).await?;
    let mut peers = Vec::new();
    for _ in 0..3 {
        let mut peer = server.client().await?;
        exchange(&mut peer, HOSTNAME, 1).await?;
        peers.push(peer);
    }
    assert_eq!(server.descriptions().len(), 3);

    let task = server.task.as_mut().ok_or("DNS listener already joined")?;
    task.abort();
    let joined = timeout(IO_TIMEOUT, task).await?;
    server.task.take();
    assert!(joined.is_err_and(|error| error.is_cancelled()));
    for peer in &mut peers {
        assert_closed(peer).await?;
    }
    Ok(())
}

#[tokio::test]
async fn ordinary_doh_eof_completes_without_a_capture_failure() -> TestResult {
    let mut server = Server::start(ServerMode::Connection).await?;
    let mut client = server.client().await?;
    let response = exchange(&mut client, HOSTNAME, 1).await?;
    assert_eq!(response.get(6..8), Some(&[0, 1][..]));
    assert_eq!(server.descriptions(), [format!("A {HOSTNAME}")]);

    client.shutdown().await?;
    drop(client);
    server.finish(IO_TIMEOUT).await
}

#[tokio::test]
async fn completed_doh_connection_releases_a_live_work_slot() -> TestResult {
    let server = Server::start(ServerMode::Capture).await?;
    let mut peers = Vec::new();
    for _ in 0..8 {
        let mut peer = server.client().await?;
        exchange(&mut peer, HOSTNAME, 1).await?;
        peers.push(peer);
    }

    let mut completed = peers.remove(0);
    completed.shutdown().await?;
    assert_closed(&mut completed).await?;
    let mut replacement = server.client().await?;
    exchange(&mut replacement, HOSTNAME, 1).await?;
    assert_eq!(server.descriptions().len(), 9);
    Ok(())
}

#[tokio::test]
async fn malformed_doh_child_request_fails_the_capture_owner() -> TestResult {
    let mut server = Server::start(ServerMode::Capture).await?;
    let mut client = server.client().await?;
    exchange(&mut client, HOSTNAME, 1).await?;

    client
        .write_all(b"POST /dns-query HTTP/1.1\r\ncontent-length: 1\r\n\r\nx")
        .await?;
    client.flush().await?;
    let failure = server
        .finish(IO_TIMEOUT)
        .await
        .err()
        .ok_or("malformed DNS query did not fail the capture")?;
    assert!(failure.to_string().contains("malformed DNS query"));
    assert_eq!(server.descriptions().len(), 1);
    Ok(())
}

#[tokio::test]
async fn doh_fixture_rejects_a_leaf_signed_by_an_untrusted_ca() -> TestResult {
    let server = Server::start(ServerMode::Connection).await?;
    let (_, unrelated_root) = test_identity()?;

    let failure = server
        .client_with_root(&unrelated_root)
        .await
        .err()
        .ok_or("untrusted DNS fixture certificate was accepted")?;
    let tls = failure
        .downcast_ref::<btls::ssl::Error>()
        .ok_or("untrusted certificate failed outside the TLS verification boundary")?;
    assert_eq!(tls.code(), ErrorCode::SSL);
    assert!(tls.ssl_error().is_some_and(|stack| {
        stack
            .errors()
            .iter()
            .any(|error| error.reason() == Some("CERTIFICATE_VERIFY_FAILED"))
    }));
    Ok(())
}

#[tokio::test]
async fn graceful_doh_shutdown_closes_every_acknowledged_child() -> TestResult {
    let mut server = Server::start(ServerMode::Capture).await?;
    let mut peers = Vec::new();
    for _ in 0..3 {
        let mut peer = server.client().await?;
        exchange(&mut peer, HOSTNAME, 1).await?;
        peers.push(peer);
    }

    server.stop().await?;
    for peer in &mut peers {
        assert_closed(peer).await?;
    }
    assert_eq!(server.descriptions(), vec![format!("A {HOSTNAME}"); 3]);
    Ok(())
}

#[tokio::test]
async fn speculative_tcp_eof_does_not_fail_the_dns_capture() -> TestResult {
    let mut server = Server::start(ServerMode::Capture).await?;
    let mut speculative = TcpStream::connect(server.address).await?;
    speculative.shutdown().await?;
    drop(speculative);

    let mut peer = server.client().await?;
    exchange(&mut peer, HOSTNAME, 1).await?;
    server.stop().await?;
    assert_closed(&mut peer).await?;
    assert_eq!(server.descriptions(), [format!("A {HOSTNAME}")]);
    Ok(())
}

#[tokio::test]
async fn corrupted_tls_input_fails_the_dns_capture() -> TestResult {
    let mut server = Server::start(ServerMode::Capture).await?;
    let mut peer = TcpStream::connect(server.address).await?;
    peer.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
    peer.flush().await?;

    let failure = server
        .finish(IO_TIMEOUT)
        .await
        .err()
        .ok_or("corrupt TLS was accepted")?;
    let tls = failure
        .downcast_ref::<btls::ssl::Error>()
        .ok_or("corrupt input did not reach TLS")?;
    assert_eq!(tls.code(), ErrorCode::SSL);
    assert!(tls.ssl_error().is_some());
    assert!(server.descriptions().is_empty());
    Ok(())
}

struct DropSignal(Option<oneshot::Sender<()>>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            // A missing receiver means the test has already failed.
            let _ = sender.send(());
        }
    }
}

async fn pending_origin() -> CaptureResult<(JoinSet<()>, oneshot::Receiver<()>)> {
    let (started, running) = oneshot::channel();
    let (dropped, stopped) = oneshot::channel();
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let _drop_signal = DropSignal(Some(dropped));
        if started.send(()).is_ok() {
            std::future::pending::<()>().await;
        }
    });
    timeout(IO_TIMEOUT, running).await??;
    Ok((tasks, stopped))
}

#[tokio::test]
async fn origin_failure_joins_origin_and_dns_children_before_returning() -> TestResult {
    let mut server = Server::start(ServerMode::Capture).await?;
    let mut peer = server.client().await?;
    exchange(&mut peer, HOSTNAME, 1).await?;
    let (tasks, stopped) = pending_origin().await?;
    let capture = server.take_capture()?;

    let failure = timeout(
        IO_TIMEOUT,
        finish_capture(Err("controlled origin failure".into()), tasks, capture),
    )
    .await?
    .err()
    .ok_or("origin failure was discarded")?;
    assert_eq!(failure.to_string(), "controlled origin failure");
    timeout(IO_TIMEOUT, stopped).await??;
    assert_closed(&mut peer).await?;
    assert_eq!(server.descriptions(), [format!("A {HOSTNAME}")]);
    Ok(())
}

#[tokio::test]
async fn dns_failure_during_origin_grace_joins_all_owned_work() -> TestResult {
    let mut server = Server::start(ServerMode::Capture).await?;
    let mut peer = server.client().await?;
    exchange(&mut peer, HOSTNAME, 1).await?;
    let (tasks, stopped) = pending_origin().await?;
    let capture = server.take_capture()?;
    peer.write_all(b"POST /dns-query HTTP/1.1\r\ncontent-length: 1\r\n\r\nx")
        .await?;
    peer.flush().await?;

    let failure = timeout(IO_TIMEOUT, finish_capture(Ok(()), tasks, capture))
        .await?
        .err()
        .ok_or("DNS failure during origin grace was discarded")?;
    assert!(failure.to_string().contains("malformed DNS query"));
    timeout(IO_TIMEOUT, stopped).await??;
    assert_closed(&mut peer).await?;
    assert_eq!(server.descriptions(), [format!("A {HOSTNAME}")]);
    Ok(())
}

#[tokio::test]
async fn consumed_dns_failure_can_be_followed_by_owner_shutdown() -> TestResult {
    let mut server = Server::start(ServerMode::Capture).await?;
    let mut peer = server.client().await?;
    exchange(&mut peer, HOSTNAME, 1).await?;
    let mut capture = server.take_capture()?;
    peer.write_all(b"POST /dns-query HTTP/1.1\r\ncontent-length: 1\r\n\r\nx")
        .await?;
    peer.flush().await?;

    let failure = timeout(IO_TIMEOUT, capture.wait())
        .await?
        .err()
        .ok_or("DNS failure was discarded")?;
    assert!(failure.to_string().contains("malformed DNS query"));
    timeout(IO_TIMEOUT, capture.stop()).await??;
    assert_closed(&mut peer).await?;
    Ok(())
}

#[tokio::test]
async fn shutdown_keeps_a_completed_dns_child_failure() -> TestResult {
    let mut server = Server::start(ServerMode::Capture).await?;
    let mut peer = server.client().await?;
    exchange(&mut peer, HOSTNAME, 1).await?;
    let capture = server.take_capture()?;
    peer.write_all(b"POST /dns-query HTTP/1.1\r\ncontent-length: 1\r\n\r\nx")
        .await?;
    peer.flush().await?;
    assert_closed(&mut peer).await?;

    let failure = timeout(IO_TIMEOUT, capture.stop())
        .await?
        .err()
        .ok_or("shutdown discarded a DNS child failure")?;
    assert!(failure.to_string().contains("malformed DNS query"));
    assert_eq!(server.descriptions(), [format!("A {HOSTNAME}")]);
    Ok(())
}

#[tokio::test]
async fn dripping_request_bytes_do_not_extend_the_exchange_deadline() -> TestResult {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let mut server = Server::start(ServerMode::Connection).await?;
    let mut peer = server.client().await?;
    peer.write_all(b"POST /dns-query HTTP/1.1\r\ncontent-length: 32\r\n\r\nx")
        .await?;
    peer.flush().await?;
    let written = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&written);
    let mut writer = JoinSet::new();
    writer.spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if peer.write_all(b"x").await.is_err() || peer.flush().await.is_err() {
                return;
            }
            written.fetch_add(1, Ordering::SeqCst);
        }
    });

    let result = server.finish(DEADLINE_TEST_TIMEOUT).await;
    writer.abort_all();
    while let Some(result) = writer.join_next().await {
        if let Err(error) = result {
            if !error.is_cancelled() {
                return Err(error.into());
            }
        }
    }
    assert!(
        observed.load(Ordering::SeqCst) >= 2,
        "no sustained request drip reached the peer"
    );
    let failure = result
        .err()
        .ok_or("dripping request completed without a deadline failure")?;
    assert!(failure.to_string().contains("request") && failure.to_string().contains("timed out"));
    assert!(server.descriptions().is_empty());
    Ok(())
}
