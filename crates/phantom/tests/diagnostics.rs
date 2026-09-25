//! Loopback tests of the `diagnostics` feature: the TLS key log and qlog files.
#![cfg(feature = "diagnostics")]

#[allow(dead_code)]
#[path = "support/h3.rs"]
mod h3_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;
#[allow(dead_code)]
#[path = "support/tunnel_proxy.rs"]
mod tunnel_proxy;

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use btls::ssl::SslAcceptor;
use http::{Response, StatusCode};
use phantom::{
    Client, ClientBuilder, HttpProtocol, HttpProxy, RequestErrorKind, Route,
    profile::{CipherSuite, ClientProfile, NamedGroup, TlsSettings, TlsVersion},
};
use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinHandle, time::timeout};

use h3_support::{accept_request, client_settings, server_endpoint};
// `tunnel_proxy` reaches the TLS helpers as `super::tls`.
use tls_support as tls;
use tls_support::{H1_ALPN, TestIdentity, TestResult, accept_tls, read_head, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// NSS key-log labels of a TLS 1.3 handshake without early data.
const TLS13_LABELS: [&str; 5] = [
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
];

#[tokio::test]
async fn key_log_holds_the_secrets_of_a_loopback_tls_connection() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let url = format!("https://{}/", listener.local_addr()?);
    let origin = tokio::spawn(serve_one_tls_request(listener, identity.acceptor(H1_ALPN)?));

    let client = Client::builder(ClientProfile::new(tls13_http1_settings()))
        .add_root_certificate_der(identity.root_der.clone())
        .key_log(NonZeroUsize::new(16).ok_or("16 is nonzero")?)
        .build()?;
    let response = timeout(TEST_TIMEOUT, client.get(HttpProtocol::Http1, &url)?.send()).await??;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    timeout(TEST_TIMEOUT, origin).await???;

    let handshakes = drain_key_log(&client)?;
    assert_eq!(handshakes.len(), 1, "{handshakes:?}");
    Ok(())
}

#[tokio::test]
async fn key_log_holds_the_secrets_of_a_loopback_quic_handshake() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, server) = serve_one_http3_request(&identity)?;
    let client = http3_client(&identity)
        .key_log(NonZeroUsize::new(16).ok_or("16 is nonzero")?)
        .build()?;
    let response = timeout(
        TEST_TIMEOUT,
        client
            .get(HttpProtocol::Http3, &format!("https://{address}/"))?
            .send(),
    )
    .await??;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let handshakes = drain_key_log(&client);
    drop(response);
    drop(client);
    server.abort();
    let handshakes = handshakes?;
    assert_eq!(handshakes.len(), 1, "{handshakes:?}");
    Ok(())
}

#[tokio::test]
async fn key_log_holds_the_proxy_and_origin_handshakes_of_an_https_proxy_route() -> TestResult<()> {
    let origin_identity = TestIdentity::generate()?;
    let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let origin_address = origin_listener.local_addr()?;
    let origin = tokio::spawn(serve_one_tls_request(
        origin_listener,
        origin_identity.acceptor(H1_ALPN)?,
    ));

    let proxy_identity = TestIdentity::generate()?;
    let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy_address = proxy_listener.local_addr()?;
    let proxy = tokio::spawn(tunnel_proxy::https1_connect(
        proxy_listener,
        proxy_identity.acceptor(H1_ALPN)?,
        origin_address,
    ));

    let client = Client::builder(ClientProfile::new(tls13_http1_settings()))
        .add_root_certificate_der(origin_identity.root_der.clone())
        .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
        .route(Route::http_connect(HttpProxy::new(&format!(
            "https://{proxy_address}"
        ))?))
        .key_log(NonZeroUsize::new(16).ok_or("16 is nonzero")?)
        .build()?;
    let response = timeout(
        TEST_TIMEOUT,
        client
            .get(HttpProtocol::Http1, &format!("https://{origin_address}/"))?
            .send(),
    )
    .await??;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    timeout(TEST_TIMEOUT, proxy).await???;
    timeout(TEST_TIMEOUT, origin).await???;

    // The proxy session and the origin session inside its tunnel each log a
    // full set of secrets under their own client random.
    let handshakes = drain_key_log(&client)?;
    assert_eq!(handshakes.len(), 2, "{handshakes:?}");
    Ok(())
}

#[tokio::test]
async fn key_log_is_absent_unless_enabled() -> TestResult<()> {
    let client = Client::builder(ClientProfile::new(tls_settings())).build()?;
    assert!(client.key_log().is_none());
    Ok(())
}

#[tokio::test]
async fn qlog_dir_receives_a_file_for_a_loopback_http3_connection() -> TestResult<()> {
    let dir = scratch_dir("qlog")?;
    let result = send_http3_with_qlog(&dir).await;
    let files = std::fs::read_dir(&dir)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>();
    remove_scratch_dir(&dir).await;
    let contents = result?;
    let files = files?;

    assert_eq!(files.len(), 1, "{files:?}");
    let name = files[0]
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("qlog file name is not UTF-8")?;
    assert!(
        name.starts_with("phantom-") && name.ends_with(".sqlog"),
        "{name}"
    );
    // A JSON-SEQ file opens with the record separator of its header record.
    assert!(!contents.is_empty(), "the qlog file is empty");
    assert_eq!(contents[0], 0x1e, "JSON-SEQ record separator");
    for needle in [&b"\"qlog_version\""[..], b"packet_sent", b"packet_received"] {
        assert!(
            contains(&contents, needle),
            "{} missing from the qlog file",
            String::from_utf8_lossy(needle)
        );
    }
    Ok(())
}

#[tokio::test]
async fn qlog_dir_that_does_not_exist_fails_the_connection_before_its_handshake() -> TestResult<()>
{
    let identity = TestIdentity::generate()?;
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "phantom-qlog-missing-{}-{nanos}",
        std::process::id()
    ));
    assert!(!dir.exists());
    // A bound socket that no handshake packet may reach.
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    peer.set_nonblocking(true)?;
    let address = peer.local_addr()?;

    let client = http3_client(&identity).qlog_dir(&dir).build()?;
    let result = timeout(
        TEST_TIMEOUT,
        client
            .get(HttpProtocol::Http3, &format!("https://{address}/"))?
            .send(),
    )
    .await?;
    let Err(error) = result else {
        return Err("the request succeeded without a qlog file".into());
    };
    assert_eq!(error.kind(), RequestErrorKind::Http3, "{error:?}");
    let mut datagram = [0_u8; 1];
    assert_eq!(
        peer.recv(&mut datagram).map_err(|error| error.kind()),
        Err(std::io::ErrorKind::WouldBlock),
        "a QUIC packet reached the peer"
    );
    assert!(!dir.exists());
    Ok(())
}

/// Sends one HTTP/3 request with qlog enabled and returns the qlog file once
/// the closed connection has flushed it.
async fn send_http3_with_qlog(dir: &Path) -> TestResult<Vec<u8>> {
    let identity = TestIdentity::generate()?;
    let (address, server) = serve_one_http3_request(&identity)?;
    let client = http3_client(&identity).qlog_dir(dir).build()?;
    let response = timeout(
        TEST_TIMEOUT,
        client
            .get(HttpProtocol::Http3, &format!("https://{address}/"))?
            .send(),
    )
    .await;
    drop(client);
    server.abort();
    assert_eq!(response??.status(), StatusCode::NO_CONTENT);

    let file = std::fs::read_dir(dir)?
        .next()
        .ok_or("no qlog file was created")??
        .path();
    // Writes are buffered until the closed connection drops its writer. Every
    // record ends with a newline, so a flushed file does too.
    timeout(TEST_TIMEOUT, async {
        loop {
            let contents = std::fs::read(&file)?;
            if contents.ends_with(b"\n") && contains(&contents, b"packet_received") {
                return TestResult::Ok(contents);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Returns a builder whose profile carries the loopback HTTP/3 settings.
fn http3_client(identity: &TestIdentity) -> ClientBuilder {
    Client::builder(ClientProfile::new(tls_settings()).with_http3(client_settings()))
        .add_root_certificate_der(identity.root_der.clone())
}

/// HTTP/1.1 TLS settings limited to TLS 1.3, whose secrets the key log keeps.
fn tls13_http1_settings() -> TlsSettings {
    let mut tls = tls_settings();
    tls.min_version = TlsVersion::Tls13;
    tls.max_version = TlsVersion::Tls13;
    tls.cipher_suites = vec![CipherSuite::Aes128GcmSha256];
    tls.key_shares = vec![NamedGroup::X25519];
    tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    tls
}

/// Accepts one HTTP/1.1 request over TLS and answers it with 204.
async fn serve_one_tls_request(listener: TcpListener, acceptor: SslAcceptor) -> TestResult<()> {
    let mut stream = accept_tls(listener, acceptor).await?;
    read_head(&mut stream).await?;
    stream
        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
        .await?;
    Ok(())
}

/// Starts an HTTP/3 endpoint that answers one request with 204.
fn serve_one_http3_request(
    identity: &TestIdentity,
) -> TestResult<(SocketAddr, JoinHandle<TestResult<()>>)> {
    let (address, endpoint) = server_endpoint(identity)?;
    let server = tokio::spawn(async move {
        let (_request, mut stream, _connection) = accept_request(&endpoint).await?;
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
            )
            .await?;
        stream.finish().await?;
        endpoint.wait_idle().await;
        TestResult::Ok(())
    });
    Ok((address, server))
}

/// Drains the client's key log and groups its labels by client random.
///
/// Fails unless nothing was dropped, each line is
/// `<label> <client random> <secret>`, and each handshake logged exactly the
/// TLS 1.3 labels without early data.
fn drain_key_log(client: &Client) -> TestResult<BTreeMap<String, Vec<String>>> {
    let key_log = client.key_log().ok_or("key logging was not enabled")?;
    let mut output = Vec::new();
    let written = key_log.write_pending(&mut output)?;
    if key_log.dropped_line_count() != 0 {
        return Err(format!("{} key log lines dropped", key_log.dropped_line_count()).into());
    }
    let output = String::from_utf8(output)?;
    if output.lines().count() != written {
        return Err("write_pending miscounted its lines".into());
    }

    let mut handshakes = BTreeMap::<String, Vec<String>>::new();
    for line in output.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        let [label, client_random, _secret] = fields[..] else {
            return Err(format!("key log line has {} fields", fields.len()).into());
        };
        handshakes
            .entry(client_random.to_owned())
            .or_default()
            .push(label.to_owned());
    }
    let mut expected: Vec<String> = TLS13_LABELS.iter().map(|&label| label.into()).collect();
    expected.sort();
    for labels in handshakes.values_mut() {
        labels.sort();
        if *labels != expected {
            return Err(format!("handshake logged {labels:?}").into());
        }
    }
    Ok(handshakes)
}

/// Removes a scratch directory, retrying while Windows reports the qlog file
/// of a closing connection as still open. A directory that outlives the
/// retries stays behind in the temporary directory.
async fn remove_scratch_dir(dir: &Path) {
    for _ in 0..50 {
        if std::fs::remove_dir_all(dir).is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Creates an empty directory under the system temporary directory.
fn scratch_dir(prefix: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = std::env::temp_dir().join(format!("phantom-{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir(&dir)?;
    Ok(dir)
}
