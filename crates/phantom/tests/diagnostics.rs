//! Loopback tests of the `diagnostics` feature: the TLS key log and qlog files.
#![cfg(feature = "diagnostics")]

#[allow(dead_code)]
#[path = "support/h3.rs"]
mod h3_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{
    net::Ipv4Addr,
    num::NonZeroUsize,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use http::{Response, StatusCode};
use phantom::{
    Client, HttpProtocol,
    profile::{CipherSuite, ClientProfile, NamedGroup, TlsVersion},
};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

use h3_support::{accept_request, client_settings, server_endpoint};
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
    let acceptor = identity.acceptor(H1_ALPN)?;
    let server = tokio::spawn(async move {
        let mut stream = accept_tls(listener, acceptor).await?;
        read_head(&mut stream).await?;
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await?;
        TestResult::Ok(())
    });

    let mut tls = tls_settings();
    tls.min_version = TlsVersion::Tls13;
    tls.max_version = TlsVersion::Tls13;
    tls.cipher_suites = vec![CipherSuite::Aes128GcmSha256];
    tls.key_shares = vec![NamedGroup::X25519];
    tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    let client = Client::builder(ClientProfile::new(tls))
        .add_root_certificate_der(identity.root_der.clone())
        .key_log(NonZeroUsize::new(16).ok_or("16 is nonzero")?)
        .build()?;
    let response = timeout(TEST_TIMEOUT, client.get(HttpProtocol::Http1, &url)?.send()).await??;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    timeout(TEST_TIMEOUT, server).await???;

    let key_log = client.key_log().ok_or("key logging was not enabled")?;
    let mut output = Vec::new();
    assert_eq!(key_log.write_pending(&mut output)?, TLS13_LABELS.len());
    assert_eq!(key_log.dropped_line_count(), 0);
    let output = String::from_utf8(output)?;
    let labels: Vec<&str> = output
        .lines()
        .filter_map(|line| line.split(' ').next())
        .collect();
    for label in TLS13_LABELS {
        assert!(labels.contains(&label), "{label} missing from {labels:?}");
    }
    // Each line is `<label> <client random> <secret>` in hex.
    assert!(output.lines().all(|line| line.split(' ').count() == 3));
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
    result?;
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
    Ok(())
}

async fn send_http3_with_qlog(dir: &std::path::Path) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
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

    let client = Client::builder(ClientProfile::new(tls_settings()).with_http3(client_settings()))
        .add_root_certificate_der(identity.root_der.clone())
        .qlog_dir(dir)
        .build()?;
    let response = timeout(
        TEST_TIMEOUT,
        client
            .get(HttpProtocol::Http3, &format!("https://{address}/"))?
            .send(),
    )
    .await??;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Quinn writes each event as it happens, so the file already holds the
    // JSON-SEQ header and the handshake's packets.
    let file = std::fs::read_dir(dir)?
        .next()
        .ok_or("no qlog file was created")??
        .path();
    let contents = std::fs::read(&file)?;
    assert_eq!(contents.first(), Some(&0x1e), "JSON-SEQ record separator");
    for needle in [&b"\"qlog_version\""[..], b"packet_sent", b"packet_received"] {
        assert!(
            contents
                .windows(needle.len())
                .any(|window| window == needle),
            "{} missing from the qlog file",
            String::from_utf8_lossy(needle)
        );
    }
    drop(response);
    drop(client);
    server.abort();
    Ok(())
}

/// Removes a scratch directory, retrying while Windows reports the qlog file
/// of a closing connection as still open. A directory that outlives the
/// retries stays behind in the temporary directory.
async fn remove_scratch_dir(dir: &std::path::Path) {
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
