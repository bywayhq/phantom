use std::{
    io,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
    time::{Duration, timeout},
};

use super::{
    StreamLog, StreamMode, TestResult, decode_capsule, hold_until_closed, parse_target,
    relay_capsules, serve_http1,
};

const DEADLINE: Duration = Duration::from_secs(5);

#[test]
fn target_paths_keep_numeric_loopback_addresses() -> TestResult<()> {
    for (host, expected) in [
        ("127.0.0.1", "127.0.0.1:443"),
        ("127.1.2.3", "127.1.2.3:443"),
        ("%3A%3A1", "[::1]:443"),
    ] {
        let path = format!("/.well-known/masque/udp/{host}/443/");
        assert_eq!(parse_target(&path), Some(expected.parse()?));
    }
    Ok(())
}

#[tokio::test]
async fn received_targets_outside_loopback_fail_before_a_relay_response() -> TestResult<()> {
    for host in ["192.0.2.1", "0.0.0.0", "2001%3Adb8%3A%3A1", "%3A%3A"] {
        let (mut peer, stream) = tokio::io::duplex(4096);
        let path = format!("/.well-known/masque/udp/{host}/443/");
        peer.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n\r\n")
                .as_bytes(),
        )
        .await?;
        let log = Arc::new(Mutex::new(StreamLog::default()));
        let error = timeout(
            DEADLINE,
            serve_http1(stream, StreamMode::Relay, log.clone()),
        )
        .await?
        .err()
        .ok_or("a received nonloopback target started a relay")?;
        assert_eq!(error.to_string(), "CONNECT-UDP path has no loopback target");
        assert_eq!(super::lock(&log).requests[0].path, path);
        // No Upgrade or successful tunnel response precedes rejection.
        assert_eq!(peer.read(&mut [0; 1]).await?, 0);
    }
    Ok(())
}

#[test]
fn an_advertised_oversized_capsule_fails_before_its_payload_arrives() -> TestResult<()> {
    let error = decode_capsule(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
        .err()
        .ok_or("oversized capsule was treated as incomplete")?;
    assert_eq!(
        error
            .downcast_ref::<io::Error>()
            .ok_or("original input error missing")?
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        decode_capsule(b"\x2a\x03xyz")?,
        Some((42, b"xyz".to_vec(), 5))
    );
    assert_eq!(decode_capsule(b"\x2a\x03xy")?, None);
    Ok(())
}

#[tokio::test]
async fn coalesced_capsules_larger_than_one_buffer_keep_all_complete_values() -> TestResult<()> {
    let target = phantom_testkit::udp::bind_tokio("127.0.0.1:0".parse()?)?;
    let (inbound_tx, inbound) = mpsc::channel(1);
    let (outbound, mut received) = mpsc::channel(1);
    let mut bytes = Vec::new();
    for _ in 0..3 {
        // Literal QUIC four-byte length encoding for 40,000 bytes.
        bytes.extend_from_slice(&[0x2a, 0x80, 0, 0x9c, 0x40]);
        bytes.extend(std::iter::repeat_n(b'x', 40_000));
    }
    inbound_tx.send(Bytes::from(bytes)).await?;
    drop(inbound_tx);
    let log = Arc::new(Mutex::new(StreamLog::default()));

    timeout(
        DEADLINE,
        relay_capsules(inbound, outbound, target.local_addr()?, log.clone()),
    )
    .await??;

    assert_eq!(super::lock(&log).client_capsules, [(42, None, 40_000); 3]);
    assert_eq!(
        received.recv().await.ok_or("relay preamble missing")?,
        Bytes::from_static(b"\x2a\x03xyz\x00\x10\x02unknown-context")
    );
    Ok(())
}

#[tokio::test]
async fn a_partial_capsule_after_a_forwarded_datagram_keeps_the_original_eof() -> TestResult<()> {
    let target = phantom_testkit::udp::bind_tokio("127.0.0.1:0".parse()?)?;
    let (inbound_tx, inbound) = mpsc::channel(1);
    let (outbound, _received) = mpsc::channel(1);
    // One complete Context ID zero datagram, then a missing payload byte.
    inbound_tx
        .send(Bytes::from_static(b"\x00\x03\x00!!\x00\x02\x00"))
        .await?;
    drop(inbound_tx);
    let log = Arc::new(Mutex::new(StreamLog::default()));

    let error = timeout(
        DEADLINE,
        relay_capsules(inbound, outbound, target.local_addr()?, log.clone()),
    )
    .await?
    .err()
    .ok_or("truncated capsule was silently discarded")?;

    assert_eq!(
        error
            .downcast_ref::<io::Error>()
            .ok_or("original EOF missing")?
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
    assert_eq!(super::lock(&log).client_capsules, [(0, Some(0), 3)]);
    let mut received = [0; 16];
    let (count, sender) = timeout(DEADLINE, target.recv_from(&mut received)).await??;
    assert_eq!(&received[..count], b"!!");
    let rebound = phantom_testkit::udp::bind_tokio(sender)?;
    assert_eq!(rebound.local_addr()?, sender);
    Ok(())
}

#[tokio::test]
async fn a_rejected_request_body_has_a_bounded_drain() -> TestResult<()> {
    let (mut peer, stream) = tokio::io::duplex(128 * 1024);
    peer.write_all(&vec![b'x'; 64 * 1024 + 1]).await?;
    peer.shutdown().await?;

    let error = timeout(DEADLINE, hold_until_closed(stream))
        .await?
        .err()
        .ok_or("oversized rejected body was drained without a limit")?;

    assert_eq!(
        error
            .downcast_ref::<io::Error>()
            .ok_or("original drain error missing")?
            .kind(),
        io::ErrorKind::InvalidData
    );
    let (mut peer, stream) = tokio::io::duplex(32);
    peer.write_all(b"short").await?;
    peer.shutdown().await?;
    timeout(DEADLINE, hold_until_closed(stream)).await??;
    Ok(())
}
