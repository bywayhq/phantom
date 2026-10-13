use std::{
    io,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

use bytes::Bytes;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinError,
    time::timeout,
};

use super::{
    Behavior, CLEANUP_TIMEOUT, ConnectionLog, PREFACE, TestResult, TestServer, WireDecoder,
    serve_h2,
};
use crate::support::{tls::read_head, tunnel_proxy::connection_peer::FixtureFailures};

#[tokio::test]
async fn interrupted_shutdown_retains_the_caller_and_accepted_connection() -> TestResult<()> {
    let mut server = TestServer::start_plaintext(Behavior::ACCEPT).await?;
    let address = server.address;
    let mut client = accepted_idle_client(&server).await?;
    let primary = io::Error::new(io::ErrorKind::PermissionDenied, CallerFailure);
    {
        let finish = server.finish::<()>(Err(primary.into()));
        tokio::pin!(finish);
        assert!(futures_util::poll!(&mut finish).is_pending());
    }
    assert!(
        server.task.is_some(),
        "interrupted shutdown removed the original worker"
    );
    let error = server
        .finish(Ok(()))
        .await
        .err()
        .ok_or("caller failure was discarded")?;
    let cause = error
        .downcast_ref::<io::Error>()
        .ok_or("original caller I/O cause was lost")?;
    assert_eq!(cause.kind(), io::ErrorKind::PermissionDenied);
    assert!(
        cause
            .get_ref()
            .is_some_and(|error| error.is::<CallerFailure>())
    );
    assert!(server.task.is_none(), "completed worker was not collected");
    assert_peer_closed(&mut client).await?;
    let rebound = TcpListener::bind(address).await?;
    assert_eq!(rebound.local_addr()?, address);
    Ok(())
}

#[tokio::test]
async fn caller_failure_and_original_accepted_frame_failure_are_both_observed() -> TestResult<()> {
    let mut server = TestServer::start_plaintext(Behavior::ACCEPT).await?;
    let address = server.address;
    let mut client = TcpStream::connect(address).await?;
    client.write_all(b"GET /echo HTTP/1.1\r\nHost: localhost\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").await?;
    let response = timeout(CLEANUP_TIMEOUT, read_head(&mut client)).await??;
    assert!(response.starts_with(b"HTTP/1.1 101 "));
    client.write_all(&[0x81, 0]).await?;
    // The original accepted operation has failed and released its socket,
    // before explicit shutdown or any independent repair.
    assert_peer_closed(&mut client).await?;
    let primary = io::Error::new(io::ErrorKind::PermissionDenied, CallerFailure);
    let error = server
        .finish::<()>(Err(primary.into()))
        .await
        .err()
        .ok_or("caller and serving failures were discarded")?;
    let failures = error
        .downcast_ref::<FixtureFailures>()
        .ok_or("independent serving failure was lost")?;
    let caller = failures
        .primary
        .downcast_ref::<io::Error>()
        .ok_or("original caller cause was lost")?;
    let serving = failures
        .cleanup
        .downcast_ref::<io::Error>()
        .ok_or("original serving cause was lost")?;
    assert_eq!(caller.kind(), io::ErrorKind::PermissionDenied);
    assert!(
        caller
            .get_ref()
            .is_some_and(|error| error.is::<CallerFailure>())
    );
    assert_eq!(serving.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        serving.to_string(),
        "profile client frame was unmasked or exceeded its bound"
    );
    let rebound = TcpListener::bind(address).await?;
    assert_eq!(rebound.local_addr()?, address);
    Ok(())
}

#[tokio::test]
async fn a_pending_external_abort_is_not_classified_as_requested_shutdown() -> TestResult<()> {
    let mut server = TestServer::start_plaintext(Behavior::ACCEPT).await?;
    let mut client = accepted_idle_client(&server).await?;
    let abort = server
        .task
        .as_ref()
        .ok_or("listener was not owned")?
        .abort_handle();
    let id = abort.id();
    abort.abort();
    // Do not wait for the pending abort to complete before asking for normal
    // fixture shutdown: is_finished cannot establish cancellation provenance.
    let error = server
        .finish(Ok(()))
        .await
        .err()
        .ok_or("external cancellation was suppressed")?;
    let join = error
        .downcast_ref::<JoinError>()
        .ok_or("original cancelled JoinError was lost")?;
    assert!(join.is_cancelled());
    assert_eq!(join.id(), id);
    assert_peer_closed(&mut client).await?;
    Ok(())
}

#[tokio::test]
async fn normal_shutdown_collects_a_healthy_request_and_idle_accepted_peer() -> TestResult<()> {
    let mut server = TestServer::start_plaintext(Behavior::ACCEPT).await?;
    let address = server.address;
    let mut client = TcpStream::connect(address).await?;
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    let response = timeout(CLEANUP_TIMEOUT, read_head(&mut client)).await??;
    assert_eq!(response, b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n");
    let mut body = [0_u8; 2];
    timeout(CLEANUP_TIMEOUT, client.read_exact(&mut body)).await??;
    assert_eq!(&body, b"ok");
    assert_peer_closed(&mut client).await?;
    let mut idle = accepted_idle_client(&server).await?;
    server.finish(Ok(())).await?;
    assert_peer_closed(&mut idle).await?;
    assert!(server.task.is_none());
    assert_eq!(server.connections()?.len(), 2);
    let rebound = TcpListener::bind(address).await?;
    assert_eq!(rebound.local_addr()?, address);
    Ok(())
}

#[test]
fn a_complete_truncated_priority_returns_its_typed_parser_failure() -> TestResult<()> {
    for length in 0_u8..5 {
        let mut wire = PREFACE.to_vec();
        wire.extend_from_slice(&[0, 0, length, 1, 0x24, 0, 0, 0, 1]);
        wire.extend_from_slice(&vec![0; usize::from(length)]);
        let error = WireDecoder::default()
            .headers_for(&wire, 1)
            .err()
            .ok_or("short complete HEADERS priority was accepted")?;
        let cause = error
            .downcast_ref::<io::Error>()
            .ok_or("priority parser failure was not typed")?;
        assert_eq!(cause.kind(), io::ErrorKind::InvalidData);
    }
    let mut healthy = PREFACE.to_vec();
    healthy.extend_from_slice(&[0, 0, 6, 1, 0x24, 0, 0, 0, 1, 0, 0, 0, 0, 15, 0x82]);
    let (priority, fields) = WireDecoder::default().headers_for(&healthy, 1)?;
    assert_eq!(priority, Some((false, 0, 16)));
    assert_eq!(fields[0].0, ":method");
    Ok(())
}

#[test]
fn oversized_hpack_continuations_return_typed_failures_without_losing_valid_fields()
-> TestResult<()> {
    // Literal base-128 encodings exercise both addition overflow and the
    // largest representable value; no test encoder repeats the parser.
    let (overflow, maximum, overflowing_part): (&[u8], &[u8], &[u8]) = match usize::BITS {
        64 => (
            &[
                0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
            ],
            &[
                0x3f, 0xe0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
            ],
            &[
                0x3f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02,
            ],
        ),
        32 => (
            &[0x3f, 0xff, 0xff, 0xff, 0xff, 0x0f],
            &[0x3f, 0xe0, 0xff, 0xff, 0xff, 0x0f],
            &[0x3f, 0x80, 0x80, 0x80, 0x80, 0x10],
        ),
        _ => return Err("HPACK control requires a 32-bit or 64-bit usize".into()),
    };
    let mut excessive_shift = vec![0x3f];
    excessive_shift.extend(vec![0x80; usize::try_from(usize::BITS / 7 + 2)?]);
    excessive_shift.push(0);
    for block in [overflow, overflowing_part, excessive_shift.as_slice()] {
        let error = WireDecoder::default()
            .decode_block(block)
            .err()
            .ok_or("oversized HPACK continuation was accepted")?;
        let cause = error
            .downcast_ref::<io::Error>()
            .ok_or("original HPACK range failure was not typed")?;
        assert_eq!(cause.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            cause.to_string(),
            "HPACK integer exceeds the fixture's range"
        );
    }
    let mut cursor = 0;
    assert_eq!(super::read_integer(maximum, &mut cursor, 5)?, usize::MAX);
    assert_eq!(cursor, maximum.len());
    let mut healthy = maximum.to_vec();
    healthy.push(0x82);
    let fields = WireDecoder::default().decode_block(&healthy)?;
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].0, ":method");
    assert_eq!(fields[0].1.kind, "indexed");
    assert_eq!(fields[0].1.index, 2);
    Ok(())
}

#[test]
fn hpack_name_and_value_ranges_reject_overflow_and_truncation() -> TestResult<()> {
    let maximum_length: &[u8] = match usize::BITS {
        64 => &[
            0x7f, 0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
        ],
        32 => &[0x7f, 0x80, 0xff, 0xff, 0xff, 0x0f],
        _ => return Err("HPACK control requires a 32-bit or 64-bit usize".into()),
    };
    for first in [0x00, 0x01] {
        // A zero name index reads a literal name; :authority's index skips
        // its literal value. Both paths receive the same impossible extent.
        let mut overflowing = vec![first];
        overflowing.extend_from_slice(maximum_length);
        for (block, message) in [
            (overflowing, "HPACK string range overflows"),
            (vec![first, 0x05, b'a'], "HPACK string is truncated"),
        ] {
            let error = WireDecoder::default()
                .decode_block(&block)
                .err()
                .ok_or("invalid HPACK string range was accepted")?;
            let cause = error
                .downcast_ref::<io::Error>()
                .ok_or("original HPACK string failure was not typed")?;
            assert_eq!(cause.kind(), io::ErrorKind::InvalidData);
            assert_eq!(cause.to_string(), message);
        }
    }
    let fields = WireDecoder::default().decode_block(&[
        0x00, 0x07, b':', b'm', b'e', b't', b'h', b'o', b'd', 0x03, b'G', b'E', b'T',
    ])?;
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].0, ":method");
    assert_eq!(fields[0].1.kind, "without-indexing");
    assert_eq!(fields[0].1.name_huffman, Some(false));
    assert_eq!(fields[0].1.value_huffman, Some(false));
    Ok(())
}

#[tokio::test]
async fn one_http2_data_chunk_echoes_both_coalesced_websocket_frames() -> TestResult<()> {
    timeout(CLEANUP_TIMEOUT, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let log = Arc::new(Mutex::new(vec![ConnectionLog::default()]));
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let serving = async {
            let (stream, _) = listener.accept().await?;
            serve_h2(stream, 0, &log, Behavior::ACCEPT, stopped).await
        };
        let client = async {
            let result: TestResult<()> = async {
                let stream = TcpStream::connect(address).await?;
                let (requests, connection) = ::http2::client::handshake(stream).await?;
                let script = async {
                    let mut requests = requests.ready().await?;
                    // Reading the first response also observes the peer's
                    // earlier SETTINGS enabling extended CONNECT.
                    let (response, _) = requests.send_request(
                        http::Request::builder()
                            .uri("http://localhost/ready")
                            .body(())?,
                        true,
                    )?;
                    let mut body = response.await?.into_body();
                    let chunk = body
                        .data()
                        .await
                        .ok_or("ordinary response ended before its body")??;
                    assert_eq!(chunk, Bytes::from_static(b"ok"));
                    body.flow_control().release_capacity(chunk.len())?;
                    let mut request = http::Request::builder()
                        .method(http::Method::CONNECT)
                        .uri("http://localhost/echo")
                        .body(())?;
                    request
                        .extensions_mut()
                        .insert(::http2::ext::Protocol::from_static("websocket"));
                    let (response, mut send) = requests.send_request(request, false)?;
                    let mut body = response.await?.into_body();
                    // Both complete masked frames are in one original DATA
                    // chunk. Clearing the whole input after the first frame
                    // loses the second echo and fails this actual script.
                    send.send_data(
                        Bytes::from_static(&[
                            0x81,
                            0x81,
                            1,
                            2,
                            3,
                            4,
                            b'a' ^ 1,
                            0x81,
                            0x81,
                            1,
                            2,
                            3,
                            4,
                            b'b' ^ 1,
                        ]),
                        false,
                    )?;
                    let mut echoes = Vec::new();
                    while echoes.len() < 6 {
                        let chunk = body.data().await.ok_or("second frame was not echoed")??;
                        if echoes.len() + chunk.len() > 6 {
                            return Err("echo exceeded the two-frame contract".into());
                        }
                        body.flow_control().release_capacity(chunk.len())?;
                        echoes.extend_from_slice(&chunk);
                    }
                    assert_eq!(echoes, [0x81, 1, b'a', 0x81, 1, b'b']);
                    send.send_reset(::http2::Reason::CANCEL);
                    TestResult::Ok(())
                };
                tokio::select! {
                    biased;
                    result = script => result,
                    result = connection => match result {
                        Err(error) => Err(error.into()),
                        Ok(()) => Err("HTTP/2 driver ended before both echoes".into()),
                    }
                }
            }
            .await;
            stop.send_replace(true);
            result
        };
        let (serving, client) = tokio::join!(serving, client);
        crate::support::tunnel_proxy::finish_with_cleanup(client, serving)?;
        let log = log.lock().map_err(|_| "coalesced-frame log was poisoned")?;
        assert_eq!(log[0].client_frames.len(), 2);
        Ok(())
    })
    .await?
}

async fn accepted_idle_client(server: &TestServer) -> TestResult<TcpStream> {
    let previous = server.connections()?.len();
    let mut client = TcpStream::connect(server.address).await?;
    client.write_all(b"GET ").await?;
    timeout(CLEANUP_TIMEOUT, async {
        loop {
            if server.connections()?.len() > previous {
                return TestResult::Ok(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    Ok(client)
}

async fn assert_peer_closed(client: &mut TcpStream) -> TestResult<()> {
    let outcome = timeout(CLEANUP_TIMEOUT, client.read(&mut [0_u8; 1])).await?;
    assert!(
        matches!(outcome, Ok(0))
            || matches!(outcome,
        Err(ref error) if crate::support::tls::is_peer_gone(error))
    );
    Ok(())
}

#[derive(Debug)]
struct CallerFailure;

impl std::fmt::Display for CallerFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("original profile caller failure")
    }
}

impl std::error::Error for CallerFailure {}
