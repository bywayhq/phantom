//! Frame order and fallback of the HTTP/2 CONNECT replay, against a
//! frame-level proxy.

use std::{path::PathBuf, time::Duration};

use phantom_profile::{
    Http2RejectedConnect, Http2Setting, Http2Settings,
    chromium::{v154_http2, v154_proxy_connect},
    firefox::v156_http2,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

use super::{
    http2_connect::bounded,
    http2_raw_proxy::{
        END_STREAM, Frame, HEADERS, RawConnection, WINDOW_UPDATE, body, goaway, response,
    },
    https_connect::tls_settings,
};
use crate::{
    proxy::{
        HttpBasicCredentials, HttpConnectError, HttpConnectHeader, HttpsProxyConnector,
        HttpsProxyProtocol,
    },
    tls::test_support::{TEST_SERVER_NAME, TestIdentity, TestResult, TestServerAlpn},
};

const ORIGIN: &str = "origin.example:443";
/// SETTINGS_MAX_CONCURRENT_STREAMS.
const MAX_CONCURRENT_STREAMS: u16 = 0x3;
/// RST_STREAM error code CANCEL.
const CANCEL: [u8; 4] = [0, 0, 0, 8];
const PROXY_WAIT: Duration = Duration::from_secs(5);

/// Both profile choices end or keep the challenged stream as their browser
/// does, and on a proxy that allows one concurrent stream the replay still
/// goes on the challenged connection as stream 3, after the challenged
/// stream has ended.
#[tokio::test]
async fn replay_waits_for_a_proxy_that_allows_one_stream() -> TestResult<()> {
    for rejected in [
        Http2RejectedConnect::EndStream,
        Http2RejectedConnect::LeaveOpen,
    ] {
        bounded(async {
            let (connector, port, listener, acceptor) = proxy_setup(rejected, v154_http2())?;
            let proxy = tokio::spawn(async move {
                let mut connection =
                    RawConnection::accept(&listener, &acceptor, &[(MAX_CONCURRENT_STREAMS, 1)])
                        .await?;
                challenge_then_accept_replay(&mut connection).await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(connection)
            });
            echo_through(&connector, port).await?;
            let connection = proxy.await??;
            // With one stream allowed, the challenged stream must end first,
            // whatever the profile says.
            assert_eq!(
                shapes(&connection.frames_before(1, 3)),
                [("DATA", END_STREAM, 0)],
                "{rejected:?}"
            );
            Ok(())
        })
        .await?;
    }
    Ok(())
}

/// The empty END_STREAM DATA frame on the challenged stream precedes the
/// replay's HEADERS on a multi-thread runtime too, where the connection
/// driver runs on another worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn challenged_stream_ends_before_the_replay_on_a_multi_thread_runtime() -> TestResult<()> {
    for _ in 0..20 {
        bounded(async {
            let (connector, port, listener, acceptor) =
                proxy_setup(Http2RejectedConnect::EndStream, v154_http2())?;
            let proxy = tokio::spawn(async move {
                let mut connection = RawConnection::accept(&listener, &acceptor, &[]).await?;
                challenge_then_accept_replay(&mut connection).await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(connection)
            });
            echo_through(&connector, port).await?;
            let connection = proxy.await??;
            assert_eq!(
                shapes(&connection.frames_before(1, 3)),
                [("DATA", END_STREAM, 0)]
            );
            Ok(())
        })
        .await?;
    }
    Ok(())
}

/// Each profile sends, between the `407` and the replay, the frames its
/// browser sends on the challenged stream in the
/// `https-proxy-auth-secure-hostname` capture: Chrome 154, Edge 153, Brave
/// 154, and Opera 135 an empty END_STREAM DATA frame, Firefox 156 nothing.
/// Brave and Opera take the Chromium CONNECT and HTTP/2 recipes. Firefox's stream stays
/// quiet while the tunnel runs.
#[tokio::test]
async fn challenged_stream_frames_match_the_captures() -> TestResult<()> {
    for (browser, rejected, http2) in [
        (
            "chrome/154.0.8037.58",
            Http2RejectedConnect::EndStream,
            v154_http2(),
        ),
        (
            "edge/153.0.4234.48",
            Http2RejectedConnect::EndStream,
            v154_http2(),
        ),
        (
            "brave/154.1.96.59",
            v154_proxy_connect().http2_rejected,
            v154_http2(),
        ),
        (
            "opera/135.0.5973.92",
            v154_proxy_connect().http2_rejected,
            v154_http2(),
        ),
        (
            "firefox/156.0",
            Http2RejectedConnect::LeaveOpen,
            v156_http2(),
        ),
    ] {
        let captured = captured_challenged_stream_frames(browser)?;
        bounded(async {
            let (connector, port, listener, acceptor) = proxy_setup(rejected, http2)?;
            let proxy = tokio::spawn(async move {
                let mut connection = RawConnection::accept(&listener, &acceptor, &[]).await?;
                challenge_then_accept_replay(&mut connection).await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(connection)
            });
            echo_through(&connector, port).await?;
            let connection = proxy.await??;
            let sent: Vec<_> = connection
                .frames_before(1, 3)
                .into_iter()
                .filter(|frame| frame.kind != WINDOW_UPDATE)
                .map(Frame::shape)
                .collect();
            assert_eq!(sent, captured, "{browser}");
            if rejected == Http2RejectedConnect::LeaveOpen {
                assert!(
                    connection.frames.iter().all(|frame| frame.stream != 1
                        || frame.kind == HEADERS
                        || frame.kind == WINDOW_UPDATE),
                    "{browser}: the client wrote on the challenged stream while the tunnel ran"
                );
            }
            Ok(())
        })
        .await?;
    }
    Ok(())
}

/// A `GOAWAY` that arrives with the `407`, or after the replay's HEADERS,
/// and a proxy that closes the connection after the replay's HEADERS, each
/// move the replay to a new connection once.
#[tokio::test]
async fn unprocessed_replay_moves_to_a_new_connection() -> TestResult<()> {
    for case in [
        Unprocessed::GoAwayWithChallenge,
        Unprocessed::GoAwayAfterReplay,
        Unprocessed::CloseAfterReplay,
    ] {
        bounded(async {
            let (connector, port, listener, acceptor) =
                proxy_setup(Http2RejectedConnect::EndStream, v154_http2())?;
            let proxy = tokio::spawn(async move {
                let mut first = RawConnection::accept(&listener, &acceptor, &[]).await?;
                first.read_until(|frame| frame.kind == HEADERS).await?;
                match case {
                    Unprocessed::GoAwayWithChallenge => {
                        first.write(&[response(1, 407, true), goaway(1)]).await?;
                    }
                    Unprocessed::GoAwayAfterReplay | Unprocessed::CloseAfterReplay => {
                        first.write(&[response(1, 407, true)]).await?;
                        first
                            .read_until(|frame| frame.kind == HEADERS && frame.stream == 3)
                            .await?;
                        if matches!(case, Unprocessed::GoAwayAfterReplay) {
                            first.write(&[goaway(1)]).await?;
                        }
                    }
                }
                let first_task = tokio::spawn(async move {
                    if !matches!(case, Unprocessed::CloseAfterReplay) {
                        first.read_to_end(PROXY_WAIT).await?;
                    }
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                });
                let mut second = RawConnection::accept(&listener, &acceptor, &[]).await?;
                let replay = second.read_until(|frame| frame.kind == HEADERS).await?;
                second.write(&[response(replay.stream, 200, false)]).await?;
                second.echo(replay.stream).await?;
                first_task.await??;
                let third = timeout(Duration::from_millis(100), listener.accept()).await;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>((replay.stream, third.is_err()))
            });
            echo_through(&connector, port).await?;
            let (replay_stream, two_connections) = proxy.await??;
            assert_eq!(replay_stream, 1, "{case:?}");
            assert!(two_connections, "{case:?}");
            Ok(())
        })
        .await?;
    }
    Ok(())
}

/// A `407` whose body is still arriving: the client resets the stream with
/// CANCEL, returns the body's connection window, and replays on the same
/// connection.
#[tokio::test]
async fn challenge_with_an_unfinished_body_replays_on_the_same_connection() -> TestResult<()> {
    const BODY: usize = 60_000;
    bounded(async {
        // A 65,535-byte connection window, so the body uses most of it.
        let mut http2 = v154_http2();
        http2.initial_connection_window_size = 65_535;
        for setting in &mut http2.initial_settings {
            if let Http2Setting::InitialWindowSize(size) = setting {
                *size = 65_535;
            }
        }
        let (connector, port, listener, acceptor) =
            proxy_setup(Http2RejectedConnect::EndStream, http2)?;
        let proxy = tokio::spawn(async move {
            let mut connection = RawConnection::accept(&listener, &acceptor, &[]).await?;
            connection.read_until(|frame| frame.kind == HEADERS).await?;
            let mut challenge = vec![response(1, 407, false)];
            challenge.extend(body(1, BODY));
            connection.write(&challenge).await?;
            let replay = connection
                .read_until(|frame| frame.kind == HEADERS && frame.stream == 3)
                .await?;
            // The connection-level WINDOW_UPDATE frames, before or after the
            // replay, return the discarded body's window.
            while returned_window(&connection.frames) < BODY {
                connection
                    .read_frame()
                    .await?
                    .ok_or("client closed before returning the window")?;
            }
            connection
                .write(&[response(replay.stream, 200, false)])
                .await?;
            connection.echo(replay.stream).await?;
            let third = timeout(Duration::from_millis(100), listener.accept()).await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((connection, third.is_err()))
        });
        echo_through(&connector, port).await?;
        let (connection, one_connection) = proxy.await??;
        assert!(one_connection);
        let challenged: Vec<&Frame> = connection
            .frames
            .iter()
            .filter(|frame| frame.stream == 1 && frame.kind != HEADERS)
            .collect();
        let shapes: Vec<_> = challenged.iter().map(|frame| frame.shape()).collect();
        assert_eq!(shapes, [("RST_STREAM", 0, 4)], "{challenged:?}");
        assert_eq!(challenged[0].payload, CANCEL);
        Ok(())
    })
    .await
}

/// A CONNECT rejected with `502` ends its stream with an empty END_STREAM
/// DATA frame, resets nothing, and fails with the status.
#[tokio::test]
async fn rejected_connect_ends_its_stream() -> TestResult<()> {
    bounded(async {
        let (connector, port, listener, acceptor) =
            proxy_setup(Http2RejectedConnect::EndStream, v154_http2())?;
        let proxy = tokio::spawn(async move {
            let mut connection = RawConnection::accept(&listener, &acceptor, &[]).await?;
            connection.read_until(|frame| frame.kind == HEADERS).await?;
            connection.write(&[response(1, 502, true)]).await?;
            connection.read_to_end(PROXY_WAIT).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(connection)
        });
        let error = connector
            .connect_tunnel(
                "127.0.0.1",
                port,
                TEST_SERVER_NAME,
                ORIGIN,
                &[HttpConnectHeader::authority("Host")],
            )
            .await
            .err()
            .ok_or("a rejected CONNECT succeeded")?;
        assert!(matches!(error, HttpConnectError::Rejected { status: 502 }));
        let connection = proxy.await??;
        let stream: Vec<_> = connection
            .frames
            .iter()
            .filter(|frame| frame.stream == 1 && frame.kind != HEADERS)
            .map(Frame::shape)
            .filter(|(name, ..)| *name != "WINDOW_UPDATE")
            .collect();
        assert_eq!(stream, [("DATA", END_STREAM, 0)]);
        Ok(())
    })
    .await
}

#[derive(Clone, Copy, Debug)]
enum Unprocessed {
    GoAwayWithChallenge,
    GoAwayAfterReplay,
    CloseAfterReplay,
}

/// Challenges stream 1, then accepts the replay on stream 3 and echoes one
/// tunnel payload.
async fn challenge_then_accept_replay(connection: &mut RawConnection) -> TestResult<()> {
    connection.read_until(|frame| frame.kind == HEADERS).await?;
    connection.write(&[response(1, 407, true)]).await?;
    connection
        .read_until(|frame| frame.kind == HEADERS && frame.stream == 3)
        .await?;
    connection.write(&[response(3, 200, false)]).await?;
    connection.echo(3).await
}

type Setup = (
    HttpsProxyConnector,
    u16,
    TcpListener,
    btls::ssl::SslAcceptor,
);

/// Binds a loopback proxy listener and builds an HTTP/2 connector for it.
fn proxy_setup(rejected: Http2RejectedConnect, http2: Http2Settings) -> TestResult<Setup> {
    let identity = TestIdentity::generate()?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let connector =
        HttpsProxyConnector::new_with_additional_roots(&tls_settings(), [identity.root_der()])?
            .with_http2_settings(&http2)
            .with_protocol(HttpsProxyProtocol::Http2)
            .with_http2_rejected_connect(rejected);
    let acceptor = identity.acceptor(TestServerAlpn::H2)?;
    Ok((connector, port, TcpListener::from_std(listener)?, acceptor))
}

/// Opens one authenticated tunnel and checks that it carries bytes both
/// ways.
async fn echo_through(connector: &HttpsProxyConnector, port: u16) -> TestResult<()> {
    let mut tunnel = connector
        .connect_tunnel_with_basic_auth(
            "127.0.0.1",
            port,
            TEST_SERVER_NAME,
            ORIGIN,
            &[
                HttpConnectHeader::authority("Host"),
                HttpConnectHeader::proxy_authorization("Proxy-Authorization"),
            ],
            &HttpBasicCredentials::new("alice", "secret")?,
        )
        .await?;
    tunnel.write_all(b"ping").await?;
    let mut echoed = [0_u8; 4];
    tunnel.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"ping");
    Ok(())
}

/// Sums the increments of the client's connection-level WINDOW_UPDATE
/// frames.
fn returned_window(frames: &[Frame]) -> usize {
    frames
        .iter()
        .filter(|frame| frame.kind == WINDOW_UPDATE && frame.stream == 0)
        .map(|frame| {
            let increment = u32::from_be_bytes([
                frame.payload[0],
                frame.payload[1],
                frame.payload[2],
                frame.payload[3],
            ]) & 0x7fff_ffff;
            usize::try_from(increment).unwrap_or(usize::MAX)
        })
        .sum()
}

fn shapes(frames: &[&Frame]) -> Vec<(&'static str, u8, usize)> {
    frames
        .iter()
        .filter(|frame| frame.kind != WINDOW_UPDATE)
        .map(|frame| frame.shape())
        .collect()
}

/// Returns, for run 0 of a browser's `https-proxy-auth-secure-hostname`
/// capture, the client frames on the challenged CONNECT stream between the
/// `407` and the replay's HEADERS, as (type, flags, length).
fn captured_challenged_stream_frames(browser: &str) -> TestResult<Vec<(&'static str, u8, usize)>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/proxy")
        .join(browser)
        .join("windows-11-26200/https-proxy-auth-secure-hostname.txt");
    let text = std::fs::read_to_string(path)?;
    let value = |key: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
    };
    let challenged = (0..)
        .map_while(|index| value(&format!("run_0_request_{index}")))
        .find(|request| request.contains("kind:https-connect") && request.contains("status:407"))
        .ok_or("capture has no challenged CONNECT")?;
    let field = |name: &str| -> TestResult<String> {
        challenged
            .split(',')
            .find_map(|part| part.strip_prefix(name)?.strip_prefix(':'))
            .map(ToOwned::to_owned)
            .ok_or_else(|| format!("request has no {name}").into())
    };
    let connection = field("connection")?;
    let stream = format!("stream:{},", field("stream")?);
    let frames: Vec<&str> = (0..)
        .map_while(|index| value(&format!("run_0_connection_{connection}_frame_{index}")))
        .collect();
    let challenge = frames
        .iter()
        .position(|frame| frame.starts_with("server:HEADERS") && frame.contains(&stream))
        .ok_or("capture has no 407 HEADERS")?;
    let mut captured = Vec::new();
    for frame in &frames[challenge + 1..] {
        if frame.starts_with("client:HEADERS") {
            break;
        }
        if !frame.starts_with("client:") || !frame.contains(&stream) {
            continue;
        }
        let kind = frame
            .strip_prefix("client:")
            .and_then(|rest| rest.split(',').next())
            .ok_or("malformed frame")?;
        let name = match kind {
            "DATA" => "DATA",
            "RST_STREAM" => "RST_STREAM",
            "WINDOW_UPDATE" => continue,
            _ => "OTHER",
        };
        let flags = frame
            .split(',')
            .find_map(|part| part.strip_prefix("flags:0x"))
            .map(|hex| u8::from_str_radix(hex, 16))
            .transpose()?
            .unwrap_or(0);
        let length = frame
            .split(',')
            .find_map(|part| part.strip_prefix("data_length:"))
            .map(str::parse::<usize>)
            .transpose()?
            .unwrap_or(0);
        captured.push((name, flags, length));
    }
    Ok(captured)
}
