//! The PING a Chromium profile sends right after a request frame on a
//! connection that has read nothing for longer than its idle time, against a
//! loopback peer and the retained Chrome 154 capture, and the close that
//! follows when the PING goes unanswered.
//!
//! The recipe's 10-second idle time is shortened to 1 second, and its
//! 10-second PING timeout to 1 to 3 seconds, so the tests run quickly;
//! everything else is the Chrome 154 recipe.

use std::{future::Future, net::Ipv4Addr, time::Duration};

use bytes::Bytes;
use http::Method;
use phantom_profile::{Http2Settings, chromium, firefox};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinSet,
    time::timeout,
};

use super::{TestResult, target};
use crate::http2::{Http2Connection, Http2Error};

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const SETTINGS: u8 = 0x4;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;
const ACK: u8 = 0x1;
const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const IDLE: Duration = Duration::from_secs(1);
const PAST_IDLE: Duration = Duration::from_millis(1_500);
const SHORT_WAIT: Duration = Duration::from_millis(300);
const PROBE: &[u8; 8] = b"probe!!!";
/// Chrome 154 reusing one connection after idle periods, recorded by
/// `scripts/capture/http2_preface_ping.py`.
const CHROME_CAPTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/http2/chrome/154.0.8037.58/windows-11-26200/preface-ping.txt"
));
/// Chromium's `kSpdyDefaultConnectionAtRiskOfLossSeconds`, in milliseconds.
const CHROME_IDLE_MS: f64 = 10_000.0;

/// Bounds a test whose timeline spans several idle periods.
async fn idle_peer_test<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    match timeout(Duration::from_secs(15), future).await {
        Ok(result) => result,
        Err(_) => Err("preface PING test exceeded its absolute deadline".into()),
    }
}

/// The Chrome 154 recipe waits 10 seconds without a read; Firefox 156 sends
/// no such PING.
#[test]
fn recipes_state_the_preface_ping_idle_time() {
    assert_eq!(
        chromium::v154_http2().preface_ping_after,
        Some(Duration::from_secs(10))
    );
    assert_eq!(firefox::v156_http2().preface_ping_after, None);
}

/// The Chrome 154 recipe closes a connection whose PING goes unanswered for
/// 10 seconds without a read; Firefox 156 sends no such PING to time.
#[test]
fn recipes_state_the_ping_timeout() {
    assert_eq!(
        chromium::v154_http2().ping_timeout,
        Some(Duration::from_secs(10))
    );
    assert_eq!(firefox::v156_http2().ping_timeout, None);
}

/// A PING the peer never answers closes the connection once nothing has been
/// read for the timeout: `GOAWAY` with last stream ID 0, `PROTOCOL_ERROR`,
/// and `Failed ping.`, then the end of the byte stream. The open request
/// fails with [`Http2Error::PingTimeout`], and a later one with
/// [`Http2Error::ReusedConnectionClosed`].
#[tokio::test]
async fn chromium_recipe_closes_a_connection_whose_ping_goes_unanswered() -> TestResult<()> {
    idle_peer_test(async {
        let mut settings = chromium::v154_http2();
        settings.preface_ping_after = Some(IDLE);
        settings.ping_timeout = Some(Duration::from_secs(2));
        let (mut peer, connection) = start(&settings).await?;
        tokio::time::sleep(PAST_IDLE).await;
        let open = tokio::spawn({
            let connection = connection.clone();
            let target = target()?;
            async move {
                connection
                    .send_request(Method::GET, "example.test", target, Vec::new(), None)
                    .await
                    .map(drop)
            }
        });
        let ping = read_ping_after_headers(&mut peer).await?;
        assert_eq!(ping, 1_u64.to_be_bytes());
        let ping_read = tokio::time::Instant::now();

        let (kind, flags, stream, payload) = read_frame(&mut peer).await?;
        let waited = ping_read.elapsed();
        assert_eq!((kind, flags, stream), (GOAWAY, 0, 0));
        assert_eq!(payload.get(..8), Some(&[0, 0, 0, 0, 0, 0, 0, 1][..]));
        assert_eq!(payload.get(8..), Some(&b"Failed ping."[..]));
        assert!(
            waited >= Duration::from_secs(1) && waited < Duration::from_secs(4),
            "GOAWAY after {waited:?}"
        );
        assert_closed(&mut peer).await?;

        assert!(matches!(open.await?, Err(Http2Error::PingTimeout)));
        assert!(!connection.is_reusable());
        // Nothing of a later request is sent, so it may go elsewhere.
        let later = connection
            .send_request(Method::GET, "example.test", target()?, Vec::new(), None)
            .await;
        assert!(matches!(later, Err(Http2Error::ReusedConnectionClosed)));
        Ok(())
    })
    .await
}

/// A frame read moves the close to a timeout after it; only the ACK stops
/// the timeout. With a 4-second timeout and a `WINDOW_UPDATE` 2 seconds after
/// the PING, the connection closes 6 seconds after the PING, as Chrome's
/// `CheckPingStatus` would: not 4, which ignores the read, nor 8.
#[tokio::test]
async fn a_frame_read_restarts_the_ping_timeout() -> TestResult<()> {
    idle_peer_test(async {
        let mut settings = chromium::v154_http2();
        settings.preface_ping_after = Some(IDLE);
        settings.ping_timeout = Some(Duration::from_secs(4));
        let (mut peer, connection) = start(&settings).await?;
        let mut requests = JoinSet::new();
        tokio::time::sleep(PAST_IDLE).await;
        request(&connection, &mut requests)?;
        read_ping_after_headers(&mut peer).await?;
        let ping_read = tokio::time::Instant::now();

        tokio::time::sleep(Duration::from_secs(2)).await;
        write_frame(&mut peer, WINDOW_UPDATE, 0, 0, &1_u32.to_be_bytes()).await?;
        let (kind, _, _, _) = read_frame(&mut peer).await?;
        let waited = ping_read.elapsed();
        assert_eq!(kind, GOAWAY);
        assert!(
            waited >= Duration::from_secs(5) && waited < Duration::from_secs(7),
            "GOAWAY after {waited:?}"
        );
        requests.abort_all();
        Ok(())
    })
    .await
}

/// An acknowledged PING leaves the connection open past the timeout.
#[tokio::test]
async fn an_acknowledged_ping_keeps_the_connection() -> TestResult<()> {
    idle_peer_test(async {
        let mut settings = chromium::v154_http2();
        settings.preface_ping_after = Some(IDLE);
        settings.ping_timeout = Some(Duration::from_secs(1));
        let (mut peer, connection) = start(&settings).await?;
        let mut requests = JoinSet::new();
        tokio::time::sleep(PAST_IDLE).await;
        request(&connection, &mut requests)?;
        let ping = read_ping_after_headers(&mut peer).await?;
        write_frame(&mut peer, PING, ACK, 0, &ping).await?;

        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(connection.is_reusable());
        request(&connection, &mut requests)?;
        assert_eq!(
            read_request(&mut peer).await?,
            (3, Some(2_u64.to_be_bytes()))
        );
        requests.abort_all();
        Ok(())
    })
    .await
}

/// A request sent within the idle time carries no PING; one sent after it is
/// followed at once by PING 1; reading its ACK restarts the idle time; and
/// the next idle period brings PING 2.
#[tokio::test]
async fn chromium_recipe_pings_after_request_headers_on_a_read_idle_connection() -> TestResult<()> {
    idle_peer_test(async {
        let mut settings = chromium::v154_http2();
        settings.preface_ping_after = Some(IDLE);
        let (mut peer, connection) = start(&settings).await?;
        let mut requests = JoinSet::new();

        request(&connection, &mut requests)?;
        assert_eq!(read_request(&mut peer).await?, (1, None));

        tokio::time::sleep(PAST_IDLE).await;
        request(&connection, &mut requests)?;
        assert_eq!(
            read_request(&mut peer).await?,
            (3, Some(1_u64.to_be_bytes()))
        );
        write_frame(&mut peer, PING, ACK, 0, &1_u64.to_be_bytes()).await?;

        request(&connection, &mut requests)?;
        assert_eq!(read_request(&mut peer).await?, (5, None));

        tokio::time::sleep(PAST_IDLE).await;
        request(&connection, &mut requests)?;
        assert_eq!(
            read_request(&mut peer).await?,
            (7, Some(2_u64.to_be_bytes()))
        );
        requests.abort_all();
        Ok(())
    })
    .await
}

/// Without the setting, a request after the same idle period carries no PING.
#[tokio::test]
async fn settings_without_a_preface_ping_send_none_after_read_idle() -> TestResult<()> {
    idle_peer_test(async {
        let mut settings = chromium::v154_http2();
        settings.preface_ping_after = None;
        settings.ping_timeout = None;
        let (mut peer, connection) = start(&settings).await?;
        let mut requests = JoinSet::new();
        request(&connection, &mut requests)?;
        assert_eq!(read_request(&mut peer).await?, (1, None));
        tokio::time::sleep(PAST_IDLE).await;
        request(&connection, &mut requests)?;
        assert_eq!(read_request(&mut peer).await?, (3, None));
        requests.abort_all();
        Ok(())
    })
    .await
}

/// The retained capture: after `/a`, a request sent more than 10 seconds
/// after the last read (`/b`, then `POST /p`) is followed at once by a PING
/// whose payload counts 1, then 2; `/c`, sent 9 seconds after the ACK, and
/// `/done` are not. The POST's PING comes between its HEADERS and its DATA.
#[test]
fn chrome_capture_pings_right_after_the_request_frame() -> TestResult<()> {
    let frames = capture_frames()?;
    assert_eq!(
        request_sequence(&frames),
        [
            "HEADERS",
            "HEADERS",
            "PING 0000000000000001",
            "HEADERS",
            "HEADERS",
            "PING 0000000000000002",
            "DATA",
            "HEADERS",
        ]
    );
    let sent = |path: &str| {
        frames
            .iter()
            .find(|frame| frame.path.as_deref() == Some(path))
            .map(|frame| frame.milliseconds)
            .ok_or(format!("capture has no request for {path}"))
    };
    assert!(sent("/b")? - sent("/a")? > CHROME_IDLE_MS);
    assert!(sent("/c")? - sent("/b")? < CHROME_IDLE_MS);
    assert!(sent("/p")? - sent("/c")? > CHROME_IDLE_MS);
    Ok(())
}

/// Phantom's Chromium recipe, driven through the capture's timeline with the
/// idle time scaled to 1 second, writes the capture's request frames and
/// PINGs in the same order with the same payloads.
#[tokio::test]
async fn chromium_recipe_replays_the_chrome_capture_ping_sequence() -> TestResult<()> {
    idle_peer_test(async {
        let mut settings = chromium::v154_http2();
        settings.preface_ping_after = Some(IDLE);
        let (peer, connection) = start(&settings).await?;
        let (frames, mut sequence) = mpsc::unbounded_channel();
        let peer = tokio::spawn(answer_requests(peer, frames));

        get(&connection).await?;
        tokio::time::sleep(PAST_IDLE).await;
        get(&connection).await?;
        tokio::time::sleep(SHORT_WAIT).await;
        get(&connection).await?;
        tokio::time::sleep(PAST_IDLE).await;
        connection
            .send_request(
                Method::POST,
                "example.test",
                target()?,
                Vec::new(),
                Some(Bytes::from(vec![b'x'; 100])),
            )
            .await?;
        get(&connection).await?;
        peer.abort();

        let mut replayed = Vec::new();
        while let Ok(symbol) = sequence.try_recv() {
            replayed.push(symbol);
        }
        assert_eq!(replayed, request_sequence(&capture_frames()?));
        Ok(())
    })
    .await
}

/// One client frame of the retained capture.
struct CapturedFrame {
    milliseconds: f64,
    kind: String,
    path: Option<String>,
    payload: Option<String>,
}

fn capture_frames() -> TestResult<Vec<CapturedFrame>> {
    let mut frames = Vec::new();
    for line in CHROME_CAPTURE.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if !key.starts_with("frame_") || key == "frame_count" {
            continue;
        }
        let mut frame = CapturedFrame {
            milliseconds: 0.0,
            kind: String::new(),
            path: None,
            payload: None,
        };
        for item in value.split(',') {
            let (name, value) = item.split_once(':').ok_or("malformed frame item")?;
            match name {
                "ms" => frame.milliseconds = value.parse()?,
                "type" => value.clone_into(&mut frame.kind),
                "path" => frame.path = Some(value.to_owned()),
                "payload" => frame.payload = Some(value.to_owned()),
                _ => {}
            }
        }
        frames.push(frame);
    }
    Ok(frames)
}

/// The request frames and PINGs from `/a` on, without the SETTINGS and
/// WINDOW_UPDATE frames, which belong to no request.
fn request_sequence(frames: &[CapturedFrame]) -> Vec<String> {
    frames
        .iter()
        .skip_while(|frame| frame.path.as_deref() != Some("/a"))
        .filter_map(|frame| match frame.kind.as_str() {
            "HEADERS" | "DATA" => Some(frame.kind.clone()),
            "PING" => Some(format!("PING {}", frame.payload.as_deref().unwrap_or(""))),
            _ => None,
        })
        .collect()
}

/// Sends one GET and waits for its response.
async fn get(connection: &Http2Connection) -> TestResult<()> {
    connection
        .send_request(Method::GET, "example.test", target()?, Vec::new(), None)
        .await?;
    Ok(())
}

/// Records the client's request frames and PINGs in the capture's notation,
/// acknowledges each PING, and answers each request with an empty 200 once
/// its last frame arrives.
async fn answer_requests(
    mut peer: TcpStream,
    frames: mpsc::UnboundedSender<String>,
) -> TestResult<()> {
    loop {
        let (kind, flags, stream, payload) = read_frame(&mut peer).await?;
        match kind {
            HEADERS | DATA => {
                let name = if kind == HEADERS { "HEADERS" } else { "DATA" };
                frames.send(name.to_owned())?;
                if flags & END_STREAM != 0 {
                    // `:status: 200` is static table entry 8.
                    write_frame(
                        &mut peer,
                        HEADERS,
                        END_STREAM | END_HEADERS,
                        stream,
                        &[0x88],
                    )
                    .await?;
                }
            }
            PING if flags & ACK == 0 => {
                let hex: String = payload.iter().map(|byte| format!("{byte:02x}")).collect();
                frames.send(format!("PING {hex}"))?;
                write_frame(&mut peer, PING, ACK, 0, &payload).await?;
            }
            GOAWAY => return Err("client sent GOAWAY".into()),
            _ => {}
        }
    }
}

/// Connects a client over loopback and completes the peer's side of the
/// handshake, reading the client's preface and initial SETTINGS.
async fn start(settings: &Http2Settings) -> TestResult<(TcpStream, Http2Connection)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let client = TcpStream::connect(listener.local_addr()?).await?;
    let (mut peer, _) = listener.accept().await?;
    let connection = Http2Connection::connect(client, settings).await?;
    let mut preface = [0_u8; CLIENT_PREFACE.len()];
    peer.read_exact(&mut preface).await?;
    if preface.as_slice() != CLIENT_PREFACE {
        return Err("client sent an invalid HTTP/2 connection preface".into());
    }
    let (kind, flags, _, _) = read_frame(&mut peer).await?;
    if (kind, flags) != (SETTINGS, 0) {
        return Err("client did not start with SETTINGS".into());
    }
    write_frame(&mut peer, SETTINGS, 0, 0, &[]).await?;
    Ok((peer, connection))
}

/// Sends one GET whose response never arrives.
fn request(
    connection: &Http2Connection,
    requests: &mut JoinSet<Result<(), String>>,
) -> TestResult<()> {
    let connection = connection.clone();
    let target = target()?;
    requests.spawn(async move {
        connection
            .send_request(Method::GET, "example.test", target, Vec::new(), None)
            .await
            .map(drop)
            .map_err(|error| error.to_string())
    });
    Ok(())
}

/// Reads the next request HEADERS and returns its stream with the payload of
/// a PING the client wrote right after it, if any.
///
/// A probe PING bounds the wait: the client writes its own PING with the
/// HEADERS, so it arrives before the probe's ACK.
async fn read_request(peer: &mut TcpStream) -> TestResult<(u32, Option<[u8; 8]>)> {
    let stream = loop {
        let (kind, flags, stream, _) = read_frame(peer).await?;
        match kind {
            HEADERS => break stream,
            DATA => return Err("client sent DATA for a GET".into()),
            GOAWAY => return Err("client sent GOAWAY".into()),
            PING if flags & ACK == 0 => return Err("a PING came before the HEADERS".into()),
            _ => {}
        }
    };
    write_frame(peer, PING, 0, 0, PROBE).await?;
    let mut ping = None;
    let mut first = true;
    loop {
        let (kind, flags, _, payload) = read_frame(peer).await?;
        match kind {
            GOAWAY => return Err("client sent GOAWAY".into()),
            PING if flags & ACK != 0 && payload == PROBE => return Ok((stream, ping)),
            PING if flags & ACK == 0 => {
                if !first {
                    return Err("a frame came between the HEADERS and the PING".into());
                }
                ping = Some(
                    payload
                        .try_into()
                        .map_err(|_| "PING payload is not 8 bytes")?,
                );
            }
            _ => {}
        }
        first = false;
    }
}

/// Reads up to the next request HEADERS without writing anything, and
/// returns the payload of the PING the client wrote right after them.
async fn read_ping_after_headers(peer: &mut TcpStream) -> TestResult<[u8; 8]> {
    loop {
        let (kind, _, _, _) = read_frame(peer).await?;
        match kind {
            HEADERS => break,
            SETTINGS | WINDOW_UPDATE => {}
            _ => return Err(format!("unexpected frame type {kind} before HEADERS").into()),
        }
    }
    let (kind, flags, _, payload) = read_frame(peer).await?;
    if (kind, flags) != (PING, 0) {
        return Err(format!("frame type {kind} followed the HEADERS, not a PING").into());
    }
    Ok(payload
        .try_into()
        .map_err(|_| "PING payload is not 8 bytes")?)
}

/// Requires the client to end the byte stream after its GOAWAY. Windows can
/// report the close as a reset or an abort rather than an orderly end.
async fn assert_closed(peer: &mut TcpStream) -> TestResult<()> {
    let mut rest = Vec::new();
    match timeout(Duration::from_secs(2), peer.read_to_end(&mut rest)).await {
        Err(_) => Err("the client kept the connection open after GOAWAY".into()),
        Ok(Ok(_)) if rest.is_empty() => Ok(()),
        Ok(Ok(_)) => Err(format!("the client wrote {} bytes after GOAWAY", rest.len()).into()),
        Ok(Err(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            ) =>
        {
            Ok(())
        }
        Ok(Err(error)) => Err(error.into()),
    }
}

async fn read_frame(peer: &mut TcpStream) -> TestResult<(u8, u8, u32, Vec<u8>)> {
    let mut head = [0_u8; 9];
    peer.read_exact(&mut head).await?;
    let length = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
    let mut payload = vec![0_u8; length];
    peer.read_exact(&mut payload).await?;
    let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
    Ok((head[3], head[4], stream, payload))
}

async fn write_frame(
    peer: &mut TcpStream,
    kind: u8,
    flags: u8,
    stream: u32,
    payload: &[u8],
) -> TestResult<()> {
    let length = u32::try_from(payload.len())?;
    let mut head = [0_u8; 9];
    head[..3].copy_from_slice(&length.to_be_bytes()[1..]);
    head[3] = kind;
    head[4] = flags;
    head[5..].copy_from_slice(&stream.to_be_bytes());
    peer.write_all(&head).await?;
    peer.write_all(payload).await?;
    peer.flush().await?;
    Ok(())
}
