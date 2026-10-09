//! The PING a Chromium profile sends right after a request frame on a
//! connection that has read nothing for longer than its idle time, against a
//! loopback peer and the retained Chrome 154 capture, and the close that
//! follows when the PING goes unanswered.
//!
//! The recipe's 10-second idle time is shortened to 1 second, and its
//! 10-second PING timeout to 1 to 3 seconds, so the tests run quickly;
//! everything else is the Chrome 154 recipe.

use std::time::Duration;

use bytes::Bytes;
use http::Method;
use phantom_profile::browser::{chrome, firefox};
use tokio::{net::TcpStream, sync::mpsc, task::JoinSet};

use super::{
    TestResult,
    ping_peer::{
        ACK, CapturedFrame, DATA, GOAWAY, HEADERS, IDLE, PAST_IDLE, PING, SETTINGS, WINDOW_UPDATE,
        answer_requests, assert_closed, captured_frames, get, idle_peer_test, read_frame, request,
        request_sequence, start, write_frame,
    },
    target,
};
use crate::http2::Http2Error;

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

/// The Chrome 154 recipe waits 10 seconds without a read; Firefox 157 sends
/// no such PING.
#[test]
fn recipes_state_the_preface_ping_idle_time() {
    assert_eq!(
        chrome::v154_http2().preface_ping_after,
        Some(Duration::from_secs(10))
    );
    assert_eq!(firefox::v157_http2().preface_ping_after, None);
}

/// The Chrome 154 recipe closes a connection whose PING goes unanswered for
/// 10 seconds without a read; Firefox 157 sends no such PING to time.
#[test]
fn recipes_state_the_ping_timeout() {
    assert_eq!(
        chrome::v154_http2().ping_timeout,
        Some(Duration::from_secs(10))
    );
    assert_eq!(firefox::v157_http2().ping_timeout, None);
}

/// A PING the peer never answers closes the connection once nothing has been
/// read for the timeout: `GOAWAY` with last stream ID 0, `PROTOCOL_ERROR`,
/// and `Failed ping.`, then the end of the byte stream. The open request
/// fails with [`Http2Error::PingTimeout`], and a later one with
/// [`Http2Error::ReusedConnectionClosed`].
#[tokio::test]
async fn chromium_recipe_closes_a_connection_whose_ping_goes_unanswered() -> TestResult<()> {
    idle_peer_test(async {
        let mut settings = chrome::v154_http2();
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
        let mut settings = chrome::v154_http2();
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
        let mut settings = chrome::v154_http2();
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
        let mut settings = chrome::v154_http2();
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
        let mut settings = chrome::v154_http2();
        settings.preface_ping_after = None;
        settings.ping_timeout = None;
        settings.ping_failure_retries = 0;
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
        let mut settings = chrome::v154_http2();
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

fn capture_frames() -> TestResult<Vec<CapturedFrame>> {
    captured_frames(CHROME_CAPTURE, "frame_")
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
