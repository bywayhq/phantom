//! The PING a Firefox profile sends on a connection that has read nothing for
//! its idle time, whether or not requests are open, against a loopback peer
//! and the retained Firefox 157 capture, and the close that follows when the
//! PING goes unanswered.
//!
//! The recipe's 58-second idle time is shortened to 1 second, and its
//! 8-second timeout to 1 or 2 seconds, so the tests run quickly; everything
//! else is the Firefox 157 recipe.

use std::time::Duration;

use http::Method;
use phantom_profile::{Http2Settings, firefox};
use tokio::{sync::mpsc, task::JoinSet};

use super::{
    TestResult,
    ping_peer::{
        ACK, CapturedFrame, GOAWAY, HEADERS, IDLE, PAST_IDLE, PING, WINDOW_UPDATE, answer_requests,
        assert_closed, captured_frames, get, idle_peer_test, read_frame, request, request_sequence,
        start, write_frame,
    },
    target,
};
use crate::http2::{Http2Error, translate_settings};

/// Firefox 157 leaving a pooled connection idle for 75 seconds between two
/// fetches, recorded by `scripts/capture/http_lifecycle.py`.
const FIREFOX_CAPTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/lifecycle/firefox/157.0/windows-11-26200/idle-ping.txt"
));
/// `network.http.http2.ping-threshold`, in milliseconds.
const FIREFOX_IDLE_MS: f64 = 58_000.0;

/// The Firefox 157 recipe with its idle time scaled to [`IDLE`].
fn scaled_firefox(ping_timeout: Option<Duration>) -> Http2Settings {
    let mut settings = firefox::v157_http2();
    settings.idle_ping_after = Some(IDLE);
    settings.idle_ping_timeout = ping_timeout;
    settings
}

/// The retained capture: after `/a`, the idle connection carries one PING
/// with a zero payload, more than 58 seconds after `/a` and before `/b`.
#[test]
fn firefox_capture_pings_once_on_the_idle_connection() -> TestResult<()> {
    let frames = capture_frames()?;
    assert_eq!(
        request_sequence(&frames),
        ["HEADERS", "PING 0000000000000000", "HEADERS", "HEADERS"]
    );
    let sent = |path: &str| {
        frames
            .iter()
            .find(|frame| frame.path.as_deref() == Some(path))
            .map(|frame| frame.milliseconds)
            .ok_or(format!("capture has no request for {path}"))
    };
    let ping = frames
        .iter()
        .find(|frame| frame.kind == "PING")
        .map(|frame| frame.milliseconds)
        .ok_or("capture has no PING")?;
    assert!(ping - sent("/a")? > FIREFOX_IDLE_MS);
    assert!(sent("/b")? > ping);
    Ok(())
}

/// Phantom's Firefox recipe, driven through the capture's timeline with the
/// idle time scaled, writes the capture's request frames and PING in the same
/// order with the same payload, the PING with no request open.
#[tokio::test]
async fn firefox_recipe_replays_the_firefox_capture_ping_sequence() -> TestResult<()> {
    idle_peer_test(async {
        let (peer, connection) = start(&scaled_firefox(Some(Duration::from_secs(2)))).await?;
        let (frames, mut sequence) = mpsc::unbounded_channel();
        let peer = tokio::spawn(answer_requests(peer, frames));

        get(&connection).await?;
        tokio::time::sleep(PAST_IDLE).await;
        get(&connection).await?;
        get(&connection).await?;
        peer.abort();

        let mut replayed = Vec::new();
        while let Ok(symbol) = sequence.try_recv() {
            replayed.push(symbol);
        }
        assert_eq!(replayed, request_sequence(&capture_frames()?));
        assert!(connection.is_reusable());
        Ok(())
    })
    .await
}

/// An idle PING the peer never answers closes the connection once nothing
/// has been read for the timeout: `GOAWAY` with last stream ID 0,
/// `INTERNAL_ERROR`, and no debug data, then the end of the byte stream. The
/// open request fails with [`Http2Error::PingTimeout`], and a later one with
/// [`Http2Error::ReusedConnectionClosed`].
#[tokio::test]
async fn firefox_recipe_closes_a_connection_whose_idle_ping_goes_unanswered() -> TestResult<()> {
    idle_peer_test(async {
        let (mut peer, connection) = start(&scaled_firefox(Some(Duration::from_secs(2)))).await?;
        let mut requests = JoinSet::new();
        request(&connection, &mut requests)?;
        let ping = loop {
            let (kind, flags, _, payload) = read_frame(&mut peer).await?;
            match kind {
                PING if flags & ACK == 0 => break payload,
                GOAWAY => return Err("client sent GOAWAY before its PING".into()),
                _ => {}
            }
        };
        assert_eq!(ping, [0; 8]);
        let ping_read = tokio::time::Instant::now();

        let (kind, flags, stream, payload) = read_frame(&mut peer).await?;
        let waited = ping_read.elapsed();
        assert_eq!((kind, flags, stream), (GOAWAY, 0, 0));
        assert_eq!(payload, [0, 0, 0, 0, 0, 0, 0, 2]);
        assert!(
            waited >= Duration::from_secs(1) && waited < Duration::from_secs(4),
            "GOAWAY after {waited:?}"
        );
        assert_closed(&mut peer).await?;

        let open = requests.join_next().await.ok_or("request task missing")??;
        assert_eq!(open, Err(Http2Error::PingTimeout.to_string()));
        assert!(!connection.is_reusable());
        let later = connection
            .send_request(Method::GET, "example.test", target()?, Vec::new(), None)
            .await;
        assert!(matches!(later, Err(Http2Error::ReusedConnectionClosed)));
        Ok(())
    })
    .await
}

/// Any frame read clears the outstanding PING, so a peer that answers only
/// with other frames keeps the connection past the timeout.
#[tokio::test]
async fn a_frame_read_keeps_a_connection_with_an_unanswered_idle_ping() -> TestResult<()> {
    idle_peer_test(async {
        let (mut peer, connection) = start(&scaled_firefox(Some(Duration::from_secs(1)))).await?;
        loop {
            let (kind, flags, _, _) = read_frame(&mut peer).await?;
            if kind == PING && flags & ACK == 0 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        write_frame(&mut peer, WINDOW_UPDATE, 0, 0, &1_u32.to_be_bytes()).await?;
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert!(connection.is_reusable());
        let mut requests = JoinSet::new();
        request(&connection, &mut requests)?;
        loop {
            let (kind, _, _, _) = read_frame(&mut peer).await?;
            match kind {
                HEADERS => break,
                GOAWAY => return Err("client sent GOAWAY".into()),
                _ => {}
            }
        }
        requests.abort_all();
        Ok(())
    })
    .await
}

fn capture_frames() -> TestResult<Vec<CapturedFrame>> {
    captured_frames(FIREFOX_CAPTURE, "connection_0_frame_")
}

/// Settings that skipped validation and carry an idle PING value the
/// backend cannot honor are refused, as validation would refuse them.
#[tokio::test]
async fn unvalidated_idle_ping_values_are_refused() {
    let invalid = [
        (Some(Duration::ZERO), None),
        (Some(Duration::MAX), None),
        (Some(IDLE), Some(Duration::ZERO)),
        (Some(IDLE), Some(Duration::MAX)),
        (None, Some(IDLE)),
    ];
    for (after, ping_timeout) in invalid {
        let mut settings = firefox::v157_http2();
        settings.idle_ping_after = after;
        settings.idle_ping_timeout = ping_timeout;
        assert!(
            matches!(
                translate_settings(&settings),
                Err(Http2Error::UnsupportedSetting)
            ),
            "{after:?} {ping_timeout:?}"
        );
    }
    assert!(translate_settings(&firefox::v157_http2()).is_ok());
}
