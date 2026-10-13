//! The idle limit a Firefox profile puts on a connection that reads no
//! response HEADERS or DATA, against a loopback peer, and the `GOAWAY` the
//! connection sends once its last handle is dropped.
//!
//! The recipe's 170-second limit is shortened to 1 second so the tests run
//! quickly; everything else is the Firefox 157 recipe.

use std::time::Duration;

use http::Method;
use http_body_util::BodyExt;
use phantom_profile::{
    Http2IdleTimeout, Http2Settings,
    browser::{chrome, firefox},
};
use tokio::{io::AsyncReadExt, net::TcpStream, sync::oneshot, time::Instant};

use super::{
    TestResult,
    ping_peer::{
        ACK, DATA, GOAWAY, HEADERS, IDLE, PAST_IDLE, PING, assert_closed, get, idle_peer_test,
        read_frame, start, start_with_peer_settings, write_frame,
    },
    target,
};
use crate::{
    http2::{Http2Connection, Http2Error, Http2ExtendedConnectOutcome, translate_settings},
    request::RequestHeader,
};

const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;

/// The Firefox 157 recipe with its idle limit scaled to [`IDLE`] and its idle
/// PING after `ping_after`.
fn scaled_firefox(ping_after: Option<Duration>) -> Http2Settings {
    let mut settings = firefox::v157_http2();
    settings.idle_timeout = Http2IdleTimeout::ClosedOnTimer(IDLE);
    settings.idle_ping_after = ping_after;
    settings.idle_ping_timeout = None;
    settings
}

/// Answers each request with an empty 200 and each PING with its ACK until
/// the client sends `GOAWAY`, and returns that frame's stream ID and payload.
async fn answer_until_goaway(peer: &mut TcpStream) -> TestResult<(u32, Vec<u8>, usize)> {
    let mut pings = 0;
    loop {
        let (kind, flags, stream, payload) = read_frame(peer).await?;
        match kind {
            HEADERS if flags & END_STREAM != 0 => {
                // `:status: 200` is static table entry 8.
                write_frame(peer, HEADERS, END_STREAM | END_HEADERS, stream, &[0x88]).await?;
            }
            PING if flags & ACK == 0 => {
                pings += 1;
                write_frame(peer, PING, ACK, 0, &payload).await?;
            }
            GOAWAY => return Ok((stream, payload, pings)),
            _ => {}
        }
    }
}

/// A response head resets the idle time. A connection that has read nothing
/// for its limit is no longer reusable, and dropping it sends `GOAWAY` with
/// last stream ID 0, `NO_ERROR`, and no debug data, then ends the byte
/// stream.
///
/// The checks hold whatever the scheduler's delays: the last read comes
/// after the request is sent and before the response returns.
#[tokio::test]
async fn a_connection_idle_past_its_limit_stops_being_reusable_and_closes_with_no_error()
-> TestResult<()> {
    idle_peer_test(async {
        let (mut peer, connection) = start(&scaled_firefox(None)).await?;
        let started = Instant::now();
        let peer_task = tokio::spawn(async move {
            let goaway = answer_until_goaway(&mut peer).await?;
            assert_closed(&mut peer).await?;
            TestResult::Ok(goaway)
        });

        tokio::time::sleep_until(started + IDLE / 2).await;
        let sent = Instant::now();
        get(&connection).await?;
        let answered = Instant::now();
        let left = connection.idle_time_left().ok_or("no idle limit")?;
        assert!(
            left + sent.elapsed() >= IDLE,
            "the response head did not reset the idle time: {left:?} left"
        );
        assert!(connection.is_reusable());

        tokio::time::sleep_until(answered + IDLE).await;
        assert_eq!(connection.idle_time_left(), Some(Duration::ZERO));
        assert!(!connection.is_reusable());

        drop(connection);
        let (stream, payload, _) = peer_task.await??;
        assert_eq!((stream, payload), (0, vec![0; 8]));
        Ok(())
    })
    .await
}

/// Idle PINGs and their ACKs are read but leave the idle time running, as
/// in Firefox, where only HEADERS and DATA reset it.
#[tokio::test]
async fn idle_ping_acks_do_not_reset_the_idle_time() -> TestResult<()> {
    idle_peer_test(async {
        let ping_after = Duration::from_millis(400);
        let (mut peer, connection) = start(&scaled_firefox(Some(ping_after))).await?;
        let peer_task = tokio::spawn(async move { answer_until_goaway(&mut peer).await });

        tokio::time::sleep(PAST_IDLE).await;
        assert!(!connection.is_reusable());
        drop(connection);
        let (stream, payload, pings) = peer_task.await??;
        assert!(pings >= 2, "{pings} PINGs answered");
        assert_eq!((stream, payload), (0, vec![0; 8]));
        Ok(())
    })
    .await
}

/// A DATA frame handed to the caller resets the idle time, though its
/// stream stays open.
#[tokio::test]
async fn a_data_frame_resets_the_idle_time() -> TestResult<()> {
    idle_peer_test(async {
        let (mut peer, connection) = start(&scaled_firefox(None)).await?;
        let started = Instant::now();
        let request =
            connection.send_request(Method::GET, "example.test", target()?, Vec::new(), None);
        let respond = async {
            let stream = loop {
                let (kind, _, stream, _) = read_frame(&mut peer).await?;
                if kind == HEADERS {
                    break stream;
                }
            };
            write_frame(&mut peer, HEADERS, END_HEADERS, stream, &[0x88]).await?;
            TestResult::Ok(stream)
        };
        let (response, stream) = tokio::join!(request, respond);
        let (response, stream) = (response?, stream?);
        let mut body = response.into_body();

        tokio::time::sleep_until(started + IDLE / 2).await;
        let written = Instant::now();
        write_frame(&mut peer, DATA, 0, stream, b"late").await?;
        let frame = body.frame().await.ok_or("body ended")??;
        let read = Instant::now();
        assert_eq!(frame.into_data().ok().as_deref(), Some(&b"late"[..]));
        let left = connection.idle_time_left().ok_or("no idle limit")?;
        assert!(
            left + written.elapsed() >= IDLE,
            "the DATA frame did not reset the idle time: {left:?} left"
        );

        tokio::time::sleep_until(read + IDLE).await;
        assert!(!connection.is_reusable());
        Ok(())
    })
    .await
}

/// `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x8) set to 1, so the client may open
/// extended CONNECT streams.
const ENABLE_CONNECT_PROTOCOL: [u8; 6] = [0x00, 0x08, 0x00, 0x00, 0x00, 0x01];

/// Reads frames until the client's `GOAWAY` and returns its stream ID and
/// payload.
async fn read_until_goaway(peer: &mut TcpStream) -> TestResult<(u32, Vec<u8>)> {
    loop {
        let (kind, _, stream, payload) = read_frame(peer).await?;
        if kind == GOAWAY {
            return Ok((stream, payload));
        }
    }
}

/// DATA read from an extended CONNECT stream, as a WebSocket reads it,
/// resets the idle time. While the stream stays open, a connection past its
/// limit whose last handle is dropped sends no `GOAWAY`; the `GOAWAY` follows
/// once the stream ends.
#[tokio::test]
async fn an_extended_connect_stream_resets_the_idle_time_and_holds_back_the_goaway()
-> TestResult<()> {
    idle_peer_test(async {
        let settings = scaled_firefox(None);
        let (mut peer, connection) =
            start_with_peer_settings(&settings, &ENABLE_CONNECT_PROTOCOL).await?;
        let started = Instant::now();
        let open = connection.send_extended_connect_with_settings(
            &settings,
            "example.test",
            target()?,
            vec![RequestHeader::new("sec-websocket-version", "13")],
        );
        let accept = async {
            let stream = loop {
                let (kind, _, stream, _) = read_frame(&mut peer).await?;
                if kind == HEADERS {
                    break stream;
                }
            };
            write_frame(&mut peer, HEADERS, END_HEADERS, stream, &[0x88]).await?;
            TestResult::Ok(stream)
        };
        let (outcome, stream_id) = tokio::join!(open, accept);
        let Http2ExtendedConnectOutcome::Accepted { mut stream, .. } = outcome? else {
            return Err("the peer's 200 did not accept the stream".into());
        };
        let stream_id = stream_id?;

        tokio::time::sleep_until(started + IDLE / 2).await;
        let written = Instant::now();
        write_frame(&mut peer, DATA, 0, stream_id, b"late").await?;
        let mut data = [0_u8; 4];
        stream.read_exact(&mut data).await?;
        let read = Instant::now();
        assert_eq!(&data, b"late");
        let left = connection.idle_time_left().ok_or("no idle limit")?;
        assert!(
            left + written.elapsed() >= IDLE,
            "the DATA frame did not reset the idle time: {left:?} left"
        );

        let (goaway_sent, goaway) = oneshot::channel();
        let peer_task = tokio::spawn(async move {
            let frame = read_until_goaway(&mut peer).await;
            let _ = goaway_sent.send(Instant::now());
            let frame = frame?;
            assert_closed(&mut peer).await?;
            TestResult::Ok(frame)
        });
        tokio::time::sleep_until(read + PAST_IDLE).await;
        assert!(!connection.is_reusable());
        drop(connection);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let stream_ended = Instant::now();
        drop(stream);
        let goaway_at = goaway.await?;
        assert!(
            goaway_at >= stream_ended,
            "GOAWAY arrived while the stream was open"
        );
        let (last_stream, payload) = peer_task.await??;
        assert_eq!((last_stream, payload), (0, vec![0; 8]));
        Ok(())
    })
    .await
}

/// A limit under a second, which validation rejects, is refused by the
/// translation as well, for a caller that skips validation.
#[tokio::test]
async fn a_limit_under_a_second_is_refused() -> TestResult<()> {
    let mut settings = scaled_firefox(None);
    settings.idle_timeout = Http2IdleTimeout::ClosedOnTimer(Duration::from_millis(500));
    assert!(matches!(
        translate_settings(&settings),
        Err(Http2Error::UnsupportedSetting)
    ));
    let (client, _server) = tokio::io::duplex(1024);
    match Http2Connection::connect(client, &settings).await {
        Err(Http2Error::InvalidSettings(error)) => assert_eq!(error.field(), "idle_timeout"),
        other => return Err(format!("{other:?}").into()),
    }
    Ok(())
}

/// The Chromium recipe sets no limit.
#[tokio::test]
async fn chromium_recipe_sets_no_idle_limit() -> TestResult<()> {
    idle_peer_test(async {
        let (_peer, connection) = start(&chrome::v154_http2()).await?;
        assert_eq!(connection.idle_time_left(), None);
        assert!(connection.is_reusable());
        Ok(())
    })
    .await
}
