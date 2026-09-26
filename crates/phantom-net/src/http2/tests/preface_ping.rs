//! The PING a Chromium profile sends right after a request frame on a
//! connection that has read nothing for longer than its idle time, against a
//! loopback peer.
//!
//! The recipe's 10-second idle time is shortened so the test runs quickly;
//! everything else is the Chrome 154 recipe.

use std::{net::Ipv4Addr, time::Duration};

use http::Method;
use phantom_profile::{Http2Settings, chromium, firefox};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
};

use super::{TestResult, bounded_peer_test, target};
use crate::http2::Http2Connection;

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const SETTINGS: u8 = 0x4;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const ACK: u8 = 0x1;
const IDLE: Duration = Duration::from_millis(250);
const PAST_IDLE: Duration = Duration::from_millis(400);
const PROBE: &[u8; 8] = b"probe!!!";

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

/// A request sent within the idle time carries no PING; one sent after it is
/// followed at once by PING 1; reading its ACK restarts the idle time; and
/// the next idle period brings PING 2.
#[tokio::test]
async fn chromium_recipe_pings_after_request_headers_on_a_read_idle_connection() -> TestResult<()> {
    bounded_peer_test(async {
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
    bounded_peer_test(async {
        let mut settings = chromium::v154_http2();
        settings.preface_ping_after = None;
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
