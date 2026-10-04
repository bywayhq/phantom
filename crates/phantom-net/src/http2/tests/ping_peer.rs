//! A loopback peer that speaks raw HTTP/2 frames to a client connection,
//! for the PING tests, and the parser of the PING captures they replay.

use std::{future::Future, net::Ipv4Addr, time::Duration};

use http::Method;
use phantom_profile::Http2Settings;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinSet,
    time::timeout,
};

use super::{TestResult, target};
use crate::http2::Http2Connection;

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub(super) const DATA: u8 = 0x0;
pub(super) const HEADERS: u8 = 0x1;
pub(super) const SETTINGS: u8 = 0x4;
pub(super) const PING: u8 = 0x6;
pub(super) const GOAWAY: u8 = 0x7;
pub(super) const WINDOW_UPDATE: u8 = 0x8;
pub(super) const ACK: u8 = 0x1;
const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
/// The idle time the tests give a profile in place of its own.
pub(super) const IDLE: Duration = Duration::from_secs(1);
pub(super) const PAST_IDLE: Duration = Duration::from_millis(1_500);

/// Bounds a test whose timeline spans several idle periods.
pub(super) async fn idle_peer_test<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    match timeout(Duration::from_secs(15), future).await {
        Ok(result) => result,
        Err(_) => Err("PING test exceeded its absolute deadline".into()),
    }
}

/// One client frame of a retained capture.
pub(super) struct CapturedFrame {
    pub(super) milliseconds: f64,
    pub(super) kind: String,
    pub(super) path: Option<String>,
    payload: Option<String>,
}

/// Parses the client frames of `capture`, whose keys are `prefix` and the
/// frame's index.
pub(super) fn captured_frames(capture: &str, prefix: &str) -> TestResult<Vec<CapturedFrame>> {
    let mut frames = Vec::new();
    for line in capture.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let Some(index) = key.strip_prefix(prefix) else {
            continue;
        };
        if index == "count" {
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
pub(super) fn request_sequence(frames: &[CapturedFrame]) -> Vec<String> {
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
pub(super) async fn get(connection: &Http2Connection) -> TestResult<()> {
    connection
        .send_request(Method::GET, "example.test", target()?, Vec::new(), None)
        .await?;
    Ok(())
}

/// Records the client's request frames and PINGs in the capture's notation,
/// acknowledges each PING, and answers each request with an empty 200 once
/// its last frame arrives.
pub(super) async fn answer_requests(
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
pub(super) async fn start(settings: &Http2Settings) -> TestResult<(TcpStream, Http2Connection)> {
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
pub(super) fn request(
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

/// Requires the client to end the byte stream after its GOAWAY. Windows can
/// report the close as a reset or an abort rather than an orderly end.
pub(super) async fn assert_closed(peer: &mut TcpStream) -> TestResult<()> {
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

pub(super) async fn read_frame(peer: &mut TcpStream) -> TestResult<(u8, u8, u32, Vec<u8>)> {
    let mut head = [0_u8; 9];
    peer.read_exact(&mut head).await?;
    let length = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
    let mut payload = vec![0_u8; length];
    peer.read_exact(&mut payload).await?;
    let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
    Ok((head[3], head[4], stream, payload))
}

pub(super) async fn write_frame(
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
