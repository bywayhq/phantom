//! Replays retained browser HTTP/2 sessions through the profile HPACK encoder.
//!
//! Each session is one captured connection: the peer's SETTINGS and every
//! request HEADERS block the browser sent on it, in order. The replay opens an
//! [`Http2Connection`] with the browser family's recipe against a raw peer
//! that sends the captured SETTINGS, and sends each captured request with the
//! captured pseudo-header values and ordinary fields, rejoining cookie crumbs
//! into one `cookie` field. Every HPACK block the client sends must equal the
//! captured block byte for byte, on the stream the browser sent it on: Chrome,
//! Edge, Brave, and Opera number a connection's requests 1, 3, 5, and Firefox
//! 3, 5, 7.
//!
//! A browser does not wait for the peer's SETTINGS before its first request,
//! so the table size can reach its encoder after one or more blocks. Where the
//! capture records the browser's frames, the replay applies the SETTINGS
//! where the browser acknowledged them: after the request HEADERS it sent
//! before its SETTINGS acknowledgement.
//!
//! The encoder's output depends only on the fields it encodes and the peer's
//! table size, not on the responses, so the peer answers every request with
//! `:status: 200`.
//!
//! Sessions come from `fixtures/cookies/<browser>/<version>/windows-11-26200/
//! crumbs-h2.txt`, three runs of four requests with five cookies, and from
//! every HTTP/2 connection in `fixtures/websocket/<browser>/<version>/
//! windows-11-26200/`, whose page loads mix navigations, `fetch()`, and
//! extended CONNECT.

use std::collections::BTreeMap;

use http::Method;
use phantom_profile::{Http2Settings, chromium, firefox};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex},
    time::timeout,
};

use super::{OriginForm, RequestHeader, TestResult};
use crate::http2::Http2Connection;

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const MAX_CLIENT_FRAME_LEN: usize = 1 << 20;
const SESSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// SETTINGS sent by the cookie capture server, python-h2 4.4.1 with its default
/// configuration. The cookie fixtures do not record the server's frames; the
/// proxy route captures record these values from a server built the same way
/// (`scripts/capture/proxy_route.py`). Only `SETTINGS_HEADER_TABLE_SIZE`
/// reaches the encoder, and Firefox's first block answers it with a 4,096-byte
/// update.
const H2_DEFAULT_SERVER_SETTINGS: &str = "1=4096;2=0;4=65535;5=16384;8=0;3=100;6=65536";

macro_rules! fixture {
    ($path:literal) => {
        (
            $path,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../fixtures/",
                $path
            )),
        )
    };
}

const CHROME_COOKIES: (&str, &str) =
    fixture!("cookies/chrome/154.0.8037.58/windows-11-26200/crumbs-h2.txt");
const EDGE_COOKIES: (&str, &str) =
    fixture!("cookies/edge/153.0.4234.48/windows-11-26200/crumbs-h2.txt");
const FIREFOX_COOKIES: (&str, &str) =
    fixture!("cookies/firefox/156.0/windows-11-26200/crumbs-h2.txt");

const CHROME_WEBSOCKET: &[(&str, &str)] = &[
    fixture!("websocket/chrome/154.0.8037.58/windows-11-26200/accept.txt"),
    fixture!("websocket/chrome/154.0.8037.58/windows-11-26200/accept-deflate.txt"),
    fixture!("websocket/chrome/154.0.8037.58/windows-11-26200/extension-mismatch.txt"),
    fixture!("websocket/chrome/154.0.8037.58/windows-11-26200/no-connect-protocol.txt"),
    fixture!("websocket/chrome/154.0.8037.58/windows-11-26200/refused-stream.txt"),
    fixture!("websocket/chrome/154.0.8037.58/windows-11-26200/reject-403.txt"),
];
const EDGE_WEBSOCKET: &[(&str, &str)] = &[
    fixture!("websocket/edge/154.0.4258.37/windows-11-26200/accept.txt"),
    fixture!("websocket/edge/154.0.4258.37/windows-11-26200/accept-deflate.txt"),
    fixture!("websocket/edge/154.0.4258.37/windows-11-26200/extension-mismatch.txt"),
    fixture!("websocket/edge/154.0.4258.37/windows-11-26200/no-connect-protocol.txt"),
    fixture!("websocket/edge/154.0.4258.37/windows-11-26200/refused-stream.txt"),
    fixture!("websocket/edge/154.0.4258.37/windows-11-26200/reject-403.txt"),
];
const BRAVE_WEBSOCKET: &[(&str, &str)] = &[
    fixture!("websocket/brave/154.1.96.59/windows-11-26200/accept.txt"),
    fixture!("websocket/brave/154.1.96.59/windows-11-26200/accept-deflate.txt"),
    fixture!("websocket/brave/154.1.96.59/windows-11-26200/extension-mismatch.txt"),
    fixture!("websocket/brave/154.1.96.59/windows-11-26200/no-connect-protocol.txt"),
    fixture!("websocket/brave/154.1.96.59/windows-11-26200/refused-stream.txt"),
    fixture!("websocket/brave/154.1.96.59/windows-11-26200/reject-403.txt"),
];
const OPERA_WEBSOCKET: &[(&str, &str)] = &[
    fixture!("websocket/opera/135.0.5973.92/windows-11-26200/accept.txt"),
    fixture!("websocket/opera/135.0.5973.92/windows-11-26200/accept-deflate.txt"),
    fixture!("websocket/opera/135.0.5973.92/windows-11-26200/extension-mismatch.txt"),
    fixture!("websocket/opera/135.0.5973.92/windows-11-26200/no-connect-protocol.txt"),
    fixture!("websocket/opera/135.0.5973.92/windows-11-26200/refused-stream.txt"),
    fixture!("websocket/opera/135.0.5973.92/windows-11-26200/reject-403.txt"),
];
const FIREFOX_WEBSOCKET: &[(&str, &str)] = &[
    fixture!("websocket/firefox/156.0/windows-11-26200/accept.txt"),
    fixture!("websocket/firefox/156.0/windows-11-26200/accept-deflate.txt"),
    fixture!("websocket/firefox/156.0/windows-11-26200/extension-mismatch.txt"),
    fixture!("websocket/firefox/156.0/windows-11-26200/fresh-origin.txt"),
    fixture!("websocket/firefox/156.0/windows-11-26200/no-connect-protocol.txt"),
    fixture!("websocket/firefox/156.0/windows-11-26200/refused-stream.txt"),
    fixture!("websocket/firefox/156.0/windows-11-26200/reject-403.txt"),
];

#[tokio::test]
async fn chrome_cookie_sessions_match_the_captured_streams_and_hpack_bytes() -> TestResult<()> {
    replay_all(
        &[CHROME_COOKIES],
        chromium::v154_http2(),
        Source::Cookies,
        4,
    )
    .await
}

#[tokio::test]
async fn edge_cookie_sessions_match_the_captured_streams_and_hpack_bytes() -> TestResult<()> {
    // Edge 153 uses the Chromium recipe (`phantom_profile::edge`).
    replay_all(&[EDGE_COOKIES], chromium::v154_http2(), Source::Cookies, 3).await
}

#[tokio::test]
async fn firefox_cookie_sessions_match_the_captured_streams_and_hpack_bytes() -> TestResult<()> {
    replay_all(
        &[FIREFOX_COOKIES],
        firefox::v156_http2(),
        Source::Cookies,
        3,
    )
    .await
}

#[tokio::test]
async fn chrome_websocket_sessions_match_the_captured_streams_and_hpack_bytes() -> TestResult<()> {
    replay_all(
        CHROME_WEBSOCKET,
        chromium::v154_http2(),
        Source::WebSocket,
        18,
    )
    .await
}

#[tokio::test]
async fn edge_websocket_sessions_match_the_captured_streams_and_hpack_bytes() -> TestResult<()> {
    replay_all(
        EDGE_WEBSOCKET,
        chromium::v154_http2(),
        Source::WebSocket,
        18,
    )
    .await
}

#[tokio::test]
async fn brave_and_opera_websocket_sessions_match_the_chromium_streams_and_hpack_bytes()
-> TestResult<()> {
    // Brave 154 and Opera 135 use the Chromium recipe too.
    replay_all(
        BRAVE_WEBSOCKET,
        chromium::v154_http2(),
        Source::WebSocket,
        18,
    )
    .await?;
    replay_all(
        OPERA_WEBSOCKET,
        chromium::v154_http2(),
        Source::WebSocket,
        20,
    )
    .await
}

#[tokio::test]
async fn firefox_websocket_sessions_match_the_captured_streams_and_hpack_bytes() -> TestResult<()> {
    replay_all(
        FIREFOX_WEBSOCKET,
        firefox::v156_http2(),
        Source::WebSocket,
        24,
    )
    .await
}

/// The rules each Firefox capture needs are not all satisfied by Chromium's
/// recipe: the replay tells the two families apart by the first stream alone,
/// and by the HPACK blocks once the Chromium recipe numbers streams as
/// Firefox does.
#[tokio::test]
async fn chromium_recipe_does_not_reproduce_a_firefox_session() -> TestResult<()> {
    let mut renumbered = chromium::v154_http2();
    renumbered.streams.first_stream_id = 3;
    for (settings, expected) in [
        (
            chromium::v154_http2(),
            "was sent on stream 1, captured on stream 3",
        ),
        (renumbered, "HPACK block differs"),
    ] {
        let (name, text) = FIREFOX_COOKIES;
        let session = sessions(text, Source::Cookies)?
            .into_iter()
            .next()
            .ok_or("the Firefox cookie capture holds no session")?;
        let result = timeout(SESSION_TIMEOUT, replay_session(&session, &settings)).await?;
        let error = match result {
            Ok(()) => {
                return Err(format!("{name} run 0 replayed under the Chromium recipe").into());
            }
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains(expected),
            "{name} run 0 failed for another reason: {error}"
        );
    }
    Ok(())
}

/// Which fixture format a capture file uses.
#[derive(Clone, Copy)]
enum Source {
    /// `phantom-cookie-crumbs-v1`: one connection per run.
    Cookies,
    /// The WebSocket session format: several connections per run.
    WebSocket,
}

/// One captured connection.
struct Session {
    label: String,
    settings: Vec<(u16, u32)>,
    /// How many requests the browser encoded before applying `settings`.
    settings_after: usize,
    requests: Vec<Request>,
}

/// One captured request HEADERS block, its stream, and the fields it decodes
/// to.
struct Request {
    stream_id: u32,
    fields: Vec<(String, String)>,
    block: Vec<u8>,
}

async fn replay_all(
    files: &[(&str, &str)],
    settings: Http2Settings,
    source: Source,
    expected_sessions: usize,
) -> TestResult<()> {
    let mut replayed = 0;
    for (name, text) in files {
        for session in sessions(text, source)? {
            let label = format!("{name} {}", session.label);
            timeout(SESSION_TIMEOUT, replay_session(&session, &settings))
                .await
                .map_err(|_| format!("{label}: replay timed out"))?
                .map_err(|error| format!("{label}: {error}"))?;
            replayed += 1;
        }
    }
    assert_eq!(replayed, expected_sessions, "replayed session count");
    Ok(())
}

async fn replay_session(session: &Session, settings: &Http2Settings) -> TestResult<()> {
    let (client, server) = duplex(1 << 20);
    let peer = tokio::spawn(run_peer(
        server,
        session.settings.clone(),
        session.settings_after,
        session
            .requests
            .iter()
            .map(|r| (r.stream_id, r.block.clone()))
            .collect(),
    ));
    let connection = Http2Connection::connect(client, settings).await?;
    let sent = send_requests(&connection, session, settings).await;
    drop(connection);
    // The peer's comparison explains a client failure it caused.
    let compared = peer.await?;
    compared.and(sent)
}

async fn send_requests(
    connection: &Http2Connection,
    session: &Session,
    settings: &Http2Settings,
) -> TestResult<()> {
    if session.settings_after == 0 {
        // The captured first block was encoded after the peer's SETTINGS.
        connection.extended_connect_enabled().await?;
    }

    for request in &session.requests {
        let pseudo = |name: &str| {
            request
                .fields
                .iter()
                .find(|(field, _)| field == name)
                .map(|(_, value)| value.as_str())
        };
        let method = pseudo(":method").ok_or("captured request has no :method")?;
        let authority = pseudo(":authority").ok_or("captured request has no :authority")?;
        let path = pseudo(":path").ok_or("captured request has no :path")?;
        if pseudo(":scheme") != Some("https") {
            return Err("replay supports only https requests".into());
        }
        let target = OriginForm::parse(path)?;
        let headers = ordinary_fields(&request.fields);
        if method == "CONNECT" {
            if pseudo(":protocol") != Some("websocket") {
                return Err("replay supports only WebSocket extended CONNECT".into());
            }
            // The encoder state is all that matters; the stream is dropped.
            let _outcome = connection
                .send_extended_connect_with_settings(settings, authority, target, headers)
                .await?;
        } else {
            let method = Method::from_bytes(method.as_bytes())?;
            connection
                .send_request(method, authority, target, headers, None)
                .await?;
        }
    }
    Ok(())
}

/// Returns the ordinary fields in order, joining each run of cookie crumbs
/// back into the one `cookie` field a caller or cookie jar supplies.
fn ordinary_fields(fields: &[(String, String)]) -> Vec<RequestHeader> {
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut previous_cookie = false;
    for (name, value) in fields.iter().filter(|(name, _)| !name.starts_with(':')) {
        let cookie = name == "cookie";
        match headers.last_mut() {
            Some((_, joined)) if cookie && previous_cookie => {
                joined.push_str("; ");
                joined.push_str(value);
            }
            _ => headers.push((name.clone(), value.clone())),
        }
        previous_cookie = cookie;
    }
    headers
        .into_iter()
        .map(|(name, value)| RequestHeader::new(name, value))
        .collect()
}

/// Sends the captured SETTINGS, answers each request, and compares each
/// request's HPACK block with the capture.
///
/// The SETTINGS go out before the first request when `settings_after` is 0,
/// and otherwise right after that many requests, before the response that
/// lets the client send the next one.
async fn run_peer(
    mut stream: DuplexStream,
    settings: Vec<(u16, u32)>,
    settings_after: usize,
    expected: Vec<(u32, Vec<u8>)>,
) -> TestResult<()> {
    let mut preface = [0_u8; CLIENT_PREFACE.len()];
    stream.read_exact(&mut preface).await?;
    if preface.as_slice() != CLIENT_PREFACE {
        return Err("client sent an invalid HTTP/2 connection preface".into());
    }
    let payload = settings
        .iter()
        .flat_map(|(id, value)| id.to_be_bytes().into_iter().chain(value.to_be_bytes()))
        .collect::<Vec<_>>();
    // A server's first frame is its SETTINGS, so the client's SETTINGS are
    // acknowledged only after it.
    let mut acknowledge = settings_after == 0;
    if acknowledge {
        write_frame(&mut stream, 0x04, 0, 0, &payload).await?;
        stream.flush().await?;
    }

    for (index, (want_stream, want)) in expected.iter().enumerate() {
        let (stream_id, end_stream, got) = read_request_block(&mut stream, acknowledge).await?;
        if stream_id != *want_stream {
            return Err(format!(
                "request {index} was sent on stream {stream_id}, captured on stream {want_stream}"
            )
            .into());
        }
        if index + 1 == settings_after {
            write_frame(&mut stream, 0x04, 0, 0, &payload).await?;
            write_frame(&mut stream, 0x04, 0x01, 0, &[]).await?;
            acknowledge = true;
        }
        if &got != want {
            return Err(format!(
                "request {index} HPACK block differs\n  captured: {}\n  phantom:  {}",
                hex(want),
                hex(&got)
            )
            .into());
        }
        // `:status: 200`, ending the stream only when the request ended its own.
        let flags = if end_stream { 0x05 } else { 0x04 };
        write_frame(&mut stream, 0x01, flags, stream_id, &[0x88]).await?;
        stream.flush().await?;
    }
    // Keep reading until the client closes, so it never writes to a closed
    // peer.
    while read_frame(&mut stream).await.is_ok() {}
    Ok(())
}

/// Reads frames until one complete request HEADERS block, acknowledging the
/// client's SETTINGS on the way when `acknowledge` is set.
async fn read_request_block(
    stream: &mut DuplexStream,
    acknowledge: bool,
) -> TestResult<(u32, bool, Vec<u8>)> {
    loop {
        let (kind, flags, stream_id, payload) = read_frame(stream).await?;
        match kind {
            0x04 if flags & 0x01 == 0 && acknowledge => {
                write_frame(stream, 0x04, 0x01, 0, &[]).await?;
                stream.flush().await?;
            }
            0x01 => {
                let mut start = 0;
                let mut padding = 0;
                if flags & 0x08 != 0 {
                    padding = usize::from(*payload.first().ok_or("padded HEADERS is empty")?);
                    start += 1;
                }
                if flags & 0x20 != 0 {
                    start += 5;
                }
                let end = payload
                    .len()
                    .checked_sub(padding)
                    .filter(|end| *end >= start)
                    .ok_or("HEADERS metadata exceeded its payload")?;
                let mut block = payload[start..end].to_vec();
                let mut end_headers = flags & 0x04 != 0;
                while !end_headers {
                    let (kind, flags, id, payload) = read_frame(stream).await?;
                    if kind != 0x09 || id != stream_id {
                        return Err("HEADERS was interrupted before END_HEADERS".into());
                    }
                    block.extend_from_slice(&payload);
                    end_headers = flags & 0x04 != 0;
                }
                return Ok((stream_id, flags & 0x01 != 0, block));
            }
            _ => {}
        }
    }
}

async fn read_frame(stream: &mut DuplexStream) -> TestResult<(u8, u8, u32, Vec<u8>)> {
    let mut head = [0_u8; 9];
    stream.read_exact(&mut head).await?;
    let length = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
    if length > MAX_CLIENT_FRAME_LEN {
        return Err("client frame exceeded the peer's length bound".into());
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).await?;
    let stream_id = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
    Ok((head[3], head[4], stream_id, payload))
}

async fn write_frame(
    stream: &mut DuplexStream,
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload: &[u8],
) -> TestResult<()> {
    let length = u32::try_from(payload.len())?;
    let mut head = [0_u8; 9];
    head[..3].copy_from_slice(&length.to_be_bytes()[1..]);
    head[3] = kind;
    head[4] = flags;
    head[5..].copy_from_slice(&stream_id.to_be_bytes());
    stream.write_all(&head).await?;
    stream.write_all(payload).await?;
    Ok(())
}

/// Parses every connection with request HEADERS from one capture file.
fn sessions(text: &str, source: Source) -> TestResult<Vec<Session>> {
    let values = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect::<BTreeMap<_, _>>();
    let value = |key: &str| {
        values
            .get(key)
            .copied()
            .ok_or_else(|| format!("capture omitted {key}"))
    };
    let count = |key: &str| -> TestResult<usize> { Ok(value(key)?.parse()?) };
    let block = |prefix: &str| -> TestResult<Request> {
        let mut fields = Vec::new();
        for field in 0..count(&format!("{prefix}_field_count"))? {
            let record = value(&format!("{prefix}_field_{field}"))?;
            let attribute = |name: &str| {
                record
                    .split(',')
                    .find_map(|item| item.strip_prefix(name)?.strip_prefix(':'))
                    .ok_or_else(|| format!("capture field omitted {name}"))
            };
            if attribute("repr")? == "size-update" {
                continue;
            }
            fields.push((
                String::from_utf8(decode_hex(attribute("name_hex")?)?)?,
                String::from_utf8(decode_hex(attribute("value_hex")?)?)?,
            ));
        }
        let stream_id = value(prefix)?
            .split(',')
            .find_map(|item| item.strip_prefix("stream:"))
            .ok_or("capture request omitted its stream")?
            .parse()?;
        Ok(Request {
            stream_id,
            fields,
            block: decode_hex(value(&format!("{prefix}_block_hex"))?)?,
        })
    };

    let mut sessions = Vec::new();
    for run in 0..count("repeat_count")? {
        match source {
            Source::Cookies => {
                // A run can move to a new connection, so group its requests
                // by the connection each arrived on, in arrival order.
                let mut connections: BTreeMap<&str, Vec<Request>> = BTreeMap::new();
                for request in 0..count(&format!("run_{run}_request_count"))? {
                    let prefix = format!("run_{run}_request_{request}");
                    let connection = value(&prefix)?
                        .split(',')
                        .find_map(|item| item.strip_prefix("connection:"))
                        .ok_or("capture request omitted its connection")?;
                    connections
                        .entry(connection)
                        .or_default()
                        .push(block(&prefix)?);
                }
                for (connection, requests) in connections {
                    sessions.push(Session {
                        label: format!("run {run} connection {connection}"),
                        settings: parse_settings(H2_DEFAULT_SERVER_SETTINGS)?,
                        settings_after: 0,
                        requests,
                    });
                }
            }
            Source::WebSocket => {
                for connection in 0..count(&format!("run_{run}_connection_count"))? {
                    let prefix = format!("run_{run}_connection_{connection}");
                    let headers = match values.get(format!("{prefix}_headers_count").as_str()) {
                        Some(headers) => headers.parse::<usize>()?,
                        None => continue,
                    };
                    if headers == 0 {
                        continue;
                    }
                    let requests = (0..headers)
                        .map(|index| block(&format!("{prefix}_headers_{index}")))
                        .collect::<TestResult<Vec<_>>>()?;
                    let frames = (0..count(&format!("{prefix}_frame_count"))?)
                        .map(|frame| value(&format!("{prefix}_frame_{frame}")))
                        .collect::<Result<Vec<_>, _>>()?;
                    sessions.push(Session {
                        label: format!("run {run} connection {connection}"),
                        settings: server_settings(&frames)?,
                        settings_after: requests_before_settings_ack(&frames),
                        requests,
                    });
                }
            }
        }
    }
    Ok(sessions)
}

/// Returns the server's initial SETTINGS recorded for one connection.
fn server_settings(frames: &[&str]) -> TestResult<Vec<(u16, u32)>> {
    let record = frames
        .iter()
        .find(|record| {
            record.contains("dir:server")
                && record.contains("type:SETTINGS")
                && record.contains("flags:0x00")
        })
        .ok_or("connection recorded no server SETTINGS")?;
    let settings = record
        .split(',')
        .find_map(|item| item.strip_prefix("settings:"))
        .ok_or("server SETTINGS omitted its values")?;
    parse_settings(settings)
}

/// Counts the request HEADERS the browser sent before acknowledging the
/// server's SETTINGS, which it does when it applies them.
fn requests_before_settings_ack(frames: &[&str]) -> usize {
    let client = |record: &&&str, kind: &str| {
        record.contains("dir:client") && record.contains(&format!("type:{kind},"))
    };
    frames
        .iter()
        .take_while(|record| !(client(record, "SETTINGS") && record.contains("flags:0x01")))
        .filter(|record| client(record, "HEADERS"))
        .count()
}

fn parse_settings(text: &str) -> TestResult<Vec<(u16, u32)>> {
    text.split(';')
        .map(|pair| {
            let (id, value) = pair.split_once('=').ok_or("malformed setting")?;
            Ok((id.parse()?, value.parse()?))
        })
        .collect()
}

fn decode_hex(encoded: &str) -> TestResult<Vec<u8>> {
    if !encoded.len().is_multiple_of(2) {
        return Err("capture hex has odd length".into());
    }
    (0..encoded.len())
        .step_by(2)
        .map(|index| Ok(u8::from_str_radix(&encoded[index..index + 2], 16)?))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
