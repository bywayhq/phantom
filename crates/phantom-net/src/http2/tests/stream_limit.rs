//! Stream numbering and the stream limit a profile assumes before the peer's
//! SETTINGS, against a loopback peer that holds its SETTINGS back.
//!
//! The client sends one request more than the assumed limit. The peer counts
//! the request HEADERS that arrive before it sends any SETTINGS, then sends
//! SETTINGS that omit `SETTINGS_MAX_CONCURRENT_STREAMS`, and only then states
//! a limit that admits the last request.

use std::net::Ipv4Addr;

use http::Method;
use phantom_profile::{Http2Priority, Http2Settings, Http2StreamSettings, chromium, firefox};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
};

use super::{TestResult, bounded_peer_test, target};
use crate::http2::{Http2Connection, Http2Error, translate_settings};

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const HEADERS: u8 = 0x1;
const SETTINGS: u8 = 0x4;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const ACK: u8 = 0x1;
const MAX_CONCURRENT_STREAMS: u16 = 0x3;

/// Chrome 154 opens at most 100 streams before the peer states a limit,
/// numbered from 1.
#[tokio::test]
async fn chromium_recipe_opens_100_streams_from_1_before_settings() -> TestResult<()> {
    bounded_peer_test(expect_assumed_limit(chromium::v154_http2(), 1, 100)).await
}

/// Firefox 156 opens at most 100 streams before the peer states a limit,
/// numbered from 3.
#[tokio::test]
async fn firefox_recipe_opens_100_streams_from_3_before_settings() -> TestResult<()> {
    bounded_peer_test(expect_assumed_limit(firefox::v156_http2(), 3, 100)).await
}

/// Without an assumed limit, every request opens before the peer's SETTINGS.
#[tokio::test]
async fn settings_without_an_assumed_limit_open_every_request_at_once() -> TestResult<()> {
    bounded_peer_test(async {
        let mut settings = chromium::v154_http2();
        settings.streams = Http2StreamSettings::default();
        let (mut peer, _connection, mut requests) = start(&settings, 101).await?;
        for index in 0..101 {
            let stream = read_headers(&mut peer).await?;
            assert_eq!(stream, 1 + 2 * index, "request {index} stream");
        }
        requests.abort_all();
        Ok(())
    })
    .await
}

/// An even first stream is refused before any I/O, whether or not the
/// settings were validated, instead of reaching the backend's assertion.
#[tokio::test]
async fn an_even_first_stream_id_is_refused() -> TestResult<()> {
    let mut settings = firefox::v156_http2();
    settings.streams.first_stream_id = 2;
    assert!(matches!(
        translate_settings(&settings),
        Err(Http2Error::UnsupportedSetting)
    ));
    let (client, _peer) = tokio::io::duplex(1024);
    assert!(matches!(
        Http2Connection::connect(client, &settings).await,
        Err(Http2Error::InvalidSettings(_))
    ));
    Ok(())
}

/// A per-request priority that depends on the connection's first stream is
/// refused before any I/O: stream 3 under the Firefox recipe.
#[tokio::test]
async fn a_request_priority_on_the_first_stream_is_refused() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, _peer) = tokio::io::duplex(64 * 1024);
        let connection = Http2Connection::connect(client, &firefox::v156_http2()).await?;
        let result = connection
            .send_request_body_with_trailers_and_priority(
                Method::GET,
                "example.test",
                target()?,
                Vec::new(),
                None,
                Vec::new(),
                Http2Priority {
                    dependency_stream_id: 3,
                    weight: 220,
                    exclusive: true,
                },
            )
            .await;
        assert!(matches!(
            result,
            Err(Http2Error::InvalidPriorityDependency { stream_id: 3 })
        ));
        Ok(())
    })
    .await
}

async fn expect_assumed_limit(settings: Http2Settings, first: u32, limit: u32) -> TestResult<()> {
    let (mut peer, connection, mut requests) = start(&settings, limit + 1).await?;
    for index in 0..limit {
        let stream = read_headers(&mut peer).await?;
        assert_eq!(stream, first + 2 * index, "request {index} stream");
    }
    // The assumed limit is not the peer's.
    assert_eq!(connection.peer_max_concurrent_streams(), None);

    // A request opened before the SETTINGS would arrive before their ACK.
    write_frame(&mut peer, SETTINGS, 0, 0, &[]).await?;
    read_until(&mut peer, SETTINGS, ACK).await?;
    // SETTINGS without a limit leave the assumed one in place.
    write_frame(&mut peer, PING, 0, 0, b"assumed!").await?;
    read_until(&mut peer, PING, ACK).await?;
    let assumed = usize::try_from(limit)?;
    assert_eq!(connection.peer_max_concurrent_streams(), Some(assumed));

    let mut stated = MAX_CONCURRENT_STREAMS.to_be_bytes().to_vec();
    stated.extend_from_slice(&(limit + 1).to_be_bytes());
    write_frame(&mut peer, SETTINGS, 0, 0, &stated).await?;
    assert_eq!(read_headers(&mut peer).await?, first + 2 * limit);
    assert_eq!(connection.peer_max_concurrent_streams(), Some(assumed + 1));
    requests.abort_all();
    Ok(())
}

/// Connects a client over loopback and sends `count` requests on it without
/// answering the preface, returning the peer's socket past the client's
/// preface.
async fn start(
    settings: &Http2Settings,
    count: u32,
) -> TestResult<(TcpStream, Http2Connection, JoinSet<Result<(), String>>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let client = TcpStream::connect(listener.local_addr()?).await?;
    let (mut peer, _) = listener.accept().await?;
    let connection = Http2Connection::connect(client, settings).await?;
    let mut requests = JoinSet::new();
    for _ in 0..count {
        let connection = connection.clone();
        let target = target()?;
        requests.spawn(async move {
            connection
                .send_request(Method::GET, "example.test", target, Vec::new(), None)
                .await
                .map(drop)
                .map_err(|error| error.to_string())
        });
    }
    let mut preface = [0_u8; CLIENT_PREFACE.len()];
    peer.read_exact(&mut preface).await?;
    if preface.as_slice() != CLIENT_PREFACE {
        return Err("client sent an invalid HTTP/2 connection preface".into());
    }
    Ok((peer, connection, requests))
}

/// Reads frames until a request HEADERS and returns its stream.
async fn read_headers(peer: &mut TcpStream) -> TestResult<u32> {
    loop {
        let (kind, _, stream, _) = read_frame(peer).await?;
        match kind {
            HEADERS => return Ok(stream),
            GOAWAY => return Err("client sent GOAWAY".into()),
            _ => {}
        }
    }
}

/// Reads frames until one of `kind` with `flags`, failing on a request
/// HEADERS before it.
async fn read_until(peer: &mut TcpStream, kind: u8, flags: u8) -> TestResult<()> {
    loop {
        let (got, got_flags, stream, _) = read_frame(peer).await?;
        match got {
            HEADERS => return Err(format!("stream {stream} opened past the limit").into()),
            GOAWAY => return Err("client sent GOAWAY".into()),
            _ if got == kind && got_flags & flags == flags => return Ok(()),
            _ => {}
        }
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
