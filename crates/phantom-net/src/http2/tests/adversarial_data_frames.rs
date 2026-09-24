use http_body_util::BodyExt;
use phantom_profile::{Http2Settings, chromium::v154_http2, firefox::v156_http2};
use tokio::io::{AsyncWriteExt, DuplexStream, duplex};

use super::adversarial_malformed::{
    establish_baseline, expect_one_goaway, read_frame, write_frame,
};
use super::{TestResult, bounded_peer_test, target};
use crate::http2::Http2Connection;

const ENHANCE_YOUR_CALM: u32 = 0x0b;
const TOO_MANY_DATA_FRAMES: &[u8] = b"too_many_data_frames";
// Connection lifetime limit on empty non-final DATA frames (h2 0.4.17).
const MAX_EMPTY_DATA_FRAMES: usize = 100;
// Approximate memory cost of one buffered DATA event (h2 0.4.16).
const DATA_FRAME_OVERHEAD: usize = 256;
// `:status: 200` from the HPACK static table.
const STATUS_200: &[u8] = &[0x88];
const END_STREAM: u8 = 0x01;
const END_HEADERS: u8 = 0x04;
const PADDED: u8 = 0x08;

#[tokio::test]
async fn empty_data_flood_emits_one_calm_error_with_chrome_profile() -> TestResult<()> {
    bounded_peer_test(run_flood(v154_http2(), DataFlood::Empty)).await
}

#[tokio::test]
async fn empty_data_flood_emits_one_calm_error_with_firefox_profile() -> TestResult<()> {
    bounded_peer_test(run_flood(v156_http2(), DataFlood::Empty)).await
}

#[tokio::test]
async fn padded_empty_data_flood_emits_one_calm_error() -> TestResult<()> {
    bounded_peer_test(run_flood(v154_http2(), DataFlood::PaddedEmpty)).await
}

#[tokio::test]
async fn unread_small_data_flood_emits_one_calm_error() -> TestResult<()> {
    bounded_peer_test(run_flood(v154_http2(), DataFlood::Small)).await
}

#[tokio::test]
async fn tolerated_empty_data_frames_are_not_delivered_as_body_chunks() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = duplex(64 * 1024);
        let peer = tokio::spawn(run_tolerated_peer(server));
        let connection = Http2Connection::connect(client, &v154_http2()).await?;

        let response = connection
            .send_get("example.test", target()?, Vec::new())
            .await?;
        let mut body = response.into_body();
        let mut chunks = Vec::new();
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame?.into_data() {
                chunks.push(data);
            }
        }
        if chunks != [bytes::Bytes::from_static(b"hello")] {
            return Err(format!("empty DATA frames reached the body: {chunks:?}").into());
        }
        if connection.is_closed() {
            return Err("tolerated empty DATA frames closed the connection".into());
        }
        drop(connection);
        peer.await??;
        Ok(())
    })
    .await
}

async fn run_flood(settings: Http2Settings, flood: DataFlood) -> TestResult<()> {
    let frames = flood.frames(&settings);
    let (client, server) = duplex(64 * 1024);
    let peer = tokio::spawn(run_flood_peer(server, flood, frames));
    let connection = Http2Connection::connect(client, &settings).await?;

    // The body is held without reading, so small frames stay buffered.
    let response = connection
        .send_get("example.test", target()?, Vec::new())
        .await?;
    let mut body = response.into_body();
    peer.await??;

    // Buffered one-byte chunks may be observed before the connection error.
    loop {
        match body.frame().await {
            Some(Err(_)) => break,
            Some(Ok(frame)) if frame.is_data() && flood == DataFlood::Small => {}
            other => {
                return Err(format!("{} body did not fail: {other:?}", flood.name()).into());
            }
        }
    }
    if !connection.is_closed() {
        return Err(format!("{} did not close the connection", flood.name()).into());
    }
    Ok(())
}

async fn run_flood_peer(
    mut stream: DuplexStream,
    flood: DataFlood,
    frames: usize,
) -> TestResult<()> {
    establish_baseline(&mut stream).await?;
    write_frame(&mut stream, 0x01, END_HEADERS, 1, STATUS_200).await?;
    for _ in 0..frames {
        match flood {
            DataFlood::Empty => write_frame(&mut stream, 0x00, 0, 1, &[]).await?,
            // Pad length 1 followed by one padding byte: an empty payload.
            DataFlood::PaddedEmpty => write_frame(&mut stream, 0x00, PADDED, 1, &[1, 0]).await?,
            DataFlood::Small => write_frame(&mut stream, 0x00, 0, 1, b"a").await?,
        }
    }
    stream.flush().await?;
    expect_one_goaway(
        &mut stream,
        flood.name(),
        ENHANCE_YOUR_CALM,
        TOO_MANY_DATA_FRAMES,
    )
    .await
}

async fn run_tolerated_peer(mut stream: DuplexStream) -> TestResult<()> {
    establish_baseline(&mut stream).await?;
    write_frame(&mut stream, 0x01, END_HEADERS, 1, STATUS_200).await?;
    for _ in 0..MAX_EMPTY_DATA_FRAMES {
        write_frame(&mut stream, 0x00, 0, 1, &[]).await?;
    }
    write_frame(&mut stream, 0x00, END_STREAM, 1, b"hello").await?;
    stream.flush().await?;
    while let Some(frame) = read_frame(&mut stream).await? {
        if frame.frame_type == 0x07 && frame.payload.get(4..8) != Some(&[0, 0, 0, 0]) {
            return Err("client rejected tolerated empty DATA frames".into());
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DataFlood {
    Empty,
    PaddedEmpty,
    Small,
}

impl DataFlood {
    fn name(self) -> &'static str {
        match self {
            Self::Empty => "empty DATA flood",
            Self::PaddedEmpty => "padded empty DATA flood",
            Self::Small => "unread one-byte DATA flood",
        }
    }

    /// Returns the frame count whose last frame first exceeds the limit.
    fn frames(self, settings: &Http2Settings) -> usize {
        match self {
            Self::Empty | Self::PaddedEmpty => MAX_EMPTY_DATA_FRAMES + 1,
            Self::Small => {
                // Half the connection window, at least 100 overhead units
                // (h2 0.4.19); each unread one-byte frame charges 255.
                let window = settings.initial_connection_window_size as usize;
                let budget = (window / 2).max(DATA_FRAME_OVERHEAD * 100);
                budget / (DATA_FRAME_OVERHEAD - 1) + 1
            }
        }
    }
}
