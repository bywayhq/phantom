use phantom_profile::{Http2Setting, Http2Settings, chromium::v152_http2, firefox::v154_http2};
use tokio::io::{AsyncWriteExt, DuplexStream, duplex};

use super::adversarial_malformed::{
    establish_baseline, expect_one_goaway, read_frame, write_frame,
};
use super::{TestResult, bounded_peer_test, target};
use crate::http2::{Http2Connection, Http2Error};

const ENHANCE_YOUR_CALM: u32 = 0x0b;
const PROTOCOL_ERROR: u32 = 0x01;
const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x06;
// Firefox's `network.http.max_response_header_size` default.
const FIREFOX_LIMIT: usize = 393_216;
// Chromium's `kSpdyMaxHeaderListSize`, advertised by the Chrome profile.
const CHROME_LIMIT: usize = 262_144;
// RFC 9113 section 6.5.2 cost of `:status: 200`.
const STATUS_200_COST: usize = ":status".len() + "200".len() + 32;
const END_STREAM: u8 = 0x01;
const END_HEADERS: u8 = 0x04;
const FRAGMENT_LEN: usize = 16_384;

#[tokio::test]
async fn oversized_header_list_is_a_typed_stream_error_with_firefox_profile() -> TestResult<()> {
    bounded_peer_test(run_oversized(v154_http2(), FIREFOX_LIMIT)).await
}

#[tokio::test]
async fn oversized_header_list_is_a_typed_stream_error_with_chrome_profile() -> TestResult<()> {
    bounded_peer_test(run_oversized(v152_http2(), CHROME_LIMIT)).await
}

#[tokio::test]
async fn header_list_below_firefox_ceiling_is_accepted() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = duplex(64 * 1024);
        let peer = tokio::spawn(async move {
            let mut stream = server;
            establish_baseline(&mut stream).await?;
            write_header_block(&mut stream, 1, &header_block(FIREFOX_LIMIT - 64), true).await?;
            drain_without_error(&mut stream).await
        });
        let connection = Http2Connection::connect(client, &v154_http2()).await?;
        let response = connection
            .send_get("example.test", target()?, Vec::new())
            .await?;
        if response.status() != 200 {
            return Err(format!("unexpected status {}", response.status()).into());
        }
        drop(response);
        drop(connection);
        peer.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn firefox_empty_continuation_flood_emits_one_calm_error() -> TestResult<()> {
    bounded_peer_test(run_connection_abuse(Abuse::EmptyContinuations)).await
}

#[tokio::test]
async fn firefox_cumulative_header_abuse_emits_one_calm_error() -> TestResult<()> {
    bounded_peer_test(run_connection_abuse(Abuse::CumulativeHeaderList)).await
}

#[tokio::test]
async fn firefox_nonempty_continuation_flood_emits_one_calm_error() -> TestResult<()> {
    bounded_peer_test(run_connection_abuse(Abuse::NonemptyContinuations)).await
}

async fn run_oversized(settings: Http2Settings, limit: usize) -> TestResult<()> {
    let advertised = settings
        .initial_settings
        .iter()
        .find_map(|setting| match setting {
            Http2Setting::MaxHeaderListSize(value) => Some(*value),
            _ => None,
        });
    let (client, server) = duplex(64 * 1024);
    let peer = tokio::spawn(run_oversized_peer(server, limit, advertised));
    let connection = Http2Connection::connect(client, &settings).await?;

    match connection
        .send_get("example.test", target()?, Vec::new())
        .await
    {
        Err(Http2Error::ResponseHeaderListTooLarge) => {}
        other => {
            let peer = peer.await;
            return Err(format!(
                "oversized header list was not rejected: {other:?}; peer: {peer:?}"
            )
            .into());
        }
    }
    if connection.is_closed() {
        return Err("an oversized header list closed the whole connection".into());
    }

    let response = match connection
        .send_get("example.test", target()?, Vec::new())
        .await
    {
        Ok(response) => response,
        Err(error) => {
            let peer = peer.await;
            return Err(format!("sibling stream failed: {error}; peer: {peer:?}").into());
        }
    };
    if response.status() != 200 {
        return Err(format!("sibling stream returned {}", response.status()).into());
    }
    drop(response);
    drop(connection);
    peer.await??;
    Ok(())
}

async fn run_oversized_peer(
    mut stream: DuplexStream,
    limit: usize,
    advertised: Option<u32>,
) -> TestResult<()> {
    let settings = establish_baseline(&mut stream).await?;
    // The local ceiling is never advertised: the SETTINGS entry is present
    // exactly when the profile carries it, with the profile's value.
    let sent = settings
        .chunks_exact(6)
        .filter(|entry| u16::from_be_bytes([entry[0], entry[1]]) == SETTINGS_MAX_HEADER_LIST_SIZE)
        .map(|entry| u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]))
        .collect::<Vec<_>>();
    if sent != advertised.into_iter().collect::<Vec<_>>() {
        return Err(format!("client advertised MAX_HEADER_LIST_SIZE {sent:?}").into());
    }

    // Without END_STREAM the stream stays open, so the client must reset it.
    write_header_block(&mut stream, 1, &header_block(limit + 64), false).await?;
    stream.flush().await?;

    let reset = read_frame(&mut stream)
        .await?
        .ok_or("client closed instead of resetting the stream")?;
    if reset.frame_type != 0x03 || reset.stream_id != 1 {
        return Err(format!(
            "expected RST_STREAM on stream 1, got type {:#04x} on {}",
            reset.frame_type, reset.stream_id
        )
        .into());
    }
    let code = u32::from_be_bytes(reset.payload.as_slice().try_into()?);
    if code != PROTOCOL_ERROR {
        return Err(format!("RST_STREAM code {code}, expected PROTOCOL_ERROR").into());
    }

    loop {
        let frame = read_frame(&mut stream)
            .await?
            .ok_or("client closed before the sibling request")?;
        if frame.frame_type == 0x01 && frame.stream_id == 3 {
            break;
        }
    }
    write_frame(&mut stream, 0x01, END_HEADERS | END_STREAM, 3, &[0x88]).await?;
    stream.flush().await?;
    drain_without_error(&mut stream).await
}

async fn run_connection_abuse(abuse: Abuse) -> TestResult<()> {
    let (client, server) = duplex(64 * 1024);
    let peer = tokio::spawn(async move {
        let mut stream = server;
        establish_baseline(&mut stream).await?;
        abuse.write(&mut stream).await?;
        stream.flush().await?;
        expect_one_goaway(
            &mut stream,
            abuse.name(),
            ENHANCE_YOUR_CALM,
            abuse.debug_data(),
        )
        .await
    });
    let connection = Http2Connection::connect(client, &v154_http2()).await?;
    if connection
        .send_get("example.test", target()?, Vec::new())
        .await
        .is_ok()
    {
        return Err(format!("{} was accepted as a response", abuse.name()).into());
    }
    peer.await??;
    if !connection.is_closed() {
        return Err(format!("{} did not close the connection", abuse.name()).into());
    }
    Ok(())
}

/// Connection-level header-block abuse measured against the Firefox profile's
/// unadvertised 393,216-byte ceiling.
#[derive(Clone, Copy)]
enum Abuse {
    EmptyContinuations,
    CumulativeHeaderList,
    NonemptyContinuations,
}

impl Abuse {
    fn name(self) -> &'static str {
        match self {
            Self::EmptyContinuations => "Firefox empty CONTINUATION flood",
            Self::CumulativeHeaderList => "Firefox cumulative header-list abuse",
            Self::NonemptyContinuations => "Firefox nonempty CONTINUATION flood",
        }
    }

    fn debug_data(self) -> &'static [u8] {
        match self {
            Self::EmptyContinuations => b"too_many_empty_continuations",
            Self::CumulativeHeaderList => b"header_list_way_too_large",
            Self::NonemptyContinuations => b"too_many_continuations",
        }
    }

    async fn write(self, stream: &mut DuplexStream) -> TestResult<()> {
        match self {
            Self::EmptyContinuations => {
                write_frame(stream, 0x01, 0, 1, &[0x88]).await?;
                for _ in 0..17 {
                    write_frame(stream, 0x09, 0, 1, &[]).await?;
                }
            }
            Self::CumulativeHeaderList => {
                // Each five-byte block is the legal HPACK literal `x: a` (the
                // value is Huffman `a`) and costs 34 decoded bytes. The last
                // field is the first to exceed four times the ceiling.
                const HUFFMAN_FIELD: &[u8] = &[0x00, 0x01, b'x', 0x81, 0x1f];
                const FIELD_COST: usize = 34;
                const FIELDS_PER_FRAGMENT: usize = 3_000;
                let mut remaining = (4 * FIREFOX_LIMIT - STATUS_200_COST) / FIELD_COST + 1;

                write_frame(stream, 0x01, 0, 1, &[0x88]).await?;
                while remaining > 0 {
                    let count = remaining.min(FIELDS_PER_FRAGMENT);
                    write_frame(stream, 0x09, 0, 1, &HUFFMAN_FIELD.repeat(count)).await?;
                    remaining -= count;
                }
            }
            Self::NonemptyContinuations => {
                // Four times the ceiling in quarter-minimum-frame units.
                let maximum = (4 * FIREFOX_LIMIT + 12).div_ceil(FRAGMENT_LEN / 4);
                // Literal `x` with a 1,000-byte raw value spread one byte per
                // fragment, so decoded size stays far below the ceiling.
                write_frame(stream, 0x01, 0, 1, &[0x00, 0x01, b'x', 0x7f, 0xe9, 0x06]).await?;
                for _ in 0..=maximum {
                    write_frame(stream, 0x09, 0, 1, b"a").await?;
                }
            }
        }
        Ok(())
    }
}

/// Encodes `:status: 200` plus raw literals whose RFC 9113 section 6.5.2
/// header-list size is exactly `total` bytes.
fn header_block(total: usize) -> Vec<u8> {
    const NAME: &[u8] = b"x-f";
    const FIELD_OVERHEAD: usize = 3 + 32;
    const MAX_VALUE: usize = 8_192;

    let mut block = vec![0x88];
    let mut remaining = total - STATUS_200_COST;
    while remaining > 0 {
        let mut value_len = (remaining - FIELD_OVERHEAD).min(MAX_VALUE);
        let rest = remaining - FIELD_OVERHEAD - value_len;
        if rest > 0 && rest < FIELD_OVERHEAD + 1 {
            // Leave room for one more complete field.
            value_len -= FIELD_OVERHEAD + 1;
        }
        // Literal header field without indexing, new name, raw strings.
        block.push(0x00);
        block.push(NAME.len() as u8);
        block.extend_from_slice(NAME);
        encode_length(value_len, &mut block);
        block.resize(block.len() + value_len, b'a');
        remaining -= FIELD_OVERHEAD + value_len;
    }
    block
}

/// Encodes an HPACK string length with a 7-bit prefix and no Huffman flag.
fn encode_length(mut value: usize, block: &mut Vec<u8>) {
    if value < 0x7f {
        block.push(value as u8);
        return;
    }
    block.push(0x7f);
    value -= 0x7f;
    while value >= 0x80 {
        block.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    block.push(value as u8);
}

async fn write_header_block(
    stream: &mut DuplexStream,
    stream_id: u32,
    block: &[u8],
    end_stream: bool,
) -> TestResult<()> {
    let mut fragments = block.chunks(FRAGMENT_LEN).peekable();
    let mut frame_type = 0x01;
    let mut flags = if end_stream { END_STREAM } else { 0 };
    while let Some(fragment) = fragments.next() {
        if fragments.peek().is_none() {
            flags |= END_HEADERS;
        }
        write_frame(stream, frame_type, flags, stream_id, fragment).await?;
        frame_type = 0x09;
        flags = 0;
    }
    Ok(())
}

async fn drain_without_error(stream: &mut DuplexStream) -> TestResult<()> {
    while let Some(frame) = read_frame(stream).await? {
        if frame.frame_type == 0x07 && frame.payload.get(4..8) != Some(&[0, 0, 0, 0]) {
            return Err("client closed the connection with an error".into());
        }
    }
    Ok(())
}
