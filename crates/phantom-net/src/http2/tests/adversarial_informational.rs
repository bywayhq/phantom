use phantom_profile::{Http2Settings, chromium::v152_http2, firefox::v154_http2};
use tokio::io::{AsyncWriteExt, DuplexStream, duplex};

use super::adversarial_malformed::{establish_baseline, read_frame, write_frame};
use super::{TestResult, bounded_peer_test, target};
use crate::http2::{Http2Connection, Http2Error};

const MAX_INFORMATIONAL: usize = 8;
const ENHANCE_YOUR_CALM: u32 = 0x0b;
// `:status: 103` as a literal without indexing using static name index 8.
const STATUS_103: &[u8] = &[0x08, 0x03, b'1', b'0', b'3'];
// `:status: 200` from the HPACK static table.
const STATUS_200: &[u8] = &[0x88];
const END_STREAM: u8 = 0x01;
const END_HEADERS: u8 = 0x04;

#[tokio::test]
async fn eight_informational_responses_precede_the_final_response() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = duplex(64 * 1024);
        let peer = tokio::spawn(async move {
            let mut stream = server;
            establish_baseline(&mut stream).await?;
            for _ in 0..MAX_INFORMATIONAL {
                write_frame(&mut stream, 0x01, END_HEADERS, 1, STATUS_103).await?;
            }
            write_frame(&mut stream, 0x01, END_HEADERS | END_STREAM, 1, STATUS_200).await?;
            stream.flush().await?;
            drain_without_reset(&mut stream).await
        });
        let connection = Http2Connection::connect(client, &v152_http2()).await?;
        let response = connection
            .send_get("example.test", target()?, Vec::new())
            .await?;
        if response.status() != 200 {
            return Err(format!("unexpected final status {}", response.status()).into());
        }
        drop(response);
        drop(connection);
        peer.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn ninth_informational_response_is_rejected_with_chrome_profile() -> TestResult<()> {
    bounded_peer_test(run_excess(v152_http2(), MAX_INFORMATIONAL + 1)).await
}

#[tokio::test]
async fn ninth_informational_response_is_rejected_with_firefox_profile() -> TestResult<()> {
    bounded_peer_test(run_excess(v154_http2(), MAX_INFORMATIONAL + 1)).await
}

#[tokio::test]
async fn informational_burst_is_cut_off_at_the_ninth_response() -> TestResult<()> {
    bounded_peer_test(run_excess(v152_http2(), 1_000)).await
}

async fn run_excess(settings: Http2Settings, sent: usize) -> TestResult<()> {
    let (client, server) = duplex(64 * 1024);
    let peer = tokio::spawn(run_excess_peer(server, sent));
    let connection = Http2Connection::connect(client, &settings).await?;

    match connection
        .send_get("example.test", target()?, Vec::new())
        .await
    {
        Err(Http2Error::TooManyInformationalResponses { maximum })
            if maximum == MAX_INFORMATIONAL => {}
        other => {
            let peer = peer.await;
            return Err(
                format!("{sent} informational responses: {other:?}; peer: {peer:?}").into(),
            );
        }
    }
    if connection.is_closed() {
        return Err("excess informational responses closed the whole connection".into());
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

async fn run_excess_peer(mut stream: DuplexStream, sent: usize) -> TestResult<()> {
    establish_baseline(&mut stream).await?;
    for _ in 0..sent {
        write_frame(&mut stream, 0x01, END_HEADERS, 1, STATUS_103).await?;
    }
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
    if code != ENHANCE_YOUR_CALM {
        return Err(format!("RST_STREAM code {code}, expected ENHANCE_YOUR_CALM").into());
    }

    loop {
        let frame = read_frame(&mut stream)
            .await?
            .ok_or("client closed before the sibling request")?;
        match (frame.frame_type, frame.stream_id) {
            (0x01, 3) => break,
            (0x03, 1) => return Err("client reset stream 1 more than once".into()),
            (0x07, _) => return Err("client closed the connection".into()),
            _ => {}
        }
    }
    write_frame(&mut stream, 0x01, END_HEADERS | END_STREAM, 3, STATUS_200).await?;
    stream.flush().await?;
    drain_without_reset(&mut stream).await
}

async fn drain_without_reset(stream: &mut DuplexStream) -> TestResult<()> {
    while let Some(frame) = read_frame(stream).await? {
        if frame.frame_type == 0x03 {
            return Err(format!("client reset stream {}", frame.stream_id).into());
        }
        if frame.frame_type == 0x07 && frame.payload.get(4..8) != Some(&[0, 0, 0, 0]) {
            return Err("client closed the connection with an error".into());
        }
    }
    Ok(())
}
