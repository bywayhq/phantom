use std::{
    io::Cursor,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::io::{AsyncRead, ReadBuf};

use super::{
    CLIENT_CONNECTION_PREFACE, CaptureCompletion, CaptureError, CaptureLimits,
    capture_client_frames,
};

const GENEROUS_LIMITS: CaptureLimits = CaptureLimits::new(64 * 1024, 128 * 1024, 16);

fn frame(frame_type: u8, flags: u8, raw_stream_id: u32, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= 0x00ff_ffff);
    let length = payload.len();
    let mut wire = vec![
        ((length >> 16) & 0xff) as u8,
        ((length >> 8) & 0xff) as u8,
        (length & 0xff) as u8,
        frame_type,
        flags,
    ];
    wire.extend_from_slice(&raw_stream_id.to_be_bytes());
    wire.extend_from_slice(payload);
    wire
}

fn setting(identifier: u16, value: u32) -> [u8; 6] {
    let identifier = identifier.to_be_bytes();
    let value = value.to_be_bytes();
    [
        identifier[0],
        identifier[1],
        value[0],
        value[1],
        value[2],
        value[3],
    ]
}

fn client_bytes(frames: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    let mut wire = CLIENT_CONNECTION_PREFACE.to_vec();
    for frame in frames {
        wire.extend_from_slice(&frame);
    }
    wire
}

async fn capture(
    bytes: Vec<u8>,
    completion: CaptureCompletion,
) -> Result<super::ClientFrameCapture, CaptureError> {
    let mut reader = OneByteReader::new(bytes, usize::MAX);
    capture_client_frames(
        &mut reader,
        tokio::time::Instant::now() + Duration::from_secs(1),
        GENEROUS_LIMITS,
        completion,
    )
    .await
}

struct OneByteReader {
    bytes: Cursor<Vec<u8>>,
    max_read: usize,
}

impl OneByteReader {
    fn new(bytes: Vec<u8>, max_read: usize) -> Self {
        Self {
            bytes: Cursor::new(bytes),
            max_read,
        }
    }

    fn consumed(&self) -> usize {
        usize::try_from(self.bytes.position()).unwrap_or(usize::MAX)
    }
}

impl AsyncRead for OneByteReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let start = self.consumed();
        let available = self.bytes.get_ref().len().saturating_sub(start);
        let count = available.min(buffer.remaining()).min(self.max_read);
        if count > 0 {
            buffer.put_slice(&self.bytes.get_ref()[start..start + count]);
            self.bytes.set_position((start + count) as u64);
        }
        Poll::Ready(Ok(()))
    }
}

mod capture;
mod frame_decoding;
