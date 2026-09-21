use crate::frame::{self, Frame, Kind, Reason};
use crate::frame::{
    DEFAULT_MAX_FRAME_SIZE, DEFAULT_SETTINGS_HEADER_TABLE_SIZE, MAX_MAX_FRAME_SIZE,
};
use crate::proto::Error;

use crate::hpack;
use crate::tracing;

use futures_core::Stream;

use bytes::{Buf, BytesMut};

use std::io;

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::AsyncRead;
use tokio_util::codec::FramedRead as InnerFramedRead;
use tokio_util::codec::{LengthDelimitedCodec, LengthDelimitedCodecError};

// 16 MB "sane default" taken from golang http2
const DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE: usize = 16 << 20;
// HPACK's longest Huffman code is 30 bits per decoded byte. Two six-byte
// table-size updates are the only block metadata not charged to header size.
const MAX_HPACK_ENCODED_BYTES_PER_DECODED_BYTE: usize = 4;
const HPACK_STATE_UPDATE_ALLOWANCE: usize = 12;
// Permit quarter-sized minimum frames while bounding tiny-fragment CPU work.
const CONTINUATION_FRAGMENT_BUDGET: usize = DEFAULT_MAX_FRAME_SIZE as usize / 4;
const MIN_CONTINUATION_FRAMES: usize = 16;
const MAX_CONTINUATION_FRAMES: usize = 16_384;
// Empty fragments add no HPACK input and only repeat decoder work.
const MAX_EMPTY_CONTINUATION_FRAMES: usize = 16;

#[derive(Debug)]
pub struct FramedRead<T> {
    inner: InnerFramedRead<T, LengthDelimitedCodec>,

    // hpack decoder state
    hpack: hpack::Decoder,

    max_header_list_size: usize,

    max_header_block_bytes: usize,

    max_continuation_frames: usize,

    partial: Option<Partial>,
}

/// Partially loaded headers frame
#[derive(Debug)]
struct Partial {
    /// Empty frame
    frame: Continuable,

    /// Partial header payload
    buf: BytesMut,

    header_block_bytes: usize,

    continuation_frames_count: usize,

    empty_continuation_frames_count: usize,
}

#[derive(Debug)]
enum Continuable {
    Headers(frame::Headers),
    PushPromise(frame::PushPromise),
}

impl<T> FramedRead<T> {
    pub fn new(inner: InnerFramedRead<T, LengthDelimitedCodec>) -> FramedRead<T> {
        let max_header_list_size = DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE;
        let max_header_block_bytes = calc_max_header_block_bytes(max_header_list_size);
        let max_continuation_frames = calc_max_continuation_frames(max_header_list_size);
        FramedRead {
            inner,
            hpack: hpack::Decoder::new(DEFAULT_SETTINGS_HEADER_TABLE_SIZE),
            max_header_list_size,
            max_header_block_bytes,
            max_continuation_frames,
            partial: None,
        }
    }

    pub fn get_ref(&self) -> &T {
        self.inner.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }

    /// Returns the current max frame size setting
    #[inline]
    pub fn max_frame_size(&self) -> usize {
        self.inner.decoder().max_frame_length()
    }

    /// Updates the max frame size setting.
    ///
    /// Must be within 16,384 and 16,777,215.
    #[inline]
    pub fn set_max_frame_size(&mut self, val: usize) {
        assert!(DEFAULT_MAX_FRAME_SIZE as usize <= val && val <= MAX_MAX_FRAME_SIZE as usize);
        self.inner.decoder_mut().set_max_frame_length(val);
    }

    /// Update the max header list size setting.
    #[inline]
    pub fn set_max_header_list_size(&mut self, val: usize) {
        self.max_header_list_size = val;
        self.max_header_block_bytes = calc_max_header_block_bytes(val);
        self.max_continuation_frames = calc_max_continuation_frames(val);
    }

    /// Update the header table size setting.
    #[inline]
    pub fn set_header_table_size(&mut self, val: usize) {
        self.hpack.queue_size_update(val);
    }
}

fn calc_max_header_block_bytes(header_max: usize) -> usize {
    header_max
        .saturating_mul(MAX_HPACK_ENCODED_BYTES_PER_DECODED_BYTE)
        .saturating_add(HPACK_STATE_UPDATE_ALLOWANCE)
}

fn calc_max_continuation_frames(header_max: usize) -> usize {
    calc_max_header_block_bytes(header_max)
        .div_ceil(CONTINUATION_FRAGMENT_BUDGET)
        .clamp(MIN_CONTINUATION_FRAMES, MAX_CONTINUATION_FRAMES)
}

/// Decodes a frame.
///
/// This method is intentionally de-generified and outlined because it is very large.
fn decode_frame(
    hpack: &mut hpack::Decoder,
    max_header_list_size: usize,
    max_header_block_bytes: usize,
    max_continuation_frames: usize,
    partial_inout: &mut Option<Partial>,
    mut bytes: BytesMut,
) -> Result<Option<Frame>, Error> {
    let _span = tracing::trace_span!("FramedRead::decode_frame", offset = bytes.len());

    tracing::trace!("decoding frame from {}B", bytes.len());

    // Parse the head
    let head = frame::Head::parse(&bytes);

    if partial_inout.is_some() && head.kind() != Kind::Continuation {
        proto_err!(conn: "expected CONTINUATION, got {:?}", head.kind());
        return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
    }

    let kind = head.kind();

    tracing::trace!(frame.kind = ?kind);

    macro_rules! header_block {
        ($frame:ident, $head:ident, $bytes:ident) => ({
            // Drop the frame header
            $bytes.advance(frame::HEADER_LEN);

            // Parse the header frame w/o parsing the payload
            let (mut frame, mut payload) = match frame::$frame::load($head, $bytes) {
                Ok(res) => res,
                Err(frame::Error::InvalidDependencyId) => {
                    proto_err!(stream: "invalid HEADERS dependency ID");
                    // A stream cannot depend on itself. An endpoint MUST
                    // treat this as a stream error (Section 5.4.2) of type
                    // `PROTOCOL_ERROR`.
                    return Err(Error::library_reset($head.stream_id(), Reason::PROTOCOL_ERROR));
                },
                Err(_e) => {
                    proto_err!(conn: "failed to load frame; err={:?}", _e);
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            };

            let is_end_headers = frame.is_end_headers();
            let header_block_bytes = payload.len();
            if header_block_bytes > max_header_block_bytes {
                tracing::debug!("header_block_too_large, max = {}", max_header_block_bytes);
                return Err(Error::library_go_away_data(
                    Reason::ENHANCE_YOUR_CALM,
                    "header_block_too_large",
                ));
            }

            // Load the HPACK encoded headers
            match frame.load_hpack(&mut payload, max_header_list_size, hpack) {
                Ok(_) => {},
                Err(frame::Error::Hpack(hpack::DecoderError::NeedMore(_))) if !is_end_headers => {},
                Err(frame::Error::MalformedMessage) => {
                    let id = $head.stream_id();
                    proto_err!(stream: "malformed header block; stream={:?}", id);
                    return Err(Error::library_reset(id, Reason::PROTOCOL_ERROR));
                },
                Err(frame::Error::HeaderListWayTooLarge) => {
                    proto_err!(conn: "decoded header list size over abuse limit");
                    return Err(Error::library_go_away_data(
                        Reason::ENHANCE_YOUR_CALM,
                        "header_list_way_too_large",
                    ));
                },
                Err(frame::Error::Hpack(_e)) => {
                    proto_err!(conn: "failed HPACK decoding; err={:?}", _e);
                    return Err(Error::library_go_away(Reason::COMPRESSION_ERROR));
                },
                Err(_e) => {
                    proto_err!(conn: "failed HPACK decoding; err={:?}", _e);
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            }

            if is_end_headers {
                frame.into()
            } else {
                tracing::trace!("loaded partial header block");
                // Defer returning the frame
                *partial_inout = Some(Partial {
                    frame: Continuable::$frame(frame),
                    buf: payload,
                    header_block_bytes,
                    continuation_frames_count: 0,
                    empty_continuation_frames_count: 0,
                });

                return Ok(None);
            }
        });
    }

    let frame = match kind {
        Kind::Settings => {
            let res = frame::Settings::load(head, &bytes[frame::HEADER_LEN..]);

            res.map_err(|error| {
                proto_err!(conn: "failed to load SETTINGS frame; err={:?}", error);
                let reason = match error {
                    frame::Error::InvalidPayloadLength
                    | frame::Error::InvalidPayloadAckSettings => Reason::FRAME_SIZE_ERROR,
                    _ => Reason::PROTOCOL_ERROR,
                };
                Error::library_go_away(reason)
            })?
            .into()
        }
        Kind::Ping => {
            let res = frame::Ping::load(head, &bytes[frame::HEADER_LEN..]);

            res.map_err(|error| {
                proto_err!(conn: "failed to load PING frame; err={:?}", error);
                let reason = match error {
                    frame::Error::BadFrameSize => Reason::FRAME_SIZE_ERROR,
                    _ => Reason::PROTOCOL_ERROR,
                };
                Error::library_go_away(reason)
            })?
            .into()
        }
        Kind::WindowUpdate => {
            let res = frame::WindowUpdate::load(head, &bytes[frame::HEADER_LEN..]);

            res.map_err(|_e| {
                proto_err!(conn: "failed to load WINDOW_UPDATE frame; err={:?}", _e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::Data => {
            bytes.advance(frame::HEADER_LEN);
            let res = frame::Data::load(head, bytes.freeze());

            // TODO: Should this always be connection level? Probably not...
            res.map_err(|_e| {
                proto_err!(conn: "failed to load DATA frame; err={:?}", _e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::Headers => header_block!(Headers, head, bytes),
        Kind::Reset => {
            let res = frame::Reset::load(head, &bytes[frame::HEADER_LEN..]);
            res.map_err(|_e| {
                proto_err!(conn: "failed to load RESET frame; err={:?}", _e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::GoAway => {
            let res = frame::GoAway::load(&bytes[frame::HEADER_LEN..]);
            res.map_err(|_e| {
                proto_err!(conn: "failed to load GO_AWAY frame; err={:?}", _e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::PushPromise => header_block!(PushPromise, head, bytes),
        Kind::Priority => {
            if head.stream_id() == 0 {
                // Invalid stream identifier
                proto_err!(conn: "invalid stream ID 0");
                return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
            }

            match frame::Priority::load(head, &bytes[frame::HEADER_LEN..]) {
                Ok(frame) => frame.into(),
                Err(frame::Error::InvalidDependencyId) => {
                    // A stream cannot depend on itself. An endpoint MUST
                    // treat this as a stream error (Section 5.4.2) of type
                    // `PROTOCOL_ERROR`.
                    let id = head.stream_id();
                    proto_err!(stream: "PRIORITY invalid dependency ID; stream={:?}", id);
                    return Err(Error::library_reset(id, Reason::PROTOCOL_ERROR));
                }
                Err(_e) => {
                    proto_err!(conn: "failed to load PRIORITY frame; err={:?};", _e);
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            }
        }
        Kind::Continuation => {
            let is_end_headers = (head.flag() & 0x4) == 0x4;
            let payload_len = bytes.len() - frame::HEADER_LEN;

            let mut partial = match partial_inout.take() {
                Some(partial) => partial,
                None => {
                    proto_err!(conn: "received unexpected CONTINUATION frame");
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            };

            // The stream identifiers must match
            if partial.frame.stream_id() != head.stream_id() {
                proto_err!(conn: "CONTINUATION frame stream ID does not match previous frame stream ID");
                return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
            }

            partial.header_block_bytes = partial.header_block_bytes.saturating_add(payload_len);
            if partial.header_block_bytes > max_header_block_bytes {
                tracing::debug!("header_block_too_large, max = {}", max_header_block_bytes);
                return Err(Error::library_go_away_data(
                    Reason::ENHANCE_YOUR_CALM,
                    "header_block_too_large",
                ));
            }

            partial.continuation_frames_count += 1;
            if partial.continuation_frames_count > max_continuation_frames {
                tracing::debug!("too_many_continuations, max = {}", max_continuation_frames);
                return Err(Error::library_go_away_data(
                    Reason::ENHANCE_YOUR_CALM,
                    "too_many_continuations",
                ));
            }

            if payload_len == 0 {
                partial.empty_continuation_frames_count += 1;
                if partial.empty_continuation_frames_count > MAX_EMPTY_CONTINUATION_FRAMES {
                    tracing::debug!(
                        "too_many_empty_continuations, max = {}",
                        MAX_EMPTY_CONTINUATION_FRAMES
                    );
                    return Err(Error::library_go_away_data(
                        Reason::ENHANCE_YOUR_CALM,
                        "too_many_empty_continuations",
                    ));
                }
            }

            // Extend the buf
            if partial.buf.is_empty() {
                partial.buf = bytes.split_off(frame::HEADER_LEN);
            } else {
                if partial.frame.is_over_size() {
                    // If there was left over bytes previously, they may be
                    // needed to continue decoding, even though we will
                    // be ignoring this frame. This is done to keep the HPACK
                    // decoder state up-to-date.
                    //
                    // Still, we need to be careful, because if a malicious
                    // attacker were to try to send a gigantic string, such
                    // that it fits over multiple header blocks, we could
                    // grow memory uncontrollably again, and that'd be a shame.
                    //
                    // Instead, we use a simple heuristic to determine if
                    // we should continue to ignore decoding, or to tell
                    // the attacker to go away.
                    if partial.buf.len() + bytes.len() > max_header_list_size {
                        proto_err!(conn: "CONTINUATION frame header block size over ignorable limit");
                        return Err(Error::library_go_away(Reason::COMPRESSION_ERROR));
                    }
                }
                partial.buf.extend_from_slice(&bytes[frame::HEADER_LEN..]);
            }

            match partial
                .frame
                .load_hpack(&mut partial.buf, max_header_list_size, hpack)
            {
                Ok(_) => {}
                Err(frame::Error::Hpack(hpack::DecoderError::NeedMore(_))) if !is_end_headers => {}
                Err(frame::Error::MalformedMessage) => {
                    let id = head.stream_id();
                    proto_err!(stream: "malformed CONTINUATION frame; stream={:?}", id);
                    return Err(Error::library_reset(id, Reason::PROTOCOL_ERROR));
                }
                Err(frame::Error::HeaderListWayTooLarge) => {
                    proto_err!(conn: "decoded CONTINUATION header list size over abuse limit");
                    return Err(Error::library_go_away_data(
                        Reason::ENHANCE_YOUR_CALM,
                        "header_list_way_too_large",
                    ));
                }
                Err(frame::Error::Hpack(_e)) => {
                    proto_err!(conn: "failed HPACK decoding; err={:?}", _e);
                    return Err(Error::library_go_away(Reason::COMPRESSION_ERROR));
                }
                Err(_e) => {
                    proto_err!(conn: "failed HPACK decoding; err={:?}", _e);
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            }

            if is_end_headers {
                partial.frame.into()
            } else {
                *partial_inout = Some(partial);
                return Ok(None);
            }
        }
        Kind::AltSvc => {
            bytes.advance(frame::HEADER_LEN);
            match frame::AltSvc::load(head, bytes.freeze()) {
                Some(frame) => frame.into(),
                // RFC 7838 section 4: invalid ALTSVC frames are ignored.
                None => return Ok(None),
            }
        }
        Kind::Unknown => {
            // Unknown frames are ignored
            return Ok(None);
        }
    };

    Ok(Some(frame))
}

impl<T> Stream for FramedRead<T>
where
    T: AsyncRead + Unpin,
{
    type Item = Result<Frame, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let _span = tracing::trace_span!("FramedRead::poll_next");
        loop {
            tracing::trace!("poll");
            let bytes = match ready!(Pin::new(&mut self.inner).poll_next(cx)) {
                Some(Ok(bytes)) => bytes,
                Some(Err(e)) => return Poll::Ready(Some(Err(map_err(e)))),
                None => return Poll::Ready(None),
            };

            tracing::trace!(read.bytes = bytes.len());
            let Self {
                ref mut hpack,
                max_header_list_size,
                max_header_block_bytes,
                ref mut partial,
                max_continuation_frames,
                ..
            } = *self;
            if let Some(frame) = decode_frame(
                hpack,
                max_header_list_size,
                max_header_block_bytes,
                max_continuation_frames,
                partial,
                bytes,
            )? {
                tracing::debug!(?frame, "received");
                return Poll::Ready(Some(Ok(frame)));
            }
        }
    }
}

fn map_err(err: io::Error) -> Error {
    if let io::ErrorKind::InvalidData = err.kind() {
        if let Some(custom) = err.get_ref() {
            if custom.is::<LengthDelimitedCodecError>() {
                return Error::library_go_away(Reason::FRAME_SIZE_ERROR);
            }
        }
    }
    err.into()
}

#[cfg(test)]
mod tests {
    use super::{
        calc_max_continuation_frames, calc_max_header_block_bytes, MAX_CONTINUATION_FRAMES,
        MIN_CONTINUATION_FRAMES,
    };

    #[test]
    fn header_block_budget_covers_maximum_huffman_expansion() {
        assert_eq!(calc_max_header_block_bytes(65_536), 262_156);
        assert_eq!(calc_max_continuation_frames(65_536), 65);
        assert!(calc_max_continuation_frames(16 << 20) >= 3_585);
    }

    #[test]
    fn continuation_budget_is_bounded_for_tiny_and_huge_lists() {
        assert_eq!(calc_max_continuation_frames(0), MIN_CONTINUATION_FRAMES);
        assert_eq!(
            calc_max_continuation_frames(usize::MAX),
            MAX_CONTINUATION_FRAMES
        );
    }
}

// ===== impl Continuable =====

impl Continuable {
    fn stream_id(&self) -> frame::StreamId {
        match *self {
            Continuable::Headers(ref h) => h.stream_id(),
            Continuable::PushPromise(ref p) => p.stream_id(),
        }
    }

    fn is_over_size(&self) -> bool {
        match *self {
            Continuable::Headers(ref h) => h.is_over_size(),
            Continuable::PushPromise(ref p) => p.is_over_size(),
        }
    }

    fn load_hpack(
        &mut self,
        src: &mut BytesMut,
        max_header_list_size: usize,
        decoder: &mut hpack::Decoder,
    ) -> Result<(), frame::Error> {
        match *self {
            Continuable::Headers(ref mut h) => h.load_hpack(src, max_header_list_size, decoder),
            Continuable::PushPromise(ref mut p) => p.load_hpack(src, max_header_list_size, decoder),
        }
    }
}

impl<T> From<Continuable> for Frame<T> {
    fn from(cont: Continuable) -> Self {
        match cont {
            Continuable::Headers(mut headers) => {
                headers.set_end_headers();
                headers.into()
            }
            Continuable::PushPromise(mut push) => {
                push.set_end_headers();
                push.into()
            }
        }
    }
}
