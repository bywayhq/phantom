use std::{
    sync::{Arc, Weak},
    task::{Context, Poll},
};

use bytes::Buf;

#[cfg(feature = "tracing")]
use tracing::trace;

use crate::error::Code;
use crate::proto::frame::SettingsError;
use crate::proto::push::InvalidPushId;
use crate::qpack::{
    DecoderState, ReadAheadLease as QpackReadAheadLease, RequestGuard as QpackRequestGuard,
    RuntimeError as QpackRuntimeError, Section as QpackSection,
};
use crate::quic::{InvalidStreamId, StreamErrorIncoming};
use crate::shared_state::SharedState;
use crate::stream::{BoundedRead, BufRecvStream, WriteBuf};
use crate::{
    buf::BufList,
    proto::{
        frame::{self, Frame, PayloadLen},
        stream::StreamId,
    },
    quic::{BidiStream, RecvStream, SendStream},
};

/// Decodes Frames from the underlying QUIC stream
pub struct FrameStream<S, B> {
    pub stream: BufRecvStream<S, B>,
    // Already read data from the stream
    decoder: FrameDecoder,
    remaining_data: usize,
    qpack_decoder: Option<Arc<DecoderState>>,
    shared: Weak<SharedState>,
    header_section: Option<QpackSection>,
    request_guard: Option<QpackRequestGuard>,
    read_ahead: Option<QpackReadAheadLease>,
}

// Known non-DATA frames are decoded as a complete payload. Unknown frames
// are skipped incrementally and DATA remains streaming.
const MAX_BUFFERED_FRAME_PAYLOAD: u64 = 1024 * 1024;
const MAX_FRAME_STREAM_WORK_BYTES_PER_POLL: usize = 64 * 1024;

const MAX_BUFFERED_WHILE_QPACK_BLOCKED: usize = 64 * 1024;
const MAX_QPACK_BLOCKED_READ_BYTES_PER_POLL: usize = 64 * 1024;
const MAX_REQUEST_FRAME_CHUNK_BYTES: usize =
    crate::qpack::MAX_ENCODED_FIELD_SECTION_BYTES + MAX_BUFFERED_WHILE_QPACK_BLOCKED + 16;

impl<S, B> FrameStream<S, B> {
    pub fn new(stream: BufRecvStream<S, B>) -> Self {
        Self {
            stream,
            decoder: FrameDecoder::default(),
            remaining_data: 0,
            qpack_decoder: None,
            shared: Weak::new(),
            header_section: None,
            request_guard: None,
            read_ahead: None,
        }
    }

    pub(crate) fn new_request(
        stream: BufRecvStream<S, B>,
        qpack_decoder: Arc<DecoderState>,
        shared: &Arc<SharedState>,
    ) -> Result<Self, QpackRuntimeError>
    where
        S: RecvStream,
    {
        let request_guard =
            qpack_decoder.begin_request(Arc::downgrade(shared), stream.recv_id().into_inner())?;
        Ok(Self {
            stream,
            decoder: FrameDecoder::default(),
            remaining_data: 0,
            qpack_decoder: Some(qpack_decoder),
            shared: Arc::downgrade(shared),
            header_section: None,
            request_guard: Some(request_guard),
            read_ahead: None,
        })
    }

    /// Returns the underlying stream and buffered bytes not yet consumed.
    ///
    /// Decoder state, including a partially skipped unknown frame's remaining
    /// length, is not returned. Bytes already discarded stay discarded.
    pub fn into_inner(self) -> BufRecvStream<S, B> {
        self.stream
    }
}

impl<S, B> FrameStream<S, B>
where
    S: crate::quic::Is0rtt,
{
    /// Checks if the stream was opened in 0-RTT mode
    pub(crate) fn is_0rtt(&self) -> bool {
        self.stream.is_0rtt()
    }
}

impl<S, B> FrameStream<S, B>
where
    S: RecvStream,
{
    /// Polls the stream for the next frame header
    ///
    /// When a frame header is received use `poll_data` to retrieve the frame's data.
    pub fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Frame<PayloadLen>>, FrameStreamError>> {
        self.release_drained_read_ahead();
        assert!(
            self.remaining_data == 0,
            "There is still data to read, please call poll_data() until it returns None."
        );

        let mut processed: usize = 0;
        loop {
            if self.header_section.is_none() && self.decoder.remaining_unknown == 0 {
                if let Some(qpack_decoder) = self.qpack_decoder.as_ref() {
                    let header_len = {
                        let mut cursor = self.stream.buf_mut().cursor();
                        Frame::headers_payload_len(&mut cursor)
                    };
                    match header_len {
                        Ok(Some(encoded_bytes)) => {
                            self.header_section = Some(
                                qpack_decoder
                                    .reserve(
                                        self.shared.clone(),
                                        self.stream.recv_id().into_inner(),
                                        encoded_bytes,
                                    )
                                    .map_err(qpack_resource_error)?,
                            );
                        }
                        Ok(None) | Err(frame::FrameError::Incomplete(_)) => {}
                        Err(frame::FrameError::ExcessiveLoad(size)) => {
                            return Poll::Ready(Err(FrameStreamError::ExcessiveLoad(format!(
                                "frame payload length {size} is not representable"
                            ))));
                        }
                        Err(_) => {}
                    }
                }
            }

            let before = self.stream.buf().remaining();
            let decoded = self.decoder.decode(self.stream.buf_mut())?;
            processed = processed.saturating_add(before - self.stream.buf().remaining());
            match decoded {
                Some(Frame::Data(PayloadLen(len))) => {
                    self.remaining_data = len;
                    return Poll::Ready(Ok(Some(Frame::Data(PayloadLen(len)))));
                }
                frame @ Some(Frame::WebTransportStream(_)) => {
                    self.remaining_data = usize::MAX;
                    return Poll::Ready(Ok(frame));
                }
                Some(frame) => return Poll::Ready(Ok(Some(frame))),
                None => {}
            }

            if processed >= MAX_FRAME_STREAM_WORK_BYTES_PER_POLL {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if self.decoder.expected.is_none() && self.stream.buf().has_remaining() {
                continue;
            }

            let before = self.stream.buf().remaining();
            match self.try_recv_frame(cx)? {
                // Account for reads as well as skipped bytes while frames are incomplete.
                Poll::Ready(false) => {
                    processed = processed.saturating_add(self.stream.buf().remaining() - before);
                    if processed >= MAX_FRAME_STREAM_WORK_BYTES_PER_POLL {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(true) => {
                    if self.stream.buf_mut().has_remaining() || self.decoder.remaining_unknown != 0
                    {
                        // Reached the end of receive stream, but there is still some data:
                        // The frame is incomplete.
                        return Poll::Ready(Err(FrameStreamError::UnexpectedEnd));
                    } else {
                        return Poll::Ready(Ok(None));
                    }
                }
            }
        }
    }

    /// Retrieves the next piece of data in an incoming data packet or webtransport stream
    ///
    ///
    /// WebTransport bidirectional payload has no finite length and is processed until the end of the stream.
    pub fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<impl Buf>, FrameStreamError>> {
        if self.remaining_data == 0 {
            return Poll::Ready(Ok(None));
        };

        let end = match self.try_recv(cx) {
            Poll::Ready(Ok(end)) => end,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => false,
        };
        let data = self.stream.buf_mut().take_chunk(self.remaining_data);
        self.release_drained_read_ahead();

        match (data, end) {
            (None, true) => Poll::Ready(Ok(None)),
            (None, false) => Poll::Pending,
            (Some(d), true)
                if d.remaining() < self.remaining_data
                    && !self.stream.buf_mut().has_remaining() =>
            {
                Poll::Ready(Err(FrameStreamError::UnexpectedEnd))
            }
            (Some(d), _) => {
                self.remaining_data -= d.remaining();
                Poll::Ready(Ok(Some(d)))
            }
        }
    }

    /// Stops the underlying stream with the provided error code
    pub(crate) fn stop_sending(&mut self, error_code: Code) {
        self.stream.stop_sending(error_code.into());
        self.cancel_request();
    }

    pub(crate) fn has_data(&self) -> bool {
        self.remaining_data != 0
    }

    pub(crate) fn take_ignored_unknown(&mut self) -> bool {
        self.decoder.take_ignored_unknown()
    }

    pub(crate) fn is_eos(&self) -> bool {
        self.stream.is_eos() && !self.stream.buf().has_remaining()
    }

    pub(crate) fn take_header_section(&mut self) -> Option<QpackSection> {
        self.header_section.take()
    }

    pub(crate) fn put_header_section(&mut self, section: QpackSection) {
        debug_assert!(self.header_section.is_none());
        self.header_section = Some(section);
    }

    pub(crate) fn cancel_header_section(&mut self) {
        if let Some(mut section) = self.header_section.take() {
            section.cancel();
        }
    }

    pub(crate) fn cancel_request(&mut self) {
        self.cancel_header_section();
        if let Some(mut guard) = self.request_guard.take() {
            guard.cancel();
        }
        self.release_drained_read_ahead();
    }

    pub(crate) fn complete_request(&mut self) {
        self.cancel_header_section();
        if let Some(mut guard) = self.request_guard.take() {
            guard.complete();
        }
        self.read_ahead = None;
    }

    pub(crate) fn poll_while_qpack_blocked(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), FrameStreamError>> {
        if self.header_section.is_none() {
            return Poll::Ready(Err(FrameStreamError::ExcessiveLoad(
                "blocked QPACK section lost its reservation".to_string(),
            )));
        }
        if self.read_ahead.is_none() {
            let decoder = self.qpack_decoder.as_ref().ok_or_else(|| {
                FrameStreamError::ExcessiveLoad(
                    "blocked QPACK section lost its decoder state".to_string(),
                )
            })?;
            self.read_ahead = Some(
                decoder
                    .reserve_read_ahead(MAX_BUFFERED_WHILE_QPACK_BLOCKED)
                    .map_err(qpack_resource_error)?,
            );
        }

        let mut received: usize = 0;
        loop {
            if self.stream.buf_mut().remaining() > MAX_BUFFERED_WHILE_QPACK_BLOCKED {
                return Poll::Ready(Err(FrameStreamError::ExcessiveLoad(
                    "buffered response bytes exceeded the blocked QPACK limit".to_string(),
                )));
            }
            if self.stream.is_eos() {
                return Poll::Pending;
            }

            let before = self.stream.buf_mut().remaining();
            match self
                .stream
                .poll_read_bounded(cx, MAX_BUFFERED_WHILE_QPACK_BLOCKED)
            {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(FrameStreamError::Quic(error))),
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(BoundedRead::End)) => return Poll::Pending,
                Poll::Ready(Ok(BoundedRead::Read)) => {}
                Poll::Ready(Ok(BoundedRead::LimitExceeded)) => {
                    return Poll::Ready(Err(FrameStreamError::ExcessiveLoad(
                        "buffered response bytes exceeded the blocked QPACK limit".to_string(),
                    )))
                }
            }
            let after = self.stream.buf_mut().remaining();
            received = received.saturating_add(after.saturating_sub(before));
            if received >= MAX_QPACK_BLOCKED_READ_BYTES_PER_POLL {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
    }

    fn try_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, FrameStreamError>> {
        if self.stream.is_eos() {
            return Poll::Ready(Ok(true));
        }
        match self.stream.poll_read(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(FrameStreamError::Quic(e))),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(eos)) => Poll::Ready(Ok(eos)),
        }
    }

    fn release_drained_read_ahead(&mut self) {
        if !self.stream.buf().has_remaining() {
            self.read_ahead = None;
        }
    }

    fn try_recv_frame(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, FrameStreamError>> {
        if self.qpack_decoder.is_none() {
            return self.try_recv(cx);
        }
        if self.stream.is_eos() {
            return Poll::Ready(Ok(true));
        }
        match self
            .stream
            .poll_read_bounded(cx, MAX_REQUEST_FRAME_CHUNK_BYTES)
        {
            Poll::Ready(Err(error)) => Poll::Ready(Err(FrameStreamError::Quic(error))),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(BoundedRead::End)) => Poll::Ready(Ok(true)),
            Poll::Ready(Ok(BoundedRead::Read)) => Poll::Ready(Ok(false)),
            Poll::Ready(Ok(BoundedRead::LimitExceeded)) => {
                Poll::Ready(Err(FrameStreamError::ExcessiveLoad(
                    "request-stream transport chunk exceeded the frame buffer limit".to_string(),
                )))
            }
        }
    }

    pub fn id(&self) -> StreamId {
        self.stream.recv_id()
    }
}

impl<T, B> SendStream<B> for FrameStream<T, B>
where
    T: SendStream<B>,
    B: Buf,
{
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.stream.poll_ready(cx)
    }

    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        self.stream.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.stream.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.stream.reset(reset_code)
    }

    fn send_id(&self) -> StreamId {
        self.stream.send_id()
    }
}

impl<S, B> FrameStream<S, B>
where
    S: BidiStream<B>,
    B: Buf,
{
    pub(crate) fn split(self) -> (FrameStream<S::SendStream, B>, FrameStream<S::RecvStream, B>) {
        let (send, recv) = self.stream.split();
        (
            FrameStream {
                stream: send,
                decoder: FrameDecoder::default(),
                remaining_data: 0,
                qpack_decoder: None,
                shared: Weak::new(),
                header_section: None,
                request_guard: None,
                read_ahead: None,
            },
            FrameStream {
                stream: recv,
                decoder: self.decoder,
                remaining_data: self.remaining_data,
                qpack_decoder: self.qpack_decoder,
                shared: self.shared,
                header_section: self.header_section,
                request_guard: self.request_guard,
                read_ahead: self.read_ahead,
            },
        )
    }
}

#[derive(Default)]
pub struct FrameDecoder {
    expected: Option<usize>,
    ignored_unknown: bool,
    remaining_unknown: u64,
}

impl FrameDecoder {
    fn decode<B: Buf>(
        &mut self,
        src: &mut BufList<B>,
    ) -> Result<Option<Frame<PayloadLen>>, FrameStreamError> {
        // Unknown frames return control to `FrameStream` so it can reserve a
        // following HEADERS section before decoding it.
        if !src.has_remaining() {
            return Ok(None);
        }
        if self.remaining_unknown != 0 {
            self.skip_unknown(src);
            return Ok(None);
        }

        if let Some(min) = self.expected {
            if src.remaining() < min {
                return Ok(None);
            }
        }

        let header = {
            let mut cur = src.cursor();
            Frame::decode_header(&mut cur).map(|(ty, len)| (cur.position(), ty, len))
        };
        if let Ok((header_len, ty, Some(len))) = header {
            if ty.is_unknown() {
                // Preserve the full varint length even on 32-bit targets. Only
                // available payload bytes are discarded, never the next frame.
                src.advance(header_len);
                self.expected = None;
                self.ignored_unknown = true;
                self.remaining_unknown = len;
                self.skip_unknown(src);
                return Ok(None);
            }
            if ty != frame::FrameType::DATA
                && !ty.is_forbidden()
                && len > MAX_BUFFERED_FRAME_PAYLOAD
            {
                return Err(FrameStreamError::ExcessiveLoad(format!(
                    "frame payload length {len} exceeds the buffered frame limit"
                )));
            }
        }

        let (pos, decoded) = {
            let mut cur = src.cursor();
            let decoded = Frame::decode(&mut cur);
            (cur.position(), decoded)
        };

        match decoded {
            Err(frame::FrameError::UnknownFrame(_ty)) => {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
                //# Frames of unknown types (Section 9), including reserved frames
                //# (Section 7.2.8) MAY be sent on a request or push stream before,
                //# after, or interleaved with other frames described in this section.
                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.8
                //# Endpoints MUST
                //# NOT consider these frames to have any meaning upon receipt.
                #[cfg(feature = "tracing")]
                trace!("ignore unknown frame type {:#x}", _ty);

                src.advance(pos);
                self.expected = None;
                self.ignored_unknown = true;
                Ok(None)
            }
            Err(frame::FrameError::Incomplete(min)) => {
                self.expected = Some(min);
                Ok(None)
            }
            Ok(frame) => {
                src.advance(pos);
                self.expected = None;
                Ok(Some(frame))
            }
            // -------------- Map the error Values --------------
            Err(frame::FrameError::InvalidStreamId(e)) => Err(FrameStreamError::Proto(
                FrameProtocolError::InvalidStreamId(e),
            )),
            Err(frame::FrameError::InvalidPushId(e)) => Err(FrameStreamError::Proto(
                FrameProtocolError::InvalidPushId(e),
            )),
            Err(frame::FrameError::Settings(e)) => {
                Err(FrameStreamError::Proto(FrameProtocolError::Settings(e)))
            }
            Err(frame::FrameError::UnsupportedFrame(ty)) => Err(FrameStreamError::Proto(
                FrameProtocolError::ForbiddenFrame(ty),
            )),
            Err(frame::FrameError::InvalidFrameValue) => Err(FrameStreamError::Proto(
                FrameProtocolError::InvalidFrameValue,
            )),
            Err(frame::FrameError::ExcessiveLoad(size)) => Err(FrameStreamError::ExcessiveLoad(
                format!("frame payload length {size} is not representable"),
            )),
            Err(frame::FrameError::Malformed) => {
                Err(FrameStreamError::Proto(FrameProtocolError::Malformed))
            }
        }
    }

    fn skip_unknown<B: Buf>(&mut self, src: &mut BufList<B>) {
        let available = src.remaining().min(MAX_FRAME_STREAM_WORK_BYTES_PER_POLL);
        let consumed = self.remaining_unknown.min(available as u64) as usize;
        src.advance(consumed);
        self.remaining_unknown -= consumed as u64;
    }

    fn take_ignored_unknown(&mut self) -> bool {
        std::mem::take(&mut self.ignored_unknown)
    }
}

#[derive(Debug)]
/// Errors that can occur while decoding frames
pub enum FrameStreamError {
    Proto(FrameProtocolError),
    Quic(StreamErrorIncoming),
    UnexpectedEnd,
    ExcessiveLoad(String),
}

#[derive(Debug, PartialEq)]
/// Protocol specific errors that can occur while decoding frames in a stream
pub enum FrameProtocolError {
    Malformed,
    ForbiddenFrame(u64), // Known (http2) frames that should generate an error
    InvalidFrameValue,
    Settings(SettingsError),
    InvalidStreamId(InvalidStreamId),
    InvalidPushId(InvalidPushId),
}

fn qpack_resource_error(error: QpackRuntimeError) -> FrameStreamError {
    FrameStreamError::ExcessiveLoad(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    use assert_matches::assert_matches;
    use bytes::{BufMut, Bytes, BytesMut};
    use futures_util::{future::poll_fn, task::noop_waker_ref};
    use std::{cell::Cell, collections::VecDeque, rc::Rc};

    use crate::proto::{coding::Encode, frame::FrameType, varint::VarInt};

    // Decoder

    #[test]
    fn one_frame() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers(&b"salut"[..]).encode_with_payload(&mut buf);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn incomplete_frame() {
        let frame = Frame::headers(&b"salut"[..]);

        let mut buf = BytesMut::with_capacity(16);
        frame.encode(&mut buf);
        buf.truncate(buf.len() - 1);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(None));
    }

    #[test]
    fn header_spread_multiple_buf() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers(&b"salut"[..]).encode_with_payload(&mut buf);
        let mut buf_list = BufList::new();
        // Cut buffer between type and length
        buf_list.push(&buf[..1]);
        buf_list.push(&buf[1..]);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf_list), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn varint_spread_multiple_buf() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers("salut".repeat(1024)).encode_with_payload(&mut buf);

        let mut buf_list = BufList::new();
        // Cut buffer in the middle of length's varint
        buf_list.push(&buf[..2]);
        buf_list.push(&buf[2..]);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf_list), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn two_frames_then_incomplete() {
        let mut buf = BytesMut::with_capacity(64);
        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        Frame::Data(&b"body"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);

        buf.truncate(buf.len() - 1);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(Some(Frame::Headers(_))));
        assert_matches!(
            decoder.decode(&mut buf),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_matches!(decoder.decode(&mut buf), Ok(None));
    }

    // FrameStream

    macro_rules! assert_poll_matches {
        ($poll_fn:expr, $match:pat) => {
            assert_matches!(
                poll_fn($poll_fn).await,
                $match
            );
        };
        ($poll_fn:expr, $match:pat if $cond:expr ) => {
            assert_matches!(
                poll_fn($poll_fn).await,
                $match if $cond
            );
        }
    }

    #[tokio::test]
    async fn poll_full_request() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        Frame::Data(&b"body"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);
        recv.chunk(buf.freeze());

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 4
        );
        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
    }

    #[tokio::test]
    async fn poll_next_applies_backpressure_before_reading_more_chunks() {
        const CHUNK_COUNT: usize = 64;
        const FRAMES_PER_CHUNK: usize = 16;
        const FRAME_PAYLOAD_SIZE: usize = 1024;

        let mut encoded_chunk = BytesMut::new();
        let payload = Bytes::from(vec![0_u8; FRAME_PAYLOAD_SIZE]);
        for _ in 0..FRAMES_PER_CHUNK {
            Frame::headers(payload.clone()).encode_with_payload(&mut encoded_chunk);
        }
        let encoded_chunk = encoded_chunk.freeze();
        let max_buffered = encoded_chunk.len();

        let mut recv = FakeRecv::default();
        for _ in 0..CHUNK_COUNT {
            recv.chunk(encoded_chunk.clone());
        }
        let transport_polls = recv.poll_count.clone();

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        // Model a consumer that processes one frame per wake while the
        // transport can provide chunks containing many complete frames.
        for _ in 0..CHUNK_COUNT {
            assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
        }

        let buffered = stream.stream.buf().remaining();
        assert!(
            buffered <= max_buffered,
            "frame buffering grew past one transport chunk: {buffered} > {max_buffered}"
        );
        assert_eq!(
            transport_polls.get(),
            CHUNK_COUNT.div_ceil(FRAMES_PER_CHUNK),
            "transport was polled while complete frames were still buffered"
        );
    }

    #[tokio::test]
    async fn oversized_headers_are_rejected_from_declared_length() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::new();
        FrameType::HEADERS.encode(&mut buf);
        VarInt::try_from((crate::qpack::MAX_ENCODED_FIELD_SECTION_BYTES + 1) as u64)
            .unwrap()
            .encode(&mut buf);
        recv.chunk(buf.freeze());

        let decoder = DecoderState::new(64, u64::MAX, 1).unwrap();
        let shared = Arc::new(SharedState::default());
        let mut stream: FrameStream<_, ()> =
            FrameStream::new_request(BufRecvStream::new(recv), decoder, &shared).unwrap();

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Err(FrameStreamError::ExcessiveLoad(reason))
                if reason.contains("encoded field section")
        );
    }

    #[tokio::test]
    async fn cancellation_releases_empty_read_ahead_while_stream_is_retained() {
        let encoded = Bytes::from_static(&[0x02, 0x80, 0xd9, 0x10]);
        let mut wire = BytesMut::new();
        let mut frame: Frame<Bytes> = Frame::Headers(encoded.clone());
        frame.encode_with_payload(&mut wire);
        let mut recv = FakeRecv::default();
        recv.chunk(wire.freeze());

        let decoder = DecoderState::new(64, u64::MAX, 1).unwrap();
        let shared = Arc::new(SharedState::default());
        let mut stream: FrameStream<_, ()> =
            FrameStream::new_request(BufRecvStream::new(recv), Arc::clone(&decoder), &shared)
                .unwrap();
        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));

        let mut section = stream.take_header_section().unwrap();
        let cx = Context::from_waker(noop_waker_ref());
        assert!(matches!(
            section.poll_decode(&encoded, &cx),
            Ok(crate::qpack::DecodeStatus::Blocked)
        ));
        stream.put_header_section(section);
        let mut cx = Context::from_waker(noop_waker_ref());
        assert!(stream.poll_while_qpack_blocked(&mut cx).is_pending());
        assert_eq!(
            decoder.reserved_bytes(),
            encoded.len() + MAX_BUFFERED_WHILE_QPACK_BLOCKED
        );

        stream.cancel_request();
        assert_eq!(decoder.reserved_bytes(), 0);
        assert_eq!(decoder.take_feedback(), &b"\x40"[..]);

        // The stream remains alive, proving release is tied to the empty
        // buffer rather than handle destruction.
        assert!(stream.request_guard.is_none());
    }

    #[tokio::test]
    async fn poll_next_incomplete_frame() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        let mut buf = buf.freeze();
        recv.chunk(buf.split_to(buf.len() - 1));
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    #[tokio::test]
    #[should_panic(
        expected = "There is still data to read, please call poll_data() until it returns None"
    )]
    async fn poll_next_reamining_data() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        // There is still data to consume, poll_next should panic
        let _ = poll_fn(|cx| stream.poll_next(cx)).await;
    }

    #[tokio::test]
    async fn poll_data_split() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // Body is split into two bufs
        Frame::Data(Bytes::from("body")).encode_with_payload(&mut buf);

        let mut buf = buf.freeze();
        recv.chunk(buf.split_to(buf.len() - 2));
        recv.chunk(buf);
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        // We get the total size of data about to be received
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        // Then we get parts of body, chunked as they arrived
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 2
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 2
        );
    }

    #[tokio::test]
    async fn poll_data_unexpected_end() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // Truncated body
        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        buf.put_slice(&b"b"[..]);
        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    #[tokio::test]
    async fn poll_data_ignores_unknown_frames() {
        use crate::proto::varint::BufMutExt as _;

        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // grease a lil
        crate::proto::frame::FrameType::grease().encode(&mut buf);
        buf.write_var(0);

        // grease with some data
        crate::proto::frame::FrameType::grease().encode(&mut buf);
        buf.write_var(6);
        buf.put_slice(b"grease");

        // Body
        Frame::Data(Bytes::from("body")).encode_with_payload(&mut buf);

        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"body"
        );
    }

    #[tokio::test]
    async fn poll_data_eos_but_buffered_data() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        buf.put_slice(&b"bo"[..]);
        recv.chunk(buf.clone().freeze());

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        buf.truncate(0);
        buf.put_slice(&b"dy"[..]);
        stream.stream.buf_mut().push_bytes(&mut buf.freeze());

        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"bo"
        );

        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"dy"
        );
    }

    /// A peer that pauses instead of reporting EOF when its chunks run out.
    /// Tests add chunks between direct polls of the real frame decoder.
    struct PausedControlRecv {
        chunks: Rc<std::cell::RefCell<VecDeque<Bytes>>>,
    }

    impl RecvStream for PausedControlRecv {
        type Buf = Bytes;

        fn poll_data(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
            match self.chunks.borrow_mut().pop_front() {
                Some(bytes) => Poll::Ready(Ok(Some(bytes))),
                None => Poll::Pending,
            }
        }

        fn stop_sending(&mut self, _code: u64) {}

        fn recv_id(&self) -> StreamId {
            StreamId(3)
        }
    }

    const CONTROL_PAYLOAD_LEN: u32 = 2 * 1024 * 1024;
    const CONTROL_CHUNK_LEN: usize = 16 * 1024;

    fn unknown_control_prefix(length: u32) -> Bytes {
        let mut prefix = BytesMut::new();
        // SETTINGS is first on the actual control stream, followed by a
        // reserved frame whose payload has no HTTP/3 meaning.
        prefix.extend_from_slice(&[0x04, 0x00]);
        VarInt::from(0x21_u32).encode(&mut prefix);
        VarInt::from(length).encode(&mut prefix);
        prefix.freeze()
    }

    #[test]
    fn partial_unknown_control_frame_does_not_retain_payload() {
        let chunks = Rc::new(std::cell::RefCell::new(VecDeque::new()));
        chunks
            .borrow_mut()
            .push_back(unknown_control_prefix(CONTROL_PAYLOAD_LEN));
        let recv = PausedControlRecv {
            chunks: Rc::clone(&chunks),
        };
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
        let mut cx = Context::from_waker(noop_waker_ref());
        assert_matches!(
            stream.poll_next(&mut cx),
            Poll::Ready(Ok(Some(Frame::Settings(_))))
        );

        // Only half the announced payload arrives. Each chunk owns its own
        // allocation, so retained BufList bytes correspond to retained data.
        for _ in 0..CONTROL_PAYLOAD_LEN as usize / CONTROL_CHUNK_LEN / 2 {
            chunks
                .borrow_mut()
                .push_back(Bytes::from(vec![0; CONTROL_CHUNK_LEN]));
            assert!(stream.poll_next(&mut cx).is_pending());
            assert_eq!(
                stream.stream.buf().remaining(),
                0,
                "unknown payload was retained"
            );
        }
    }

    #[test]
    fn fragmented_unknown_control_frame_preserves_following_goaway() {
        let chunks = Rc::new(std::cell::RefCell::new(VecDeque::new()));
        chunks
            .borrow_mut()
            .push_back(unknown_control_prefix(CONTROL_PAYLOAD_LEN));
        let recv = PausedControlRecv {
            chunks: Rc::clone(&chunks),
        };
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
        let mut cx = Context::from_waker(noop_waker_ref());
        assert_matches!(
            stream.poll_next(&mut cx),
            Poll::Ready(Ok(Some(Frame::Settings(_))))
        );

        for _ in 0..CONTROL_PAYLOAD_LEN as usize / CONTROL_CHUNK_LEN - 1 {
            chunks
                .borrow_mut()
                .push_back(Bytes::from(vec![0; CONTROL_CHUNK_LEN]));
            assert!(stream.poll_next(&mut cx).is_pending());
        }
        // Final unknown payload bytes and the next frame share one chunk.
        let mut final_chunk = vec![0; CONTROL_CHUNK_LEN];
        final_chunk.extend_from_slice(&[0x07, 0x01, 0x00]);
        chunks.borrow_mut().push_back(Bytes::from(final_chunk));
        assert_matches!(stream.poll_next(&mut cx), Poll::Ready(Ok(Some(Frame::Goaway(id)))) if id.into_inner() == 0);
        assert!(stream.poll_next(&mut cx).is_pending());
        assert_eq!(stream.stream.buf().remaining(), 0);
    }

    #[test]
    fn oversized_settings_payload_is_rejected_before_buffering() {
        let mut prefix = BytesMut::new();
        FrameType::SETTINGS.encode(&mut prefix);
        VarInt::from(CONTROL_PAYLOAD_LEN).encode(&mut prefix);
        let chunks = Rc::new(std::cell::RefCell::new(VecDeque::from([prefix.freeze()])));
        let recv = PausedControlRecv { chunks };
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
        let mut cx = Context::from_waker(noop_waker_ref());
        assert_matches!(
            stream.poll_next(&mut cx),
            Poll::Ready(Err(FrameStreamError::ExcessiveLoad(_)))
        );
    }

    #[test]
    fn fragmented_unknown_header_preserves_the_full_varint_length() {
        let chunks = Rc::new(std::cell::RefCell::new(VecDeque::new()));
        let recv = PausedControlRecv {
            chunks: Rc::clone(&chunks),
        };
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
        let mut cx = Context::from_waker(noop_waker_ref());
        let mut prefix = BytesMut::new();
        VarInt::MAX.encode(&mut prefix);
        VarInt::MAX.encode(&mut prefix);
        for byte in prefix.iter().copied() {
            chunks.borrow_mut().push_back(Bytes::from(vec![byte]));
            assert!(stream.poll_next(&mut cx).is_pending());
        }
        assert_eq!(stream.decoder.remaining_unknown, VarInt::MAX.into_inner());
        assert_eq!(stream.stream.buf().remaining(), 0);
        assert!(stream.take_ignored_unknown());
        chunks
            .borrow_mut()
            .push_back(Bytes::from_static(b"discard"));
        assert!(stream.poll_next(&mut cx).is_pending());
        assert_eq!(
            stream.decoder.remaining_unknown,
            VarInt::MAX.into_inner() - 7
        );
        assert_eq!(stream.stream.buf().remaining(), 0);
    }

    #[test]
    fn incomplete_unknown_payload_eof_is_a_frame_error() {
        let mut recv = FakeRecv::default();
        recv.chunk(Bytes::from_static(&[0x21, 0x02, 0x00]));
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
        let mut cx = Context::from_waker(noop_waker_ref());
        assert_matches!(
            stream.poll_next(&mut cx),
            Poll::Ready(Err(FrameStreamError::UnexpectedEnd))
        );
        assert_eq!(stream.stream.buf().remaining(), 0);
        assert_eq!(stream.decoder.remaining_unknown, 1);
    }

    #[test]
    fn unknown_skip_yields_with_continuously_ready_transport() {
        let mut recv = FakeRecv::default();
        recv.chunk(unknown_control_prefix(CONTROL_PAYLOAD_LEN));
        for _ in 0..CONTROL_PAYLOAD_LEN as usize / CONTROL_CHUNK_LEN {
            recv.chunk(Bytes::from(vec![0; CONTROL_CHUNK_LEN]));
        }
        recv.chunk(Bytes::from_static(&[0x07, 0x01, 0x00]));
        let polls = Rc::clone(&recv.poll_count);
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
        let mut cx = Context::from_waker(noop_waker_ref());
        assert_matches!(
            stream.poll_next(&mut cx),
            Poll::Ready(Ok(Some(Frame::Settings(_))))
        );
        let before = polls.get();
        assert!(stream.poll_next(&mut cx).is_pending());
        assert!(polls.get() - before <= MAX_FRAME_STREAM_WORK_BYTES_PER_POLL / CONTROL_CHUNK_LEN);
        assert!(stream.decoder.remaining_unknown != 0);
        assert!(stream.stream.buf().remaining() <= CONTROL_CHUNK_LEN);

        // The self-wake budget resumes from the exact remaining payload.
        for _ in 0..CONTROL_PAYLOAD_LEN as usize / CONTROL_CHUNK_LEN {
            match stream.poll_next(&mut cx) {
                Poll::Pending => {}
                Poll::Ready(Ok(Some(Frame::Goaway(id)))) if id.into_inner() == 0 => return,
                result => panic!("unexpected control result: {result:?}"),
            }
        }
        panic!("following GOAWAY did not become ready");
    }

    #[test]
    fn cancelled_next_frame_future_keeps_unknown_skip_boundary() {
        let chunks = Rc::new(std::cell::RefCell::new(VecDeque::from([
            Bytes::from_static(&[0x21, 0x04, 0x00, 0x00]),
        ])));
        let recv = PausedControlRecv {
            chunks: Rc::clone(&chunks),
        };
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
        let mut cx = Context::from_waker(noop_waker_ref());
        let mut next = Box::pin(poll_fn(|cx| stream.poll_next(cx)));
        assert!(std::future::Future::poll(next.as_mut(), &mut cx).is_pending());
        drop(next);
        assert_eq!(stream.decoder.remaining_unknown, 2);
        chunks
            .borrow_mut()
            .push_back(Bytes::from_static(&[0x00, 0x00, 0x07, 0x01, 0x00]));
        assert_matches!(stream.poll_next(&mut cx), Poll::Ready(Ok(Some(Frame::Goaway(id)))) if id.into_inner() == 0);
    }

    #[test]
    fn buffered_payload_limit_is_inclusive_and_data_stays_streaming() {
        let mut bytes = BytesMut::new();
        FrameType::HEADERS.encode(&mut bytes);
        VarInt::try_from(MAX_BUFFERED_FRAME_PAYLOAD)
            .unwrap()
            .encode(&mut bytes);
        bytes.resize(bytes.len() + MAX_BUFFERED_FRAME_PAYLOAD as usize, 0);
        let mut buf = BufList::from(bytes.freeze());
        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(Some(Frame::Headers(payload))) if payload.len() == MAX_BUFFERED_FRAME_PAYLOAD as usize);
        assert_eq!(buf.remaining(), 0);

        let mut prefix = BytesMut::new();
        FrameType::HEADERS.encode(&mut prefix);
        VarInt::try_from(MAX_BUFFERED_FRAME_PAYLOAD + 1)
            .unwrap()
            .encode(&mut prefix);
        let mut buf = BufList::from(prefix.freeze());
        assert_matches!(
            decoder.decode(&mut buf),
            Err(FrameStreamError::ExcessiveLoad(_))
        );

        let mut prefix = BytesMut::new();
        FrameType::DATA.encode(&mut prefix);
        VarInt::try_from(MAX_BUFFERED_FRAME_PAYLOAD + 1)
            .unwrap()
            .encode(&mut prefix);
        let mut buf = BufList::from(prefix.freeze());
        assert_matches!(decoder.decode(&mut buf), Ok(Some(Frame::Data(PayloadLen(len)))) if len == MAX_BUFFERED_FRAME_PAYLOAD as usize + 1);
    }

    #[test]
    fn forbidden_frames_do_not_wait_for_their_payload() {
        let mut prefix = BytesMut::new();
        FrameType::H2_PING.encode(&mut prefix);
        VarInt::MAX.encode(&mut prefix);
        let mut decoder = FrameDecoder::default();
        let mut buf = BufList::from(prefix.freeze());
        assert_matches!(
            decoder.decode(&mut buf),
            Err(FrameStreamError::Proto(FrameProtocolError::ForbiddenFrame(
                0x06
            )))
        );
    }

    #[test]
    fn unknown_request_payload_is_not_reserved_as_a_headers_prefix() {
        let decoder = DecoderState::new(64, u64::MAX, 1).unwrap();
        let shared = Arc::new(SharedState::default());
        let mut wire = BytesMut::new();
        VarInt::from(0x21_u32).encode(&mut wire);
        VarInt::from(96 * 1024_u32).encode(&mut wire);
        wire.extend_from_slice(&vec![0; MAX_FRAME_STREAM_WORK_BYTES_PER_POLL]);
        // After one discard step these payload bytes resemble an oversized
        // HEADERS declaration. They must never reach QPACK reservation.
        wire.extend_from_slice(&[0x01, 0x80, 0x20, 0x00, 0x00]);
        wire.extend_from_slice(&vec![0; 32 * 1024 - 5]);
        wire.extend_from_slice(&[0x01, 0x02, 0x00, 0x00]);
        let mut recv = FakeRecv::default();
        recv.chunk(wire.freeze());
        let mut stream: FrameStream<_, ()> =
            FrameStream::new_request(BufRecvStream::new(recv), Arc::clone(&decoder), &shared)
                .unwrap();
        let mut cx = Context::from_waker(noop_waker_ref());
        for _ in 0..4 {
            match stream.poll_next(&mut cx) {
                Poll::Pending => assert_eq!(decoder.reserved_bytes(), 0),
                Poll::Ready(Ok(Some(Frame::Headers(payload)))) => {
                    assert_eq!(payload.as_ref(), &[0x00, 0x00]);
                    assert_eq!(decoder.reserved_bytes(), 2);
                    assert!(stream.take_header_section().is_some());
                    return;
                }
                result => panic!("unknown payload reached the frame parser: {result:?}"),
            }
        }
        panic!("following HEADERS did not become ready");
    }

    const ZERO_IDENTIFIERS: [&[u8]; 4] = [
        &[0x00],
        &[0x40, 0x00],
        &[0x80, 0x00, 0x00, 0x00],
        &[0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    ];

    fn assert_zero_identifier(frame: Frame<PayloadLen>, ty: FrameType) {
        match frame {
            Frame::Goaway(id) if ty == FrameType::GOAWAY => assert_eq!(id.into_inner(), 0),
            Frame::CancelPush(id) if ty == FrameType::CANCEL_PUSH => assert_eq!(id.0, 0),
            Frame::MaxPushId(id) if ty == FrameType::MAX_PUSH_ID => assert_eq!(id.0, 0),
            other => panic!("unexpected identifier frame for {ty:?}: {other:?}"),
        }
    }

    #[test]
    fn identifier_frames_reject_trailing_payload_before_publishing_a_frame() {
        for ty in [
            FrameType::CANCEL_PUSH,
            FrameType::GOAWAY,
            FrameType::MAX_PUSH_ID,
        ] {
            for identifier in ZERO_IDENTIFIERS {
                for extra in [&[0x00][..], &[0x04, 0x00][..]] {
                    let mut wire = BytesMut::new();
                    ty.encode(&mut wire);
                    VarInt::from((identifier.len() + extra.len()) as u32).encode(&mut wire);
                    wire.extend_from_slice(identifier);
                    wire.extend_from_slice(extra);
                    // A genuine next frame is outside the malformed payload.
                    wire.extend_from_slice(&[0x07, 0x01, 0x00]);
                    let chunks = Rc::new(std::cell::RefCell::new(VecDeque::from([wire.freeze()])));
                    let recv = PausedControlRecv { chunks };
                    let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
                    let mut cx = Context::from_waker(noop_waker_ref());
                    assert_matches!(
                        stream.poll_next(&mut cx),
                        Poll::Ready(Err(FrameStreamError::Proto(FrameProtocolError::Malformed)))
                    );
                }
            }
        }
    }

    #[test]
    fn fully_present_truncated_identifier_is_not_incomplete_outer_input() {
        for ty in [
            FrameType::CANCEL_PUSH,
            FrameType::GOAWAY,
            FrameType::MAX_PUSH_ID,
            FrameType::PUSH_PROMISE,
        ] {
            for payload in [
                &[][..],
                &[0x40][..],
                &[0x80, 0x00][..],
                &[0xc0, 0x00, 0x00][..],
            ] {
                let mut wire = BytesMut::new();
                ty.encode(&mut wire);
                VarInt::from(payload.len() as u32).encode(&mut wire);
                wire.extend_from_slice(payload);
                let chunks = Rc::new(std::cell::RefCell::new(VecDeque::from([wire.freeze()])));
                let recv = PausedControlRecv { chunks };
                let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
                let mut cx = Context::from_waker(noop_waker_ref());
                assert_matches!(
                    stream.poll_next(&mut cx),
                    Poll::Ready(Err(FrameStreamError::Proto(FrameProtocolError::Malformed)))
                );
            }
        }
    }

    #[test]
    fn identifier_frames_accept_every_varint_width_and_keep_the_next_frame() {
        for ty in [
            FrameType::CANCEL_PUSH,
            FrameType::GOAWAY,
            FrameType::MAX_PUSH_ID,
        ] {
            for identifier in ZERO_IDENTIFIERS {
                let mut wire = BytesMut::new();
                ty.encode(&mut wire);
                VarInt::from(identifier.len() as u32).encode(&mut wire);
                wire.extend_from_slice(identifier);
                wire.extend_from_slice(&[0x07, 0x01, 0x00]);
                let mut recv = FakeRecv::default();
                recv.chunk(wire.freeze());
                let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
                let mut cx = Context::from_waker(noop_waker_ref());
                let Poll::Ready(Ok(Some(frame))) = stream.poll_next(&mut cx) else {
                    panic!("valid {ty:?} with identifier {identifier:?} was not ready");
                };
                assert_zero_identifier(frame, ty);
                assert_matches!(stream.poll_next(&mut cx),
                    Poll::Ready(Ok(Some(Frame::Goaway(id)))) if id.into_inner() == 0);
                assert_eq!(stream.stream.buf().remaining(), 0);
            }
        }
    }

    #[test]
    fn fragmented_outer_identifier_frame_waits_for_its_remaining_bytes() {
        for ty in [
            FrameType::CANCEL_PUSH,
            FrameType::GOAWAY,
            FrameType::MAX_PUSH_ID,
        ] {
            let mut wire = BytesMut::new();
            ty.encode(&mut wire);
            // A nonminimal two-byte length, followed by an eight-byte zero ID.
            wire.extend_from_slice(&[0x40, 0x08]);
            wire.extend_from_slice(ZERO_IDENTIFIERS[3]);
            let chunks = Rc::new(std::cell::RefCell::new(VecDeque::new()));
            let recv = PausedControlRecv {
                chunks: Rc::clone(&chunks),
            };
            let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
            let mut cx = Context::from_waker(noop_waker_ref());
            for byte in &wire[..wire.len() - 1] {
                chunks.borrow_mut().push_back(Bytes::from(vec![*byte]));
                assert!(stream.poll_next(&mut cx).is_pending());
            }
            chunks
                .borrow_mut()
                .push_back(Bytes::copy_from_slice(&wire[wire.len() - 1..]));
            let Poll::Ready(Ok(Some(frame))) = stream.poll_next(&mut cx) else {
                panic!("complete fragmented {ty:?} was not ready");
            };
            assert_zero_identifier(frame, ty);
        }
    }

    // Helpers

    #[derive(Default)]
    struct FakeRecv {
        chunks: VecDeque<Bytes>,
        poll_count: Rc<Cell<usize>>,
    }

    impl FakeRecv {
        fn chunk(&mut self, buf: Bytes) -> &mut Self {
            self.chunks.push_back(buf);
            self
        }
    }

    impl RecvStream for FakeRecv {
        type Buf = Bytes;

        fn poll_data(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
            self.poll_count.set(self.poll_count.get() + 1);
            Poll::Ready(Ok(self.chunks.pop_front()))
        }

        fn stop_sending(&mut self, _: u64) {
            unimplemented!()
        }

        fn recv_id(&self) -> StreamId {
            StreamId(0)
        }
    }

    fn to_bytes(
        x: Poll<Result<Option<impl Buf>, FrameStreamError>>,
    ) -> Poll<Result<Option<Bytes>, FrameStreamError>> {
        x.map(|b| b.map(|b| b.map(|mut b| b.copy_to_bytes(b.remaining()))))
    }
}
