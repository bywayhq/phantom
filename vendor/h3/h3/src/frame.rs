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

    /// Unwraps the Framed streamer and returns the underlying stream **without** data loss for
    /// partially received/read frames.
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

        loop {
            if self.header_section.is_none() {
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

            match self.decoder.decode(self.stream.buf_mut())? {
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

            if self.decoder.expected.is_none() && self.stream.buf().has_remaining() {
                continue;
            }

            match self.try_recv_frame(cx)? {
                // Received a chunk but the frame is incomplete, poll until we get `Pending`.
                Poll::Ready(false) => continue,
                Poll::Pending => return Poll::Pending,
                Poll::Ready(true) => {
                    if self.stream.buf_mut().has_remaining() {
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

        if let Some(min) = self.expected {
            if src.remaining() < min {
                return Ok(None);
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
