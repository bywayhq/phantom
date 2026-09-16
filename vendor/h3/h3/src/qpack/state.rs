use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, Weak},
    task::{Context, Waker},
};

use bytes::{Buf, Bytes, BytesMut};

use crate::{
    error::{internal_error::InternalConnectionError, Code},
    shared_state::{ConnectionState, SharedState},
};

use super::{decoder, Decoded, Decoder, DecoderError};

pub(crate) const MAX_ENCODED_FIELD_SECTION_BYTES: usize = 1024 * 1024;
const MAX_RETAINED_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PENDING_FEEDBACK_BYTES: usize = 64 * 1024;

pub(crate) struct DecoderState {
    inner: Mutex<Inner>,
}

struct Inner {
    decoder: Decoder,
    max_blocked_streams: u64,
    max_retained_bytes: usize,
    max_feedback_bytes: usize,
    sections: HashMap<u64, SectionState>,
    blocked_streams: u64,
    reserved_bytes: usize,
    reserved_feedback_bytes: usize,
    feedback: BytesMut,
    feedback_in_flight: usize,
    closed: bool,
}

struct SectionState {
    encoded_bytes: usize,
    acknowledgement: Bytes,
    blocked: Option<BlockedState>,
}

struct BlockedState {
    required_insert_count: usize,
    waker: Waker,
}

#[derive(Debug)]
pub(crate) enum RuntimeError {
    Codec(DecoderError),
    TooManyBlockedStreams,
    EncodedSectionTooLarge { size: usize, limit: usize },
    BlockedBytesExceeded { size: usize, limit: usize },
    FeedbackExceeded,
    DuplicateSection(u64),
    Closed,
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Codec(error) => write!(f, "{error}"),
            Self::TooManyBlockedStreams => write!(f, "QPACK blocked-stream limit exceeded"),
            Self::EncodedSectionTooLarge { size, limit } => {
                write!(f, "encoded field section is {size} bytes; limit is {limit}")
            }
            Self::BlockedBytesExceeded { size, limit } => {
                write!(
                    f,
                    "retained field sections require {size} bytes; limit is {limit}"
                )
            }
            Self::FeedbackExceeded => write!(f, "QPACK decoder feedback limit exceeded"),
            Self::DuplicateSection(stream_id) => {
                write!(f, "stream {stream_id} already owns a field section")
            }
            Self::Closed => write!(f, "QPACK decoder state is closed"),
        }
    }
}

impl std::error::Error for RuntimeError {}

pub(crate) enum DecodeStatus {
    Decoded(Decoded),
    Blocked,
}

pub(crate) struct Section {
    decoder: Arc<DecoderState>,
    shared: Weak<SharedState>,
    stream_id: u64,
    active: bool,
}

pub(crate) struct RequestGuard {
    decoder: Arc<DecoderState>,
    shared: Weak<SharedState>,
    cancellation: Bytes,
    active: bool,
}

pub(crate) struct ReadAheadLease {
    decoder: Arc<DecoderState>,
    bytes: usize,
    active: bool,
}

impl DecoderState {
    pub(crate) fn new(
        max_table_capacity: u64,
        max_field_section_size: u64,
        max_blocked_streams: u64,
    ) -> Result<Arc<Self>, DecoderError> {
        Self::with_limits(
            max_table_capacity,
            max_field_section_size,
            max_blocked_streams,
            MAX_RETAINED_RESPONSE_BYTES,
            MAX_PENDING_FEEDBACK_BYTES,
        )
    }

    fn with_limits(
        max_table_capacity: u64,
        max_field_section_size: u64,
        max_blocked_streams: u64,
        max_retained_bytes: usize,
        max_feedback_bytes: usize,
    ) -> Result<Arc<Self>, DecoderError> {
        Ok(Arc::new(Self {
            inner: Mutex::new(Inner {
                decoder: Decoder::new(max_table_capacity, max_field_section_size)?,
                max_blocked_streams,
                max_retained_bytes,
                max_feedback_bytes,
                sections: HashMap::new(),
                blocked_streams: 0,
                reserved_bytes: 0,
                reserved_feedback_bytes: 0,
                feedback: BytesMut::new(),
                feedback_in_flight: 0,
                closed: false,
            }),
        }))
    }

    pub(crate) fn reserve(
        self: &Arc<Self>,
        shared: Weak<SharedState>,
        stream_id: u64,
        encoded_bytes: usize,
    ) -> Result<Section, RuntimeError> {
        let mut inner = self.lock();
        if inner.closed {
            return Err(RuntimeError::Closed);
        }
        if encoded_bytes > MAX_ENCODED_FIELD_SECTION_BYTES {
            return Err(RuntimeError::EncodedSectionTooLarge {
                size: encoded_bytes,
                limit: MAX_ENCODED_FIELD_SECTION_BYTES,
            });
        }
        if inner.sections.contains_key(&stream_id) {
            return Err(RuntimeError::DuplicateSection(stream_id));
        }
        let reserved_bytes = inner.reserved_bytes.checked_add(encoded_bytes).ok_or(
            RuntimeError::BlockedBytesExceeded {
                size: usize::MAX,
                limit: inner.max_retained_bytes,
            },
        )?;
        if reserved_bytes > inner.max_retained_bytes {
            return Err(RuntimeError::BlockedBytesExceeded {
                size: reserved_bytes,
                limit: inner.max_retained_bytes,
            });
        }

        let mut acknowledgement = BytesMut::new();
        decoder::ack_header(stream_id, &mut acknowledgement);
        inner.reserve_feedback(acknowledgement.len())?;

        inner.reserved_bytes = reserved_bytes;
        inner.sections.insert(
            stream_id,
            SectionState {
                encoded_bytes,
                acknowledgement: acknowledgement.freeze(),
                blocked: None,
            },
        );
        drop(inner);

        Ok(Section {
            decoder: Arc::clone(self),
            shared,
            stream_id,
            active: true,
        })
    }

    pub(crate) fn begin_request(
        self: &Arc<Self>,
        shared: Weak<SharedState>,
        stream_id: u64,
    ) -> Result<RequestGuard, RuntimeError> {
        let mut cancellation = BytesMut::new();
        decoder::stream_canceled(stream_id, &mut cancellation);

        let mut inner = self.lock();
        if inner.closed {
            return Err(RuntimeError::Closed);
        }
        inner.reserve_feedback(cancellation.len())?;
        drop(inner);

        Ok(RequestGuard {
            decoder: Arc::clone(self),
            shared,
            cancellation: cancellation.freeze(),
            active: true,
        })
    }

    pub(crate) fn reserve_read_ahead(
        self: &Arc<Self>,
        bytes: usize,
    ) -> Result<ReadAheadLease, RuntimeError> {
        let mut inner = self.lock();
        if inner.closed {
            return Err(RuntimeError::Closed);
        }
        let reserved_bytes =
            inner
                .reserved_bytes
                .checked_add(bytes)
                .ok_or(RuntimeError::BlockedBytesExceeded {
                    size: usize::MAX,
                    limit: inner.max_retained_bytes,
                })?;
        if reserved_bytes > inner.max_retained_bytes {
            return Err(RuntimeError::BlockedBytesExceeded {
                size: reserved_bytes,
                limit: inner.max_retained_bytes,
            });
        }
        inner.reserved_bytes = reserved_bytes;
        drop(inner);

        Ok(ReadAheadLease {
            decoder: Arc::clone(self),
            bytes,
            active: true,
        })
    }

    pub(crate) fn on_encoder_recv<R: Buf>(&self, read: &mut R) -> Result<Vec<Waker>, RuntimeError> {
        let mut inner = self.lock();
        if inner.closed {
            return Err(RuntimeError::Closed);
        }

        let mut feedback = BytesMut::new();
        inner
            .decoder
            .on_encoder_recv(read, &mut feedback)
            .map_err(RuntimeError::Codec)?;
        inner.enqueue_feedback(&feedback)?;

        let total_inserted = inner.decoder.total_inserted();
        Ok(inner
            .sections
            .values()
            .filter_map(|section| section.blocked.as_ref())
            .filter(|blocked| blocked.required_insert_count <= total_inserted)
            .map(|blocked| blocked.waker.clone())
            .collect())
    }

    pub(crate) fn take_feedback(&self) -> BytesMut {
        let mut inner = self.lock();
        let feedback = std::mem::take(&mut inner.feedback);
        inner.feedback_in_flight = inner.feedback_in_flight.saturating_add(feedback.len());
        feedback
    }

    pub(crate) fn feedback_sent(&self, bytes: usize) {
        let mut inner = self.lock();
        inner.feedback_in_flight = inner.feedback_in_flight.saturating_sub(bytes);
    }

    pub(crate) fn abort(&self) -> Vec<Waker> {
        let mut inner = self.lock();
        inner.closed = true;
        let wakers = inner
            .sections
            .values()
            .filter_map(|section| section.blocked.as_ref())
            .map(|blocked| blocked.waker.clone())
            .collect();
        inner.sections.clear();
        inner.blocked_streams = 0;
        inner.reserved_bytes = 0;
        inner.reserved_feedback_bytes = 0;
        wakers
    }

    fn poll_decode(
        &self,
        section: &mut Section,
        encoded: &Bytes,
        cx: &Context<'_>,
    ) -> Result<DecodeStatus, RuntimeError> {
        let mut inner = self.lock();
        if inner.closed {
            return Err(RuntimeError::Closed);
        }
        if !section.active || !inner.sections.contains_key(&section.stream_id) {
            return Err(RuntimeError::Closed);
        }

        let mut cursor = encoded.clone();
        match inner.decoder.decode_header(&mut cursor) {
            Ok(decoded) => {
                let state = inner.remove_section(section.stream_id).unwrap();
                section.active = false;
                if decoded.dyn_ref {
                    inner.enqueue_reserved_feedback(
                        &state.acknowledgement,
                        state.acknowledgement.len(),
                    )?;
                } else {
                    inner.release_feedback_reservation(&state);
                }
                Ok(DecodeStatus::Decoded(decoded))
            }
            Err(DecoderError::MissingRefs(required_insert_count)) => {
                if inner
                    .sections
                    .get(&section.stream_id)
                    .and_then(|state| state.blocked.as_ref())
                    .is_none()
                {
                    if inner.blocked_streams >= inner.max_blocked_streams {
                        if let Some(state) = inner.remove_section(section.stream_id) {
                            inner.release_feedback_reservation(&state);
                        }
                        section.active = false;
                        return Err(RuntimeError::TooManyBlockedStreams);
                    }

                    let state = inner.sections.get_mut(&section.stream_id).unwrap();
                    state.blocked = Some(BlockedState {
                        required_insert_count,
                        waker: cx.waker().clone(),
                    });
                    inner.blocked_streams += 1;
                } else {
                    let blocked = inner
                        .sections
                        .get_mut(&section.stream_id)
                        .unwrap()
                        .blocked
                        .as_mut()
                        .unwrap();
                    blocked.required_insert_count = required_insert_count;
                    if !blocked.waker.will_wake(cx.waker()) {
                        blocked.waker = cx.waker().clone();
                    }
                }
                Ok(DecodeStatus::Blocked)
            }
            Err(error @ DecoderError::HeaderTooLong(_)) => {
                let state = inner.remove_section(section.stream_id).unwrap();
                section.active = false;
                inner.release_feedback_reservation(&state);
                Err(RuntimeError::Codec(error))
            }
            Err(error) => {
                if let Some(state) = inner.remove_section(section.stream_id) {
                    inner.release_feedback_reservation(&state);
                }
                section.active = false;
                Err(RuntimeError::Codec(error))
            }
        }
    }

    fn abandon(&self, stream_id: u64) {
        let mut inner = self.lock();
        let Some(state) = inner.remove_section(stream_id) else {
            return;
        };
        inner.release_feedback_reservation(&state);
    }

    fn cancel_request(&self, cancellation: &[u8]) -> Result<bool, RuntimeError> {
        let mut inner = self.lock();
        if inner.closed {
            return Ok(false);
        }
        inner.enqueue_reserved_feedback(cancellation, cancellation.len())?;
        Ok(true)
    }

    fn complete_request(&self, cancellation_bytes: usize) {
        let mut inner = self.lock();
        if !inner.closed {
            inner.reserved_feedback_bytes = inner
                .reserved_feedback_bytes
                .saturating_sub(cancellation_bytes);
        }
    }

    fn release_read_ahead(&self, bytes: usize) {
        let mut inner = self.lock();
        inner.reserved_bytes = inner.reserved_bytes.saturating_sub(bytes);
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(test)]
    pub(crate) fn reserved_bytes(&self) -> usize {
        self.lock().reserved_bytes
    }
}

impl Inner {
    fn feedback_usage(&self) -> usize {
        self.feedback
            .len()
            .saturating_add(self.feedback_in_flight)
            .saturating_add(self.reserved_feedback_bytes)
    }

    fn reserve_feedback(&mut self, bytes: usize) -> Result<(), RuntimeError> {
        if self.feedback_usage().saturating_add(bytes) > self.max_feedback_bytes {
            return Err(RuntimeError::FeedbackExceeded);
        }
        self.reserved_feedback_bytes += bytes;
        Ok(())
    }

    fn enqueue_feedback(&mut self, feedback: &[u8]) -> Result<(), RuntimeError> {
        if self.feedback_usage().saturating_add(feedback.len()) > self.max_feedback_bytes {
            return Err(RuntimeError::FeedbackExceeded);
        }
        self.feedback.extend_from_slice(feedback);
        Ok(())
    }

    fn enqueue_reserved_feedback(
        &mut self,
        feedback: &[u8],
        reserved_bytes: usize,
    ) -> Result<(), RuntimeError> {
        self.reserved_feedback_bytes = self.reserved_feedback_bytes.saturating_sub(reserved_bytes);
        if self.feedback_usage().saturating_add(feedback.len()) > self.max_feedback_bytes {
            return Err(RuntimeError::FeedbackExceeded);
        }
        self.feedback.extend_from_slice(feedback);
        Ok(())
    }

    fn remove_section(&mut self, stream_id: u64) -> Option<SectionState> {
        let state = self.sections.remove(&stream_id)?;
        self.reserved_bytes = self.reserved_bytes.saturating_sub(state.encoded_bytes);
        if state.blocked.is_some() {
            self.blocked_streams = self.blocked_streams.saturating_sub(1);
        }
        Some(state)
    }

    fn release_feedback_reservation(&mut self, state: &SectionState) {
        self.reserved_feedback_bytes = self
            .reserved_feedback_bytes
            .saturating_sub(state.acknowledgement.len());
    }
}

impl Section {
    pub(crate) fn poll_decode(
        &mut self,
        encoded: &Bytes,
        cx: &Context<'_>,
    ) -> Result<DecodeStatus, RuntimeError> {
        let decoder = Arc::clone(&self.decoder);
        let result = decoder.poll_decode(self, encoded, cx);
        if matches!(&result, Ok(DecodeStatus::Decoded(decoded)) if decoded.dyn_ref)
            || matches!(
                result,
                Err(RuntimeError::Codec(DecoderError::HeaderTooLong(_)))
            )
        {
            self.wake_driver();
        }
        result
    }

    pub(crate) fn cancel(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        self.decoder.abandon(self.stream_id);
    }

    fn wake_driver(&self) {
        if let Some(shared) = self.shared.upgrade() {
            shared.waker().wake();
        }
    }
}

impl RequestGuard {
    pub(crate) fn cancel(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        match self.decoder.cancel_request(&self.cancellation) {
            Ok(feedback_queued) => {
                if feedback_queued {
                    self.wake_driver();
                }
            }
            Err(error) => self.fail_connection(error),
        }
    }

    pub(crate) fn complete(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        self.decoder.complete_request(self.cancellation.len());
    }

    fn wake_driver(&self) {
        if let Some(shared) = self.shared.upgrade() {
            shared.waker().wake();
        }
    }

    fn fail_connection(&self, error: RuntimeError) {
        if let Some(shared) = self.shared.upgrade() {
            shared.set_conn_error_and_wake(InternalConnectionError::new(
                Code::H3_EXCESSIVE_LOAD,
                error.to_string(),
            ));
        }
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        self.cancel();
    }
}

impl Drop for ReadAheadLease {
    fn drop(&mut self) {
        if self.active {
            self.active = false;
            self.decoder.release_read_ahead(self.bytes);
        }
    }
}

impl Drop for Section {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(test)]
#[path = "state/tests.rs"]
mod tests;
