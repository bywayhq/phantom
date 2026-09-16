use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::Context,
};

use bytes::{Bytes, BytesMut};
use futures_util::task::{waker, ArcWake};

use crate::shared_state::SharedState;

use super::super::{dynamic::DynamicTable, encoder::set_dynamic_table_size, Encoder, HeaderField};
use super::{DecodeStatus, DecoderState, RuntimeError, Section};

struct DynamicFixture {
    block: Bytes,
    encoder_instructions: Bytes,
}

fn dynamic_fixture() -> DynamicFixture {
    let mut table = DynamicTable::new();
    table.set_max_blocked(1).unwrap();

    let mut encoder_instructions = Vec::new();
    set_dynamic_table_size(&mut table, &mut encoder_instructions, 64).unwrap();
    let mut encoder = Encoder::from(table);
    let mut block = Vec::new();
    encoder
        .encode(
            0,
            &mut block,
            &mut encoder_instructions,
            [
                HeaderField::new(":status", "200"),
                HeaderField::new("x", "y"),
            ],
        )
        .unwrap();

    DynamicFixture {
        block: block.into(),
        encoder_instructions: encoder_instructions.into(),
    }
}

struct CountWake(AtomicUsize);

impl ArcWake for CountWake {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn poll_decode(
    section: &mut Section,
    counter: &Arc<CountWake>,
    encoded: &Bytes,
) -> Result<DecodeStatus, RuntimeError> {
    let waker = waker(Arc::clone(counter));
    let cx = Context::from_waker(&waker);
    section.poll_decode(encoded, &cx)
}

fn decoder(max_blocked: u64) -> Arc<DecoderState> {
    DecoderState::with_limits(64, u64::MAX, max_blocked, 1024, 1024).unwrap()
}

#[test]
fn block_insert_unblock_orders_feedback_and_releases_accounting() {
    let fixture = dynamic_fixture();
    let decoder = decoder(1);
    let shared = Arc::new(SharedState::default());
    let mut section = decoder
        .reserve(Arc::downgrade(&shared), 0, fixture.block.len())
        .unwrap();
    let wake = Arc::new(CountWake(AtomicUsize::new(0)));

    assert!(matches!(
        poll_decode(&mut section, &wake, &fixture.block),
        Ok(DecodeStatus::Blocked)
    ));
    {
        let inner = decoder.lock();
        assert_eq!(inner.blocked_streams, 1);
        assert_eq!(inner.reserved_bytes, fixture.block.len());
    }

    let wakers = decoder
        .on_encoder_recv(&mut fixture.encoder_instructions.clone())
        .unwrap();
    for waker in wakers {
        waker.wake();
    }
    assert_eq!(wake.0.load(Ordering::Relaxed), 1);

    let decoded = poll_decode(&mut section, &wake, &fixture.block).unwrap();
    let DecodeStatus::Decoded(decoded) = decoded else {
        panic!("field section remained blocked");
    };
    assert_eq!(decoded.fields.len(), 2);
    assert_eq!(decoded.fields[0].name.as_ref(), b":status");
    assert_eq!(decoded.fields[0].value.as_ref(), b"200");
    assert_eq!(decoded.fields[1].name.as_ref(), b"x");
    assert_eq!(decoded.fields[1].value.as_ref(), b"y");

    assert_eq!(decoder.take_feedback(), &b"\x01\x80"[..]);
    let inner = decoder.lock();
    assert_eq!(inner.blocked_streams, 0);
    assert_eq!(inner.reserved_bytes, 0);
}

#[test]
fn repeated_poll_replaces_waker_without_double_accounting() {
    let fixture = dynamic_fixture();
    let decoder = decoder(1);
    let shared = Arc::new(SharedState::default());
    let mut section = decoder
        .reserve(Arc::downgrade(&shared), 0, fixture.block.len())
        .unwrap();
    let first = Arc::new(CountWake(AtomicUsize::new(0)));
    let second = Arc::new(CountWake(AtomicUsize::new(0)));

    assert!(matches!(
        poll_decode(&mut section, &first, &fixture.block),
        Ok(DecodeStatus::Blocked)
    ));
    assert!(matches!(
        poll_decode(&mut section, &second, &fixture.block),
        Ok(DecodeStatus::Blocked)
    ));
    {
        let inner = decoder.lock();
        assert_eq!(inner.blocked_streams, 1);
        assert_eq!(inner.reserved_bytes, fixture.block.len());
    }

    for waker in decoder
        .on_encoder_recv(&mut fixture.encoder_instructions.clone())
        .unwrap()
    {
        waker.wake();
    }
    assert_eq!(first.0.load(Ordering::Relaxed), 0);
    assert_eq!(second.0.load(Ordering::Relaxed), 1);
}

#[test]
fn cancelling_blocked_section_queues_one_cancellation() {
    let fixture = dynamic_fixture();
    let decoder = decoder(1);
    let shared = Arc::new(SharedState::default());
    let mut request = decoder.begin_request(Arc::downgrade(&shared), 0).unwrap();
    let mut section = decoder
        .reserve(Arc::downgrade(&shared), 0, fixture.block.len())
        .unwrap();
    let wake = Arc::new(CountWake(AtomicUsize::new(0)));
    assert!(matches!(
        poll_decode(&mut section, &wake, &fixture.block),
        Ok(DecodeStatus::Blocked)
    ));

    section.cancel();
    section.cancel();
    drop(section);
    request.cancel();
    request.cancel();
    drop(request);

    assert_eq!(decoder.take_feedback(), &b"\x40"[..]);
    let inner = decoder.lock();
    assert_eq!(inner.blocked_streams, 0);
    assert_eq!(inner.reserved_bytes, 0);
}

#[test]
fn cancelling_before_decode_still_releases_peer_references() {
    let fixture = dynamic_fixture();
    let decoder = decoder(1);
    let shared = Arc::new(SharedState::default());
    let request = decoder.begin_request(Arc::downgrade(&shared), 0).unwrap();
    let section = decoder
        .reserve(Arc::downgrade(&shared), 0, fixture.block.len())
        .unwrap();

    drop(section);
    drop(request);

    assert_eq!(decoder.take_feedback(), &b"\x40"[..]);
    let inner = decoder.lock();
    assert!(inner.sections.is_empty());
    assert_eq!(inner.reserved_bytes, 0);
    assert_eq!(inner.reserved_feedback_bytes, 0);
}

#[test]
fn request_guard_cancels_before_any_section_is_received() {
    let decoder = decoder(1);
    let shared = Arc::new(SharedState::default());
    let request = decoder.begin_request(Arc::downgrade(&shared), 0).unwrap();

    drop(request);

    assert_eq!(decoder.take_feedback(), &b"\x40"[..]);
    assert_eq!(decoder.lock().reserved_feedback_bytes, 0);
}

#[test]
fn request_guard_cancels_after_an_acknowledged_section() {
    let fixture = dynamic_fixture();
    let decoder = decoder(1);
    let shared = Arc::new(SharedState::default());
    let request = decoder.begin_request(Arc::downgrade(&shared), 0).unwrap();
    decoder
        .on_encoder_recv(&mut fixture.encoder_instructions.clone())
        .unwrap();
    let mut section = decoder
        .reserve(Arc::downgrade(&shared), 0, fixture.block.len())
        .unwrap();
    let wake = Arc::new(CountWake(AtomicUsize::new(0)));

    assert!(matches!(
        poll_decode(&mut section, &wake, &fixture.block),
        Ok(DecodeStatus::Decoded(_))
    ));
    drop(request);

    assert_eq!(decoder.take_feedback(), &b"\x01\x80\x40"[..]);
    assert_eq!(decoder.lock().reserved_feedback_bytes, 0);
}

#[test]
fn cancelling_one_section_preserves_other_feedback_reservation() {
    let fixture = dynamic_fixture();
    let decoder = decoder(2);
    let shared = Arc::new(SharedState::default());
    let wake = Arc::new(CountWake(AtomicUsize::new(0)));
    let mut first_request = decoder.begin_request(Arc::downgrade(&shared), 0).unwrap();
    let mut second_request = decoder.begin_request(Arc::downgrade(&shared), 1).unwrap();
    let mut first = decoder
        .reserve(Arc::downgrade(&shared), 0, fixture.block.len())
        .unwrap();
    let mut second = decoder
        .reserve(Arc::downgrade(&shared), 1, fixture.block.len())
        .unwrap();

    assert!(matches!(
        poll_decode(&mut first, &wake, &fixture.block),
        Ok(DecodeStatus::Blocked)
    ));
    assert!(matches!(
        poll_decode(&mut second, &wake, &fixture.block),
        Ok(DecodeStatus::Blocked)
    ));

    first.cancel();
    first_request.cancel();
    assert_eq!(decoder.lock().reserved_feedback_bytes, 2);
    second.cancel();
    second_request.cancel();
    assert_eq!(decoder.lock().reserved_feedback_bytes, 0);
    assert_eq!(decoder.take_feedback(), &b"\x40\x41"[..]);
}

#[test]
fn acknowledgement_releases_cancellation_reservation_at_prefix_boundaries() {
    let fixture = dynamic_fixture();
    let shared = Arc::new(SharedState::default());
    let wake = Arc::new(CountWake(AtomicUsize::new(0)));

    for stream_id in [62, 63, 64, 126, 127, 128, 16_382, 16_383, 16_384] {
        let decoder = decoder(1);
        decoder
            .on_encoder_recv(&mut fixture.encoder_instructions.clone())
            .unwrap();
        let feedback = decoder.take_feedback();
        decoder.feedback_sent(feedback.len());
        let mut request = decoder
            .begin_request(Arc::downgrade(&shared), stream_id)
            .unwrap();
        let mut section = decoder
            .reserve(Arc::downgrade(&shared), stream_id, fixture.block.len())
            .unwrap();

        assert!(matches!(
            poll_decode(&mut section, &wake, &fixture.block),
            Ok(DecodeStatus::Decoded(_))
        ));
        request.complete();
        assert_eq!(decoder.lock().reserved_feedback_bytes, 0);
    }
}

#[test]
fn read_ahead_uses_the_connection_wide_byte_budget() {
    let fixture = dynamic_fixture();
    let shared = Arc::new(SharedState::default());
    let decoder =
        DecoderState::with_limits(64, u64::MAX, 1, fixture.block.len() + 8, 1024).unwrap();
    let section = decoder
        .reserve(Arc::downgrade(&shared), 0, fixture.block.len())
        .unwrap();

    let read_ahead = decoder.reserve_read_ahead(9);
    assert!(matches!(
        read_ahead,
        Err(RuntimeError::BlockedBytesExceeded { .. })
    ));
    drop(section);
    assert_eq!(decoder.lock().reserved_bytes, 0);
}

#[test]
fn decoded_sections_retain_read_ahead_until_the_buffer_lease_drops() {
    const READ_AHEAD: usize = 100;

    let fixture = dynamic_fixture();
    let shared = Arc::new(SharedState::default());
    let retained_limit = fixture.block.len() * 2 + READ_AHEAD * 2;
    let decoder = DecoderState::with_limits(64, u64::MAX, 2, retained_limit, 1024).unwrap();
    let wake = Arc::new(CountWake(AtomicUsize::new(0)));
    let mut first = decoder
        .reserve(Arc::downgrade(&shared), 0, fixture.block.len())
        .unwrap();
    let mut second = decoder
        .reserve(Arc::downgrade(&shared), 1, fixture.block.len())
        .unwrap();

    assert!(matches!(
        poll_decode(&mut first, &wake, &fixture.block),
        Ok(DecodeStatus::Blocked)
    ));
    let first_read_ahead = decoder.reserve_read_ahead(READ_AHEAD).unwrap();
    assert!(matches!(
        poll_decode(&mut second, &wake, &fixture.block),
        Ok(DecodeStatus::Blocked)
    ));
    let second_read_ahead = decoder.reserve_read_ahead(READ_AHEAD).unwrap();
    decoder
        .on_encoder_recv(&mut fixture.encoder_instructions.clone())
        .unwrap();

    assert!(matches!(
        poll_decode(&mut first, &wake, &fixture.block),
        Ok(DecodeStatus::Decoded(_))
    ));
    assert!(matches!(
        poll_decode(&mut second, &wake, &fixture.block),
        Ok(DecodeStatus::Decoded(_))
    ));
    assert_eq!(decoder.lock().reserved_bytes, READ_AHEAD * 2);

    drop(first_read_ahead);
    assert_eq!(decoder.lock().reserved_bytes, READ_AHEAD);
    drop(second_read_ahead);
    assert_eq!(decoder.lock().reserved_bytes, 0);
}

#[test]
fn blocked_stream_and_byte_limits_are_distinct() {
    let fixture = dynamic_fixture();
    let shared = Arc::new(SharedState::default());
    let decoder = DecoderState::with_limits(64, u64::MAX, 0, 4, 1024).unwrap();
    let mut section = decoder
        .reserve(Arc::downgrade(&shared), 0, fixture.block.len())
        .unwrap();
    let wake = Arc::new(CountWake(AtomicUsize::new(0)));
    assert!(matches!(
        poll_decode(&mut section, &wake, &fixture.block),
        Err(RuntimeError::TooManyBlockedStreams)
    ));

    let decoder = DecoderState::with_limits(64, u64::MAX, 1, 3, 1024).unwrap();
    assert!(matches!(
        decoder.reserve(Arc::downgrade(&shared), 0, fixture.block.len()),
        Err(RuntimeError::BlockedBytesExceeded { .. })
    ));
}

#[test]
fn feedback_limit_fails_closed_without_leaking_section_bytes() {
    let fixture = dynamic_fixture();
    let shared = Arc::new(SharedState::default());
    let decoder = DecoderState::with_limits(64, u64::MAX, 1, 1024, 0).unwrap();
    assert!(matches!(
        decoder.reserve(Arc::downgrade(&shared), 0, fixture.block.len()),
        Err(RuntimeError::FeedbackExceeded)
    ));
    let inner = decoder.lock();
    assert_eq!(inner.blocked_streams, 0);
    assert_eq!(inner.reserved_bytes, 0);
    assert_eq!(inner.feedback, BytesMut::new());
}
