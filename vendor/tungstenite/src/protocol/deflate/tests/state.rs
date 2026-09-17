use super::{support::Incoming, *};
use crate::error::ProtocolError;
use std::io::Cursor;

fn client(frames: &[u8]) -> WebSocket<Incoming> {
    WebSocket::from_raw_socket(
        Incoming(Cursor::new(frames.to_vec())),
        Role::Client,
        Some(WebSocketConfig::default().enable_deflate()),
    )
}

const FIRST_FRAGMENT: &[u8] = &[0xf2, 0x48, 0xcd];
const LAST_FRAGMENT: &[u8] = &[0xc9, 0xc9, 0x07, 0x00];

#[test]
fn a_rejected_stray_frame_does_not_clear_the_saved_compressed_mode() {
    let mut frames = vec![0x42, 0x03];
    frames.extend_from_slice(FIRST_FRAGMENT);
    frames.extend_from_slice(&[0x01, 0x01, b'A']);
    frames.extend_from_slice(&[0x80, 0x04]);
    frames.extend_from_slice(LAST_FRAGMENT);

    let mut socket = client(&frames);
    assert!(
        matches!(
            socket.read().unwrap_err(),
            Error::Protocol(ProtocolError::ExpectedFragment(_))
        ),
        "a new data frame during an open message is illegal"
    );
    assert_eq!(
        socket
            .read()
            .expect("the continuation is still part of a compressed message"),
        Message::binary(b"Hello".to_vec())
    );
}

const FIRST: &[u8] = b"permessage-deflate context takeover shares one window";
const SECOND: &[u8] = b"context takeover shares one window, so this back-references";

fn peer_pair() -> (Vec<u8>, Vec<u8>) {
    let mut peer = deflate::Context::new(Role::Server, deflate::Settings::default());
    let first = peer
        .compress(FIRST)
        .expect("the peer compresses its first message");
    let second = peer
        .compress(SECOND)
        .expect("the peer compresses its second message");
    (first.to_vec(), second.to_vec())
}

fn frame_bytes(fin: bool, rsv1: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
    assert!(
        payload.len() < 126,
        "the fixture keeps every header two bytes"
    );
    let first = (u8::from(fin) << 7) | (u8::from(rsv1) << 6) | opcode;
    let mut out = vec![first, payload.len() as u8];
    out.extend_from_slice(payload);
    out
}

#[test]
fn a_skipped_compressed_message_ends_the_connection() {
    let (first, _) = peer_pair();
    let mut frames = frame_bytes(false, false, 0x2, b"open");
    frames.extend(frame_bytes(true, true, 0x2, &first));
    frames.extend(frame_bytes(true, false, 0x0, b"close"));

    let mut socket = client(&frames);
    assert!(matches!(
        socket.read().unwrap_err(),
        Error::Protocol(ProtocolError::ExpectedFragment(_))
    ));
    assert!(
        matches!(socket.read().unwrap_err(), Error::AlreadyClosed),
        "the message that would have completed must not be read against a stale window"
    );
}

#[test]
fn control_the_second_message_needs_the_first_in_the_decoder() {
    let (first, second) = peer_pair();

    let mut both = frame_bytes(true, true, 0x2, &first);
    both.extend(frame_bytes(true, true, 0x2, &second));
    let mut socket = client(&both);
    assert_eq!(
        socket.read().expect("first message"),
        Message::binary(FIRST.to_vec())
    );
    assert_eq!(
        socket.read().expect("second message"),
        Message::binary(SECOND.to_vec())
    );

    let mut alone = client(&frame_bytes(true, true, 0x2, &second));
    assert!(
        !matches!(alone.read(), Ok(Message::Binary(ref bytes)) if bytes.as_ref() == SECOND),
        "the second message must not decode correctly against a window without the first"
    );
}

fn masked_frame_bytes(fin: bool, rsv1: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
    const KEY: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];
    assert!(
        payload.len() < 126,
        "the fixture keeps every header two bytes"
    );
    let first = (u8::from(fin) << 7) | (u8::from(rsv1) << 6) | opcode;
    let mut out = vec![first, 0x80 | payload.len() as u8];
    out.extend_from_slice(&KEY);
    out.extend(
        payload
            .iter()
            .enumerate()
            .map(|(i, byte)| byte ^ KEY[i % 4]),
    );
    out
}

fn server(frames: &[u8]) -> WebSocket<Wire> {
    WebSocket::from_raw_socket(
        Wire::new(frames.to_vec()),
        Role::Server,
        Some(WebSocketConfig::default().enable_deflate()),
    )
}

#[test]
fn a_discarded_compressed_frame_ends_the_connection() {
    let (first, second) = peer_pair();

    // Reserved bits, on a compressed message the peer's compressor already consumed.
    let mut frames = frame_bytes(true, true, 0x2, &first);
    frames[0] |= 0x20;
    frames.extend(frame_bytes(true, true, 0x2, &second));
    let mut socket = client(&frames);
    assert!(matches!(
        socket.read().unwrap_err(),
        Error::Protocol(ProtocolError::NonZeroReservedBits)
    ));
    assert!(matches!(socket.read().unwrap_err(), Error::AlreadyClosed));

    // A masked frame from a server, same shape.
    let mut frames = masked_frame_bytes(true, true, 0x2, &first);
    frames.extend(frame_bytes(true, true, 0x2, &second));
    let mut socket = client(&frames);
    assert!(matches!(
        socket.read().unwrap_err(),
        Error::Protocol(ProtocolError::MaskedFrameFromServer)
    ));
    assert!(matches!(socket.read().unwrap_err(), Error::AlreadyClosed));
}

#[test]
fn a_discarded_unmasked_continuation_ends_the_connection() {
    let (first, _) = peer_pair();
    let (head, tail) = first.split_at(first.len() / 2);
    let mut frames = masked_frame_bytes(false, true, 0x2, head);
    frames.extend(frame_bytes(false, false, 0x0, tail));
    let mut socket = server(&frames);

    assert!(matches!(
        socket.read().unwrap_err(),
        Error::Protocol(ProtocolError::UnmaskedFrameFromClient)
    ));
    assert!(matches!(socket.read().unwrap_err(), Error::AlreadyClosed));
    assert!(matches!(socket.flush().unwrap_err(), Error::AlreadyClosed));
}

fn unmasked_whole_message() -> Vec<u8> {
    let (first, second) = peer_pair();
    let mut frames = frame_bytes(true, true, 0x2, &first);
    frames.extend(masked_frame_bytes(true, true, 0x2, &second));
    frames
}

fn server_after_unmasked_rejection() -> WebSocket<Wire> {
    let config = WebSocketConfig::default()
        .enable_deflate()
        .write_buffer_size(64 * 1024);
    let mut socket = WebSocket::from_raw_socket(
        Wire::new(unmasked_whole_message()),
        Role::Server,
        Some(config),
    );
    socket
        .write(Message::binary(b"queued".to_vec()))
        .expect("the frame queues");
    assert!(
        socket.get_ref().written.is_empty(),
        "the fixture must leave the frame queued"
    );
    assert!(matches!(
        socket.read().unwrap_err(),
        Error::Protocol(ProtocolError::UnmaskedFrameFromClient)
    ));
    socket
}

#[test]
fn a_discarded_unmasked_message_stops_later_reads() {
    let mut socket = server_after_unmasked_rejection();
    assert!(matches!(socket.read().unwrap_err(), Error::AlreadyClosed));
    nothing_reached_the_stream(&socket);
}

#[test]
fn a_discarded_unmasked_message_stops_later_flushes() {
    let mut socket = server_after_unmasked_rejection();
    assert!(matches!(socket.flush().unwrap_err(), Error::AlreadyClosed));
    nothing_reached_the_stream(&socket);
}

#[test]
fn a_discarded_unmasked_message_stops_later_closes() {
    let mut socket = server_after_unmasked_rejection();
    assert!(matches!(
        socket.close(None).unwrap_err(),
        Error::AlreadyClosed
    ));
    nothing_reached_the_stream(&socket);
}

#[test]
fn control_accepting_unmasked_frames_decodes_the_same_message() {
    let (first, _) = peer_pair();
    let config = WebSocketConfig::default()
        .enable_deflate()
        .accept_unmasked_frames(true);
    let mut socket = WebSocket::from_raw_socket(
        Wire::new(frame_bytes(true, true, 0x2, &first)),
        Role::Server,
        Some(config),
    );
    assert_eq!(
        socket.read().expect("the caller asked for this frame"),
        Message::binary(FIRST.to_vec())
    );
}

fn standalone_compressed(payload: &[u8]) -> Vec<u8> {
    let mut peer = deflate::Context::new(Role::Server, deflate::Settings::default());
    peer.compress(payload)
        .expect("the peer compresses a standalone message")
        .to_vec()
}

#[test]
fn a_discarded_frame_claiming_compression_ends_the_connection() {
    let compressed = standalone_compressed(FIRST);

    // A continuation with no message to continue: nothing is left to classify it by,
    // whether it claims compression or not, and at either discarding exit.
    let mut stray_rsv2 = frame_bytes(true, false, 0x0, &compressed);
    stray_rsv2[0] |= 0x20;
    for frames in [
        stray_rsv2,
        frame_bytes(true, true, 0x0, &compressed),
        masked_frame_bytes(true, false, 0x0, &compressed),
    ] {
        let mut socket = client(&frames);
        assert!(socket.read().is_err(), "the stray continuation is rejected");
        assert!(matches!(socket.read().unwrap_err(), Error::AlreadyClosed));
    }

    // A plain continuation of an open *compressed* message: no RSV1 claim of its own,
    // but the message it continues had one.
    let (head, tail) = compressed.split_at(compressed.len() / 2);
    let mut frames = frame_bytes(false, true, 0x2, head);
    let mut discarded = frame_bytes(true, false, 0x0, tail);
    discarded[0] |= 0x20;
    frames.extend(discarded);
    let mut socket = client(&frames);
    assert!(matches!(
        socket.read().unwrap_err(),
        Error::Protocol(ProtocolError::NonZeroReservedBits)
    ));
    assert!(matches!(socket.read().unwrap_err(), Error::AlreadyClosed));

    // RSV1 on a continuation while a *plain* message is open. It is in position, so it
    // never reaches the fragment-sequence branch, and `compressed_incomplete` is false
    // -- only the RSV1 claim itself makes this unusable.
    let mut frames = vec![0x02, 0x03, b'a', b'b', b'c'];
    frames.extend(frame_bytes(true, true, 0x0, &compressed));
    let mut socket = client(&frames);
    assert!(matches!(
        socket.read().unwrap_err(),
        Error::Protocol(ProtocolError::NonZeroReservedBits)
    ));
    assert!(matches!(socket.read().unwrap_err(), Error::AlreadyClosed));

    // RSV1 on a control frame: FIN + RSV1 + Ping, empty.
    let mut socket = client(&[0xc9, 0x00]);
    assert!(matches!(
        socket.read().unwrap_err(),
        Error::Protocol(ProtocolError::NonZeroReservedBits)
    ));
    assert!(matches!(socket.read().unwrap_err(), Error::AlreadyClosed));
}

#[test]
fn control_a_discarded_plain_continuation_leaves_the_connection_open() {
    // Open a plain message, discard one continuation on RSV2, then finish the message
    // and send a compressed one. The discarded bytes are simply lost, as they are at
    // base -- what must survive is the connection.
    let mut frames = vec![
        0x02, 0x03, b'a', b'b', b'c', // plain, non-final
        0x20, 0x02, b'd', b'e', // continuation with RSV2: discarded
        0x80, 0x02, b'f', b'g', // continuation, final
    ];
    frames.extend(frame_bytes(true, true, 0x2, &standalone_compressed(FIRST)));
    let mut socket = client(&frames);

    assert!(matches!(
        socket.read().unwrap_err(),
        Error::Protocol(ProtocolError::NonZeroReservedBits)
    ));
    assert_eq!(
        socket.read().expect("nothing compressed was discarded"),
        Message::binary(b"abcfg".to_vec()),
        "the message completes without the frame that was thrown away"
    );
    assert_eq!(
        socket.read().expect("and the decoder is still usable"),
        Message::binary(FIRST.to_vec()),
        "a later compressed message decodes exactly"
    );
}

#[test]
fn control_a_discarded_plain_control_frame_leaves_the_connection_open() {
    // FIN | RSV2 | Ping, empty -- rejected for the reserved bit, claiming no RSV1.
    let mut frames = vec![0xa9, 0x00];
    frames.extend(frame_bytes(true, true, 0x2, &standalone_compressed(FIRST)));
    let mut socket = client(&frames);

    assert!(matches!(
        socket.read().unwrap_err(),
        Error::Protocol(ProtocolError::NonZeroReservedBits)
    ));
    assert_eq!(
        socket.read().expect("a plain control frame claims nothing"),
        Message::binary(FIRST.to_vec())
    );
}

#[test]
fn a_discarded_compressed_frame_keeps_queued_bytes_off_the_stream() {
    let mut frames = frame_bytes(true, true, 0x2, &standalone_compressed(FIRST));
    frames[0] |= 0x20;
    let mut socket = queued(frames);
    assert!(matches!(
        socket.read().unwrap_err(),
        Error::Protocol(ProtocolError::NonZeroReservedBits)
    ));
    assert!(matches!(socket.flush().unwrap_err(), Error::AlreadyClosed));
    nothing_reached_the_stream(&socket);
}

#[test]
fn a_skipped_compressed_message_keeps_queued_bytes_off_the_stream() {
    let mut frames = frame_bytes(false, false, 0x2, b"open");
    frames.extend(frame_bytes(true, true, 0x2, &standalone_compressed(FIRST)));
    let mut socket = queued(frames);
    assert!(matches!(
        socket.read().unwrap_err(),
        Error::Protocol(ProtocolError::ExpectedFragment(_))
    ));
    assert!(matches!(socket.flush().unwrap_err(), Error::AlreadyClosed));
    nothing_reached_the_stream(&socket);
}

#[test]
fn control_a_discarded_plain_frame_leaves_the_connection_open() {
    let mut frames = frame_bytes(true, false, 0x2, b"plain");
    frames[0] |= 0x20;
    frames.extend(frame_bytes(true, true, 0x2, &standalone_compressed(FIRST)));
    let mut socket = client(&frames);

    assert!(matches!(
        socket.read().unwrap_err(),
        Error::Protocol(ProtocolError::NonZeroReservedBits)
    ));
    assert_eq!(
        socket.read().expect("no compressed payload was discarded"),
        Message::binary(FIRST.to_vec()),
        "the connection is untouched, so the next message decodes exactly"
    );
}

#[test]
fn a_decode_failure_ends_the_connection() {
    let mut socket = client(&[0xc2, 0x03, 0xff, 0xff, 0xff, 0xc2, 0x07]);
    assert!(matches!(
        socket.read().unwrap_err(),
        Error::Protocol(ProtocolError::Compression)
    ));
    assert!(matches!(socket.read().unwrap_err(), Error::AlreadyClosed));
    assert!(matches!(
        socket
            .write(Message::binary(b"later".to_vec()))
            .unwrap_err(),
        Error::AlreadyClosed
    ));
}

#[test]
fn an_oversized_decompressed_message_ends_the_connection_too() {
    let mut frames = vec![0xc2, 0x07];
    frames.extend_from_slice(FIRST_FRAGMENT);
    frames.extend_from_slice(LAST_FRAGMENT);
    let config = WebSocketConfig::default()
        .enable_deflate()
        .max_message_size(Some(2));
    let mut socket =
        WebSocket::from_raw_socket(Incoming(Cursor::new(frames)), Role::Client, Some(config));
    assert!(matches!(
        socket.read().unwrap_err(),
        Error::Capacity(CapacityError::MessageTooLong { .. })
    ));
    assert!(matches!(socket.read().unwrap_err(), Error::AlreadyClosed));
}

struct Wire {
    inbound: Cursor<Vec<u8>>,
    written: Vec<u8>,
    flushes: usize,
}

impl Wire {
    fn new(inbound: Vec<u8>) -> Self {
        Self {
            inbound: Cursor::new(inbound),
            written: Vec::new(),
            flushes: 0,
        }
    }
}

impl io::Read for Wire {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut self.inbound, buf)
    }
}

impl io::Write for Wire {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        Ok(())
    }
}

fn queued(inbound: Vec<u8>) -> WebSocket<Wire> {
    let config = WebSocketConfig::default()
        .enable_deflate()
        // larger than the queued frame, so `write` buffers instead of draining
        .write_buffer_size(64 * 1024);
    let mut socket = WebSocket::from_raw_socket(Wire::new(inbound), Role::Client, Some(config));
    socket
        .write(Message::binary(b"queued".to_vec()))
        .expect("the frame queues");
    assert!(
        socket.get_ref().written.is_empty(),
        "the fixture must leave the frame queued"
    );
    socket
}

fn queued_then_failed() -> WebSocket<Wire> {
    let mut socket = queued(vec![0xc2, 0x03, 0xff, 0xff, 0xff]);
    assert!(matches!(
        socket.read().unwrap_err(),
        Error::Protocol(ProtocolError::Compression)
    ));
    socket
}

fn nothing_reached_the_stream(socket: &WebSocket<Wire>) {
    assert!(
        socket.get_ref().written.is_empty(),
        "no queued byte may reach the stream"
    );
    assert_eq!(
        socket.get_ref().flushes,
        0,
        "the stream must not be flushed"
    );
}

#[test]
fn a_codec_failure_keeps_queued_bytes_out_of_flush() {
    let mut socket = queued_then_failed();
    assert!(matches!(socket.flush().unwrap_err(), Error::AlreadyClosed));
    nothing_reached_the_stream(&socket);
}

#[test]
fn a_codec_failure_keeps_queued_bytes_out_of_close() {
    let mut socket = queued_then_failed();
    assert!(matches!(
        socket.close(None).unwrap_err(),
        Error::AlreadyClosed
    ));
    nothing_reached_the_stream(&socket);
}

#[test]
fn control_the_same_queued_bytes_are_flushed_when_the_codec_is_healthy() {
    let mut socket = queued(Vec::new());
    socket.flush().expect("a healthy connection flushes");
    assert!(
        !socket.get_ref().written.is_empty(),
        "the queued frame reaches the stream"
    );
    assert_eq!(socket.get_ref().flushes, 1);
}

#[test]
fn a_caller_owned_frame_may_not_claim_rsv1_while_deflate_is_negotiated() {
    let mut socket = WebSocket::from_raw_socket(
        Incoming(Cursor::new(Vec::new())),
        Role::Server,
        Some(WebSocketConfig::default().enable_deflate()),
    );
    let mut frame = Frame::message(vec![b'x'; 4], OpCode::Data(OpData::Binary), true);
    frame.header_mut().rsv1 = true;
    assert!(matches!(
        socket.write(Message::Frame(frame)).unwrap_err(),
        Error::Protocol(ProtocolError::NonZeroReservedBits)
    ));

    let frame = Frame::message(vec![b'x'; 4], OpCode::Data(OpData::Binary), true);
    socket
        .write(Message::Frame(frame))
        .expect("an rsv1-clear raw frame still queues");
}
