use super::*;
use crate::Message;
use std::io;

#[derive(Default)]
struct Recorder(Vec<u8>);

impl io::Write for Recorder {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Read for Recorder {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

fn server() -> WebSocket<Recorder> {
    let config = WebSocketConfig::default()
        // `write_buffer_size` must exceed the first message, or `write`
        // auto-flushes it and the buffer is empty when the second arrives --
        // in which case nothing is ever rejected and every arm is vacuous.
        .write_buffer_size(400)
        .max_write_buffer_size(500)
        .enable_deflate();
    WebSocket::from_raw_socket(Recorder::default(), Role::Server, Some(config))
}

fn noise(len: usize, seed: u8) -> Vec<u8> {
    // splitmix64. A linear sequence is not incompressible -- deflate takes 300
    // bytes of `i * 37 + seed` down to 276, which would silently defeat the
    // sizing every arm depends on.
    let mut x = u64::from(seed).wrapping_add(0x9E37_79B9_7F4A_7C15);
    (0..len)
        .map(|_| {
            x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            (z ^ (z >> 31)) as u8
        })
        .collect()
}

fn decode_all(wire: &[u8]) -> Vec<Message> {
    let config = WebSocketConfig::default().enable_deflate();
    let mut peer =
        WebSocket::from_raw_socket(io::Cursor::new(wire.to_vec()), Role::Client, Some(config));
    let mut out = Vec::new();
    loop {
        match peer.read() {
            Ok(message) => out.push(message),
            Err(Error::Protocol(ProtocolError::ResetWithoutClosingHandshake)) => return out,
            Err(other) => panic!("the recorded wire failed to decode: {other:?}"),
        }
    }
}

fn reject_one(first: &[u8], second: &[u8]) -> (WebSocket<Recorder>, Frame) {
    let mut socket = server();
    socket
        .write(Message::binary(first.to_vec()))
        .expect("the first message fits");

    let returned = match socket.write(Message::binary(second.to_vec())) {
        Err(Error::WriteBufferFull(message)) => match *message {
            Message::Frame(frame) => frame,
            other => panic!("WriteBufferFull must carry a frame, got {other:?}"),
        },
        other => panic!("the second message must be rejected, got {other:?}"),
    };
    assert!(
        !returned.header().rsv1,
        "the returned frame must be uncompressed, which is what makes every retry order safe"
    );
    (socket, returned)
}

#[test]
fn arm_four_expansion_sends_plain_and_leaves_the_next_message_decodable() {
    use crate::protocol::deflate::{Context, Settings};

    let payload = noise(300, 7);
    let compressed_len = Context::new(Role::Server, Settings::default())
        .compress(&payload)
        .expect("compress")
        .len();
    assert!(
        compressed_len > payload.len(),
        "the fixture must actually expand: {} -> {compressed_len}",
        payload.len()
    );

    let plain_wire = Frame::message(payload.clone(), OpCode::Data(OpData::Binary), true).len();
    let config = WebSocketConfig::default()
        .write_buffer_size(plain_wire - 1)
        .max_write_buffer_size(plain_wire)
        .enable_deflate();
    let mut socket = WebSocket::from_raw_socket(Recorder::default(), Role::Server, Some(config));

    socket
        .write(Message::binary(payload.clone()))
        .expect("the plain frame fits, so this must not be rejected");
    socket.flush().expect("flush");

    let after_expansion = socket.get_ref().0.len();
    let first = decode_all(&socket.get_ref().0);
    assert_eq!(
        first,
        vec![Message::binary(payload.clone())],
        "the expansion branch must send the message uncompressed"
    );

    // A second message, now compressed, against a peer whose inflate window
    // never saw the first. It has to *share bytes* with the first, or the
    // encoder finds nothing to back-reference and a stale window is
    // indistinguishable from a fresh one.
    let second = payload[..120].to_vec();
    socket
        .write(Message::binary(second.clone()))
        .expect("second send");
    socket.flush().expect("flush");

    let tail = &socket.get_ref().0[after_expansion..];
    assert_eq!(
        decode_all(tail),
        vec![Message::binary(second)],
        "without the expansion reset the encoder references history the peer \
             never received, and this decodes to garbage or fails"
    );
}

#[test]
fn arm_five_a_large_compressible_message_is_rejected_on_its_plain_size() {
    let payload = vec![b'z'; 400];
    let plain_wire = Frame::message(payload.clone(), OpCode::Data(OpData::Binary), true).len();
    let compressed_len = crate::protocol::deflate::Context::new(
        Role::Server,
        crate::protocol::deflate::Settings::default(),
    )
    .compress(&payload)
    .expect("compress")
    .len();
    assert!(
        compressed_len + 4 < 200 && plain_wire > 200,
        "the fixture must straddle the cap: plain {plain_wire}, compressed {compressed_len}"
    );

    let config = WebSocketConfig::default()
        .write_buffer_size(100)
        .max_write_buffer_size(200)
        .enable_deflate();
    let mut socket = WebSocket::from_raw_socket(Recorder::default(), Role::Server, Some(config));

    match socket.write(Message::binary(payload.clone())) {
        Err(Error::WriteBufferFull(message)) => match *message {
            Message::Frame(frame) => {
                assert!(
                    !frame.header().rsv1,
                    "the returned frame must be the uncompressed one"
                )
            }
            other => panic!("must carry a frame, got {other:?}"),
        },
        other => panic!(
            "a message whose plain form exceeds the cap must be rejected even though \
                 it compresses small enough to fit -- got {other:?}"
        ),
    }
    socket.flush().expect("flush");
    assert!(
        socket.get_ref().0.is_empty(),
        "nothing may reach the wire for a rejected message"
    );
}

#[test]
fn arm_six_client_preflight_counts_the_mask_before_it_is_added() {
    let payload = vec![b'z'; 400];
    let plain = Frame::message(payload.clone(), OpCode::Data(OpData::Binary), true);
    let server_wire = wire_size(Role::Server, &plain);
    let client_wire = wire_size(Role::Client, &plain);
    assert_eq!(
        client_wire,
        server_wire + 4,
        "the fixture must isolate the mask term"
    );
    let cap = server_wire + 2;

    let config = WebSocketConfig::default()
        .write_buffer_size(100)
        .max_write_buffer_size(cap)
        .enable_deflate();
    let mut socket = WebSocket::from_raw_socket(Recorder::default(), Role::Client, Some(config));

    match socket.write(Message::binary(payload)) {
        Err(Error::WriteBufferFull(message)) => match *message {
            Message::Frame(frame) => {
                assert!(
                    !frame.header().rsv1,
                    "the returned frame must be uncompressed"
                )
            }
            other => panic!("must carry a frame, got {other:?}"),
        },
        other => panic!("the client mask makes the plain frame exceed the cap: {other:?}"),
    }
}

#[test]
fn arm_seven_client_compressed_size_counts_the_mask() {
    use crate::protocol::deflate::{Context, Settings};

    let payload = noise(300, 7);
    let compressed = Context::new(Role::Client, Settings::default())
        .compress(&payload)
        .expect("compress");
    assert!(compressed.len() > payload.len(), "the fixture must expand");

    let plain = Frame::message(payload.clone(), OpCode::Data(OpData::Binary), true);
    let mut compressed_frame = Frame::message(compressed, OpCode::Data(OpData::Binary), true);
    compressed_frame.header_mut().rsv1 = true;
    let plain_wire = wire_size(Role::Client, &plain);
    let compressed_server_wire = wire_size(Role::Server, &compressed_frame);
    let compressed_client_wire = wire_size(Role::Client, &compressed_frame);
    assert_eq!(compressed_client_wire, compressed_server_wire + 4);
    let cap = compressed_server_wire + 2;
    assert!(
        plain_wire <= cap && cap < compressed_client_wire,
        "the cap must isolate the compressed-frame mask term"
    );

    let config = WebSocketConfig::default()
        .write_buffer_size(0)
        .max_write_buffer_size(cap)
        .enable_deflate();
    let mut socket = WebSocket::from_raw_socket(Recorder::default(), Role::Client, Some(config));
    socket
        .write(Message::binary(payload.clone()))
        .expect("expansion must fall back to the plain frame");
    socket.flush().expect("flush");

    let wire = &socket.get_ref().0;
    assert_eq!(wire[0] & 0x40, 0, "the expansion branch must clear RSV1");
    let mut peer = WebSocket::from_raw_socket(
        io::Cursor::new(wire.clone()),
        Role::Server,
        Some(WebSocketConfig::default().enable_deflate()),
    );
    assert_eq!(
        peer.read().expect("peer reads the plain frame"),
        Message::binary(payload)
    );
}

#[test]
fn arm_one_immediate_retry_of_the_returned_frame() {
    let (a, b) = (noise(300, 1), noise(300, 2));
    let (mut socket, returned) = reject_one(&a, &b);
    socket.flush().expect("draining makes room");
    socket
        .write(Message::Frame(returned))
        .expect("the returned frame now fits");
    socket.flush().expect("flush");

    let decoded = decode_all(&socket.get_ref().0);
    assert_eq!(
        decoded,
        vec![Message::binary(a.clone()), Message::binary(b.clone())]
    );
}

#[test]
fn arm_two_drop_the_returned_frame_then_send_another() {
    let (a, b) = (noise(300, 1), noise(300, 2));
    let (mut socket, returned) = reject_one(&a, &b);
    drop(returned);
    socket.flush().expect("flush");
    let c = noise(150, 3);
    socket
        .write(Message::binary(c.clone()))
        .expect("a later message still sends");
    socket.flush().expect("flush");

    let decoded = decode_all(&socket.get_ref().0);
    assert_eq!(
        decoded,
        vec![Message::binary(a.clone()), Message::binary(c.clone())],
        "dropping the rejected message must not corrupt what follows"
    );
}

#[test]
fn arm_three_another_message_first_then_retry_the_returned_frame() {
    let (a, b) = (noise(300, 1), noise(300, 2));
    let (mut socket, returned) = reject_one(&a, &b);
    socket.flush().expect("flush");
    let c = noise(150, 3);
    socket
        .write(Message::binary(c.clone()))
        .expect("send an intervening message");
    socket.flush().expect("flush");
    socket
        .write(Message::Frame(returned))
        .expect("retry after C");
    socket.flush().expect("flush");

    let decoded = decode_all(&socket.get_ref().0);
    assert_eq!(
        decoded,
        vec![
            Message::binary(a.clone()),
            Message::binary(c.clone()),
            Message::binary(b.clone())
        ],
        "the returned frame is uncompressed, so an intervening compressed \
             message cannot shift its back-references"
    );
}

#[test]
fn a_rejected_client_raw_frame_is_returned_masked() {
    let frame = Frame::message(vec![b'z'; 400], OpCode::Data(OpData::Binary), true);
    let unmasked = frame.len();
    let config = WebSocketConfig::default()
        .write_buffer_size(0)
        .max_write_buffer_size(unmasked + 1)
        .enable_deflate();

    let mut server = WebSocket::from_raw_socket(Recorder::default(), Role::Server, Some(config));
    server
        .write(Message::Frame(frame.clone()))
        .expect("a server frame fits under this cap");

    let mut client = WebSocket::from_raw_socket(Recorder::default(), Role::Client, Some(config));
    match client.write(Message::Frame(frame)) {
        Err(Error::WriteBufferFull(message)) => match *message {
            Message::Frame(returned) => {
                assert!(
                    returned.header().mask.is_some(),
                    "the capacity check runs after masking, so the frame comes back masked"
                );
                assert_eq!(
                    returned.len(),
                    unmasked + 4,
                    "and it is four bytes longer than the frame handed in"
                );
            }
            other => panic!("must carry a frame, got {other:?}"),
        },
        other => panic!("the mask is what pushes this frame past the cap: {other:?}"),
    }
}
