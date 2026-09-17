use super::{support::Incoming, *};
use crate::error::ProtocolError;
use std::io::Cursor;

fn reads_as_reserved_bits_error(frames: &[u8], deflate: bool) {
    let config = if deflate {
        WebSocketConfig::default().enable_deflate()
    } else {
        WebSocketConfig::default()
    };
    let mut socket = WebSocket::from_raw_socket(
        Incoming(Cursor::new(frames.to_vec())),
        Role::Client,
        Some(config),
    );
    assert!(
        matches!(
            socket.read().unwrap_err(),
            Error::Protocol(ProtocolError::NonZeroReservedBits)
        ),
        "RSV1 must be rejected here"
    );
}

#[test]
fn rsv1_without_a_negotiated_extension_is_rejected() {
    reads_as_reserved_bits_error(&[0x41, 0x03, 0xf2, 0x48, 0xcd], false);
}

#[test]
fn rsv1_on_a_control_frame_is_rejected() {
    reads_as_reserved_bits_error(&[0xc9, 0x00], true);
}

#[test]
fn rsv1_on_a_continuation_frame_is_rejected() {
    reads_as_reserved_bits_error(
        &[
            0x41, 0x03, 0xf2, 0x48, 0xcd, 0xc0, 0x04, 0xc9, 0xc9, 0x07, 0x00,
        ],
        true,
    );
}

#[test]
fn control_the_same_message_without_rsv1_on_the_continuation_decodes() {
    let mut socket = WebSocket::from_raw_socket(
        Incoming(Cursor::new(vec![
            0x41, 0x03, 0xf2, 0x48, 0xcd, 0x80, 0x04, 0xc9, 0xc9, 0x07, 0x00,
        ])),
        Role::Client,
        Some(WebSocketConfig::default().enable_deflate()),
    );
    assert_eq!(
        socket.read().expect("a legal compressed message"),
        Message::text("Hello")
    );
}
