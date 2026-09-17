use super::*;
use crate::protocol::frame::coding::{Data as OpData, OpCode};

#[test]
fn client_counts_the_mask_it_has_not_added_yet_at_every_header_boundary() {
    for (payload, header) in [(0, 2), (125, 2), (126, 4), (65_535, 4), (65_536, 10)] {
        let frame = Frame::message(vec![0u8; payload], OpCode::Data(OpData::Binary), true);
        assert!(!frame.is_masked(), "a fresh frame is unmasked");
        assert_eq!(frame.len(), header + payload, "payload {payload}");

        assert_eq!(
            wire_size(Role::Server, &frame),
            header + payload,
            "a server never masks, so wire size is the frame ({payload})"
        );
        assert_eq!(
            wire_size(Role::Client, &frame),
            header + payload + 4,
            "a client masks at buffer time, so preflight must add 4 ({payload})"
        );
    }
}
