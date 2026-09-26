//! QUIC version 2 packet protection against the RFC 9369 Appendix A vectors.

use bytes::BytesMut;
use quinn_proto::crypto::{HeaderKey as _, PacketKey as _};

use crate::{
    EndpointSide, QuicVersion, derive_initial_keys,
    key_schedule::{CipherSuite, derive_version_keys},
    verify_retry_integrity,
};

const DESTINATION_CONNECTION_ID: &str = "8394c8f03e515708";

#[test]
fn wire_numbers_round_trip() {
    for version in [QuicVersion::V1, QuicVersion::V2] {
        assert_eq!(QuicVersion::from_wire(version.wire()), Some(version));
    }
    assert_eq!(QuicVersion::V2.wire(), 0x6b33_43cf);
    assert_eq!(QuicVersion::from_wire(0xff00_001d), None);
}

#[test]
fn rfc_9369_server_initial_is_exact() {
    let destination = hex(DESTINATION_CONNECTION_ID);
    let server = derive_initial_keys(QuicVersion::V2, &destination, EndpointSide::Server)
        .unwrap_or_else(|error| panic!("RFC 9369 server derivation failed: {error}"));
    let header = hex("d16b3343cf0008f067a5502a4262b50040750001");
    let payload = hex(
        "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739\
         88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94\
         0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00\
         020304",
    );
    let expected = hex(
        "dc6b3343cf0008f067a5502a4262b5004075d92faaf16f05d8a4398c47089698\
         baeea26b91eb761d9b89237bbf87263017915358230035f7fd3945d88965cf17\
         f9af6e16886c61bfc703106fbaf3cb4cfa52382dd16a393e42757507698075b2\
         c984c707f0a0812d8cd5a6881eaf21ceda98f4bd23f6fe1a3e2c43edd9ce7ca8\
         4bed8521e2e140",
    );
    let packet_key: &dyn quinn_proto::crypto::PacketKey = server.local().packet();
    let header_key: &dyn quinn_proto::crypto::HeaderKey = server.local().header();
    let mut packet = vec![0; header.len() + payload.len() + packet_key.tag_len()];
    packet[..header.len()].copy_from_slice(&header);
    packet[header.len()..header.len() + payload.len()].copy_from_slice(&payload);

    packet_key.encrypt(1, &mut packet, header.len());
    header_key.encrypt(18, &mut packet);
    assert_eq!(packet, expected);

    let client = derive_initial_keys(QuicVersion::V2, &destination, EndpointSide::Client)
        .unwrap_or_else(|error| panic!("RFC 9369 client derivation failed: {error}"));
    client.remote().header().decrypt(18, &mut packet);
    assert_eq!(&packet[..header.len()], &header);
    let mut sealed = BytesMut::from(&packet[header.len()..]);
    client
        .remote()
        .packet()
        .decrypt(1, &header, &mut sealed)
        .unwrap_or_else(|_| panic!("RFC 9369 server Initial did not open"));
    assert_eq!(sealed.as_ref(), payload);
}

#[test]
fn rfc_9369_retry_is_authenticated_only_as_version_2() {
    let destination = hex(DESTINATION_CONNECTION_ID);
    let retry = hex("cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d955543665dcc7b6");
    assert_eq!(
        verify_retry_integrity(QuicVersion::V2, &destination, &retry).ok(),
        Some(true)
    );
    assert_ne!(
        verify_retry_integrity(QuicVersion::V1, &destination, &retry).ok(),
        Some(true)
    );
}

#[test]
fn rfc_9369_chacha20_short_header_is_exact() {
    let secret = hex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    let keys = derive_version_keys(
        CipherSuite::ChaCha20Poly1305Sha256,
        &secret,
        QuicVersion::V2,
    )
    .unwrap_or_else(|error| panic!("RFC 9369 ChaCha20 derivation failed: {error}"));
    // Packet 654360564 carries one PING frame; RFC 9369 section A.5.
    let mut packet = hex("4200bff401");
    packet.resize(packet.len() + keys.packet().tag_len(), 0);
    keys.packet().encrypt(654_360_564, &mut packet, 4);
    keys.header().encrypt(1, &mut packet);
    assert_eq!(packet, hex("5558b1c60ae7b6b932bc27d786f4bc2bb20f2162ba"));
}

fn hex(input: &str) -> Vec<u8> {
    let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    assert_eq!(compact.len() % 2, 0, "fixture has odd encoded length");
    compact
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|digits| {
            let digits = std::str::from_utf8(digits).unwrap_or_else(|_| panic!("not UTF-8"));
            u8::from_str_radix(digits, 16).unwrap_or_else(|_| panic!("not hexadecimal"))
        })
        .collect()
}
