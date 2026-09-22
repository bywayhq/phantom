use crate::{
    CryptoError, EndpointSide, HeaderProtectionKey, PacketProtectionKey, QuicVersion,
    derive_initial_keys, retry_integrity_tag, verify_retry_integrity,
};

#[test]
fn rfc_9001_client_initial_packet_and_header_protection_are_exact() {
    let destination_connection_id = hex::<8>("8394c8f03e515708");
    let keys = derive_initial_keys(
        QuicVersion::V1,
        &destination_connection_id,
        EndpointSide::Client,
    )
    .unwrap_or_else(|error| panic!("RFC fixture derivation failed: {error}"));

    let header = hex::<22>("c300000001088394c8f03e5157080000449e00000002");
    let crypto_frame = hex::<245>(
        "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868\
         04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578\
         616d706c652e636f6dff01000100000a00080006001d00170018001000070005\
         04616c706e000500050100000000003300260024001d00209370b2c9caa47fba\
         baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400\
         0d0010000e0403050306030203080408050806002d00020101001c0002400100\
         3900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075\
         300901100f088394c8f03e51570806048000ffff",
    );
    let mut packet = vec![0; header.len() + 1_162 + keys.local().packet().tag_len()];
    packet[..header.len()].copy_from_slice(&header);
    packet[header.len()..header.len() + crypto_frame.len()].copy_from_slice(&crypto_frame);

    keys.local()
        .packet()
        .seal(2, &mut packet, header.len())
        .unwrap_or_else(|error| panic!("RFC packet protection failed: {error}"));
    assert_eq!(
        &packet[header.len()..header.len() + 16],
        &hex::<16>("d1b1c98dd7689fb8ec11d242b123dc9b")
    );

    keys.local()
        .header()
        .protect(18, &mut packet)
        .unwrap_or_else(|error| panic!("RFC header protection failed: {error}"));
    let expected = hex_vec(include_str!("../testdata/rfc9001-client-initial.hex"));
    assert_eq!(packet, expected);

    let server = derive_initial_keys(
        QuicVersion::V1,
        &destination_connection_id,
        EndpointSide::Server,
    )
    .unwrap_or_else(|error| panic!("RFC server derivation failed: {error}"));

    let mut aad_mismatch = packet.clone();
    server
        .remote()
        .header()
        .unprotect(18, &mut aad_mismatch)
        .unwrap_or_else(|error| panic!("RFC header removal failed: {error}"));
    let (mismatched_header, protected_payload) = aad_mismatch.split_at_mut(header.len());
    mismatched_header[1] ^= 1;
    assert_eq!(
        server
            .remote()
            .packet()
            .open(2, mismatched_header, protected_payload),
        Err(CryptoError::AuthenticationFailed)
    );
    assert!(crate::backend::error_queue_is_empty());

    server
        .remote()
        .header()
        .unprotect(18, &mut packet)
        .unwrap_or_else(|error| panic!("RFC header removal failed: {error}"));
    assert_eq!(&packet[..header.len()], &header);
    let (opened_header, protected_payload) = packet.split_at_mut(header.len());
    let plaintext_len = server
        .remote()
        .packet()
        .open(2, opened_header, protected_payload)
        .unwrap_or_else(|error| panic!("RFC packet opening failed: {error}"));
    assert_eq!(plaintext_len, 1_162);
    assert_eq!(&protected_payload[..crypto_frame.len()], &crypto_frame);
    assert!(
        protected_payload[crypto_frame.len()..plaintext_len]
            .iter()
            .all(|byte| *byte == 0)
    );
}

#[test]
fn rfc_9001_server_initial_packet_and_header_protection_are_exact() {
    let destination_connection_id = hex::<8>("8394c8f03e515708");
    let server = derive_initial_keys(
        QuicVersion::V1,
        &destination_connection_id,
        EndpointSide::Server,
    )
    .unwrap_or_else(|error| panic!("RFC server derivation failed: {error}"));
    let client = derive_initial_keys(
        QuicVersion::V1,
        &destination_connection_id,
        EndpointSide::Client,
    )
    .unwrap_or_else(|error| panic!("RFC client derivation failed: {error}"));

    let header = hex::<20>("c1000000010008f067a5502a4262b50040750001");
    let payload = hex::<99>(
        "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739\
         88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94\
         0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00\
         020304",
    );
    let mut packet = vec![0; header.len() + payload.len() + server.local().packet().tag_len()];
    packet[..header.len()].copy_from_slice(&header);
    packet[header.len()..header.len() + payload.len()].copy_from_slice(&payload);

    server
        .local()
        .packet()
        .seal(1, &mut packet, header.len())
        .unwrap_or_else(|error| panic!("RFC server packet protection failed: {error}"));
    assert_eq!(
        &packet[header.len() + 2..header.len() + 18],
        &hex::<16>("2cd0991cd25b0aac406a5816b6394100")
    );
    server
        .local()
        .header()
        .protect(18, &mut packet)
        .unwrap_or_else(|error| panic!("RFC server header protection failed: {error}"));
    let expected = hex_vec(include_str!("../testdata/rfc9001-server-initial.hex"));
    assert_eq!(packet, expected);

    client
        .remote()
        .header()
        .unprotect(18, &mut packet)
        .unwrap_or_else(|error| panic!("RFC server header removal failed: {error}"));
    assert_eq!(&packet[..header.len()], &header);
    let (opened_header, protected_payload) = packet.split_at_mut(header.len());
    let plaintext_len = client
        .remote()
        .packet()
        .open(1, opened_header, protected_payload)
        .unwrap_or_else(|error| panic!("RFC server packet opening failed: {error}"));
    assert_eq!(plaintext_len, payload.len());
    assert_eq!(&protected_payload[..plaintext_len], &payload);
}

#[test]
fn rfc_9001_chacha_short_header_and_three_byte_packet_number_are_exact() {
    let header_key = HeaderProtectionKey::chacha20(&hex::<32>(
        "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
    ))
    .unwrap_or_else(|error| panic!("RFC ChaCha header key failed: {error}"));
    let protected = hex::<21>("4cfe4189655e5cd55c41f69080575d7999c25a5bfb");
    let mut packet = protected;

    header_key
        .unprotect(1, &mut packet)
        .unwrap_or_else(|error| panic!("RFC short-header removal failed: {error}"));
    assert_eq!(&packet[..4], &hex::<4>("4200bff4"));
    header_key
        .protect(1, &mut packet)
        .unwrap_or_else(|error| panic!("RFC short-header protection failed: {error}"));
    assert_eq!(packet, protected);
}

#[test]
fn rfc_9001_known_mask_covers_one_and_two_byte_packet_numbers() {
    let header_key = HeaderProtectionKey::chacha20(&hex::<32>(
        "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
    ))
    .unwrap_or_else(|error| panic!("RFC ChaCha header key failed: {error}"));
    let sample = hex::<16>("5e5cd55c41f69080575d7999c25a5bfb");

    let mut one_byte = vec![0x40, 0x12, 0xaa, 0xbb, 0xcc];
    one_byte.extend_from_slice(&sample);
    header_key
        .protect(1, &mut one_byte)
        .unwrap_or_else(|error| panic!("one-byte packet number protection failed: {error}"));
    let mut expected_one = vec![0x4e, 0xec, 0xaa, 0xbb, 0xcc];
    expected_one.extend_from_slice(&sample);
    assert_eq!(one_byte, expected_one);

    let mut two_byte = vec![0x41, 0x12, 0x34, 0xbb, 0xcc];
    two_byte.extend_from_slice(&sample);
    header_key
        .protect(1, &mut two_byte)
        .unwrap_or_else(|error| panic!("two-byte packet number protection failed: {error}"));
    let mut expected_two = vec![0x4f, 0xec, 0xca, 0xbb, 0xcc];
    expected_two.extend_from_slice(&sample);
    assert_eq!(two_byte, expected_two);
}

#[test]
fn rfc_9001_retry_integrity_tag_is_exact() {
    let original_destination_connection_id = hex::<8>("8394c8f03e515708");
    let retry_without_tag = hex::<20>("ff000000010008f067a5502a4262b5746f6b656e");
    let expected_tag = hex::<16>("04a265ba2eff4d829058fb3f0f2496ba");

    let actual = retry_integrity_tag(
        QuicVersion::V1,
        &original_destination_connection_id,
        &retry_without_tag,
    )
    .unwrap_or_else(|error| panic!("RFC Retry tag failed: {error}"));
    assert_eq!(actual, expected_tag);

    let mut complete = retry_without_tag.to_vec();
    complete.extend_from_slice(&expected_tag);
    assert_eq!(
        verify_retry_integrity(
            QuicVersion::V1,
            &original_destination_connection_id,
            &complete,
        ),
        Ok(true)
    );
    let last = complete.len() - 1;
    complete[last] ^= 1;
    assert_eq!(
        verify_retry_integrity(
            QuicVersion::V1,
            &original_destination_connection_id,
            &complete,
        ),
        Ok(false)
    );
}

#[test]
fn malformed_key_nonce_sample_and_output_bounds_are_typed_errors() {
    assert!(matches!(
        HeaderProtectionKey::aes_128(&[0; 15]),
        Err(CryptoError::InvalidKeyLength {
            actual: 15,
            expected: 16
        })
    ));
    assert!(matches!(
        HeaderProtectionKey::chacha20(&[0; 31]),
        Err(CryptoError::InvalidKeyLength {
            actual: 31,
            expected: 32
        })
    ));
    assert!(matches!(
        PacketProtectionKey::aes_128_gcm(&[0; 16], &[0; 11]),
        Err(CryptoError::InvalidNonceLength {
            actual: 11,
            expected: 12
        })
    ));

    let header = HeaderProtectionKey::aes_128(&[0; 16])
        .unwrap_or_else(|error| panic!("test key initialization failed: {error}"));
    assert!(matches!(
        header.protect(0, &mut [0; 32]),
        Err(CryptoError::InvalidPacketNumberOffset { .. })
    ));
    assert!(matches!(
        header.protect(8, &mut [0; 27]),
        Err(CryptoError::InvalidSampleBounds { .. })
    ));

    let packet = PacketProtectionKey::aes_128_gcm(&[0; 16], &[0; 12])
        .unwrap_or_else(|error| panic!("test packet key initialization failed: {error}"));
    assert!(matches!(
        packet.seal(0, &mut [0; 15], 0),
        Err(CryptoError::InsufficientOutputCapacity { .. })
    ));
    assert!(matches!(
        packet.seal(0, &mut [0; 16], 17),
        Err(CryptoError::InsufficientOutputCapacity { .. })
    ));
    assert!(matches!(
        packet.open(0, &[], &mut [0; 15]),
        Err(CryptoError::InsufficientOutputCapacity { .. })
    ));
    assert!(matches!(
        derive_initial_keys(QuicVersion::V1, &[0; 21], EndpointSide::Client),
        Err(CryptoError::InvalidConnectionIdLength { .. })
    ));
}

#[test]
fn authentication_failure_is_typed_and_clears_unauthenticated_output() {
    let packet = PacketProtectionKey::aes_128_gcm(&[7; 16], &[9; 12])
        .unwrap_or_else(|error| panic!("test packet key initialization failed: {error}"));
    let header = [0xc0, 0, 0, 1];
    let mut payload = [0; 21];
    payload[..5].copy_from_slice(b"hello");
    packet
        .seal(42, &mut payload, 0)
        .unwrap_or_else(|error| panic!("test packet sealing failed: {error}"));
    payload[0] ^= 1;

    assert_eq!(
        packet.open(42, &header, &mut payload),
        Err(CryptoError::AuthenticationFailed)
    );
    assert!(payload.iter().all(|byte| *byte == 0));
}

#[test]
fn debug_output_redacts_key_material() {
    let key = hex::<16>("00112233445566778899aabbccddeeff");
    let header = HeaderProtectionKey::aes_128(&key)
        .unwrap_or_else(|error| panic!("test header key initialization failed: {error}"));
    let packet = PacketProtectionKey::aes_128_gcm(&key, &[0; 12])
        .unwrap_or_else(|error| panic!("test packet key initialization failed: {error}"));

    let header_debug = format!("{header:?}");
    let packet_debug = format!("{packet:?}");
    assert!(header_debug.contains("REDACTED"));
    assert!(packet_debug.contains("REDACTED"));
    assert!(!header_debug.contains("00112233"));
    assert!(!packet_debug.contains("00112233"));
}

fn hex<const N: usize>(input: &str) -> [u8; N] {
    let compact: String = input
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    assert_eq!(compact.len(), N * 2, "fixture has wrong encoded length");
    let mut output = [0; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let start = index * 2;
        *byte = match u8::from_str_radix(&compact[start..start + 2], 16) {
            Ok(value) => value,
            Err(error) => panic!("fixture is not hexadecimal: {error}"),
        };
    }
    output
}

fn hex_vec(input: &str) -> Vec<u8> {
    let compact: String = input
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    assert_eq!(compact.len() % 2, 0, "fixture has odd encoded length");
    compact
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|encoded| {
            let encoded = match std::str::from_utf8(encoded) {
                Ok(encoded) => encoded,
                Err(error) => panic!("fixture is not UTF-8: {error}"),
            };
            match u8::from_str_radix(encoded, 16) {
                Ok(value) => value,
                Err(error) => panic!("fixture is not hexadecimal: {error}"),
            }
        })
        .collect()
}
