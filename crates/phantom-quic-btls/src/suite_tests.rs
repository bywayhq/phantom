use bytes::BytesMut;

use crate::{CryptoError, HeaderProtectionKey, PacketProtectionKey};

#[test]
fn aes_256_gcm_matches_nist_known_answer() {
    // NIST GCM vector carried by pinned BoringSSL in
    // crypto/cipher/test/aes_256_gcm_tests.txt.
    let key = PacketProtectionKey::aes_256_gcm(&[0; 32], &[0; 12])
        .unwrap_or_else(|error| panic!("AES-256-GCM key failed: {error}"));
    let mut packet = [0; 32];

    key.seal(0, &mut packet, 0)
        .unwrap_or_else(|error| panic!("AES-256-GCM sealing failed: {error}"));

    assert_eq!(
        packet,
        hex::<32>(
            "cea7403d4d606b6e074ec5d3baf39d18\
             d0d1c8a799996bf0265b98b5d48ab919"
        )
    );
    let plaintext_len = key
        .open(0, &[], &mut packet)
        .unwrap_or_else(|error| panic!("AES-256-GCM opening failed: {error}"));
    assert_eq!(plaintext_len, 16);
    assert_eq!(&packet[..plaintext_len], &[0; 16]);
}

#[test]
fn aes_256_header_protection_matches_fips_197_block_vector() {
    // FIPS 197 Appendix C.3 AES-256 example. QUIC uses the first five bytes
    // of AES-ECB(sample) as its header mask.
    let key = HeaderProtectionKey::aes_256(&hex::<32>(
        "000102030405060708090a0b0c0d0e0f\
         101112131415161718191a1b1c1d1e1f",
    ))
    .unwrap_or_else(|error| panic!("AES-256 header key failed: {error}"));
    let sample = hex::<16>("00112233445566778899aabbccddeeff");
    let mut packet = vec![0x40, 0, 0, 0, 0];
    packet.extend_from_slice(&sample);

    key.protect(1, &mut packet)
        .unwrap_or_else(|error| panic!("AES-256 header protection failed: {error}"));

    let mut expected = vec![0x4e, 0xa2, 0, 0, 0];
    expected.extend_from_slice(&sample);
    assert_eq!(packet, expected);
    key.unprotect(1, &mut packet)
        .unwrap_or_else(|error| panic!("AES-256 header removal failed: {error}"));
    assert_eq!(&packet[..5], &[0x40, 0, 0, 0, 0]);
}

#[test]
fn rfc_9001_chacha_packet_and_header_are_exact_through_quinn_traits() {
    // RFC 9001 Appendix A.5.
    let packet_key = PacketProtectionKey::chacha20_poly1305(
        &hex::<32>(
            "c6d98ff3441c3fe1b2182094f69caa2e\
             d4b716b65488960a7a984979fb23e1c8",
        ),
        &hex::<12>("e0459b3474bdd0e44a41c144"),
    )
    .unwrap_or_else(|error| panic!("RFC ChaCha packet key failed: {error}"));
    let header_key = HeaderProtectionKey::chacha20(&hex::<32>(
        "25a282b9e82f06f21f488917a4fc8f1b\
         73573685608597d0efcb076b0ab7a7a4",
    ))
    .unwrap_or_else(|error| panic!("RFC ChaCha header key failed: {error}"));
    let packet_key: &dyn quinn_proto::crypto::PacketKey = &packet_key;
    let header_key: &dyn quinn_proto::crypto::HeaderKey = &header_key;
    let unprotected_header = hex::<4>("4200bff4");
    let mut packet = vec![0; unprotected_header.len() + 1 + packet_key.tag_len()];
    packet[..unprotected_header.len()].copy_from_slice(&unprotected_header);
    packet[unprotected_header.len()] = 1;

    packet_key.encrypt(654_360_564, &mut packet, unprotected_header.len());
    assert_eq!(
        &packet[unprotected_header.len()..],
        &hex::<17>("655e5cd55c41f69080575d7999c25a5bfb")
    );
    header_key.encrypt(1, &mut packet);
    assert_eq!(
        packet,
        hex::<21>("4cfe4189655e5cd55c41f69080575d7999c25a5bfb")
    );

    header_key.decrypt(1, &mut packet);
    assert_eq!(&packet[..unprotected_header.len()], &unprotected_header);
    let (_, payload) = packet.split_at(unprotected_header.len());
    let mut payload = BytesMut::from(payload);
    packet_key
        .decrypt(654_360_564, &unprotected_header, &mut payload)
        .unwrap_or_else(|_| panic!("RFC ChaCha packet decryption failed"));
    assert_eq!(payload.as_ref(), &[1]);
}

#[test]
fn aes_256_quinn_traits_round_trip_packet_and_header() {
    let packet_key = PacketProtectionKey::aes_256_gcm(&[0x11; 32], &[0x22; 12])
        .unwrap_or_else(|error| panic!("AES-256 packet key failed: {error}"));
    let header_key = HeaderProtectionKey::aes_256(&[0x33; 32])
        .unwrap_or_else(|error| panic!("AES-256 header key failed: {error}"));
    let packet_key: &dyn quinn_proto::crypto::PacketKey = &packet_key;
    let header_key: &dyn quinn_proto::crypto::HeaderKey = &header_key;
    let header = hex::<4>("4200bff4");
    let plaintext = *b"AES-256-GCM payload";
    let mut packet = vec![0; header.len() + plaintext.len() + packet_key.tag_len()];
    packet[..header.len()].copy_from_slice(&header);
    packet[header.len()..header.len() + plaintext.len()].copy_from_slice(&plaintext);

    packet_key.encrypt(654_360_564, &mut packet, header.len());
    header_key.encrypt(1, &mut packet);
    assert_ne!(&packet[..header.len()], &header);

    header_key.decrypt(1, &mut packet);
    assert_eq!(&packet[..header.len()], &header);
    let (_, payload) = packet.split_at(header.len());
    let mut payload = BytesMut::from(payload);
    packet_key
        .decrypt(654_360_564, &header, &mut payload)
        .unwrap_or_else(|_| panic!("AES-256 packet decryption failed"));
    assert_eq!(payload.as_ref(), &plaintext);
}

#[test]
fn quinn_traits_report_suite_specific_rfc_9001_limits() {
    let aes = PacketProtectionKey::aes_256_gcm(&[0; 32], &[0; 12])
        .unwrap_or_else(|error| panic!("AES-256 packet key failed: {error}"));
    let aes: &dyn quinn_proto::crypto::PacketKey = &aes;
    assert_eq!(aes.confidentiality_limit(), 1 << 23);
    assert_eq!(aes.integrity_limit(), 1 << 52);

    let chacha = PacketProtectionKey::chacha20_poly1305(&[0; 32], &[0; 12])
        .unwrap_or_else(|error| panic!("ChaCha packet key failed: {error}"));
    let chacha: &dyn quinn_proto::crypto::PacketKey = &chacha;
    assert_eq!(chacha.confidentiality_limit(), u64::MAX);
    assert_eq!(chacha.integrity_limit(), 1 << 36);
}

#[test]
fn new_suite_constructors_reject_malformed_key_iv_and_tag_lengths() {
    assert!(matches!(
        PacketProtectionKey::aes_256_gcm(&[0; 31], &[0; 12]),
        Err(CryptoError::InvalidKeyLength {
            actual: 31,
            expected: 32,
        })
    ));
    assert!(matches!(
        PacketProtectionKey::chacha20_poly1305(&[0; 31], &[0; 12]),
        Err(CryptoError::InvalidKeyLength {
            actual: 31,
            expected: 32,
        })
    ));
    assert!(matches!(
        PacketProtectionKey::aes_256_gcm(&[0; 32], &[0; 11]),
        Err(CryptoError::InvalidNonceLength {
            actual: 11,
            expected: 12,
        })
    ));
    assert!(matches!(
        PacketProtectionKey::chacha20_poly1305(&[0; 32], &[0; 11]),
        Err(CryptoError::InvalidNonceLength {
            actual: 11,
            expected: 12,
        })
    ));
    assert!(matches!(
        HeaderProtectionKey::aes_256(&[0; 31]),
        Err(CryptoError::InvalidKeyLength {
            actual: 31,
            expected: 32,
        })
    ));

    for key in [
        PacketProtectionKey::aes_256_gcm(&[0; 32], &[0; 12]),
        PacketProtectionKey::chacha20_poly1305(&[0; 32], &[0; 12]),
    ] {
        let key = key.unwrap_or_else(|error| panic!("test packet key failed: {error}"));
        let mut missing_tag = [0xab; 15];
        assert_eq!(
            key.seal(0, &mut missing_tag, 0),
            Err(CryptoError::InsufficientOutputCapacity {
                actual: 15,
                required: 16,
            })
        );
        assert_eq!(
            key.open(0, &[], &mut missing_tag),
            Err(CryptoError::InsufficientOutputCapacity {
                actual: 15,
                required: 16,
            })
        );
    }
}

#[test]
fn new_suite_authentication_failures_clear_output_and_error_queue() {
    for key in [
        PacketProtectionKey::aes_256_gcm(&[0x11; 32], &[0x22; 12]),
        PacketProtectionKey::chacha20_poly1305(&[0x33; 32], &[0x44; 12]),
    ] {
        let key = key.unwrap_or_else(|error| panic!("test packet key failed: {error}"));
        let mut payload = vec![0x55; 8 + key.tag_len()];
        key.seal(7, &mut payload, 0)
            .unwrap_or_else(|error| panic!("test packet sealing failed: {error}"));
        let last = payload.len() - 1;
        payload[last] ^= 1;

        assert_eq!(
            key.open(7, &[], &mut payload),
            Err(CryptoError::AuthenticationFailed)
        );
        assert!(payload.iter().all(|byte| *byte == 0));
        assert!(crate::backend::error_queue_is_empty());
    }
}

#[test]
fn new_suite_debug_output_redacts_key_material() {
    let aes_packet = PacketProtectionKey::aes_256_gcm(&[0x5a; 32], &[0xa5; 12])
        .unwrap_or_else(|error| panic!("AES-256 packet key failed: {error}"));
    let chacha_packet = PacketProtectionKey::chacha20_poly1305(&[0x5a; 32], &[0xa5; 12])
        .unwrap_or_else(|error| panic!("ChaCha packet key failed: {error}"));
    let aes_header = HeaderProtectionKey::aes_256(&[0x5a; 32])
        .unwrap_or_else(|error| panic!("AES-256 header key failed: {error}"));

    assert_eq!(format!("{aes_packet:?}"), "PacketProtectionKey([REDACTED])");
    assert_eq!(
        format!("{chacha_packet:?}"),
        "PacketProtectionKey([REDACTED])"
    );
    assert_eq!(format!("{aes_header:?}"), "HeaderProtectionKey([REDACTED])");
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
