use super::*;

#[test]
fn rfc_9001_chacha20_material_and_update_are_exact() {
    let secret = hex::<32>("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    let material = KeyMaterial::derive(CipherSuite::ChaCha20Poly1305Sha256, &secret)
        .unwrap_or_else(|error| panic!("RFC fixture derivation failed: {error}"));
    assert_eq!(
        &material.key.as_slice()[..material.key_len],
        &hex::<32>("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8")
    );
    assert_eq!(
        material.iv.as_slice(),
        &hex::<12>("e0459b3474bdd0e44a41c144")
    );
    assert_eq!(
        &material.header.as_slice()[..material.key_len],
        &hex::<32>("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
    );

    let traffic_secret = TrafficSecret::new(HkdfDigest::Sha256, &secret)
        .unwrap_or_else(|error| panic!("RFC fixture secret failed: {error}"));
    let next = traffic_secret
        .next()
        .unwrap_or_else(|error| panic!("RFC fixture update failed: {error}"));
    assert_eq!(
        next.as_slice(),
        &hex::<32>("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9")
    );
}

#[test]
fn sha384_material_and_repeated_updates_are_exact() {
    // RFC 8446 HKDF-Expand-Label with IKM 00..2f.
    // See docs/quic-key-schedule-fixtures.md for reproduction.
    let secret: [u8; SHA384_LEN] = core::array::from_fn(|index| index as u8);
    let material = KeyMaterial::derive(CipherSuite::Aes256GcmSha384, &secret)
        .unwrap_or_else(|error| panic!("SHA-384 fixture derivation failed: {error}"));
    assert_eq!(
        &material.key.as_slice()[..material.key_len],
        &hex::<32>("95c517eea81b6469ff8f27a065fd04c1a27b3023591b93e273a9df5f921d1f68")
    );
    assert_eq!(
        material.iv.as_slice(),
        &hex::<12>("a8d8316bf5bb0bbfa74cbf17")
    );
    assert_eq!(
        &material.header.as_slice()[..material.key_len],
        &hex::<32>("307135de335efef95873468a03d3dfa1e38050df7cc6ab7f22fd7aced73b66e5")
    );

    let initial = TrafficSecret::new(HkdfDigest::Sha384, &secret)
        .unwrap_or_else(|error| panic!("SHA-384 fixture secret failed: {error}"));
    let first = initial
        .next()
        .unwrap_or_else(|error| panic!("first SHA-384 update failed: {error}"));
    assert_eq!(
        first.as_slice(),
        &hex::<48>(
            "d21f524277390ba96b86484d9c687f850f1e4d1f997033bba06051129179a762a94067d065f3f715e83d65a7bf8c79b9"
        )
    );
    let second = first
        .next()
        .unwrap_or_else(|error| panic!("second SHA-384 update failed: {error}"));
    assert_eq!(
        second.as_slice(),
        &hex::<48>(
            "b59dc4ced911d493647f41512cc4dd23f2c923690d97a00c65a6fceb5223efb25c9ef800978182d78ffa35232acad18b"
        )
    );
}

#[test]
fn schedule_maps_client_and_server_to_local_and_remote() {
    let client_secret = [0x11; SHA256_LEN];
    let server_secret = [0x22; SHA256_LEN];
    let client = TrafficKeySchedule::new(
        TLS_CHACHA20_POLY1305_SHA256,
        EndpointSide::Client,
        &client_secret,
        &server_secret,
    )
    .unwrap_or_else(|error| panic!("client schedule failed: {error}"));
    let server = TrafficKeySchedule::new(
        TLS_CHACHA20_POLY1305_SHA256,
        EndpointSide::Server,
        &client_secret,
        &server_secret,
    )
    .unwrap_or_else(|error| panic!("server schedule failed: {error}"));

    assert_eq!(client.local.as_slice(), server.remote.as_slice());
    assert_eq!(client.remote.as_slice(), server.local.as_slice());
}

#[test]
fn schedule_rejects_unknown_suite_and_wrong_secret_length() {
    assert!(matches!(
        TrafficKeySchedule::new(0x9999, EndpointSide::Client, &[0; 32], &[0; 32]),
        Err(CryptoError::UnsupportedCipherSuite { id: 0x9999 })
    ));
    assert!(matches!(
        TrafficKeySchedule::new(
            TLS_AES_256_GCM_SHA384,
            EndpointSide::Client,
            &[0; SHA384_LEN - 1],
            &[0; SHA384_LEN],
        ),
        Err(CryptoError::InvalidKeyLength {
            actual: 47,
            expected: SHA384_LEN,
        })
    ));
}

#[test]
fn current_and_updated_keys_cover_every_tls_suite() {
    for (suite, secret_len) in [
        (TLS_AES_128_GCM_SHA256, SHA256_LEN),
        (TLS_AES_256_GCM_SHA384, SHA384_LEN),
        (TLS_CHACHA20_POLY1305_SHA256, SHA256_LEN),
    ] {
        let client = vec![0x33; secret_len];
        let server = vec![0x44; secret_len];
        let mut schedule = TrafficKeySchedule::new(suite, EndpointSide::Client, &client, &server)
            .unwrap_or_else(|error| panic!("suite 0x{suite:04x} schedule failed: {error}"));

        let keys = schedule
            .keys()
            .unwrap_or_else(|error| panic!("suite 0x{suite:04x} keys failed: {error}"));
        assert_eq!(keys.local.packet().tag_len(), 16);
        assert_eq!(keys.remote.packet().tag_len(), 16);
        let first = schedule
            .next_packet_keys()
            .unwrap_or_else(|error| panic!("suite 0x{suite:04x} first update failed: {error}"));
        assert_eq!(first.local.tag_len(), 16);
        assert_eq!(first.remote.tag_len(), 16);
        let second = schedule
            .next_packet_keys()
            .unwrap_or_else(|error| panic!("suite 0x{suite:04x} second update failed: {error}"));
        assert_eq!(second.local.tag_len(), 16);
        assert_eq!(second.remote.tag_len(), 16);
    }
}

#[test]
fn current_key_derivation_failures_preserve_secrets_and_retry_exactly() {
    for stage in [
        TestDerivationStage::CurrentLocalKeys,
        TestDerivationStage::CurrentRemoteKeys,
    ] {
        let schedule = test_schedule();
        let control = test_schedule();
        let local_before = schedule.local.as_slice().to_vec();
        let remote_before = schedule.remote.as_slice().to_vec();
        schedule.inject_derivation_failure(TestDerivationFailure::current(stage));

        assert!(matches!(
            schedule.keys(),
            Err(CryptoError::BackendFailure("injected key derivation"))
        ));
        assert_eq!(schedule.local.as_slice(), local_before);
        assert_eq!(schedule.remote.as_slice(), remote_before);

        let retry = schedule
            .keys()
            .unwrap_or_else(|error| panic!("retry after {stage:?} failed: {error}"));
        let expected = control
            .keys()
            .unwrap_or_else(|error| panic!("control derivation failed: {error}"));
        assert_direction_keys_match(&retry.local, &expected.local);
        assert_direction_keys_match(&retry.remote, &expected.remote);
    }
}

#[test]
fn update_derivation_failures_preserve_secrets_and_retry_exactly() {
    for stage in [
        TestDerivationStage::NextLocalSecret,
        TestDerivationStage::NextRemoteSecret,
        TestDerivationStage::NextLocalPacketKey,
        TestDerivationStage::NextRemotePacketKey,
    ] {
        let mut schedule = test_schedule();
        let mut control = test_schedule();
        let local_before = schedule.local.as_slice().to_vec();
        let remote_before = schedule.remote.as_slice().to_vec();
        schedule.inject_derivation_failure(TestDerivationFailure::update(stage, 1));

        assert!(matches!(
            schedule.next_packet_keys(),
            Err(CryptoError::BackendFailure("injected key derivation"))
        ));
        assert_eq!(schedule.local.as_slice(), local_before);
        assert_eq!(schedule.remote.as_slice(), remote_before);

        let retry = schedule
            .next_packet_keys()
            .unwrap_or_else(|error| panic!("retry after {stage:?} failed: {error}"));
        let expected = control
            .next_packet_keys()
            .unwrap_or_else(|error| panic!("control update failed: {error}"));
        assert_packet_keys_match(&retry.local, &expected.local);
        assert_packet_keys_match(&retry.remote, &expected.remote);
    }
}

#[test]
fn secret_owning_types_redact_debug_output() {
    let schedule = TrafficKeySchedule::new(
        TLS_AES_128_GCM_SHA256,
        EndpointSide::Client,
        &[0x11; SHA256_LEN],
        &[0x22; SHA256_LEN],
    )
    .unwrap_or_else(|error| panic!("schedule failed: {error}"));

    assert_eq!(format!("{:?}", schedule.local), "TrafficSecret([REDACTED])");
    assert_eq!(format!("{schedule:?}"), "TrafficKeySchedule([REDACTED])");
}

fn test_schedule() -> TrafficKeySchedule {
    TrafficKeySchedule::new(
        TLS_AES_128_GCM_SHA256,
        EndpointSide::Client,
        &[0x33; SHA256_LEN],
        &[0x44; SHA256_LEN],
    )
    .unwrap_or_else(|error| panic!("test schedule failed: {error}"))
}

fn assert_direction_keys_match(actual: &DirectionKeys, expected: &DirectionKeys) {
    let mut actual_header = test_header();
    let mut expected_header = actual_header.clone();
    actual
        .header()
        .protect(5, &mut actual_header)
        .unwrap_or_else(|error| panic!("actual header protection failed: {error}"));
    expected
        .header()
        .protect(5, &mut expected_header)
        .unwrap_or_else(|error| panic!("expected header protection failed: {error}"));
    assert_eq!(actual_header, expected_header);
    assert_packet_keys_match(actual.packet(), expected.packet());
}

fn assert_packet_keys_match(actual: &PacketProtectionKey, expected: &PacketProtectionKey) {
    let mut actual_packet = test_packet();
    let mut expected_packet = actual_packet.clone();
    actual
        .seal(7, &mut actual_packet, 5)
        .unwrap_or_else(|error| panic!("actual packet protection failed: {error}"));
    expected
        .seal(7, &mut expected_packet, 5)
        .unwrap_or_else(|error| panic!("expected packet protection failed: {error}"));
    assert_eq!(actual_packet, expected_packet);
}

fn test_header() -> Vec<u8> {
    (0..32).map(|value| value as u8).collect()
}

fn test_packet() -> Vec<u8> {
    let mut packet = b"headrpayload".to_vec();
    packet.extend_from_slice(&[0; 16]);
    packet
}

fn hex<const N: usize>(input: &str) -> [u8; N] {
    assert_eq!(input.len(), N * 2, "fixture has wrong encoded length");
    let mut output = [0; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let start = index * 2;
        *byte = match u8::from_str_radix(&input[start..start + 2], 16) {
            Ok(value) => value,
            Err(error) => panic!("fixture is not hexadecimal: {error}"),
        };
    }
    output
}
