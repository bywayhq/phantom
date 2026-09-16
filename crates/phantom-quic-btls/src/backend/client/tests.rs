use super::*;

#[test]
fn version_validation_happens_before_io() {
    assert_eq!(interpret_version(QUIC_VERSION_1), Ok(QuicVersion::V1));
    assert_eq!(
        interpret_version(0xff00_001d),
        Err(ConnectError::UnsupportedVersion)
    );
}

#[test]
fn dns_name_validation_accepts_ascii_dns_names() {
    for valid in [
        "localhost",
        "example.com",
        "EXAMPLE.COM",
        "a-b.example",
        "xn--bcher-kva.example",
    ] {
        assert_eq!(validate_dns_name(valid), Ok(()));
    }
}

#[test]
fn dns_name_validation_rejects_non_dns_and_absolute_names() {
    for invalid in [
        "",
        "127.0.0.1",
        "::1",
        "example.com.",
        "bad_name.example",
        "-bad.example",
        "bad-.example",
        "bad..example",
        "b\u{fc}cher.example",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example",
    ] {
        assert!(matches!(
            validate_dns_name(invalid),
            Err(ConnectError::InvalidServerName(_))
        ));
    }
}

#[test]
fn public_metadata_is_owned_and_debug_does_not_emit_certificates() {
    let handshake = HandshakeData {
        protocol: H3_PROTOCOL.to_vec(),
    };
    assert_eq!(handshake.protocol(), H3_PROTOCOL);

    let identity = PeerIdentity {
        certificates: vec![vec![0xde, 0xad, 0xbe, 0xef]],
    };
    assert_eq!(identity.certificates(), &[vec![0xde, 0xad, 0xbe, 0xef]]);
    let debug = format!("{identity:?}");
    assert_eq!(debug, "PeerIdentity { certificate_count: 1 }");
    assert!(!debug.contains("222"));
}

#[test]
fn outbound_flights_stay_in_their_packet_number_spaces() {
    let mut outbound = OutboundHandshake::default();
    outbound.stage(HandshakeChunk {
        level: EncryptionLevel::Handshake,
        bytes: b"handshake".to_vec(),
    });
    outbound.stage(HandshakeChunk {
        level: EncryptionLevel::Application,
        bytes: b"application".to_vec(),
    });
    outbound.stage(HandshakeChunk {
        level: EncryptionLevel::Initial,
        bytes: b"initial-a".to_vec(),
    });
    outbound.stage(HandshakeChunk {
        level: EncryptionLevel::Initial,
        bytes: b"initial-b".to_vec(),
    });

    let mut handshake_keys = Some(test_keys(1));
    let mut application_keys = Some(test_keys(2));
    let mut initial = Vec::new();
    assert!(
        outbound
            .write(&mut initial, &mut handshake_keys, &mut application_keys)
            .is_some()
    );
    assert_eq!(initial, b"initial-ainitial-b");

    let mut handshake = Vec::new();
    assert!(
        outbound
            .write(&mut handshake, &mut handshake_keys, &mut application_keys)
            .is_some()
    );
    assert_eq!(handshake, b"handshake");

    let mut application = Vec::new();
    assert!(
        outbound
            .write(&mut application, &mut handshake_keys, &mut application_keys)
            .is_none()
    );
    assert_eq!(application, b"application");
}

#[test]
fn peer_transport_parameters_distinguish_pending_missing_and_malformed() {
    assert!(matches!(
        decode_peer_transport_parameters(None, true),
        Ok(None)
    ));
    assert!(matches!(
        decode_peer_transport_parameters(None, false),
        Err(TransportError {
            code: TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
            ..
        })
    ));
    assert!(matches!(
        decode_peer_transport_parameters(Some(&[0x03, 0x02, 0x44]), false),
        Err(TransportError {
            code: TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
            ..
        })
    ));
}

fn test_keys(connection_id_byte: u8) -> Keys {
    let initial = derive_initial_keys(
        QuicVersion::V1,
        &[connection_id_byte; 8],
        EndpointSide::Client,
    )
    .unwrap_or_else(|error| panic!("test Initial keys failed: {error}"));
    initial_keys_into_quinn(initial)
}
