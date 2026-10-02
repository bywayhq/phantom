use super::*;

#[test]
fn version_validation_happens_before_io() {
    assert_eq!(interpret_version(0x0000_0001), Ok(QuicVersion::V1));
    assert_eq!(interpret_version(0x6b33_43cf), Ok(QuicVersion::V2));
    assert_eq!(
        interpret_version(0xff00_001d),
        Err(ConnectError::UnsupportedVersion)
    );
}

#[test]
fn server_name_validation_accepts_dns_names_and_ip_literals() {
    for valid in [
        "localhost",
        "example.com",
        "EXAMPLE.COM",
        "a-b.example",
        "xn--bcher-kva.example",
        "127.0.0.1",
        "::1",
    ] {
        assert_eq!(validate_server_name_inner(valid), Ok(()));
    }
}

#[test]
fn server_name_validation_rejects_invalid_and_absolute_names() {
    for invalid in [
        "",
        "example.com.",
        "bad_name.example",
        "-bad.example",
        "bad-.example",
        "bad..example",
        "b\u{fc}cher.example",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example",
    ] {
        assert!(matches!(
            validate_server_name_inner(invalid),
            Err(InvalidServerName)
        ));
    }
}

#[test]
fn public_metadata_is_owned_and_debug_does_not_emit_certificates() {
    let handshake = HandshakeData {
        protocol: H3_PROTOCOL.to_vec(),
        peer_application_settings: Some(b"private ALPS payload".to_vec()),
        session_resumed: false,
        ech_accepted: false,
        peer_initial_max_streams_bidi: Some(100),
    };
    assert_eq!(handshake.protocol(), H3_PROTOCOL);
    assert_eq!(handshake.peer_initial_max_streams_bidi(), Some(100));
    assert_eq!(
        handshake.peer_application_settings(),
        Some(&b"private ALPS payload"[..])
    );
    let handshake_debug = format!("{handshake:?}");
    assert!(handshake_debug.contains("Some(20)"));
    assert!(!handshake_debug.contains("private"));

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
fn peer_transport_parameters_distinguish_pending_and_missing() {
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
}

#[test]
fn peer_transport_parameters_reject_malformed_wire_encodings() {
    for malformed in [
        &[0x03, 0x02, 0x44][..],
        &[0x04, 0x01, 0x40],
        &[0x04, 0x01, 0x01, 0x04, 0x01, 0x02],
        &[0x40],
        &[0x04, 0x40],
        &[0x04, 0x02, 0x01],
    ] {
        assert!(matches!(
            decode_peer_transport_parameters(Some(malformed), false),
            Err(TransportError {
                code: TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                ..
            })
        ));
    }
}

#[test]
fn peer_transport_parameter_order_does_not_change_semantics() {
    let ordered =
        decode_peer_transport_parameters(Some(&[0x04, 0x01, 0x01, 0x05, 0x01, 0x02]), false);
    let reordered =
        decode_peer_transport_parameters(Some(&[0x05, 0x01, 0x02, 0x04, 0x01, 0x01]), false);

    assert!(matches!((&ordered, &reordered), (Ok(Some(_)), Ok(Some(_)))));
    assert_eq!(ordered, reordered);
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

type FixtureResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Reads a PEM fixture that ships with the vendored btls crate.
fn btls_fixture(file: &str) -> FixtureResult<Vec<u8>> {
    Ok(std::fs::read(format!(
        "{}/../../vendor/btls/test/{file}",
        env!("CARGO_MANIFEST_DIR")
    ))?)
}

/// The DER certificate and PKCS #8 key of the btls test identity.
fn client_certificate_der() -> FixtureResult<(Vec<u8>, Vec<u8>)> {
    let certificate = X509::from_pem(&btls_fixture("cert.pem")?)?.to_der()?;
    let key = PKey::private_key_from_pem(&btls_fixture("key.pem")?)?.private_key_to_der_pkcs8()?;
    Ok((certificate, key))
}

fn assert_invalid_client_certificate(
    result: Result<QuicClientCertificate, QuicTlsProfileError>,
) -> FixtureResult {
    let error = result
        .err()
        .ok_or("an invalid client certificate was accepted")?;
    assert_eq!(error.kind(), QuicTlsProfileErrorKind::InvalidProfile);
    assert_eq!(error.field(), "client_certificate");
    Ok(())
}

#[test]
fn client_certificate_with_its_own_key_is_accepted() -> FixtureResult {
    let (certificate, key) = client_certificate_der()?;

    QuicClientCertificate::from_der([certificate.as_slice()], &key)?;
    Ok(())
}

#[test]
fn client_certificate_without_a_certificate_is_invalid() -> FixtureResult {
    let (_, key) = client_certificate_der()?;

    assert_invalid_client_certificate(QuicClientCertificate::from_der([], &key))
}

#[test]
fn client_certificate_chain_that_is_not_der_is_invalid() -> FixtureResult {
    let (certificate, key) = client_certificate_der()?;
    let pem = btls_fixture("cert.pem")?;

    assert_invalid_client_certificate(QuicClientCertificate::from_der(
        [certificate.as_slice(), pem.as_slice()],
        &key,
    ))
}

#[test]
fn client_certificate_key_that_is_not_der_is_invalid() -> FixtureResult {
    let (certificate, _) = client_certificate_der()?;
    let pem = btls_fixture("key.pem")?;

    assert_invalid_client_certificate(QuicClientCertificate::from_der(
        [certificate.as_slice()],
        &pem,
    ))
}

#[test]
fn client_certificate_with_another_certificate_s_key_is_invalid() -> FixtureResult {
    let (certificate, _) = client_certificate_der()?;
    let other_key =
        PKey::private_key_from_pem(&btls_fixture("ecdsa-key.pem")?)?.private_key_to_der_pkcs8()?;

    assert_invalid_client_certificate(QuicClientCertificate::from_der(
        [certificate.as_slice()],
        &other_key,
    ))
}
