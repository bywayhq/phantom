use super::*;

#[test]
fn tls_profile_validation_retains_the_typed_settings_error() -> FixtureResult {
    use std::error::Error as _;

    use phantom_profile::{ValidationErrorKind, browser::chrome};

    let mut settings = chrome::v154_quic_tls();
    settings.alpn_protocols.clear();

    let error = QuicClientConfig::validate_tls_profile(&settings)
        .err()
        .ok_or("TLS settings without ALPN were accepted")?;
    let source = error
        .source()
        .and_then(|source| source.downcast_ref::<InvalidTlsSettings>())
        .ok_or("the original TLS validation error was lost")?;

    assert_eq!(error.kind(), QuicTlsProfileErrorKind::InvalidProfile);
    assert_eq!(error.field(), "alpn_protocols");
    assert_eq!(source.kind(), ValidationErrorKind::Missing);
    assert_eq!(source.field(), "alpn_protocols");
    assert_eq!(source.reason(), "at least one ALPN protocol is required");
    assert_eq!(
        error.to_string(),
        "QUIC TLS profile alpn_protocols: invalid TLS alpn_protocols: at least one ALPN protocol is required"
    );
    Ok(())
}

#[test]
fn quic_version_requirement_has_no_underlying_settings_error() -> FixtureResult {
    use std::error::Error as _;

    use phantom_profile::browser::chrome;

    let settings = chrome::v154_tcp_tls();
    settings.validate()?;

    let error = QuicClientConfig::validate_tls_profile(&settings)
        .err()
        .ok_or("a TCP TLS recipe was accepted for QUIC")?;

    assert_eq!(error.kind(), QuicTlsProfileErrorKind::InvalidProfile);
    assert_eq!(error.field(), "version range");
    assert_eq!(
        error.to_string(),
        "QUIC TLS profile version range: QUIC requires an explicit TLS 1.3-only profile"
    );
    assert!(error.source().is_none());
    Ok(())
}

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
        cipher_suite: Some(0x1301),
        peer_verified: true,
        ech_accepted: false,
        peer_initial_max_streams_bidi: Some(100),
    };
    assert_eq!(handshake.protocol(), H3_PROTOCOL);
    assert_eq!(handshake.cipher_suite(), Some(0x1301));
    assert!(handshake.peer_verified());
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

fn transfer_test_config(custom_verifier: bool) -> FixtureResult<QuicClientConfig> {
    use btls::ssl::{SslMethod, SslVerifyMode};
    let mut context = SslContext::builder(SslMethod::tls())?;
    context.set_verify(SslVerifyMode::PEER);
    if custom_verifier {
        context.set_verify_callback(SslVerifyMode::PEER, |_, _| true);
    }
    QuicClientConfig::enable_session_resumption(&mut context)?;
    Ok(QuicClientConfig::new(context.build())
        .with_tls_profile(&phantom_profile::browser::chrome::v154_quic_tls())?
        .with_isolated_session_cache())
}

fn transfer_test_policy()
-> Result<btls::ssl::SessionTransferPolicy, btls::ssl::SessionTransferError> {
    btls::ssl::SessionTransferPolicy::new(b"synthetic QUIC owner policy", &[0, 0], None, &[3; 32])
}

fn transfer_test_owner(
    config: &QuicClientConfig,
) -> FixtureResult<crate::QuicSessionTicketCacheOwner> {
    config
        .session_ticket_cache()
        .and_then(|cache| cache.upgrade())
        .ok_or_else(|| "missing live QUIC ticket owner".into())
}

#[test]
fn upgraded_ticket_owner_retains_its_actual_context_until_drop() -> FixtureResult {
    let config = transfer_test_config(false)?;
    let control = config
        .session_ticket_cache()
        .ok_or("missing cache control")?;
    let owner = transfer_test_owner(&config)?;
    drop(config);
    assert!(control.is_live());
    owner.bind_transfer_policy("peer.example", transfer_test_policy()?)?;
    drop(owner);
    assert!(!control.is_live());
    Ok(())
}

#[test]
fn first_ticket_capture_prevents_late_transfer_binding() -> FixtureResult {
    let config = transfer_test_config(false)?;
    let cache = config.session_cache().ok_or("missing cache")?;
    let capture = cache.capture();
    assert!(capture.transfer_binding().is_none());
    assert!(matches!(
        transfer_test_owner(&config)?.bind_transfer_policy("peer.example", transfer_test_policy()?),
        Err(btls::ssl::SessionTransferError::Policy)
    ));
    assert!(cache.capture().transfer_binding().is_none());
    Ok(())
}

#[test]
fn repeated_bound_policy_is_captured_before_and_after_first_use() -> FixtureResult {
    let config = transfer_test_config(false)?;
    let owner = transfer_test_owner(&config)?;
    owner.bind_transfer_policy("peer.example", transfer_test_policy()?)?;
    let cache = config.session_cache().ok_or("missing cache")?;
    assert!(cache.capture().transfer_binding().is_some());
    owner.bind_transfer_policy("PEER.example", transfer_test_policy()?)?;
    assert!(cache.capture().transfer_binding().is_some());
    Ok(())
}

#[test]
fn bound_profile_and_early_data_changes_fork_without_revoking_original() -> FixtureResult {
    let config = transfer_test_config(false)?;
    let owner = transfer_test_owner(&config)?;
    owner.bind_transfer_policy("peer.example", transfer_test_policy()?)?;
    let original = config.session_cache().ok_or("missing cache")?;
    let changed = config
        .clone_with_sessions(config.sessions.clone())
        .with_tls_profile(&phantom_profile::browser::chrome::v154_quic_tls())?;
    let changed_cache = changed.session_cache().ok_or("missing changed cache")?;
    assert!(!original.shares_storage_with(changed_cache));
    assert!(!changed_cache.has_transfer_policy());
    let early = config.with_early_data();
    assert!(!original.shares_storage_with(early.session_cache().ok_or("missing early cache")?));
    assert!(
        !early
            .session_cache()
            .ok_or("missing early cache")?
            .has_transfer_policy()
    );
    let suppressed = config.without_ticket_offers().without_early_data();
    assert!(
        original.shares_storage_with(
            suppressed
                .session_cache()
                .ok_or("missing suppressed cache")?
        )
    );
    owner.bind_transfer_policy("peer.example", transfer_test_policy()?)?;
    Ok(())
}

#[test]
fn unbound_profile_and_early_data_changes_start_independent_caches() -> FixtureResult {
    let config = transfer_test_config(false)?;
    let original = config.session_cache().ok_or("missing cache")?;
    let changed = config
        .clone_with_sessions(config.sessions.clone())
        .with_tls_profile(&phantom_profile::browser::chrome::v154_quic_tls())?;
    assert!(!original.shares_storage_with(changed.session_cache().ok_or("missing changed cache")?));
    assert!(
        !original.shares_storage_with(
            config
                .with_early_data()
                .session_cache()
                .ok_or("missing early cache")?
        )
    );
    let early = config.with_early_data();
    assert!(
        early
            .session_cache()
            .ok_or("missing early cache")?
            .shares_storage_with(
                early
                    .with_early_data()
                    .session_cache()
                    .ok_or("missing repeated early cache")?
            )
    );
    Ok(())
}

#[test]
fn custom_verifier_cannot_bind_transfer_policy() -> FixtureResult {
    let config = transfer_test_config(true)?;
    assert!(matches!(
        transfer_test_owner(&config)?.bind_transfer_policy("peer.example", transfer_test_policy()?),
        Err(btls::ssl::SessionTransferError::Policy)
    ));
    Ok(())
}

#[cfg(feature = "danger-disable-verification")]
#[test]
fn per_session_disabled_authentication_cannot_bind_the_verifying_context() -> FixtureResult {
    let original = transfer_test_config(false)?;
    let disabled = original
        .clone_with_sessions(original.sessions.clone())
        .danger_disable_server_authentication();
    assert!(matches!(
        transfer_test_owner(&disabled)?
            .bind_transfer_policy("peer.example", transfer_test_policy()?),
        Err(btls::ssl::SessionTransferError::Policy)
    ));
    transfer_test_owner(&original)?
        .bind_transfer_policy("peer.example", transfer_test_policy()?)?;
    Ok(())
}

#[test]
fn captured_transfer_policy_checks_the_final_ssl_verification_mode() -> FixtureResult {
    let config = transfer_test_config(false)?;
    transfer_test_owner(&config)?.bind_transfer_policy("peer.example", transfer_test_policy()?)?;
    let capture = config.session_cache().ok_or("missing cache")?.capture();
    let result = ClientSession::new_with_profile(
        &config.context,
        "peer.example",
        &[1, 0],
        &config.tls_profile,
        ClientSessionOptions {
            session: Some(ScopedSessionOffer {
                scope: capture.scope(),
                session: None,
            }),
            transfer_binding: capture.transfer_binding(),
            verify_peer: false,
            ..ClientSessionOptions::default()
        },
    );
    assert!(matches!(
        result,
        Err(ClientSessionError::SessionTransferPolicy)
    ));
    Ok(())
}
