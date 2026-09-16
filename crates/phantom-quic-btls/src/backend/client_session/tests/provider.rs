use std::io::Cursor;
use std::sync::Arc;

use btls::x509::X509;
use phantom_profile::chromium;
use quinn_proto::crypto;
use quinn_proto::{
    ConnectError, ConnectionId, Side, TransportError, TransportErrorCode,
    transport_parameters::TransportParameters,
};

use super::super::{H3_PROTOCOL, HandshakeProgress};
use super::support::*;
use crate::backend::callback_state::EncryptionLevel;
use crate::key_schedule::{TestDerivationFailure, TestDerivationStage};
use crate::{HandshakeData, PeerIdentity, QuicClientConfig};

fn client_transport_parameters() -> TransportParameters {
    let encoded = [0x0f, 0x01, 0x01];
    test_ok(
        TransportParameters::read(Side::Server, &mut Cursor::new(encoded)),
        "client transport parameters",
    )
}

fn quinn_client_handshake(
    failure: Option<TestDerivationFailure>,
) -> Result<(Box<dyn crypto::Session>, RawServer, usize), TransportError> {
    let client_context = client_context(true);
    let server_context = server_context();
    let mut config = QuicClientConfig::new(client_context.0);
    if let Some(failure) = failure {
        config = config.with_test_derivation_failure(failure);
    }
    let config = Arc::new(config);
    let mut client = test_ok(
        crypto::ClientConfig::start_session(
            config,
            0x0000_0001,
            SERVER_NAME,
            &client_transport_parameters(),
        ),
        "Quinn client session",
    );
    let mut server = test_ok(RawServer::new(&server_context), "server session");
    let mut metadata_events = 0;

    let mut client_initial = Vec::new();
    assert!(client.write_handshake(&mut client_initial).is_none());
    assert!(!client_initial.is_empty());
    test_ok(
        server.provide_current_level(&client_initial),
        "server ClientHello input",
    );
    assert_eq!(
        test_ok(server.drive(), "server first flight"),
        HandshakeProgress::NeedsData
    );

    for chunk in test_ok(server.drain_output(), "server first flight output") {
        if client.read_handshake(&chunk.bytes)? {
            metadata_events += 1;
        }
    }

    let mut old_space = Vec::new();
    assert!(client.write_handshake(&mut old_space).is_some());
    assert!(old_space.is_empty());

    let mut client_finish = Vec::new();
    assert!(client.write_handshake(&mut client_finish).is_some());
    assert!(!client_finish.is_empty());
    test_ok(
        server.provide_current_level(&client_finish),
        "server client-finish input",
    );
    assert_eq!(
        test_ok(server.drive(), "server completion"),
        HandshakeProgress::Complete
    );

    for chunk in test_ok(server.drain_output(), "server application output") {
        assert_eq!(chunk.level, EncryptionLevel::Application);
        if client.read_handshake(&chunk.bytes)? {
            metadata_events += 1;
        }
    }
    Ok((client, server, metadata_events))
}

#[test]
fn completes_with_owned_metadata_identity_and_exporter() {
    let (mut client, server, metadata_events) =
        test_ok(quinn_client_handshake(None), "Quinn client handshake");
    assert_eq!(metadata_events, 1);
    assert!(!client.is_handshaking());

    let first = test_some(client.handshake_data(), "handshake metadata");
    let first = first
        .downcast::<HandshakeData>()
        .unwrap_or_else(|_| panic!("unexpected handshake metadata type"));
    assert_eq!(first.protocol(), H3_PROTOCOL);
    let retained = test_some(client.handshake_data(), "retained handshake metadata");
    let retained = retained
        .downcast::<HandshakeData>()
        .unwrap_or_else(|_| panic!("unexpected retained metadata type"));
    assert_eq!(retained.protocol(), H3_PROTOCOL);

    let identity = test_some(client.peer_identity(), "peer identity");
    let identity = identity
        .downcast::<PeerIdentity>()
        .unwrap_or_else(|_| panic!("unexpected peer identity type"));
    let certificate_pem = std::fs::read(format!(
        "{}/../../vendor/btls/test/cert.pem",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|error| panic!("test certificate read failed: {error}"));
    let expected = X509::from_pem(&certificate_pem)
        .unwrap_or_else(|error| panic!("test certificate parse failed: {error}"))
        .to_der()
        .unwrap_or_else(|error| panic!("test certificate encoding failed: {error}"));
    assert_eq!(identity.certificates().first(), Some(&expected));

    let peer_parameters = test_some(
        test_ok(client.transport_parameters(), "peer parameters"),
        "decoded peer parameters",
    );
    let expected_parameters = test_ok(
        TransportParameters::read(Side::Client, &mut Cursor::new(SERVER_PARAMETERS)),
        "expected peer parameters",
    );
    assert_eq!(peer_parameters, expected_parameters);

    let label = [0xff, 0x00, b'h', b'3'];
    let mut client_export = [0; 32];
    let mut server_export = [0; 32];
    test_ok(
        client.export_keying_material(&mut client_export, &label, &[]),
        "client exporter",
    );
    test_ok(
        server.export(&mut server_export, &label, &[]),
        "server exporter",
    );
    assert_eq!(client_export, server_export);

    for _ in 0..3 {
        assert!(
            test_ok(client.next_1rtt_keys(), "repeated key update").is_some(),
            "application schedule must remain available"
        );
    }
}

#[test]
fn application_key_derivation_failure_is_a_transport_error() {
    for stage in [
        TestDerivationStage::CurrentLocalKeys,
        TestDerivationStage::CurrentRemoteKeys,
    ] {
        let error = match quinn_client_handshake(Some(TestDerivationFailure::current(stage))) {
            Ok(_) => panic!("{stage:?} failure completed the handshake"),
            Err(error) => error,
        };
        assert_eq!(error.code, TransportErrorCode::INTERNAL_ERROR);
        assert_eq!(error.reason, "QUIC traffic key derivation failed");
    }
}

#[test]
fn later_key_derivation_failure_follows_a_successful_generation() {
    let failure = TestDerivationFailure::update(TestDerivationStage::NextRemotePacketKey, 2);
    let (mut client, _, _) = test_ok(
        quinn_client_handshake(Some(failure)),
        "Quinn client handshake",
    );

    assert!(
        test_ok(client.next_1rtt_keys(), "first key generation").is_some(),
        "application schedule must produce the first generation"
    );
    let error = match client.next_1rtt_keys() {
        Ok(_) => panic!("injected later key derivation failure succeeded"),
        Err(error) => error,
    };
    assert_eq!(error.code, TransportErrorCode::INTERNAL_ERROR);
    assert_eq!(error.reason, "1-RTT key update failed");
    assert!(
        test_ok(client.next_1rtt_keys(), "retry after failure").is_some(),
        "failed generation must remain retryable"
    );
}

#[test]
fn rejects_unsupported_versions_and_ip_names_before_io() {
    for (version, name, expected) in [
        (0xff00_001d, SERVER_NAME, "version"),
        (0x0000_0001, "127.0.0.1", "name"),
        (0x0000_0001, "::1", "name"),
    ] {
        let context = client_context(true);
        let result = crypto::ClientConfig::start_session(
            Arc::new(QuicClientConfig::new(context.0)),
            version,
            name,
            &client_transport_parameters(),
        );
        match expected {
            "version" => assert!(matches!(result, Err(ConnectError::UnsupportedVersion))),
            "name" => assert!(matches!(result, Err(ConnectError::InvalidServerName(_)))),
            _ => panic!("unknown expected mapping"),
        }
    }
}

#[test]
fn profiled_transport_mismatch_has_a_truthful_connect_error() {
    let context = client_context(true);
    let config = test_ok(
        QuicClientConfig::with_transport_profile(context.0, chromium::v152_macos_quic()),
        "profiled client config",
    );

    let result = crypto::ClientConfig::start_session(
        Arc::new(config),
        0x0000_0001,
        SERVER_NAME,
        &client_transport_parameters(),
    );

    assert!(matches!(
        result,
        Err(ConnectError::InvalidTransportParameters(_))
    ));
}

#[test]
fn exporter_fails_early_and_retry_is_exact() {
    let context = client_context(true);
    let mut client = test_ok(
        crypto::ClientConfig::start_session(
            Arc::new(QuicClientConfig::new(context.0)),
            0x0000_0001,
            SERVER_NAME,
            &client_transport_parameters(),
        ),
        "Quinn client session",
    );
    assert!(
        client
            .export_keying_material(&mut [0; 8], b"label", &[])
            .is_err()
    );

    let original_destination_connection_id = ConnectionId::new(&hex::<8>("8394c8f03e515708"));
    let retry_without_tag = hex::<20>("ff000000010008f067a5502a4262b5746f6b656e");
    let tag = hex::<16>("04a265ba2eff4d829058fb3f0f2496ba");
    let mut payload = retry_without_tag[7..].to_vec();
    payload.extend_from_slice(&tag);
    assert!(client.is_valid_retry(
        &original_destination_connection_id,
        &retry_without_tag[..7],
        &payload,
    ));
    let last = payload.len() - 1;
    payload[last] ^= 1;
    assert!(!client.is_valid_retry(
        &original_destination_connection_id,
        &retry_without_tag[..7],
        &payload,
    ));

    let mut initial = Vec::new();
    assert!(client.write_handshake(&mut initial).is_none());
    assert!(!initial.is_empty());
}

fn hex<const N: usize>(input: &str) -> [u8; N] {
    assert_eq!(input.len(), N * 2, "fixture has wrong encoded length");
    let mut output = [0; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&input[start..start + 2], 16)
            .unwrap_or_else(|error| panic!("fixture is not hexadecimal: {error}"));
    }
    output
}
