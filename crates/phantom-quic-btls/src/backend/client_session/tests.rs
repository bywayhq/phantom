mod provider;
mod support;

use btls_sys as ffi;

use super::{ClientSession, ClientSessionError, HandshakeProgress, encryption_level};
use crate::backend::callback_state::{CallbackError, EncryptionLevel};
use support::*;

fn assert_send<T: Send>() {}

#[test]
fn initial_client_hello_is_flush_published_without_bio() {
    assert_send::<ClientSession>();
    let context = client_context(true);
    let mut client = session(&context);

    assert!(test_ok(client.drain_output(), "preflight output").is_empty());
    assert_eq!(
        test_ok(client.start_handshake(), "start handshake"),
        HandshakeProgress::NeedsData
    );
    assert!(client.callbacks.completed_flushes() > 0);
    let output = test_ok(client.drain_output(), "client hello");
    assert!(!output.is_empty());
    assert!(
        output
            .iter()
            .all(|chunk| chunk.level == EncryptionLevel::Initial)
    );
    assert_eq!(output[0].bytes.first(), Some(&1));
    // SAFETY: the owned SSL remains live for these read-only queries.
    assert!(unsafe { ffi::SSL_get_rbio(client.ssl.as_ptr()) }.is_null());
    // SAFETY: the owned SSL remains live for this read-only query.
    assert!(unsafe { ffi::SSL_get_wbio(client.ssl.as_ptr()) }.is_null());
}

#[test]
fn drop_releases_ssl_and_callback_owners() {
    let context = client_context(true);
    let client = session(&context);
    let retained = client.callbacks.clone();

    assert_eq!(retained.owner_count(), 3);
    drop(client);
    assert_eq!(retained.owner_count(), 1);
}

#[test]
fn disabled_peer_verification_is_rejected() {
    let context = client_context(false);
    let result = ClientSession::new(context.as_context(), SERVER_NAME, CLIENT_PARAMETERS);
    let error = match result {
        Ok(_) => panic!("verification-disabled session was accepted"),
        Err(error) => error,
    };

    assert_eq!(error, ClientSessionError::PeerVerificationDisabled);
}

#[test]
fn callback_failure_is_reported_before_backend_failure() {
    let context = client_context(true);
    let mut client = session(&context);
    client
        .callbacks
        .record_terminal(CallbackError::CallbackPanicked);

    assert_eq!(
        client.start_handshake(),
        Err(ClientSessionError::Callback(
            CallbackError::CallbackPanicked
        ))
    );
}

fn client_result_after_server_flight(
    client_context: &OwnedContext,
    server_context: &OwnedContext,
    server_name: &str,
) -> Result<HandshakeProgress, ClientSessionError> {
    let mut client =
        ClientSession::new(client_context.as_context(), server_name, CLIENT_PARAMETERS)?;
    let mut server = RawServer::new(server_context)?;
    client.start_handshake()?;
    for chunk in client.drain_output()? {
        server.provide(&chunk)?;
    }
    server.drive()?;

    let mut progress = HandshakeProgress::NeedsData;
    for chunk in server.drain_output()? {
        progress = client.provide_handshake_data(&chunk.bytes)?;
    }
    Ok(progress)
}

#[test]
fn hostname_mismatch_is_reported_as_a_tls_failure() {
    let client_context = client_context(true);
    let server_context = server_context();
    let client = ClientSession::new(
        client_context.as_context(),
        "wrong.example",
        CLIENT_PARAMETERS,
    );
    let mut client = test_ok(client, "mismatched-host client session");
    let mut server = test_ok(RawServer::new(&server_context), "server session");

    assert_eq!(
        test_ok(client.start_handshake(), "client start"),
        HandshakeProgress::NeedsData
    );
    for chunk in test_ok(client.drain_output(), "client hello") {
        test_ok(server.provide(&chunk), "server input");
    }
    assert_eq!(
        test_ok(server.drive(), "server first flight"),
        HandshakeProgress::NeedsData
    );

    let mut failure = None;
    for chunk in test_ok(server.drain_output(), "server output") {
        assert_eq!(
            test_ok(client.incoming_level(), "client inferred input level"),
            chunk.level
        );
        match client.provide_handshake_data(&chunk.bytes) {
            Ok(_) => {}
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
    }
    assert!(matches!(
        failure,
        Some(ClientSessionError::TlsFailure {
            operation: "TLS handshake",
            ..
        })
    ));
}

#[test]
fn untrusted_chain_is_reported_as_a_tls_failure() {
    let client_context = untrusted_client_context();
    let server_context = server_context();

    assert!(matches!(
        client_result_after_server_flight(&client_context, &server_context, SERVER_NAME),
        Err(ClientSessionError::TlsFailure {
            operation: "TLS handshake",
            ..
        })
    ));
}

#[test]
fn permissive_callback_cannot_override_failed_peer_verification() {
    let client_context = permissive_untrusted_client_context();
    let server_context = server_context();

    assert_eq!(
        client_result_after_server_flight(&client_context, &server_context, SERVER_NAME),
        Err(ClientSessionError::PeerVerificationFailed)
    );
}

#[test]
fn wrong_alpn_is_rejected_during_handshake() {
    let client_context = client_context(true);
    let server_context = server_context_with_wrong_alpn();

    assert!(matches!(
        client_result_after_server_flight(&client_context, &server_context, SERVER_NAME),
        Err(ClientSessionError::TlsFailure { .. }) | Err(ClientSessionError::AlpnNotNegotiated)
    ));
}

#[test]
fn fragmented_peer_input_completes_and_copies_transport_parameters() {
    let client_context = client_context(true);
    let server_context = server_context();
    let mut client = session(&client_context);
    let mut server = test_ok(RawServer::new(&server_context), "server session");

    assert_eq!(
        test_ok(client.start_handshake(), "client start"),
        HandshakeProgress::NeedsData
    );
    for chunk in test_ok(client.drain_output(), "client hello") {
        test_ok(server.provide(&chunk), "server input");
    }
    assert_eq!(
        test_ok(server.drive(), "server first flight"),
        HandshakeProgress::NeedsData
    );

    let server_flight = test_ok(server.drain_output(), "server output");
    assert!(!server_flight.is_empty());
    let mut fragments = 0;
    let mut client_progress = HandshakeProgress::NeedsData;
    for chunk in server_flight {
        let midpoint = chunk.bytes.len().div_ceil(2);
        for fragment in chunk.bytes.chunks(midpoint.max(1)) {
            fragments += 1;
            assert_eq!(
                test_ok(client.incoming_level(), "client inferred input level"),
                chunk.level
            );
            client_progress = test_ok(
                client.provide_handshake_data(fragment),
                "fragmented server input",
            );
        }
    }
    assert!(fragments > 1);
    assert_eq!(client_progress, HandshakeProgress::Complete);
    // SAFETY: the client SSL is live and its handshake completed.
    let verification = unsafe { ffi::SSL_get_verify_result(client.ssl.as_ptr()) };
    assert_eq!(verification, i64::from(ffi::X509_V_OK));

    let copied = test_ok(client.peer_transport_parameters(), "peer parameters");
    let mut copied = test_some(copied, "server parameters");
    assert_eq!(copied, SERVER_PARAMETERS);
    copied[0] ^= 0xff;
    assert_eq!(
        test_ok(client.peer_transport_parameters(), "fresh copy"),
        Some(SERVER_PARAMETERS.to_vec())
    );

    let client_finish = test_ok(client.drain_output(), "client finish");
    assert!(!client_finish.is_empty());
    for chunk in client_finish {
        test_ok(server.provide(&chunk), "server finish input");
    }
    assert_eq!(
        test_ok(server.drive(), "server completion"),
        HandshakeProgress::Complete
    );

    let post_handshake = test_ok(server.drain_output(), "server post-handshake output");
    assert!(!post_handshake.is_empty());
    for chunk in post_handshake {
        assert_eq!(chunk.level, EncryptionLevel::Application);
        assert_eq!(
            test_ok(client.incoming_level(), "post-handshake input level"),
            EncryptionLevel::Application
        );
        assert_eq!(
            test_ok(
                client.provide_handshake_data(&chunk.bytes),
                "post-handshake server input"
            ),
            HandshakeProgress::Complete
        );
    }
}

#[test]
fn unsupported_read_levels_are_rejected() {
    for raw in [
        ffi::ssl_encryption_level_t::ssl_encryption_early_data,
        ffi::ssl_encryption_level_t(99),
    ] {
        assert_eq!(
            encryption_level(raw),
            Err(CallbackError::UnsupportedEncryptionLevel { raw: raw.0 })
        );
    }
}
