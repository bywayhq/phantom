//! Dropping a client mid-handshake or while holding uncollected sessions.
//!
//! Every case checks that dropping the `SSL` ran the ex-data destructor, which
//! leaves only the test's own `CallbackState` handle. Cases that offered a
//! session then resume with it again: `SSL_free` released only the `SSL`'s own
//! reference, taken by `SSL_set_session`. Under AddressSanitizer a double free
//! or a use after free on either path is reported here.

use btls::ssl::{ScopedSslSession, SslContext, SslMethod, SslRef, SslSessionScope, SslVerifyMode};
use btls_sys as ffi;
use foreign_types::ForeignTypeRef;

use super::super::{ClientSession, ClientSessionOptions, HandshakeProgress, ScopedSessionOffer};
use super::support::*;
use crate::backend::callback_state::{CallbackState, EncryptionLevel, HandshakeChunk};
use crate::backend::client::ClientTlsProfile;

fn offering(context: &OwnedContext, session: &ScopedSslSession, early_data: bool) -> ClientSession {
    test_ok(
        ClientSession::new_with_profile(
            context.as_context(),
            SERVER_NAME,
            CLIENT_PARAMETERS,
            &ClientTlsProfile::default(),
            ClientSessionOptions {
                session: Some(ScopedSessionOffer {
                    scope: context.1.clone(),
                    session: Some(session),
                }),
                early_data,
                ..ClientSessionOptions::default()
            },
        ),
        "client offering a session",
    )
}

/// Drops `client`, asserts that its `SSL` released the callback state, and
/// returns the only remaining handle to that state.
fn drop_and_assert_released(client: ClientSession) -> CallbackState {
    let retained = client.callbacks.clone();
    // SSL owns both native QUIC state and the scoped session collector.
    assert_eq!(retained.owner_count(), 4);
    drop(client);
    assert_eq!(retained.owner_count(), 1);
    retained
}

fn assert_still_resumes(context: &OwnedContext, server: &OwnedContext, session: &ScopedSslSession) {
    let mut client = offering(context, session, false);
    let mut server = test_ok(RawServer::new(server), "server session");
    complete_without_tickets(&mut client, &mut server);
    assert!(client.session_reused());
}

fn in_early_data(client: &ClientSession) -> bool {
    // SAFETY: the client's SSL is live; the query reads handshake state only.
    unsafe { ffi::SSL_in_early_data(client.ssl.as_ptr()) != 0 }
}

fn publication_authenticated(client: &ClientSession) -> bool {
    // SAFETY: the test owns the live SSL and only queries its backend proof.
    unsafe { SslRef::from_ptr(client.ssl.as_ptr()) }.authenticate_scoped_session_publication()
}

/// Starts `client`, runs `server` over its ClientHello, and returns the
/// server's first flight.
fn server_first_flight(client: &mut ClientSession, server: &mut RawServer) -> Vec<HandshakeChunk> {
    assert_eq!(
        test_ok(client.start_handshake(), "client start"),
        HandshakeProgress::NeedsData
    );
    for chunk in test_ok(client.drain_output(), "client hello") {
        test_ok(server.provide(&chunk), "server input");
    }
    test_ok(server.drive(), "server first flight");
    test_ok(server.drain_output(), "server output")
}

/// Returns the first handshake message in `bytes`.
fn first_message(bytes: &[u8]) -> &[u8] {
    let len = usize::from(bytes[1]) << 16 | usize::from(bytes[2]) << 8 | usize::from(bytes[3]);
    &bytes[..4 + len]
}

#[test]
fn drop_after_offering_a_session_leaves_the_session_resumable() {
    let client_context = resumption_client_context();
    let server_context = server_context();
    let offered = issued_session(&client_context, &server_context, false);

    drop_and_assert_released(offering(&client_context, &offered, false));

    let mut started = offering(&client_context, &offered, false);
    assert_eq!(
        test_ok(started.start_handshake(), "client start"),
        HandshakeProgress::NeedsData
    );
    drop_and_assert_released(started);

    assert_still_resumes(&client_context, &server_context, &offered);
}

#[test]
fn drop_while_sending_early_data_releases_the_client() {
    let client_context = resumption_client_context();
    let server_context = server_context();
    let offered = issued_session(&client_context, &server_context, true);

    let mut client = offering(&client_context, &offered, true);
    assert_eq!(
        test_ok(client.start_handshake(), "client start"),
        HandshakeProgress::NeedsData
    );
    assert!(in_early_data(&client));
    assert!(!publication_authenticated(&client));
    drop_and_assert_released(client);

    // The server accepted 0-RTT and its ServerHello arrived; the client is
    // still in early data when it is dropped.
    let mut client = offering(&client_context, &offered, true);
    let mut server = test_ok(
        RawServer::new_accepting_early_data(&server_context),
        "server accepting early data",
    );
    for chunk in server_first_flight(&mut client, &mut server)
        .iter()
        .filter(|chunk| chunk.level == EncryptionLevel::Initial)
    {
        test_ok(client.provide_handshake_data(&chunk.bytes), "ServerHello");
    }
    assert!(in_early_data(&client));
    assert!(client.is_handshaking());
    assert!(!publication_authenticated(&client));
    drop_and_assert_released(client);

    assert_still_resumes(&client_context, &server_context, &offered);
}

#[test]
fn drop_after_early_data_rejection_mid_handshake_releases_the_client() {
    let client_context = resumption_client_context();
    let server_context = server_context();
    let offered = issued_session(&client_context, &server_context, true);

    let mut client = offering(&client_context, &offered, true);
    let mut declining = test_ok(RawServer::new(&server_context), "server declining");
    let flight = server_first_flight(&mut client, &mut declining);
    for chunk in flight
        .iter()
        .filter(|chunk| chunk.level == EncryptionLevel::Initial)
    {
        test_ok(client.provide_handshake_data(&chunk.bytes), "ServerHello");
    }
    // EncryptedExtensions without early_data is where the client learns of
    // the rejection; the server's Finished is withheld.
    let handshake = test_some(
        flight
            .iter()
            .find(|chunk| chunk.level == EncryptionLevel::Handshake),
        "handshake-level flight",
    );
    assert_eq!(
        test_ok(
            client.provide_handshake_data(first_message(&handshake.bytes)),
            "EncryptedExtensions"
        ),
        HandshakeProgress::NeedsData
    );
    assert!(client.early_data_rejected());
    assert!(!in_early_data(&client));
    assert!(client.is_handshaking());
    drop_and_assert_released(client);

    assert_still_resumes(&client_context, &server_context, &offered);
}

#[test]
fn drop_mid_full_handshake_releases_the_client() {
    let client_context = resumption_client_context();
    let server_context = server_context();
    let mut client = session(&client_context);
    let mut server = test_ok(RawServer::new(&server_context), "server session");
    for chunk in server_first_flight(&mut client, &mut server)
        .iter()
        .filter(|chunk| chunk.level == EncryptionLevel::Initial)
    {
        test_ok(client.provide_handshake_data(&chunk.bytes), "ServerHello");
    }
    assert!(client.is_handshaking());
    drop_and_assert_released(client);
}

#[test]
fn drop_with_uncollected_tickets_releases_each_session_once() {
    let client_context = resumption_client_context();
    let server_context = server_context();
    let mut client = session(&client_context);
    let mut server = test_ok(RawServer::new(&server_context), "server session");
    for chunk in complete_without_tickets(&mut client, &mut server) {
        test_ok(client.provide_handshake_data(&chunk.bytes), "ticket input");
    }
    test_ok(
        client.provide_handshake_data(&new_session_ticket(7200, &[])),
        "crafted ticket",
    );

    let retained = drop_and_assert_released(client);
    // The sessions outlive the SSL only through the retained handle, and are
    // freed when it drops.
    let sessions = retained.take_sessions();
    assert_eq!(sessions.len(), 2);
    assert!(sessions.iter().all(ScopedSslSession::is_authenticated));
}

#[test]
fn scoped_ticket_delivery_remains_pending_until_default_authentication_completes() {
    let context = resumption_client_context();
    let server_context = server_context();
    let mut client = session(&context);
    assert!(!publication_authenticated(&client));
    assert!(client.take_new_sessions().is_empty());
    let mut server = test_ok(RawServer::new(&server_context), "server session");
    let tickets = complete_without_tickets(&mut client, &mut server);
    assert!(publication_authenticated(&client));
    assert!(client.take_new_sessions().is_empty());
    for chunk in tickets {
        test_ok(
            client.provide_handshake_data(&chunk.bytes),
            "late ticket input",
        );
    }
    let issued = client.take_new_sessions();
    assert_eq!(issued.len(), 1);
    assert!(issued[0].is_authenticated());
    drop_and_assert_released(client);
    assert!(issued[0].is_authenticated(), "the proof outlives SSL");
}

#[test]
fn resumed_scoped_publication_requires_the_authenticated_original_ticket() {
    let context = resumption_client_context();
    let server_context = server_context();
    let ticket = issued_session(&context, &server_context, true);
    assert!(ticket.is_authenticated());
    let mut client = offering(&context, &ticket, true);
    assert!(!publication_authenticated(&client));
    let mut server = test_ok(
        RawServer::new_accepting_early_data(&server_context),
        "server accepting early data",
    );
    for chunk in complete_without_tickets(&mut client, &mut server) {
        test_ok(
            client.provide_handshake_data(&chunk.bytes),
            "resumed ticket input",
        );
    }
    assert!(client.session_reused());
    assert!(publication_authenticated(&client));
    let issued = client.take_new_sessions();
    assert_eq!(issued.len(), 1);
    assert!(issued[0].is_authenticated());
    drop_and_assert_released(client);
}

#[test]
fn custom_verification_keeps_local_resumption_without_authenticated_publication() {
    let mut builder = test_ok(SslContext::builder(SslMethod::tls()), "client context");
    builder.set_verify_callback(SslVerifyMode::PEER, |_, _| true);
    test_ok(
        builder.set_ca_file(format!(
            "{}/../../vendor/btls/test/root-ca.pem",
            env!("CARGO_MANIFEST_DIR")
        )),
        "test root",
    );
    test_ok(
        crate::QuicClientConfig::enable_session_resumption(&mut builder),
        "session preparation",
    );
    let context = OwnedContext::from_context(builder.build());
    let server_context = server_context();
    let ticket = issued_session(&context, &server_context, false);
    assert!(!ticket.is_authenticated());
    let mut client = offering(&context, &ticket, false);
    let mut server = test_ok(RawServer::new(&server_context), "server session");
    complete_without_tickets(&mut client, &mut server);
    assert!(client.session_reused());
    assert!(!publication_authenticated(&client));
    drop_and_assert_released(client);
}

#[test]
fn failed_scoped_verification_publishes_no_authenticated_ticket() {
    let mut builder = test_ok(SslContext::builder(SslMethod::tls()), "client context");
    builder.set_verify(SslVerifyMode::PEER);
    test_ok(
        crate::QuicClientConfig::enable_session_resumption(&mut builder),
        "session preparation",
    );
    let context = OwnedContext::from_context(builder.build());
    let mut client = session(&context);
    let server_context = server_context();
    let mut server = test_ok(RawServer::new(&server_context), "server session");
    let flight = server_first_flight(&mut client, &mut server);
    let mut failure = None;
    for chunk in flight {
        if let Err(error) = client.provide_handshake_data(&chunk.bytes) {
            failure = Some(error);
            break;
        }
    }
    assert!(matches!(
        failure,
        Some(super::super::ClientSessionError::TlsFailure { .. })
    ));
    assert!(!publication_authenticated(&client));
    assert!(client.take_new_sessions().is_empty());
    drop_and_assert_released(client);
}

#[test]
fn scoped_offers_refuse_other_cache_context_or_server_name() {
    let context = resumption_client_context();
    let server_context = server_context();
    let ticket = issued_session(&context, &server_context, false);
    let other_context = resumption_client_context();
    for (actual_context, name, scope) in [
        (
            context.as_context(),
            SERVER_NAME,
            SslSessionScope::default(),
        ),
        (other_context.as_context(), SERVER_NAME, context.1.clone()),
        (context.as_context(), "other.example", context.1.clone()),
    ] {
        let error = ClientSession::new_with_profile(
            actual_context,
            name,
            CLIENT_PARAMETERS,
            &ClientTlsProfile::default(),
            ClientSessionOptions {
                session: Some(ScopedSessionOffer {
                    scope,
                    session: Some(&ticket),
                }),
                ..ClientSessionOptions::default()
            },
        )
        .err()
        .unwrap_or_else(|| panic!("a mismatched scoped ticket was accepted"));
        assert_eq!(
            error,
            super::super::ClientSessionError::SessionScopeMismatch
        );
    }
}

#[cfg(feature = "danger-disable-verification")]
#[test]
fn disabled_verification_keeps_local_scoped_tickets_without_authentication_proof() {
    let context = resumption_client_context();
    let server_context = server_context();
    let make_client = |ticket: Option<&ScopedSslSession>| {
        test_ok(
            ClientSession::new_with_profile(
                context.as_context(),
                "wrong.example",
                CLIENT_PARAMETERS,
                &ClientTlsProfile::default(),
                ClientSessionOptions {
                    session: Some(ScopedSessionOffer {
                        scope: context.1.clone(),
                        session: ticket,
                    }),
                    verify_peer: false,
                    ..ClientSessionOptions::default()
                },
            ),
            "verification-disabled client",
        )
    };
    let mut client = make_client(None);
    let mut server = test_ok(RawServer::new(&server_context), "server session");
    for chunk in complete_without_tickets(&mut client, &mut server) {
        test_ok(
            client.provide_handshake_data(&chunk.bytes),
            "unverified ticket input",
        );
    }
    assert!(!publication_authenticated(&client));
    let ticket = test_some(
        client.take_new_sessions().pop_front(),
        "unverified local ticket",
    );
    assert!(!ticket.is_authenticated());
    drop_and_assert_released(client);
    let mut client = make_client(Some(&ticket));
    let mut server = test_ok(RawServer::new(&server_context), "resuming server");
    for chunk in complete_without_tickets(&mut client, &mut server) {
        test_ok(
            client.provide_handshake_data(&chunk.bytes),
            "resumed unverified ticket input",
        );
    }
    assert!(client.session_reused());
    assert!(!publication_authenticated(&client));
    assert!(
        client
            .take_new_sessions()
            .iter()
            .all(|session| !session.is_authenticated())
    );
    drop_and_assert_released(client);
}
