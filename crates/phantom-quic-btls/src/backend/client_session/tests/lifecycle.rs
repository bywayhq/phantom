//! Dropping a client mid-handshake or while holding uncollected sessions.
//!
//! Every case checks that dropping the `SSL` ran the ex-data destructor, which
//! leaves only the test's own `CallbackState` handle. Cases that offered a
//! session then resume with it again: `SSL_free` released only the `SSL`'s own
//! reference, taken by `SSL_set_session`. Under AddressSanitizer a double free
//! or a use after free on either path is reported here.

use btls::ssl::SslSession;
use btls_sys as ffi;

use super::super::{ClientSession, HandshakeProgress};
use super::support::*;
use crate::backend::callback_state::{CallbackState, EncryptionLevel, HandshakeChunk};
use crate::backend::client::ClientTlsProfile;

fn offering(context: &OwnedContext, session: &SslSession, early_data: bool) -> ClientSession {
    test_ok(
        ClientSession::new_with_profile(
            context.as_context(),
            SERVER_NAME,
            CLIENT_PARAMETERS,
            &ClientTlsProfile::default(),
            Some(session),
            early_data,
            None,
        ),
        "client offering a session",
    )
}

/// Drops `client`, asserts that its `SSL` released the callback state, and
/// returns the only remaining handle to that state.
fn drop_and_assert_released(client: ClientSession) -> CallbackState {
    let retained = client.callbacks.clone();
    assert_eq!(retained.owner_count(), 3);
    drop(client);
    assert_eq!(retained.owner_count(), 1);
    retained
}

fn assert_still_resumes(context: &OwnedContext, server: &OwnedContext, session: &SslSession) {
    let mut client = offering(context, session, false);
    let mut server = test_ok(RawServer::new(server), "server session");
    complete_without_tickets(&mut client, &mut server);
    assert!(client.session_reused());
}

fn in_early_data(client: &ClientSession) -> bool {
    // SAFETY: the client's SSL is live; the query reads handshake state only.
    unsafe { ffi::SSL_in_early_data(client.ssl.as_ptr()) != 0 }
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
    assert_eq!(retained.take_sessions().len(), 2);
}
