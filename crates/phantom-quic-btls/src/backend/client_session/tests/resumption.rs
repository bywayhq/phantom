use std::io::Cursor;
use std::sync::Arc;

use btls_sys as ffi;
use foreign_types::ForeignType;
use phantom_profile::chromium;
use quinn_proto::crypto;
use quinn_proto::{Side, transport_parameters::TransportParameters};

use super::super::{ClientSession, HandshakeProgress};
use super::support::*;
use crate::backend::callback_state::EncryptionLevel;
use crate::backend::client::ClientTlsProfile;
use crate::{HandshakeData, QuicClientConfig, QuicTlsProfileErrorKind};

/// A Chrome HTTP/3 TLS profile with ticket resumption enabled.
fn resuming_tls_settings() -> phantom_profile::TlsSettings {
    let mut settings = chromium::v154_http3_tls();
    settings.session_tickets = true;
    settings
}

fn ticketless_tls_settings() -> phantom_profile::TlsSettings {
    let mut settings = chromium::v154_http3_tls();
    settings.session_tickets = false;
    settings
}

fn resuming_config() -> QuicClientConfig {
    test_ok(
        QuicClientConfig::new(resumption_client_context().0)
            .with_tls_profile(&resuming_tls_settings()),
        "resuming TLS profile",
    )
}

fn transport_parameters() -> TransportParameters {
    test_ok(
        TransportParameters::read(Side::Server, &mut Cursor::new([0x0f, 0x01, 0x01])),
        "client transport parameters",
    )
}

/// Runs one complete handshake, including the server's post-handshake
/// flight that carries its NewSessionTicket, and returns the client session.
fn handshake(
    config: &Arc<QuicClientConfig>,
    server_context: &OwnedContext,
) -> Box<dyn crypto::Session> {
    let mut client = test_ok(
        crypto::ClientConfig::start_session(
            Arc::clone(config),
            0x0000_0001,
            SERVER_NAME,
            &transport_parameters(),
        ),
        "Quinn client session",
    );
    let mut server = test_ok(RawServer::new(server_context), "server session");

    let mut client_initial = Vec::new();
    assert!(client.write_handshake(&mut client_initial).is_none());
    test_ok(
        server.provide_current_level(&client_initial),
        "server ClientHello input",
    );
    assert_eq!(
        test_ok(server.drive(), "server first flight"),
        HandshakeProgress::NeedsData
    );
    for chunk in test_ok(server.drain_output(), "server first flight output") {
        test_ok(client.read_handshake(&chunk.bytes), "client first input");
    }

    let mut initial_space = Vec::new();
    assert!(client.write_handshake(&mut initial_space).is_some());
    let mut client_finish = Vec::new();
    assert!(client.write_handshake(&mut client_finish).is_some());
    test_ok(
        server.provide_current_level(&client_finish),
        "server client-finish input",
    );
    assert_eq!(
        test_ok(server.drive(), "server completion"),
        HandshakeProgress::Complete
    );
    for chunk in test_ok(server.drain_output(), "server post-handshake output") {
        assert_eq!(chunk.level, EncryptionLevel::Application);
        test_ok(client.read_handshake(&chunk.bytes), "client ticket input");
    }
    assert!(!client.is_handshaking());
    client
}

fn resumed(client: &dyn crypto::Session) -> bool {
    let data = test_some(client.handshake_data(), "handshake metadata");
    let data = data
        .downcast::<HandshakeData>()
        .unwrap_or_else(|_| panic!("handshake metadata had an unexpected type"));
    data.session_resumed()
}

fn cache_len(config: &QuicClientConfig) -> usize {
    test_some(config.session_cache(), "isolated session cache").len()
}

#[test]
fn second_handshake_resumes_with_the_ticket_from_the_first() {
    let server_context = server_context();
    let config = Arc::new(resuming_config().with_isolated_session_cache());
    assert!(config.resumes_sessions());

    let first = handshake(&config, &server_context);
    assert!(!resumed(first.as_ref()));
    assert_eq!(cache_len(&config), 1);

    let second = handshake(&config, &server_context);
    assert!(resumed(second.as_ref()));
    // The presented ticket was consumed; the resumed connection's new ticket
    // replaces it.
    assert_eq!(cache_len(&config), 1);
    assert!(second.peer_identity().is_some());
}

#[test]
fn only_isolated_configurations_retain_tickets() {
    let server_context = server_context();
    let base = Arc::new(resuming_config());
    assert!(!base.resumes_sessions());

    handshake(&base, &server_context);
    let again = handshake(&base, &server_context);
    assert!(!resumed(again.as_ref()));
}

#[test]
fn a_ticket_is_never_presented_by_a_sibling_configuration() {
    let server_context = server_context();
    let base = resuming_config();
    let learned = Arc::new(base.with_isolated_session_cache());
    let sibling = Arc::new(base.with_isolated_session_cache());
    let learned_cache = test_some(learned.session_cache(), "learned cache");
    let sibling_cache = test_some(sibling.session_cache(), "sibling cache");
    assert!(!learned_cache.shares_storage_with(sibling_cache));

    handshake(&learned, &server_context);
    assert_eq!(cache_len(&learned), 1);
    let other_route = handshake(&sibling, &server_context);
    assert!(!resumed(other_route.as_ref()));
    assert_eq!(cache_len(&learned), 1);
}

#[test]
fn a_ticket_is_presented_only_for_the_name_that_authenticated_it() {
    let server_context = server_context();
    let config = Arc::new(resuming_config().with_isolated_session_cache());
    handshake(&config, &server_context);
    let cache = test_some(config.session_cache(), "isolated session cache");

    assert!(cache.take("other.example").is_none());
    assert_eq!(cache.len(), 1);
    assert!(cache.take(&SERVER_NAME.to_ascii_uppercase()).is_some());
    assert_eq!(cache.len(), 0);
}

#[test]
fn expired_ticket_falls_back_to_a_full_handshake_without_error() {
    let server_context = server_context();
    let config = Arc::new(resuming_config().with_isolated_session_cache());
    handshake(&config, &server_context);
    let cache = test_some(config.session_cache(), "isolated session cache");
    let session = test_some(cache.take(SERVER_NAME), "issued ticket");

    // SAFETY: the test owns the only reference to this session, so moving
    // its establishment time to the epoch races with no reader.
    unsafe {
        ffi::SSL_SESSION_set_time(session.as_ptr(), 1);
    }
    // The cache discards the expired ticket instead of presenting it.
    cache.insert(SERVER_NAME, session.clone());
    assert_eq!(cache.len(), 0);
    let fallback = handshake(&config, &server_context);
    assert!(!resumed(fallback.as_ref()));

    // Offered directly, BoringSSL drops the expired ticket at ClientHello time.
    let client_context = resumption_client_context();
    let mut client = test_ok(
        ClientSession::new_with_profile(
            client_context.as_context(),
            SERVER_NAME,
            CLIENT_PARAMETERS,
            &ClientTlsProfile::default(),
            Some(&session),
        ),
        "client with expired session",
    );
    let mut server = test_ok(RawServer::new(&server_context), "server session");
    test_ok(client.start_handshake(), "client start");
    for chunk in test_ok(client.drain_output(), "client hello") {
        test_ok(server.provide(&chunk), "server input");
    }
    test_ok(server.drive(), "server first flight");
    let mut progress = HandshakeProgress::NeedsData;
    for chunk in test_ok(server.drain_output(), "server output") {
        progress = test_ok(client.provide_handshake_data(&chunk.bytes), "client input");
    }
    assert_eq!(progress, HandshakeProgress::Complete);
    assert!(!client.session_reused());
}

#[test]
fn session_tickets_require_a_prepared_context() {
    let error = QuicClientConfig::new(client_context(true).0)
        .with_tls_profile(&resuming_tls_settings())
        .err()
        .unwrap_or_else(|| panic!("an unprepared context accepted session tickets"));
    assert_eq!(error.field(), "session_tickets");
    assert_eq!(error.kind(), QuicTlsProfileErrorKind::InvalidProfile);

    let without_tickets = test_ok(
        QuicClientConfig::new(resumption_client_context().0)
            .with_tls_profile(&ticketless_tls_settings()),
        "ticketless profile on a prepared context",
    );
    assert!(
        !without_tickets
            .with_isolated_session_cache()
            .resumes_sessions()
    );
}

#[test]
fn a_full_handshake_retry_stores_tickets_without_presenting_one() {
    let server_context = server_context();
    let config = Arc::new(resuming_config().with_isolated_session_cache());
    handshake(&config, &server_context);
    assert!(config.has_ticket_for(SERVER_NAME));

    let retry = Arc::new(config.without_ticket_offers());
    assert!(!retry.has_ticket_for(SERVER_NAME));
    let full = handshake(&retry, &server_context);
    assert!(!resumed(full.as_ref()));
    // The retry neither consumed the retained ticket nor dropped its own.
    assert_eq!(cache_len(&config), 2);
    let resumed_again = handshake(&config, &server_context);
    assert!(resumed(resumed_again.as_ref()));
}
