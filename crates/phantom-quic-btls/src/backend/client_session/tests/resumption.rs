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
use crate::resumption::{MAX_APPLICATION_STATE_LEN, MAX_HELD_TICKETS};
use crate::{ApplicationState, HandshakeData, QuicClientConfig, QuicTlsProfileErrorKind};

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
    let server = test_ok(RawServer::new(server_context), "server session");
    handshake_with(start(config), server)
}

fn start(config: &Arc<QuicClientConfig>) -> Box<dyn crypto::Session> {
    test_ok(
        crypto::ClientConfig::start_session(
            Arc::clone(config),
            0x0000_0001,
            SERVER_NAME,
            &transport_parameters(),
        ),
        "Quinn client session",
    )
}

fn handshake_with(
    mut client: Box<dyn crypto::Session>,
    mut server: RawServer,
) -> Box<dyn crypto::Session> {
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
    let ticket = test_some(cache.take(SERVER_NAME), "issued ticket");
    assert!(ticket.peer_transport_parameters.is_some());
    let session = ticket.session.clone();

    // SAFETY: the session is live, and no other thread reads it while its
    // establishment time moves to the epoch.
    unsafe {
        ffi::SSL_SESSION_set_time(session.as_ptr(), 1);
    }
    // The cache discards the expired ticket instead of presenting it.
    cache.insert(SERVER_NAME, ticket);
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
            false,
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

fn accepting_handshake(
    config: &Arc<QuicClientConfig>,
    server_context: &OwnedContext,
) -> Box<dyn crypto::Session> {
    let server = test_ok(
        RawServer::new_accepting_early_data(server_context),
        "server accepting early data",
    );
    handshake_with(start(config), server)
}

#[test]
fn early_data_is_offered_only_by_an_opted_in_configuration() {
    let server_context = server_context();
    let config = resuming_config().with_isolated_session_cache();
    assert!(!config.sends_early_data());
    let early = Arc::new(config.with_early_data());
    assert!(early.sends_early_data());
    let config = Arc::new(config);
    accepting_handshake(&config, &server_context);

    // Resuming without the opt-in installs no 0-RTT keys.
    let ordinary = start(&config);
    assert!(ordinary.early_crypto().is_none());
    assert!(test_ok(ordinary.transport_parameters(), "pending parameters").is_none());
    let ordinary = handshake_with(
        ordinary,
        test_ok(
            RawServer::new_accepting_early_data(&server_context),
            "server accepting early data",
        ),
    );
    assert!(resumed(ordinary.as_ref()));
    assert_eq!(ordinary.early_data_accepted(), Some(false));

    // With the opt-in, 0-RTT keys and the issuer's remembered transport
    // parameters are available before the server's first flight.
    let client = start(&early);
    assert!(client.early_crypto().is_some());
    let remembered = test_ok(client.transport_parameters(), "remembered parameters");
    assert!(remembered.is_some());
    let server = test_ok(
        RawServer::new_accepting_early_data(&server_context),
        "server accepting early data",
    );
    let client = handshake_with(client, server);
    assert!(resumed(client.as_ref()));
    assert_eq!(client.early_data_accepted(), Some(true));
}

#[test]
fn rejected_early_data_still_completes_the_handshake() {
    let server_context = server_context();
    let config = resuming_config().with_isolated_session_cache();
    let early = Arc::new(config.with_early_data());
    accepting_handshake(&early, &server_context);

    let client = start(&early);
    assert!(client.early_crypto().is_some());
    let declining = test_ok(
        RawServer::new(&server_context),
        "server declining early data",
    );
    let client = handshake_with(client, declining);
    assert_eq!(client.early_data_accepted(), Some(false));
    assert!(client.peer_identity().is_some());
}

#[test]
fn a_ticket_without_early_data_permission_sends_none() {
    let server_context = server_context();
    let early = Arc::new(
        resuming_config()
            .with_isolated_session_cache()
            .with_early_data(),
    );
    handshake(&early, &server_context);

    let client = start(&early);
    assert!(client.early_crypto().is_none());
    let client = handshake_with(
        client,
        test_ok(RawServer::new(&server_context), "server session"),
    );
    assert!(resumed(client.as_ref()));
    assert_eq!(client.early_data_accepted(), Some(false));
}

#[test]
fn a_profile_offers_early_data_only_with_session_tickets() {
    let quic = chromium::v154_quic();
    assert!(quic.early_data);
    let offering = test_ok(
        test_ok(
            QuicClientConfig::with_transport_profile(resumption_client_context().0, quic.clone()),
            "Chrome QUIC profile",
        )
        .with_tls_profile(&resuming_tls_settings()),
        "Chrome H3 TLS profile",
    );
    assert!(offering.sends_early_data());
    assert!(!offering.without_early_data().sends_early_data());

    // Without tickets no connection resumes, so nothing could be offered.
    let ticketless = test_ok(
        test_ok(
            QuicClientConfig::with_transport_profile(resumption_client_context().0, quic),
            "Chrome QUIC profile",
        )
        .with_tls_profile(&ticketless_tls_settings()),
        "ticketless H3 TLS profile",
    );
    assert!(!ticketless.sends_early_data());
}

#[test]
fn application_state_is_stored_with_held_tickets_and_read_back_for_early_data() {
    let server_context = server_context();
    let early = resuming_config()
        .with_isolated_session_cache()
        .with_early_data();
    let learning_state = ApplicationState::new();
    let learning = Arc::new(early.with_application_state(&learning_state));
    accepting_handshake(&learning, &server_context);

    // The ticket waits for the state to keep with it.
    assert_eq!(cache_len(&early), 0);
    assert_eq!(learning_state.held_len(), 1);
    assert!(learning_state.store(b"remembered settings"));
    assert_eq!(cache_len(&early), 1);
    assert_eq!(learning_state.held_len(), 0);
    assert!(!learning_state.store(b"later settings"));

    // A sibling cache, as for another route, has neither ticket nor state.
    let sibling_state = ApplicationState::new();
    let sibling = Arc::new(
        resuming_config()
            .with_isolated_session_cache()
            .with_early_data()
            .with_application_state(&sibling_state),
    );
    let other_route = start(&sibling);
    assert!(other_route.early_crypto().is_none());
    assert_eq!(sibling_state.remembered(), None);

    let resuming_state = ApplicationState::new();
    let resuming = Arc::new(early.with_application_state(&resuming_state));
    let client = start(&resuming);
    assert!(client.early_crypto().is_some());
    assert_eq!(
        resuming_state.remembered().as_deref(),
        Some(&b"remembered settings"[..])
    );
    let client = handshake_with(
        client,
        test_ok(
            RawServer::new_accepting_early_data(&server_context),
            "server accepting early data",
        ),
    );
    assert_eq!(client.early_data_accepted(), Some(true));
}

#[test]
fn early_data_needs_a_ticket_stored_with_application_state() {
    let server_context = server_context();
    let early = resuming_config()
        .with_isolated_session_cache()
        .with_early_data();
    // A connection without a handle stores its ticket without state.
    accepting_handshake(&Arc::new(early.with_early_data()), &server_context);
    assert_eq!(cache_len(&early), 1);

    let state = ApplicationState::new();
    let client = start(&Arc::new(early.with_application_state(&state)));
    assert!(client.early_crypto().is_none());
    assert_eq!(state.remembered(), None);
    let client = handshake_with(
        client,
        test_ok(
            RawServer::new_accepting_early_data(&server_context),
            "server accepting early data",
        ),
    );
    assert!(resumed(client.as_ref()));
    assert_eq!(client.early_data_accepted(), Some(false));
}

#[test]
fn held_tickets_are_bounded_and_dropped_with_oversized_state() {
    let server_context = server_context();
    let config = resuming_config().with_isolated_session_cache();
    let full = Arc::new(config.without_ticket_offers());
    for _ in 0..3 {
        handshake(&full, &server_context);
    }
    let cache = test_some(config.session_cache(), "isolated session cache");
    let tickets: Vec<_> = (0..3)
        .map(|_| test_some(cache.take(SERVER_NAME), "retained ticket"))
        .collect();
    assert_eq!(cache.len(), 0);

    let state = ApplicationState::new();
    state.start(Some((cache.clone(), Box::from(SERVER_NAME))), None);
    for ticket in tickets.iter().cloned() {
        state.receive(ticket);
    }
    assert_eq!(state.held_len(), MAX_HELD_TICKETS);
    assert!(state.store(b"settings"));
    assert_eq!(cache.len(), MAX_HELD_TICKETS);
    let stored = test_some(cache.take(SERVER_NAME), "stored ticket");
    assert_eq!(stored.application_state.as_deref(), Some(&b"settings"[..]));

    let refused = ApplicationState::new();
    refused.start(Some((cache.clone(), Box::from(SERVER_NAME))), None);
    refused.receive(tickets[0].clone());
    assert!(!refused.store(&[0; MAX_APPLICATION_STATE_LEN + 1]));
    assert_eq!(refused.held_len(), 0);
    refused.receive(tickets[1].clone());
    assert_eq!(refused.held_len(), 0);
    assert_eq!(cache.len(), MAX_HELD_TICKETS - 1);
}
