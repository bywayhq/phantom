//! Hostile post-handshake input from a server whose handshake succeeded.
//!
//! Each case crafts the bytes a server would put in application-level CRYPTO
//! frames. The alert numbers are TLS AlertDescription values (RFC 8446,
//! section 6).

use super::super::{ClientSession, ClientSessionError, HandshakeProgress};
use super::support::*;
use crate::backend::callback_state::{Alert, EncryptionLevel};

const DECODE_ERROR: u8 = 50;
const ILLEGAL_PARAMETER: u8 = 47;
const UNEXPECTED_MESSAGE: u8 = 10;
const KEY_UPDATE: u8 = 24;

/// A client that authenticated its server, received no ticket yet, and
/// retains every ticket BoringSSL reports.
fn authenticated_client() -> ClientSession {
    let client_context = resumption_client_context();
    let server_context = server_context();
    let mut client = session(&client_context);
    let mut server = test_ok(RawServer::new(&server_context), "server session");
    // The server's genuine ticket is withheld so every case starts empty.
    complete_without_tickets(&mut client, &mut server);
    assert!(client.take_new_sessions().is_empty());
    client
}

/// Delivers `input` and returns the failure, the alerts the client queued,
/// and how many sessions it retained.
fn rejection(input: &[u8]) -> (ClientSessionError, Vec<Alert>, usize) {
    let mut client = authenticated_client();
    let error = match client.provide_handshake_data(input) {
        Ok(progress) => panic!("hostile post-handshake input was accepted: {progress:?}"),
        Err(error) => error,
    };
    let alerts = test_ok(client.drain_alerts(), "queued alerts");
    (error, alerts, client.take_new_sessions().len())
}

fn assert_rejected_with_alert(input: &[u8], description: u8) {
    let (error, alerts, sessions) = rejection(input);
    assert_eq!(
        error,
        ClientSessionError::BackendFailure("post-handshake processing")
    );
    assert_eq!(
        alerts,
        [Alert {
            level: EncryptionLevel::Application,
            description,
        }]
    );
    assert_eq!(sessions, 0);
}

#[test]
fn well_formed_crafted_ticket_is_retained() {
    let mut client = authenticated_client();
    let unknown = extension(0xfafa, b"ignored");
    assert_eq!(
        test_ok(
            client.provide_handshake_data(&new_session_ticket(7200, &unknown)),
            "crafted ticket"
        ),
        HandshakeProgress::Complete
    );
    assert_eq!(client.take_new_sessions().len(), 1);
}

#[test]
fn malformed_ticket_bodies_fail_with_decode_error_and_retain_nothing() {
    let valid = ticket_body(7200, &[1; 16], &[]);
    let mut trailing = valid.clone();
    trailing.push(0);
    let mut overlong_nonce = 7200_u32.to_be_bytes().to_vec();
    overlong_nonce.extend_from_slice(&[0, 0, 0, 1, 0xff, 0]);
    let mut truncated_extension = 7200_u32.to_be_bytes().to_vec();
    truncated_extension.extend_from_slice(&[0, 0, 0, 1, 0, 0, 1, 1, 0, 3, 0, 42, 0]);

    let cases: [(&str, Vec<u8>); 7] = [
        ("empty body", Vec::new()),
        ("lifetime only", 7200_u32.to_be_bytes().to_vec()),
        ("nonce longer than the body", overlong_nonce),
        ("empty ticket", ticket_body(7200, &[], &[])),
        ("trailing byte", trailing),
        ("truncated extension", truncated_extension),
        (
            "early_data extension of two bytes",
            ticket_body(7200, &[1; 16], &extension(EARLY_DATA_EXTENSION, &[0, 0])),
        ),
    ];
    for (case, body) in cases {
        let (error, alerts, sessions) = rejection(&handshake_message(NEW_SESSION_TICKET, &body));
        assert_eq!(
            error,
            ClientSessionError::BackendFailure("post-handshake processing"),
            "{case}"
        );
        assert_eq!(
            alerts.first().map(|alert| alert.description),
            Some(DECODE_ERROR),
            "{case}"
        );
        assert_eq!(sessions, 0, "{case}");
    }
}

#[test]
fn early_data_limit_other_than_the_quic_value_is_an_illegal_parameter() {
    // RFC 9001, section 4.6.1: a QUIC ticket's max_early_data_size is 0xffffffff.
    let limited = extension(EARLY_DATA_EXTENSION, &0x4000_u32.to_be_bytes());
    assert_rejected_with_alert(&new_session_ticket(7200, &limited), ILLEGAL_PARAMETER);
}

#[test]
fn duplicate_ticket_extension_is_an_illegal_parameter() {
    let early_data = extension(EARLY_DATA_EXTENSION, &u32::MAX.to_be_bytes());
    let duplicated = [early_data.clone(), early_data].concat();
    assert_rejected_with_alert(&new_session_ticket(7200, &duplicated), ILLEGAL_PARAMETER);
}

#[test]
fn key_update_and_unknown_messages_are_unexpected_after_a_quic_handshake() {
    // RFC 9001, section 6: QUIC forbids the TLS KeyUpdate message.
    assert_rejected_with_alert(&handshake_message(KEY_UPDATE, &[0]), UNEXPECTED_MESSAGE);
    // Finished, CertificateRequest, and an unassigned type.
    for message_type in [20, 13, 0xfe] {
        assert_rejected_with_alert(&handshake_message(message_type, &[]), UNEXPECTED_MESSAGE);
    }
}

#[test]
fn incomplete_message_is_buffered_only_up_to_the_flight_limit() {
    // On the QUIC path BoringSSL applies no per-message limit while a message
    // is incomplete, even for a header that promises 16 MiB; only the
    // 16 KiB bound on buffered application-level data applies.
    for promised in [[0x00, 0x4e, 0x20], [0xff, 0xff, 0xff]] {
        let mut client = authenticated_client();
        let header = [NEW_SESSION_TICKET, promised[0], promised[1], promised[2]];
        assert_eq!(
            test_ok(client.provide_handshake_data(&header), "partial header"),
            HandshakeProgress::Complete
        );
        assert_eq!(
            test_ok(
                client.provide_handshake_data(&[0; 8 * 1024]),
                "partial body"
            ),
            HandshakeProgress::Complete
        );
        assert!(client.take_new_sessions().is_empty());

        assert_eq!(
            client.provide_handshake_data(&[0; 9 * 1024]),
            Err(ClientSessionError::BackendFailure(
                "provide QUIC handshake data"
            ))
        );
        assert!(test_ok(client.drain_alerts(), "queued alerts").is_empty());
        assert!(client.take_new_sessions().is_empty());
    }
}

#[test]
fn ticket_flood_retains_only_the_newest_four_sessions() {
    let mut client = authenticated_client();
    let flood: Vec<u8> = (0..64_u32)
        .flat_map(|lifetime| new_session_ticket(3600 + lifetime, &[]))
        .collect();
    assert_eq!(
        test_ok(client.provide_handshake_data(&flood), "ticket flood"),
        HandshakeProgress::Complete
    );
    // BoringSSL caps each session's lifetime at the ticket's, which tells
    // the tickets apart.
    let lifetimes: Vec<_> = client
        .take_new_sessions()
        .iter()
        .map(|session| session.timeout())
        .collect();
    assert_eq!(lifetimes, [3660, 3661, 3662, 3663]);
}

#[test]
fn malformed_message_after_a_valid_ticket_stops_later_tickets() {
    let mut client = authenticated_client();
    let mut input = new_session_ticket(7200, &[]);
    input.extend(handshake_message(NEW_SESSION_TICKET, &[]));
    assert_eq!(
        client.provide_handshake_data(&input),
        Err(ClientSessionError::BackendFailure(
            "post-handshake processing"
        ))
    );
    // The ticket before the failure had already reached the callback; it is
    // released with the connection unless collected.
    assert_eq!(client.take_new_sessions().len(), 1);

    // BoringSSL replays the read error rather than parsing more input.
    assert!(
        client
            .provide_handshake_data(&new_session_ticket(7200, &[]))
            .is_err()
    );
    assert!(client.take_new_sessions().is_empty());
}
