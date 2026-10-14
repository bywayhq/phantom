use std::io::Cursor;
use std::sync::{Arc, Mutex};

use btls::hpke::HpkeKey;
use btls::ssl::{
    AlpnError, SslContext, SslContextBuilder, SslEchKeys, SslFiletype, SslMethod, SslVerifyMode,
    select_next_proto,
};
use phantom_testkit::tls::{
    ClientHelloSummary, EchOuterExtension, TEST_ECH_KEYS, ech_config, ech_config_list,
};
use quinn_proto::crypto::{self, ClientConfig as _, ServerConfig as _};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{Side, TransportError, TransportErrorCode};

use super::{QuicServerConfig, QuicServerSession, ServerHandshakeData, ServerSession, ServerState};
use crate::{EchOffer, EchOutcome, HandshakeData, QuicClientConfig, QuicVersion};

const SERVER_NAME: &str = "foobar.com";
const OTHER_PUBLIC_NAME: &str = "public.example";
const H3_WIRE: &[u8] = b"\x02h3";
/// `ech_required` (RFC 9849, section 11.2) as a QUIC crypto error.
const ECH_REQUIRED: u8 = 121;

fn test_file(name: &str) -> String {
    format!(
        "{}/../../vendor/btls/test/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn parameters(side: Side) -> TransportParameters {
    let encoded = [0x0f, 0x01, 0x01];
    TransportParameters::read(side, &mut Cursor::new(encoded))
        .unwrap_or_else(|error| panic!("test transport parameters: {error}"))
}

fn client_config() -> QuicClientConfig {
    let mut builder = SslContext::builder(SslMethod::tls())
        .unwrap_or_else(|error| panic!("client context: {error}"));
    builder.set_verify(SslVerifyMode::PEER);
    builder
        .set_ca_file(test_file("root-ca.pem"))
        .unwrap_or_else(|error| panic!("client roots: {error}"));
    QuicClientConfig::new(builder.build())
}

/// A server holding `key_index`'s ECH key under `config_id`, or no key.
fn server_config(ech: Option<(u8, usize, &str)>) -> QuicServerConfig {
    let mut builder = SslContextBuilder::new(SslMethod::tls())
        .unwrap_or_else(|error| panic!("server context: {error}"));
    builder
        .set_certificate_chain_file(test_file("cert.pem"))
        .unwrap_or_else(|error| panic!("server certificate: {error}"));
    builder
        .set_private_key_file(test_file("key.pem"), SslFiletype::PEM)
        .unwrap_or_else(|error| panic!("server key: {error}"));
    builder.set_alpn_select_callback(|_, offered| {
        select_next_proto(H3_WIRE, offered).ok_or(AlpnError::NOACK)
    });
    if let Some((config_id, key_index, public_name)) = ech {
        let key = &TEST_ECH_KEYS[key_index];
        let mut keys = SslEchKeys::builder().unwrap_or_else(|error| panic!("ECH keys: {error}"));
        keys.add_key(
            true,
            &ech_config(config_id, key, public_name),
            HpkeKey::dhkem_p256_sha256(&key.private_key)
                .unwrap_or_else(|error| panic!("ECH private key: {error}")),
        )
        .unwrap_or_else(|error| panic!("ECH key: {error}"));
        builder
            .set_ech_keys(&keys.build())
            .unwrap_or_else(|error| panic!("server ECH keys: {error}"));
    }
    QuicServerConfig::new(builder.build())
}

fn published_list(config_id: u8, key_index: usize, public_name: &str) -> Vec<u8> {
    ech_config_list(&[ech_config(
        config_id,
        &TEST_ECH_KEYS[key_index],
        public_name,
    )])
}

struct Handshake {
    client: Box<dyn crypto::Session>,
    server: Box<dyn crypto::Session>,
    client_result: Result<(), TransportError>,
}

/// Moves handshake bytes between a Quinn client and server session until
/// neither has more to send or one of them fails.
fn run(client: QuicClientConfig, server: QuicServerConfig) -> Handshake {
    let client = Arc::new(client)
        .start_session(1, SERVER_NAME, &parameters(Side::Client))
        .unwrap_or_else(|error| panic!("client session: {error}"));
    let server = Arc::new(server).start_session(1, &parameters(Side::Server));
    exchange(client, server)
}

fn exchange(
    mut client: Box<dyn crypto::Session>,
    mut server: Box<dyn crypto::Session>,
) -> Handshake {
    let mut client_result = Ok(());
    'exchange: loop {
        let mut moved = false;
        loop {
            let mut bytes = Vec::new();
            let keys = client.write_handshake(&mut bytes);
            if !bytes.is_empty() {
                moved = true;
                if let Err(error) = server.read_handshake(&bytes) {
                    panic!("server rejected client bytes: {error}");
                }
            }
            if keys.is_none() && bytes.is_empty() {
                break;
            }
        }
        loop {
            let mut bytes = Vec::new();
            let keys = server.write_handshake(&mut bytes);
            if !bytes.is_empty() {
                moved = true;
                if let Err(error) = client.read_handshake(&bytes) {
                    client_result = Err(error);
                    break 'exchange;
                }
            }
            if keys.is_none() && bytes.is_empty() {
                break;
            }
        }
        if !moved {
            break;
        }
    }
    Handshake {
        client,
        server,
        client_result,
    }
}

fn server_data(session: &dyn crypto::Session) -> ServerHandshakeData {
    *session
        .handshake_data()
        .unwrap_or_else(|| panic!("server handshake data"))
        .downcast::<ServerHandshakeData>()
        .unwrap_or_else(|_| panic!("server handshake data type"))
}

fn client_data(session: &dyn crypto::Session) -> HandshakeData {
    *session
        .handshake_data()
        .unwrap_or_else(|| panic!("client handshake data"))
        .downcast::<HandshakeData>()
        .unwrap_or_else(|_| panic!("client handshake data type"))
}

fn outer_extension(client_hello: &[u8]) -> Option<EchOuterExtension> {
    let summary = ClientHelloSummary::from_handshake_bytes(client_hello)
        .unwrap_or_else(|error| panic!("server saw no ClientHello: {error:?}"));
    summary
        .encrypted_client_hello()
        .and_then(EchOuterExtension::parse)
}

#[test]
fn accepted_ech_carries_the_inner_name_to_the_server() {
    let list = published_list(1, 0, OTHER_PUBLIC_NAME);
    let offer = EchOffer::new(&list);
    let handshake = run(
        client_config().with_ech(&offer),
        server_config(Some((1, 0, OTHER_PUBLIC_NAME))),
    );
    assert_eq!(handshake.client_result, Ok(()));
    assert!(!handshake.client.is_handshaking());
    assert!(!handshake.server.is_handshaking());
    assert_eq!(offer.outcome(), Some(EchOutcome::Accepted));
    assert!(client_data(&*handshake.client).ech_accepted());

    let server = server_data(&*handshake.server);
    assert!(server.ech_accepted());
    assert_eq!(server.server_name(), Some(SERVER_NAME));
    assert_eq!(server.protocol(), b"h3");
    let outer = outer_extension(server.client_hello())
        .unwrap_or_else(|| panic!("outer ClientHello has no ECH extension"));
    assert_eq!(outer.config_id, 1);
    assert_eq!(outer.enc_length, 32);
}

#[test]
fn rejected_ech_reports_the_retry_configurations() {
    // The server holds the second key under config ID 2; the client offers
    // the first under config ID 1. Both name the certificate's own name, so
    // the rejection authenticates.
    let offer = EchOffer::new(&published_list(1, 0, SERVER_NAME));
    let handshake = run(
        client_config().with_ech(&offer),
        server_config(Some((2, 1, SERVER_NAME))),
    );
    let error = handshake
        .client_result
        .err()
        .unwrap_or_else(|| panic!("a rejected ECH offer fails the handshake"));
    assert_eq!(error.code, TransportErrorCode::crypto(ECH_REQUIRED));
    let server = server_data(&*handshake.server);
    assert!(!server.ech_accepted());
    assert_eq!(server.server_name(), Some(SERVER_NAME));
    assert_eq!(
        offer.outcome(),
        Some(EchOutcome::Rejected {
            retry_configs: Some(published_list(2, 1, SERVER_NAME).into_boxed_slice()),
        })
    );

    // A connection offering the retry configuration is accepted.
    let retry = EchOffer::new(&published_list(2, 1, SERVER_NAME));
    let handshake = run(
        client_config().with_ech(&retry),
        server_config(Some((2, 1, SERVER_NAME))),
    );
    assert_eq!(handshake.client_result, Ok(()));
    assert_eq!(retry.outcome(), Some(EchOutcome::Accepted));
}

#[test]
fn server_without_ech_keys_rejects_without_retry_configurations() {
    let offer = EchOffer::new(&published_list(1, 0, SERVER_NAME));
    let handshake = run(client_config().with_ech(&offer), server_config(None));
    let error = handshake
        .client_result
        .err()
        .unwrap_or_else(|| panic!("a rejected ECH offer fails the handshake"));
    assert_eq!(error.code, TransportErrorCode::crypto(ECH_REQUIRED));
    assert_eq!(
        offer.outcome(),
        Some(EchOutcome::Rejected {
            retry_configs: None
        })
    );
}

#[test]
fn rejection_by_a_certificate_without_the_public_name_is_not_an_ech_outcome() {
    // The certificate covers `foobar.com` but not the public name, so the
    // rejection cannot authenticate and verification fails first.
    let offer = EchOffer::new(&published_list(1, 0, OTHER_PUBLIC_NAME));
    let handshake = run(
        client_config().with_ech(&offer),
        server_config(Some((2, 1, OTHER_PUBLIC_NAME))),
    );
    let error = handshake
        .client_result
        .err()
        .unwrap_or_else(|| panic!("an unauthenticated rejection fails the handshake"));
    assert_ne!(error.code, TransportErrorCode::crypto(ECH_REQUIRED));
    assert_eq!(offer.outcome(), None);
}

#[test]
fn a_list_boringssl_refuses_fails_before_any_byte() {
    let offer = EchOffer::new(&[0x00, 0x03, 0xfe, 0x0d, 0x00]);
    let result = Arc::new(client_config().with_ech(&offer)).start_session(
        1,
        SERVER_NAME,
        &parameters(Side::Client),
    );
    assert!(result.is_err());
    assert_eq!(offer.outcome(), Some(EchOutcome::InvalidConfigList));
}

#[test]
fn without_an_offer_the_server_sees_the_true_name() {
    let handshake = run(client_config(), server_config(Some((1, 0, SERVER_NAME))));
    assert_eq!(handshake.client_result, Ok(()));
    let server = server_data(&*handshake.server);
    assert!(!server.ech_accepted());
    assert_eq!(server.server_name(), Some(SERVER_NAME));
    assert!(!client_data(&*handshake.client).ech_accepted());
    assert!(outer_extension(server.client_hello()).is_none());
}

/// Transport parameters BoringSSL could not carry fail the session before any
/// FFI call, and the failed session ends the connection with
/// `INTERNAL_ERROR` on its first input instead of reaching BoringSSL.
#[test]
fn a_session_that_fails_to_start_closes_on_its_first_input() {
    let context = SslContextBuilder::new(SslMethod::tls())
        .unwrap_or_else(|error| panic!("server context: {error}"))
        .build();
    let oversized = vec![0; usize::from(u16::MAX) + 1];
    let error = ServerSession::new(&context, &oversized, None)
        .err()
        .unwrap_or_else(|| panic!("oversized transport parameters were accepted"));
    assert_eq!(error, "server transport parameters too long");

    let mut session = QuicServerSession {
        state: Mutex::new(ServerState::new(QuicVersion::V1, Err(error))),
    };
    assert!(crypto::Session::is_handshaking(&session));
    let error = crypto::Session::read_handshake(&mut session, &[1, 0, 0, 0])
        .err()
        .unwrap_or_else(|| panic!("a failed session read handshake data"));
    assert_eq!(error.code, TransportErrorCode::INTERNAL_ERROR);
    assert!(crypto::Session::handshake_data(&session).is_none());
    let mut output = [0; 16];
    assert!(crypto::Session::export_keying_material(&session, &mut output, b"label", b"").is_err());
}

/// A context without a certificate fails the server handshake with the TLS
/// alert BoringSSL chose, carried as a QUIC crypto error.
#[test]
fn a_server_without_a_certificate_fails_with_a_crypto_error() {
    let mut builder = SslContextBuilder::new(SslMethod::tls())
        .unwrap_or_else(|error| panic!("server context: {error}"));
    builder.set_alpn_select_callback(|_, offered| {
        select_next_proto(H3_WIRE, offered).ok_or(AlpnError::NOACK)
    });
    let server = QuicServerConfig::new(builder.build());
    let mut client = Arc::new(client_config())
        .start_session(1, SERVER_NAME, &parameters(Side::Client))
        .unwrap_or_else(|error| panic!("client session: {error}"));
    let mut session = Arc::new(server).start_session(1, &parameters(Side::Server));
    let mut hello = Vec::new();
    let _ = client.write_handshake(&mut hello);
    let error = session
        .read_handshake(&hello)
        .err()
        .unwrap_or_else(|| panic!("a server without a certificate completed"));
    let code = u64::from(error.code);
    assert!((0x100..0x200).contains(&code), "{error:?}");
    assert!(session.is_handshaking());
}

fn resuming_client() -> QuicClientConfig {
    let mut builder = SslContext::builder(SslMethod::tls())
        .unwrap_or_else(|error| panic!("client context: {error}"));
    builder.set_verify(SslVerifyMode::PEER);
    builder
        .set_ca_file(test_file("root-ca.pem"))
        .unwrap_or_else(|error| panic!("client roots: {error}"));
    QuicClientConfig::enable_session_resumption(&mut builder)
        .unwrap_or_else(|error| panic!("client resumption: {error}"));
    QuicClientConfig::new(builder.build())
        .with_tls_profile(&phantom_profile::browser::chrome::v154_quic_tls())
        .unwrap_or_else(|error| panic!("client TLS profile: {error}"))
        .with_isolated_session_cache()
}

fn accepting(server: QuicServerConfig, context: &[u8]) -> QuicServerConfig {
    server
        .with_early_data(context)
        .unwrap_or_else(|error| panic!("server early-data context: {error}"))
}

fn learn_ticket(client: &QuicClientConfig, server: &QuicServerConfig) {
    let first = run(client.without_early_data(), server.clone());
    assert_eq!(first.client_result, Ok(()));
    assert!(!first.client.is_handshaking());
    assert!(!first.server.is_handshaking());
    assert!(!client_data(&*first.client).session_resumed());
    assert!(!server_data(&*first.server).session_resumed());
    assert_eq!(
        server_data(&*first.server).early_data_accepted(),
        Some(false)
    );
    assert!(client.has_ticket_for(SERVER_NAME));
}

fn offer_early(
    client: QuicClientConfig,
    server: QuicServerConfig,
    server_parameters: &TransportParameters,
) -> (Box<dyn crypto::Session>, Box<dyn crypto::Session>) {
    let mut client = Arc::new(client)
        .start_session(1, SERVER_NAME, &parameters(Side::Client))
        .unwrap_or_else(|error| panic!("client resumed session: {error}"));
    assert!(
        client.early_crypto().is_some(),
        "ticket did not permit early data"
    );
    let mut server = Arc::new(server).start_session(1, server_parameters);
    let mut hello = Vec::new();
    let _ = client.write_handshake(&mut hello);
    assert!(!hello.is_empty());
    server
        .read_handshake(&hello)
        .unwrap_or_else(|error| panic!("server resumed hello: {error}"));
    assert!(
        server.is_handshaking(),
        "server completed before client Finished"
    );
    assert_eq!(server_data(&*server).early_data_accepted(), None);
    (client, server)
}

// Quinn's decoded TransportParameters discard reserved values. Supply raw
// parameters to the same context calculation and native server constructor
// so this control retains the per-connection values a real endpoint writes.
fn raw_parameter_server(server: &QuicServerConfig, encoded: &[u8]) -> Box<dyn crypto::Session> {
    let state = server
        .application_state
        .as_deref()
        .unwrap_or_else(|| panic!("raw-parameter server requires early data"));
    let context =
        crate::transport_parameters::server_early_data_context(encoded, state, QuicVersion::V1)
            .unwrap_or_else(|error| panic!("raw-parameter early context: {error}"));
    let session = ServerSession::new(&server.context, encoded, Some(&context));
    Box::new(QuicServerSession {
        state: Mutex::new(ServerState::new(QuicVersion::V1, session)),
    })
}

fn offer_after_reserved_parameter_change(
    application_state: &[u8],
    transport_limit: u8,
) -> (Box<dyn crypto::Session>, Box<dyn crypto::Session>) {
    let client =
        resuming_client().with_ech(&EchOffer::new(&published_list(1, 0, OTHER_PUBLIC_NAME)));
    let base = server_config(Some((1, 0, OTHER_PUBLIC_NAME)));
    let first_server = accepting(base.clone(), b"settings-v1");
    let first_client = Arc::new(client.without_early_data())
        .start_session(1, SERVER_NAME, &parameters(Side::Client))
        .unwrap_or_else(|error| panic!("first raw-parameter client: {error}"));
    // initial_source_connection_id=1, initial_max_data=5, reserved 27=[a1].
    let first = exchange(
        first_client,
        raw_parameter_server(&first_server, &[0x0f, 1, 1, 4, 1, 5, 27, 1, 0xa1]),
    );
    assert_eq!(first.client_result, Ok(()));
    assert!(!first.client.is_handshaking());
    assert!(!first.server.is_handshaking());
    assert!(!server_data(&*first.server).session_resumed());
    assert!(server_data(&*first.server).ech_accepted());
    assert_eq!(
        server_data(&*first.server).early_data_accepted(),
        Some(false)
    );
    assert!(client.has_ticket_for(SERVER_NAME));

    let mut client = Arc::new(client.with_early_data())
        .start_session(1, SERVER_NAME, &parameters(Side::Client))
        .unwrap_or_else(|error| panic!("resumed raw-parameter client: {error}"));
    assert!(
        client.early_crypto().is_some(),
        "no actual early-data offer"
    );
    // Change both reserved ID and payload without changing the ticket keys.
    let mut server = raw_parameter_server(
        &accepting(base, application_state),
        &[0x0f, 1, 1, 4, 1, transport_limit, 58, 2, 0xb2, 0xc3],
    );
    let mut hello = Vec::new();
    let _ = client.write_handshake(&mut hello);
    assert!(!hello.is_empty());
    server
        .read_handshake(&hello)
        .unwrap_or_else(|error| panic!("raw-parameter resumed hello: {error}"));
    assert!(server.is_handshaking(), "completed before client Finished");
    assert!(server_data(&*server).ech_accepted());
    assert_eq!(server_data(&*server).early_data_accepted(), None);
    (client, server)
}

#[test]
fn changed_reserved_parameters_keep_native_ech_early_data_acceptance() {
    let (client, server) = offer_after_reserved_parameter_change(b"settings-v1", 5);
    assert!(server.early_crypto().is_some(), "no native early READ keys");
    let complete = exchange(client, server);
    assert_eq!(complete.client_result, Ok(()));
    assert!(!complete.client.is_handshaking());
    assert!(!complete.server.is_handshaking());
    assert!(server_data(&*complete.server).session_resumed());
    assert!(server_data(&*complete.server).ech_accepted());
    assert!(client_data(&*complete.client).session_resumed());
    assert_eq!(
        server_data(&*complete.server).early_data_accepted(),
        Some(true)
    );
    assert_eq!(complete.client.early_data_accepted(), Some(true));
}

#[test]
fn changed_reserved_parameters_do_not_hide_application_context_rejection() {
    let (client, server) = offer_after_reserved_parameter_change(b"settings-v2", 5);
    assert!(server.early_crypto().is_none());
    let complete = exchange(client, server);
    assert_eq!(complete.client_result, Ok(()));
    assert!(!complete.client.is_handshaking());
    assert!(!complete.server.is_handshaking());
    assert!(server_data(&*complete.server).session_resumed());
    assert!(server_data(&*complete.server).ech_accepted());
    assert_eq!(
        server_data(&*complete.server).early_data_accepted(),
        Some(false)
    );
    assert_eq!(complete.client.early_data_accepted(), Some(false));
}

#[test]
fn changed_reserved_parameters_do_not_hide_transport_limit_rejection() {
    let (client, server) = offer_after_reserved_parameter_change(b"settings-v1", 4);
    assert!(server.early_crypto().is_none());
    let complete = exchange(client, server);
    assert_eq!(complete.client_result, Ok(()));
    assert!(!complete.client.is_handshaking());
    assert!(!complete.server.is_handshaking());
    assert!(server_data(&*complete.server).session_resumed());
    assert!(server_data(&*complete.server).ech_accepted());
    assert_eq!(
        server_data(&*complete.server).early_data_accepted(),
        Some(false)
    );
    assert_eq!(complete.client.early_data_accepted(), Some(false));
}

#[test]
fn early_data_context_rejects_empty_and_oversized_input() {
    for length in [0, usize::from(u16::MAX) + 1] {
        let error = server_config(None)
            .with_early_data(&vec![0; length])
            .err()
            .unwrap_or_else(|| panic!("invalid context length {length} was accepted"));
        assert_eq!(
            error,
            crate::CryptoError::InvalidEarlyDataContextLength {
                actual: length,
                minimum: 1,
                maximum: usize::from(u16::MAX),
            }
        );
        assert_eq!(
            error.to_string(),
            format!("early-data application context length {length} is outside 1..=65535")
        );
    }
    for length in [1, usize::from(u16::MAX)] {
        assert!(
            server_config(None)
                .with_early_data(&vec![0; length])
                .is_ok()
        );
    }
}

#[test]
fn accepted_ech_installs_real_early_read_keys_while_handshake_is_pending() {
    let offer = EchOffer::new(&published_list(1, 0, OTHER_PUBLIC_NAME));
    let client = resuming_client().with_ech(&offer);
    let server = accepting(
        server_config(Some((1, 0, OTHER_PUBLIC_NAME))),
        b"settings-v1",
    );
    learn_ticket(&client, &server);
    let (client, server) = offer_early(client.with_early_data(), server, &parameters(Side::Server));
    let pending = server_data(&*server);
    assert!(pending.ech_accepted());
    assert_eq!(pending.server_name(), Some(SERVER_NAME));
    assert!(
        !pending.session_resumed(),
        "pending metadata claimed completion"
    );
    let mut exporter = [0; 16];
    assert!(
        server
            .export_keying_material(&mut exporter, b"pending", b"")
            .is_err()
    );
    let (write_header, write_packet) = client
        .early_crypto()
        .unwrap_or_else(|| panic!("client early keys disappeared"));
    let (read_header, read_packet) = server
        .early_crypto()
        .unwrap_or_else(|| panic!("server never installed early read keys"));
    let header = [0xd0, 0, 0, 0, 7];
    let payload = b"native early-data packet payload";
    let mut packet = header.to_vec();
    packet.extend_from_slice(payload);
    packet.resize(packet.len() + write_packet.tag_len(), 0);
    write_packet.encrypt(7, &mut packet, header.len());
    write_header.encrypt(4, &mut packet);
    read_header.decrypt(4, &mut packet);
    assert_eq!(&packet[..header.len()], &header);
    let mut encrypted = bytes::BytesMut::from(&packet[header.len()..]);
    let mut corrupted = encrypted.clone();
    corrupted[0] ^= 1;
    assert!(read_packet.decrypt(7, &header, &mut corrupted).is_err());
    assert!(read_packet.decrypt(7, &header, &mut encrypted).is_ok());
    assert_eq!(&encrypted[..], payload);

    let complete = exchange(client, server);
    assert_eq!(complete.client_result, Ok(()));
    assert!(!complete.server.is_handshaking());
    assert!(!complete.client.is_handshaking());
    let established = server_data(&*complete.server);
    assert!(established.session_resumed());
    assert!(established.ech_accepted());
    assert_eq!(established.early_data_accepted(), Some(true));
    assert_eq!(complete.client.early_data_accepted(), Some(true));
    assert!(client_data(&*complete.client).session_resumed());
    assert_eq!(
        pending.early_data_accepted(),
        None,
        "pending snapshot changed"
    );
    assert!(
        complete
            .server
            .export_keying_material(&mut exporter, b"complete", b"")
            .is_ok()
    );
}

#[test]
fn disabling_early_data_keeps_ticket_resumption_and_ech() {
    let client =
        resuming_client().with_ech(&EchOffer::new(&published_list(1, 0, OTHER_PUBLIC_NAME)));
    let server = server_config(Some((1, 0, OTHER_PUBLIC_NAME)));
    learn_ticket(&client, &accepting(server.clone(), b"settings-v1"));
    let (client, server) = offer_early(client.with_early_data(), server, &parameters(Side::Server));
    assert!(server.early_crypto().is_none());
    let complete = exchange(client, server);
    assert_eq!(complete.client_result, Ok(()));
    let data = server_data(&*complete.server);
    assert!(data.session_resumed());
    assert!(data.ech_accepted());
    assert_eq!(data.early_data_accepted(), Some(false));
    assert_eq!(complete.client.early_data_accepted(), Some(false));
    assert!(!complete.server.is_handshaking());
}

#[test]
fn changed_application_context_rejects_early_data_without_losing_resumption() {
    let client = resuming_client();
    let base = server_config(None);
    learn_ticket(&client, &accepting(base.clone(), b"settings-v1"));
    let (client, server) = offer_early(
        client.with_early_data(),
        accepting(base, b"settings-v2"),
        &parameters(Side::Server),
    );
    assert!(server.early_crypto().is_none());
    let complete = exchange(client, server);
    assert_eq!(complete.client_result, Ok(()));
    assert!(server_data(&*complete.server).session_resumed());
    assert_eq!(
        server_data(&*complete.server).early_data_accepted(),
        Some(false)
    );
    assert_eq!(complete.client.early_data_accepted(), Some(false));
}

#[test]
fn changed_transport_limit_rejects_early_data_without_losing_resumption() {
    let client = resuming_client();
    let server = accepting(server_config(None), b"settings-v1");
    learn_ticket(&client, &server);
    let changed = TransportParameters::read(Side::Server, &mut &[0x04, 0x01, 0x01][..])
        .unwrap_or_else(|error| panic!("changed parameters: {error}"));
    let (client, server) = offer_early(client.with_early_data(), server, &changed);
    assert!(server.early_crypto().is_none());
    let complete = exchange(client, server);
    assert_eq!(complete.client_result, Ok(()));
    assert!(server_data(&*complete.server).session_resumed());
    assert_eq!(
        server_data(&*complete.server).early_data_accepted(),
        Some(false)
    );
    assert_eq!(complete.client.early_data_accepted(), Some(false));
}

#[test]
fn changed_connection_id_keeps_early_data_acceptance() {
    let client = resuming_client();
    let server = accepting(server_config(None), b"settings-v1");
    learn_ticket(&client, &server);
    let changed = TransportParameters::read(Side::Server, &mut &[0x0f, 0x01, 0x02][..])
        .unwrap_or_else(|error| panic!("changed connection ID: {error}"));
    let (client, server) = offer_early(client.with_early_data(), server, &changed);
    assert!(server.early_crypto().is_some());
    let complete = exchange(client, server);
    assert_eq!(complete.client_result, Ok(()));
    assert!(!complete.server.is_handshaking());
    assert!(!complete.client.is_handshaking());
    assert!(server_data(&*complete.server).session_resumed());
    assert_eq!(
        server_data(&*complete.server).early_data_accepted(),
        Some(true)
    );
    assert_eq!(complete.client.early_data_accepted(), Some(true));
}

#[test]
fn a_default_server_ticket_resumes_without_any_early_keys() {
    let client = resuming_client();
    let server = server_config(None);
    learn_ticket(&client, &server);
    let mut resumed = Arc::new(client.with_early_data())
        .start_session(1, SERVER_NAME, &parameters(Side::Client))
        .unwrap_or_else(|error| panic!("resumed session: {error}"));
    assert!(resumed.early_crypto().is_none());
    let mut peer = Arc::new(server).start_session(1, &parameters(Side::Server));
    let mut hello = Vec::new();
    let _ = resumed.write_handshake(&mut hello);
    peer.read_handshake(&hello)
        .unwrap_or_else(|error| panic!("server hello: {error}"));
    assert!(peer.early_crypto().is_none());
    let complete = exchange(resumed, peer);
    assert_eq!(complete.client_result, Ok(()));
    assert!(server_data(&*complete.server).session_resumed());
    assert_eq!(
        server_data(&*complete.server).early_data_accepted(),
        Some(false)
    );
}
