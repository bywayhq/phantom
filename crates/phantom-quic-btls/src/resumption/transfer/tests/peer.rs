//! Real peer-issued TLS tickets through in-process Quinn crypto sessions.
//! This does not drive UDP, Quinn connection state, or HTTP/3.

use std::io::Cursor;

use btls::ssl::{
    AlpnError, SslContext, SslFiletype, SslMethod, SslVerifyMode, open_envelope, seal_envelope,
    select_next_proto,
};
use quinn_proto::{Side, crypto, transport_parameters::TransportParameters};

use super::*;
use crate::{HandshakeData, PeerIdentity, QuicClientConfig, QuicServerConfig, ServerHandshakeData};

const HOST: &str = "foobar.com";
const APPLICATION: &[u8] = b"Q1 application settings";
const PAYLOAD: &[u8] = b"Q1 source owner";
const SNAPSHOT_KEY: [u8; 32] = [29; 32];

fn fixture(name: &str) -> String {
    format!(
        "{}/../../vendor/btls/test/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn client(key: [u8; 32]) -> Result<QuicClientConfig, Box<dyn std::error::Error>> {
    let mut builder = SslContext::builder(SslMethod::tls())?;
    builder.set_verify(SslVerifyMode::PEER);
    builder.set_ca_file(fixture("root-ca.pem"))?;
    QuicClientConfig::enable_session_resumption(&mut builder)?;
    let config = QuicClientConfig::new(builder.build())
        .with_tls_profile(&phantom_profile::browser::chrome::v154_quic_tls())?
        .with_isolated_session_cache()
        .without_early_data();
    config
        .session_ticket_cache()
        .and_then(|control| control.upgrade())
        .ok_or("client cache absent")?
        .bind_transfer_policy(
            HOST,
            SessionTransferPolicy::new(b"Q1 actual peer policy", &[0, 0], None, &key)?,
        )?;
    Ok(config)
}

fn server() -> Result<Arc<QuicServerConfig>, Box<dyn std::error::Error>> {
    let mut builder = SslContext::builder(SslMethod::tls())?;
    builder.set_certificate_chain_file(fixture("cert.pem"))?;
    builder.set_private_key_file(fixture("key.pem"), SslFiletype::PEM)?;
    builder.set_alpn_select_callback(|_, offered| {
        select_next_proto(b"\x02h3", offered).ok_or(AlpnError::NOACK)
    });
    Ok(Arc::new(QuicServerConfig::new(builder.build())))
}

fn parameters(side: Side) -> Result<TransportParameters, Box<dyn std::error::Error>> {
    // A real parser supplies the connection-ID parameter used by existing peers.
    Ok(TransportParameters::read(
        side,
        &mut Cursor::new([0x0f, 1, 1]),
    )?)
}

struct Completed {
    client: HandshakeData,
    server: ServerHandshakeData,
    certificates: Vec<Vec<u8>>,
}

fn handshake(
    config: &QuicClientConfig,
    server: &Arc<QuicServerConfig>,
    version: QuicVersion,
    deliver_tickets: bool,
) -> Result<Completed, Box<dyn std::error::Error>> {
    use crypto::{ClientConfig as _, ServerConfig as _};

    let mut client = Arc::new(config.without_early_data()).start_session(
        version.wire(),
        HOST,
        &parameters(Side::Client)?,
    )?;
    let mut peer = Arc::clone(server).start_session(version.wire(), &parameters(Side::Server)?);
    // Every iteration must make progress. Finite flight bounds catch a fixture
    // regression without timers, detached tasks, or ignored handshake failures.
    for round in 0..32 {
        let mut moved = false;
        for flight in 0..16 {
            let mut bytes = Vec::new();
            let keys = client.write_handshake(&mut bytes);
            if !bytes.is_empty() {
                peer.read_handshake(&bytes)?;
                moved = true;
            }
            if keys.is_none() && bytes.is_empty() {
                break;
            }
            if flight == 15 {
                return Err("client flight bound exceeded".into());
            }
        }
        for flight in 0..16 {
            let mut bytes = Vec::new();
            let keys = peer.write_handshake(&mut bytes);
            if !bytes.is_empty() {
                if deliver_tickets || client.is_handshaking() || peer.is_handshaking() {
                    client.read_handshake(&bytes)?;
                }
                moved = true;
            }
            if keys.is_none() && bytes.is_empty() {
                break;
            }
            if flight == 15 {
                return Err("server flight bound exceeded".into());
            }
        }
        if !moved {
            assert!(!client.is_handshaking());
            assert!(!peer.is_handshaking());
            assert!(client.early_crypto().is_none());
            assert!(peer.early_crypto().is_none());
            let client_data = client
                .handshake_data()
                .ok_or("client handshake data absent")?
                .downcast::<HandshakeData>()
                .map_err(|_| "client handshake data type")?;
            let peer_data = peer
                .handshake_data()
                .ok_or("server handshake data absent")?
                .downcast::<ServerHandshakeData>()
                .map_err(|_| "server handshake data type")?;
            let identity = client
                .peer_identity()
                .ok_or("verified peer identity absent")?
                .downcast::<PeerIdentity>()
                .map_err(|_| "peer identity type")?;
            assert_eq!(client_data.protocol(), b"h3");
            assert_eq!(peer_data.protocol(), b"h3");
            assert_eq!(peer_data.server_name(), Some(HOST));
            assert_eq!(client.early_data_accepted(), Some(false));
            return Ok(Completed {
                client: *client_data,
                server: *peer_data,
                certificates: identity.certificates().to_vec(),
            });
        }
        if round == 31 {
            return Err("handshake round bound exceeded".into());
        }
    }
    Err("handshake did not complete".into())
}

#[test]
fn real_published_ticket_transfer_resumes_both_versions_in_process() -> TestResult {
    for version in [QuicVersion::V1, QuicVersion::V2] {
        let peer = server()?;
        let source = client([7; 32])?;
        let recipient = client([8; 32])?;
        let source_cache = source.session_cache().ok_or("source cache absent")?;
        let recipient_cache = recipient.session_cache().ok_or("recipient cache absent")?;
        assert!(!source_cache.shares_storage_with(recipient_cache));
        let source_owner = source_cache
            .control()
            .upgrade()
            .ok_or("source owner absent")?;
        let recipient_owner = recipient_cache
            .control()
            .upgrade()
            .ok_or("recipient owner absent")?;
        assert!(recipient_cache.state().sessions.is_empty());

        let application = ApplicationState::new();
        let first = handshake(
            &source.with_application_state(&application),
            &peer,
            version,
            true,
        )?;
        assert!(!first.client.session_resumed());
        assert!(!first.server.session_resumed());
        assert!(!first.certificates.is_empty());
        assert!(source_cache.state().sessions.is_empty());
        assert!(!application.lock().held.is_empty());
        assert!(application.store(APPLICATION));
        let generation = source_cache.capture();
        let count = source_cache.state().sessions.len();
        assert!(count > 0 && count <= MAX_SESSIONS);
        let expected = source_cache
            .state()
            .sessions
            .iter()
            .map(|cached| {
                assert_eq!(cached.ticket.version, version);
                assert_eq!(cached.ticket.session.protocol_version(), SslVersion::TLS1_3);
                assert!(cached.ticket.session.should_be_single_use());
                (
                    Arc::clone(&cached.ticket.session),
                    cached.ticket.peer_transport_parameters.clone(),
                    cached.ticket.application_state.clone(),
                )
            })
            .collect::<Vec<_>>();
        let rtt = Duration::new(0, 12_345_678);
        source_cache.record_round_trip_time(HOST, rtt);
        let mut capture = QuicSessionTicketCacheOwner::prepare_captures(&[(&source_owner, HOST)])?
            .pop()
            .ok_or("capture absent")?;
        let source_binding = capture.binding().clone();
        let bindings = [&source_binding];
        let native_plan = PreparedSessionPolicyFreeze::new(&bindings)?;
        let frozen = source_owner.freeze();
        let native = native_plan.try_freeze()?;
        frozen.capture(&mut capture, &native)?;
        drop(native);
        drop(frozen);
        let captured = capture.into_export()?;
        let header = captured.header();
        assert_eq!(header.record_count(), count);
        assert_eq!(header.excluded_expired_count(), 0);
        assert_eq!(header.round_trip_time(), Some(rtt));
        let mut records = Vec::new();
        for (ordinal, record) in captured.into_records().into_iter().enumerate() {
            assert_eq!(record.ordinal(), ordinal);
            assert!(record.application_state() == Some(APPLICATION));
            records.push(record.seal(PAYLOAD, &SNAPSHOT_KEY)?);
        }
        let sealed = seal_envelope(&records, &SNAPSHOT_KEY)?;
        let mut opened = open_envelope(
            sealed.as_bytes(),
            &SNAPSHOT_KEY,
            &recipient_owner.inner.context,
        )?;
        assert_eq!(opened.record_count(), count);
        let recipient_binding = recipient_cache
            .state()
            .transfer_binding
            .clone()
            .ok_or("binding absent")?;
        let mut permits = Vec::new();
        for (ordinal, (_, parameters, application)) in expected.iter().enumerate() {
            assert!(opened.source_witness(ordinal)? == [0, 0]);
            let shape = QuicSessionRecordMetadata::parse(opened.owner_metadata(ordinal)?)?;
            assert_eq!(shape.header(), header);
            assert_eq!(shape.ordinal(), ordinal);
            assert_eq!(shape.version, version);
            assert!(shape.peer_transport_parameters == parameters.as_deref());
            assert!(shape.application_state() == application.as_deref());
            assert!(shape.payload() == PAYLOAD);
            permits.push(opened.authorize_record(ordinal, &recipient_binding)?);
        }
        let mut replacement =
            recipient_owner.prepare_replacement(Arc::from(HOST), header, permits)?;
        let bindings = [&recipient_binding];
        let native_plan = PreparedSessionPolicyFreeze::new(&bindings)?;
        let mut frozen = recipient_owner.freeze();
        let native = native_plan.try_freeze()?;
        let retired = frozen
            .validate_replacement(&mut replacement, &native)?
            .commit();
        drop(native);
        drop(frozen);
        assert_eq!(retired.finish(), 0);
        assert!(generation.is_current());
        assert_eq!(source_cache.round_trip_time(HOST), Some(rtt));
        {
            let state = source_cache.state();
            assert_eq!(state.sessions.len(), count);
            for (cached, (session, parameters, application)) in state.sessions.iter().zip(&expected)
            {
                assert!(Arc::ptr_eq(&cached.ticket.session, session));
                assert!(
                    cached.ticket.peer_transport_parameters.as_deref() == parameters.as_deref()
                );
                assert!(cached.ticket.application_state.as_deref() == application.as_deref());
            }
        }
        // Discard new post-handshake server flights so no replacement ticket
        // can hide reuse of an imported single-use ticket.
        for remaining in (0..count).rev() {
            let resumed = handshake(&recipient, &peer, version, false)?;
            assert!(resumed.client.session_resumed());
            assert!(resumed.server.session_resumed());
            assert!(resumed.certificates == first.certificates);
            assert_eq!(recipient_cache.state().sessions.len(), remaining);
        }
        let empty = handshake(&recipient, &peer, version, false)?;
        assert!(!empty.client.session_resumed());
        assert!(!empty.server.session_resumed());
        assert!(recipient_cache.state().sessions.is_empty());
        let preserved = handshake(&source, &peer, version, false)?;
        assert!(preserved.client.session_resumed());
        assert!(preserved.server.session_resumed());
        assert!(preserved.certificates == first.certificates);
        assert_eq!(source_cache.state().sessions.len(), count - 1);
    }
    Ok(())
}
