use std::sync::atomic::{AtomicUsize, Ordering};

use btls::pkey::PKey;
use btls::ssl::{
    AlpnError, SslFiletype, SslInfoCallbackMode, SslMessageContentType, SslMessageDirection,
    SslVerifyMode, select_next_proto,
};
use btls::x509::X509;

use super::*;
use crate::QuicClientCertificate;

#[derive(Default)]
struct PeerObservations {
    certificate_messages: AtomicUsize,
    completed: AtomicUsize,
    matching_peer_certificates: AtomicUsize,
}

fn certificate() -> X509 {
    test_ok(
        X509::from_pem(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vendor/btls/test/cert.pem"
        ))),
        "test certificate",
    )
}

fn identity() -> QuicClientCertificate {
    let certificate = test_ok(certificate().to_der(), "client DER certificate");
    let key = test_ok(
        PKey::private_key_from_pem(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vendor/btls/test/key.pem"
        ))),
        "client key",
    );
    let key = test_ok(key.private_key_to_der_pkcs8(), "client DER key");
    test_ok(
        QuicClientCertificate::from_der([certificate.as_slice()], &key),
        "client identity",
    )
}

fn authentication_server(mode: SslVerifyMode) -> (OwnedContext, Arc<PeerObservations>) {
    let mut builder = test_ok(SslContextBuilder::new(SslMethod::tls()), "server context");
    test_ok(
        builder.set_certificate(&certificate()),
        "server certificate",
    );
    test_ok(
        builder.set_private_key_file(
            format!(
                "{}/../../vendor/btls/test/key.pem",
                env!("CARGO_MANIFEST_DIR")
            ),
            SslFiletype::PEM,
        ),
        "server key",
    );
    test_ok(
        builder.set_ca_file(format!(
            "{}/../../vendor/btls/test/root-ca.pem",
            env!("CARGO_MANIFEST_DIR")
        )),
        "client certificate roots",
    );
    test_ok(
        builder.set_session_id_context(b"client-certificate-observation"),
        "server session context",
    );
    builder.set_verify(mode);
    builder.set_alpn_select_callback(|_, offered| {
        select_next_proto(b"\x02h3", offered).ok_or(AlpnError::NOACK)
    });
    let observations = Arc::new(PeerObservations::default());
    let incoming = Arc::clone(&observations);
    builder.set_msg_callback(move |_, message| {
        if message.direction == SslMessageDirection::Read
            && message.content_type == SslMessageContentType::HANDSHAKE
            && message.data.first() == Some(&11)
        {
            incoming.certificate_messages.fetch_add(1, Ordering::SeqCst);
        }
    });
    let completion = Arc::clone(&observations);
    let expected_der = test_ok(certificate().to_der(), "expected client certificate");
    builder.set_info_callback(move |ssl, mode, _| {
        if mode == SslInfoCallbackMode::HANDSHAKE_DONE {
            completion.completed.fetch_add(1, Ordering::SeqCst);
            let peer_der = ssl.peer_certificate().and_then(|peer| peer.to_der().ok());
            if peer_der.as_deref() == Some(expected_der.as_slice()) {
                completion
                    .matching_peer_certificates
                    .fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    (OwnedContext::from_context(builder.build()), observations)
}

fn metadata(session: &dyn crypto::Session) -> HandshakeData {
    *test_some(session.handshake_data(), "client handshake data")
        .downcast::<HandshakeData>()
        .unwrap_or_else(|_| panic!("client handshake data type"))
}

#[test]
fn configured_certificate_is_reported_only_when_the_peer_requests_it() {
    let config = Arc::new(resuming_config().with_client_certificate(&identity()));
    let requesting = start(&config);
    let unrequested = start(&config);
    assert!(requesting.handshake_data().is_none());
    assert!(unrequested.handshake_data().is_none());
    let (required, observed) =
        authentication_server(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    let requested = handshake_with(
        requesting,
        test_ok(RawServer::new(&required), "requiring server"),
    );
    let (ordinary, not_requested) = authentication_server(SslVerifyMode::NONE);
    let unrequested = handshake_with(
        unrequested,
        test_ok(RawServer::new(&ordinary), "ordinary server"),
    );
    assert!(metadata(requested.as_ref()).client_certificate_sent());
    assert!(!metadata(unrequested.as_ref()).client_certificate_sent());
    assert!(metadata(requested.as_ref()).peer_verified());
    assert!(metadata(unrequested.as_ref()).peer_verified());
    assert_eq!(observed.certificate_messages.load(Ordering::SeqCst), 1);
    assert_eq!(observed.completed.load(Ordering::SeqCst), 1);
    assert_eq!(
        observed.matching_peer_certificates.load(Ordering::SeqCst),
        1
    );
    assert_eq!(not_requested.certificate_messages.load(Ordering::SeqCst), 0);
    assert_eq!(not_requested.completed.load(Ordering::SeqCst), 1);
    assert_eq!(
        not_requested
            .matching_peer_certificates
            .load(Ordering::SeqCst),
        0
    );
}

#[test]
fn an_optional_request_without_an_identity_sends_only_an_empty_certificate() {
    let config = Arc::new(resuming_config());
    let (optional, observed) = authentication_server(SslVerifyMode::PEER);
    let client = handshake(&config, &optional);
    assert!(!metadata(client.as_ref()).client_certificate_sent());
    assert!(metadata(client.as_ref()).peer_verified());
    assert_eq!(observed.certificate_messages.load(Ordering::SeqCst), 1);
    assert_eq!(observed.completed.load(Ordering::SeqCst), 1);
    assert_eq!(
        observed.matching_peer_certificates.load(Ordering::SeqCst),
        0
    );
}

#[test]
fn resumed_mtls_does_not_copy_the_full_handshakes_sent_certificate_fact() {
    let config = Arc::new(
        resuming_config()
            .with_client_certificate(&identity())
            .with_isolated_session_cache()
            .with_early_data(),
    );
    let (server, observed) =
        authentication_server(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    let full = accepting_handshake(&config, &server);
    assert!(!resumed(full.as_ref()));
    assert!(metadata(full.as_ref()).client_certificate_sent());
    assert!(metadata(full.as_ref()).peer_verified());
    let accepted = accepting_handshake(&config, &server);
    assert!(resumed(accepted.as_ref()));
    assert_eq!(accepted.early_data_accepted(), Some(true));
    assert!(!metadata(accepted.as_ref()).client_certificate_sent());
    assert!(metadata(accepted.as_ref()).peer_verified());
    let rejected = handshake(&config, &server);
    assert!(resumed(rejected.as_ref()));
    assert_eq!(rejected.early_data_accepted(), Some(false));
    assert!(!metadata(rejected.as_ref()).client_certificate_sent());
    assert!(metadata(rejected.as_ref()).peer_verified());
    assert_eq!(observed.certificate_messages.load(Ordering::SeqCst), 1);
    assert_eq!(observed.completed.load(Ordering::SeqCst), 3);
    assert_eq!(
        observed.matching_peer_certificates.load(Ordering::SeqCst),
        3
    );
}
