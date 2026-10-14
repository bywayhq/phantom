use super::server::Server;
use crate::ffi;
use crate::ssl::test::MessageDigest;
use crate::ssl::ErrorCode;
use crate::ssl::HmacCtxRef;
use crate::ssl::ScopedSslSession;
use crate::ssl::SslConnector;
use crate::ssl::SslRef;
use crate::ssl::SslSession;
use crate::ssl::SslSessionCacheMode;
use crate::ssl::SslSessionScope;
use crate::ssl::SslVerifyError;
use crate::ssl::SslVerifyMode;
use crate::ssl::SslVersion;
use crate::ssl::TicketKeyCallbackResult;
use crate::symm::Cipher;
use crate::symm::CipherCtxRef;
use foreign_types::ForeignTypeRef;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};

static SUCCESS_ENCRYPTION_CALLED_BACK: AtomicU8 = AtomicU8::new(0);
static SUCCESS_DECRYPTION_CALLED_BACK: AtomicU8 = AtomicU8::new(0);
static NOOP_ENCRYPTION_CALLED_BACK: AtomicU8 = AtomicU8::new(0);
static NOOP_DECRYPTION_CALLED_BACK: AtomicU8 = AtomicU8::new(0);

#[test]
fn scoped_context_configuration_preserves_original_policy() {
    let mut builder = publication_client_builder();
    builder.set_options(crate::ssl::SslOptions::NO_TICKET);
    builder
        .set_cipher_list("ECDHE-RSA-AES128-GCM-SHA256")
        .unwrap();
    let context = builder.build().into_context();
    let configuration = context.configure_client().unwrap();
    let mut ssl = configuration.into_ssl("foobar.com").unwrap();
    assert_eq!(ssl.ssl_context().as_ptr(), context.as_ptr());
    assert_eq!(ssl.verify_mode(), SslVerifyMode::PEER);
    assert_eq!(ssl.min_proto_version(), Some(SslVersion::TLS1_3));
    assert_eq!(ssl.max_proto_version(), Some(SslVersion::TLS1_3));
    assert_eq!(
        ssl.ssl_context().cert_store().as_ptr(),
        context.cert_store().as_ptr()
    );
    // SAFETY: both native owners remain live throughout these read-only queries.
    unsafe {
        assert_eq!(
            ffi::SSL_get_options(ssl.as_ptr()),
            ffi::SSL_CTX_get_options(context.as_ptr())
        );
    }
    assert_eq!(
        ssl.ciphers()[0].name(),
        context.ciphers().unwrap()[0].name()
    );
    assert_eq!(
        ssl.servername(crate::ssl::NameType::HOST_NAME),
        Some("foobar.com")
    );
}

#[test]
fn scoped_context_non_x509_is_rejected_without_mutation() {
    // SAFETY: this test never uses any X.509 operation on the buffer context.
    let method = unsafe { crate::ssl::SslMethod::tls_with_buffer() };
    let mut context = crate::ssl::SslContext::builder(method).unwrap();
    let before = scoped_context_native_state(&context.ctx);
    assert!(matches!(
        context.ctx.configure_client(),
        Err(crate::ssl::ClientSessionConfigurationError::X509ContextRequired)
    ));
    assert!(matches!(
        context.try_enable_scoped_client_sessions_with_early_data(),
        Err(crate::ssl::ClientSessionConfigurationError::X509ContextRequired)
    ));
    assert_eq!(scoped_context_native_state(&context.ctx), before);
}

#[test]
fn scoped_context_preparation_is_idempotent_and_reenables_disabled_cache() {
    let mut context = crate::ssl::SslContext::builder(crate::ssl::SslMethod::tls()).unwrap();
    assert_eq!(
        context.ctx.scoped_client_session_mode(),
        crate::ssl::ScopedClientSessionMode::Off
    );
    context
        .try_enable_scoped_client_sessions_with_early_data()
        .unwrap();
    let prepared = scoped_context_native_state(&context.ctx);
    context
        .try_enable_scoped_client_sessions_with_early_data()
        .unwrap();
    assert_eq!(scoped_context_native_state(&context.ctx), prepared);
    assert_eq!(
        context.ctx.scoped_client_session_mode(),
        crate::ssl::ScopedClientSessionMode::ScopedWithEarlyData
    );
    context.set_session_cache_mode(SslSessionCacheMode::OFF);
    assert_eq!(
        context.ctx.scoped_client_session_mode(),
        crate::ssl::ScopedClientSessionMode::Off
    );
    context
        .try_enable_scoped_client_sessions_with_early_data()
        .unwrap();
    assert_eq!(scoped_context_native_state(&context.ctx), prepared);
}

#[test]
fn scoped_context_foreign_callback_is_rejected_even_when_cache_is_off() {
    let mut context = crate::ssl::SslContext::builder(crate::ssl::SslMethod::tls()).unwrap();
    context.set_new_session_callback(|_, _| {});
    for mode in [SslSessionCacheMode::CLIENT, SslSessionCacheMode::OFF] {
        context.set_session_cache_mode(mode);
        let before = scoped_context_native_state(&context.ctx);
        assert_eq!(
            context.ctx.scoped_client_session_mode(),
            crate::ssl::ScopedClientSessionMode::Foreign
        );
        assert!(matches!(
            context.try_enable_scoped_client_sessions_with_early_data(),
            Err(crate::ssl::ClientSessionConfigurationError::ForeignSessionCallback)
        ));
        assert_eq!(scoped_context_native_state(&context.ctx), before);
    }
}

#[test]
fn scoped_context_safe_callback_replacement_retires_private_marker() {
    let mut context = crate::ssl::SslContext::builder(crate::ssl::SslMethod::tls()).unwrap();
    context
        .try_enable_scoped_client_sessions_with_early_data()
        .unwrap();
    // SAFETY: this live builder owns the callback and its retained closure data.
    let original = unsafe { ffi::SSL_CTX_sess_get_new_cb(context.as_ptr()) };
    context.set_new_session_callback(|_, _| {});
    assert_eq!(
        context.ctx.scoped_client_session_mode(),
        crate::ssl::ScopedClientSessionMode::Foreign
    );
    // SAFETY: original closure data is still retained in the same context. Restoring
    // its native pointer cannot restore the marker retired by the public setter.
    unsafe { ffi::SSL_CTX_sess_set_new_cb(context.as_ptr(), original) };
    assert_eq!(
        context.ctx.scoped_client_session_mode(),
        crate::ssl::ScopedClientSessionMode::Foreign
    );
    let before = scoped_context_native_state(&context.ctx);
    assert!(matches!(
        context.try_enable_scoped_client_sessions_with_early_data(),
        Err(crate::ssl::ClientSessionConfigurationError::ForeignSessionCallback)
    ));
    assert_eq!(scoped_context_native_state(&context.ctx), before);
}

#[test]
fn scoped_context_same_generic_trampoline_does_not_prove_callback_ownership() {
    fn first(_: &mut SslRef, _: SslSession) {}
    fn second(_: &mut SslRef, _: SslSession) {}
    let mut context = crate::ssl::SslContext::builder(crate::ssl::SslMethod::tls()).unwrap();
    context.set_new_session_callback(first as fn(&mut SslRef, SslSession));
    let before = scoped_context_native_state(&context.ctx);
    context.set_new_session_callback(second as fn(&mut SslRef, SslSession));
    assert_eq!(scoped_context_native_state(&context.ctx).0, before.0);
    assert_eq!(
        context.ctx.scoped_client_session_mode(),
        crate::ssl::ScopedClientSessionMode::Foreign
    );
    assert!(matches!(
        context.try_enable_scoped_client_sessions_with_early_data(),
        Err(crate::ssl::ClientSessionConfigurationError::ForeignSessionCallback)
    ));
}

#[test]
fn scoped_context_native_callback_replacement_is_detected() {
    unsafe extern "C" fn foreign(_: *mut ffi::SSL, _: *mut ffi::SSL_SESSION) -> std::ffi::c_int {
        0
    }
    let mut context = crate::ssl::SslContext::builder(crate::ssl::SslMethod::tls()).unwrap();
    context
        .try_enable_scoped_client_sessions_with_early_data()
        .unwrap();
    for callback in [Some(foreign as unsafe extern "C" fn(_, _) -> _), None] {
        // SAFETY: the unique builder owns this valid callback slot. No handshake
        // invokes the test replacement, and no session reference is fabricated.
        unsafe { ffi::SSL_CTX_sess_set_new_cb(context.as_ptr(), callback) };
        let before = scoped_context_native_state(&context.ctx);
        assert_eq!(
            context.ctx.scoped_client_session_mode(),
            crate::ssl::ScopedClientSessionMode::Foreign
        );
        assert!(matches!(
            context.try_enable_scoped_client_sessions_with_early_data(),
            Err(crate::ssl::ClientSessionConfigurationError::ForeignSessionCallback)
        ));
        assert_eq!(scoped_context_native_state(&context.ctx), before);
    }
}

#[test]
fn scoped_context_conflicting_early_data_policy_is_preserved() {
    let mut context = tls13_client_builder();
    context.enable_scoped_client_sessions();
    assert_eq!(
        context.ctx.scoped_client_session_mode(),
        crate::ssl::ScopedClientSessionMode::Scoped
    );
    for mode in [
        SslSessionCacheMode::CLIENT | SslSessionCacheMode::NO_INTERNAL,
        SslSessionCacheMode::OFF,
    ] {
        context.set_session_cache_mode(mode);
        let before = scoped_context_native_state(&context.ctx);
        assert!(matches!(
            context.try_enable_scoped_client_sessions_with_early_data(),
            Err(crate::ssl::ClientSessionConfigurationError::ConflictingEarlyDataPolicy)
        ));
        assert_eq!(scoped_context_native_state(&context.ctx), before);
    }
}

#[test]
fn scoped_context_changed_internal_cache_policy_is_rejected() {
    let mut context = crate::ssl::SslContext::builder(crate::ssl::SslMethod::tls()).unwrap();
    context
        .try_enable_scoped_client_sessions_with_early_data()
        .unwrap();
    for mode in [
        SslSessionCacheMode::CLIENT,
        SslSessionCacheMode::CLIENT | SslSessionCacheMode::NO_INTERNAL_LOOKUP,
        SslSessionCacheMode::CLIENT | SslSessionCacheMode::NO_INTERNAL_STORE,
    ] {
        context.set_session_cache_mode(mode);
        let before = scoped_context_native_state(&context.ctx);
        assert_eq!(
            context.ctx.scoped_client_session_mode(),
            crate::ssl::ScopedClientSessionMode::Off
        );
        assert!(matches!(
            context.try_enable_scoped_client_sessions_with_early_data(),
            Err(crate::ssl::ClientSessionConfigurationError::InternalSessionCacheEnabled)
        ));
        assert_eq!(scoped_context_native_state(&context.ctx), before);
    }
}

#[test]
fn scoped_context_configuration_delivers_real_sessions_and_resumes_authenticated_source() {
    let server = tls13_server(2).build();
    let mut context = crate::ssl::SslContext::builder(crate::ssl::SslMethod::tls()).unwrap();
    context.set_ca_file("test/root-ca.pem").unwrap();
    context.set_verify(SslVerifyMode::PEER);
    context
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    context
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    context
        .try_enable_scoped_client_sessions_with_early_data()
        .unwrap();
    let context = context.build();
    let scope = SslSessionScope::default();
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let callback_sessions = Arc::clone(&sessions);
    let ssl = context
        .configure_client()
        .unwrap()
        .into_ssl_with_scoped_session("foobar.com", &scope, None, move |session| {
            let session = session.unwrap();
            assert!(!session.is_authenticated());
            callback_sessions.lock().unwrap().push(session);
        })
        .unwrap()
        .unwrap();
    assert!(!ssl.authenticate_scoped_session_publication());
    let mut first = ssl.connect(server.connect_tcp()).unwrap();
    first.read_exact(&mut [0]).unwrap();
    assert!(!first.ssl().session_reused());
    assert!(first.ssl().authenticate_scoped_session_publication());
    let ticket = sessions.lock().unwrap().pop().unwrap();
    assert!(ticket.is_authenticated());
    let second = context
        .configure_client()
        .unwrap()
        .into_ssl_with_scoped_session("foobar.com", &scope, Some(&ticket), |_| {})
        .unwrap()
        .unwrap();
    let mut second = second.connect(server.connect_tcp()).unwrap();
    second.read_exact(&mut [0]).unwrap();
    assert!(second.ssl().session_reused());
    assert!(second.ssl().authenticate_scoped_session_publication());
}

#[test]
fn scoped_context_configuration_errors_preserve_native_source() {
    use std::error::Error;
    let error =
        crate::ssl::ClientSessionConfigurationError::Backend(crate::error::ErrorStack::get());
    assert!(error.source().is_some());
    assert!(error
        .to_string()
        .starts_with("client connection allocation failed:"));
    assert!(
        crate::ssl::ClientSessionConfigurationError::ForeignSessionCallback
            .source()
            .is_none()
    );
}

#[cfg(not(feature = "fips"))]
#[test]
fn scoped_context_preparation_preserves_real_early_data_ticket_capability() {
    let mut server = tls13_server(1);
    // SAFETY: the live server builder exclusively owns its context.
    unsafe { ffi::SSL_CTX_set_early_data_enabled(server.ctx().as_ptr(), 1) };
    let server = server.build();
    let mut context = publication_client_builder();
    context
        .try_enable_scoped_client_sessions_with_early_data()
        .unwrap();
    let context = context.build().into_context();
    let scope = SslSessionScope::default();
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let callback_sessions = Arc::clone(&sessions);
    let mut configuration = context.configure_client().unwrap();
    configuration.set_early_data_enabled(true);
    let ssl = configuration
        .into_ssl_with_scoped_session("foobar.com", &scope, None, move |session| {
            callback_sessions.lock().unwrap().push(session.unwrap());
        })
        .unwrap()
        .unwrap();
    let mut stream = ssl.connect(server.connect_tcp()).unwrap();
    stream.read_exact(&mut [0]).unwrap();
    let sessions = sessions.lock().unwrap();
    assert!(!sessions.is_empty());
    assert!(sessions.iter().all(ScopedSslSession::early_data_capable));
    assert!(sessions.iter().all(|session| !session.is_authenticated()));
    assert!(stream.ssl().authenticate_scoped_session_publication());
    assert!(sessions.iter().all(ScopedSslSession::is_authenticated));
}

fn scoped_context_native_state(context: &crate::ssl::SslContextRef) -> (Option<usize>, i32) {
    // SAFETY: context is live. Addresses are used only for local ownership tests,
    // never as portable session binding or authentication evidence.
    unsafe {
        (
            ffi::SSL_CTX_sess_get_new_cb(context.as_ptr()).map(|callback| callback as usize),
            ffi::SSL_CTX_get_session_cache_mode(context.as_ptr()),
        )
    }
}

#[test]
fn resume_session() {
    static SESSION_TICKET: OnceLock<SslSession> = OnceLock::new();
    static NST_RECIEVED_COUNT: AtomicU8 = AtomicU8::new(0);

    let mut server = Server::builder();
    server.expected_connections_count(2);
    let server = server.build();

    let mut client = server.client();
    client
        .ctx()
        .set_session_cache_mode(SslSessionCacheMode::CLIENT);
    client.ctx().set_new_session_callback(|_, session| {
        NST_RECIEVED_COUNT.fetch_add(1, Ordering::SeqCst);
        // The server sends multiple session tickets but we only care to retrieve one.
        let _ = SESSION_TICKET.set(session);
    });
    let ssl_stream = client.connect();

    assert!(!ssl_stream.ssl().session_reused());
    assert!(SESSION_TICKET.get().is_some());
    assert_eq!(NST_RECIEVED_COUNT.load(Ordering::SeqCst), 2);

    // Retrieve the session ticket
    let session_ticket = SESSION_TICKET.get().unwrap();

    // Attempt to resume the connection using the session ticket
    let client_2 = server.client();
    let mut ssl_builder = client_2.build().builder();
    unsafe { ssl_builder.ssl().set_session(session_ticket).unwrap() };
    let ssl_stream_2 = ssl_builder.connect();

    assert!(ssl_stream_2.ssl().session_reused());
}

#[test]
fn client_session_cache_apis() {
    let mut server = Server::builder();
    server.expected_connections_count(2);
    server
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    let server = server.build();

    let sessions = Arc::new(Mutex::new(Vec::new()));
    let callback_sessions = Arc::clone(&sessions);
    let verify_count = Arc::new(AtomicU8::new(0));
    let callback_verify_count = Arc::clone(&verify_count);

    let mut client = server.client();
    client
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client
        .ctx()
        .set_session_cache_mode(SslSessionCacheMode::CLIENT | SslSessionCacheMode::NO_INTERNAL);
    let _ = client.ctx().set_session_timeout(60);
    assert_eq!(client.ctx().set_session_timeout(120), 60);
    client.ctx().set_reverify_on_resume(true);
    client
        .ctx()
        .set_custom_verify_callback(SslVerifyMode::PEER, move |_| {
            callback_verify_count.fetch_add(1, Ordering::SeqCst);
            Ok::<_, SslVerifyError>(())
        });
    client.ctx().set_new_session_callback(move |_, session| {
        callback_sessions.lock().unwrap().push(session);
    });
    let client = client.build();

    let first = client.builder().connect();
    assert!(!first.ssl().session_reused());
    assert_eq!(verify_count.load(Ordering::SeqCst), 1);

    let mut sessions = sessions.lock().unwrap();
    assert_eq!(sessions.len(), 2);
    assert!(sessions
        .iter()
        .all(|session| session.should_be_single_use()));
    let session = sessions.pop().unwrap();
    drop(sessions);
    assert!(session.should_be_single_use());
    let session_without_early_data = session.copy_without_early_data().unwrap();
    assert_eq!(
        session.to_der().unwrap(),
        session_without_early_data.to_der().unwrap()
    );

    let mut resumed = client.builder();
    // SAFETY: The session was created by this client's SSL_CTX, and the new handshake has not
    // started.
    unsafe { resumed.ssl().set_session(&session).unwrap() };
    let resumed = resumed.connect();
    assert!(resumed.ssl().session_reused());
    assert_eq!(verify_count.load(Ordering::SeqCst), 2);
}

#[test]
fn strict_session_bytes_round_trip_metadata_and_reject_partial_input() {
    let server = tls13_server(1).build();
    let scope = SslSessionScope::default();
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let client = scoped_tls13_client();
    let first = connect_and_read_scoped(&server, &client, "foobar.com", &scope, &sessions, None);
    assert!(!first.ssl().session_reused());
    let session = sessions.lock().unwrap().pop().unwrap();
    let bytes = session.to_bytes().unwrap();
    let destination = scoped_tls13_client();
    let decoded = SslSession::from_bytes(&bytes, destination.context()).unwrap();
    assert_eq!(decoded.protocol_version(), session.protocol_version());
    assert_eq!(decoded.time(), session.time());
    assert_eq!(decoded.timeout(), session.timeout());
    assert_eq!(
        decoded.should_be_single_use(),
        session.should_be_single_use()
    );
    // Boolean comparisons prevent assertion output from printing ticket secrets.
    assert!(decoded.to_bytes().unwrap() == bytes);
    for end in 0..bytes.len() {
        assert!(SslSession::from_bytes(&bytes[..end], destination.context()).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(SslSession::from_bytes(&trailing, destination.context()).is_err());
    trailing.extend_from_slice(&bytes);
    assert!(SslSession::from_bytes(&trailing, destination.context()).is_err());
    assert!(SslSession::from_bytes(b"not a native session", destination.context()).is_err());
    assert_eq!(format!("{session:?}"), "ScopedSslSession { .. }");
}

#[test]
fn scoped_publication_requires_completed_default_verification() {
    let server = tls13_server(1).build();
    let scope = SslSessionScope::default();
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let client = publication_client();
    let ssl = configured_scoped_ssl(&client, "foobar.com", &scope, &sessions, None).unwrap();
    assert!(!ssl.authenticate_scoped_session_publication());
    let mut stream = ssl.connect(server.connect_tcp()).unwrap();
    stream.read_exact(&mut [0]).unwrap();
    assert!(!sessions.lock().unwrap().is_empty());
    assert!(sessions
        .lock()
        .unwrap()
        .iter()
        .all(|s| !s.is_authenticated()));
    assert!(stream.ssl().authenticate_scoped_session_publication());
    assert!(stream.ssl().authenticate_scoped_session_publication());
    assert!(sessions
        .lock()
        .unwrap()
        .iter()
        .all(ScopedSslSession::is_authenticated));
    assert_eq!(
        format!("{:?}", sessions.lock().unwrap()[0]),
        "ScopedSslSession { .. }"
    );
}

#[test]
fn scoped_publication_late_tickets_inherit_completed_proof() {
    let server = tls13_server(1).build();
    let scope = SslSessionScope::default();
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let client = publication_client();
    let ssl = configured_scoped_ssl(&client, "foobar.com", &scope, &sessions, None).unwrap();
    let mut stream = ssl.connect(server.connect_tcp()).unwrap();
    assert!(sessions.lock().unwrap().is_empty());
    assert!(stream.ssl().authenticate_scoped_session_publication());
    stream.read_exact(&mut [0]).unwrap();
    assert!(!sessions.lock().unwrap().is_empty());
    assert!(sessions
        .lock()
        .unwrap()
        .iter()
        .all(ScopedSslSession::is_authenticated));
}

#[test]
fn scoped_publication_custom_context_verifiers_stay_excluded_after_reset() {
    for verifier in 0..3 {
        for reset in [false, true] {
            let server = tls13_server(1).build();
            let scope = SslSessionScope::default();
            let sessions = Arc::new(Mutex::new(Vec::new()));
            let mut client = publication_client_builder();
            match verifier {
                0 => client.set_cert_verify_callback(|_| true),
                1 => client.set_verify_callback(SslVerifyMode::PEER, |_, _| true),
                _ => client.set_custom_verify_callback(SslVerifyMode::PEER, |_| Ok(())),
            }
            if reset {
                client.set_verify(SslVerifyMode::PEER);
            }
            client.enable_scoped_client_sessions();
            let client = client.build();
            let stream =
                connect_and_read_scoped(&server, &client, "foobar.com", &scope, &sessions, None);
            assert!(!stream.ssl().authenticate_scoped_session_publication());
            assert!(!sessions.lock().unwrap().is_empty());
            assert!(sessions
                .lock()
                .unwrap()
                .iter()
                .all(|s| !s.is_authenticated()));
        }
    }
}

#[test]
fn scoped_publication_custom_ssl_verifiers_before_binding_stay_excluded() {
    for custom in [false, true] {
        for reset in [false, true] {
            let server = tls13_server(1).build();
            let scope = SslSessionScope::default();
            let sessions = Arc::new(Mutex::new(Vec::new()));
            let client = publication_client();
            let mut configured = client.configure().unwrap();
            if custom {
                configured.set_custom_verify_callback(SslVerifyMode::PEER, |_| Ok(()));
            } else {
                configured.set_verify_callback(SslVerifyMode::PEER, |_, _| true);
            }
            if reset {
                configured.set_verify(SslVerifyMode::PEER);
            }
            let collected = Arc::clone(&sessions);
            let ssl = configured
                .into_ssl_with_scoped_session("foobar.com", &scope, None, move |session| {
                    collected.lock().unwrap().push(session.unwrap())
                })
                .unwrap()
                .unwrap();
            let mut stream = ssl.connect(server.connect_tcp()).unwrap();
            stream.read_exact(&mut [0]).unwrap();
            assert!(!stream.ssl().authenticate_scoped_session_publication());
            assert!(!sessions.lock().unwrap().is_empty());
            assert!(sessions
                .lock()
                .unwrap()
                .iter()
                .all(|s| !s.is_authenticated()));
        }
    }
}

#[test]
fn scoped_publication_custom_ssl_verifiers_after_binding_stay_excluded() {
    for custom in [false, true] {
        let server = tls13_server(1).build();
        let scope = SslSessionScope::default();
        let sessions = Arc::new(Mutex::new(Vec::new()));
        let client = publication_client();
        let mut ssl =
            configured_scoped_ssl(&client, "foobar.com", &scope, &sessions, None).unwrap();
        if custom {
            ssl.set_custom_verify_callback(SslVerifyMode::PEER, |_| Ok(()));
        } else {
            ssl.set_verify_callback(SslVerifyMode::PEER, |_, _| true);
        }
        ssl.set_verify(SslVerifyMode::PEER);
        let mut stream = ssl.connect(server.connect_tcp()).unwrap();
        stream.read_exact(&mut [0]).unwrap();
        assert!(!stream.ssl().authenticate_scoped_session_publication());
        assert!(!sessions.lock().unwrap().is_empty());
        assert!(sessions
            .lock()
            .unwrap()
            .iter()
            .all(|s| !s.is_authenticated()));
    }
}

#[test]
fn scoped_publication_verification_mutations_permanently_retire_proof() {
    let mutations: &[fn(&mut SslRef)] = &[
        |ssl| ssl.set_verify(SslVerifyMode::PEER),
        |ssl| ssl.set_verify_depth(100),
        |ssl| ssl.set_verify_callback(SslVerifyMode::PEER, |valid, _| valid),
        |ssl| ssl.set_custom_verify_callback(SslVerifyMode::PEER, |_| Ok(())),
        |ssl| {
            let _ = ssl.verify_param_mut();
        },
        |ssl| {
            let _ = ssl.param_mut();
        },
        |ssl| {
            ssl.set_hostname("foobar.com").unwrap();
        },
        |ssl| {
            let context = ssl.ssl_context().to_owned();
            ssl.set_ssl_context(&context).unwrap();
        },
        |ssl| {
            let original = ssl.ssl_context().to_owned();
            let other = scoped_tls13_client();
            ssl.set_ssl_context(other.context()).unwrap();
            ssl.set_ssl_context(&original).unwrap();
        },
        |ssl| {
            let store = crate::x509::store::X509StoreBuilder::new().unwrap().build();
            ssl.set_verify_cert_store(store).unwrap();
        },
        |ssl| {
            ssl.set_verify_algorithm_prefs(&[
                crate::ssl::SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256,
            ])
            .unwrap();
        },
    ];
    for mutate in mutations {
        let server = tls13_server(1).build();
        let scope = SslSessionScope::default();
        let sessions = Arc::new(Mutex::new(Vec::new()));
        let client = publication_client();
        let mut stream =
            connect_and_read_scoped(&server, &client, "foobar.com", &scope, &sessions, None);
        assert!(stream.ssl().authenticate_scoped_session_publication());
        assert!(sessions
            .lock()
            .unwrap()
            .iter()
            .all(ScopedSslSession::is_authenticated));
        mutate(stream.ssl_mut());
        assert!(!stream.ssl().authenticate_scoped_session_publication());
        assert!(sessions
            .lock()
            .unwrap()
            .iter()
            .all(|s| !s.is_authenticated()));
        stream.ssl_mut().set_verify(SslVerifyMode::PEER);
        assert!(!stream.ssl().authenticate_scoped_session_publication());
    }
}

#[cfg(feature = "rpk")]
#[test]
fn scoped_publication_certificate_type_mutation_retires_proof() {
    let server = tls13_server(1).build();
    let scope = SslSessionScope::default();
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let client = publication_client();
    let mut stream =
        connect_and_read_scoped(&server, &client, "foobar.com", &scope, &sessions, None);
    assert!(stream.ssl().authenticate_scoped_session_publication());
    // A mutation attempt retires provenance even if native configuration rejects it.
    let _result = stream
        .ssl_mut()
        .set_server_certificate_types(&[crate::ssl::CertificateType::X509]);
    assert!(!stream.ssl().authenticate_scoped_session_publication());
    assert!(sessions
        .lock()
        .unwrap()
        .iter()
        .all(|s| !s.is_authenticated()));
}

#[test]
fn scoped_publication_resumption_requires_authenticated_original_source() {
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        let mut server = Server::builder();
        server.expected_connections_count(3);
        server.ctx().set_min_proto_version(Some(version)).unwrap();
        server.ctx().set_max_proto_version(Some(version)).unwrap();
        let server = server.build();
        let mut client = publication_client_builder();
        client.set_min_proto_version(Some(version)).unwrap();
        client.set_max_proto_version(Some(version)).unwrap();
        client.enable_scoped_client_sessions();
        let client = client.build();
        let scope = SslSessionScope::default();
        let sessions = Arc::new(Mutex::new(Vec::new()));
        let first =
            connect_and_read_scoped(&server, &client, "foobar.com", &scope, &sessions, None);
        let source = sessions.lock().unwrap().pop().unwrap();
        assert!(!source.is_authenticated());
        let pending = connect_and_read_scoped(
            &server,
            &client,
            "foobar.com",
            &scope,
            &sessions,
            Some(&source),
        );
        assert!(pending.ssl().session_reused());
        assert!(!pending.ssl().authenticate_scoped_session_publication());
        assert!(first.ssl().authenticate_scoped_session_publication());
        assert!(source.is_authenticated());
        let authenticated = connect_and_read_scoped(
            &server,
            &client,
            "foobar.com",
            &scope,
            &sessions,
            Some(&source),
        );
        assert!(authenticated.ssl().session_reused());
        assert!(authenticated
            .ssl()
            .authenticate_scoped_session_publication());
    }
}

#[test]
fn scoped_publication_disabled_verification_cannot_authenticate() {
    let server = tls13_server(1).build();
    let mut client = publication_client_builder();
    client.set_verify(SslVerifyMode::NONE);
    client.enable_scoped_client_sessions();
    let client = client.build();
    let scope = SslSessionScope::default();
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let stream =
        connect_and_read_scoped(&server, &client, "other.example", &scope, &sessions, None);
    assert!(!stream.ssl().authenticate_scoped_session_publication());
    assert!(!sessions.lock().unwrap().is_empty());
    assert!(sessions
        .lock()
        .unwrap()
        .iter()
        .all(|s| !s.is_authenticated()));
}

#[test]
fn scoped_publication_failed_handshake_remains_pending() {
    let mut server = tls13_server(1);
    server.should_error();
    let server = server.build();
    let client = publication_client();
    let scope = SslSessionScope::default();
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let ssl = configured_scoped_ssl(&client, "other.example", &scope, &sessions, None).unwrap();
    let failure = ssl.connect(server.connect_tcp()).unwrap_err();
    let crate::ssl::HandshakeError::Failure(failed) = failure else {
        panic!("expected failed verification")
    };
    assert!(!failed.ssl().authenticate_scoped_session_publication());
    assert!(sessions
        .lock()
        .unwrap()
        .iter()
        .all(|s| !s.is_authenticated()));
}

#[test]
fn scoped_publication_early_data_waits_for_authenticated_completion() {
    let received = Arc::new(Mutex::new(Vec::new()));
    let server = early_data_server(Arc::clone(&received), |_| true);
    let mut client = publication_client_builder();
    client.enable_scoped_client_sessions_with_early_data();
    let client = client.build();
    let scope = SslSessionScope::default();
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let first = connect_and_read_scoped(&server, &client, "foobar.com", &scope, &sessions, None);
    assert!(first.ssl().authenticate_scoped_session_publication());
    let source = sessions.lock().unwrap().pop().unwrap();
    drop(first);
    let mut ssl =
        configured_scoped_ssl(&client, "foobar.com", &scope, &sessions, Some(&source)).unwrap();
    ssl.set_early_data_enabled(true);
    let mut stream = ssl.connect(server.connect_tcp()).unwrap();
    assert!(stream.ssl().in_early_data());
    assert!(!stream.ssl().authenticate_scoped_session_publication());
    stream.write_all(b"early").unwrap();
    stream.read_exact(&mut [0]).unwrap();
    assert!(!stream.ssl().in_early_data());
    assert!(stream.ssl().authenticate_scoped_session_publication());
    drop(stream);
    drop(server);
    assert_eq!(*received.lock().unwrap(), [b"early".to_vec()]);
}

fn publication_client_builder() -> crate::ssl::SslConnectorBuilder {
    let mut client = tls13_client_builder();
    client.set_verify(SslVerifyMode::PEER);
    client
}

fn publication_client() -> SslConnector {
    let mut client = publication_client_builder();
    client.enable_scoped_client_sessions();
    client.build()
}

#[test]
fn scoped_client_session_resumes_with_matching_scope_and_context() {
    let server = tls13_server(2);
    let server = server.build();
    let scope = SslSessionScope::default();
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let client = scoped_tls13_client();

    let first = connect_and_read_scoped(&server, &client, "foobar.com", &scope, &sessions, None);
    assert!(!first.ssl().session_reused());
    let session = sessions.lock().unwrap().pop().unwrap();
    assert_eq!(session.protocol_version(), SslVersion::TLS1_3);
    assert!(session.should_be_single_use());
    assert!(session.time() > 0);
    assert!(session.timeout() > 0);

    let resumed = connect_and_read_scoped(
        &server,
        &client,
        "foobar.com",
        &scope,
        &sessions,
        Some(&session),
    );
    assert!(resumed.ssl().session_reused());
}

#[test]
fn scoped_client_session_refuses_a_distinct_scope() {
    let server = tls13_server(1);
    let server = server.build();
    let scope = SslSessionScope::default();
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let client = scoped_tls13_client();

    let _ = connect_and_read_scoped(&server, &client, "foobar.com", &scope, &sessions, None);
    let session = sessions.lock().unwrap().pop().unwrap();

    assert!(configured_scoped_ssl(
        &client,
        "foobar.com",
        &SslSessionScope::default(),
        &sessions,
        Some(&session),
    )
    .is_none());
}

#[test]
fn scoped_client_session_refuses_a_distinct_context() {
    let server = tls13_server(1);
    let server = server.build();
    let scope = SslSessionScope::default();
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let client = scoped_tls13_client();

    let _ = connect_and_read_scoped(&server, &client, "foobar.com", &scope, &sessions, None);
    let session = sessions.lock().unwrap().pop().unwrap();
    let other_sessions = Arc::new(Mutex::new(Vec::new()));
    let other_client = scoped_tls13_client();

    assert!(configured_scoped_ssl(
        &other_client,
        "foobar.com",
        &scope,
        &other_sessions,
        Some(&session),
    )
    .is_none());
}

#[test]
fn scoped_client_session_refuses_a_distinct_hostname() {
    let server = tls13_server(1).build();
    let scope = SslSessionScope::default();
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let client = scoped_tls13_client();

    let _ = connect_and_read_scoped(&server, &client, "foobar.com", &scope, &sessions, None);
    let session = sessions.lock().unwrap().pop().unwrap();

    assert!(
        configured_scoped_ssl(&client, "FOOBAR.COM", &scope, &sessions, Some(&session),).is_some()
    );
    assert!(
        configured_scoped_ssl(&client, "other.example", &scope, &sessions, Some(&session),)
            .is_none()
    );
}

#[test]
fn scoped_client_session_hostname_matching_canonicalizes_ip_addresses() {
    assert!(super::super::session_hostnames_match(
        "2001:db8::1",
        "2001:0db8:0:0:0:0:0:1"
    ));
    assert!(super::super::session_hostnames_match(
        "example.com",
        "EXAMPLE.COM"
    ));
    assert!(!super::super::session_hostnames_match(
        "127.0.0.1",
        "127.0.0.2"
    ));
}

#[test]
fn scoped_client_sessions_require_hostname_verification() {
    let scope = SslSessionScope::default();
    let client = scoped_tls13_client();
    let mut configured = client.configure().unwrap();
    configured.set_verify_hostname(false);

    assert!(configured
        .into_ssl_with_scoped_session("foobar.com", &scope, None, |_| {})
        .unwrap()
        .is_none());
}

#[cfg(not(feature = "fips"))]
#[test]
fn scoped_client_session_strips_early_data() {
    let mut server = tls13_server(2);
    // SAFETY: the test server context is live and uniquely owned by its builder.
    unsafe { ffi::SSL_CTX_set_early_data_enabled(server.ctx().as_ptr(), 1) };
    let server = server.build();
    let saw_early_data = Arc::new(AtomicU8::new(0));
    let callback_saw_early_data = Arc::clone(&saw_early_data);
    let mut observing_client = tls13_client_builder();
    // SAFETY: the client context is live and uniquely owned by its builder.
    unsafe { ffi::SSL_CTX_set_early_data_enabled(observing_client.as_ptr(), 1) };
    observing_client
        .set_session_cache_mode(SslSessionCacheMode::CLIENT | SslSessionCacheMode::NO_INTERNAL);
    observing_client.set_new_session_callback(move |_, session| {
        // SAFETY: the callback owns a live session for its duration.
        let capable = unsafe { ffi::SSL_SESSION_early_data_capable(session.as_ref().as_ptr()) };
        callback_saw_early_data.store(capable as u8, Ordering::SeqCst);
    });
    let observing_client = observing_client.build();
    let _ = connect_and_read(&server, &observing_client);
    assert_eq!(saw_early_data.load(Ordering::SeqCst), 1);

    let scope = SslSessionScope::default();
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let mut client = tls13_client_builder();
    // SAFETY: the client context is live and uniquely owned by its builder.
    unsafe { ffi::SSL_CTX_set_early_data_enabled(client.as_ptr(), 1) };
    client.enable_scoped_client_sessions();
    let client = client.build();
    let _ = connect_and_read_scoped(&server, &client, "foobar.com", &scope, &sessions, None);
    let session = sessions.lock().unwrap().pop().unwrap();
    assert_eq!(
        // SAFETY: the scoped session owns a live session.
        unsafe { ffi::SSL_SESSION_early_data_capable(session.session.as_ref().as_ptr()) },
        0
    );
}

#[test]
fn scoped_client_session_with_early_data_sends_accepted_early_data() {
    let received = Arc::new(Mutex::new(Vec::new()));
    let server = early_data_server(Arc::clone(&received), |_| true);
    let scope = SslSessionScope::default();
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let client = scoped_tls13_client_with_early_data();

    let _ = connect_and_read_scoped(&server, &client, "foobar.com", &scope, &sessions, None);
    let session = sessions.lock().unwrap().pop().unwrap();
    assert!(session.early_data_capable());

    let mut ssl =
        configured_scoped_ssl(&client, "foobar.com", &scope, &sessions, Some(&session)).unwrap();
    ssl.set_early_data_enabled(true);
    let mut stream = ssl.connect(server.connect_tcp()).unwrap();
    assert!(stream.ssl().in_early_data());
    assert!(!stream.ssl_mut().reset_early_data_reject());
    stream.write_all(b"early").unwrap();
    stream.read_exact(&mut [0]).unwrap();
    assert!(!stream.ssl().in_early_data());
    assert!(stream.ssl().early_data_accepted());
    assert!(stream.ssl().session_reused());
    drop(stream);
    drop(server);
    assert_eq!(*received.lock().unwrap(), [b"early".to_vec()]);
}

#[test]
fn scoped_client_session_resends_after_rejected_early_data() {
    let received = Arc::new(Mutex::new(Vec::new()));
    // The first connection issues tickets that permit early data; the second
    // declines the early data it is offered.
    let server = early_data_server(Arc::clone(&received), |connection| connection == 0);
    let scope = SslSessionScope::default();
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let client = scoped_tls13_client_with_early_data();

    let _ = connect_and_read_scoped(&server, &client, "foobar.com", &scope, &sessions, None);
    let session = sessions.lock().unwrap().pop().unwrap();

    let mut ssl =
        configured_scoped_ssl(&client, "foobar.com", &scope, &sessions, Some(&session)).unwrap();
    ssl.set_early_data_enabled(true);
    let mut stream = ssl.connect(server.connect_tcp()).unwrap();
    stream.write_all(b"early").unwrap();
    let error = stream.ssl_read(&mut [0]).unwrap_err();
    assert_eq!(error.code(), ErrorCode::EARLY_DATA_REJECTED);
    assert!(stream.ssl_mut().reset_early_data_reject());
    assert!(!stream.ssl_mut().reset_early_data_reject());
    stream.write_all(b"again").unwrap();
    stream.read_exact(&mut [0]).unwrap();
    assert!(!stream.ssl().early_data_accepted());
    drop(stream);
    drop(server);
    assert_eq!(*received.lock().unwrap(), [b"again".to_vec()]);
}

#[test]
fn scoped_client_session_without_early_data_offers_none() {
    let received = Arc::new(Mutex::new(Vec::new()));
    let server = early_data_server(Arc::clone(&received), |_| true);
    let scope = SslSessionScope::default();
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let client = scoped_tls13_client_with_early_data();

    let _ = connect_and_read_scoped(&server, &client, "foobar.com", &scope, &sessions, None);
    let session = sessions.lock().unwrap().pop().unwrap();

    // The session permits early data, but this connection does not enable it.
    let ssl =
        configured_scoped_ssl(&client, "foobar.com", &scope, &sessions, Some(&session)).unwrap();
    let mut stream = ssl.connect(server.connect_tcp()).unwrap();
    assert!(!stream.ssl().in_early_data());
    assert!(stream.ssl().session_reused());
    stream.write_all(b"after").unwrap();
    stream.read_exact(&mut [0]).unwrap();
    assert!(!stream.ssl().early_data_accepted());
    drop(stream);
    drop(server);
    assert_eq!(*received.lock().unwrap(), [b"after".to_vec()]);
}

/// Serves two TLS 1.3 connections, enabling early data on each one for which
/// `accept_early_data` returns true, and records the five bytes read from each
/// connection that sends them.
fn early_data_server(
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    accept_early_data: impl Fn(usize) -> bool + Send + 'static,
) -> Server {
    let mut server = tls13_server(2);
    let connections = AtomicUsize::new(0);
    server.ssl_cb(move |ssl| {
        let connection = connections.fetch_add(1, Ordering::SeqCst);
        ssl.set_early_data_enabled(accept_early_data(connection));
    });
    server.io_cb(move |mut stream| {
        let mut bytes = [0; 5];
        if stream.read_exact(&mut bytes).is_ok() {
            received.lock().unwrap().push(bytes.to_vec());
        }
        // Read the client's remaining handshake messages until it closes, so
        // closing this socket cannot reset the client's unread data.
        let _ = stream.read_to_end(&mut Vec::new());
    });
    server.build()
}

fn scoped_tls13_client_with_early_data() -> SslConnector {
    let mut client = tls13_client_builder();
    client.enable_scoped_client_sessions_with_early_data();
    client.build()
}

fn tls13_server(expected_connections: usize) -> super::server::Builder {
    let mut server = Server::builder();
    server.expected_connections_count(expected_connections);
    server
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server
}

fn tls13_client_builder() -> crate::ssl::SslConnectorBuilder {
    let mut client = SslConnector::bare_builder(crate::ssl::SslMethod::tls()).unwrap();
    client.set_ca_file("test/root-ca.pem").unwrap();
    client
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client
}

fn scoped_tls13_client() -> SslConnector {
    let mut client = tls13_client_builder();
    client.enable_scoped_client_sessions();
    client.build()
}

fn configured_scoped_ssl(
    client: &SslConnector,
    hostname: &str,
    scope: &SslSessionScope,
    sessions: &Arc<Mutex<Vec<ScopedSslSession>>>,
    session: Option<&ScopedSslSession>,
) -> Option<crate::ssl::Ssl> {
    let sessions = Arc::clone(sessions);
    client
        .configure()
        .unwrap()
        .into_ssl_with_scoped_session(hostname, scope, session, move |session| {
            sessions.lock().unwrap().push(session.unwrap());
        })
        .unwrap()
}

fn connect_and_read_scoped(
    server: &Server,
    client: &SslConnector,
    hostname: &str,
    scope: &SslSessionScope,
    sessions: &Arc<Mutex<Vec<ScopedSslSession>>>,
    session: Option<&ScopedSslSession>,
) -> crate::ssl::SslStream<std::net::TcpStream> {
    let ssl = configured_scoped_ssl(client, hostname, scope, sessions, session).unwrap();
    let mut stream = ssl.connect(server.connect_tcp()).unwrap();
    stream.read_exact(&mut [0]).unwrap();
    stream
}

fn connect_and_read(
    server: &Server,
    client: &SslConnector,
) -> crate::ssl::SslStream<std::net::TcpStream> {
    let mut stream = client.connect("foobar.com", server.connect_tcp()).unwrap();
    stream.read_exact(&mut [0]).unwrap();
    stream
}

#[test]
fn custom_callback_success() {
    static SESSION_TICKET: OnceLock<SslSession> = OnceLock::new();
    static NST_RECIEVED_COUNT: AtomicU8 = AtomicU8::new(0);

    let mut server = Server::builder();
    server.expected_connections_count(2);
    unsafe {
        server
            .ctx()
            .set_ticket_key_callback(test_success_tickey_key_callback);
    };
    let server = server.build();

    let mut client = server.client();
    client
        .ctx()
        .set_session_cache_mode(SslSessionCacheMode::CLIENT);
    client.ctx().set_new_session_callback(|_, session| {
        NST_RECIEVED_COUNT.fetch_add(1, Ordering::SeqCst);
        // The server sends multiple session tickets but we only care to retrieve one.
        let _ = SESSION_TICKET.set(session);
    });
    let ssl_stream = client.connect();

    assert!(!ssl_stream.ssl().session_reused());
    assert!(SESSION_TICKET.get().is_some());
    assert_eq!(SUCCESS_ENCRYPTION_CALLED_BACK.load(Ordering::SeqCst), 2);
    assert_eq!(SUCCESS_DECRYPTION_CALLED_BACK.load(Ordering::SeqCst), 0);
    assert_eq!(NST_RECIEVED_COUNT.load(Ordering::SeqCst), 2);

    // Retrieve the session ticket
    let session_ticket = SESSION_TICKET.get().unwrap();

    // Attempt to resume the connection using the session ticket
    let client_2 = server.client();
    let mut ssl_builder = client_2.build().builder();
    unsafe { ssl_builder.ssl().set_session(session_ticket).unwrap() };
    let ssl_stream_2 = ssl_builder.connect();

    assert!(ssl_stream_2.ssl().session_reused());
    assert_eq!(SUCCESS_ENCRYPTION_CALLED_BACK.load(Ordering::SeqCst), 4);
    assert_eq!(SUCCESS_DECRYPTION_CALLED_BACK.load(Ordering::SeqCst), 1);
}

#[test]
fn custom_callback_unrecognized_decryption_ticket() {
    static SESSION_TICKET: OnceLock<SslSession> = OnceLock::new();
    static NST_RECIEVED_COUNT: AtomicU8 = AtomicU8::new(0);

    let mut server = Server::builder();
    server.expected_connections_count(2);
    unsafe {
        server
            .ctx()
            .set_ticket_key_callback(test_noop_tickey_key_callback);
    };
    let server = server.build();

    let mut client = server.client();
    client
        .ctx()
        .set_session_cache_mode(SslSessionCacheMode::CLIENT);
    client.ctx().set_new_session_callback(|_, session| {
        NST_RECIEVED_COUNT.fetch_add(1, Ordering::SeqCst);
        // The server sends multiple session tickets but we only care to retrieve one.
        let _ = SESSION_TICKET.set(session);
    });
    let ssl_stream = client.connect();

    assert!(!ssl_stream.ssl().session_reused());
    assert!(SESSION_TICKET.get().is_some());
    assert_eq!(NOOP_ENCRYPTION_CALLED_BACK.load(Ordering::SeqCst), 2);
    assert_eq!(NOOP_DECRYPTION_CALLED_BACK.load(Ordering::SeqCst), 0);
    assert_eq!(NST_RECIEVED_COUNT.load(Ordering::SeqCst), 2);

    // Retrieve the session ticket
    let session_ticket = SESSION_TICKET.get().unwrap();

    // Attempt to resume the connection using the session ticket
    let client_2 = server.client();
    let mut ssl_builder = client_2.build().builder();
    unsafe { ssl_builder.ssl().set_session(session_ticket).unwrap() };
    let ssl_stream_2 = ssl_builder.connect();

    // Second connection was NOT resumed due to TicketKeyCallbackResult::Noop on decryption
    assert!(!ssl_stream_2.ssl().session_reused());
    assert_eq!(NOOP_ENCRYPTION_CALLED_BACK.load(Ordering::SeqCst), 4);
    assert_eq!(NOOP_DECRYPTION_CALLED_BACK.load(Ordering::SeqCst), 1);
}

// Successfully return a session ticket in encryption mode but return a
// TicketKeyCallbackResult::Noop in decryption mode.
fn test_noop_tickey_key_callback(
    _ssl: &SslRef,
    key_name: &mut [u8; 16],
    iv: &mut [u8; ffi::EVP_MAX_IV_LENGTH as usize],
    evp_ctx: &mut CipherCtxRef,
    hmac_ctx: &mut HmacCtxRef,
    encrypt: bool,
) -> TicketKeyCallbackResult {
    // These should only be used for testing purposes.
    const TEST_KEY_NAME: [u8; 16] = [5; 16];
    const TEST_CBC_IV: [u8; ffi::EVP_MAX_IV_LENGTH as usize] = [1; ffi::EVP_MAX_IV_LENGTH as usize];
    const TEST_AES_128_CBC_KEY: [u8; 16] = [2; 16];
    const TEST_HMAC_KEY: [u8; 32] = [3; 32];

    let digest = MessageDigest::sha256();
    let cipher = Cipher::aes_128_cbc();

    if encrypt {
        NOOP_ENCRYPTION_CALLED_BACK.fetch_add(1, Ordering::SeqCst);

        // Ensure key_name and iv are initialized and set test values.
        assert_eq!(key_name, &[0; 16]);
        assert_eq!(iv, &[0; 16]);
        key_name.copy_from_slice(&TEST_KEY_NAME);
        iv.copy_from_slice(&TEST_CBC_IV);

        // Set the encryption context.
        evp_ctx
            .init_encrypt(&cipher, &TEST_AES_128_CBC_KEY, &TEST_CBC_IV)
            .unwrap();

        // Set the hmac context.
        hmac_ctx.init(&TEST_HMAC_KEY, &digest).unwrap();

        TicketKeyCallbackResult::Success
    } else {
        NOOP_DECRYPTION_CALLED_BACK.fetch_add(1, Ordering::SeqCst);

        // Check key_name matches.
        assert_eq!(key_name, &TEST_KEY_NAME);

        TicketKeyCallbackResult::Noop
    }
}

// Custom callback to encrypt and decrypt session tickets
fn test_success_tickey_key_callback(
    _ssl: &SslRef,
    key_name: &mut [u8; 16],
    iv: &mut [u8; ffi::EVP_MAX_IV_LENGTH as usize],
    evp_ctx: &mut CipherCtxRef,
    hmac_ctx: &mut HmacCtxRef,
    encrypt: bool,
) -> TicketKeyCallbackResult {
    // These should only be used for testing purposes.
    const TEST_KEY_NAME: [u8; 16] = [5; 16];
    const TEST_CBC_IV: [u8; ffi::EVP_MAX_IV_LENGTH as usize] = [1; ffi::EVP_MAX_IV_LENGTH as usize];
    const TEST_AES_128_CBC_KEY: [u8; 16] = [2; 16];
    const TEST_HMAC_KEY: [u8; 32] = [3; 32];

    let digest = MessageDigest::sha256();
    let cipher = Cipher::aes_128_cbc();

    if encrypt {
        SUCCESS_ENCRYPTION_CALLED_BACK.fetch_add(1, Ordering::SeqCst);

        // Ensure key_name and iv are initialized and set test values.
        assert_eq!(key_name, &[0; 16]);
        assert_eq!(iv, &[0; 16]);
        key_name.copy_from_slice(&TEST_KEY_NAME);
        iv.copy_from_slice(&TEST_CBC_IV);

        // Set the encryption context.
        evp_ctx
            .init_encrypt(&cipher, &TEST_AES_128_CBC_KEY, &TEST_CBC_IV)
            .unwrap();

        // Set the hmac context.
        hmac_ctx.init(&TEST_HMAC_KEY, &digest).unwrap();
    } else {
        SUCCESS_DECRYPTION_CALLED_BACK.fetch_add(1, Ordering::SeqCst);

        // Check key_name matches.
        assert_eq!(key_name, &TEST_KEY_NAME);

        // Set the decryption context.
        evp_ctx
            .init_decrypt(&cipher, &TEST_AES_128_CBC_KEY, iv)
            .unwrap();

        // Set the hmac context.
        hmac_ctx.init(&TEST_HMAC_KEY, &digest).unwrap();
    }

    TicketKeyCallbackResult::Success
}
