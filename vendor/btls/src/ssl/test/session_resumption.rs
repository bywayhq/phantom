use super::server::Server;
#[cfg(not(feature = "fips"))]
use crate::ffi;
use crate::ssl::test::MessageDigest;
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
#[cfg(not(feature = "fips"))]
use foreign_types::ForeignTypeRef;
use std::io::Read;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};

static SUCCESS_ENCRYPTION_CALLED_BACK: AtomicU8 = AtomicU8::new(0);
static SUCCESS_DECRYPTION_CALLED_BACK: AtomicU8 = AtomicU8::new(0);
static NOOP_ENCRYPTION_CALLED_BACK: AtomicU8 = AtomicU8::new(0);
static NOOP_DECRYPTION_CALLED_BACK: AtomicU8 = AtomicU8::new(0);

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
