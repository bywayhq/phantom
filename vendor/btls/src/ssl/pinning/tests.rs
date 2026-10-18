use std::{
    error::Error,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::{
    ssl::{
        HandshakeError, ScopedSslSession, Ssl, SslAcceptor, SslAcceptorBuilder, SslConnector,
        SslFiletype, SslMethod, SslSessionScope, SslVerifyMode, SslVersion,
    },
    x509::X509,
};

use super::{spki_sha256, SpkiPinConfigurationError, SpkiPinVerification, SpkiPins};

type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

fn fixture_pin() -> TestResult<[u8; 32]> {
    // Independent OpenSSL 3.5.6: x509 -pubkey | pkey -pubin -outform DER |
    // dgst -sha256. This hashes the full SPKI, not X509_pubkey_digest's bit string.
    Ok(
        hex::decode("5474006cd97aee79a464934449e4cabd3c5be5b42677599a5a730a1bfb637006")?
            .try_into()
            .map_err(|_| "fixture pin length")?,
    )
}

#[test]
fn spki_digest_matches_an_independent_encoding() -> TestResult<()> {
    let leaf = X509::from_pem(include_bytes!("../../../test/cert.pem"))?;
    assert_eq!(spki_sha256(&leaf)?, fixture_pin()?);
    let cert_hash = leaf.digest(crate::hash::MessageDigest::sha256())?;
    assert_ne!(spki_sha256(&leaf)?.as_slice(), &*cert_hash);
    Ok(())
}

#[test]
fn pin_identity_is_canonical_and_rejects_unbounded_configuration() -> TestResult<()> {
    let first = SpkiPins::new(vec![[2; 32], [1; 32], [2; 32]])?;
    let second = SpkiPins::new(vec![[1; 32], [2; 32]])?;
    assert_eq!(first, second);
    assert_eq!(first.sha256_digests(), &[[1; 32], [2; 32]]);
    assert_eq!(
        SpkiPins::new(Vec::new()).unwrap_err(),
        SpkiPinConfigurationError::InvalidCount
    );
    assert_eq!(
        SpkiPins::new(vec![[0; 32]; 33]).unwrap_err(),
        SpkiPinConfigurationError::InvalidCount
    );
    let mut context = SslConnector::builder(SslMethod::tls())?;
    context.set_cert_verify_callback(|_| true);
    assert_eq!(
        context.set_spki_pins(first).unwrap_err(),
        SpkiPinConfigurationError::CustomVerifier
    );
    Ok(())
}

#[test]
fn leaf_pins_restrict_native_chain_and_hostname_verification() -> TestResult<()> {
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        for (trusted, hostname, matching, expected) in [
            (true, "foobar.com", true, SpkiPinVerification::Matched),
            (true, "foobar.com", false, SpkiPinVerification::Mismatch),
            (
                false,
                "foobar.com",
                true,
                SpkiPinVerification::CertificateInvalid,
            ),
            (
                false,
                "foobar.com",
                false,
                SpkiPinVerification::CertificateInvalid,
            ),
            (
                true,
                "wrong.example",
                true,
                SpkiPinVerification::CertificateInvalid,
            ),
        ] {
            let accepted = expected == SpkiPinVerification::Matched;
            let mut builder = SslConnector::builder(SslMethod::tls())?;
            builder.set_min_proto_version(Some(version))?;
            builder.set_max_proto_version(Some(version))?;
            if trusted {
                builder.set_ca_file("test/root-ca.pem")?;
            }
            let pin = if matching { fixture_pin()? } else { [0; 32] };
            builder.set_spki_pins(SpkiPins::new(vec![pin])?)?;
            let connector = builder.build();
            let peer = Peer::start(accepted)?;
            let result = request(&connector, peer.address, hostname);
            let cleanup = peer.finish();
            let ((sent, state), received) = match (result, cleanup) {
                (Ok(result), Ok(received)) => (result, received),
                (client, peer) => return Err(format!("client: {client:?}; peer: {peer:?}").into()),
            };
            assert_eq!(state, expected, "version {version:?}, trusted {trusted}");
            assert_eq!(sent, accepted);
            assert_eq!(received, usize::from(accepted));
        }
    }
    Ok(())
}

fn request(
    connector: &SslConnector,
    address: SocketAddr,
    name: &str,
) -> TestResult<(bool, SpkiPinVerification)> {
    let ssl = connector.configure()?.into_ssl(name)?;
    match ssl.connect(socket(address)?) {
        Ok(mut stream) => {
            let result = stream.ssl().spki_pin_verification();
            stream.write_all(b"x")?;
            stream.read_exact(&mut [0])?;
            Ok((true, result))
        }
        Err(HandshakeError::Failure(stream)) => Ok((false, stream.ssl().spki_pin_verification())),
        Err(error) => Err(format!("unexpected handshake setup outcome: {error:?}").into()),
    }
}

fn socket(address: SocketAddr) -> TestResult<TcpStream> {
    let socket = TcpStream::connect_timeout(&address, Duration::from_secs(3))?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    socket.set_write_timeout(Some(Duration::from_secs(3)))?;
    Ok(socket)
}

fn pinned_client(version: SslVersion) -> TestResult<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_min_proto_version(Some(version))?;
    builder.set_max_proto_version(Some(version))?;
    builder.set_ca_file("test/root-ca.pem")?;
    builder.set_spki_pins(SpkiPins::new(vec![[0; 32], fixture_pin()?])?)?;
    builder.enable_scoped_client_sessions();
    Ok(builder.build())
}

fn scoped_ssl(
    client: &SslConnector,
    scope: &SslSessionScope,
    sessions: &Arc<Mutex<Vec<ScopedSslSession>>>,
    offered: Option<&ScopedSslSession>,
) -> TestResult<Option<Ssl>> {
    let captured = Arc::clone(sessions);
    Ok(client.configure()?.into_ssl_with_scoped_session(
        "foobar.com",
        scope,
        offered,
        move |session| {
            captured
                .lock()
                .expect("session collection poisoned")
                .push(session.expect("native session copy"));
        },
    )?)
}

#[test]
fn pinned_resumption_requires_authenticated_source_before_attachment() -> TestResult<()> {
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        let client = pinned_client(version)?;
        let scope = SslSessionScope::default();
        let sessions = Arc::new(Mutex::new(Vec::new()));
        let peer = Peer::start_many(true, 2, |context| {
            context.set_min_proto_version(Some(version))?;
            context.set_max_proto_version(Some(version))?;
            context.set_session_id_context(b"pinning-test")?;
            Ok(())
        })?;
        let result = (|| -> TestResult<()> {
            let first =
                scoped_ssl(&client, &scope, &sessions, None)?.ok_or("fresh binding rejected")?;
            assert!(!first.authenticate_scoped_session_publication());
            let mut first = first.connect(socket(peer.address)?)?;
            first.write_all(b"x")?;
            first.read_exact(&mut [0])?;
            assert_eq!(
                first.ssl().spki_pin_verification(),
                SpkiPinVerification::Matched
            );
            assert!(!first.ssl().session_reused());
            let session = sessions
                .lock()
                .map_err(|_| "session collection poisoned")?
                .pop()
                .ok_or("no ticket")?;
            assert!(!session.is_authenticated());
            assert!(scoped_ssl(&client, &scope, &sessions, Some(&session))?.is_none());
            assert!(first.ssl().authenticate_scoped_session_publication());
            assert!(session.is_authenticated());
            let other = pinned_client(version)?;
            assert!(scoped_ssl(&other, &scope, &sessions, Some(&session))?.is_none());
            drop(first);
            let resumed = scoped_ssl(&client, &scope, &sessions, Some(&session))?
                .ok_or("authenticated binding rejected")?;
            assert_eq!(
                resumed.spki_pin_verification(),
                SpkiPinVerification::Pending
            );
            let mut resumed = resumed.connect(socket(peer.address)?)?;
            resumed.write_all(b"x")?;
            resumed.read_exact(&mut [0])?;
            assert!(resumed.ssl().session_reused());
            assert_eq!(
                resumed.ssl().spki_pin_verification(),
                SpkiPinVerification::Resumed
            );
            assert!(resumed.ssl().authenticate_scoped_session_publication());
            Ok(())
        })();
        let received = peer.finish();
        match (result, received) {
            (Ok(()), Ok(2)) => {}
            (client, peer) => {
                return Err(format!("resumption client: {client:?}; peer: {peer:?}").into())
            }
        }
    }
    Ok(())
}

#[test]
fn per_ssl_verifier_override_cannot_acquire_pinned_publication_authority() -> TestResult<()> {
    for custom in [false, true] {
        let client = pinned_client(SslVersion::TLS1_3)?;
        let scope = SslSessionScope::default();
        let sessions = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&sessions);
        let mut before = client.configure()?;
        before.set_custom_verify_callback(SslVerifyMode::PEER, |_| Ok(()));
        assert!(before
            .into_ssl_with_scoped_session("foobar.com", &scope, None, |_| {})?
            .is_none());
        let mut ssl = scoped_ssl(&client, &scope, &sessions, None)?.ok_or("binding rejected")?;
        if custom {
            ssl.set_custom_verify_callback(SslVerifyMode::PEER, |_| Ok(()));
        } else {
            ssl.set_verify_callback(SslVerifyMode::PEER, |_, _| true);
        }
        ssl.set_verify(SslVerifyMode::PEER);
        let peer = Peer::start(false)?;
        let result = (|| -> TestResult<()> {
            match ssl.connect(socket(peer.address)?) {
                Ok(mut stream) if custom => {
                    stream.read_exact(&mut [0])?;
                    assert!(!stream.ssl().authenticate_scoped_session_publication());
                    assert!(!captured
                        .lock()
                        .map_err(|_| "session collection poisoned")?
                        .is_empty());
                }
                Err(HandshakeError::Failure(stream)) if !custom => {
                    assert_eq!(
                        stream.ssl().spki_pin_verification(),
                        SpkiPinVerification::BackendFailure
                    );
                    assert!(!stream.ssl().authenticate_scoped_session_publication());
                }
                outcome => return Err(format!("unexpected override outcome: {outcome:?}").into()),
            }
            assert!(captured
                .lock()
                .map_err(|_| "session collection poisoned")?
                .iter()
                .all(|session| !session.is_authenticated()));
            Ok(())
        })();
        let cleanup = peer.finish();
        if result.is_err() || !matches!(cleanup, Ok(0)) {
            return Err(format!("override client: {result:?}; peer: {cleanup:?}").into());
        }
    }
    Ok(())
}

#[cfg(not(feature = "fips"))]
#[test]
fn ech_rejection_authenticates_retry_configs_without_origin_pin_authority() -> TestResult<()> {
    use crate::{hpke::HpkeKey, ssl::SslEchKeys};
    for rejected in [false, true] {
        let (config, key): (&[u8], &[u8]) = if rejected {
            (
                include_bytes!("../../../test/echconfig-2"),
                include_bytes!("../../../test/echkey-2"),
            )
        } else {
            (
                include_bytes!("../../../test/echconfig"),
                include_bytes!("../../../test/echkey"),
            )
        };
        let mut keys = SslEchKeys::builder()?;
        keys.add_key(true, config, HpkeKey::dhkem_p256_sha256(key)?)?;
        let keys = keys.build();
        let peer = Peer::start_many(!rejected, 1, |context| {
            context.set_ech_keys(&keys)?;
            Ok(())
        })?;
        let result = (|| -> TestResult<()> {
            let mut builder = SslConnector::builder(SslMethod::tls())?;
            builder.set_ca_file("test/root-ca.pem")?;
            builder.set_spki_pins(SpkiPins::new(vec![if rejected {
                [0; 32]
            } else {
                fixture_pin()?
            }])?)?;
            builder.enable_scoped_client_sessions();
            let client = builder.build();
            let scope = SslSessionScope::default();
            let sessions = Arc::new(Mutex::new(Vec::new()));
            let mut ssl =
                scoped_ssl(&client, &scope, &sessions, None)?.ok_or("ECH binding rejected")?;
            ssl.set_ech_config_list(include_bytes!("../../../test/echconfiglist"))?;
            match ssl.connect(socket(peer.address)?) {
                Ok(mut stream) if !rejected => {
                    assert!(stream.ssl().ech_accepted());
                    assert_eq!(
                        stream.ssl().spki_pin_verification(),
                        SpkiPinVerification::Matched
                    );
                    assert!(stream.ssl().authenticate_scoped_session_publication());
                    stream.write_all(b"x")?;
                    stream.read_exact(&mut [0])?;
                }
                Err(HandshakeError::Failure(stream)) if rejected => {
                    assert_eq!(
                        stream.ssl().spki_pin_verification(),
                        SpkiPinVerification::EchRejected
                    );
                    assert!(stream.ssl().get_ech_retry_configs().is_some());
                    assert_eq!(stream.ssl().get_ech_name_override(), Some(&b"ech.com"[..]));
                    assert!(!stream.ssl().authenticate_scoped_session_publication());
                    assert!(sessions
                        .lock()
                        .map_err(|_| "session collection poisoned")?
                        .iter()
                        .all(|s| !s.is_authenticated()));
                }
                outcome => return Err(format!("unexpected ECH outcome: {outcome:?}").into()),
            }
            Ok(())
        })();
        let received = peer.finish();
        match (result, received) {
            (Ok(()), Ok(count)) if count == usize::from(!rejected) => {}
            (client, peer) => return Err(format!("ECH client: {client:?}; peer: {peer:?}").into()),
        }
    }
    Ok(())
}

struct Peer {
    address: SocketAddr,
    child: Option<JoinHandle<TestResult<usize>>>,
}

impl Peer {
    fn start(accepts_application_data: bool) -> TestResult<Self> {
        Self::start_many(accepts_application_data, 1, |_| Ok(()))
    }

    fn start_many(
        accepts_application_data: bool,
        connections: usize,
        configure: impl FnOnce(&mut SslAcceptorBuilder) -> TestResult<()>,
    ) -> TestResult<Self> {
        let mut context = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        context.set_certificate_chain_file("test/cert.pem")?;
        context.set_private_key_file("test/key.pem", SslFiletype::PEM)?;
        context.check_private_key()?;
        configure(&mut context)?;
        let context = context.build();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let child = thread::spawn(move || {
            let mut received = 0;
            for _ in 0..connections {
                let deadline = Instant::now() + Duration::from_secs(5);
                let socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                return Err("pin peer was not connected".into());
                            }
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => return Err(error.into()),
                    }
                };
                socket.set_read_timeout(Some(Duration::from_secs(3)))?;
                socket.set_write_timeout(Some(Duration::from_secs(3)))?;
                received += match context.accept(socket) {
                    Ok(mut stream) => {
                        if let Err(error) = stream.write_all(b"y") {
                            if accepts_application_data {
                                return Err(error.into());
                            }
                            continue;
                        }
                        let mut byte = [0];
                        match stream.read(&mut byte) {
                            Ok(length) => Ok(length),
                            Err(_) if !accepts_application_data => Ok(0),
                            Err(error) => Err(error.into()),
                        }
                    }
                    Err(_) if !accepts_application_data => Ok(0),
                    Err(error) => Err(format!("pin peer handshake failed: {error:?}").into()),
                }?;
            }
            Ok(received)
        });
        Ok(Self {
            address,
            child: Some(child),
        })
    }

    fn finish(mut self) -> TestResult<usize> {
        self.child
            .take()
            .ok_or("pin peer missing")?
            .join()
            .map_err(|_| "pin peer panicked")?
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            // A panic still owns this bounded peer through termination.
            let result = child.join();
            if !matches!(result, Ok(Ok(_))) {
                eprintln!("pin peer cleanup failed: {result:?}");
            }
        }
    }
}
