use std::{error::Error, pin::Pin};

use btls::{
    hpke::HpkeKey,
    ssl::{AlpnError, Ssl, SslAcceptor, SslEchKeys, select_next_proto},
};
use phantom_profile::browser::firefox;
use phantom_testkit::tls::{TEST_ECH_KEYS, ech_config, ech_config_list};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_btls::SslStream as BoringStream;

use crate::{
    EchFailure,
    connection_diagnostics::{TlsMetadata, TlsPeerRole},
    tls::{
        EarlyData, TlsConnector, TlsErrorKind, TlsStream, negotiated_tls_version,
        test_support::{TEST_TIMEOUT, TestIdentity, TestResult, TestServerAlpn, loopback_listener},
        tests::session_cache::finish_ticket_control_peer,
    },
};

const INNER_NAME: &str = "inner.phantom.test";
const PUBLIC_NAME: &str = "public.phantom.test";

enum RejectionCase {
    ReplacementConfigs,
    RemoveEch,
    InvalidPublicName,
}

#[tokio::test]
async fn deferred_ech_rejection_retains_retry_configs_for_each_waiter() -> TestResult<()> {
    rejection(RejectionCase::ReplacementConfigs).await
}

#[tokio::test]
async fn deferred_ech_rejection_retains_the_decision_to_remove_ech() -> TestResult<()> {
    rejection(RejectionCase::RemoveEch).await
}

#[tokio::test]
async fn deferred_certificate_failure_does_not_authenticate_ech_retry_configs() -> TestResult<()> {
    rejection(RejectionCase::InvalidPublicName).await
}

async fn rejection(case: RejectionCase) -> TestResult<()> {
    let publish_retry = !matches!(case, RejectionCase::RemoveEch);
    let valid_public_name = !matches!(case, RejectionCase::InvalidPublicName);
    let names = if valid_public_name {
        &[INNER_NAME, PUBLIC_NAME][..]
    } else {
        &[INNER_NAME][..]
    };
    let identity = TestIdentity::generate_for_names(names)?;
    let mut builder = identity.acceptor_builder()?;
    builder.set_alpn_select_callback(|_, offered| {
        select_next_proto(b"\x02h2", offered).ok_or(AlpnError::NOACK)
    });
    let seed_config = ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME);
    let retry_config = ech_config(2, &TEST_ECH_KEYS[1], PUBLIC_NAME);
    let mut keys = SslEchKeys::builder()?;
    keys.add_key(
        true,
        &seed_config,
        HpkeKey::dhkem_p256_sha256(&TEST_ECH_KEYS[0].private_key)?,
    )?;
    builder.set_ech_keys(&keys.build())?;
    let acceptor = builder.build();
    let mut rotated = SslEchKeys::builder()?;
    if publish_retry {
        rotated.add_key(
            true,
            &retry_config,
            HpkeKey::dhkem_p256_sha256(&TEST_ECH_KEYS[1].private_key)?,
        )?;
    }
    let rotated = rotated.build();
    let without_ech = (!publish_retry)
        .then(|| identity.acceptor(TestServerAlpn::H2))
        .transpose()?;
    let connector = TlsConnector::new_with_roots(&firefox::v157_tcp_tls(), [identity.root_der()])?
        .with_isolated_session_cache();
    let (address, listener) = loopback_listener().await?;
    let mut peer = tokio::spawn(async move {
        let mut seed = server_stream(&listener, &acceptor).await?;
        Pin::new(&mut seed).accept().await?;
        assert!(seed.ssl().ech_accepted());
        seed.write_all(b"x").await?;
        seed.flush().await?;
        if publish_retry {
            // Change only ECH keys; the same context keeps the ticket keys.
            acceptor.context().set_ech_keys(&rotated)?;
        }
        let mut byte = [0_u8; 1];
        assert_eq!(seed.read(&mut byte).await?, 0);

        // Removing ECH uses a plain server context, which also rejects the
        // old ticket. The client still offers early data before learning this.
        let mut resumed =
            server_stream(&listener, without_ech.as_ref().unwrap_or(&acceptor)).await?;
        let handshake = Pin::new(&mut resumed).accept().await;
        assert!(!resumed.ssl().ech_accepted());
        assert!(!resumed.ssl().early_data_accepted());
        if handshake.is_ok() {
            // The client must fail authentication instead of replaying bytes
            // over the public-name connection.
            let read = resumed.read(&mut byte).await;
            assert!(!matches!(read, Ok(count) if count > 0));
        }
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });

    let exchange = tokio::time::timeout(TEST_TIMEOUT, async {
        let configs = ech_config_list(&[seed_config]);
        let tcp = TcpStream::connect(address).await?;
        let mut seed = connector
            .connect_with_ech(INNER_NAME, tcp, Some(&configs))
            .await?;
        let mut byte = [0_u8; 1];
        seed.read_exact(&mut byte).await?;
        seed.inner.shutdown().await?;
        drop(seed);
        let cache = connector
            .session_cache
            .as_ref()
            .ok_or("ticket cache missing")?;
        let session = cache.take(INNER_NAME).ok_or("source ticket missing")?;
        if !session.early_data_capable() {
            return Err("source ticket does not permit early data".into());
        }
        while cache.take(INNER_NAME).is_some() {}
        cache.restore(INNER_NAME, session);

        let mut stream = deferred_stream(&connector, address, &configs).await?;
        let first = stream
            .early_data_wait()
            .ok_or("no deferred authentication")?;
        let second = first.clone();
        stream.write_all(b"early").await?;
        stream.flush().await?;
        if stream.read(&mut byte).await.is_ok() {
            return Err("deferred ECH authentication unexpectedly succeeded".into());
        }
        drop(stream);
        if cache.len() != 0 {
            return Err("failed ECH authentication published session tickets".into());
        }

        for waiter in [first, second] {
            if waiter.answered().await.is_ok() {
                return Err("waiter reported a successful deferred ECH handshake".into());
            }
            let failure = waiter.failure().ok_or("missing deferred failure")?;
            // Taking one reconstructed error's configs cannot consume them
            // from another waiter or a later conversion of the same failure.
            for _ in 0..2 {
                let mut error = failure.tls_error().ok_or("missing TLS failure")?;
                if error.kind() != TlsErrorKind::Handshake {
                    return Err(
                        format!("wrong deferred TLS failure kind: {:?}", error.kind()).into(),
                    );
                }
                let backend = error
                    .source()
                    .and_then(|source| source.source())
                    .and_then(|source| source.downcast_ref::<btls::ssl::Error>())
                    .ok_or("deferred failure lost its backend source")?;
                if backend.ssl_error().is_none() {
                    return Err("deferred TLS failure omitted its backend error stack".into());
                }
                if valid_public_name {
                    if error.ech_failure() != Some(EchFailure::Rejected) {
                        return Err(
                            "authenticated deferred rejection lost its ECH classification".into(),
                        );
                    }
                    let expected =
                        publish_retry.then(|| ech_config_list(std::slice::from_ref(&retry_config)));
                    if error.take_ech_retry_configs().as_deref() != expected.as_deref() {
                        return Err(
                            "authenticated deferred rejection changed its retry decision".into(),
                        );
                    }
                } else {
                    if error.ech_failure().is_some() {
                        return Err(
                            "certificate failure was classified as authenticated ECH rejection"
                                .into(),
                        );
                    }
                    // SSL_R_CERTIFICATE_VERIFY_FAILED at the pinned
                    // BoringSSL include/openssl/ssl.h revision.
                    if !backend.ssl_error().is_some_and(|stack| {
                        stack
                            .errors()
                            .iter()
                            .any(|entry| entry.library_code() == 16 && entry.reason_code() == 125)
                    }) {
                        return Err(
                            "invalid public-name certificate did not fail verification".into()
                        );
                    }
                    if error.take_ech_retry_configs().is_some() {
                        return Err(
                            "certificate failure exposed unauthenticated ECH retry configs".into(),
                        );
                    }
                }
            }
        }
        Ok(())
    })
    .await;
    let result: TestResult<()> = match exchange {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };
    finish_ticket_control_peer(result, &mut peer, TEST_TIMEOUT).await
}

async fn server_stream(
    listener: &tokio::net::TcpListener,
    acceptor: &SslAcceptor,
) -> TestResult<BoringStream<TcpStream>> {
    let (tcp, _) = listener.accept().await?;
    let mut ssl = Ssl::new(acceptor.context())?;
    ssl.set_early_data_enabled(true);
    Ok(BoringStream::new(ssl, tcp)?)
}

/// Exercise the deferred owner with a real ECH/early-data handshake without
/// changing either production guard that excludes this combination.
async fn deferred_stream(
    connector: &TlsConnector,
    address: std::net::SocketAddr,
    configs: &[u8],
) -> TestResult<TlsStream<TcpStream>> {
    let cache = connector
        .session_cache
        .as_ref()
        .ok_or("ticket cache missing")?;
    let capture = cache.begin_handshake(INNER_NAME);
    let session = capture.take_session().ok_or("resumption ticket missing")?;
    let mut configuration = connector.handshake_configuration(INNER_NAME, Some(configs))?;
    configuration.set_early_data_enabled(true);
    let callback_capture = capture.clone();
    let ssl = configuration
        .into_ssl_with_scoped_session(INNER_NAME, cache.scope(), Some(&session), move |session| {
            callback_capture.capture(session)
        })?
        .ok_or("session scope changed")?;
    let mut inner = BoringStream::new(ssl, TcpStream::connect(address).await?)?;
    Pin::new(&mut inner).connect().await?;
    if !inner.ssl().in_early_data() {
        return Err("resumed handshake did not defer authentication for early data".into());
    }
    let negotiated_alpn = inner.ssl().selected_alpn_protocol().map(Box::from);
    Ok(TlsStream {
        ech_accepted: inner.ssl().ech_accepted(),
        early_data: Some(Box::new(EarlyData::new(
            negotiated_alpn.clone(),
            Some(capture),
        ))),
        negotiated_alpn,
        peer_application_settings: inner.ssl().peer_application_settings().map(Box::from),
        negotiated_tls_version: negotiated_tls_version(inner.ssl().version2()),
        negotiated_cipher_suite: None,
        session_reused: inner.ssl().session_reused(),
        metadata: TlsMetadata::new(TlsPeerRole::Origin, true),
        close_notify: connector.close_notify,
        inner,
    })
}
