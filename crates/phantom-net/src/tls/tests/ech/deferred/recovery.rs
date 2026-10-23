use std::sync::{Arc, Mutex, PoisonError};

use btls::ssl::{ExtensionType, SelectCertError, SslAcceptorBuilder};

use super::*;
use crate::direct::{Dialer, DirectTlsError, retry_ech};

enum RetryCase {
    ReplacementConfigs,
    RemoveEch,
    SecondRejection,
}

#[derive(Debug, PartialEq)]
struct Offer {
    psk: bool,
    early_data: bool,
}

#[tokio::test]
async fn deferred_ech_retry_uses_a_full_handshake_and_preserves_unused_tickets() -> TestResult<()> {
    recovery(RetryCase::ReplacementConfigs).await
}

#[tokio::test]
async fn deferred_ech_retry_can_authenticate_without_ech() -> TestResult<()> {
    recovery(RetryCase::RemoveEch).await
}

#[tokio::test]
async fn deferred_ech_retry_cannot_retry_a_second_authenticated_rejection() -> TestResult<()> {
    recovery(RetryCase::SecondRejection).await
}

async fn recovery(case: RetryCase) -> TestResult<()> {
    let identity = TestIdentity::generate_for_names(&[INNER_NAME, PUBLIC_NAME])?;
    let offers = Arc::new(Mutex::new(Vec::new()));
    let builder = recording_acceptor(&identity, &offers)?;
    let seed_config = ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME);
    let retry_config = ech_config(2, &TEST_ECH_KEYS[1], PUBLIC_NAME);
    let mut seed_keys = SslEchKeys::builder()?;
    seed_keys.add_key(
        true,
        &seed_config,
        HpkeKey::dhkem_p256_sha256(&TEST_ECH_KEYS[0].private_key)?,
    )?;
    builder.set_ech_keys(&seed_keys.build())?;
    let acceptor = builder.build();
    let mut rotated = SslEchKeys::builder()?;
    if !matches!(case, RetryCase::RemoveEch) {
        rotated.add_key(
            true,
            &retry_config,
            HpkeKey::dhkem_p256_sha256(&TEST_ECH_KEYS[1].private_key)?,
        )?;
    }
    let rotated = rotated.build();
    // BoringSSL rejects an ECH key set with no retry configuration. Removing
    // ECH therefore uses an ordinary server context, as the existing native
    // deferred-authentication control does.
    let without_ech = matches!(case, RetryCase::RemoveEch)
        .then(|| recording_acceptor(&identity, &offers).map(|builder| builder.build()))
        .transpose()?;
    let connector = TlsConnector::new_with_roots(&firefox::v157_tcp_tls(), [identity.root_der()])?
        .with_isolated_session_cache();
    let (address, listener) = loopback_listener().await?;
    let expects_rejection = matches!(case, RetryCase::SecondRejection);
    let expects_ech = !matches!(case, RetryCase::RemoveEch);
    let mut peer = tokio::spawn(async move {
        let mut seed = server_stream(&listener, &acceptor).await?;
        Pin::new(&mut seed).accept().await?;
        assert!(seed.ssl().ech_accepted());
        seed.write_all(b"x").await?;
        seed.flush().await?;
        if without_ech.is_none() {
            acceptor.context().set_ech_keys(&rotated)?;
        }
        let mut byte = [0_u8; 1];
        assert_eq!(seed.read(&mut byte).await?, 0);
        let acceptor = without_ech.unwrap_or(acceptor);

        let mut rejected = server_stream(&listener, &acceptor).await?;
        let handshake = Pin::new(&mut rejected).accept().await;
        assert!(!rejected.ssl().ech_accepted());
        assert!(!rejected.ssl().early_data_accepted());
        if handshake.is_ok() {
            assert!(!matches!(rejected.read(&mut byte).await, Ok(count) if count > 0));
        }
        drop(rejected);

        if expects_rejection {
            let config = ech_config(3, &TEST_ECH_KEYS[0], PUBLIC_NAME);
            let mut keys = SslEchKeys::builder()?;
            keys.add_key(
                true,
                &config,
                HpkeKey::dhkem_p256_sha256(&TEST_ECH_KEYS[0].private_key)?,
            )?;
            acceptor.context().set_ech_keys(&keys.build())?;
        }
        let mut recovered = server_stream(&listener, &acceptor).await?;
        let handshake = Pin::new(&mut recovered).accept().await;
        assert!(!recovered.ssl().session_reused());
        assert!(!recovered.ssl().early_data_accepted());
        if expects_rejection {
            assert!(!recovered.ssl().ech_accepted());
            if handshake.is_ok() {
                assert!(!matches!(recovered.read(&mut byte).await, Ok(count) if count > 0));
            }
        } else {
            handshake?;
            assert_eq!(recovered.ssl().ech_accepted(), expects_ech);
            let mut request = [0_u8; 9];
            recovered.read_exact(&mut request).await?;
            assert_eq!(&request, b"recovered");
            recovered.write_all(b"y").await?;
            recovered.flush().await?;
        }
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });
    let exchange = tokio::time::timeout(TEST_TIMEOUT, async {
        let configs = ech_config_list(&[seed_config]);
        let mut seed = connector
            .connect_with_ech(
                INNER_NAME,
                TcpStream::connect(address).await?,
                Some(&configs),
            )
            .await?;
        let mut byte = [0_u8; 1];
        seed.read_exact(&mut byte).await?;
        seed.inner.shutdown().await?;
        drop(seed);
        let cache = connector
            .session_cache
            .as_ref()
            .ok_or("missing session cache")?;
        if cache.len() < 2 {
            return Err("seed did not issue an unused control ticket".into());
        }
        let mut failed = deferred_stream(&connector, address, &configs).await?;
        failed.set_ech_retry_peer(&connector, INNER_NAME, address);
        let first = failed
            .early_data_wait()
            .ok_or("missing deferred handshake")?;
        let second = first.clone();
        failed.write_all(b"early").await?;
        failed.flush().await?;
        if failed.read(&mut byte).await.is_ok() {
            return Err("old ECH configuration unexpectedly authenticated".into());
        }
        drop(failed);
        if cache.len() == 0 {
            return Err("failed handshake discarded the unused control ticket".into());
        }
        let failure = first.failure().ok_or("missing first failure")?;
        let error = failure.tls_error().ok_or("missing first TLS error")?;
        let retry = error
            .ech_retry()
            .ok_or("missing authenticated ECH retry")?
            .clone();
        let failure = second.failure().ok_or("missing second failure")?;
        let error = failure.tls_error().ok_or("missing second TLS error")?;
        let other = error
            .ech_retry()
            .ok_or("second waiter lost ECH retry")?
            .clone();
        let unrelated = TlsConnector::new_with_roots(
            &firefox::v157_tcp_tls(),
            [identity.root_der()],
        )?;
        for (connector, name) in [(&connector, PUBLIC_NAME), (&unrelated, INNER_NAME)] {
            if !matches!(retry_ech(connector, Dialer::default(), name, &retry).await,
                Err(DirectTlsError::Tls(error)) if error.kind() == TlsErrorKind::InvalidConfiguration)
            {
                return Err("ECH retry accepted a different origin or TLS owner".into());
            }
        }
        let result = retry_ech(&connector, Dialer::default(), INNER_NAME, &retry).await;
        match result {
            Err(DirectTlsError::Tls(error)) if expects_rejection => {
                if error.ech_failure() != Some(EchFailure::Rejected) || error.ech_retry().is_some()
                {
                    return Err("second ECH rejection supplied another retry".into());
                }
            }
            Ok(mut stream) if !expects_rejection => {
                if stream.early_data_wait().is_some() || stream.session_reused() {
                    return Err("ECH retry offered a cached session or early data".into());
                }
                stream.write_all(b"recovered").await?;
                stream.flush().await?;
                stream.read_exact(&mut byte).await?;
                if byte != *b"y" {
                    return Err("recovered origin returned the wrong response".into());
                }
            }
            _ => return Err("ECH retry returned the wrong outcome".into()),
        }
        // A second reconstruction shares the original connection's allowance.
        if !matches!(retry_ech(&connector, Dialer::default(), INNER_NAME, &other).await,
            Err(DirectTlsError::Tls(error)) if error.ech_failure() == Some(EchFailure::Rejected))
        {
            return Err("another waiter reused the ECH recovery allowance".into());
        }
        Ok(())
    })
    .await;
    let result = match exchange {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };
    finish_ticket_control_peer(result, &mut peer, TEST_TIMEOUT).await?;
    let offers = offers.lock().unwrap_or_else(PoisonError::into_inner);
    // The successful seed and fresh retry are decrypted ClientHellos. A
    // rejected ECH inner cannot be inspected by the rotated key.
    let fresh = offers.last().ok_or("fresh handshake observation missing")?;
    assert_eq!(
        fresh,
        &Offer {
            psk: false,
            early_data: false
        }
    );
    Ok(())
}

fn recording_acceptor(
    identity: &TestIdentity,
    offers: &Arc<Mutex<Vec<Offer>>>,
) -> TestResult<SslAcceptorBuilder> {
    let mut builder = identity.acceptor_builder()?;
    builder.set_alpn_select_callback(|_, offered| {
        select_next_proto(b"\x02h2", offered).ok_or(AlpnError::NOACK)
    });
    let observed = Arc::clone(offers);
    builder.set_select_certificate_callback(move |hello| {
        observed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Offer {
                psk: hello.get_extension(ExtensionType::PRE_SHARED_KEY).is_some(),
                early_data: hello.get_extension(ExtensionType::EARLY_DATA).is_some(),
            });
        Ok::<_, SelectCertError>(())
    });
    Ok(builder)
}
