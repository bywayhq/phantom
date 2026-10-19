//! Actual TCP cache contexts supply the native transfer binding.

use std::{
    future::{Future, poll_fn},
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    pin::Pin,
    task::Poll,
};

use btls::ssl::{
    SessionPolicyBinding, SessionTransferError, SessionTransferPolicy, Ssl, SslOptions, SslVersion,
};
use phantom_profile::{
    TlsVersion, TlsVersionRange,
    browser::{chrome, firefox},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
};
use tokio_btls::SslStream;

use crate::tls::{
    TlsConnector, TlsErrorKind,
    test_support::{
        TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, connect_local, loopback_listener,
    },
};

fn policy() -> Result<SessionTransferPolicy, SessionTransferError> {
    SessionTransferPolicy::new(
        b"complete synthetic TCP test policy",
        &[0, 0],
        None,
        &[7; 32],
    )
}

fn bind(connector: &TlsConnector, name: &str) -> TestResult<SessionPolicyBinding> {
    let owner = connector
        .session_ticket_cache()
        .ok_or("TCP cache missing")?
        .upgrade()
        .ok_or("TCP cache owner missing")?;
    Ok(owner.bind_tcp_transfer_policy(name, policy()?)?)
}

fn connector(identity: &TestIdentity, version: TlsVersion) -> TestResult<TlsConnector> {
    let mut settings = match version {
        TlsVersion::Tls12 => chrome::v154_tcp_tls(),
        _ => firefox::v157_tcp_tls(),
    };
    settings.versions = TlsVersionRange::only(version);
    if version == TlsVersion::Tls12 {
        settings.alps = None;
        settings.key_shares.clear();
        settings.certificate_compression.clear();
        settings.ech = phantom_profile::EchSettings::Disabled;
        settings.requested_trust_anchor_ids = None;
    }
    Ok(
        TlsConnector::new_with_roots(&settings, [identity.root_der()])?
            .with_isolated_session_cache(),
    )
}

struct TcpPeer {
    task: JoinHandle<TestResult<Vec<bool>>>,
}

impl Drop for TcpPeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TcpPeer {
    async fn run<T>(
        mut self,
        primary: impl Future<Output = TestResult<T>>,
    ) -> TestResult<(T, TestResult<Vec<bool>>)> {
        let mut primary = std::pin::pin!(primary);
        // A panicking future is never polled again. Collect the peer before
        // resuming the original assertion panic, including its payload.
        let result = poll_fn(|context| {
            match catch_unwind(AssertUnwindSafe(|| primary.as_mut().poll(context))) {
                Ok(Poll::Pending) => Poll::Pending,
                Ok(Poll::Ready(result)) => Poll::Ready(Ok(result)),
                Err(panic) => Poll::Ready(Err(panic)),
            }
        })
        .await;
        let result = match result {
            Ok(result) => result,
            Err(panic) => {
                if let Err(error) = self.abort_and_join().await {
                    eprintln!("TCP peer cleanup after assertion panic failed: {error}");
                }
                resume_unwind(panic);
            }
        };
        match result {
            Err(error) => {
                super::session_cache::finish_ticket_control_peer(
                    Err(error),
                    &mut self.task,
                    TEST_TIMEOUT,
                )
                .await
            }
            Ok(value) => match tokio::time::timeout(TEST_TIMEOUT, &mut self.task).await {
                Ok(joined) => Ok((value, joined?)),
                Err(error) => {
                    super::session_cache::finish_ticket_control_peer(
                        Err(error.into()),
                        &mut self.task,
                        TEST_TIMEOUT,
                    )
                    .await
                }
            },
        }
    }

    async fn abort_and_join(&mut self) -> TestResult<()> {
        self.task.abort();
        match tokio::time::timeout(TEST_TIMEOUT, &mut self.task).await? {
            Ok(result) => result.map(drop),
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

async fn peer(
    identity: &TestIdentity,
    version: TlsVersion,
    connections: usize,
) -> TestResult<(std::net::SocketAddr, TcpPeer)> {
    let mut acceptor = identity.acceptor_builder()?;
    let version = match version {
        TlsVersion::Tls12 => SslVersion::TLS1_2,
        _ => SslVersion::TLS1_3,
    };
    acceptor.set_min_proto_version(Some(version))?;
    acceptor.set_max_proto_version(Some(version))?;
    let acceptor = acceptor.build();
    let (address, listener) = loopback_listener().await?;
    let task = tokio::spawn(async move {
        let mut resumed = Vec::new();
        for _ in 0..connections {
            let (tcp, _) = listener.accept().await?;
            let mut stream = SslStream::new(Ssl::new(acceptor.context())?, tcp)?;
            Pin::new(&mut stream).accept().await?;
            resumed.push(stream.ssl().session_reused());
            stream.write_all(b"x").await?;
            stream.flush().await?;
            let mut acknowledged = [0];
            stream.read_exact(&mut acknowledged).await?;
            assert_eq!(acknowledged, [b'a']);
        }
        Ok(resumed)
    });
    Ok((address, TcpPeer { task }))
}

async fn consume_reply<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
) -> TestResult<()> {
    let mut reply = [0];
    tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut reply)).await??;
    assert_eq!(reply, [b'x']);
    stream.write_all(b"a").await?;
    stream.flush().await?;
    Ok(())
}

#[tokio::test]
async fn attached_tcp_ticket_store_resumes_and_clears_through_both_connectors() -> TestResult<()> {
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let identity = TestIdentity::generate()?;
        let source = connector(&identity, version)?;
        let control = source.session_ticket_cache().ok_or("cache missing")?;
        let owner = control.upgrade().ok_or("owner missing")?;
        let other = source
            .with_isolated_session_cache()
            .with_session_ticket_cache(&owner)?;
        let (address, task) = peer(&identity, version, 3).await?;
        let ((), result) = task
            .run(async {
                let mut first = connect_local(&source, address, TEST_SERVER_NAME).await??;
                consume_reply(&mut first).await?;
                drop(first);
                let mut second = connect_local(&other, address, TEST_SERVER_NAME).await??;
                assert!(second.session_reused());
                consume_reply(&mut second).await?;
                drop(second);
                assert!(other.session_ticket_cache().ok_or("cache missing")?.clear() > 0);
                assert_eq!(
                    source.session_cache.as_ref().ok_or("cache missing")?.len(),
                    0
                );
                let mut third = connect_local(&source, address, TEST_SERVER_NAME).await??;
                assert!(!third.session_reused());
                consume_reply(&mut third).await?;
                Ok(())
            })
            .await?;
        assert_eq!(result?, [false, true, false]);
    }
    Ok(())
}

#[test]
fn attached_tcp_ticket_store_rejects_an_independently_built_policy() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let source = connector(&identity, TlsVersion::Tls13)?;
    let owner = source
        .session_ticket_cache()
        .ok_or("cache missing")?
        .upgrade()
        .ok_or("owner missing")?;
    assert!(
        source
            .without_early_data()
            .with_session_ticket_cache(&owner)
            .is_ok()
    );
    let independent = connector(&identity, TlsVersion::Tls13)?;
    assert_eq!(
        independent
            .with_session_ticket_cache(&owner)
            .err()
            .map(|e| e.kind()),
        Some(TlsErrorKind::InvalidConfiguration)
    );
    Ok(())
}

#[tokio::test]
async fn bound_tcp_tls12_and_tls13_publish_sealable_tickets_and_resume() -> TestResult<()> {
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let identity = TestIdentity::generate()?;
        let connector = connector(&identity, version)?;
        let binding = bind(&connector, TEST_SERVER_NAME)?;
        let (address, task) = peer(&identity, version, 2).await?;
        let ((), result) = task
            .run(async {
                let mut first = connect_local(&connector, address, TEST_SERVER_NAME).await??;
                consume_reply(&mut first).await?;
                let cache = connector.session_cache.as_ref().ok_or("cache missing")?;
                let source = cache
                    .take(TEST_SERVER_NAME)
                    .ok_or("source ticket missing")?;
                assert!(source.is_authenticated());
                binding.seal_session(&source, b"opaque owner metadata", &[9; 32])?;
                // Equal installation after real use keeps the authenticated source valid.
                bind(&connector, TEST_SERVER_NAME)?;
                binding.seal_session(&source, b"opaque owner metadata", &[9; 32])?;
                while cache.take(TEST_SERVER_NAME).is_some() {}
                cache.restore(TEST_SERVER_NAME, source);
                drop(first);
                let mut second = connect_local(&connector, address, TEST_SERVER_NAME).await??;
                assert!(second.inner.ssl().session_reused());
                consume_reply(&mut second).await?;
                let issued = cache
                    .take(TEST_SERVER_NAME)
                    .ok_or("resumed ticket missing")?;
                assert!(issued.is_authenticated());
                binding.seal_session(&issued, b"opaque owner metadata", &[9; 32])?;
                drop(second);
                Ok(())
            })
            .await?;
        assert_eq!(result?, [false, true]);
    }
    Ok(())
}

#[tokio::test]
async fn post_finalization_ssl_mutation_revokes_actual_tcp_source_tickets() -> TestResult<()> {
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let identity = TestIdentity::generate()?;
        let connector = connector(&identity, version)?;
        let binding = bind(&connector, TEST_SERVER_NAME)?;
        let (address, task) = peer(&identity, version, 1).await?;
        let ((), result) = task
            .run(async {
                let mut stream = connect_local(&connector, address, TEST_SERVER_NAME).await??;
                consume_reply(&mut stream).await?;
                let source = connector
                    .session_cache
                    .as_ref()
                    .ok_or("cache missing")?
                    .take(TEST_SERVER_NAME)
                    .ok_or("source missing")?;
                binding.seal_session(&source, b"metadata", &[9; 32])?;
                stream.inner.ssl_mut().set_options(SslOptions::NO_TICKET);
                assert!(matches!(
                    binding.seal_session(&source, b"metadata", &[9; 32]),
                    Err(SessionTransferError::Unauthenticated) | Err(SessionTransferError::Policy)
                ));
                drop(stream);
                Ok(())
            })
            .await?;
        assert_eq!(result?, [false]);
    }
    Ok(())
}

#[tokio::test]
async fn unbound_local_tcp_tickets_do_not_gain_native_transfer_authority() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = connector(&identity, TlsVersion::Tls13)?;
    let other = connector.with_isolated_session_cache();
    let binding = bind(&other, TEST_SERVER_NAME)?;
    let (address, task) = peer(&identity, TlsVersion::Tls13, 1).await?;
    let ((), result) = task
        .run(async {
            let mut stream = connect_local(&connector, address, TEST_SERVER_NAME).await??;
            consume_reply(&mut stream).await?;
            let source = connector
                .session_cache
                .as_ref()
                .ok_or("cache missing")?
                .take(TEST_SERVER_NAME)
                .ok_or("source missing")?;
            assert!(source.is_authenticated());
            assert!(matches!(
                binding.seal_session(&source, b"metadata", &[9; 32]),
                Err(SessionTransferError::Policy)
            ));
            drop(stream);
            Ok(())
        })
        .await?;
    assert_eq!(result?, [false]);
    Ok(())
}

#[test]
fn first_binding_after_handshake_start_is_rejected_and_dead_cache_has_no_owner() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = connector(&identity, TlsVersion::Tls13)?;
    let control = connector.session_ticket_cache().ok_or("cache missing")?;
    let capture = connector
        .session_cache
        .as_ref()
        .ok_or("cache missing")?
        .begin_handshake(TEST_SERVER_NAME);
    let owner = control.upgrade().ok_or("owner missing")?;
    assert!(matches!(
        owner.bind_tcp_transfer_policy(TEST_SERVER_NAME, policy()?),
        Err(SessionTransferError::Policy)
    ));
    assert!(capture.transfer_binding().is_none());
    drop(owner);
    drop(capture);
    drop(connector);
    assert!(control.upgrade().is_none());
    Ok(())
}

#[tokio::test]
async fn an_invalid_installed_binding_cannot_fall_back_to_local_resumption() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = connector(&identity, TlsVersion::Tls13)?;
    bind(&connector, TEST_SERVER_NAME)?;
    let owner = connector
        .session_ticket_cache()
        .ok_or("cache missing")?
        .upgrade()
        .ok_or("owner missing")?;
    assert!(matches!(
        owner.bind_tcp_transfer_policy("different.phantom.test", policy()?),
        Err(SessionTransferError::Policy)
    ));
    let (client, _peer) = tokio::io::duplex(128);
    let result =
        tokio::time::timeout(TEST_TIMEOUT, connector.connect(TEST_SERVER_NAME, client)).await?;
    let error = result
        .err()
        .ok_or("invalid policy unexpectedly connected")?;
    assert_eq!(error.kind(), TlsErrorKind::BackendConfiguration);
    assert!(matches!(
        std::error::Error::source(&error)
            .and_then(|error| error.downcast_ref::<SessionTransferError>()),
        Some(SessionTransferError::Policy)
    ));
    Ok(())
}

#[tokio::test]
async fn bound_tcp_wrong_hostname_and_untrusted_root_still_fail_verification() -> TestResult<()> {
    for trusted in [true, false] {
        let identity = TestIdentity::generate()?;
        let roots: Vec<&[u8]> = if trusted {
            vec![identity.root_der()]
        } else {
            vec![]
        };
        let connector = TlsConnector::new_with_roots(&chrome::v154_tcp_tls(), roots)?
            .with_isolated_session_cache();
        let name = if trusted {
            "wrong.phantom.test"
        } else {
            TEST_SERVER_NAME
        };
        bind(&connector, name)?;
        let (address, task) = peer(&identity, TlsVersion::Tls13, 1).await?;
        let ((), result) = task
            .run(async {
                let error = connect_local(&connector, address, name)
                    .await?
                    .err()
                    .ok_or("invalid certificate accepted")?;
                assert_eq!(error.kind(), TlsErrorKind::Handshake);
                assert_eq!(
                    connector
                        .session_cache
                        .as_ref()
                        .ok_or("cache missing")?
                        .len(),
                    0
                );
                Ok(())
            })
            .await?;
        assert!(result.is_err());
    }
    Ok(())
}

#[test]
fn quic_owners_reject_the_tcp_binding_bridge() -> TestResult<()> {
    let mut context = btls::ssl::SslContextBuilder::new(btls::ssl::SslMethod::tls())?;
    phantom_quic_btls::QuicClientConfig::enable_session_resumption(&mut context)?;
    let config = phantom_quic_btls::QuicClientConfig::new(context.build())
        .with_tls_profile(&chrome::v154_quic_tls())?
        .with_isolated_session_cache();
    let control =
        crate::SessionTicketCache::quic(config.session_ticket_cache().ok_or("QUIC cache missing")?);
    let owner = control.upgrade().ok_or("QUIC owner missing")?;
    assert!(matches!(
        owner.bind_tcp_transfer_policy(TEST_SERVER_NAME, policy()?),
        Err(SessionTransferError::Policy)
    ));
    Ok(())
}
