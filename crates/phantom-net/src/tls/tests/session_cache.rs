use std::pin::Pin;

use btls::ssl::{Ssl, SslAcceptor, SslVersion};
use phantom_profile::{TlsSettings, TlsVersion, chromium::v152_macos_tls};
use tokio::net::{TcpListener, TcpStream};
use tokio_btls::SslStream;

use crate::tls::{
    TlsConnector, TlsErrorKind,
    test_support::{TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, connect_local},
};

#[tokio::test]
async fn authentication_failure_discards_pending_and_attempted_sessions() -> TestResult<()> {
    let trusted = TestIdentity::generate()?;
    let untrusted = TestIdentity::generate()?;
    let trusted_acceptor = tls12_acceptor(&trusted)?;
    let untrusted_acceptor = tls12_acceptor(&untrusted)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let first = accept_tls_from(&listener, &trusted_acceptor).await?;
        assert!(!first.ssl().session_reused());
        drop(first);

        let failed = accept_tls_from(&listener, &untrusted_acceptor).await;
        assert!(
            failed.is_err(),
            "untrusted handshake unexpectedly succeeded"
        );

        let final_connection = accept_tls_from(&listener, &trusted_acceptor).await?;
        let resumed = final_connection.ssl().session_reused();
        drop(final_connection);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(resumed)
    });

    let connector = TlsConnector::new_with_roots(&tls12_settings(), [trusted.root_der()])?
        .with_isolated_session_cache();
    let first = connect_local(&connector, address, TEST_SERVER_NAME).await??;
    assert!(!first.session_reused());
    drop(first);
    assert_eq!(
        connector.session_cache.as_ref().map(|cache| cache.len()),
        Some(1)
    );

    let failed = connect_local(&connector, address, TEST_SERVER_NAME).await?;
    assert_eq!(
        failed.err().map(|error| error.kind()),
        Some(TlsErrorKind::Handshake)
    );
    assert_eq!(
        connector.session_cache.as_ref().map(|cache| cache.len()),
        Some(0)
    );

    let final_connection = connect_local(&connector, address, TEST_SERVER_NAME).await??;
    assert!(!final_connection.session_reused());
    let server_resumed = tokio::time::timeout(TEST_TIMEOUT, server).await???;
    assert!(!server_resumed);
    Ok(())
}

#[tokio::test]
async fn session_capture_requires_authenticated_commit() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let acceptor = tls12_acceptor(&identity)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let stream = accept_tls_from(&listener, &acceptor).await?;
            assert!(!stream.ssl().session_reused());
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });

    let connector = TlsConnector::new_with_roots(&tls12_settings(), [identity.root_der()])?
        .with_isolated_session_cache();
    let first = connect_local(&connector, address, TEST_SERVER_NAME).await??;
    drop(first);
    let cache = connector
        .session_cache
        .as_ref()
        .ok_or("isolated connector omitted its session cache")?;
    let first_session = cache.take().ok_or("first handshake omitted its session")?;
    let pending = cache.begin_handshake();
    pending.capture(Ok(first_session));
    assert_eq!(cache.len(), 0);
    drop(pending);
    assert_eq!(cache.len(), 0);

    let second = connect_local(&connector, address, TEST_SERVER_NAME).await??;
    drop(second);
    let second_session = cache.take().ok_or("second handshake omitted its session")?;
    let pending = cache.begin_handshake();
    pending.capture(Ok(second_session));
    assert_eq!(cache.len(), 0);
    assert_eq!(pending.commit_authenticated(), 1);
    assert_eq!(cache.len(), 1);

    let committed_session = cache.take().ok_or("committed session was not retained")?;
    let committed = cache.begin_handshake();
    assert_eq!(committed.commit_authenticated(), 0);
    committed.capture(Ok(committed_session));
    assert_eq!(cache.len(), 1);
    tokio::time::timeout(TEST_TIMEOUT, server).await???;
    Ok(())
}

fn tls12_settings() -> TlsSettings {
    let mut settings = v152_macos_tls();
    settings.max_version = TlsVersion::Tls12;
    settings.alps = None;
    settings.key_shares.clear();
    settings.certificate_compression.clear();
    settings.ech_grease = false;
    settings.requested_trust_anchor_ids = None;
    settings
}

fn tls12_acceptor(identity: &TestIdentity) -> TestResult<SslAcceptor> {
    let mut acceptor = identity.acceptor_builder()?;
    acceptor.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    acceptor.set_max_proto_version(Some(SslVersion::TLS1_2))?;
    Ok(acceptor.build())
}

async fn accept_tls_from(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
) -> TestResult<SslStream<TcpStream>> {
    let (tcp, _) = listener.accept().await?;
    let ssl = Ssl::new(acceptor.context())?;
    let mut stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
}
