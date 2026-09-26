use std::pin::Pin;

use btls::ssl::{Ssl, SslAcceptor, SslVersion};
use phantom_profile::{TlsSettings, TlsVersion, chromium::v154_tls};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_btls::SslStream;

use crate::tls::{
    TlsConnector, TlsErrorKind,
    test_support::{
        TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, TestServerAlpn, connect_local,
    },
};

/// Three servers with separate ticket keys give three TLS 1.3 tickets that
/// each resume only against their own server. Stored oldest first under a
/// bound of two, the first ticket is evicted, the first take returns the
/// third, and the second take returns the second.
#[tokio::test]
async fn a_full_origin_evicts_its_oldest_ticket_and_takes_the_newest_first() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut settings = v154_tls();
    settings.session_tickets_per_origin = 2;
    let connector = TlsConnector::new_with_roots(&settings, [identity.root_der()])?
        .with_isolated_session_cache();
    let cache = connector
        .session_cache
        .clone()
        .ok_or("isolated connector omitted its session cache")?;

    let mut servers = Vec::new();
    let mut tickets = Vec::new();
    for _ in 0..3 {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let server = tokio::spawn(async move {
            let mut resumed = Vec::new();
            for _ in 0..2 {
                let mut stream = accept_tls_from(&listener, &acceptor).await?;
                resumed.push(stream.ssl().session_reused());
                stream.write_all(b"x").await?;
                stream.flush().await?;
                let mut rest = Vec::new();
                let _ = stream.read_to_end(&mut rest).await;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(resumed)
        });
        let mut stream = connect_local(&connector, address, TEST_SERVER_NAME).await??;
        assert!(!stream.session_reused());
        // Reading the server's first byte processes the tickets sent before it.
        let mut byte = [0_u8; 1];
        tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut byte)).await??;
        drop(stream);
        let ticket = cache
            .take(TEST_SERVER_NAME)
            .ok_or("the server's tickets were not stored")?;
        while cache.take(TEST_SERVER_NAME).is_some() {}
        tickets.push(ticket);
        servers.push((address, server));
    }

    for ticket in tickets {
        cache.restore(TEST_SERVER_NAME, ticket);
    }
    assert_eq!(cache.len(), 2);
    let first = cache.take(TEST_SERVER_NAME).ok_or("first take was empty")?;
    let second = cache
        .take(TEST_SERVER_NAME)
        .ok_or("second take was empty")?;
    assert!(cache.take(TEST_SERVER_NAME).is_none());

    // Each ticket resumes only against the server that issued it.
    let mut resumed = Vec::new();
    for (ticket, index) in [(Some(first), 2), (Some(second), 1), (None, 0)] {
        if let Some(ticket) = ticket {
            cache.restore(TEST_SERVER_NAME, ticket);
        }
        let stream = connect_local(&connector, servers[index].0, TEST_SERVER_NAME).await??;
        resumed.push(stream.session_reused());
        while cache.take(TEST_SERVER_NAME).is_some() {}
    }
    assert_eq!(resumed, [true, true, false]);
    for (_, server) in servers {
        let server_resumed = tokio::time::timeout(TEST_TIMEOUT, server).await???;
        assert_eq!(server_resumed.first(), Some(&false));
    }
    Ok(())
}

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
    let first_session = cache
        .take(TEST_SERVER_NAME)
        .ok_or("first handshake omitted its session")?;
    let pending = cache.begin_handshake(TEST_SERVER_NAME);
    pending.capture(Ok(first_session));
    assert_eq!(cache.len(), 0);
    drop(pending);
    assert_eq!(cache.len(), 0);

    let second = connect_local(&connector, address, TEST_SERVER_NAME).await??;
    drop(second);
    let second_session = cache
        .take(TEST_SERVER_NAME)
        .ok_or("second handshake omitted its session")?;
    let pending = cache.begin_handshake(TEST_SERVER_NAME);
    pending.capture(Ok(second_session));
    assert_eq!(cache.len(), 0);
    assert_eq!(pending.commit_authenticated(), 1);
    assert_eq!(cache.len(), 1);

    let committed_session = cache
        .take(TEST_SERVER_NAME)
        .ok_or("committed session was not retained")?;
    let committed = cache.begin_handshake(TEST_SERVER_NAME);
    assert_eq!(committed.commit_authenticated(), 0);
    committed.capture(Ok(committed_session));
    assert_eq!(cache.len(), 1);
    tokio::time::timeout(TEST_TIMEOUT, server).await???;
    Ok(())
}

#[tokio::test]
async fn alternating_hosts_resume_their_own_sessions_on_one_isolated_connector() -> TestResult<()> {
    const FIRST_HOST: &str = "first.phantom.test";
    const SECOND_HOST: &str = "second.phantom.test";
    let identity = TestIdentity::generate_for_names(&[FIRST_HOST, SECOND_HOST])?;
    let acceptor = tls12_acceptor(&identity)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let mut resumed = Vec::new();
        for _ in 0..4 {
            let stream = accept_tls_from(&listener, &acceptor).await?;
            resumed.push(stream.ssl().session_reused());
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(resumed)
    });

    let connector = TlsConnector::new_with_roots(&tls12_settings(), [identity.root_der()])?
        .with_isolated_session_cache();
    let mut client_resumed = Vec::new();
    for host in [FIRST_HOST, SECOND_HOST, FIRST_HOST, SECOND_HOST] {
        let stream = connect_local(&connector, address, host).await??;
        client_resumed.push(stream.session_reused());
    }

    let server_resumed = tokio::time::timeout(TEST_TIMEOUT, server).await???;
    assert_eq!(client_resumed, [false, false, true, true]);
    assert_eq!(server_resumed, client_resumed);
    Ok(())
}

fn tls12_settings() -> TlsSettings {
    let mut settings = v154_tls();
    settings.max_version = TlsVersion::Tls12;
    settings.alps = None;
    settings.key_shares.clear();
    settings.certificate_compression.clear();
    settings.ech_grease = false;
    settings.ech_from_https_records = false;
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
