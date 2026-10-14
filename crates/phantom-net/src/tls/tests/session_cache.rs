use std::{net::SocketAddr, pin::Pin};

use btls::ssl::{ScopedSslSession, Ssl, SslAcceptor, SslVersion};
use phantom_profile::{
    TlsSettings, TlsVersion,
    browser::{
        chrome::v154_tcp_tls,
        firefox::{v156_android_tcp_tls as v156_android_tls, v157_tcp_tls},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_btls::SslStream;

use crate::tls::{
    ClientCertificate, TlsConnector, TlsErrorKind, TlsStream,
    session_cache::TlsSessionCache,
    test_support::{
        TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, TestServerAlpn, connect_local,
    },
};

type ServerResult = Result<Vec<bool>, Box<dyn std::error::Error + Send + Sync>>;

/// Three servers with separate ticket keys give three TLS 1.3 tickets that
/// each resume only against their own server. Stored oldest first under a
/// bound of two, the first ticket is evicted, the first take returns the
/// third, and the second take returns the second.
#[tokio::test]
async fn a_full_origin_evicts_its_oldest_ticket_and_takes_the_newest_first() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut settings = v154_tcp_tls();
    settings.session_tickets = phantom_profile::SessionTickets::enabled(2)?;
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

/// With the Firefox order, a connection presents a ticket of the connection
/// whose tickets were stored first. Servers A and B have separate ticket
/// keys, so a ticket resumes only against its issuer. A's connection stores
/// two tickets; B's connection presents one of them, which B rejects, and
/// stores two of B's. A's other ticket comes out first, then B's two.
#[tokio::test]
async fn the_firefox_order_takes_the_earliest_connections_tickets_first() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (connector, cache) = isolated_connector(&identity, &v157_tcp_tls())?;
    let (server_a, a) = ticket_server(&identity, 2).await?;
    let (server_b, b) = ticket_server(&identity, 3).await?;

    drop(connect_and_read(&connector, server_a, false).await?);
    assert_eq!(cache.len(), 2);
    drop(connect_and_read(&connector, server_b, false).await?);
    assert_eq!(cache.len(), 3);

    let mut tickets = Vec::new();
    while let Some(ticket) = cache.take(TEST_SERVER_NAME) {
        tickets.push(ticket);
    }
    assert_eq!(tickets.len(), 3);
    for (ticket, server) in tickets.into_iter().zip([server_a, server_b, server_b]) {
        resume_alone(&connector, &cache, ticket, server).await?;
    }

    assert_eq!(
        tokio::time::timeout(TEST_TIMEOUT, a).await???,
        [false, true]
    );
    assert_eq!(
        tokio::time::timeout(TEST_TIMEOUT, b).await???,
        [false, true, true]
    );
    Ok(())
}

/// Tickets of two connections stored interleaved keep each connection's
/// order: connection X stores A's ticket, connection Y stores C's, then X
/// stores B's. The Firefox order takes X's tickets first, the one stored
/// last first, then Y's: B, A, C. The newest-first order would take C
/// second.
#[tokio::test]
async fn the_firefox_order_keeps_interleaved_connections_apart() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (connector, cache) = isolated_connector(&identity, &v157_tcp_tls())?;
    let mut servers = Vec::new();
    let mut tickets = Vec::new();
    for _ in 0..3 {
        let (address, server) = ticket_server(&identity, 2).await?;
        tickets.push(one_ticket(&connector, &cache, address).await?);
        servers.push((address, server));
    }
    let [ticket_a, ticket_b, ticket_c] =
        <[ScopedSslSession; 3]>::try_from(tickets).map_err(|_| "expected three tickets")?;

    let x = cache.begin_handshake(TEST_SERVER_NAME);
    let y = cache.begin_handshake(TEST_SERVER_NAME);
    assert_eq!(x.commit_authenticated(), 0);
    assert_eq!(y.commit_authenticated(), 0);
    x.capture(Ok(ticket_a));
    y.capture(Ok(ticket_c));
    x.capture(Ok(ticket_b));
    assert_eq!(cache.len(), 3);

    let mut taken = Vec::new();
    while let Some(ticket) = cache.take(TEST_SERVER_NAME) {
        taken.push(ticket);
    }
    assert_eq!(taken.len(), 3);
    for (ticket, index) in taken.into_iter().zip([1, 0, 2]) {
        resume_alone(&connector, &cache, ticket, servers[index].0).await?;
    }
    for (_, server) in servers {
        let resumed = tokio::time::timeout(TEST_TIMEOUT, server).await???;
        assert_eq!(resumed, [false, true]);
    }
    Ok(())
}

/// Storing a ticket in a full origin evicts the ticket the Firefox order
/// would take next. Under a bound of three, X stores A's and then B's ticket
/// around Y's C; storing D's ticket evicts B's, the last ticket of the
/// earliest connection, where the newest-first order evicts A's. A, C, and D
/// remain, in that order.
#[tokio::test]
async fn a_full_origin_evicts_the_ticket_the_firefox_order_takes_next() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut settings = v157_tcp_tls();
    settings.session_tickets = phantom_profile::SessionTickets::enabled(3)?;
    let (connector, cache) = isolated_connector(&identity, &settings)?;
    let mut servers = Vec::new();
    let mut tickets = Vec::new();
    // B's server never sees its ticket again.
    for connections in [2, 1, 2, 2] {
        let (address, server) = ticket_server(&identity, connections).await?;
        tickets.push(one_ticket(&connector, &cache, address).await?);
        servers.push((address, server));
    }
    let [ticket_a, ticket_b, ticket_c, ticket_d] =
        <[ScopedSslSession; 4]>::try_from(tickets).map_err(|_| "expected four tickets")?;

    let x = cache.begin_handshake(TEST_SERVER_NAME);
    let y = cache.begin_handshake(TEST_SERVER_NAME);
    assert_eq!(x.commit_authenticated(), 0);
    assert_eq!(y.commit_authenticated(), 0);
    x.capture(Ok(ticket_a));
    y.capture(Ok(ticket_c));
    x.capture(Ok(ticket_b));
    cache.restore(TEST_SERVER_NAME, ticket_d);
    assert_eq!(cache.len(), 3);

    let mut taken = Vec::new();
    while let Some(ticket) = cache.take(TEST_SERVER_NAME) {
        taken.push(ticket);
    }
    assert_eq!(taken.len(), 3);
    for (ticket, index) in taken.into_iter().zip([0, 2, 3]) {
        resume_alone(&connector, &cache, ticket, servers[index].0).await?;
    }
    for (index, (_, server)) in servers.into_iter().enumerate() {
        let resumed = tokio::time::timeout(TEST_TIMEOUT, server).await???;
        let expected: &[bool] = if index == 1 { &[false] } else { &[false, true] };
        assert_eq!(resumed, expected);
    }
    Ok(())
}

/// The Firefox for Android order takes tickets in the order they were
/// stored, whichever connection stored them: X stores A's ticket, Y stores
/// C's, then X stores B's, and the takes return A, C, B, where the desktop
/// Firefox order returns B, A, C.
#[tokio::test]
async fn the_android_firefox_order_takes_tickets_in_the_order_they_were_stored() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (connector, cache) = isolated_connector(&identity, &v156_android_tls())?;
    let mut servers = Vec::new();
    let mut tickets = Vec::new();
    for _ in 0..3 {
        let (address, server) = ticket_server(&identity, 2).await?;
        tickets.push(one_ticket(&connector, &cache, address).await?);
        servers.push((address, server));
    }
    let [ticket_a, ticket_b, ticket_c] =
        <[ScopedSslSession; 3]>::try_from(tickets).map_err(|_| "expected three tickets")?;

    let x = cache.begin_handshake(TEST_SERVER_NAME);
    let y = cache.begin_handshake(TEST_SERVER_NAME);
    assert_eq!(x.commit_authenticated(), 0);
    assert_eq!(y.commit_authenticated(), 0);
    x.capture(Ok(ticket_a));
    y.capture(Ok(ticket_c));
    x.capture(Ok(ticket_b));
    assert_eq!(cache.len(), 3);

    let mut taken = Vec::new();
    while let Some(ticket) = cache.take(TEST_SERVER_NAME) {
        taken.push(ticket);
    }
    assert_eq!(taken.len(), 3);
    for (ticket, index) in taken.into_iter().zip([0, 2, 1]) {
        resume_alone(&connector, &cache, ticket, servers[index].0).await?;
    }
    for (_, server) in servers {
        let resumed = tokio::time::timeout(TEST_TIMEOUT, server).await???;
        assert_eq!(resumed, [false, true]);
    }
    Ok(())
}

/// Under the Firefox for Android order, a full origin evicts the ticket
/// stored first, which is also the ticket it would take next. Under a bound
/// of three, X stores A's and then B's ticket around Y's C; storing D's
/// ticket evicts A's. C, B, and D remain, in that order.
#[tokio::test]
async fn a_full_origin_evicts_the_ticket_the_android_firefox_order_takes_next() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut settings = v156_android_tls();
    settings.session_tickets = phantom_profile::SessionTickets::enabled(3)?;
    let (connector, cache) = isolated_connector(&identity, &settings)?;
    let mut servers = Vec::new();
    let mut tickets = Vec::new();
    // A's server never sees its ticket again.
    for connections in [1, 2, 2, 2] {
        let (address, server) = ticket_server(&identity, connections).await?;
        tickets.push(one_ticket(&connector, &cache, address).await?);
        servers.push((address, server));
    }
    let [ticket_a, ticket_b, ticket_c, ticket_d] =
        <[ScopedSslSession; 4]>::try_from(tickets).map_err(|_| "expected four tickets")?;

    let x = cache.begin_handshake(TEST_SERVER_NAME);
    let y = cache.begin_handshake(TEST_SERVER_NAME);
    assert_eq!(x.commit_authenticated(), 0);
    assert_eq!(y.commit_authenticated(), 0);
    x.capture(Ok(ticket_a));
    y.capture(Ok(ticket_c));
    x.capture(Ok(ticket_b));
    cache.restore(TEST_SERVER_NAME, ticket_d);
    assert_eq!(cache.len(), 3);

    let mut taken = Vec::new();
    while let Some(ticket) = cache.take(TEST_SERVER_NAME) {
        taken.push(ticket);
    }
    assert_eq!(taken.len(), 3);
    for (ticket, index) in taken.into_iter().zip([2, 1, 3]) {
        resume_alone(&connector, &cache, ticket, servers[index].0).await?;
    }
    for (index, (_, server)) in servers.into_iter().enumerate() {
        let resumed = tokio::time::timeout(TEST_TIMEOUT, server).await???;
        let expected: &[bool] = if index == 0 { &[false] } else { &[false, true] };
        assert_eq!(resumed, expected);
    }
    Ok(())
}

/// Firefox keeps up to ten tickets per peer. Each connection after the first
/// resumes one ticket and stores the server's two, so ten connections would
/// leave eleven; the Firefox recipe keeps ten.
#[tokio::test]
async fn the_firefox_recipe_keeps_ten_tickets_per_origin() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (connector, cache) = isolated_connector(&identity, &v157_tcp_tls())?;
    let (address, server) = ticket_server(&identity, 10).await?;
    drop(connect_and_read(&connector, address, false).await?);
    for _ in 1..10 {
        drop(connect_and_read(&connector, address, true).await?);
    }
    assert_eq!(cache.len(), 10);
    let resumed = tokio::time::timeout(TEST_TIMEOUT, server).await???;
    assert_eq!(resumed.iter().filter(|resumed| **resumed).count(), 9);
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
    assert!(first_session.is_authenticated());
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
    assert!(second_session.is_authenticated());
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
async fn tls12_restored_sessions_retain_authenticated_publication() -> TestResult<()> {
    check_tls12_publication(false).await
}

#[tokio::test]
async fn custom_verification_keeps_local_sessions_without_portable_proof() -> TestResult<()> {
    check_tls12_publication(true).await
}

async fn check_tls12_publication(custom_verifier: bool) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let settings = tls12_settings();
    let (mut connector, cache) = isolated_connector(&identity, &settings)?;
    if custom_verifier {
        let mut roots = btls::x509::store::X509StoreBuilder::new()?;
        roots.add_cert(btls::x509::X509::from_der(identity.root_der())?)?;
        let mut builder = btls::ssl::SslConnector::bare_builder(btls::ssl::SslMethod::tls())?;
        builder.set_cert_store_builder(roots);
        builder.set_verify_callback(btls::ssl::SslVerifyMode::PEER, |verified, _| verified);
        super::super::configuration::apply(&mut builder, &settings)?;
        builder.enable_scoped_client_sessions();
        connector.backend = builder.build();
    }
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let acceptor = tls12_acceptor(&identity)?;
    let mut peer = tokio::spawn(async move {
        for resumed in [false, true] {
            let stream = accept_tls_from(&listener, &acceptor).await?;
            if stream.ssl().session_reused() != resumed {
                return Err("server saw an unexpected TLS 1.2 resumption".into());
            }
        }
        Ok(())
    });
    let received = async {
        for resumed in [false, true] {
            let stream = connect_local(&connector, address, TEST_SERVER_NAME).await??;
            if stream.session_reused() != resumed || stream.inner.ssl().verify_result().is_err() {
                return Err("TLS 1.2 resumption or native verification failed".into());
            }
            drop(stream);
            let session = cache
                .take(TEST_SERVER_NAME)
                .ok_or("TLS 1.2 retained no session")?;
            if session.is_authenticated() == custom_verifier || session.should_be_single_use() {
                return Err(
                    "TLS 1.2 session has incorrect publication or consumption state".into(),
                );
            }
            cache.restore(TEST_SERVER_NAME, session);
        }
        Ok(())
    }
    .await;
    finish_ticket_control_peer(received, &mut peer, TEST_TIMEOUT).await
}

#[tokio::test]
async fn late_tls13_tickets_have_completed_default_verification_proof() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (connector, cache) = isolated_connector(&identity, &v157_tcp_tls())?;
    let (address, mut peer) = ticket_server(&identity, 2).await?;
    let received = async {
        for resumed in [false, true] {
            let mut stream = connect_local(&connector, address, TEST_SERVER_NAME).await??;
            if stream.session_reused() != resumed {
                return Err("TLS 1.3 unexpectedly changed resumption state".into());
            }
            let mut reply = [0_u8; 1];
            tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut reply)).await??;
            drop(stream);
            let session = cache
                .take(TEST_SERVER_NAME)
                .ok_or("TLS 1.3 retained no issued ticket")?;
            if !session.is_authenticated() || !session.should_be_single_use() {
                return Err("late TLS 1.3 ticket lacks authenticated single-use state".into());
            }
            while cache.take(TEST_SERVER_NAME).is_some() {}
            cache.restore(TEST_SERVER_NAME, session);
        }
        Ok(())
    }
    .await;
    finish_ticket_control_peer(received, &mut peer, TEST_TIMEOUT).await
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

/// A connector that presents a client certificate never offers a session
/// that a connector without it learned, while that connector still resumes.
#[tokio::test]
async fn client_certificate_connector_does_not_offer_sessions_learned_without_it() -> TestResult<()>
{
    let identity = TestIdentity::generate()?;
    let acceptor = tls12_acceptor(&identity)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let mut resumed = Vec::new();
        for _ in 0..3 {
            let stream = accept_tls_from(&listener, &acceptor).await?;
            resumed.push(stream.ssl().session_reused());
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(resumed)
    });

    let connector = TlsConnector::new_with_roots(&tls12_settings(), [identity.root_der()])?
        .with_isolated_session_cache();
    drop(connect_local(&connector, address, TEST_SERVER_NAME).await??);
    assert_eq!(
        connector.session_cache.as_ref().map(|cache| cache.len()),
        Some(1)
    );

    let with_certificate = connector.with_client_certificate(&client_certificate()?);
    assert_eq!(
        with_certificate
            .session_cache
            .as_ref()
            .map(|cache| cache.len()),
        Some(0)
    );
    let fresh = connect_local(&with_certificate, address, TEST_SERVER_NAME).await??;
    assert!(!fresh.session_reused());
    drop(fresh);
    let resumed = connect_local(&connector, address, TEST_SERVER_NAME).await??;
    assert!(resumed.session_reused());
    drop(resumed);

    let server_resumed = tokio::time::timeout(TEST_TIMEOUT, server).await???;
    assert_eq!(server_resumed, [false, false, true]);
    Ok(())
}

fn isolated_connector(
    identity: &TestIdentity,
    settings: &TlsSettings,
) -> TestResult<(TlsConnector, TlsSessionCache)> {
    let connector = TlsConnector::new_with_roots(settings, [identity.root_der()])?
        .with_isolated_session_cache();
    let cache = connector
        .session_cache
        .clone()
        .ok_or("isolated connector omitted its session cache")?;
    Ok((connector, cache))
}

/// Serves `connections` TLS connections on a new loopback listener with an
/// acceptor of its own, and so ticket keys of its own. Each connection
/// writes one byte after the server's tickets and waits for the client to
/// close. The task returns whether each connection resumed.
async fn ticket_server(
    identity: &TestIdentity,
    connections: usize,
) -> TestResult<(SocketAddr, JoinHandle<ServerResult>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(TestServerAlpn::H2)?;
    let server = tokio::spawn(async move {
        let mut resumed = Vec::new();
        for _ in 0..connections {
            let mut stream = accept_tls_from(&listener, &acceptor).await?;
            resumed.push(stream.ssl().session_reused());
            stream.write_all(b"x").await?;
            stream.flush().await?;
            let mut rest = Vec::new();
            // The client closes or resets the connection when it drops it.
            let _ = stream.read_to_end(&mut rest).await;
        }
        Ok(resumed)
    });
    Ok((address, server))
}

/// Connects, checks whether the connection resumed, and reads the server's
/// first byte, which processes the tickets sent before it.
async fn connect_and_read(
    connector: &TlsConnector,
    address: SocketAddr,
    resumed: bool,
) -> TestResult<TlsStream<TcpStream>> {
    let mut stream = connect_local(connector, address, TEST_SERVER_NAME).await??;
    assert_eq!(stream.session_reused(), resumed);
    let mut byte = [0_u8; 1];
    tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut byte)).await??;
    Ok(stream)
}

/// Makes a full handshake with the server at `address` and returns one of
/// its tickets, leaving the cache empty.
async fn one_ticket(
    connector: &TlsConnector,
    cache: &TlsSessionCache,
    address: SocketAddr,
) -> TestResult<ScopedSslSession> {
    drop(connect_and_read(connector, address, false).await?);
    let ticket = cache
        .take(TEST_SERVER_NAME)
        .ok_or("the server's tickets were not stored")?;
    while cache.take(TEST_SERVER_NAME).is_some() {}
    Ok(ticket)
}

/// Connects with `ticket` as the cache's only ticket, checks that the
/// connection resumed, and empties the cache again.
async fn resume_alone(
    connector: &TlsConnector,
    cache: &TlsSessionCache,
    ticket: ScopedSslSession,
    address: SocketAddr,
) -> TestResult<()> {
    cache.restore(TEST_SERVER_NAME, ticket);
    drop(connect_and_read(connector, address, true).await?);
    while cache.take(TEST_SERVER_NAME).is_some() {}
    Ok(())
}

#[tokio::test]
async fn clear_drops_pending_tickets_and_refuses_late_tls12_restore() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = TlsConnector::new_with_roots(&tls12_settings(), [identity.root_der()])?
        .with_isolated_session_cache();
    let cache = connector
        .session_cache
        .as_ref()
        .ok_or("ticket cache missing")?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let acceptor = tls12_acceptor(&identity)?;
    let mut peer = tokio::spawn(async move {
        for _ in 0..4 {
            let stream = accept_tls_from(&listener, &acceptor).await?;
            assert!(!stream.ssl().session_reused());
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let received = async {
        let mut tickets = Vec::new();
        for _ in 0..4 {
            drop(connect_local(&connector, address, TEST_SERVER_NAME).await??);
            tickets.push(
                cache
                    .take(TEST_SERVER_NAME)
                    .ok_or("TLS 1.2 ticket missing")?,
            );
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(tickets)
    }
    .await;
    let mut tickets = finish_ticket_control_peer(received, &mut peer, TEST_TIMEOUT).await?;
    let pending = cache.begin_handshake(TEST_SERVER_NAME);
    pending.capture(Ok(tickets.pop().ok_or("pending ticket missing")?));
    let restore = cache.begin_handshake(TEST_SERVER_NAME);
    assert_eq!(cache.control().clear(), 1);
    assert_eq!(pending.commit_authenticated(), 0);
    pending.capture(Ok(tickets.pop().ok_or("late ticket missing")?));
    restore.restore(tickets.pop().ok_or("restored ticket missing")?);
    assert_eq!(cache.len(), 0);

    let fresh = cache.begin_handshake(TEST_SERVER_NAME);
    fresh.restore(tickets.pop().ok_or("fresh ticket missing")?);
    assert_eq!(cache.len(), 1);
    assert!(pending.take_session().is_none());
    assert!(fresh.take_session().is_some());
    Ok(())
}

pub(super) async fn finish_ticket_control_peer<T, U>(
    primary: TestResult<T>,
    peer: &mut JoinHandle<TestResult<U>>,
    deadline: std::time::Duration,
) -> TestResult<T> {
    let abort_requested = primary.is_err();
    if abort_requested {
        peer.abort();
    }
    let cleanup = match tokio::time::timeout(deadline, &mut *peer).await {
        Ok(joined) => ticket_control_join(joined, abort_requested),
        Err(error) => {
            peer.abort();
            let joined = match tokio::time::timeout(TEST_TIMEOUT, &mut *peer).await {
                Ok(joined) => ticket_control_join(joined, true),
                Err(error) => Err(error.into()),
            };
            combine_ticket_control(Err(error.into()), joined)
        }
    };
    combine_ticket_control(primary, cleanup)
}

fn ticket_control_join<U>(
    joined: Result<TestResult<U>, tokio::task::JoinError>,
    abort_requested: bool,
) -> TestResult<()> {
    match joined {
        Ok(result) => result.map(|_| ()),
        Err(error) if abort_requested && error.is_cancelled() => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn combine_ticket_control<T>(primary: TestResult<T>, cleanup: TestResult<()>) -> TestResult<T> {
    match (primary, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(TicketControlFailures { primary, cleanup }.into()),
    }
}

#[derive(Debug)]
struct TicketControlFailures {
    primary: Box<dyn std::error::Error + Send + Sync>,
    cleanup: Box<dyn std::error::Error + Send + Sync>,
}

impl std::fmt::Display for TicketControlFailures {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; ticket peer cleanup failed: {}",
            self.primary, self.cleanup
        )
    }
}

impl std::error::Error for TicketControlFailures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.primary.as_ref())
    }
}

#[tokio::test]
async fn ticket_control_cleanup_retains_body_errors_and_peer_panics() -> TestResult<()> {
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let mut peer = tokio::spawn(async move {
        let _ = ready_tx.send(());
        panic!("ticket control peer panic");
        #[allow(unreachable_code)]
        Ok(())
    });
    ready_rx.await?;
    let result: TestResult<()> = finish_ticket_control_peer(
        Err(std::io::Error::other("initiating control error").into()),
        &mut peer,
        TEST_TIMEOUT,
    )
    .await;
    let error = result.err().ok_or("peer panic was lost")?;
    assert!(error.to_string().contains("initiating control error"));
    assert!(error.to_string().contains("ticket control peer panic"));
    Ok(())
}

#[tokio::test]
async fn ticket_control_cleanup_retains_timeout_and_completed_peer_failure() -> TestResult<()> {
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let mut peer = tokio::task::spawn_blocking(move || -> TestResult<()> {
        let _ = ready_tx.send(());
        let _ = release_rx.recv();
        Err(std::io::Error::other("completed ticket peer failure").into())
    });
    ready_rx.await?;
    let (result, released) = tokio::join!(
        finish_ticket_control_peer(Ok(()), &mut peer, std::time::Duration::from_millis(10)),
        async {
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            release_tx.send(())
        }
    );
    released?;
    let error = result.err().ok_or("peer timeout was lost")?;
    assert!(error.to_string().contains("deadline has elapsed"));
    assert!(error.to_string().contains("completed ticket peer failure"));
    Ok(())
}

/// A self-signed P-256 client certificate and its key.
fn client_certificate() -> TestResult<ClientCertificate> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let certificate = rcgen::CertificateParams::new(Vec::<String>::new())?.self_signed(&key)?;
    Ok(ClientCertificate::from_der(
        [certificate.der().as_ref()],
        &key.serialize_der(),
    )?)
}

fn tls12_settings() -> TlsSettings {
    let mut settings = v154_tcp_tls();
    settings.versions = phantom_profile::TlsVersionRange::only(TlsVersion::Tls12);
    settings.alps = None;
    settings.key_shares.clear();
    settings.certificate_compression.clear();
    settings.ech = phantom_profile::EchSettings::Disabled;
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
