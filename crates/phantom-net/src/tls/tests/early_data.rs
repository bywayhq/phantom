//! Early data over TCP: what a resumed Firefox-profile connection sends before
//! the server answers, and how it continues after an acceptance or a
//! rejection.

use std::{io, net::SocketAddr, sync::PoisonError, time::Duration};

use btls::ssl::SslAcceptor;
use phantom_profile::browser::firefox;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

use crate::tls::{
    TlsConnector, TlsStream,
    test_support::{
        EarlyDataServerStream, TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult,
        TestServerAlpn, accept_tls_with_early_data, loopback_listener,
    },
};

/// Long enough that the client's early data is on the wire before the server
/// answers its ClientHello.
const SERVER_DELAY: Duration = Duration::from_millis(200);

#[tokio::test]
async fn scoped_session_proof_waits_for_accepted_or_rejected_early_data() -> TestResult<()> {
    for accepted in [true, false] {
        let identity = TestIdentity::generate()?;
        let connector = firefox_connector(&identity)?;
        let cache = connector
            .session_cache
            .as_ref()
            .ok_or("ticket cache missing")?;
        let h2 = identity.acceptor(TestServerAlpn::H2)?;
        let (address, listener) = loopback_listener().await?;
        let mut peer = serve_ticket_then_resumption(listener, h2.clone(), h2, accepted);
        let received = async {
            let mut first = connect_offering(&connector, address).await?;
            if first.early_data_wait().is_some() {
                return Err("full handshake unexpectedly offered early data".into());
            }
            let mut reply = [0_u8; 1];
            tokio::time::timeout(TEST_TIMEOUT, first.read_exact(&mut reply)).await??;
            drop(first);
            let source = cache
                .take(TEST_SERVER_NAME)
                .ok_or("source ticket missing")?;
            if !source.is_authenticated() {
                return Err("full handshake did not authenticate the source ticket".into());
            }
            while cache.take(TEST_SERVER_NAME).is_some() {}
            cache.restore(TEST_SERVER_NAME, source);
            let mut stream = connect_offering(&connector, address).await?;
            if !stream.inner.ssl().in_early_data()
                || stream.inner.ssl().authenticate_scoped_session_publication()
                || cache.len() != 0
            {
                return Err("early data published proof or retained an offered ticket".into());
            }
            stream.write_all(b"early").await?;
            stream.flush().await?;
            let mut reply = [0_u8; 1];
            tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut reply)).await??;
            if stream.early_data_wait().is_some()
                || !stream.inner.ssl().is_init_finished()
                || stream.inner.ssl().early_data_accepted() != accepted
            {
                return Err("early data did not settle with the expected outcome".into());
            }
            let ticket = cache
                .take(TEST_SERVER_NAME)
                .ok_or("resumed ticket missing")?;
            if !ticket.is_authenticated() {
                return Err("completed early-data handshake retained an unproven ticket".into());
            }
            Ok(())
        }
        .await;
        super::session_cache::finish_ticket_control_peer(received, &mut peer, TEST_TIMEOUT).await?;
    }
    Ok(())
}

/// What the server saw on the resumed connection.
struct Observed {
    request: Vec<u8>,
    early: Vec<u8>,
    early_data_accepted: bool,
    session_reused: bool,
}

#[tokio::test]
async fn accepted_early_data_carries_the_writes_made_before_the_answer() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = firefox_connector(&identity)?;
    let h2 = identity.acceptor(TestServerAlpn::H2)?;
    let (address, listener) = loopback_listener().await?;
    let server = serve_ticket_then_resumption(listener, h2.clone(), h2, true);

    learn_ticket(&connector, address).await?;
    let mut stream = connect_offering(&connector, address).await?;
    let answered = stream
        .early_data_wait()
        .ok_or("the resumed connection offered no early data")?;
    stream.write_all(b"early").await?;
    stream.flush().await?;
    let mut reply = [0_u8; 1];
    tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut reply)).await??;
    tokio::time::timeout(TEST_TIMEOUT, answered.answered()).await??;
    assert!(stream.early_data_wait().is_none());
    assert_eq!(stream.negotiated_alpn(), Some(&b"h2"[..]));
    drop(stream);

    let observed = tokio::time::timeout(TEST_TIMEOUT, server).await???;
    assert_eq!(observed.request, b"early");
    assert_eq!(observed.early, b"early");
    assert!(observed.early_data_accepted);
    assert!(observed.session_reused);
    Ok(())
}

#[tokio::test]
async fn rejected_early_data_is_sent_again_on_the_same_connection() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = firefox_connector(&identity)?;
    let h2 = identity.acceptor(TestServerAlpn::H2)?;
    let (address, listener) = loopback_listener().await?;
    let server = serve_ticket_then_resumption(listener, h2.clone(), h2, false);

    learn_ticket(&connector, address).await?;
    let mut stream = connect_offering(&connector, address).await?;
    let answered = stream
        .early_data_wait()
        .ok_or("the resumed connection offered no early data")?;
    stream.write_all(b"early").await?;
    stream.flush().await?;
    let mut reply = [0_u8; 1];
    tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut reply)).await??;
    tokio::time::timeout(TEST_TIMEOUT, answered.answered()).await??;
    assert!(stream.session_reused());
    drop(stream);

    // The server skipped the early data and read the same bytes once, after
    // the handshake.
    let observed = tokio::time::timeout(TEST_TIMEOUT, server).await???;
    assert_eq!(observed.request, b"early");
    assert!(observed.early.is_empty());
    assert!(!observed.early_data_accepted);
    assert!(observed.session_reused);
    Ok(())
}

#[tokio::test]
async fn another_alpn_after_a_rejection_fails_the_connection() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = firefox_connector(&identity)?;
    let h2 = identity.acceptor(TestServerAlpn::H2)?;
    let http1 = identity.acceptor(TestServerAlpn::Http1)?;
    let (address, listener) = loopback_listener().await?;
    let server = serve_ticket_then_resumption(listener, h2, http1, true);

    learn_ticket(&connector, address).await?;
    let mut stream = connect_offering(&connector, address).await?;
    assert_eq!(stream.negotiated_alpn(), Some(&b"h2"[..]));
    let answered = stream
        .early_data_wait()
        .ok_or("the resumed connection offered no early data")?;
    stream.write_all(b"early").await?;
    stream.flush().await?;
    let mut reply = [0_u8; 1];
    let error = tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut reply))
        .await?
        .err()
        .ok_or("the connection continued with another ALPN protocol")?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(
        tokio::time::timeout(TEST_TIMEOUT, answered.answered())
            .await?
            .is_err()
    );
    drop(stream);
    // The server's read fails once the client gives up.
    let _ = tokio::time::timeout(TEST_TIMEOUT, server).await?;
    Ok(())
}

#[tokio::test]
async fn the_plain_handshake_offers_no_early_data() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = firefox_connector(&identity)?;
    let h2 = identity.acceptor(TestServerAlpn::H2)?;
    let (address, listener) = loopback_listener().await?;
    let server = serve_ticket_then_resumption(listener, h2.clone(), h2, true);

    learn_ticket(&connector, address).await?;
    // Proxy routes and WebSocket openings use this handshake.
    let tcp = TcpStream::connect(address).await?;
    let mut stream =
        tokio::time::timeout(TEST_TIMEOUT, connector.connect(TEST_SERVER_NAME, tcp)).await??;
    assert!(stream.early_data_wait().is_none());
    assert!(stream.session_reused());
    stream.write_all(b"after").await?;
    stream.flush().await?;
    let mut reply = [0_u8; 1];
    tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut reply)).await??;
    drop(stream);

    let observed = tokio::time::timeout(TEST_TIMEOUT, server).await???;
    assert_eq!(observed.request, b"after");
    assert!(observed.early.is_empty());
    assert!(!observed.early_data_accepted);
    Ok(())
}

fn firefox_connector(identity: &TestIdentity) -> TestResult<TlsConnector> {
    Ok(
        TlsConnector::new_with_roots(&firefox::v157_tcp_tls(), [identity.root_der()])?
            .with_isolated_session_cache(),
    )
}

/// Serves one full handshake that issues tickets permitting early data, then
/// one resumption with `resumed`, accepting early data when `early_data` is
/// set, and reports what the resumption read.
fn serve_ticket_then_resumption(
    listener: TcpListener,
    first: SslAcceptor,
    resumed: SslAcceptor,
    early_data: bool,
) -> JoinHandle<TestResult<Observed>> {
    tokio::spawn(async move {
        let mut stream =
            accept_tls_with_early_data(&listener, &first, true, Duration::ZERO).await?;
        stream.write_all(b"x").await?;
        stream.flush().await?;
        drain(&mut stream).await;

        let mut stream =
            accept_tls_with_early_data(&listener, &resumed, early_data, SERVER_DELAY).await?;
        let mut request = vec![0_u8; 5];
        stream.read_exact(&mut request).await?;
        stream.write_all(b"y").await?;
        stream.flush().await?;
        let early = stream.early_bytes();
        let early_data_accepted = stream.early_data_accepted();
        let session_reused = stream.session_reused();
        drain(&mut stream).await;
        let early = early.lock().unwrap_or_else(PoisonError::into_inner).clone();
        Ok(Observed {
            request,
            early,
            early_data_accepted,
            session_reused,
        })
    })
}

/// Reads until the client closes, so closing the server socket cannot reset
/// data the client has not read yet.
async fn drain(stream: &mut EarlyDataServerStream) {
    let _ = stream.read_to_end(&mut Vec::new()).await;
}

/// Makes a full handshake that stores the server's tickets.
async fn learn_ticket(connector: &TlsConnector, address: SocketAddr) -> TestResult<()> {
    let mut stream = connect_offering(connector, address).await?;
    assert!(stream.early_data_wait().is_none());
    let mut byte = [0_u8; 1];
    // Reading the server's first byte processes the tickets sent before it.
    tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut byte)).await??;
    Ok(())
}

async fn connect_offering(
    connector: &TlsConnector,
    address: SocketAddr,
) -> TestResult<TlsStream<TcpStream>> {
    let tcp = tokio::time::timeout(TEST_TIMEOUT, TcpStream::connect(address)).await??;
    Ok(tokio::time::timeout(
        TEST_TIMEOUT,
        connector.connect_offering_early_data(TEST_SERVER_NAME, tcp),
    )
    .await??)
}
