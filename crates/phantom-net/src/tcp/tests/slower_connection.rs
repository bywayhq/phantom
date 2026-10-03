//! The slower attempt of a backup connection, which the connectors turn into
//! an idle HTTP connection: a scripted attempt connects to a loopback origin
//! when the test lets it.

use std::{net::SocketAddr, time::Duration};

use http_body_util::BodyExt as _;
use phantom_profile::{TcpKeepalivePolicy, TcpKeepaliveSchedule, firefox};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};

use crate::{
    http1::{Http1TlsConnector, slower_plaintext},
    http1_or_2::{Http1Or2Connection, Http1Or2TlsConnector, keeps_slower},
    request::{OriginForm, RequestHeader},
    tcp::{
        SlowerAttempt,
        keepalive_schedule::{KeepalivePhase, TcpKeepaliveControl, observed},
    },
    tls::test_support::{
        TEST_SERVER_NAME, TestIdentity, TestResult, TestServerAlpn, accept_tls, loopback_listener,
    },
};

const WAIT: Duration = Duration::from_secs(5);
const SETUP: Duration = Duration::from_millis(2_150);
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

fn schedule() -> TestResult<TcpKeepaliveSchedule> {
    match firefox::v157_tcp().keepalive {
        TcpKeepalivePolicy::Schedule(schedule) => Ok(schedule),
        other => Err(format!("the recipe's keepalive is {other:?}").into()),
    }
}

/// A slower attempt that connects to `address` once the test sends on the
/// returned gate, after a setup of [`SETUP`].
fn gated(address: SocketAddr) -> TestResult<(SlowerAttempt, oneshot::Sender<()>)> {
    let (gate, opened) = oneshot::channel();
    let attempt = SlowerAttempt::scripted(
        async move {
            let _ = opened.await;
            TcpStream::connect(address).await
        },
        SETUP,
        Some(schedule()?),
    );
    Ok((attempt, gate))
}

fn only_schedule() -> TestResult<TcpKeepaliveControl> {
    let mut controls = observed::take();
    let control = controls.pop().ok_or("no keepalive schedule was opened")?;
    assert!(controls.is_empty(), "more than one schedule was opened");
    Ok(control)
}

async fn read_head(stream: &mut (impl AsyncReadExt + Unpin)) -> TestResult<()> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        if stream.read(&mut byte).await? == 0 {
            return Err("the client closed before a request head".into());
        }
        head.push(byte[0]);
    }
    Ok(())
}

fn get() -> TestResult<(OriginForm, Vec<RequestHeader>)> {
    Ok((
        OriginForm::parse("/")?,
        vec![RequestHeader::new("Host", "127.0.0.1")],
    ))
}

#[tokio::test(flavor = "current_thread")]
async fn a_plaintext_slower_connection_sets_no_keepalive_until_its_first_request() -> TestResult<()>
{
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let origin_address = listener.local_addr()?;
    let origin = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        read_head(&mut stream).await?;
        stream.write_all(RESPONSE).await?;
        TestResult::<()>::Ok(())
    });
    observed::take();
    let (attempt, gate) = gated(origin_address)?;
    let slower = slower_plaintext(attempt);
    let progress = slower.progress();
    assert!(!progress.has_connected());

    let _ = gate.send(());
    let connection = timeout(WAIT, slower.finish())
        .await?
        .ok_or("the slower connection failed")?;

    let control = only_schedule()?;
    assert!(control.is_idle());
    assert_eq!(control.interval(), Duration::from_secs(2));
    assert!(control.applied_phases().is_empty());
    let (target, headers) = get()?;
    connection
        .send_get(target, headers)
        .await?
        .into_body()
        .collect()
        .await?;
    origin.await??;
    assert_eq!(control.applied_phases(), [KeepalivePhase::ShortLived]);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_tls_slower_connection_finishes_its_handshake_without_a_request() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let acceptor = identity.acceptor(TestServerAlpn::Http1)?;
    let (address, listener) = loopback_listener().await?;
    let (handshaken, handshake_done) = oneshot::channel();
    let origin = tokio::spawn(async move {
        let (mut stream, _) = accept_tls(listener, acceptor).await?;
        let _ = handshaken.send(());
        read_head(&mut stream).await?;
        stream.write_all(RESPONSE).await?;
        stream.flush().await?;
        TestResult::<()>::Ok(())
    });
    observed::take();
    let connector =
        Http1TlsConnector::new_with_additional_roots(&firefox::v157_tls(), [identity.root_der()])?;
    let (attempt, gate) = gated(address)?;
    let slower = connector.slower_tls(attempt, TEST_SERVER_NAME);

    let _ = gate.send(());
    let connection = timeout(WAIT, slower.finish())
        .await?
        .ok_or("the slower connection failed")?;
    // The origin finished its side of the handshake before any request.
    timeout(WAIT, handshake_done).await??;

    let control = only_schedule()?;
    assert!(control.is_idle());
    assert_eq!(control.applied_phases(), [KeepalivePhase::ShortLived]);
    let (target, headers) = get()?;
    let response = connection.send_get(target, headers).await?;
    assert_eq!(response.status(), 200);
    response.into_body().collect().await?;
    origin.await??;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_negotiated_slower_connection_enters_the_protocol_alpn_selects() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let acceptor = identity.acceptor(TestServerAlpn::H2)?;
    let (address, listener) = loopback_listener().await?;
    let origin = tokio::spawn(async move {
        let (mut stream, _) = accept_tls(listener, acceptor).await?;
        let mut preface = [0; 24];
        stream.read_exact(&mut preface).await?;
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest).await;
        TestResult::<()>::Ok(())
    });
    observed::take();
    let connector = Http1Or2TlsConnector::new_with_additional_roots(
        &firefox::v157_tls(),
        &firefox::v157_http2(),
        [identity.root_der()],
    )?;
    let (attempt, gate) = gated(address)?;
    let slower = connector.slower_connection(attempt, TEST_SERVER_NAME);

    let _ = gate.send(());
    let connection = timeout(WAIT, slower.finish())
        .await?
        .ok_or("the slower connection failed")?;

    assert!(matches!(connection, Http1Or2Connection::Http2(_)));
    let control = only_schedule()?;
    assert_eq!(
        control.applied_phases(),
        [KeepalivePhase::ShortLived, KeepalivePhase::Disabled]
    );
    drop(connection);
    timeout(WAIT, origin).await???;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn an_http2_first_connection_keeps_only_a_slower_attempt_that_connected() -> TestResult<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let origin_address = listener.local_addr()?;
    let (client, _server) = tokio::io::duplex(64 * 1024);
    let http2 = Http1Or2Connection::Http2(
        crate::http2::Http2Connection::connect(client, &firefox::v157_http2()).await?,
    );
    let (client, _server) = tokio::io::duplex(1024);
    let http1 = Http1Or2Connection::Http1(crate::http1::Http1Connection::connect(client).await?);

    let (mut attempt, gate) = gated(origin_address)?;
    assert!(!keeps_slower(&http2, &attempt));
    assert!(keeps_slower(&http1, &attempt));

    // The listener's backlog completes the connect without an accept.
    let _ = gate.send(());
    timeout(WAIT, async {
        while !attempt.has_connected() {
            attempt.alongside(tokio::task::yield_now()).await;
        }
    })
    .await?;
    assert!(keeps_slower(&http2, &attempt));
    Ok(())
}
