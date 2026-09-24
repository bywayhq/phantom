use std::time::Duration;

use tokio::time::timeout;

use super::super::{Http3Connection, Http3Connector};
use super::{TEST_TIMEOUT, TestResult, server_endpoint};
use crate::tls::test_support::{TEST_SERVER_NAME, TestIdentity};
use phantom_profile::chromium;

fn trusting_connector(identity: &TestIdentity) -> TestResult<Http3Connector> {
    Ok(Http3Connector::new_with_additional_roots(
        &chromium::v154_http3_tls(),
        &chromium::v154_quic(),
        &chromium::v154_http3(),
        &chromium::v154_http3_request(),
        [identity.root_der()],
    )?)
}

/// Accepts QUIC connections and holds each until the client closes it.
fn spawn_server(endpoint: quinn::Endpoint) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                if let Ok(connection) = incoming.await {
                    connection.closed().await;
                }
            });
        }
    })
}

async fn connect(
    connector: &Http3Connector,
    address: std::net::SocketAddr,
) -> TestResult<Http3Connection> {
    Ok(timeout(
        TEST_TIMEOUT,
        connector.connect_direct(&address.ip().to_string(), address.port(), TEST_SERVER_NAME),
    )
    .await
    .map_err(|_| "HTTP/3 connection timed out")??)
}

/// Waits until the server's NewSessionTicket has reached the client cache.
async fn wait_for_ticket(connector: &Http3Connector) -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        while !connector.has_ticket_for(TEST_SERVER_NAME) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| "no session ticket arrived".into())
}

#[tokio::test(flavor = "current_thread")]
async fn second_connection_to_one_origin_and_route_resumes() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let server = spawn_server(endpoint);
    let connector = trusting_connector(&identity)?.with_isolated_session_cache();
    assert!(connector.resumes_sessions());

    let first = connect(&connector, address).await?;
    assert!(!first.session_resumed());
    wait_for_ticket(&connector).await?;
    let second = connect(&connector, address).await?;
    assert!(second.session_resumed());

    drop((first, second));
    server.abort();
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_ticket_learned_on_one_route_is_not_presented_on_another() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let server = spawn_server(endpoint);
    let base = trusting_connector(&identity)?;
    // The client pool gives each origin-and-route entry its own clone.
    let learned_route = base.with_isolated_session_cache();
    let other_route = base.with_isolated_session_cache();

    let first = connect(&learned_route, address).await?;
    wait_for_ticket(&learned_route).await?;
    assert!(!other_route.has_ticket_for(TEST_SERVER_NAME));
    let other = connect(&other_route, address).await?;
    assert!(!other.session_resumed());
    // Neither the shared base connector nor the other route consumed it.
    let unshared = connect(&base, address).await?;
    assert!(!unshared.session_resumed());
    assert!(learned_route.has_ticket_for(TEST_SERVER_NAME));

    drop((first, other, unshared));
    server.abort();
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_connection_from_an_isolated_clone_is_usable_by_its_base() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let server = spawn_server(endpoint);
    let base = trusting_connector(&identity)?;
    let isolated = base.with_isolated_session_cache();

    let connection = connect(&isolated, address).await?;
    assert!(base.can_reuse(&connection).await);

    drop(connection);
    server.abort();
    Ok(())
}

/// The retained Chrome 154 QUIC ClientHellos come from fresh processes, so a
/// resumed offer is compared against them: it must add `pre_shared_key`, last,
/// and change nothing else the capture fixes. Early data stays absent.
#[tokio::test(flavor = "current_thread")]
async fn resumed_chrome_154_client_hello_keeps_the_captured_shape() -> TestResult<()> {
    use super::connector::{
        CHROME_154_H3_CLIENT_HELLO_1, CHROME_154_H3_CLIENT_HELLO_2, CHROME_154_H3_STARTUP,
        PRE_SHARED_KEY, assert_client_hello_matches_capture,
    };
    const EARLY_DATA: u16 = 42;
    const PSK_KEY_EXCHANGE_MODES: u16 = 45;

    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let server = spawn_server(endpoint);
    let connector = trusting_connector(&identity)?.with_isolated_session_cache();

    let fresh = assert_client_hello_matches_capture(
        &connector,
        CHROME_154_H3_STARTUP,
        CHROME_154_H3_CLIENT_HELLO_1,
        &[],
    )?;
    assert!(fresh.contains(&PSK_KEY_EXCHANGE_MODES));
    for client_hello in [CHROME_154_H3_CLIENT_HELLO_1, CHROME_154_H3_CLIENT_HELLO_2] {
        let connection = connect(&connector, address).await?;
        wait_for_ticket(&connector).await?;
        let resumed = assert_client_hello_matches_capture(
            &connector,
            CHROME_154_H3_STARTUP,
            client_hello,
            &[PRE_SHARED_KEY],
        )?;
        assert!(!resumed.contains(&EARLY_DATA));
        drop(connection);
    }

    server.abort();
    Ok(())
}
