use bytes::Bytes;
use tokio::time::timeout;

use super::early_data::{connect, trusting_connector};
use super::{TEST_TIMEOUT, TestResult, server_endpoint};
use crate::http3::{Http3Connector, Http3MappingConfirmation};
use crate::tls::test_support::TestIdentity;

#[tokio::test]
async fn checked_mapping_confirmation_requires_the_originating_connector() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = trusting_connector(&identity)?;
    let unrelated = trusting_connector(&identity)?;
    let observed = observe_registration(&identity, &connector, &unrelated).await?;

    assert!(observed.initially_reusable);
    assert!(!observed.unrelated_accepted);
    assert!(!observed.unrelated_confirmed);
    assert!(observed.originating_accepted);
    assert!(observed.originating_confirmed);
    assert!(observed.clone_accepted);
    assert!(observed.after_close_accepted);
    assert!(observed.after_close_confirmed);
    Ok(())
}

#[cfg(feature = "danger-disable-verification")]
#[tokio::test]
async fn unchecked_peer_authentication_cannot_confirm_a_mapping() -> TestResult<()> {
    use phantom_profile::browser::chrome;

    let identity = TestIdentity::generate()?;
    let connector = Http3Connector::new_with_server_authentication(
        &chrome::v154_quic_tls(),
        &chrome::v154_quic(),
        &chrome::v154_http3(),
        &chrome::v154_http3_request(),
        crate::tls::ServerAuthentication::DangerDisabled,
    )?;
    let unrelated = trusting_connector(&identity)?;
    let observed = observe_registration(&identity, &connector, &unrelated).await?;

    assert!(observed.initially_reusable);
    assert!(!observed.unrelated_accepted);
    assert!(!observed.unrelated_confirmed);
    assert!(!observed.originating_accepted);
    assert!(!observed.originating_confirmed);
    assert!(!observed.clone_accepted);
    assert!(!observed.after_close_accepted);
    assert!(!observed.after_close_confirmed);
    Ok(())
}

struct RegistrationObservation {
    initially_reusable: bool,
    unrelated_accepted: bool,
    unrelated_confirmed: bool,
    originating_accepted: bool,
    originating_confirmed: bool,
    clone_accepted: bool,
    after_close_accepted: bool,
    after_close_confirmed: bool,
}

async fn observe_registration(
    identity: &TestIdentity,
    connector: &Http3Connector,
    unrelated: &Http3Connector,
) -> TestResult<RegistrationObservation> {
    let (address, endpoint) = server_endpoint(identity)?;
    let operation = timeout(TEST_TIMEOUT, async {
        let peer = async {
            let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
            let connection = incoming.await?;
            let h3 = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(
                connection.clone(),
            ))
            .await?;
            TestResult::Ok((connection, h3))
        };
        let (connection, (peer, h3)) = tokio::try_join!(connect(connector, address), peer)?;
        let initially_reusable = connector.can_reuse_now(&connection);
        let unrelated_cell = Http3MappingConfirmation::new();
        let unrelated_accepted =
            unrelated.register_mapping_confirmation(&connection, &unrelated_cell);
        let originating_cell = Http3MappingConfirmation::new();
        let originating_accepted =
            connector.register_mapping_confirmation(&connection, &originating_cell);
        let clone_accepted = connector
            .without_early_data()
            .register_mapping_confirmation(&connection, &originating_cell);

        peer.close(0_u32.into(), b"test complete");
        // Wait for actual client-side closure before checking historical setup.
        while connector.can_reuse_now(&connection) {
            tokio::task::yield_now().await;
        }
        let after_close = Http3MappingConfirmation::new();
        let after_close_accepted =
            connector.register_mapping_confirmation(&connection, &after_close);
        let observed = RegistrationObservation {
            initially_reusable,
            unrelated_accepted,
            unrelated_confirmed: unrelated_cell.is_confirmed(),
            originating_accepted,
            originating_confirmed: originating_cell.is_confirmed(),
            clone_accepted,
            after_close_accepted,
            after_close_confirmed: after_close.is_confirmed(),
        };
        drop((connection, peer, h3));
        TestResult::Ok(observed)
    })
    .await;

    endpoint.close(0_u32.into(), b"test cleanup");
    let cleanup = timeout(TEST_TIMEOUT, endpoint.wait_idle()).await;
    let operation = match operation {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };
    match (operation, cleanup) {
        (Ok(observed), Ok(())) => Ok(observed),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
        (Err(error), Err(cleanup)) => Err(format!("{error}; endpoint cleanup: {cleanup}").into()),
    }
}
