use phantom_profile::chromium::v154_tls;
use tracing::{Dispatch, dispatcher, instrument::WithSubscriber};

use super::{
    TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, TlsConnector, TlsErrorKind,
    connect_local, start_server,
};
use crate::tracing_test::{OutcomeSubscriber, poll_once_then_drop};

#[test]
fn invalid_settings_record_connector_error_kind() -> TestResult<()> {
    let subscriber = OutcomeSubscriber::default();
    let dispatch = Dispatch::new(subscriber.clone());
    let mut settings = v154_tls();
    settings.alpn_protocols = vec![Box::default()];

    let error = dispatcher::with_default(&dispatch, || {
        TlsConnector::new_with_roots(&settings, std::iter::empty::<&[u8]>())
    })
    .err()
    .ok_or("invalid settings unexpectedly built a connector")?;

    assert_eq!(error.kind(), TlsErrorKind::InvalidConfiguration);
    assert_eq!(subscriber.outcomes_for("tls.connector.build"), ["error"]);
    assert_eq!(
        subscriber.error_kinds_for("tls.connector.build"),
        ["invalid_configuration"]
    );
    Ok(())
}

#[test]
fn successful_connector_build_records_outcome_without_error_kind() -> TestResult<()> {
    let subscriber = OutcomeSubscriber::default();
    let dispatch = Dispatch::new(subscriber.clone());

    dispatcher::with_default(&dispatch, || {
        TlsConnector::new_with_roots(&v154_tls(), std::iter::empty::<&[u8]>())
    })?;

    assert_eq!(subscriber.outcomes_for("tls.connector.build"), ["ok"]);
    assert!(subscriber.error_kinds_for("tls.connector.build").is_empty());
    Ok(())
}

#[tokio::test]
async fn failed_handshake_records_static_error_kind() -> TestResult<()> {
    let connector = TlsConnector::new_with_roots(&v154_tls(), std::iter::empty::<&[u8]>())?;
    let (client, server) = tokio::io::duplex(4096);
    drop(server);
    let subscriber = OutcomeSubscriber::default();
    let dispatch = Dispatch::new(subscriber.clone());

    let error = connector
        .connect("example.test", client)
        .with_subscriber(dispatch)
        .await
        .err()
        .ok_or("closed stream unexpectedly completed a TLS handshake")?;

    assert_eq!(error.kind(), TlsErrorKind::Handshake);
    assert_eq!(subscriber.outcomes_for("tls.handshake"), ["error"]);
    assert_eq!(subscriber.error_kinds_for("tls.handshake"), ["handshake"]);
    Ok(())
}

#[tokio::test]
async fn dropped_handshake_records_cancelled_without_error_kind() -> TestResult<()> {
    let connector = TlsConnector::new_with_roots(&v154_tls(), std::iter::empty::<&[u8]>())?;
    let (client, _server) = tokio::io::duplex(4096);
    let subscriber = OutcomeSubscriber::default();

    assert!(
        poll_once_then_drop(
            connector.connect("example.test", client),
            subscriber.clone(),
        )
        .await,
        "TLS handshake completed on its first poll"
    );
    assert_eq!(subscriber.outcomes_for("tls.handshake"), ["cancelled"]);
    assert!(subscriber.error_kinds_for("tls.handshake").is_empty());
    Ok(())
}

#[tokio::test]
async fn successful_handshake_records_negotiated_version_and_cipher() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, server_task) = start_server(&identity, true).await?;
    let connector = TlsConnector::new_with_roots(&v154_tls(), [identity.root_der()])?;
    let subscriber = OutcomeSubscriber::default();
    let dispatch = Dispatch::new(subscriber.clone());

    connect_local(&connector, address, TEST_SERVER_NAME)
        .with_subscriber(dispatch)
        .await??;
    tokio::time::timeout(TEST_TIMEOUT, server_task).await???;

    assert_eq!(subscriber.tls_versions_for("tls.handshake"), ["TLSv1.3"]);
    let cipher_suites = subscriber.cipher_suites_for("tls.handshake");
    assert_eq!(cipher_suites.len(), 1);
    assert_ne!(cipher_suites[0], "unknown");
    Ok(())
}
