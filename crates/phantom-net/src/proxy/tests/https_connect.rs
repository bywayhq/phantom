use std::time::Duration;

use phantom_profile::{
    CipherSuite, ClientHelloExtensionOrder, NamedGroup, SignatureScheme, TlsSettings, TlsVersion,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
use tracing::instrument::WithSubscriber;

use crate::{
    proxy::{HttpConnectError, HttpConnectErrorKind, HttpConnectHeader, HttpsProxyConnector},
    tls::test_support::{
        TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, TestServerAlpn, accept_tls,
        loopback_listener,
    },
    tracing_test::OutcomeSubscriber,
};

#[test]
fn requires_http1_alpn_before_building_tls() -> TestResult<()> {
    let mut settings = tls_settings();
    settings.alpn_protocols = vec![Box::from(&b"h2"[..])];

    let error = HttpsProxyConnector::new(&settings)
        .err()
        .ok_or("HTTPS proxy connector accepted settings without HTTP/1.1 ALPN")?;
    assert!(matches!(error, HttpConnectError::MissingHttp1Alpn));
    assert_eq!(error.kind(), HttpConnectErrorKind::InvalidConfiguration);
    Ok(())
}

#[test]
fn exposes_tls_configuration_failure_as_proxy_error() -> TestResult<()> {
    let error = HttpsProxyConnector::new_with_additional_roots(
        &tls_settings(),
        [&b"not-a-certificate"[..]],
    )
    .err()
    .ok_or("invalid proxy trust root was accepted")?;
    assert!(matches!(error, HttpConnectError::ProxyTls(_)));
    assert_eq!(error.kind(), HttpConnectErrorKind::Tls);
    Ok(())
}

#[tokio::test]
async fn negotiates_proxy_tls_and_preserves_connect_order_and_prefix() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector =
            HttpsProxyConnector::new_with_additional_roots(&tls_settings(), [identity.root_der()])?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::Http1)?;
        let proxy_task = tokio::spawn(async move {
            let (mut stream, sni) = accept_tls(listener, acceptor).await?;
            let request = super::read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nprefix")
                .await?;
            stream.flush().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((sni, request))
        });
        let subscriber = OutcomeSubscriber::default();

        let mut tunnel = connector
            .connect_tunnel(
                "127.0.0.1",
                address.port(),
                TEST_SERVER_NAME,
                "origin.example:443",
                &[
                    HttpConnectHeader::field(crate::request::RequestHeader::new(
                        "User-Agent",
                        "fixture",
                    )),
                    HttpConnectHeader::authority("host"),
                ],
            )
            .with_subscriber(subscriber.dispatch())
            .await?;
        let mut prefix = [0_u8; 6];
        tunnel.read_exact(&mut prefix).await?;

        let (sni, request) = proxy_task.await??;
        assert_eq!(sni.as_deref(), Some(TEST_SERVER_NAME));
        assert_eq!(&prefix, b"prefix");
        assert_eq!(
            request,
            b"CONNECT origin.example:443 HTTP/1.1\r\n\
              User-Agent: fixture\r\n\
              host: origin.example:443\r\n\r\n"
        );
        assert_eq!(subscriber.outcomes_for("proxy.http_connect"), ["ok"]);
        Ok(())
    })
    .await
    .map_err(|_| "HTTPS proxy success test exceeded its deadline")?
}

#[tokio::test]
async fn accepts_absent_alpn_after_offering_http1() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector =
            HttpsProxyConnector::new_with_additional_roots(&tls_settings(), [identity.root_der()])?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::None)?;
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = accept_tls(listener, acceptor).await?;
            let request = super::read_head(&mut stream).await?;
            stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(request)
        });

        let _tunnel = connector
            .connect_tunnel(
                "127.0.0.1",
                address.port(),
                TEST_SERVER_NAME,
                "origin.example:443",
                &[HttpConnectHeader::authority("Host")],
            )
            .await?;
        assert_eq!(
            proxy_task.await??,
            b"CONNECT origin.example:443 HTTP/1.1\r\n\
              Host: origin.example:443\r\n\r\n"
        );
        Ok(())
    })
    .await
    .map_err(|_| "HTTPS proxy absent-ALPN test exceeded its deadline")?
}

#[tokio::test]
async fn rejects_h2_before_writing_connect() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector =
            HttpsProxyConnector::new_with_additional_roots(&tls_settings(), [identity.root_der()])?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = accept_tls(listener, acceptor).await?;
            let mut byte = [0_u8; 1];
            let read = timeout(Duration::from_millis(250), stream.read(&mut byte)).await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(matches!(read, Ok(Ok(0))))
        });

        let error = connector
            .connect_tunnel(
                "127.0.0.1",
                address.port(),
                TEST_SERVER_NAME,
                "origin.example:443",
                &[HttpConnectHeader::authority("Host")],
            )
            .await
            .err()
            .ok_or("HTTPS proxy accepted h2 for an HTTP/1.1 CONNECT exchange")?;
        assert!(matches!(
            error,
            HttpConnectError::UnsupportedAlpn { ref selected } if selected.as_ref() == b"h2"
        ));
        assert_eq!(error.kind(), HttpConnectErrorKind::UnsupportedProtocol);
        assert!(proxy_task.await??, "CONNECT bytes reached the h2 proxy");
        Ok(())
    })
    .await
    .map_err(|_| "HTTPS proxy ALPN test exceeded its deadline")?
}

#[tokio::test]
async fn invalid_connect_fails_before_proxy_tcp_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector =
        HttpsProxyConnector::new_with_additional_roots(&tls_settings(), [identity.root_der()])?;
    let (address, listener) = loopback_listener().await?;

    let error = connector
        .connect_tunnel(
            "127.0.0.1",
            address.port(),
            TEST_SERVER_NAME,
            "origin.example:443",
            &[],
        )
        .await
        .err()
        .ok_or("HTTPS proxy accepted CONNECT without an authority field")?;
    assert!(matches!(error, HttpConnectError::MissingAuthorityHeader));
    assert!(
        timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err(),
        "invalid CONNECT opened a proxy TCP connection"
    );
    Ok(())
}

pub(super) fn tls_settings() -> TlsSettings {
    TlsSettings {
        min_version: TlsVersion::Tls12,
        max_version: TlsVersion::Tls12,
        cipher_suites: vec![CipherSuite::EcdheEcdsaAes128GcmSha256],
        groups: vec![NamedGroup::X25519, NamedGroup::Secp256r1],
        key_shares: Vec::new(),
        signature_schemes: vec![SignatureScheme::EcdsaSecp256r1Sha256],
        delegated_credential_schemes: Vec::new(),
        alpn_protocols: vec![Box::from(&b"h2"[..]), Box::from(&b"http/1.1"[..])],
        alps: None,
        certificate_compression: Vec::new(),
        session_tickets: true,
        record_size_limit: None,
        requested_trust_anchor_ids: None,
        grease: false,
        grease_signature_algorithms: false,
        extension_order: ClientHelloExtensionOrder::BackendDefault,
        ech_grease: false,
        ech_grease_payload_length: None,
        ech_grease_aeads: Vec::new(),
        ech_from_https_records: false,
        request_ocsp_staple: false,
        request_signed_certificate_timestamps: false,
        aes_hardware: true,
    }
}
