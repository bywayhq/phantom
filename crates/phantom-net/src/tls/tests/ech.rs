use phantom_profile::{
    EchGreaseAead, EchGreasePayloadLength, EchGreaseSettings, EchSettings,
    browser::chrome::{v154_quic_tls, v154_tcp_tls},
};

use super::{
    TestResult, TlsConnector, TlsErrorKind, capture_client_hello_from, client_hello_fixture,
};

#[tokio::test]
async fn exact_ech_grease_payload_length_controls_the_wire_body() -> TestResult<()> {
    let mut settings = v154_tcp_tls();
    settings.ech = EchSettings::HttpsRecords(EchGreaseSettings::new(
        EchGreasePayloadLength::Exact(239),
        Vec::new(),
    )?);

    let capture = capture_client_hello_from(&settings).await?;
    let ech_body_length =
        capture
            .summary()?
            .extension_layout()
            .find_map(|(extension_type, body_length)| {
                (extension_type == 0xfe0d).then_some(body_length)
            });

    assert_eq!(ech_body_length, Some(281));
    Ok(())
}

#[tokio::test]
async fn omitted_ech_grease_payload_length_retains_backend_policy() -> TestResult<()> {
    let settings = v154_tcp_tls();
    assert_eq!(
        settings
            .ech
            .grease()
            .ok_or("ECH GREASE disabled")?
            .payload_length(),
        EchGreasePayloadLength::BackendDefault
    );

    let capture = capture_client_hello_from(&settings).await?;
    let ech_body_length = capture
        .summary()?
        .extension_layout()
        .find_map(|(extension_type, body_length)| (extension_type == 0xfe0d).then_some(body_length))
        .ok_or("ClientHello omitted ECH GREASE")?;

    assert!([186, 218, 250, 282].contains(&ech_body_length));
    Ok(())
}

#[tokio::test]
async fn disabled_ech_omits_the_extension() -> TestResult<()> {
    let mut settings = v154_tcp_tls();
    settings.ech = EchSettings::Disabled;
    let capture = capture_client_hello_from(&settings).await?;
    assert!(
        !capture
            .summary()?
            .extension_layout()
            .any(|(extension_type, _)| extension_type == 0xfe0d)
    );
    Ok(())
}

#[tokio::test]
async fn configured_ech_grease_aead_controls_the_wire_cipher_suite() -> TestResult<()> {
    let mut settings = v154_tcp_tls();
    settings.ech = EchSettings::HttpsRecords(EchGreaseSettings::new(
        EchGreasePayloadLength::BackendDefault,
        vec![EchGreaseAead::Aes256Gcm],
    )?);

    let capture = capture_client_hello_from(&settings).await?;

    // ECHClientHello type outer (0), HKDF-SHA256 (0x0001), AES-256-GCM (0x0002).
    assert_eq!(
        client_hello_fixture::ech_cipher_suite(capture.handshake_bytes())?,
        [0x00, 0x00, 0x01, 0x00, 0x02]
    );
    Ok(())
}

#[test]
fn ech_with_tls_12_fails_before_stream_io() -> TestResult<()> {
    let mut settings = v154_tcp_tls();
    settings.versions = phantom_profile::TlsVersionRange::only(phantom_profile::TlsVersion::Tls12);
    settings.key_shares.clear();
    let error = match TlsConnector::new(&settings) {
        Ok(_) => return Err("ECH unexpectedly built a TLS 1.2 connector".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), TlsErrorKind::InvalidConfiguration);
    assert_eq!(error.to_string(), "invalid TLS settings");
    let source = std::error::Error::source(&error)
        .and_then(|source| source.downcast_ref::<phantom_profile::InvalidTlsSettings>())
        .ok_or("TLS error omitted its original validator source")?;
    assert!(source.to_string().contains("ech"));
    Ok(())
}

#[test]
fn quic_connector_accepts_ech_from_https_records() -> TestResult<()> {
    let mut settings = v154_quic_tls();
    settings.ech = EchSettings::HttpsRecords(EchGreaseSettings::backend_default());
    TlsConnector::new_quic_with_additional_roots(&settings, [], |_| {})?;
    Ok(())
}
