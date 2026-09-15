use phantom_profile::chromium::v152_macos_tls;

use super::{TestResult, TlsConnector, TlsErrorKind, capture_client_hello_from};

#[tokio::test]
async fn exact_ech_grease_payload_length_controls_the_wire_body() -> TestResult<()> {
    let mut settings = v152_macos_tls();
    settings.ech_grease_payload_length = Some(239);

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
    let settings = v152_macos_tls();
    assert_eq!(settings.ech_grease_payload_length, None);

    let capture = capture_client_hello_from(&settings).await?;
    let ech_body_length = capture
        .summary()?
        .extension_layout()
        .find_map(|(extension_type, body_length)| (extension_type == 0xfe0d).then_some(body_length))
        .ok_or("ClientHello omitted ECH GREASE")?;

    assert!([186, 218, 250, 282].contains(&ech_body_length));
    Ok(())
}

#[test]
fn exact_ech_grease_payload_without_ech_fails_before_stream_io() -> TestResult<()> {
    let mut settings = v152_macos_tls();
    settings.ech_grease = false;
    settings.ech_grease_payload_length = Some(239);

    let error = match TlsConnector::new(&settings) {
        Ok(_) => return Err("ECH GREASE payload length unexpectedly built a connector".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), TlsErrorKind::InvalidConfiguration);
    assert!(error.to_string().contains("ech_grease_payload_length"));
    Ok(())
}
