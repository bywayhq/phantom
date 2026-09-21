use phantom_profile::{ClientHelloExtension, ClientHelloExtensionOrder, chromium::v152_tls};

use super::{TestResult, capture_client_hello_from, client_hello_fixture};

const RECORD_SIZE_LIMIT_EXTENSION: u16 = 28;

#[tokio::test]
async fn configured_record_size_limit_controls_the_wire_body() -> TestResult<()> {
    let mut settings = v152_tls();
    settings.record_size_limit = Some(16_385);
    settings.extension_order =
        ClientHelloExtensionOrder::Fixed(vec![ClientHelloExtension::RecordSizeLimit]);

    let capture = capture_client_hello_from(&settings).await?;
    assert_eq!(
        client_hello_fixture::extension_payload(
            capture.handshake_bytes(),
            RECORD_SIZE_LIMIT_EXTENSION,
        )?,
        [0x40, 0x01],
    );
    Ok(())
}

#[tokio::test]
async fn omitted_record_size_limit_omits_the_extension() -> TestResult<()> {
    let settings = v152_tls();
    assert_eq!(settings.record_size_limit, None);

    let summary = capture_client_hello_from(&settings).await?.summary()?;
    assert!(
        !summary
            .extension_types()
            .contains(&RECORD_SIZE_LIMIT_EXTENSION)
    );
    Ok(())
}
