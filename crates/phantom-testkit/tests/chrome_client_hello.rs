//! Regression assertions for the retained Chrome ClientHello fixture.

use std::{error::Error, io, time::Duration};

use phantom_testkit::tls::{CaptureLimits, capture_client_hello, is_grease};
use tokio::io::{AsyncWriteExt, duplex};

const FIXTURE: &str = include_str!("fixtures/chrome-152.0.7977.83-macos-15.5-client-hello.txt");

#[tokio::test]
async fn chrome_152_fixture_decodes_browser_relevant_fields() -> Result<(), Box<dyn Error>> {
    let wire = fixture_record("record_0_hex")?;
    assert_eq!(wire.len(), 2_043);

    let (mut writer, mut reader) = duplex(wire.len());
    writer.write_all(&wire).await?;
    drop(writer);

    let capture = capture_client_hello(
        &mut reader,
        tokio::time::Instant::now() + Duration::from_secs(1),
        CaptureLimits::new(4_096, 4_096, 2),
    )
    .await?;
    assert_eq!(capture.records().len(), 1);
    let summary = capture.summary()?;

    assert_eq!(summary.legacy_version(), 0x0303);
    assert!(
        summary
            .cipher_suites()
            .first()
            .is_some_and(|&value| is_grease(value))
    );
    assert_eq!(
        without_grease(summary.cipher_suites()),
        [
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ]
    );
    assert_eq!(
        without_grease(summary.supported_versions()),
        [0x0304, 0x0303]
    );
    assert_eq!(
        without_grease(summary.supported_groups()),
        [0x11ec, 0x001d, 0x0017, 0x0018]
    );
    assert_eq!(summary.ec_point_formats(), [0]);
    assert_eq!(
        without_grease(summary.signature_algorithms()),
        [
            0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ]
    );
    assert_eq!(
        summary.alpn_protocols(),
        [b"h2".as_slice(), b"http/1.1".as_slice()]
    );
    assert_eq!(without_grease(summary.key_share_groups()), [0x11ec, 0x001d]);

    for required_extension in [0, 10, 11, 13, 16, 43, 45, 51, 0xfe0d] {
        assert!(summary.extension_types().contains(&required_extension));
    }
    assert_eq!(summary.extension_types().len(), 19);
    assert_eq!(
        summary
            .extension_types()
            .iter()
            .filter(|&&value| is_grease(value))
            .count(),
        2
    );

    assert!(FIXTURE.contains("browser_version=152.0.7977.83"));
    assert!(FIXTURE.contains("hostname=server.phantom.test"));
    Ok(())
}

fn fixture_record(field: &str) -> Result<Vec<u8>, io::Error> {
    let prefix = format!("{field}=");
    let value = FIXTURE
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .ok_or_else(|| invalid_fixture(format!("missing {field}")))?;
    if value.len() % 2 != 0 {
        return Err(invalid_fixture(format!("{field} contains odd-length hex")));
    }

    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, io::Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(invalid_fixture(format!(
            "fixture contains non-lowercase-hex byte {byte:#04x}"
        ))),
    }
}

fn without_grease(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .copied()
        .filter(|&value| !is_grease(value))
        .collect()
}

fn invalid_fixture(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
