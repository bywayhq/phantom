//! Retained ClientHello loading and payload inspection for TLS tests.

use std::io;

use phantom_testkit::tls::{CaptureLimits, ClientHelloCapture, capture_client_hello};
use tokio::{io::AsyncWriteExt, time::Instant};

use crate::tls::test_support::{TEST_TIMEOUT, TestResult};

pub(super) async fn capture(fixture: &str) -> TestResult<ClientHelloCapture> {
    let record_count = fixture_value(fixture, "record_count")?.parse::<usize>()?;
    let records = (0..record_count)
        .map(|index| decode_hex(fixture_value(fixture, &format!("record_{index}_hex"))?))
        .collect::<Result<Vec<_>, _>>()?;
    let wire = records.concat();
    let (mut writer, mut reader) = tokio::io::duplex(wire.len());
    writer.write_all(&wire).await?;
    drop(writer);

    Ok(capture_client_hello(
        &mut reader,
        Instant::now() + TEST_TIMEOUT,
        CaptureLimits::new(32 * 1024, 40 * 1024, 4),
    )
    .await?)
}

pub(super) fn extension_payload(handshake: &[u8], expected_type: u16) -> io::Result<&[u8]> {
    let mut offset = 0;
    take(handshake, &mut offset, 4)?;
    take(handshake, &mut offset, 2 + 32)?;
    let session_id_length = usize::from(read_u8(handshake, &mut offset)?);
    take(handshake, &mut offset, session_id_length)?;
    let cipher_suites_length = usize::from(read_u16(handshake, &mut offset)?);
    take(handshake, &mut offset, cipher_suites_length)?;
    let compression_methods_length = usize::from(read_u8(handshake, &mut offset)?);
    take(handshake, &mut offset, compression_methods_length)?;
    let extensions_length = usize::from(read_u16(handshake, &mut offset)?);
    let extensions = take(handshake, &mut offset, extensions_length)?;

    let mut extension_offset = 0;
    while extension_offset < extensions.len() {
        let extension_type = read_u16(extensions, &mut extension_offset)?;
        let payload_length = usize::from(read_u16(extensions, &mut extension_offset)?);
        let payload = take(extensions, &mut extension_offset, payload_length)?;
        if extension_type == expected_type {
            return Ok(payload);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("ClientHello omitted extension 0x{expected_type:04x}"),
    ))
}

/// Returns the ECHClientHello type, HPKE KDF, and HPKE AEAD octets.
pub(super) fn ech_cipher_suite(handshake: &[u8]) -> io::Result<[u8; 5]> {
    extension_payload(handshake, 0xfe0d)?
        .first_chunk::<5>()
        .copied()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "ECH extension is shorter than its cipher suite",
            )
        })
}

fn fixture_value<'a>(fixture: &'a str, field: &str) -> Result<&'a str, io::Error> {
    let prefix = format!("{field}=");
    fixture
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("missing {field}")))
}

pub(super) fn decode_hex(value: &str) -> Result<Vec<u8>, io::Error> {
    if !value.len().is_multiple_of(2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture contains odd-length hex",
        ));
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, io::Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture contains non-lowercase hex",
        )),
    }
}

fn read_u8(bytes: &[u8], offset: &mut usize) -> io::Result<u8> {
    Ok(take(bytes, offset, 1)?[0])
}

fn read_u16(bytes: &[u8], offset: &mut usize) -> io::Result<u16> {
    let bytes = take(bytes, offset, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn take<'a>(bytes: &'a [u8], offset: &mut usize, length: usize) -> io::Result<&'a [u8]> {
    let end = offset
        .checked_add(length)
        .filter(|&end| end <= bytes.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated ClientHello"))?;
    let value = &bytes[*offset..end];
    *offset = end;
    Ok(value)
}
