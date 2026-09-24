use std::{collections::BTreeSet, io, net::SocketAddr};

use phantom_testkit::tls::ClientHelloSummary;

use super::TestResult;

const FIRST: &str = include_str!(concat!(
    "../../../../fixtures/http3/chrome/154.0.8037.58/",
    "windows-11-26200/quic-client-hello-1.txt"
));
const SECOND: &str = include_str!(concat!(
    "../../../../fixtures/http3/chrome/154.0.8037.58/",
    "windows-11-26200/quic-client-hello-2.txt"
));
const EXPECTED_EXTENSIONS: [u16; 12] = [
    0x0000, 0x000a, 0x000d, 0x0010, 0x001b, 0x002b, 0x002d, 0x0033, 0x0039, 0x44cd, 0xca34, 0xfe0d,
];

#[test]
fn chrome_154_quic_client_hello_retains_stable_fields() -> TestResult<()> {
    let captures = [QuicFixture::parse(FIRST)?, QuicFixture::parse(SECOND)?];
    let summaries = captures
        .iter()
        .map(|capture| ClientHelloSummary::from_handshake_bytes(&capture.handshake))
        .collect::<Result<Vec<_>, _>>()?;

    for (capture, summary) in captures.iter().zip(&summaries) {
        assert_eq!(capture.client, "Google Chrome");
        assert_eq!(capture.client_version, "154.0.8037.58");
        assert_eq!(capture.operating_system, "Windows 11 Home 10.0.26200 x64");
        assert_eq!(capture.hostname, "server.phantom.test");
        assert!(capture.listen_address.ip().is_loopback());
        assert_eq!(capture.quic_version, 1);
        assert_eq!(capture.alpn, "h3");
        assert_eq!(summary.legacy_version(), 0x0303);
        assert_eq!(summary.server_name(), Some(capture.hostname.as_bytes()));
        assert_eq!(summary.cipher_suites(), [0x1301, 0x1302, 0x1303]);
        assert_eq!(summary.supported_versions(), [0x0304]);
        assert_eq!(summary.supported_groups(), [0x11ec, 0x001d, 0x0017, 0x0018]);
        assert_eq!(summary.key_share_groups(), [0x11ec, 0x001d]);
        assert_eq!(
            summary.signature_algorithms(),
            [
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
            ]
        );
        assert_eq!(summary.alpn_protocols(), [b"h3".as_slice()]);
        assert_eq!(
            summary.requested_trust_anchor_ids().map(<[_]>::len),
            Some(28)
        );

        let mut extensions = summary.extension_types().to_vec();
        extensions.sort_unstable();
        assert_eq!(extensions, EXPECTED_EXTENSIONS);
        assert!(!extensions.contains(&0x0029), "fresh profile offered a PSK");
        assert!(
            !extensions.contains(&0x002a),
            "fresh profile offered early data"
        );

        let transport = extension_payload(&capture.handshake, 0x0039)?;
        assert_transport_parameters(transport)?;
    }

    assert_ne!(
        summaries[0].extension_types(),
        summaries[1].extension_types(),
        "independent captures did not exercise extension permutation"
    );
    assert_ne!(captures[0].handshake, captures[1].handshake);
    Ok(())
}

struct QuicFixture<'a> {
    client: &'a str,
    client_version: &'a str,
    operating_system: &'a str,
    hostname: &'a str,
    listen_address: SocketAddr,
    quic_version: u32,
    alpn: &'a str,
    handshake: Vec<u8>,
}

impl<'a> QuicFixture<'a> {
    fn parse(text: &'a str) -> io::Result<Self> {
        const KEYS: [&str; 13] = [
            "format",
            "captured_at_unix",
            "client",
            "client_version",
            "operating_system",
            "hostname",
            "listen_address",
            "launch_mode",
            "launch_arguments",
            "capture_tool",
            "quic_version",
            "alpn",
            "handshake_hex",
        ];
        let lines = text.lines().collect::<Vec<_>>();
        if lines.len() != KEYS.len() {
            return Err(invalid("unexpected QUIC ClientHello fixture length"));
        }
        let mut values = Vec::with_capacity(KEYS.len());
        for (line, expected) in lines.into_iter().zip(KEYS) {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| invalid("fixture line is not key=value"))?;
            if key != expected || value.is_empty() {
                return Err(invalid(format!(
                    "expected nonempty fixture field {expected}"
                )));
            }
            values.push(value);
        }
        if values[0] != "phantom-quic-client-hello-v1" {
            return Err(invalid("unexpected QUIC ClientHello fixture format"));
        }
        if values[1].parse::<u64>().map_or(true, |value| value == 0) {
            return Err(invalid("invalid capture timestamp"));
        }
        let quic_version = values[10]
            .strip_prefix("0x")
            .ok_or_else(|| invalid("QUIC version is not hexadecimal"))
            .and_then(|value| {
                u32::from_str_radix(value, 16).map_err(|error| invalid(error.to_string()))
            })?;
        Ok(Self {
            client: values[2],
            client_version: values[3],
            operating_system: values[4],
            hostname: values[5],
            listen_address: values[6]
                .parse()
                .map_err(|error| invalid(format!("invalid listen address: {error}")))?,
            quic_version,
            alpn: values[11],
            handshake: decode_hex(values[12])?,
        })
    }
}

fn assert_transport_parameters(encoded: &[u8]) -> TestResult<()> {
    let mut remaining = encoded;
    let mut identifiers = BTreeSet::new();
    while !remaining.is_empty() {
        let (identifier, id_length) = decode_varint_prefix(remaining)?;
        remaining = &remaining[id_length..];
        let (length, length_length) = decode_varint_prefix(remaining)?;
        remaining = &remaining[length_length..];
        let length = usize::try_from(length)?;
        remaining = remaining
            .get(length..)
            .ok_or_else(|| invalid("truncated transport parameter"))?;
        assert!(
            identifiers.insert(identifier),
            "duplicate transport parameter"
        );
    }

    let stable = identifiers
        .iter()
        .copied()
        .filter(|identifier| !is_reserved_transport_parameter(*identifier))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        stable,
        [1, 3, 4, 5, 6, 7, 8, 9, 15, 17, 32, 12_584]
            .into_iter()
            .collect()
    );
    assert_eq!(
        identifiers
            .iter()
            .filter(|identifier| is_reserved_transport_parameter(**identifier))
            .count(),
        1
    );
    Ok(())
}

fn extension_payload(handshake: &[u8], expected: u16) -> io::Result<&[u8]> {
    let mut offset = 4 + 2 + 32;
    let session_id = usize::from(read_u8(handshake, &mut offset)?);
    take(handshake, &mut offset, session_id)?;
    let cipher_suites = usize::from(read_u16(handshake, &mut offset)?);
    take(handshake, &mut offset, cipher_suites)?;
    let compression = usize::from(read_u8(handshake, &mut offset)?);
    take(handshake, &mut offset, compression)?;
    let extensions_length = usize::from(read_u16(handshake, &mut offset)?);
    let extensions = take(handshake, &mut offset, extensions_length)?;

    let mut extension_offset = 0;
    while extension_offset < extensions.len() {
        let kind = read_u16(extensions, &mut extension_offset)?;
        let length = usize::from(read_u16(extensions, &mut extension_offset)?);
        let payload = take(extensions, &mut extension_offset, length)?;
        if kind == expected {
            return Ok(payload);
        }
    }
    Err(invalid("ClientHello omitted QUIC transport parameters"))
}

fn decode_varint_prefix(encoded: &[u8]) -> io::Result<(u64, usize)> {
    let first = *encoded
        .first()
        .ok_or_else(|| invalid("empty QUIC varint"))?;
    let length = 1_usize << usize::from(first >> 6);
    let bytes = encoded
        .get(..length)
        .ok_or_else(|| invalid("truncated QUIC varint"))?;
    let value = bytes
        .iter()
        .enumerate()
        .fold(0_u64, |value, (index, byte)| {
            (value << 8) | u64::from(if index == 0 { byte & 0x3f } else { *byte })
        });
    Ok((value, length))
}

fn is_reserved_transport_parameter(identifier: u64) -> bool {
    identifier >= 27 && (identifier - 27).is_multiple_of(31)
}

fn decode_hex(value: &str) -> io::Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(invalid("handshake hex has odd length"));
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|digits| {
            let digits = std::str::from_utf8(digits).map_err(|error| invalid(error.to_string()))?;
            u8::from_str_radix(digits, 16).map_err(|error| invalid(error.to_string()))
        })
        .collect()
}

fn read_u8(bytes: &[u8], offset: &mut usize) -> io::Result<u8> {
    Ok(take(bytes, offset, 1)?[0])
}

fn read_u16(bytes: &[u8], offset: &mut usize) -> io::Result<u16> {
    let value = take(bytes, offset, 2)?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn take<'a>(bytes: &'a [u8], offset: &mut usize, length: usize) -> io::Result<&'a [u8]> {
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| invalid("truncated fixture bytes"))?;
    let value = &bytes[*offset..end];
    *offset = end;
    Ok(value)
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
