//! Semantic decoding for captured TLS ClientHello messages.

use std::{error::Error, fmt};

const CLIENT_HELLO_HANDSHAKE_TYPE: u8 = 1;
const RANDOM_LENGTH: usize = 32;

const SUPPORTED_GROUPS_EXTENSION: u16 = 10;
const SIGNATURE_ALGORITHMS_EXTENSION: u16 = 13;
const ALPN_EXTENSION: u16 = 16;
const SUPPORTED_VERSIONS_EXTENSION: u16 = 43;
const KEY_SHARE_EXTENSION: u16 = 51;

/// The ordered fingerprint-relevant fields decoded from a TLS ClientHello.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloSummary {
    cipher_suites: Vec<u16>,
    extension_types: Vec<u16>,
    supported_groups: Vec<u16>,
    signature_algorithms: Vec<u16>,
    alpn_protocols: Vec<Vec<u8>>,
    supported_versions: Vec<u16>,
    key_share_groups: Vec<u16>,
}

impl ClientHelloSummary {
    pub(super) fn decode(handshake: &[u8]) -> Result<Self, ClientHelloDecodeError> {
        let mut message = Cursor::new(handshake);
        let handshake_type = message.read_u8("handshake type")?;
        if handshake_type != CLIENT_HELLO_HANDSHAKE_TYPE {
            return Err(ClientHelloDecodeError::UnexpectedHandshakeType { handshake_type });
        }

        let body_length = message.read_u24("ClientHello body length")?;
        let body_bytes = message.take(body_length, "ClientHello body")?;
        if message.remaining() != 0 {
            return Err(ClientHelloDecodeError::TrailingHandshakeBytes {
                count: message.remaining(),
            });
        }

        let mut body = Cursor::new(body_bytes);
        body.take(2, "legacy version")?;
        body.take(RANDOM_LENGTH, "random")?;

        let session_id_length = usize::from(body.read_u8("session ID length")?);
        if session_id_length > 32 {
            return Err(ClientHelloDecodeError::LengthOutOfRange {
                field: "session ID",
                length: session_id_length,
                minimum: 0,
                maximum: 32,
            });
        }
        body.take(session_id_length, "session ID")?;

        let cipher_suites_length = usize::from(body.read_u16("cipher suites length")?);
        require_nonempty_even("cipher suites", cipher_suites_length, u16::MAX as usize - 1)?;
        let cipher_suites = parse_u16_values(
            body.take(cipher_suites_length, "cipher suites")?,
            "cipher suites",
        )?;

        let compression_methods_length = usize::from(body.read_u8("compression methods length")?);
        if compression_methods_length == 0 {
            return Err(ClientHelloDecodeError::LengthOutOfRange {
                field: "compression methods",
                length: 0,
                minimum: 1,
                maximum: u8::MAX as usize,
            });
        }
        body.take(compression_methods_length, "compression methods")?;

        let mut summary = Self {
            cipher_suites,
            extension_types: Vec::new(),
            supported_groups: Vec::new(),
            signature_algorithms: Vec::new(),
            alpn_protocols: Vec::new(),
            supported_versions: Vec::new(),
            key_share_groups: Vec::new(),
        };

        if body.remaining() == 0 {
            return Ok(summary);
        }

        let extensions_length = usize::from(body.read_u16("extensions length")?);
        let extensions_bytes = body.take(extensions_length, "extensions")?;
        if body.remaining() != 0 {
            return Err(ClientHelloDecodeError::TrailingClientHelloBytes {
                count: body.remaining(),
            });
        }

        let mut extensions = Cursor::new(extensions_bytes);
        let mut decoded_extensions = Vec::new();
        while extensions.remaining() != 0 {
            let extension_type = extensions.read_u16("extension type")?;
            let extension_length = usize::from(extensions.read_u16("extension length")?);
            let extension_data = extensions.take(extension_length, "extension data")?;
            summary.extension_types.push(extension_type);

            if is_decoded_extension(extension_type) {
                if decoded_extensions.contains(&extension_type) {
                    return Err(ClientHelloDecodeError::DuplicateExtension { extension_type });
                }
                decoded_extensions.push(extension_type);
            }

            match extension_type {
                SUPPORTED_GROUPS_EXTENSION => {
                    summary.supported_groups = parse_u16_length_prefixed(
                        extension_data,
                        "supported groups",
                        extension_type,
                    )?;
                }
                SIGNATURE_ALGORITHMS_EXTENSION => {
                    summary.signature_algorithms = parse_u16_length_prefixed(
                        extension_data,
                        "signature algorithms",
                        extension_type,
                    )?;
                }
                ALPN_EXTENSION => {
                    summary.alpn_protocols = parse_alpn(extension_data, extension_type)?;
                }
                SUPPORTED_VERSIONS_EXTENSION => {
                    summary.supported_versions =
                        parse_supported_versions(extension_data, extension_type)?;
                }
                KEY_SHARE_EXTENSION => {
                    summary.key_share_groups =
                        parse_key_share_groups(extension_data, extension_type)?;
                }
                _ => {}
            }
        }

        Ok(summary)
    }

    /// Returns cipher suites in their exact wire order.
    #[must_use]
    pub fn cipher_suites(&self) -> &[u16] {
        &self.cipher_suites
    }

    /// Returns extension types in their exact wire order, including unknown extensions.
    #[must_use]
    pub fn extension_types(&self) -> &[u16] {
        &self.extension_types
    }

    /// Returns supported groups in their exact wire order.
    #[must_use]
    pub fn supported_groups(&self) -> &[u16] {
        &self.supported_groups
    }

    /// Returns signature algorithms in their exact wire order.
    #[must_use]
    pub fn signature_algorithms(&self) -> &[u16] {
        &self.signature_algorithms
    }

    /// Returns ALPN protocol identifiers as their exact wire bytes.
    #[must_use]
    pub fn alpn_protocols(&self) -> &[Vec<u8>] {
        &self.alpn_protocols
    }

    /// Returns supported TLS versions in their exact wire order.
    #[must_use]
    pub fn supported_versions(&self) -> &[u16] {
        &self.supported_versions
    }

    /// Returns key-share groups in their exact wire order.
    #[must_use]
    pub fn key_share_groups(&self) -> &[u16] {
        &self.key_share_groups
    }
}

/// Failure returned while decoding a captured TLS ClientHello.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ClientHelloDecodeError {
    /// The handshake message was not a ClientHello.
    UnexpectedHandshakeType {
        /// The observed TLS handshake type.
        handshake_type: u8,
    },
    /// A field ended before its declared or required length.
    Truncated {
        /// Field being decoded.
        field: &'static str,
        /// Bytes required by the field.
        needed: usize,
        /// Bytes still available.
        remaining: usize,
    },
    /// A field length fell outside the range allowed by TLS.
    LengthOutOfRange {
        /// Field being decoded.
        field: &'static str,
        /// Observed length.
        length: usize,
        /// Smallest permitted length.
        minimum: usize,
        /// Largest permitted length.
        maximum: usize,
    },
    /// A fixed-width vector did not contain a whole number of elements.
    InvalidVectorLength {
        /// Vector being decoded.
        field: &'static str,
        /// Observed byte length.
        length: usize,
        /// Width of one vector element.
        element_width: usize,
    },
    /// A decoded singleton extension appeared more than once.
    DuplicateExtension {
        /// Duplicate TLS extension type.
        extension_type: u16,
    },
    /// Bytes followed the handshake body declared by the handshake header.
    TrailingHandshakeBytes {
        /// Number of unexpected bytes.
        count: usize,
    },
    /// Bytes followed the extension block at the end of the ClientHello body.
    TrailingClientHelloBytes {
        /// Number of unexpected bytes.
        count: usize,
    },
    /// A decoded extension contained bytes outside its nested vector.
    TrailingExtensionBytes {
        /// TLS extension type being decoded.
        extension_type: u16,
        /// Number of unexpected bytes.
        count: usize,
    },
    /// ALPN contained an empty protocol identifier.
    EmptyAlpnProtocol,
}

impl fmt::Display for ClientHelloDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedHandshakeType { handshake_type } => write!(
                formatter,
                "TLS handshake type is {handshake_type}, not ClientHello"
            ),
            Self::Truncated {
                field,
                needed,
                remaining,
            } => write!(
                formatter,
                "{field} needs {needed} bytes, but only {remaining} remain"
            ),
            Self::LengthOutOfRange {
                field,
                length,
                minimum,
                maximum,
            } => write!(
                formatter,
                "{field} length is {length}; expected {minimum}..={maximum}"
            ),
            Self::InvalidVectorLength {
                field,
                length,
                element_width,
            } => write!(
                formatter,
                "{field} length is {length}; expected a multiple of {element_width}"
            ),
            Self::DuplicateExtension { extension_type } => {
                write!(
                    formatter,
                    "TLS extension {extension_type} appears more than once"
                )
            }
            Self::TrailingHandshakeBytes { count } => {
                write!(
                    formatter,
                    "{count} bytes follow the declared ClientHello handshake"
                )
            }
            Self::TrailingClientHelloBytes { count } => {
                write!(
                    formatter,
                    "{count} bytes follow the ClientHello extension block"
                )
            }
            Self::TrailingExtensionBytes {
                extension_type,
                count,
            } => write!(
                formatter,
                "TLS extension {extension_type} contains {count} trailing bytes"
            ),
            Self::EmptyAlpnProtocol => formatter.write_str("ALPN contains an empty protocol name"),
        }
    }
}

impl Error for ClientHelloDecodeError {}

/// Reports whether a 16-bit value is reserved for GREASE.
#[must_use]
pub const fn is_grease(value: u16) -> bool {
    let [high, low] = value.to_be_bytes();
    high == low && low & 0x0f == 0x0a
}

fn is_decoded_extension(extension_type: u16) -> bool {
    matches!(
        extension_type,
        SUPPORTED_GROUPS_EXTENSION
            | SIGNATURE_ALGORITHMS_EXTENSION
            | ALPN_EXTENSION
            | SUPPORTED_VERSIONS_EXTENSION
            | KEY_SHARE_EXTENSION
    )
}

fn require_nonempty_even(
    field: &'static str,
    length: usize,
    maximum: usize,
) -> Result<(), ClientHelloDecodeError> {
    if length == 0 {
        return Err(ClientHelloDecodeError::LengthOutOfRange {
            field,
            length,
            minimum: 2,
            maximum,
        });
    }
    if length % 2 != 0 {
        return Err(ClientHelloDecodeError::InvalidVectorLength {
            field,
            length,
            element_width: 2,
        });
    }
    Ok(())
}

fn parse_u16_values(bytes: &[u8], field: &'static str) -> Result<Vec<u16>, ClientHelloDecodeError> {
    if bytes.len() % 2 != 0 {
        return Err(ClientHelloDecodeError::InvalidVectorLength {
            field,
            length: bytes.len(),
            element_width: 2,
        });
    }
    Ok(bytes
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect())
}

fn parse_u16_length_prefixed(
    data: &[u8],
    field: &'static str,
    extension_type: u16,
) -> Result<Vec<u16>, ClientHelloDecodeError> {
    let mut extension = Cursor::new(data);
    let length = usize::from(extension.read_u16(field)?);
    require_nonempty_even(field, length, u16::MAX as usize - 1)?;
    let values = parse_u16_values(extension.take(length, field)?, field)?;
    require_exhausted(&extension, extension_type)?;
    Ok(values)
}

fn parse_supported_versions(
    data: &[u8],
    extension_type: u16,
) -> Result<Vec<u16>, ClientHelloDecodeError> {
    let mut extension = Cursor::new(data);
    let length = usize::from(extension.read_u8("supported versions")?);
    require_nonempty_even("supported versions", length, u8::MAX as usize - 1)?;
    let values = parse_u16_values(
        extension.take(length, "supported versions")?,
        "supported versions",
    )?;
    require_exhausted(&extension, extension_type)?;
    Ok(values)
}

fn parse_alpn(data: &[u8], extension_type: u16) -> Result<Vec<Vec<u8>>, ClientHelloDecodeError> {
    let mut extension = Cursor::new(data);
    let list_length = usize::from(extension.read_u16("ALPN protocol list")?);
    if list_length == 0 {
        return Err(ClientHelloDecodeError::LengthOutOfRange {
            field: "ALPN protocol list",
            length: 0,
            minimum: 2,
            maximum: u16::MAX as usize,
        });
    }
    let mut protocols = Cursor::new(extension.take(list_length, "ALPN protocol list")?);
    require_exhausted(&extension, extension_type)?;

    let mut values = Vec::new();
    while protocols.remaining() != 0 {
        let length = usize::from(protocols.read_u8("ALPN protocol length")?);
        if length == 0 {
            return Err(ClientHelloDecodeError::EmptyAlpnProtocol);
        }
        values.push(protocols.take(length, "ALPN protocol")?.to_vec());
    }
    Ok(values)
}

fn parse_key_share_groups(
    data: &[u8],
    extension_type: u16,
) -> Result<Vec<u16>, ClientHelloDecodeError> {
    let mut extension = Cursor::new(data);
    let list_length = usize::from(extension.read_u16("key share list")?);
    let mut entries = Cursor::new(extension.take(list_length, "key share list")?);
    require_exhausted(&extension, extension_type)?;

    let mut groups = Vec::new();
    while entries.remaining() != 0 {
        groups.push(entries.read_u16("key share group")?);
        let key_exchange_length = usize::from(entries.read_u16("key exchange length")?);
        if key_exchange_length == 0 {
            return Err(ClientHelloDecodeError::LengthOutOfRange {
                field: "key exchange",
                length: 0,
                minimum: 1,
                maximum: u16::MAX as usize,
            });
        }
        entries.take(key_exchange_length, "key exchange")?;
    }
    Ok(groups)
}

fn require_exhausted(
    cursor: &Cursor<'_>,
    extension_type: u16,
) -> Result<(), ClientHelloDecodeError> {
    if cursor.remaining() == 0 {
        Ok(())
    } else {
        Err(ClientHelloDecodeError::TrailingExtensionBytes {
            extension_type,
            count: cursor.remaining(),
        })
    }
}

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    const fn remaining(&self) -> usize {
        self.remaining.len()
    }

    fn take(
        &mut self,
        length: usize,
        field: &'static str,
    ) -> Result<&'a [u8], ClientHelloDecodeError> {
        if self.remaining.len() < length {
            return Err(ClientHelloDecodeError::Truncated {
                field,
                needed: length,
                remaining: self.remaining.len(),
            });
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn read_u8(&mut self, field: &'static str) -> Result<u8, ClientHelloDecodeError> {
        Ok(self.take(1, field)?[0])
    }

    fn read_u16(&mut self, field: &'static str) -> Result<u16, ClientHelloDecodeError> {
        let bytes = self.take(2, field)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u24(&mut self, field: &'static str) -> Result<usize, ClientHelloDecodeError> {
        let bytes = self.take(3, field)?;
        Ok((usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ALPN_EXTENSION, ClientHelloDecodeError, ClientHelloSummary, KEY_SHARE_EXTENSION,
        SIGNATURE_ALGORITHMS_EXTENSION, SUPPORTED_GROUPS_EXTENSION, SUPPORTED_VERSIONS_EXTENSION,
        is_grease,
    };

    fn extension(extension_type: u16, data: &[u8]) -> Vec<u8> {
        let length =
            u16::try_from(data.len()).unwrap_or_else(|_| panic!("test extension too long"));
        let mut encoded = extension_type.to_be_bytes().to_vec();
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(data);
        encoded
    }

    fn body(cipher_suites: &[u8], extensions: Option<&[u8]>) -> Vec<u8> {
        let cipher_length =
            u16::try_from(cipher_suites.len()).unwrap_or_else(|_| panic!("test vector too long"));
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x42; 32]);
        body.extend_from_slice(&[2, 0xaa, 0xbb]);
        body.extend_from_slice(&cipher_length.to_be_bytes());
        body.extend_from_slice(cipher_suites);
        body.extend_from_slice(&[1, 0]);
        if let Some(extensions) = extensions {
            let length =
                u16::try_from(extensions.len()).unwrap_or_else(|_| panic!("test vector too long"));
            body.extend_from_slice(&length.to_be_bytes());
            body.extend_from_slice(extensions);
        }
        body
    }

    fn handshake(body: &[u8]) -> Vec<u8> {
        let length = body.len();
        assert!(length <= 0x00ff_ffff);
        let mut message = vec![
            1,
            ((length >> 16) & 0xff) as u8,
            ((length >> 8) & 0xff) as u8,
            (length & 0xff) as u8,
        ];
        message.extend_from_slice(body);
        message
    }

    fn decode_body(body: &[u8]) -> Result<ClientHelloSummary, ClientHelloDecodeError> {
        ClientHelloSummary::decode(&handshake(body))
    }

    #[test]
    fn decodes_ordered_fingerprint_fields() -> Result<(), ClientHelloDecodeError> {
        let mut extensions = extension(0x3a3a, &[1, 2, 3]);
        extensions.extend_from_slice(&extension(
            SUPPORTED_GROUPS_EXTENSION,
            &[0, 4, 0, 29, 0x2a, 0x2a],
        ));
        extensions.extend_from_slice(&extension(
            SIGNATURE_ALGORITHMS_EXTENSION,
            &[0, 4, 0x08, 0x04, 0x04, 0x03],
        ));
        extensions.extend_from_slice(&extension(ALPN_EXTENSION, &[0, 5, 2, b'h', b'2', 1, 0xff]));
        extensions.extend_from_slice(&extension(
            SUPPORTED_VERSIONS_EXTENSION,
            &[4, 0x03, 0x04, 0x7a, 0x7a],
        ));
        extensions.extend_from_slice(&extension(
            KEY_SHARE_EXTENSION,
            &[0, 11, 0, 29, 0, 2, 1, 2, 0x4a, 0x4a, 0, 1, 3],
        ));

        let summary = decode_body(&body(
            &[0x13, 0x02, 0x0a, 0x0a, 0x13, 0x01],
            Some(&extensions),
        ))?;

        assert_eq!(summary.cipher_suites(), &[0x1302, 0x0a0a, 0x1301]);
        assert_eq!(summary.extension_types(), &[0x3a3a, 10, 13, 16, 43, 51]);
        assert_eq!(summary.supported_groups(), &[29, 0x2a2a]);
        assert_eq!(summary.signature_algorithms(), &[0x0804, 0x0403]);
        assert_eq!(summary.alpn_protocols(), &[b"h2".to_vec(), vec![0xff]]);
        assert_eq!(summary.supported_versions(), &[0x0304, 0x7a7a]);
        assert_eq!(summary.key_share_groups(), &[29, 0x4a4a]);
        Ok(())
    }

    #[test]
    fn identifies_only_grease_values() {
        for value in [0x0a0a, 0x1a1a, 0xaaaa, 0xfafa] {
            assert!(is_grease(value));
        }
        for value in [0x0a1a, 0x1a2a, 0x0a0b, 0x1301] {
            assert!(!is_grease(value));
        }
    }

    #[test]
    fn accepts_absent_optional_extensions() -> Result<(), ClientHelloDecodeError> {
        let summary = decode_body(&body(&[0x13, 0x01], None))?;

        assert!(summary.extension_types().is_empty());
        assert!(summary.supported_groups().is_empty());
        assert!(summary.signature_algorithms().is_empty());
        assert!(summary.alpn_protocols().is_empty());
        assert!(summary.supported_versions().is_empty());
        assert!(summary.key_share_groups().is_empty());
        Ok(())
    }

    #[test]
    fn rejects_truncation_at_major_vectors() {
        let valid = body(&[0x13, 0x01], Some(&[]));
        for length in [0, 1, 2, 33, 34, 35, 37, 38, 39, valid.len() - 1] {
            assert!(matches!(
                decode_body(&valid[..length]),
                Err(ClientHelloDecodeError::Truncated { .. })
            ));
        }
    }

    #[test]
    fn rejects_odd_u16_vector_lengths() {
        assert!(matches!(
            decode_body(&body(&[0x13, 0x01, 0xff], None)),
            Err(ClientHelloDecodeError::InvalidVectorLength {
                field: "cipher suites",
                ..
            })
        ));

        for (extension_type, data, field) in [
            (
                SUPPORTED_GROUPS_EXTENSION,
                vec![0, 3, 0, 29, 0],
                "supported groups",
            ),
            (
                SIGNATURE_ALGORITHMS_EXTENSION,
                vec![0, 3, 8, 4, 0],
                "signature algorithms",
            ),
            (
                SUPPORTED_VERSIONS_EXTENSION,
                vec![3, 3, 4, 0],
                "supported versions",
            ),
        ] {
            let extensions = extension(extension_type, &data);
            assert!(matches!(
                decode_body(&body(&[0x13, 0x01], Some(&extensions))),
                Err(ClientHelloDecodeError::InvalidVectorLength { field: found, .. })
                    if found == field
            ));
        }
    }

    #[test]
    fn rejects_malformed_nested_lengths() {
        for (extension_type, data) in [
            (SUPPORTED_GROUPS_EXTENSION, vec![0, 4, 0, 29]),
            (SIGNATURE_ALGORITHMS_EXTENSION, vec![0, 4, 8, 4]),
            (ALPN_EXTENSION, vec![0, 3, 2, b'h']),
            (SUPPORTED_VERSIONS_EXTENSION, vec![4, 3, 4]),
            (KEY_SHARE_EXTENSION, vec![0, 6, 0, 29, 0, 4, 1]),
        ] {
            let extensions = extension(extension_type, &data);
            assert!(matches!(
                decode_body(&body(&[0x13, 0x01], Some(&extensions))),
                Err(ClientHelloDecodeError::Truncated { .. })
            ));
        }
    }

    #[test]
    fn accepts_empty_key_share_list() -> Result<(), ClientHelloDecodeError> {
        let extensions = extension(KEY_SHARE_EXTENSION, &[0, 0]);

        let summary = decode_body(&body(&[0x13, 0x01], Some(&extensions)))?;

        assert!(summary.key_share_groups().is_empty());
        Ok(())
    }

    #[test]
    fn rejects_empty_key_exchange() {
        let extensions = extension(KEY_SHARE_EXTENSION, &[0, 4, 0, 29, 0, 0]);

        assert!(matches!(
            decode_body(&body(&[0x13, 0x01], Some(&extensions))),
            Err(ClientHelloDecodeError::LengthOutOfRange {
                field: "key exchange",
                length: 0,
                ..
            })
        ));
    }

    #[test]
    fn rejects_duplicate_decoded_singleton_extensions() {
        for (extension_type, data) in [
            (SUPPORTED_GROUPS_EXTENSION, vec![0, 2, 0, 29]),
            (SIGNATURE_ALGORITHMS_EXTENSION, vec![0, 2, 8, 4]),
            (ALPN_EXTENSION, vec![0, 3, 2, b'h', b'2']),
            (SUPPORTED_VERSIONS_EXTENSION, vec![2, 3, 4]),
            (KEY_SHARE_EXTENSION, vec![0, 5, 0, 29, 0, 1, 1]),
        ] {
            let mut extensions = extension(extension_type, &data);
            extensions.extend_from_slice(&extension(extension_type, &data));
            assert_eq!(
                decode_body(&body(&[0x13, 0x01], Some(&extensions))),
                Err(ClientHelloDecodeError::DuplicateExtension { extension_type })
            );
        }
    }

    #[test]
    fn rejects_bytes_after_declared_extension_block() {
        let mut malformed = body(&[0x13, 0x01], Some(&[]));
        malformed.extend_from_slice(&[0xaa, 0xbb]);

        assert_eq!(
            decode_body(&malformed),
            Err(ClientHelloDecodeError::TrailingClientHelloBytes { count: 2 })
        );
    }

    #[test]
    fn rejects_bytes_after_declared_handshake_body() {
        let body = body(&[0x13, 0x01], None);
        let mut message = handshake(&body);
        message.push(0xaa);

        assert_eq!(
            ClientHelloSummary::decode(&message),
            Err(ClientHelloDecodeError::TrailingHandshakeBytes { count: 1 })
        );
    }

    #[test]
    fn rejects_trailing_bytes_inside_decoded_extensions() {
        let cases = [
            (SUPPORTED_GROUPS_EXTENSION, vec![0, 2, 0, 29, 0]),
            (SIGNATURE_ALGORITHMS_EXTENSION, vec![0, 2, 8, 4, 0]),
            (ALPN_EXTENSION, vec![0, 3, 2, b'h', b'2', 0]),
            (SUPPORTED_VERSIONS_EXTENSION, vec![2, 3, 4, 0]),
            (KEY_SHARE_EXTENSION, vec![0, 5, 0, 29, 0, 1, 1, 0]),
        ];

        for (extension_type, data) in cases {
            let extensions = extension(extension_type, &data);
            assert!(matches!(
                decode_body(&body(&[0x13, 0x01], Some(&extensions))),
                Err(ClientHelloDecodeError::TrailingExtensionBytes {
                    extension_type: found,
                    count: 1,
                }) if found == extension_type
            ));
        }
    }

    #[test]
    fn preserves_duplicate_unknown_extensions() -> Result<(), ClientHelloDecodeError> {
        let mut extensions = extension(0xbeef, &[1]);
        extensions.extend_from_slice(&extension(0xbeef, &[2]));

        let summary = decode_body(&body(&[0x13, 0x01], Some(&extensions)))?;

        assert_eq!(summary.extension_types(), &[0xbeef, 0xbeef]);
        Ok(())
    }
}
